//! Closed WASI Git read worker. The only repository path is /snapshot;
//! requests contain bounded operation parameters and no command or path.

use gix::bstr::{BString, ByteSlice};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};

const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_OFFSET: usize = 100_000;
const MAX_LIMIT: usize = 201;
const MAX_TREE_ENTRIES: usize = 100_000;
const MAX_DIFF_BLOB_BYTES: usize = 1024 * 1024;
const MAX_DIFF_HUNKS: usize = 200;
const MAX_DIFF_LINES: usize = 1000;
const MAX_DIFF_LINE_BYTES: usize = 1024;
const MAX_COMMIT_OBJECTS: usize = 30_000;
const MAX_RESTORE_BLOB_BYTES: u64 = 256 * 1024 * 1024;
const RESTORE_INDEX_OUTPUT_FILE: &str = ".lomi-restore-index-output";
const OWNER_CONTEXT_FILE: &str = "context.json";
const MAX_OWNER_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_OWNER_CONTEXT_BYTES: usize = 4 * 1024 * 1024 + 4096;
const STATUS_RENAME_LIMIT: gix::config::tree::keys::UnsignedInteger =
    gix::config::tree::keys::UnsignedInteger::new_unsigned_integer(
        "renameLimit",
        &gix::config::Tree::STATUS,
    );

fn decode_hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn decode_hex_bytes(
    value: &str,
    expected_len: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if value.len() != expected_len * 2 {
        return Err("invalid hexadecimal value".into());
    }
    let mut output = Vec::with_capacity(expected_len);
    for pair in value.as_bytes().chunks_exact(2) {
        let digit = |value: u8| match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        };
        let high = digit(pair[0]).ok_or("invalid hexadecimal value")?;
        let low = digit(pair[1]).ok_or("invalid hexadecimal value")?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn decode_path_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if value.len() > 8192 || !value.len().is_multiple_of(2) {
        return Err("invalid path encoding".into());
    }
    decode_hex_bytes(value, value.len() / 2)
}

fn decode_owner_config_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if value.len() > MAX_OWNER_CONFIG_BYTES * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid owner-local configuration".into());
    }
    decode_hex_bytes(value, value.len() / 2)
}

fn parse_owner_git_config(bytes: &[u8]) -> Result<gix::config::File, Box<dyn std::error::Error>> {
    if bytes.len() > MAX_OWNER_CONFIG_BYTES {
        return Err("owner-local configuration exceeds limits".into());
    }
    let config = gix::config::File::from_bytes_no_includes(
        bytes,
        gix::config::file::Metadata::api(),
        Default::default(),
    )
    .map_err(|_| "invalid owner-local Git configuration")?;
    if config.sections().any(|section| {
        let name = section.header().name();
        name.eq_ignore_ascii_case(b"include") || name.eq_ignore_ascii_case(b"includeIf")
    }) {
        return Err("owner-local Git configuration includes are unsupported".into());
    }
    Ok(config)
}

fn read_owner_local_context() -> Result<OwnerLocalContext, Box<dyn std::error::Error>> {
    let path = std::path::Path::new("/input").join(OWNER_CONTEXT_FILE);
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_OWNER_CONTEXT_BYTES as u64 {
        return Err("invalid owner-local context file".into());
    }
    let input = std::fs::File::open(path)?;
    let opened_metadata = input.metadata()?;
    if !opened_metadata.is_file() || opened_metadata.len() != metadata.len() {
        return Err("invalid owner-local context file".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    input
        .take(MAX_OWNER_CONTEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_OWNER_CONTEXT_BYTES || bytes.len() as u64 != metadata.len() {
        return Err("invalid owner-local context file".into());
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    let object = value
        .as_object()
        .ok_or("invalid owner-local context object")?;
    if object.len() != 4
        || object.get("version").and_then(Value::as_u64) != Some(1)
        || !object.contains_key("selectedKind")
        || !object.contains_key("commonConfigHex")
        || !object.contains_key("worktreeConfigHex")
    {
        return Err("unsupported owner-local context".into());
    }
    let selected_kind = match object
        .get("selectedKind")
        .and_then(Value::as_str)
        .ok_or("invalid selected node kind")?
    {
        "absent" => SelectedNodeKind::Absent,
        "file" => SelectedNodeKind::File,
        "symlink" => SelectedNodeKind::Symlink,
        "directory" => SelectedNodeKind::Directory,
        _ => return Err("invalid selected node kind".into()),
    };
    let common_config_hex = match object.get("commonConfigHex") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        _ => return Err("invalid common configuration payload".into()),
    };
    let worktree_config_hex = match object.get("worktreeConfigHex") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        _ => return Err("invalid worktree configuration payload".into()),
    };
    let mut config = match common_config_hex {
        Some(hex) => parse_owner_git_config(&decode_owner_config_hex(hex)?)?,
        None => gix::config::File::default(),
    };
    let worktree_config_enabled = config
        .boolean("extensions.worktreeConfig")
        .map_err(|_| "invalid worktree configuration setting")?
        .unwrap_or(false);
    if worktree_config_enabled && let Some(hex) = worktree_config_hex {
        config
            .append(parse_owner_git_config(&decode_owner_config_hex(hex)?)?)
            .map_err(|_| "invalid worktree configuration")?;
    }
    let core_symlinks = config
        .boolean("core.symlinks")
        .map_err(|_| "invalid core.symlinks setting")?
        .unwrap_or(true);
    Ok(OwnerLocalContext {
        selected_kind,
        config,
        core_symlinks,
    })
}

fn path_entry_id(repository: &[u8], path: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"lomi-git-entry-v1\0");
    digest.update(repository);
    digest.update((path.len() as u64).to_le_bytes());
    digest.update(path);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    decode_hex(&bytes)
}

fn read_request() -> Result<Value, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err("invalid request size".into());
    }
    let request: Value = serde_json::from_slice(&bytes)?;
    if !request.is_object() {
        return Err("request must be object".into());
    }
    Ok(request)
}

fn integer(
    object: &Value,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| (minimum..=maximum).contains(n))
        .ok_or_else(|| format!("invalid {name}").into())
}

fn status_request(
    request: &Value,
    repo: &gix::Repository,
) -> Result<Value, Box<dyn std::error::Error>> {
    let object = request.as_object().ok_or("request must be object")?;
    if object.len() != 3 || object.get("operation").and_then(Value::as_str) != Some("status") {
        return Err("unsupported request".into());
    }
    let offset = integer(request, "offset", 0, MAX_OFFSET)?;
    let limit = integer(request, "limit", 1, MAX_LIMIT)?;
    let head = repo
        .head_id()
        .map(|id| id.to_string())
        .unwrap_or_else(|_| "unborn".to_owned());

    let mut changes = BTreeMap::<Vec<u8>, (Option<&'static str>, Option<&'static str>)>::new();
    let status = repo
        .status(gix::progress::Discard)?
        .tree_index_track_renames(gix::status::tree_index::TrackRenames::Disabled)
        .into_iter(Vec::<BString>::new())?;
    for item in status {
        let item = item?;
        let path = item.location().as_bytes().to_vec();
        match item {
            gix::status::Item::TreeIndex(change) => {
                let index = match change {
                    gix::diff::index::ChangeRef::Addition { .. } => "added",
                    gix::diff::index::ChangeRef::Deletion { .. } => "deleted",
                    gix::diff::index::ChangeRef::Modification { .. } => "modified",
                    gix::diff::index::ChangeRef::Rewrite { copy, .. } => {
                        if copy {
                            "copied"
                        } else {
                            "renamed"
                        }
                    }
                };
                changes.entry(path).or_default().0 = Some(index);
            }
            gix::status::Item::IndexWorktree(change) => {
                use gix::status::index_worktree::iter::Summary;
                let worktree = match change.summary() {
                    Some(Summary::Removed) => Some("deleted"),
                    Some(Summary::Added) => Some("untracked"),
                    Some(Summary::Modified | Summary::TypeChange) => Some("modified"),
                    Some(Summary::Renamed) => Some("renamed"),
                    Some(Summary::Copied) => Some("copied"),
                    Some(Summary::IntentToAdd) => Some("added"),
                    Some(Summary::Conflict) => Some("unmerged"),
                    None => None,
                };
                if let Some(worktree) = worktree {
                    changes.entry(path).or_default().1 = Some(worktree);
                }
            }
        }
    }

    let total = changes.len();
    let entries: Vec<_> = changes
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(path, (index, worktree))| {
            json!({
                "pathHex": decode_hex(&path),
                "index": index,
                "worktree": worktree,
            })
        })
        .collect();
    let truncated = offset.saturating_add(entries.len()) < total;
    Ok(json!({
        "head": head,
        "entries": entries,
        "truncated": truncated,
        "total": total,
    }))
}

#[derive(Clone)]
struct SelectedLegacyChange {
    path: Vec<u8>,
    original_path: Option<Vec<u8>>,
    index: char,
    worktree: char,
    selected_kind: SelectedNodeKind,
    core_symlinks: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectedNodeKind {
    Absent,
    File,
    Symlink,
    Directory,
}

impl SelectedNodeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Directory => "directory",
        }
    }
}

struct OwnerLocalContext {
    selected_kind: SelectedNodeKind,
    config: gix::config::File,
    core_symlinks: bool,
}

impl SelectedLegacyChange {
    fn new(path: &[u8]) -> Self {
        Self {
            path: path.to_vec(),
            original_path: None,
            index: ' ',
            worktree: ' ',
            selected_kind: SelectedNodeKind::Absent,
            core_symlinks: true,
        }
    }

    fn set_original_path(&mut self, path: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if !allowed_path(path) {
            return Err("unsafe rename source path".into());
        }
        if self
            .original_path
            .as_ref()
            .is_some_and(|existing| existing.as_slice() != path)
        {
            return Err("ambiguous rename status".into());
        }
        self.original_path = Some(path.to_vec());
        Ok(())
    }
}

fn conflict_status(
    index: &gix::worktree::IndexPersistedOrInMemory,
    path: &[u8],
) -> Result<(char, char), Box<dyn std::error::Error>> {
    use gix::index::entry::Stage;
    let path = path.as_bstr();
    let has_base = index.entry_by_path_and_stage(path, Stage::Base).is_some();
    let has_ours = index.entry_by_path_and_stage(path, Stage::Ours).is_some();
    let has_theirs = index.entry_by_path_and_stage(path, Stage::Theirs).is_some();
    match (has_base, has_ours, has_theirs) {
        (true, false, false) => Ok(('D', 'D')),
        (false, true, false) => Ok(('A', 'U')),
        (true, true, false) => Ok(('U', 'D')),
        (false, false, true) => Ok(('U', 'A')),
        (true, false, true) => Ok(('D', 'U')),
        (false, true, true) => Ok(('A', 'A')),
        (true, true, true) => Ok(('U', 'U')),
        (false, false, false) => Err("missing conflict stages".into()),
    }
}

fn status_tree_index_renames(
    config: &gix::config::File,
) -> Result<gix::status::tree_index::TrackRenames, Box<dyn std::error::Error>> {
    let file = config;
    let tracking =
        match gix::config::tree::Diff::RENAMES.try_into_renames(file.boolean("status.renames"))? {
            Some(tracking) => tracking,
            None => gix::config::tree::Diff::RENAMES
                .try_into_renames(file.boolean(gix::config::tree::Diff::RENAMES))?
                .unwrap_or(gix::diff::rename::Tracking::Renames),
        };
    let default = gix::diff::Rewrites::default();
    let copies = match tracking {
        gix::diff::rename::Tracking::Disabled => {
            return Ok(gix::status::tree_index::TrackRenames::Disabled);
        }
        gix::diff::rename::Tracking::Renames => None,
        gix::diff::rename::Tracking::RenamesAndCopies => Some(Default::default()),
    };
    let limit = match STATUS_RENAME_LIMIT.try_into_usize(file.integer("status.renameLimit"))? {
        Some(limit) => limit,
        None => gix::config::tree::Diff::RENAME_LIMIT
            .try_into_usize(file.integer(gix::config::tree::Diff::RENAME_LIMIT))?
            .unwrap_or(default.limit),
    };
    let rewrites = gix::diff::Rewrites {
        copies,
        limit,
        ..default
    };
    Ok(gix::status::tree_index::TrackRenames::Given(rewrites))
}

fn selected_legacy_change(
    repo: &gix::Repository,
    path: &[u8],
    owner_context: &OwnerLocalContext,
) -> Result<SelectedLegacyChange, Box<dyn std::error::Error>> {
    if !allowed_path(path) {
        return Err("unsafe repository path".into());
    }
    let index = repo.index_or_load_from_head_or_empty()?;
    let status = repo
        .status(gix::progress::Discard)?
        .untracked_files(gix::status::UntrackedFiles::Files)
        .index_worktree_submodules(None)
        .tree_index_track_renames(status_tree_index_renames(&owner_context.config)?)
        .into_iter(Vec::<BString>::new())?;
    let mut selected = SelectedLegacyChange::new(path);
    let mut intent_to_add = false;
    let mut untracked = false;
    let mut conflict = false;
    for item in status {
        let item = item?;
        if item.location().as_bytes() != path {
            continue;
        }
        match item {
            gix::status::Item::TreeIndex(change) => match change {
                gix::diff::index::ChangeRef::Addition { .. } => selected.index = 'A',
                gix::diff::index::ChangeRef::Deletion { .. } => selected.index = 'D',
                gix::diff::index::ChangeRef::Modification {
                    previous_entry_mode,
                    entry_mode,
                    ..
                } => {
                    let previous_type = previous_entry_mode
                        .to_tree_entry_mode()
                        .ok_or("invalid index source mode")?
                        .value()
                        & 0o170000;
                    let current_type = entry_mode
                        .to_tree_entry_mode()
                        .ok_or("invalid index destination mode")?
                        .value()
                        & 0o170000;
                    selected.index = if previous_type != current_type {
                        'T'
                    } else {
                        'M'
                    };
                }
                gix::diff::index::ChangeRef::Rewrite {
                    source_location,
                    copy,
                    ..
                } => {
                    selected.index = if copy { 'C' } else { 'R' };
                    selected.set_original_path(source_location.as_ref().as_bytes())?;
                }
            },
            gix::status::Item::IndexWorktree(change) => {
                use gix::status::index_worktree::iter::Summary;
                let summary = change.summary();
                match change {
                    gix::status::index_worktree::Item::Rewrite { source, copy, .. } => {
                        selected.worktree = if copy { 'C' } else { 'R' };
                        selected.set_original_path(source.rela_path().as_bytes())?;
                    }
                    gix::status::index_worktree::Item::Modification { .. } => match summary {
                        Some(Summary::Removed) => selected.worktree = 'D',
                        Some(Summary::Modified) => selected.worktree = 'M',
                        Some(Summary::TypeChange) => selected.worktree = 'T',
                        Some(Summary::IntentToAdd) => intent_to_add = true,
                        Some(Summary::Conflict) => conflict = true,
                        Some(Summary::Renamed | Summary::Copied) => {
                            return Err("incomplete rewrite status".into());
                        }
                        Some(Summary::Added) | None => {}
                    },
                    gix::status::index_worktree::Item::DirectoryContents { .. } => {
                        if summary == Some(Summary::Added) {
                            untracked = true;
                        }
                    }
                }
            }
        }
    }
    if conflict {
        (selected.index, selected.worktree) = conflict_status(&index, path)?;
        selected.original_path = None;
    } else if untracked {
        selected.index = '?';
        selected.worktree = '?';
        selected.original_path = None;
    } else if intent_to_add {
        selected.index = ' ';
        selected.worktree = 'A';
        selected.original_path = None;
    }
    selected.selected_kind = owner_context.selected_kind;
    selected.core_symlinks = owner_context.core_symlinks;
    if !conflict {
        reconcile_selected_node_type(&mut selected, &index, owner_context.core_symlinks)?;
    }
    Ok(selected)
}

fn reconcile_selected_node_type(
    selected: &mut SelectedLegacyChange,
    index: &gix::worktree::IndexPersistedOrInMemory,
    core_symlinks: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = index_entry(index, &selected.path).or_else(|| {
        selected
            .original_path
            .as_deref()
            .and_then(|path| index_entry(index, path))
    });
    let Some(entry) = entry else {
        return Ok(());
    };
    let entry_type = entry.mode.bits() & 0o170000;
    let is_type_change = match (entry_type, selected.selected_kind, core_symlinks) {
        (0o100000, SelectedNodeKind::Symlink | SelectedNodeKind::Directory, _) => true,
        (0o120000, SelectedNodeKind::File | SelectedNodeKind::Directory, true) => true,
        _ => false,
    };
    if is_type_change {
        selected.worktree = 'T';
    }
    Ok(())
}

fn selected_change_value(change: &SelectedLegacyChange) -> Value {
    json!({
        "pathHex": decode_hex(&change.path),
        "originalPathHex": change.original_path.as_deref().map(decode_hex),
        "index": change.index.to_string(),
        "worktree": change.worktree.to_string(),
        "selectedKind": change.selected_kind.as_str(),
        "coreSymlinks": change.core_symlinks,
    })
}

fn selected_change_request(
    request: &Value,
    repo: &gix::Repository,
    owner_context: &OwnerLocalContext,
) -> Result<Value, Box<dyn std::error::Error>> {
    let object = request.as_object().ok_or("request must be object")?;
    if object.len() != 2
        || object.get("operation").and_then(Value::as_str) != Some("selectedChange")
    {
        return Err("unsupported request".into());
    }
    let path = decode_path_hex(
        object
            .get("pathHex")
            .and_then(Value::as_str)
            .ok_or("invalid selected path")?,
    )?;
    Ok(selected_change_value(&selected_legacy_change(
        repo,
        &path,
        owner_context,
    )?))
}

fn expected_status_char(request: &Value, name: &str) -> Result<char, Box<dyn std::error::Error>> {
    let value = request
        .get(name)
        .and_then(Value::as_str)
        .ok_or("invalid expected status")?;
    let mut chars = value.chars();
    let status = chars.next().ok_or("invalid expected status")?;
    if chars.next().is_some() || !" MADRCUT?!".contains(status) {
        return Err("invalid expected status".into());
    }
    Ok(status)
}

fn restore_index_request(
    request: &Value,
    repo: &gix::Repository,
    owner_context: &OwnerLocalContext,
) -> Result<Value, Box<dyn std::error::Error>> {
    let object = request.as_object().ok_or("request must be object")?;
    if object.len() != 5 || object.get("operation").and_then(Value::as_str) != Some("restoreIndex")
    {
        return Err("unsupported request".into());
    }
    let path = decode_path_hex(
        object
            .get("pathHex")
            .and_then(Value::as_str)
            .ok_or("invalid selected path")?,
    )?;
    let original_path = match object.get("expectedOriginalPathHex") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(decode_path_hex(value)?),
        _ => return Err("invalid expected rename source".into()),
    };
    if original_path
        .as_deref()
        .is_some_and(|path| !allowed_path(path))
    {
        return Err("unsafe expected rename source".into());
    }
    let expected_index = expected_status_char(request, "expectedIndex")?;
    let expected_worktree = expected_status_char(request, "expectedWorktree")?;
    let change = selected_legacy_change(repo, &path, owner_context)?;
    if change.path != path
        || change.original_path != original_path
        || change.index != expected_index
        || change.worktree != expected_worktree
    {
        return Err("selected Git status changed".into());
    }
    if !matches!(change.worktree, 'M' | 'D' | 'T') || change.index == 'U' {
        return Err("selected change cannot be restored from index".into());
    }

    let index = repo.index_or_load_from_head_or_empty()?;
    let (index_path, entry) = match index_entry(&index, &path) {
        Some(entry) => (path.as_slice(), entry),
        None if original_path.is_some() => {
            let source_path = original_path.as_deref().ok_or("missing rename source")?;
            let entry = index_entry(&index, source_path).ok_or("index blob is unavailable")?;
            (source_path, entry)
        }
        None => return Err("index blob is unavailable".into()),
    };
    let mode = entry.mode.bits();
    if !matches!(mode, 0o100644 | 0o100755 | 0o120000) {
        return Err("unsupported index entry mode".into());
    }
    let header = repo.find_header(entry.id)?;
    if header.kind() != gix::object::Kind::Blob || header.size() > MAX_RESTORE_BLOB_BYTES {
        return Err("index blob exceeds restore limits".into());
    }
    let blob = repo.find_object(entry.id)?;
    if blob.kind != gix::object::Kind::Blob
        || blob.data.len() as u64 != header.size()
        || blob.data.len() as u64 > MAX_RESTORE_BLOB_BYTES
    {
        return Err("invalid index blob".into());
    }
    let output_path = std::path::Path::new("/output").join(RESTORE_INDEX_OUTPUT_FILE);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)?;
    for chunk in blob.data.chunks(1024 * 1024) {
        output.write_all(chunk)?;
    }
    output.flush()?;
    let output_meta = std::fs::symlink_metadata(&output_path)?;
    if !output_meta.file_type().is_file() || output_meta.len() != header.size() {
        return Err("invalid private restore output".into());
    }
    Ok(json!({
        "change": selected_change_value(&change),
        "indexPathHex": decode_hex(index_path),
        "blobObjectId": entry.id.to_string(),
        "mode": mode,
        "size": header.size(),
    }))
}

#[derive(Clone)]
struct Candidate {
    path: Vec<u8>,
    old: Option<gix::ObjectId>,
    new: Option<gix::ObjectId>,
    mode_changed: bool,
    worktree: bool,
}

#[derive(Clone)]
struct TreeEntry {
    id: gix::ObjectId,
    mode: gix::object::tree::EntryKind,
}

fn allowed_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path.len() <= 3072
        && !path.starts_with(b"/")
        && path.split(|byte| *byte == b'/').all(|part| {
            !part.is_empty()
                && part != b"."
                && part != b".."
                && !part.contains(&0)
                && !part.contains(&b'\\')
                && !part.contains(&b':')
                && !is_git_metadata_component(part)
        })
}

fn is_git_metadata_component(component: &[u8]) -> bool {
    let mut end = component.len();
    while end > 0 && matches!(component[end - 1], b'.' | b' ') {
        end -= 1;
    }
    let trimmed = &component[..end];
    if trimmed.eq_ignore_ascii_case(b".git") {
        return true;
    }
    let lowercase = trimmed
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    lowercase
        .strip_prefix(b"git~")
        .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
}

fn path_filter_matches(
    path: &[u8],
    path_filter: Option<&[u8]>,
    entry_filter: Option<&str>,
    repository: Option<&[u8]>,
) -> bool {
    if let Some(filter) = path_filter {
        return filter == path;
    }
    match (entry_filter, repository) {
        (Some(entry), Some(repository)) => path_entry_id(repository, path) == entry,
        _ => true,
    }
}

fn index_entry<'a>(
    index: &'a gix::worktree::IndexPersistedOrInMemory,
    path: &[u8],
) -> Option<&'a gix::index::Entry> {
    index.entry_by_path_and_stage(path.as_bstr(), gix::index::entry::Stage::Unconflicted)
}

fn tree_entry_id(
    tree: &gix::Tree<'_>,
    path: &[u8],
) -> Result<Option<TreeEntry>, Box<dyn std::error::Error>> {
    if !allowed_path(path) {
        return Err("unsafe repository path".into());
    }
    let components = path
        .split(|byte| *byte == b'/')
        .map(BString::from)
        .collect::<Vec<_>>();
    let entry = tree.lookup_entry(components)?;
    Ok(entry.map(|entry| TreeEntry {
        id: entry.object_id(),
        mode: entry.mode().kind(),
    }))
}

fn index_diff_candidates(
    repo: &gix::Repository,
    path_filter: Option<&[u8]>,
    entry_filter: Option<&str>,
    repository_filter: Option<&[u8]>,
) -> Result<Vec<Candidate>, Box<dyn std::error::Error>> {
    let index = repo.index_or_load_from_head_or_empty()?;
    let head_tree = repo
        .head_commit()
        .and_then(|commit| commit.tree())
        .unwrap_or_else(|_| repo.empty_tree());
    let status = repo
        .status(gix::progress::Discard)?
        .untracked_files(gix::status::UntrackedFiles::None)
        .index_worktree_submodules(None)
        .tree_index_track_renames(gix::status::tree_index::TrackRenames::Disabled)
        .into_iter(Vec::<BString>::new())?;
    let mut candidates = BTreeMap::<Vec<u8>, Candidate>::new();
    for item in status {
        let item = item?;
        let gix::status::Item::TreeIndex(change) = item else {
            continue;
        };
        let path = change.location().as_bytes();
        if !allowed_path(path)
            || !path_filter_matches(path, path_filter, entry_filter, repository_filter)
        {
            continue;
        }
        let old = tree_entry_id(&head_tree, path)?;
        let new = match index_entry(&index, path) {
            Some(entry) => Some(TreeEntry {
                id: entry.id,
                mode: entry
                    .mode
                    .to_tree_entry_mode()
                    .ok_or("invalid index entry mode")?
                    .kind(),
            }),
            None => None,
        };
        if old.as_ref().map(|entry| entry.id) == new.as_ref().map(|entry| entry.id)
            && old.as_ref().map(|entry| entry.mode) == new.as_ref().map(|entry| entry.mode)
        {
            continue;
        }
        let mode_changed =
            old.as_ref().map(|entry| entry.mode) != new.as_ref().map(|entry| entry.mode);
        candidates.insert(
            path.to_vec(),
            Candidate {
                path: path.to_vec(),
                old: old.map(|entry| entry.id),
                new: new.map(|entry| entry.id),
                mode_changed,
                worktree: false,
            },
        );
        if candidates.len() > MAX_TREE_ENTRIES {
            return Err("too many diff entries".into());
        }
    }
    Ok(candidates.into_values().collect())
}

fn worktree_diff_candidates(
    repo: &gix::Repository,
    path_filter: Option<&[u8]>,
    entry_filter: Option<&str>,
    repository_filter: Option<&[u8]>,
) -> Result<Vec<Candidate>, Box<dyn std::error::Error>> {
    let index = repo.index_or_load_from_head_or_empty()?;
    let status = repo
        .status(gix::progress::Discard)?
        .untracked_files(gix::status::UntrackedFiles::None)
        .index_worktree_submodules(None)
        .into_iter(Vec::<BString>::new())?;
    let mut candidates = BTreeMap::<Vec<u8>, Candidate>::new();
    for item in status {
        let item = item?;
        let gix::status::Item::IndexWorktree(change) = item else {
            continue;
        };
        let summary = change.summary();
        let gix::status::index_worktree::Item::Modification {
            entry, rela_path, ..
        } = change
        else {
            continue;
        };
        use gix::status::index_worktree::iter::Summary;
        if summary.is_none_or(|summary| summary == Summary::IntentToAdd) {
            continue;
        }
        let path = rela_path.as_bytes();
        if !allowed_path(path)
            || !path_filter_matches(path, path_filter, entry_filter, repository_filter)
        {
            continue;
        }
        let old = entry.id;
        let mode_changed = summary == Some(Summary::TypeChange);
        candidates.insert(
            path.to_vec(),
            Candidate {
                path: path.to_vec(),
                old: Some(old),
                new: None,
                mode_changed,
                worktree: true,
            },
        );
        if candidates.len() > MAX_TREE_ENTRIES {
            return Err("too many diff entries".into());
        }
    }

    for candidate in candidates.values_mut() {
        let Some(index_entry) = index_entry(&index, &candidate.path) else {
            continue;
        };
        candidate.old = Some(index_entry.id);
        candidate.new = None;
    }
    Ok(candidates.into_values().collect())
}

fn worktree_bytes(path: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if !allowed_path(path) {
        return Err("unsafe repository path".into());
    }
    let mut full = std::path::PathBuf::from("/snapshot");
    for component in path.split(|byte| *byte == b'/') {
        let component = std::str::from_utf8(component).map_err(|_| "non-UTF-8 worktree path")?;
        full.push(component);
    }
    match std::fs::read(full) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::IsADirectory => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Copy)]
enum DiffLineError {
    NonText,
    TooLong,
}

fn clean_text_line(bytes: &[u8]) -> Result<String, DiffLineError> {
    let mut bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|_| DiffLineError::NonText)?;
    if text
        .chars()
        .any(|character| character.is_control() && character != '\t')
    {
        return Err(DiffLineError::NonText);
    }
    if text.len() > MAX_DIFF_LINE_BYTES {
        return Err(DiffLineError::TooLong);
    }
    Ok(text.to_owned())
}

#[derive(Clone)]
struct HunkRange {
    old_start: usize,
    old_end: usize,
    new_start: usize,
    new_end: usize,
    changes: Vec<gix::diff::blob::Hunk>,
}

fn diff_hunks(
    before: &[u8],
    after: &[u8],
    line_budget: &mut usize,
) -> Result<(bool, bool, Vec<Value>), Box<dyn std::error::Error>> {
    if before.len() > MAX_DIFF_BLOB_BYTES || after.len() > MAX_DIFF_BLOB_BYTES {
        return Ok((true, true, Vec::new()));
    }
    if before.contains(&0) || after.contains(&0) {
        return Ok((true, false, Vec::new()));
    }
    let before_lines = gix::diff::blob::sources::byte_lines(before);
    let after_lines = gix::diff::blob::sources::byte_lines(after);
    let input = gix::diff::blob::InternedInput::new(before_lines, after_lines);
    let mut diff = gix::diff::blob::Diff::compute(gix::diff::blob::Algorithm::Histogram, &input);
    diff.postprocess_lines(&input);
    let changes = diff.hunks().collect::<Vec<_>>();
    if changes.is_empty() {
        return Ok((false, false, Vec::new()));
    }

    let context = 3usize;
    let mut groups = Vec::<HunkRange>::new();
    for change in changes {
        let old_start = (change.before.start as usize).saturating_sub(context);
        let new_start = (change.after.start as usize).saturating_sub(context);
        let old_end = (change.before.end as usize + context).min(input.before.len());
        let new_end = (change.after.end as usize + context).min(input.after.len());
        if let Some(group) = groups.last_mut()
            && old_start <= group.old_end
        {
            group.old_end = old_end;
            group.new_end = new_end;
            group.changes.push(change);
        } else {
            groups.push(HunkRange {
                old_start,
                old_end,
                new_start,
                new_end,
                changes: vec![change],
            });
        }
    }

    let mut output = Vec::new();
    let mut truncated = false;
    let too_many_groups = groups.len() > MAX_DIFF_HUNKS;
    for group in groups.into_iter().take(MAX_DIFF_HUNKS) {
        if *line_budget == 0 {
            truncated = true;
            break;
        }
        let mut lines = Vec::<Value>::new();
        let mut old_position = group.old_start;
        let mut new_position = group.new_start;
        for change in &group.changes {
            let old_change_start = change.before.start as usize;
            let new_change_start = change.after.start as usize;
            let context_count = old_change_start.saturating_sub(old_position);
            for index in 0..context_count.min(new_change_start.saturating_sub(new_position)) {
                let old_line: &[u8] = input.interner[input.before[old_position + index]];
                let new_line: &[u8] = input.interner[input.after[new_position + index]];
                if old_line != new_line {
                    return Ok((false, true, Vec::new()));
                }
                let text = match clean_text_line(old_line) {
                    Ok(text) => text,
                    Err(DiffLineError::NonText) => return Ok((true, false, Vec::new())),
                    Err(DiffLineError::TooLong) => return Ok((false, true, Vec::new())),
                };
                if lines.len() >= 200 || *line_budget == 0 {
                    truncated = true;
                    break;
                }
                lines.push(json!({"kind": "context", "text": text}));
                *line_budget -= 1;
            }
            old_position = old_change_start + (change.before.end - change.before.start) as usize;
            new_position = new_change_start + (change.after.end - change.after.start) as usize;

            for token in &input.before[change.before.start as usize..change.before.end as usize] {
                if lines.len() >= 200 || *line_budget == 0 {
                    truncated = true;
                    break;
                }
                let text = match clean_text_line(input.interner[*token]) {
                    Ok(text) => text,
                    Err(DiffLineError::NonText) => return Ok((true, false, Vec::new())),
                    Err(DiffLineError::TooLong) => return Ok((false, true, Vec::new())),
                };
                lines.push(json!({"kind": "removed", "text": text}));
                *line_budget -= 1;
            }
            for token in &input.after[change.after.start as usize..change.after.end as usize] {
                if lines.len() >= 200 || *line_budget == 0 {
                    truncated = true;
                    break;
                }
                let text = match clean_text_line(input.interner[*token]) {
                    Ok(text) => text,
                    Err(DiffLineError::NonText) => return Ok((true, false, Vec::new())),
                    Err(DiffLineError::TooLong) => return Ok((false, true, Vec::new())),
                };
                lines.push(json!({"kind": "added", "text": text}));
                *line_budget -= 1;
            }
        }

        let old_context = group.old_end.saturating_sub(old_position);
        let new_context = group.new_end.saturating_sub(new_position);
        for index in 0..old_context.min(new_context) {
            if lines.len() >= 200 || *line_budget == 0 {
                truncated = true;
                break;
            }
            let old_line: &[u8] = input.interner[input.before[old_position + index]];
            let new_line: &[u8] = input.interner[input.after[new_position + index]];
            if old_line != new_line {
                return Ok((false, true, Vec::new()));
            }
            let text = match clean_text_line(old_line) {
                Ok(text) => text,
                Err(DiffLineError::NonText) => return Ok((true, false, Vec::new())),
                Err(DiffLineError::TooLong) => return Ok((false, true, Vec::new())),
            };
            lines.push(json!({"kind": "context", "text": text}));
            *line_budget -= 1;
        }
        let old_count = group.old_end.saturating_sub(group.old_start) as u64;
        let new_count = group.new_end.saturating_sub(group.new_start) as u64;
        output.push(json!({
            "oldStart": if old_count == 0 { group.old_start as u64 } else { group.old_start as u64 + 1 },
            "newStart": if new_count == 0 { group.new_start as u64 } else { group.new_start as u64 + 1 },
            "lines": lines,
        }));
    }
    truncated |= too_many_groups;
    Ok((false, truncated, output))
}

fn object_bytes(
    repo: &gix::Repository,
    id: Option<gix::ObjectId>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let Some(id) = id else {
        return Ok(None);
    };
    let object = repo.find_object(id)?;
    if object.kind != gix::object::Kind::Blob {
        return Ok(None);
    }
    Ok(Some(object.data.clone()))
}

fn build_diff_file(
    repo: &gix::Repository,
    candidate: Candidate,
    line_budget: &mut usize,
) -> Result<Value, Box<dyn std::error::Error>> {
    let before = object_bytes(repo, candidate.old)?;
    let after = if candidate.worktree {
        worktree_bytes(&candidate.path)?
    } else {
        object_bytes(repo, candidate.new)?
    };
    let (binary, truncated, hunks) = if candidate.mode_changed && candidate.old == candidate.new {
        (false, false, Vec::new())
    } else {
        diff_hunks(
            before.as_deref().unwrap_or_default(),
            after.as_deref().unwrap_or_default(),
            line_budget,
        )?
    };
    if candidate.path.is_empty() {
        return Err("missing diff path".into());
    }
    Ok(json!({
        "pathHex": decode_hex(&candidate.path),
        "binary": binary,
        "hunks": hunks,
        "truncated": truncated,
    }))
}

fn tree_entries(
    tree: &gix::Tree<'_>,
) -> Result<BTreeMap<Vec<u8>, TreeEntry>, Box<dyn std::error::Error>> {
    let entries = tree.traverse().breadthfirst.files()?;
    if entries.len() > MAX_TREE_ENTRIES {
        return Err("too many tree entries".into());
    }
    Ok(entries
        .into_iter()
        .filter(|entry| allowed_path(entry.filepath.as_ref()))
        .map(|entry| {
            (
                entry.filepath.into(),
                TreeEntry {
                    id: entry.oid,
                    mode: entry.mode.kind(),
                },
            )
        })
        .collect())
}

fn tree_diff_candidates(
    repo: &gix::Repository,
    old_tree: &gix::Tree<'_>,
    new_tree: &gix::Tree<'_>,
    path_filter: Option<&[u8]>,
    entry_filter: Option<&str>,
    repository_filter: Option<&[u8]>,
) -> Result<Vec<Candidate>, Box<dyn std::error::Error>> {
    let old = tree_entries(old_tree)?;
    let new = tree_entries(new_tree)?;
    let paths = old
        .keys()
        .chain(new.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut candidates = Vec::new();
    for path in paths {
        if !path_filter_matches(&path, path_filter, entry_filter, repository_filter) {
            continue;
        }
        let before = old.get(&path);
        let after = new.get(&path);
        if before.map(|entry| entry.id) == after.map(|entry| entry.id)
            && before.map(|entry| entry.mode) == after.map(|entry| entry.mode)
        {
            continue;
        }
        let mode_changed = before.map(|entry| entry.mode) != after.map(|entry| entry.mode);
        candidates.push(Candidate {
            path,
            old: before.map(|entry| entry.id),
            new: after.map(|entry| entry.id),
            mode_changed,
            worktree: false,
        });
        if candidates.len() > MAX_TREE_ENTRIES {
            return Err("too many diff entries".into());
        }
    }
    let _ = repo;
    Ok(candidates)
}

fn diff_request(
    request: &Value,
    repo: &gix::Repository,
) -> Result<Value, Box<dyn std::error::Error>> {
    let object = request.as_object().ok_or("request must be object")?;
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("missing operation")?;
    let offset = integer(request, "offset", 0, MAX_OFFSET)?;
    let limit = integer(request, "limit", 1, MAX_LIMIT)?;
    let path_filter = request
        .get("filterPathHex")
        .and_then(Value::as_str)
        .map(decode_path_hex)
        .transpose()?;
    let entry_filter = request.get("filterEntryId").and_then(Value::as_str);
    let repository_filter = request
        .get("repositoryId")
        .and_then(Value::as_str)
        .map(|value| decode_hex_bytes(value, 16))
        .transpose()?;

    let (candidates, show_commit) = match operation {
        "diff" => {
            let candidates = match request.get("view").and_then(Value::as_str) {
                Some("index") => index_diff_candidates(
                    repo,
                    path_filter.as_deref(),
                    entry_filter,
                    repository_filter.as_deref(),
                )?,
                Some("worktree") => worktree_diff_candidates(
                    repo,
                    path_filter.as_deref(),
                    entry_filter,
                    repository_filter.as_deref(),
                )?,
                _ => return Err("invalid diff view".into()),
            };
            (candidates, None)
        }
        "show" => {
            let id_text = request
                .get("objectId")
                .and_then(Value::as_str)
                .ok_or("missing object id")?;
            let id =
                gix::ObjectId::from_hex(id_text.as_bytes()).map_err(|_| "invalid object id")?;
            if id.kind() != repo.object_hash() {
                return Err("object hash kind mismatch".into());
            }
            let commit = repo
                .find_object(id)?
                .try_into_commit()
                .map_err(|_| "object is not a commit")?;
            let commit_summary = commit_summary(repo, id)?;
            let new_tree = commit.tree()?;
            let parent_tree = match commit.parent_ids().next() {
                Some(parent) => parent
                    .object()?
                    .try_into_commit()
                    .map_err(|_| "parent is not a commit")?
                    .tree()?,
                None => repo.empty_tree(),
            };
            (
                tree_diff_candidates(
                    repo,
                    &parent_tree,
                    &new_tree,
                    path_filter.as_deref(),
                    entry_filter,
                    repository_filter.as_deref(),
                )?,
                Some(commit_summary),
            )
        }
        _ => return Err("unsupported diff request".into()),
    };

    let total = candidates.len();
    let mut line_budget = MAX_DIFF_LINES;
    let mut files = Vec::new();
    for candidate in candidates.into_iter().skip(offset).take(limit) {
        files.push(build_diff_file(repo, candidate, &mut line_budget)?);
    }
    let truncated = offset.saturating_add(files.len()) < total;
    Ok(match show_commit {
        Some(commit) => json!({
            "commit": commit,
            "files": files,
            "truncated": truncated,
            "total": total,
        }),
        None => json!({
            "files": files,
            "truncated": truncated,
            "total": total,
        }),
    })
}

fn clean_git_text(bytes: &[u8], max_bytes: usize) -> String {
    let mut output = String::new();
    for character in String::from_utf8_lossy(bytes).chars() {
        let character = if character.is_control() && character != '\t' {
            '�'
        } else {
            character
        };
        if output.len() + character.len_utf8() > max_bytes {
            break;
        }
        output.push(character);
    }
    output
}

fn commit_summary(
    repo: &gix::Repository,
    id: gix::ObjectId,
) -> Result<Value, Box<dyn std::error::Error>> {
    let commit = repo
        .find_object(id)?
        .try_into_commit()
        .map_err(|_| "object is not a commit")?;
    let subject = commit
        .message()
        .map_err(|_| "invalid commit message")?
        .title;
    let author = commit.author().map_err(|_| "invalid commit author")?;
    let mut author_text = clean_git_text(author.name.as_bytes(), 1024);
    if !author.email.is_empty() {
        author_text.push_str(" <");
        author_text.push_str(&clean_git_text(author.email.as_bytes(), 1024));
        author_text.push('>');
    }
    let timestamp = commit.time()?.seconds.max(0) as u64;
    Ok(json!({
        "objectId": id.to_string(),
        "subject": clean_git_text(subject.as_bytes(), 4096),
        "author": author_text,
        "timestampSeconds": timestamp,
    }))
}

fn log_request(
    request: &Value,
    repo: &gix::Repository,
) -> Result<Value, Box<dyn std::error::Error>> {
    let object = request.as_object().ok_or("request must be object")?;
    if object.len() != 3 || object.get("operation").and_then(Value::as_str) != Some("log") {
        return Err("unsupported log request".into());
    }
    let offset = integer(request, "offset", 0, MAX_OFFSET)?;
    let limit = integer(request, "limit", 1, MAX_LIMIT)?;
    let mut commits = Vec::new();
    let mut total = 0usize;
    let mut truncated = false;
    if let Ok(head) = repo.head_id() {
        if let Ok(head_object) = head.object() {
            if let Ok(head_commit) = head_object.try_into_commit() {
                let mut walk = repo.rev_walk([head_commit.id]).all()?;
                for info in &mut walk {
                    let info = info?;
                    if total >= MAX_OFFSET {
                        truncated = true;
                        break;
                    }
                    if total >= offset && commits.len() < limit {
                        commits.push(commit_summary(repo, info.id)?);
                    } else if total == offset + limit {
                        truncated = true;
                        break;
                    }
                    total += 1;
                }
            }
        }
    }
    Ok(json!({
        "commits": commits,
        "truncated": truncated,
        "total": total,
    }))
}

fn mutation_paths(
    request: &Value,
    operation: &str,
) -> Result<Vec<(Vec<u8>, bool)>, Box<dyn std::error::Error>> {
    let object = request.as_object().ok_or("request must be object")?;
    if object.len() != 2 || object.get("operation").and_then(Value::as_str) != Some(operation) {
        return Err("unsupported mutation request".into());
    }
    let paths = object
        .get("paths")
        .and_then(Value::as_array)
        .filter(|paths| !paths.is_empty() && paths.len() <= 200)
        .ok_or("invalid mutation paths")?;
    let mut seen = BTreeSet::new();
    paths
        .iter()
        .map(|value| {
            let (path, executable) = if operation == "stage" {
                let row = value.as_object().ok_or("invalid stage path")?;
                if row.len() != 2 {
                    return Err("invalid stage path".into());
                }
                let path = row
                    .get("pathHex")
                    .and_then(Value::as_str)
                    .ok_or("invalid stage path")?;
                let executable = row
                    .get("executable")
                    .and_then(Value::as_bool)
                    .ok_or("invalid stage mode")?;
                (decode_path_hex(path)?, executable)
            } else {
                let path = value.as_str().ok_or("invalid unstage path")?;
                (decode_path_hex(path)?, false)
            };
            if !allowed_path(&path) || !seen.insert(path.clone()) {
                return Err("unsafe or duplicate mutation path".into());
            }
            Ok((path, executable))
        })
        .collect()
}

fn write_private_index(
    repo: &gix::Repository,
    index: &gix::index::File,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    index
        .write_to(&mut bytes, Default::default())
        .map_err(|_| std::io::Error::other("could not encode private Git index"))?;
    std::fs::write(repo.index_path(), bytes)?;
    Ok(())
}

fn stage_request(
    request: &Value,
    repo: &gix::Repository,
) -> Result<Value, Box<dyn std::error::Error>> {
    let paths = mutation_paths(request, "stage")?;
    let mut index = repo.index_or_load_from_head_or_empty()?.into_owned();
    let mut object_ids = Vec::new();
    for (path, executable) in paths {
        let path_text = std::str::from_utf8(&path).map_err(|_| "non-UTF-8 worktree path")?;
        let source = std::path::Path::new("/snapshot").join(path_text);
        let blob = match std::fs::symlink_metadata(&source) {
            Ok(metadata) if metadata.is_file() => Some(std::fs::read(source)?),
            Ok(_) => return Err("unsupported worktree entry".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };

        index.remove_entries(|_, entry_path, _| entry_path.as_bytes() == path.as_slice());
        if let Some(blob) = blob {
            let object_id = repo.write_blob(&blob)?.detach();
            object_ids.push(object_id.to_string());
            let mode = if executable {
                gix::index::entry::Mode::FILE_EXECUTABLE
            } else {
                gix::index::entry::Mode::FILE
            };
            let flags = gix::index::entry::Flags::from_bits_retain(path.len() as u32);
            index.dangerously_push_entry(
                Default::default(),
                object_id,
                flags,
                mode,
                path.as_bstr(),
            );
        }
    }
    index.remove_tree();
    index.sort_entries();
    write_private_index(repo, &index)?;
    Ok(json!({ "objectIds": object_ids }))
}

fn unstage_request(
    request: &Value,
    repo: &gix::Repository,
) -> Result<Value, Box<dyn std::error::Error>> {
    let paths = mutation_paths(request, "unstage")?
        .into_iter()
        .map(|(path, _)| path)
        .collect::<Vec<_>>();
    let mut index = repo.index_or_load_from_head_or_empty()?.into_owned();
    let head_tree = repo
        .head_tree_id()
        .map(|id| id.detach())
        .unwrap_or_else(|_| repo.empty_tree().id().detach());
    let head_index = repo.index_from_tree(&head_tree)?;

    for path in paths {
        let head_entry = head_index
            .entry_by_path_and_stage(path.as_bstr(), gix::index::entry::Stage::Unconflicted)
            .map(|entry| {
                (
                    entry.stat,
                    entry.id,
                    entry.flags,
                    entry.mode,
                    entry.path(&head_index).to_owned(),
                )
            });
        index.remove_entries(|_, entry_path, _| entry_path.as_bytes() == path.as_slice());
        if let Some((stat, id, flags, mode, entry_path)) = head_entry {
            index.dangerously_push_entry(stat, id, flags, mode, entry_path.as_bstr());
        }
    }
    index.remove_tree();
    index.sort_entries();
    write_private_index(repo, &index)?;
    Ok(json!({ "objectIds": Vec::<String>::new() }))
}

fn loose_object_ids() -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let object_dir = std::path::Path::new("/snapshot/.git/objects");
    let mut ids = BTreeSet::new();
    for prefix in std::fs::read_dir(object_dir)? {
        let prefix = prefix?;
        let prefix_name = prefix.file_name();
        let Some(prefix_text) = prefix_name.to_str() else {
            continue;
        };
        if prefix_text.len() != 2
            || !prefix_text.bytes().all(|byte| byte.is_ascii_hexdigit())
            || prefix_text.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            continue;
        }
        let prefix_type = std::fs::symlink_metadata(prefix.path())?.file_type();
        if prefix_type.is_symlink() {
            return Err("unsafe object directory".into());
        }
        if !prefix_type.is_dir() {
            continue;
        }
        for object in std::fs::read_dir(prefix.path())? {
            let object = object?;
            let suffix_name = object.file_name();
            let Some(suffix) = suffix_name.to_str() else {
                continue;
            };
            let id = format!("{prefix_text}{suffix}");
            if !matches!(id.len(), 40 | 64)
                || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
                || id.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                continue;
            }
            let file_type = std::fs::symlink_metadata(object.path())?.file_type();
            if file_type.is_symlink() || !file_type.is_file() {
                return Err("unsafe loose object entry".into());
            }
            ids.insert(id);
            if ids.len() > MAX_COMMIT_OBJECTS * 4 {
                return Err("too many loose objects".into());
            }
        }
    }
    Ok(ids)
}

fn commit_request(
    request: &Value,
    repo: &gix::Repository,
) -> Result<Value, Box<dyn std::error::Error>> {
    let object = request.as_object().ok_or("request must be object")?;
    if object.len() != 4 || object.get("operation").and_then(Value::as_str) != Some("commit") {
        return Err("unsupported request".into());
    }
    let message = request
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| {
            !message.is_empty()
                && message.len() <= 16_384
                && !message.chars().any(|character| {
                    character == '\0'
                        || (character.is_control() && character != '\n' && character != '\t')
                })
        })
        .ok_or("invalid commit message")?;
    let timestamp_seconds = request
        .get("timestampSeconds")
        .and_then(Value::as_i64)
        .filter(|timestamp| *timestamp >= 0)
        .ok_or("invalid commit timestamp")?;

    // `Options::isolated()` loads only repository-local configuration and
    // disables include files and all process/user/system configuration.
    let config = repo.config_snapshot();
    let (Some(name), Some(email)) = (config.string("user.name"), config.string("user.email"))
    else {
        return Ok(json!({ "errorCode": "identityRequired" }));
    };
    if name.is_empty()
        || email.is_empty()
        || [&name, &email].iter().any(|value| {
            value
                .as_bstr()
                .as_bytes()
                .iter()
                .any(|byte| *byte == b'\r' || (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
        })
    {
        return Ok(json!({ "errorCode": "identityRequired" }));
    }
    let identity = gix::actor::Identity { name, email };
    if identity.write_to(&mut Vec::new()).is_err() {
        return Ok(json!({ "errorCode": "identityRequired" }));
    }
    let signature_time = format!("{timestamp_seconds} +0000");
    let signature = gix::actor::SignatureRef {
        name: identity.name.as_bstr(),
        email: identity.email.as_bstr(),
        time: &signature_time,
    };

    let before = loose_object_ids()?;
    let index = repo.index_or_load_from_head_or_empty()?.into_owned();
    if index.entries().len() > MAX_TREE_ENTRIES {
        return Err("too many index entries".into());
    }
    let mut checked_objects = HashSet::new();
    let mut tree_editor = repo.empty_tree().edit()?;
    for entry in index.entries() {
        if entry.stage() != gix::index::entry::Stage::Unconflicted {
            return Err("cannot commit an unmerged index".into());
        }
        let path = entry.path(&index);
        if !allowed_path(path.as_bytes()) {
            return Err("unsafe index path".into());
        }
        let mode = entry
            .mode
            .to_tree_entry_mode()
            .ok_or("invalid index mode")?;
        let kind = mode.kind();
        if kind != gix::object::tree::EntryKind::Commit && checked_objects.insert(entry.id) {
            let stored = repo.find_object(entry.id)?;
            let expected_kind = if kind == gix::object::tree::EntryKind::Tree {
                gix::object::Kind::Tree
            } else {
                gix::object::Kind::Blob
            };
            if stored.kind != expected_kind {
                return Err("index object has invalid kind".into());
            }
        }
        tree_editor.upsert(path, kind, entry.id)?;
    }
    let tree_id = tree_editor.write()?.detach();

    let head = repo.head()?;
    let (parents, parent_tree) = match head.id() {
        Some(id) => {
            let parent_id = id.detach();
            let parent = repo
                .find_object(parent_id)?
                .try_into_commit()
                .map_err(|_| "HEAD does not point to a commit")?;
            let tree = parent
                .tree_id()
                .map_err(|_| "invalid parent tree")?
                .detach();
            (vec![parent_id], Some(tree))
        }
        None => (Vec::new(), None),
    };
    if parent_tree == Some(tree_id)
        || (parents.is_empty() && tree_id == repo.empty_tree().id().detach())
    {
        return Err("nothing staged to commit".into());
    }

    let commit = repo.new_commit_as(signature, signature, message, tree_id, parents)?;
    let commit_id = commit.id.to_string();
    let after = loose_object_ids()?;
    let object_ids = after.difference(&before).cloned().collect::<Vec<_>>();
    if object_ids.len() > MAX_COMMIT_OBJECTS || !object_ids.contains(&commit_id) {
        return Err("commit object set exceeded limits".into());
    }
    Ok(json!({
        "objectIds": object_ids,
        "commitId": commit_id,
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request = read_request()?;
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("missing operation")?;
    let owner_context = if matches!(operation, "selectedChange" | "restoreIndex") {
        Some(read_owner_local_context()?)
    } else {
        None
    };
    let open_options = if owner_context.is_some() {
        // The flattened private snapshot is the worktree. Never follow a
        // captured source core.worktree path outside this WASI preopen, and
        // treat its symlink blobs as materialized regular files.
        let mut permissions = gix::open::Permissions::isolated();
        // The WASI invocation receives only this fixed GIT_WORK_TREE value;
        // no host environment is inherited. gix treats it as an EnvOverride,
        // which the repository opener accepts over repository-local values.
        permissions.env.git_prefix = gix::sec::Permission::Allow;
        gix::open::Options::isolated()
            .permissions(permissions)
            .config_overrides([
                "core.worktree=/snapshot",
                "core.bare=false",
                "core.symlinks=false",
            ])
    } else {
        gix::open::Options::isolated()
    };
    let repository = gix::open_opts("/snapshot", open_options)?;
    let result = match operation {
        "status" => status_request(&request, &repository)?,
        "selectedChange" => selected_change_request(
            &request,
            &repository,
            owner_context.as_ref().ok_or("missing owner context")?,
        )?,
        "restoreIndex" => restore_index_request(
            &request,
            &repository,
            owner_context.as_ref().ok_or("missing owner context")?,
        )?,
        "diff" | "show" => diff_request(&request, &repository)?,
        "log" => log_request(&request, &repository)?,
        "stage" => stage_request(&request, &repository)?,
        "unstage" => unstage_request(&request, &repository)?,
        "commit" => commit_request(&request, &repository)?,
        _ => return Err("unsupported operation".into()),
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &result)?;
    stdout.write_all(b"\n")?;
    Ok(())
}
