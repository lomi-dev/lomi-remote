//! Owner-local Explorer Git mutations.
//!
//! This module deliberately stays outside the remote Git DTO and mutation
//! paths. It prepares one selected-path operation in a private snapshot, then
//! publishes through FileRoot while retaining the common-directory lease.

use super::*;
use lomi_files::desktop::{
    DesktopFileChange, DesktopFileErrorCode, DesktopFileOperation, DesktopMutationError,
    DesktopMutationRequest, validate_desktop_request,
};
use lomi_files::{
    GitDesktopFilePublication, GitIgnorePublication, GitIgnoreTarget, GitPullPrecondition,
    LocalNativeFileCheckPhase, OwnerGitDesktopFilePublication, OwnerGitIgnorePublication,
    OwnerGitIgnoreTarget, OwnerGitMetadataCondition, OwnerGitMetadataEntry, OwnerGitMetadataPath,
    OwnerGitMetadataRole, OwnerGitMetadataRoot, OwnerGitMetadataVersion,
};
use std::io::{Read, Write};

const MAX_IGNORE_BYTES: usize = 1024 * 1024;
const MAX_RESTORE_BYTES: u64 = 256 * 1024 * 1024;
const DESKTOP_READ_CHUNK: usize = 64 * 1024;
const MAX_OWNER_CONTEXT_BYTES: usize = 4 * 1024 * 1024 + 4096;

struct OwnerLocalSnapshot {
    snapshot: PrivateSnapshot,
    worktree_entries: Vec<SnapshotEntry>,
    common_entries: Vec<SnapshotEntry>,
    gitdir_entries: Vec<SnapshotEntry>,
}

enum DesktopRepository {
    Confined(Repository),
    External(ExternalDesktopRepository),
}

struct ExternalDesktopRepository {
    id: RepositoryId,
    entry: EntryRef,
    root_meta: Meta,
    path: RelPath,
    git_marker: Meta,
    git_dir: Arc<OwnerGitMetadataRoot>,
    common_dir: Arc<OwnerGitMetadataRoot>,
    common_identity: FileIdentity,
    commondir_condition: OwnerGitMetadataCondition,
}

struct ExternalOwnerSnapshot {
    snapshot: PrivateSnapshot,
    common_entries: Vec<OwnerMetadataSnapshotEntry>,
    gitdir_entries: Vec<OwnerMetadataSnapshotEntry>,
}

#[derive(Clone)]
struct OwnerMetadataSnapshotEntry {
    path: RelPath,
    source_path: OwnerGitMetadataPath,
    kind: Kind,
    size: u64,
    revision: String,
    nlink: u64,
    role: OwnerGitMetadataRole,
}

impl DesktopRepository {
    fn id(&self) -> RepositoryId {
        match self {
            Self::Confined(repository) => repository.id,
            Self::External(repository) => repository.id,
        }
    }

    fn common_identity(&self) -> &FileIdentity {
        match self {
            Self::Confined(repository) => &repository.common_identity,
            Self::External(repository) => &repository.common_identity,
        }
    }
}

fn discover_desktop_repository(
    service: &GitService,
    requested_path: &RelPath,
    host_protected: &[&Path],
    control: &RequestControl,
) -> Result<DesktopRepository, DesktopMutationError> {
    check_control(control)?;
    let root_meta = service
        .lookup_path(requested_path, control)
        .map_err(map_service_error)?;
    if root_meta.kind != Kind::Directory {
        return Err(DesktopFileErrorCode::NotFound.into());
    }
    let marker = service
        .lookup_optional_child(root_meta.entry, requested_path, b".git", control)
        .map_err(map_service_error)?
        .ok_or(DesktopFileErrorCode::NotFound)?;
    if !matches!(marker.kind, Kind::File | Kind::Directory)
        || (marker.kind == Kind::File && marker.nlink != 1)
    {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let marker_text = if marker.kind == Kind::File {
        Some(service.read_pointer(&marker).map_err(map_service_error)?)
    } else {
        None
    };
    let repo_host_path = requested_path
        .to_host_path(&service.root_path)
        .map_err(map_service_error)?;
    let marker_host_path = requested_path
        .joined(b".git")
        .to_host_path(&service.root_path)
        .map_err(map_service_error)?;
    service
        .files
        .protect(&marker_host_path)
        .map_err(map_file_error_to_desktop)?;

    let (gitdir_relative, gitdir_host, mut requires_owner_adapter) =
        if marker.kind == Kind::Directory {
            (
                Some(requested_path.joined(b".git")),
                marker_host_path.clone(),
                false,
            )
        } else {
            let target = parse_pointer(
                marker_text
                    .as_deref()
                    .ok_or(DesktopFileErrorCode::Changed)?,
                "gitdir: ",
            )
            .map_err(map_service_error)?;
            let requires_owner_adapter = pointer_has_parent_component(target);
            (
                pointer_relative_path(service, requested_path, target),
                pointer_host_path(&repo_host_path, target),
                requires_owner_adapter,
            )
        };
    if let Some(gitdir_relative) = &gitdir_relative {
        if let Ok(gitdir) = service.lookup_path(&gitdir_relative, control) {
            if gitdir.kind != Kind::Directory {
                return Err(DesktopFileErrorCode::Protected.into());
            }
            let commondir_marker = service
                .lookup_optional_child(gitdir.entry, &gitdir_relative, b"commondir", control)
                .map_err(map_service_error)?;
            let (common_path, commondir_marker) = match commondir_marker {
                Some(marker) => {
                    if marker.kind != Kind::File || marker.nlink != 1 {
                        return Err(DesktopFileErrorCode::Protected.into());
                    }
                    let pointer = service.read_pointer(&marker).map_err(map_service_error)?;
                    let target = parse_pointer(&pointer, "").map_err(map_service_error)?;
                    requires_owner_adapter |= pointer_has_parent_component(target);
                    (
                        pointer_relative_path(service, gitdir_relative, target),
                        Some(marker),
                    )
                }
                None => (Some(gitdir_relative.clone()), None),
            };
            if let Some(common_path) = common_path.filter(|_| !requires_owner_adapter) {
                if let Ok(common) = service.lookup_path(&common_path, control) {
                    if common.kind != Kind::Directory {
                        return Err(DesktopFileErrorCode::Protected.into());
                    }
                    let gitdir_host = gitdir_relative
                        .to_host_path(&service.root_path)
                        .map_err(map_service_error)?;
                    let common_host = common_path
                        .to_host_path(&service.root_path)
                        .map_err(map_service_error)?;
                    service
                        .files
                        .protect(&gitdir_host)
                        .and_then(|()| service.files.protect(&common_host))
                        .map_err(map_file_error_to_desktop)?;
                    service
                        .revalidate_entry(&root_meta, control)
                        .and_then(|()| service.revalidate_entry(&marker, control))
                        .and_then(|()| service.revalidate_entry(&gitdir, control))
                        .and_then(|()| service.revalidate_entry(&common, control))
                        .map_err(map_service_error)?;
                    if let Some(marker) = commondir_marker.as_ref() {
                        service
                            .revalidate_entry(marker, control)
                            .map_err(map_service_error)?;
                    }
                    let gitdir_identity = path_identity(&gitdir_host).map_err(map_service_error)?;
                    let common_identity = path_identity(&common_host).map_err(map_service_error)?;
                    let id = repository_id(&gitdir_identity, &common_identity);
                    return Ok(DesktopRepository::Confined(Repository {
                        id,
                        entry: root_meta.entry,
                        root_meta,
                        path: requested_path.clone(),
                        git_marker: marker,
                        gitdir_path: gitdir_relative.clone(),
                        gitdir,
                        commondir_marker,
                        common_path,
                        commondir: common,
                        gitdir_identity,
                        common_identity,
                    }));
                }
            }
        }
    }

    let gitdir_expected = gitdir_relative
        .as_ref()
        .and_then(|path| service.lookup_path(path, control).ok())
        .filter(|meta| meta.kind == Kind::Directory)
        .map(|meta| meta.entry);
    let marker_kind = git_pull_kind(marker.kind)?;
    let marker_condition = GitPullPrecondition {
        parent: root_meta.entry,
        name: b".git".to_vec(),
        entry: Some(marker.entry),
        revision: Some(marker.revision.clone()),
        kind: Some(marker_kind),
    };
    let git_dir = Arc::new(
        OwnerGitMetadataRoot::open_from_workspace_git_marker(
            &gitdir_host,
            OwnerGitMetadataRole::GitDir,
            &service.files,
            &service.root_path,
            root_meta.entry,
            &repo_host_path,
            &marker_condition,
            gitdir_expected,
            host_protected,
        )
        .map_err(map_file_error_to_desktop)?,
    );
    let gitdir_meta = owner_metadata_root_entry(&git_dir, control)?;
    if gitdir_meta.kind != Kind::Directory {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let commondir = owner_metadata_child(&git_dir, b"commondir", control)?;
    let (commondir_condition, common_dir) = match commondir {
        Some(entry) => {
            if entry.kind != Kind::File
                || entry.nlink != 1
                || entry.size == 0
                || entry.size > MAX_GIT_POINTER_BYTES as u64
            {
                return Err(DesktopFileErrorCode::Protected.into());
            }
            let pointer = read_owner_metadata_file(
                &git_dir,
                &OwnerGitMetadataPath::from_components(vec![b"commondir".to_vec()])
                    .map_err(map_file_error_to_desktop)?,
                &entry.revision,
                MAX_GIT_POINTER_BYTES,
                control,
            )?;
            let pointer =
                String::from_utf8(pointer).map_err(|_| DesktopFileErrorCode::Protected)?;
            let target = parse_pointer(&pointer, "").map_err(map_service_error)?;
            let condition = owner_condition(
                OwnerGitMetadataRole::GitDir,
                vec![b"commondir".to_vec()],
                Some(&entry),
            )?;
            let common_host = pointer_host_path(git_dir.canonical_path(), target);
            let common = OwnerGitMetadataRoot::open_from_commondir_pointer(
                &common_host,
                &service.root_path,
                host_protected,
                &git_dir,
                &condition,
            )
            .map_err(map_file_error_to_desktop)?;
            (condition, Some(common))
        }
        None => (
            owner_condition(
                OwnerGitMetadataRole::GitDir,
                vec![b"commondir".to_vec()],
                None,
            )?,
            None,
        ),
    };
    let common_dir = Arc::new(match common_dir {
        Some(common_dir) => common_dir,
        None => OwnerGitMetadataRoot::open_from_workspace_git_marker(
            &gitdir_host,
            OwnerGitMetadataRole::CommonDir,
            &service.files,
            &service.root_path,
            root_meta.entry,
            &repo_host_path,
            &marker_condition,
            gitdir_expected,
            host_protected,
        )
        .map_err(map_file_error_to_desktop)?,
    });
    service
        .files
        .protect(git_dir.canonical_path())
        .and_then(|()| service.files.protect(common_dir.canonical_path()))
        .map_err(map_file_error_to_desktop)?;
    let common_meta = owner_metadata_root_entry(&common_dir, control)?;
    if common_meta.kind != Kind::Directory {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    service
        .revalidate_entry(&root_meta, control)
        .and_then(|()| service.revalidate_entry(&marker, control))
        .map_err(map_service_error)?;
    let gitdir_identity = FileIdentity(git_dir.physical_identity().to_vec());
    let common_identity = FileIdentity(common_dir.physical_identity().to_vec());
    let id = repository_id(&gitdir_identity, &common_identity);
    Ok(DesktopRepository::External(ExternalDesktopRepository {
        id,
        entry: root_meta.entry,
        root_meta,
        path: requested_path.clone(),
        git_marker: marker,
        git_dir,
        common_dir,
        common_identity,
        commondir_condition,
    }))
}

fn pointer_relative_path(service: &GitService, base: &RelPath, target: &str) -> Option<RelPath> {
    if let Ok(relative) = base.resolve_relative(target) {
        return Some(relative);
    }
    let target_path = Path::new(target);
    if !target_path.is_absolute() {
        return None;
    }
    host_relative_path(&service.root_path, target_path)
}

fn pointer_has_parent_component(target: &str) -> bool {
    Path::new(target)
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn host_relative_path(root: &Path, path: &Path) -> Option<RelPath> {
    let relative = path.strip_prefix(root).ok()?;
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop()?;
            }
            std::path::Component::Normal(name) => {
                #[cfg(unix)]
                let bytes = {
                    use std::os::unix::ffi::OsStrExt;
                    name.as_bytes().to_vec()
                };
                #[cfg(windows)]
                let bytes = name.to_str()?.as_bytes().to_vec();
                #[cfg(not(any(unix, windows)))]
                let bytes = name.to_str()?.as_bytes().to_vec();
                components.push(bytes);
            }
            std::path::Component::Prefix(_) | std::path::Component::RootDir => return None,
        }
    }
    (!components.is_empty()).then_some(RelPath(components))
}

fn pointer_host_path(base: &Path, target: &str) -> PathBuf {
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        target_path.to_path_buf()
    } else {
        base.join(target_path)
    }
}

fn owner_metadata_root_entry(
    root: &OwnerGitMetadataRoot,
    control: &RequestControl,
) -> Result<OwnerGitMetadataEntry, DesktopMutationError> {
    check_control(control)?;
    root.revalidate_binding()
        .map_err(map_file_error_to_desktop)?;
    Ok(OwnerGitMetadataEntry {
        path: OwnerGitMetadataPath::root(),
        kind: Kind::Directory,
        size: 0,
        revision: String::new(),
        nlink: 1,
    })
}

fn owner_metadata_child(
    root: &OwnerGitMetadataRoot,
    name: &[u8],
    control: &RequestControl,
) -> Result<Option<OwnerGitMetadataEntry>, DesktopMutationError> {
    check_control(control)?;
    Ok(root
        .list(&OwnerGitMetadataPath::root())
        .map_err(map_file_error_to_desktop)?
        .into_iter()
        .find(|entry| entry.path.components() == [name.to_vec()]))
}

fn owner_condition(
    role: OwnerGitMetadataRole,
    path: Vec<Vec<u8>>,
    entry: Option<&OwnerGitMetadataEntry>,
) -> Result<OwnerGitMetadataCondition, DesktopMutationError> {
    Ok(OwnerGitMetadataCondition {
        role,
        path: OwnerGitMetadataPath::from_components(path).map_err(map_file_error_to_desktop)?,
        expected: entry.map(|entry| OwnerGitMetadataVersion {
            kind: entry.kind,
            revision: entry.revision.clone(),
            size: entry.size,
            nlink: entry.nlink,
        }),
    })
}

fn read_owner_metadata_file(
    root: &OwnerGitMetadataRoot,
    path: &OwnerGitMetadataPath,
    revision: &str,
    maximum: usize,
    control: &RequestControl,
) -> Result<Vec<u8>, DesktopMutationError> {
    check_control(control)?;
    let mut bytes = Vec::new();
    let mut offset = 0u64;
    loop {
        let chunk = root
            .read_chunk(path, revision, offset, maximum.min(DESKTOP_READ_CHUNK))
            .map_err(map_file_error_to_desktop)?;
        if chunk.revision != revision || chunk.size > maximum as u64 {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        bytes.extend_from_slice(&chunk.bytes);
        offset = offset.saturating_add(chunk.bytes.len() as u64);
        if !chunk.truncated {
            break;
        }
        if bytes.len() >= maximum {
            return Err(DesktopFileErrorCode::Limit.into());
        }
    }
    Ok(bytes)
}

fn create_external_owner_snapshot(
    service: &GitService,
    repository: &ExternalDesktopRepository,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<ExternalOwnerSnapshot, DesktopMutationError> {
    check_control(control)?;
    service
        .revalidate_entry(&repository.root_meta, control)
        .and_then(|()| service.revalidate_entry(&repository.git_marker, control))
        .map_err(map_service_error)?;
    repository
        .git_dir
        .revalidate_binding()
        .and_then(|()| repository.common_dir.revalidate_binding())
        .and_then(|()| repository.git_dir.check(&repository.commondir_condition))
        .map_err(map_file_error_to_desktop)?;

    let mut worktree_entries = Vec::new();
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    service
        .collect_snapshot_entries(
            repository.entry,
            RelPath::root(),
            0,
            &mut count,
            &mut total_bytes,
            &mut worktree_entries,
            control,
        )
        .map_err(map_service_error)?;

    let same_git_directory =
        repository.git_dir.physical_identity() == repository.common_dir.physical_identity();
    let separate_worktree_gitdir = !same_git_directory;
    let common_entries = collect_owner_metadata_tree(
        &repository.common_dir,
        OwnerGitMetadataRole::CommonDir,
        &mut count,
        &mut total_bytes,
        false,
        control,
    )?;
    let gitdir_entries = collect_owner_metadata_tree(
        &repository.git_dir,
        OwnerGitMetadataRole::GitDir,
        &mut count,
        &mut total_bytes,
        false,
        control,
    )?;
    validate_owner_metadata_entries(&common_entries)?;
    validate_owner_metadata_entries(&gitdir_entries)?;
    let mut worktree_file_paths = HashSet::with_capacity(worktree_entries.len());
    for worktree in &worktree_entries {
        check_control(control)?;
        if worktree.meta.kind == Kind::File {
            worktree_file_paths.insert((&worktree.path, worktree.meta.size));
        }
    }
    account_copied_owner_metadata_bytes(
        service,
        repository,
        &repository.common_dir,
        &common_entries,
        &worktree_file_paths,
        &mut total_bytes,
        control,
        |entry| {
            !(separate_worktree_gitdir && is_worktree_local_git_path(&entry.path))
                && !is_root_git_pointer(&entry.path)
        },
    )?;
    if separate_worktree_gitdir {
        account_copied_owner_metadata_bytes(
            service,
            repository,
            &repository.git_dir,
            &gitdir_entries,
            &worktree_file_paths,
            &mut total_bytes,
            control,
            |entry| {
                (is_worktree_local_git_path(&entry.path)
                    || is_owner_worktree_local_ancestor(&entry.path, &gitdir_entries))
                    && !is_root_git_pointer(&entry.path)
            },
        )?;
    }

    for entry in &worktree_entries {
        check_control(control)?;
        if entry.path.0.len() > 1 && entry.path.0[1..].iter().any(|part| part == b".git") {
            return Err(DesktopFileErrorCode::Protected.into());
        }
        if entry.path.0.first().is_some_and(|part| part == b".git")
            && entry.meta.kind == Kind::Symlink
        {
            return Err(DesktopFileErrorCode::Protected.into());
        }
    }

    let directory = tempfile::Builder::new()
        .prefix("lomi-desktop-git-external-")
        .tempdir()
        .map_err(|_| DesktopFileErrorCode::Io)?;
    fs::create_dir(directory.path().join(".git")).map_err(|_| DesktopFileErrorCode::Io)?;

    let mut executable = HashMap::<RelPath, bool>::new();
    let mut files = HashMap::<RelPath, Meta>::new();
    for entry in &worktree_entries {
        check_phase(
            phase_check,
            control.deadline,
            LocalNativeFileCheckPhase::Progress,
        )?;
        if entry.path.0.first().is_some_and(|part| part == b".git")
            || is_owner_metadata_worktree_entry(service, repository, &entry.path)?
        {
            continue;
        }
        files.insert(entry.path.clone(), entry.meta.clone());
        match entry.meta.kind {
            Kind::Directory => {
                let destination = entry
                    .path
                    .to_host_path(directory.path())
                    .map_err(map_service_error)?;
                fs::create_dir(&destination).map_err(|_| DesktopFileErrorCode::Io)?;
            }
            Kind::File => {
                if entry.meta.size > MAX_SNAPSHOT_FILE_BYTES {
                    return Err(DesktopFileErrorCode::Limit.into());
                }
                let destination = entry
                    .path
                    .to_host_path(directory.path())
                    .map_err(map_service_error)?;
                let (is_executable, copied) = copy_snapshot_file(
                    service,
                    &entry.meta,
                    &destination,
                    false,
                    control,
                    phase_check,
                )?;
                if copied != entry.meta.size {
                    return Err(DesktopFileErrorCode::Changed.into());
                }
                executable.insert(entry.path.clone(), is_executable);
            }
            Kind::Symlink => {
                let target = service
                    .files
                    .readlink_snapshot(
                        entry.meta.entry,
                        &entry.meta.revision,
                        MAX_SNAPSHOT_SYMLINK_BYTES,
                    )
                    .map_err(|error| match error {
                        FileError::Unsupported => DesktopFileErrorCode::Unsupported,
                        other => map_file_error_to_desktop(other),
                    })?;
                if target.is_empty() || target.contains(&0) {
                    return Err(DesktopFileErrorCode::Protected.into());
                }
                let destination = entry
                    .path
                    .to_host_path(directory.path())
                    .map_err(map_service_error)?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)
                    .map_err(|_| DesktopFileErrorCode::Io)?;
                output
                    .write_all(&target)
                    .and_then(|_| output.flush())
                    .map_err(|_| DesktopFileErrorCode::Io)?;
                executable.insert(entry.path.clone(), false);
            }
            Kind::Other => return Err(DesktopFileErrorCode::Unsupported.into()),
        }
    }

    let separate_worktree_gitdir = !same_git_directory;
    for entry in &common_entries {
        check_phase(
            phase_check,
            control.deadline,
            LocalNativeFileCheckPhase::Progress,
        )?;
        if separate_worktree_gitdir && is_worktree_local_git_path(&entry.path) {
            continue;
        }
        if is_root_git_pointer(&entry.path) {
            continue;
        }
        copy_owner_metadata_entry(
            &repository.common_dir,
            entry,
            directory.path(),
            false,
            control,
            phase_check,
        )?;
    }
    if separate_worktree_gitdir {
        for entry in &gitdir_entries {
            check_phase(
                phase_check,
                control.deadline,
                LocalNativeFileCheckPhase::Progress,
            )?;
            if (!is_worktree_local_git_path(&entry.path)
                && !is_owner_worktree_local_ancestor(&entry.path, &gitdir_entries))
                || is_root_git_pointer(&entry.path)
            {
                continue;
            }
            copy_owner_metadata_entry(
                &repository.git_dir,
                entry,
                directory.path(),
                true,
                control,
                phase_check,
            )?;
        }
    }
    for pointer in ["commondir", "gitdir"] {
        match fs::remove_file(directory.path().join(".git").join(pointer)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DesktopFileErrorCode::Io.into()),
        }
    }

    for entry in &worktree_entries {
        if entry.meta.kind == Kind::File {
            let path = entry
                .path
                .to_host_path(directory.path())
                .map_err(map_service_error)?;
            if let Some(is_executable) = executable.get(&entry.path) {
                set_snapshot_executable(&path, *is_executable).map_err(map_service_error)?;
            }
        }
    }
    for entry in common_entries.iter().chain(gitdir_entries.iter()) {
        if entry.kind == Kind::File {
            let path = entry
                .path
                .to_host_path(directory.path())
                .map_err(map_service_error)?;
            if let Some(metadata) = fs::metadata(&path).ok()
                && metadata.is_file()
            {
                set_snapshot_executable(&path, false).map_err(map_service_error)?;
            }
        }
    }

    let mut after_worktree = Vec::new();
    let mut after_count = 0usize;
    let mut after_bytes = 0u64;
    service
        .collect_snapshot_entries(
            repository.entry,
            RelPath::root(),
            0,
            &mut after_count,
            &mut after_bytes,
            &mut after_worktree,
            control,
        )
        .map_err(map_service_error)?;
    let after_common = collect_owner_metadata_tree(
        &repository.common_dir,
        OwnerGitMetadataRole::CommonDir,
        &mut after_count,
        &mut after_bytes,
        false,
        control,
    )?;
    let after_gitdir = collect_owner_metadata_tree(
        &repository.git_dir,
        OwnerGitMetadataRole::GitDir,
        &mut after_count,
        &mut after_bytes,
        false,
        control,
    )?;
    if !same_manifest(&worktree_entries, &after_worktree)
        || !same_owner_manifest(&common_entries, &after_common)
        || !same_owner_manifest(&gitdir_entries, &after_gitdir)
    {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    service
        .revalidate_entry(&repository.root_meta, control)
        .and_then(|()| service.revalidate_entry(&repository.git_marker, control))
        .map_err(map_service_error)?;
    repository
        .git_dir
        .revalidate_binding()
        .and_then(|()| repository.common_dir.revalidate_binding())
        .and_then(|()| repository.git_dir.check(&repository.commondir_condition))
        .map_err(map_file_error_to_desktop)?;

    let mut digest = Sha256::new();
    digest.update(b"lomi-desktop-git-external-snapshot-v1\0");
    digest.update(repository.id.to_bytes());
    digest.update(repository.root_meta.revision.as_bytes());
    for entry in &worktree_entries {
        update_path_hash(&mut digest, &entry.path);
        digest.update([kind_tag(entry.meta.kind)]);
        digest.update(entry.meta.size.to_le_bytes());
        digest.update(entry.meta.nlink.to_le_bytes());
        digest.update(entry.meta.revision.as_bytes());
    }
    for entry in common_entries.iter().chain(gitdir_entries.iter()) {
        update_path_hash(&mut digest, &entry.path);
        digest.update([kind_tag(entry.kind)]);
        digest.update(entry.size.to_le_bytes());
        digest.update(entry.nlink.to_le_bytes());
        digest.update(entry.revision.as_bytes());
    }
    Ok(ExternalOwnerSnapshot {
        snapshot: PrivateSnapshot {
            directory,
            state_token: token_hex(digest.finalize().as_slice()),
            root: repository.root_meta.clone(),
            files,
            executable,
        },
        common_entries,
        gitdir_entries,
    })
}

fn is_owner_metadata_worktree_entry(
    service: &GitService,
    repository: &ExternalDesktopRepository,
    path: &RelPath,
) -> Result<bool, DesktopMutationError> {
    let mut workspace_path = repository.path.clone();
    workspace_path.0.extend(path.0.iter().cloned());
    let host_path = workspace_path
        .to_host_path(&service.root_path)
        .map_err(map_service_error)?;
    Ok([
        repository.git_dir.canonical_path(),
        repository.common_dir.canonical_path(),
    ]
    .into_iter()
    .any(|metadata_root| host_path == metadata_root || host_path.starts_with(metadata_root)))
}

fn account_copied_owner_metadata_bytes(
    service: &GitService,
    repository: &ExternalDesktopRepository,
    root: &OwnerGitMetadataRoot,
    entries: &[OwnerMetadataSnapshotEntry],
    worktree_file_paths: &HashSet<(&RelPath, u64)>,
    total_bytes: &mut u64,
    control: &RequestControl,
    mut should_copy: impl FnMut(&OwnerMetadataSnapshotEntry) -> bool,
) -> Result<(), DesktopMutationError> {
    let root_in_workspace = host_relative_path(&service.root_path, root.canonical_path());
    let root_in_repository = root_in_workspace.as_ref().and_then(|path| {
        path.0
            .starts_with(&repository.path.0)
            .then(|| RelPath(path.0[repository.path.0.len()..].to_vec()))
    });
    for entry in entries {
        check_control(control)?;
        if entry.kind != Kind::File || !should_copy(entry) {
            continue;
        }
        let already_counted_by_worktree = root_in_repository.as_ref().is_some_and(|root_path| {
            let mut path = root_path.clone();
            path.0
                .extend(entry.source_path.components().iter().cloned());
            worktree_file_paths.contains(&(&path, entry.size))
        });
        if !already_counted_by_worktree {
            *total_bytes = total_bytes
                .checked_add(entry.size)
                .ok_or(DesktopFileErrorCode::Limit)?;
            if *total_bytes > MAX_SNAPSHOT_TOTAL_BYTES {
                return Err(DesktopFileErrorCode::Limit.into());
            }
        }
    }
    Ok(())
}

fn collect_owner_metadata_tree(
    root: &OwnerGitMetadataRoot,
    role: OwnerGitMetadataRole,
    count: &mut usize,
    total_bytes: &mut u64,
    account_bytes: bool,
    control: &RequestControl,
) -> Result<Vec<OwnerMetadataSnapshotEntry>, DesktopMutationError> {
    let mut entries = Vec::new();
    collect_owner_metadata_directory(
        root,
        role,
        &OwnerGitMetadataPath::root(),
        &RelPath(vec![b".git".to_vec()]),
        0,
        count,
        total_bytes,
        account_bytes,
        &mut entries,
        control,
    )?;
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn collect_owner_metadata_directory(
    root: &OwnerGitMetadataRoot,
    role: OwnerGitMetadataRole,
    source_directory: &OwnerGitMetadataPath,
    snapshot_directory: &RelPath,
    depth: usize,
    count: &mut usize,
    total_bytes: &mut u64,
    account_bytes: bool,
    entries: &mut Vec<OwnerMetadataSnapshotEntry>,
    control: &RequestControl,
) -> Result<(), DesktopMutationError> {
    check_control(control)?;
    if depth > MAX_SNAPSHOT_DEPTH {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    for source in root
        .list(source_directory)
        .map_err(map_file_error_to_desktop)?
    {
        check_control(control)?;
        *count = count.saturating_add(1);
        if *count > MAX_SNAPSHOT_ENTRIES {
            return Err(DesktopFileErrorCode::Limit.into());
        }
        if source.kind == Kind::Other
            || source.kind == Kind::Symlink
            || (source.kind == Kind::File
                && (source.nlink != 1 || source.size > MAX_SNAPSHOT_FILE_BYTES))
        {
            return Err(DesktopFileErrorCode::Protected.into());
        }
        if source.kind == Kind::File && account_bytes {
            *total_bytes = total_bytes
                .checked_add(source.size)
                .ok_or(DesktopFileErrorCode::Limit)?;
            if *total_bytes > MAX_SNAPSHOT_TOTAL_BYTES {
                return Err(DesktopFileErrorCode::Limit.into());
            }
        }
        let snapshot_path = snapshot_directory.joined(
            source
                .path
                .components()
                .last()
                .ok_or(DesktopFileErrorCode::Changed)?,
        );
        entries.push(OwnerMetadataSnapshotEntry {
            path: snapshot_path.clone(),
            source_path: source.path.clone(),
            kind: source.kind,
            size: source.size,
            revision: source.revision,
            nlink: source.nlink,
            role,
        });
        if source.kind == Kind::Directory {
            collect_owner_metadata_directory(
                root,
                role,
                &source.path,
                &snapshot_path,
                depth + 1,
                count,
                total_bytes,
                account_bytes,
                entries,
                control,
            )?;
        }
    }
    Ok(())
}

fn validate_owner_metadata_entries(
    entries: &[OwnerMetadataSnapshotEntry],
) -> Result<(), DesktopMutationError> {
    for entry in entries {
        if entry.path.0.first().is_some_and(|part| part == b".git")
            && (entry.kind == Kind::Symlink
                || entry.kind == Kind::Other
                || (entry.kind == Kind::File && entry.nlink != 1))
        {
            return Err(DesktopFileErrorCode::Protected.into());
        }
    }
    Ok(())
}

fn copy_owner_metadata_entry(
    root: &OwnerGitMetadataRoot,
    entry: &OwnerMetadataSnapshotEntry,
    snapshot_root: &Path,
    replace: bool,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<(), DesktopMutationError> {
    let path = entry
        .path
        .to_host_path(snapshot_root)
        .map_err(map_service_error)?;
    match entry.kind {
        Kind::Directory => match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error)
                if replace
                    && error.kind() == std::io::ErrorKind::AlreadyExists
                    && fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir()) => {}
            Err(_) => return Err(DesktopFileErrorCode::Io.into()),
        },
        Kind::File => {
            if entry.size > MAX_SNAPSHOT_FILE_BYTES {
                return Err(DesktopFileErrorCode::Limit.into());
            }
            let mut options = OpenOptions::new();
            options.write(true);
            if replace {
                options.create(true).truncate(true);
            } else {
                options.create_new(true);
            }
            let mut output = options.open(&path).map_err(|_| DesktopFileErrorCode::Io)?;
            let mut offset = 0u64;
            while offset < entry.size {
                check_phase(
                    phase_check,
                    control.deadline,
                    LocalNativeFileCheckPhase::Progress,
                )?;
                let chunk = root
                    .read_chunk(
                        &entry.source_path,
                        &entry.revision,
                        offset,
                        DESKTOP_READ_CHUNK,
                    )
                    .map_err(map_file_error_to_desktop)?;
                if chunk.kind != Kind::File
                    || chunk.revision != entry.revision
                    || chunk.size != entry.size
                    || chunk.offset != offset
                    || chunk.bytes.is_empty()
                {
                    return Err(DesktopFileErrorCode::Changed.into());
                }
                output
                    .write_all(&chunk.bytes)
                    .map_err(|_| DesktopFileErrorCode::Io)?;
                offset = offset.saturating_add(chunk.bytes.len() as u64);
                if offset > entry.size {
                    return Err(DesktopFileErrorCode::Changed.into());
                }
            }
            output.flush().map_err(|_| DesktopFileErrorCode::Io)?;
            if offset != entry.size {
                return Err(DesktopFileErrorCode::Changed.into());
            }
        }
        Kind::Symlink | Kind::Other => return Err(DesktopFileErrorCode::Protected.into()),
    }
    Ok(())
}

fn is_owner_worktree_local_ancestor(
    path: &RelPath,
    entries: &[OwnerMetadataSnapshotEntry],
) -> bool {
    path.0.len() >= 2
        && entries.iter().any(|entry| {
            entry.path.0.len() > path.0.len()
                && entry.path.0.starts_with(&path.0)
                && is_worktree_local_git_path(&entry.path)
        })
}

fn same_owner_manifest(
    expected: &[OwnerMetadataSnapshotEntry],
    current: &[OwnerMetadataSnapshotEntry],
) -> bool {
    expected.len() == current.len()
        && expected.iter().zip(current).all(|(expected, current)| {
            expected.path == current.path
                && expected.source_path == current.source_path
                && expected.kind == current.kind
                && expected.size == current.size
                && expected.revision == current.revision
                && expected.nlink == current.nlink
                && expected.role == current.role
        })
}

impl GitService {
    /// Apply one owner-local Explorer Git action. The lease uses the same
    /// physical common-directory lock as regular Git operations and remains
    /// held through preparation and the descriptor-confined publication (or
    /// legacy desktop Trash staging).
    pub fn apply_desktop_mutation(
        request: &DesktopMutationRequest,
        deadline: Instant,
        phase_check: impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
    ) -> Result<DesktopFileChange, DesktopMutationError> {
        Self::apply_desktop_mutation_inner(request, None, deadline, phase_check)
    }

    /// Apply an untracked Git discard only if the selected leaf still has the
    /// exact no-follow identity captured by the owner namespace adapter.
    pub fn apply_desktop_mutation_with_source(
        request: &DesktopMutationRequest,
        expected_source: &lomi_files::desktop::DesktopSourcePrecondition,
        deadline: Instant,
        phase_check: impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
    ) -> Result<DesktopFileChange, DesktopMutationError> {
        Self::apply_desktop_mutation_inner(request, Some(expected_source), deadline, phase_check)
    }

    fn apply_desktop_mutation_inner(
        request: &DesktopMutationRequest,
        expected_source: Option<&lomi_files::desktop::DesktopSourcePrecondition>,
        deadline: Instant,
        mut phase_check: impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
    ) -> Result<DesktopFileChange, DesktopMutationError> {
        validate_desktop_request(request)?;
        if expected_source.is_some()
            && !matches!(
                &request.operation,
                DesktopFileOperation::GitDiscard { expected, .. }
                    if expected.index == '?'
                        && expected.worktree == '?'
                        && expected.original_path.is_none()
            )
        {
            return Err(DesktopFileErrorCode::Invalid.into());
        }
        let control = RequestControl::with_deadline(CancellationToken::new(), deadline);
        check_phase(
            &mut phase_check,
            deadline,
            LocalNativeFileCheckPhase::Progress,
        )?;

        let (context, repository_relative) = match &request.operation {
            DesktopFileOperation::GitDiscard {
                context,
                repository_relative,
                ..
            }
            | DesktopFileOperation::GitIgnore {
                context,
                repository_relative,
                ..
            } => (context, repository_relative),
            _ => return Err(DesktopFileErrorCode::Unsupported.into()),
        };

        let protected = request
            .control_roots
            .iter()
            .map(PathBuf::as_path)
            .collect::<Vec<_>>();
        let service = GitService::open(&request.root, &protected, context.clone())
            .map_err(map_service_error)?;
        service.check_context(context).map_err(map_service_error)?;
        service
            .files
            .pin_native_directory(service.files.root_entry(), &service.root_path)
            .map_err(map_file_error_to_desktop)?;
        check_control(&control)?;

        let requested_repository = parse_workspace_relative(repository_relative)?;
        let repository =
            discover_desktop_repository(&service, &requested_repository, &protected, &control)?;
        let expected_repository_id = repository.id();
        let _repository_lock = common_repository_lock(repository.common_identity())
            .acquire(&control)
            .map_err(map_service_error)?;

        // Re-resolve after acquiring the shared lease. A linked worktree or
        // metadata pointer may have changed while this operation was queued.
        check_phase(
            &mut phase_check,
            deadline,
            LocalNativeFileCheckPhase::Progress,
        )?;
        let repository =
            discover_desktop_repository(&service, &requested_repository, &protected, &control)?;
        if repository.id() != expected_repository_id {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        check_control(&control)?;

        match (repository, &request.operation) {
            (
                DesktopRepository::Confined(repository),
                DesktopFileOperation::GitDiscard { expected, .. },
            ) => apply_discard(
                request,
                &service,
                &repository,
                expected,
                expected_source,
                deadline,
                &control,
                &mut phase_check,
            ),
            (
                DesktopRepository::Confined(repository),
                DesktopFileOperation::GitIgnore { local, .. },
            ) => apply_ignore(
                request,
                &service,
                &repository,
                *local,
                deadline,
                &control,
                &mut phase_check,
            ),
            (
                DesktopRepository::External(repository),
                DesktopFileOperation::GitDiscard { expected, .. },
            ) => apply_external_discard(
                request,
                &service,
                &repository,
                expected,
                expected_source,
                deadline,
                &control,
                &mut phase_check,
            ),
            (
                DesktopRepository::External(repository),
                DesktopFileOperation::GitIgnore { local, .. },
            ) => apply_external_ignore(
                request,
                &service,
                &repository,
                *local,
                deadline,
                &control,
                &mut phase_check,
            ),
            _ => unreachable!("operation was checked above"),
        }
    }
}

fn apply_discard(
    request: &DesktopMutationRequest,
    service: &GitService,
    repository: &Repository,
    expected: &lomi_files::desktop::DesktopGitChange,
    expected_source: Option<&lomi_files::desktop::DesktopSourcePrecondition>,
    deadline: Instant,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let path = parse_repository_relative(&expected.path)?;
    let path_bytes = encode_relative_path(&path);
    if !allowed_git_path(&path_bytes) {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let owner_snapshot = create_owner_snapshot(service, repository, control, phase_check)?;
    let snapshot = owner_snapshot.snapshot;
    let worktree_entries = owner_snapshot.worktree_entries;
    let common_entries = owner_snapshot.common_entries;
    let gitdir_entries = owner_snapshot.gitdir_entries;
    let (worker_context, worker_input) = create_owner_worker_context(&snapshot, &path)?;
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    let change =
        worker::run_selected_change(snapshot.path(), &path_bytes, worker_input.path(), control)
            .map_err(map_service_error)?;
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    verify_expected_change(&change, expected)?;
    if change.selected_kind != worker_context.selected_kind {
        return Err(DesktopFileErrorCode::Changed.into());
    }

    if expected.index == '?' && expected.worktree == '?' && expected.original_path.is_none() {
        let selected_meta = snapshot
            .files
            .get(&path)
            .ok_or(DesktopFileErrorCode::NotFound)?;
        let selected_kind = git_pull_kind(selected_meta.kind)?;
        let selected_condition = selected_precondition(&snapshot, &path, selected_kind)?;
        let metadata_preconditions = desktop_metadata_preconditions(
            service,
            repository,
            &snapshot,
            &worktree_entries,
            &common_entries,
            &gitdir_entries,
            control,
        )?;
        let repository_preconditions = repository_preconditions(repository)?;
        let source_precondition =
            snapshot_source_precondition(service, selected_meta, &selected_condition, control)?;
        if expected_source.is_some_and(|expected| expected != &source_precondition) {
            return Err(DesktopFileErrorCode::Changed.into());
        }

        check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
        let mut trash_request = request.clone();
        trash_request.operation = DesktopFileOperation::Trash;
        return lomi_files::desktop::apply_desktop_mutation_with_source(
            &trash_request,
            &source_precondition,
            |phase| {
                check_local_phase(phase_check, deadline, phase)?;
                if matches!(
                    phase,
                    LocalNativeFileCheckPhase::BeforeEffect
                        | LocalNativeFileCheckPhase::Publication
                ) {
                    revalidate_desktop_trash_snapshot(
                        service,
                        &selected_condition,
                        &repository_preconditions,
                        &metadata_preconditions,
                        control,
                        deadline,
                    )
                    .map_err(desktop_mutation_error_code)?;
                }
                Ok(())
            },
        );
    }

    // The legacy desktop discard implementation only supports restoring a
    // selected tracked leaf whose worktree side is modified, deleted or
    // type-changed. Staged-only entries, conflicts and worktree renames/copies
    // remain outside its one-leaf publication contract.
    if !matches!(expected.worktree, 'M' | 'D' | 'T')
        || !matches!(expected.index, ' ' | 'M' | 'A' | 'R' | 'C' | 'T')
    {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }

    let guard = worker::GuestRestoreGuard {
        path: path_bytes.clone(),
        original_path: expected
            .original_path
            .as_deref()
            .map(|original| original.as_bytes().to_vec()),
        index: expected.index,
        worktree: expected.worktree,
    };
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    let worker_output = tempfile::Builder::new()
        .prefix("lomi-desktop-git-output-")
        .tempdir()
        .map_err(|_| DesktopFileErrorCode::Io)?;
    check_control(control)?;
    let restored = worker::run_restore_index(
        snapshot.path(),
        &guard,
        worker_input.path(),
        worker_output.path(),
        control,
    )
    .map_err(map_service_error)?;
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    verify_expected_change(&restored.change, expected)?;
    if restored.change.selected_kind != worker_context.selected_kind
        || restored.change.core_symlinks != change.core_symlinks
    {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    let index_path = decode_hex(&restored.index_path_hex).ok_or(DesktopFileErrorCode::Changed)?;
    if index_path != path_bytes {
        // This operation is intentionally one leaf. A fully consistent staged
        // rename with an allowed worktree M/D/T status has its index entry at
        // the selected destination. If it does not, the captured status is
        // stale or requires a second namespace operation.
        return Err(DesktopFileErrorCode::Changed.into());
    }
    check_control(control)?;

    let contents = read_restore_blob(
        worker_output.path(),
        restored.size,
        &restored.sha256,
        deadline,
        control,
        phase_check,
    )?;
    if contents.len() as u64 != restored.size {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    let (kind, executable) =
        restored_worktree_kind(restored.mode, Some(restored.change.core_symlinks))?;
    let file = desktop_pull_file(repository, &snapshot, &path, contents, kind, executable)?;
    let metadata_preconditions = desktop_metadata_preconditions(
        service,
        repository,
        &snapshot,
        &worktree_entries,
        &common_entries,
        &gitdir_entries,
        control,
    )?;
    let repository_preconditions = repository_preconditions(repository)?;
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;

    let publication = GitDesktopFilePublication {
        repository: repository.entry,
        git_dir: repository.gitdir.entry,
        common_dir: repository.commondir.entry,
        repository_preconditions,
        metadata_preconditions,
        file,
    };
    let mut callback_error = None;
    let outcome = lomi_files::publish_git_desktop_file(&service.files, &publication, |phase| {
        let checked = check_local_phase(phase_check, deadline, phase).and_then(|()| {
            if matches!(
                phase,
                LocalNativeFileCheckPhase::BeforeEffect | LocalNativeFileCheckPhase::Publication
            ) {
                check_workspace_named_binding(service)?;
            }
            Ok(())
        });
        match checked {
            Ok(()) => true,
            Err(error) => {
                callback_error = Some(error);
                false
            }
        }
    })
    .map_err(map_file_error_to_desktop)?;
    match outcome {
        GitPublishOutcome::Published => Ok(empty_desktop_change(&request.operation_id)),
        GitPublishOutcome::AbortedBeforeFinalRename => Err(callback_error
            .unwrap_or(DesktopFileErrorCode::Changed)
            .into()),
        GitPublishOutcome::UncertainAfterFinalRename => Err(DesktopMutationError::Uncertain),
    }
}

fn apply_ignore(
    request: &DesktopMutationRequest,
    service: &GitService,
    repository: &Repository,
    local: bool,
    deadline: Instant,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let repository_relative = match &request.operation {
        DesktopFileOperation::GitIgnore {
            repository_relative,
            ..
        } => repository_relative.as_str(),
        _ => return Err(DesktopFileErrorCode::Invalid.into()),
    };
    let selected_text = selected_repository_path(request, repository_relative)?;
    if selected_text.is_empty() || selected_text.contains(['\r', '\n']) {
        return Err(DesktopFileErrorCode::Invalid.into());
    }
    let selected_path = parse_repository_relative(&selected_text)?;
    let selected_bytes = encode_relative_path(&selected_path);
    if !allowed_git_path(&selected_bytes) {
        return Err(DesktopFileErrorCode::Protected.into());
    }

    let owner_snapshot = create_owner_snapshot(service, repository, control, phase_check)?;
    let snapshot = owner_snapshot.snapshot;
    let worktree_entries = owner_snapshot.worktree_entries;
    let common_entries = owner_snapshot.common_entries;
    let gitdir_entries = owner_snapshot.gitdir_entries;
    let selected_meta = snapshot
        .files
        .get(&selected_path)
        .ok_or(DesktopFileErrorCode::NotFound)?;
    let selected_kind = match selected_meta.kind {
        Kind::File => GitPullNodeKind::File,
        Kind::Directory => GitPullNodeKind::Directory,
        Kind::Symlink => GitPullNodeKind::Symlink,
        Kind::Other => return Err(DesktopFileErrorCode::Unsupported.into()),
    };
    let selected_condition = selected_precondition(&snapshot, &selected_path, selected_kind)?;
    let metadata_preconditions = desktop_metadata_preconditions(
        service,
        repository,
        &snapshot,
        &worktree_entries,
        &common_entries,
        &gitdir_entries,
        control,
    )?;
    let repository_preconditions = repository_preconditions(repository)?;
    let pattern = ignore_pattern(&selected_bytes, selected_kind == GitPullNodeKind::Directory)?;

    let (target, expected, parent_suffix, existing_bytes) = if local {
        local_ignore_target(service, repository, control)?
    } else {
        worktree_ignore_target(service, repository, control)?
    };
    if contains_ignore_pattern(&existing_bytes, &pattern) {
        // The selected item and protected Git metadata must still match the
        // snapshot even when this is already an idempotent ignore entry.
        revalidate_preconditions(&service.files, &metadata_preconditions)?;
        revalidate_selected(&service.files, &selected_condition)?;
        check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
        return Ok(empty_desktop_change(&request.operation_id));
    }
    let bytes = append_ignore_pattern(existing_bytes, &pattern)?;
    if bytes.len() > MAX_IGNORE_BYTES {
        return Err(DesktopFileErrorCode::Limit.into());
    }

    let publication = GitIgnorePublication {
        target,
        repository: repository.entry,
        git_dir: repository.gitdir.entry,
        common_dir: repository.commondir.entry,
        repository_preconditions,
        metadata_preconditions,
        selected: selected_condition,
        parent_suffix,
        expected,
        bytes,
    };
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    let mut callback_error = None;
    let outcome = lomi_files::publish_git_ignore(&service.files, &publication, |phase| {
        let checked = check_local_phase(phase_check, deadline, phase).and_then(|()| {
            if matches!(
                phase,
                LocalNativeFileCheckPhase::BeforeEffect | LocalNativeFileCheckPhase::Publication
            ) {
                check_workspace_named_binding(service)?;
            }
            Ok(())
        });
        match checked {
            Ok(()) => true,
            Err(error) => {
                callback_error = Some(error);
                false
            }
        }
    })
    .map_err(map_file_error_to_desktop)?;
    match outcome {
        GitPublishOutcome::Published => Ok(empty_desktop_change(&request.operation_id)),
        GitPublishOutcome::AbortedBeforeFinalRename => Err(callback_error
            .unwrap_or(DesktopFileErrorCode::Changed)
            .into()),
        GitPublishOutcome::UncertainAfterFinalRename => Err(DesktopMutationError::Uncertain),
    }
}

fn apply_external_discard(
    request: &DesktopMutationRequest,
    service: &GitService,
    repository: &ExternalDesktopRepository,
    expected: &lomi_files::desktop::DesktopGitChange,
    expected_source: Option<&lomi_files::desktop::DesktopSourcePrecondition>,
    deadline: Instant,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let path = parse_repository_relative(&expected.path)?;
    let path_bytes = encode_relative_path(&path);
    if !allowed_git_path(&path_bytes) {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    if is_owner_metadata_worktree_entry(service, repository, &path)? {
        return Err(DesktopFileErrorCode::Protected.into());
    }

    let owner_snapshot = create_external_owner_snapshot(service, repository, control, phase_check)?;
    let snapshot = owner_snapshot.snapshot;
    let (worker_context, worker_input) = create_owner_worker_context(&snapshot, &path)?;
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    let change =
        worker::run_selected_change(snapshot.path(), &path_bytes, worker_input.path(), control)
            .map_err(map_service_error)?;
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    verify_expected_change(&change, expected)?;
    if change.selected_kind != worker_context.selected_kind {
        return Err(DesktopFileErrorCode::Changed.into());
    }

    let repository_preconditions = external_repository_preconditions(repository)?;
    let metadata_preconditions = external_metadata_preconditions(
        repository,
        &snapshot,
        &owner_snapshot.common_entries,
        &owner_snapshot.gitdir_entries,
        control,
    )?;

    if expected.index == '?' && expected.worktree == '?' && expected.original_path.is_none() {
        let selected_meta = snapshot
            .files
            .get(&path)
            .ok_or(DesktopFileErrorCode::NotFound)?;
        let selected_condition =
            selected_precondition(&snapshot, &path, git_pull_kind(selected_meta.kind)?)?;
        let source_precondition =
            snapshot_source_precondition(service, selected_meta, &selected_condition, control)?;
        if expected_source.is_some_and(|expected| expected != &source_precondition) {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
        let mut trash_request = request.clone();
        trash_request.operation = DesktopFileOperation::Trash;
        return lomi_files::desktop::apply_desktop_mutation_with_source(
            &trash_request,
            &source_precondition,
            |phase| {
                check_local_phase(phase_check, deadline, phase)?;
                if matches!(
                    phase,
                    LocalNativeFileCheckPhase::BeforeEffect
                        | LocalNativeFileCheckPhase::Publication
                ) {
                    revalidate_external_trash_snapshot(
                        service,
                        repository,
                        &selected_condition,
                        &repository_preconditions,
                        &metadata_preconditions,
                        control,
                        deadline,
                    )
                    .map_err(desktop_mutation_error_code)?;
                }
                Ok(())
            },
        );
    }

    if !matches!(expected.worktree, 'M' | 'D' | 'T')
        || !matches!(expected.index, ' ' | 'M' | 'A' | 'R' | 'C' | 'T')
    {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }
    let guard = worker::GuestRestoreGuard {
        path: path_bytes.clone(),
        original_path: expected
            .original_path
            .as_deref()
            .map(|original| original.as_bytes().to_vec()),
        index: expected.index,
        worktree: expected.worktree,
    };
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    let worker_output = tempfile::Builder::new()
        .prefix("lomi-desktop-git-output-")
        .tempdir()
        .map_err(|_| DesktopFileErrorCode::Io)?;
    let restored = worker::run_restore_index(
        snapshot.path(),
        &guard,
        worker_input.path(),
        worker_output.path(),
        control,
    )
    .map_err(map_service_error)?;
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    verify_expected_change(&restored.change, expected)?;
    if restored.change.selected_kind != worker_context.selected_kind
        || restored.change.core_symlinks != change.core_symlinks
    {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    let index_path = decode_hex(&restored.index_path_hex).ok_or(DesktopFileErrorCode::Changed)?;
    if index_path != path_bytes {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    let contents = read_restore_blob(
        worker_output.path(),
        restored.size,
        &restored.sha256,
        deadline,
        control,
        phase_check,
    )?;
    if contents.len() as u64 != restored.size {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    let (kind, executable) =
        restored_worktree_kind(restored.mode, Some(restored.change.core_symlinks))?;
    let file =
        external_desktop_pull_file(repository, &snapshot, &path, contents, kind, executable)?;
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    let publication = OwnerGitDesktopFilePublication {
        target: lomi_files::GitDesktopFileTarget {
            repository: repository.entry,
            repository_preconditions,
            worktree_preconditions: Vec::new(),
            file,
        },
        metadata_preconditions,
    };
    let mut callback_error = None;
    let outcome = lomi_files::publish_git_desktop_file_owner_local(
        &service.files,
        &repository.git_dir,
        &repository.common_dir,
        &publication,
        |phase| {
            let checked = check_local_phase(phase_check, deadline, phase).and_then(|()| {
                if matches!(
                    phase,
                    LocalNativeFileCheckPhase::BeforeEffect
                        | LocalNativeFileCheckPhase::Publication
                ) {
                    check_workspace_named_binding(service)?;
                }
                Ok(())
            });
            match checked {
                Ok(()) => true,
                Err(error) => {
                    callback_error = Some(error);
                    false
                }
            }
        },
    )
    .map_err(map_file_error_to_desktop)?;
    match outcome {
        GitPublishOutcome::Published => Ok(empty_desktop_change(&request.operation_id)),
        GitPublishOutcome::AbortedBeforeFinalRename => Err(callback_error
            .unwrap_or(DesktopFileErrorCode::Changed)
            .into()),
        GitPublishOutcome::UncertainAfterFinalRename => Err(DesktopMutationError::Uncertain),
    }
}

fn apply_external_ignore(
    request: &DesktopMutationRequest,
    service: &GitService,
    repository: &ExternalDesktopRepository,
    local: bool,
    deadline: Instant,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let repository_relative = match &request.operation {
        DesktopFileOperation::GitIgnore {
            repository_relative,
            ..
        } => repository_relative.as_str(),
        _ => return Err(DesktopFileErrorCode::Invalid.into()),
    };
    let selected_text = selected_repository_path(request, repository_relative)?;
    if selected_text.is_empty() || selected_text.contains(['\r', '\n']) {
        return Err(DesktopFileErrorCode::Invalid.into());
    }
    let selected_path = parse_repository_relative(&selected_text)?;
    let selected_bytes = encode_relative_path(&selected_path);
    if !allowed_git_path(&selected_bytes) {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    if is_owner_metadata_worktree_entry(service, repository, &selected_path)? {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let owner_snapshot = create_external_owner_snapshot(service, repository, control, phase_check)?;
    let snapshot = owner_snapshot.snapshot;
    let selected_meta = snapshot
        .files
        .get(&selected_path)
        .ok_or(DesktopFileErrorCode::NotFound)?;
    let selected_kind = git_pull_kind(selected_meta.kind)?;
    let selected_condition = selected_precondition(&snapshot, &selected_path, selected_kind)?;
    let mut metadata_preconditions = external_metadata_preconditions(
        repository,
        &snapshot,
        &owner_snapshot.common_entries,
        &owner_snapshot.gitdir_entries,
        control,
    )?;
    let repository_preconditions = external_repository_preconditions(repository)?;
    let pattern = ignore_pattern(&selected_bytes, selected_kind == GitPullNodeKind::Directory)?;

    let (target, existing_bytes, parent_condition) = if local {
        external_local_ignore_target(repository, &owner_snapshot.common_entries, control)?
    } else {
        let (target, bytes) =
            external_worktree_ignore_target(service, repository, &snapshot, control)?;
        (target, bytes, None)
    };
    if let Some(condition) = parent_condition {
        if !metadata_preconditions.contains(&condition) {
            metadata_preconditions.push(condition);
        }
    }
    if metadata_preconditions.len() > 32 {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    if contains_ignore_pattern(&existing_bytes, &pattern) {
        revalidate_external_ignore_target(service, repository, &target)?;
        revalidate_external_trash_snapshot(
            service,
            repository,
            &selected_condition,
            &repository_preconditions,
            &metadata_preconditions,
            control,
            deadline,
        )?;
        check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
        return Ok(empty_desktop_change(&request.operation_id));
    }
    let bytes = append_ignore_pattern(existing_bytes, &pattern)?;
    if bytes.len() > MAX_IGNORE_BYTES {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    let publication = OwnerGitIgnorePublication {
        repository: repository.entry,
        repository_path: repository.path.0.clone(),
        repository_preconditions,
        selected: selected_condition,
        metadata_preconditions,
        target,
        bytes,
    };
    check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
    let mut callback_error = None;
    let outcome = lomi_files::publish_git_ignore_owner_local(
        &service.files,
        &repository.git_dir,
        &repository.common_dir,
        &publication,
        |phase| {
            let checked = check_local_phase(phase_check, deadline, phase).and_then(|()| {
                if matches!(
                    phase,
                    LocalNativeFileCheckPhase::BeforeEffect
                        | LocalNativeFileCheckPhase::Publication
                ) {
                    check_workspace_named_binding(service)?;
                }
                Ok(())
            });
            match checked {
                Ok(()) => true,
                Err(error) => {
                    callback_error = Some(error);
                    false
                }
            }
        },
    )
    .map_err(map_file_error_to_desktop)?;
    match outcome {
        GitPublishOutcome::Published => Ok(empty_desktop_change(&request.operation_id)),
        GitPublishOutcome::AbortedBeforeFinalRename => Err(callback_error
            .unwrap_or(DesktopFileErrorCode::Changed)
            .into()),
        GitPublishOutcome::UncertainAfterFinalRename => Err(DesktopMutationError::Uncertain),
    }
}

fn external_repository_preconditions(
    repository: &ExternalDesktopRepository,
) -> Result<Vec<GitPullPrecondition>, DesktopMutationError> {
    if repository.git_marker.kind == Kind::File && repository.git_marker.nlink != 1 {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let kind = match repository.git_marker.kind {
        Kind::File => GitPullNodeKind::File,
        Kind::Directory => GitPullNodeKind::Directory,
        Kind::Symlink | Kind::Other => return Err(DesktopFileErrorCode::Protected.into()),
    };
    Ok(vec![GitPullPrecondition {
        parent: repository.entry,
        name: b".git".to_vec(),
        entry: Some(repository.git_marker.entry),
        revision: Some(repository.git_marker.revision.clone()),
        kind: Some(kind),
    }])
}

fn snapshot_source_precondition(
    service: &GitService,
    selected_meta: &Meta,
    selected: &GitPullPrecondition,
    control: &RequestControl,
) -> Result<lomi_files::desktop::DesktopSourcePrecondition, DesktopMutationError> {
    service
        .files
        .pin_native_directory(service.files.root_entry(), &service.root_path)
        .map_err(map_file_error_to_desktop)?;
    let expected_kind = match selected_meta.kind {
        Kind::File => lomi_files::desktop::DesktopFileKind::File,
        Kind::Directory => lomi_files::desktop::DesktopFileKind::Directory,
        Kind::Symlink => lomi_files::desktop::DesktopFileKind::Symlink,
        Kind::Other => return Err(DesktopFileErrorCode::Unsupported.into()),
    };
    let precondition = service
        .files
        .desktop_source_precondition(selected_meta.entry)
        .map_err(map_file_error_to_desktop)
        .map_err(DesktopMutationError::Before)?;
    if precondition.kind != expected_kind {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    service
        .files
        .pin_native_directory(service.files.root_entry(), &service.root_path)
        .map_err(map_file_error_to_desktop)?;
    revalidate_selected(&service.files, selected)?;
    service
        .revalidate_entry(selected_meta, control)
        .map_err(map_service_error)?;
    Ok(precondition)
}

fn revalidate_external_trash_snapshot(
    service: &GitService,
    repository: &ExternalDesktopRepository,
    selected: &GitPullPrecondition,
    repository_preconditions: &[GitPullPrecondition],
    metadata: &[OwnerGitMetadataCondition],
    control: &RequestControl,
    deadline: Instant,
) -> Result<(), DesktopMutationError> {
    check_control(control)?;
    if Instant::now() >= deadline {
        return Err(DesktopFileErrorCode::DeadlineExceeded.into());
    }
    service
        .files
        .pin_native_directory(service.files.root_entry(), &service.root_path)
        .map_err(map_file_error_to_desktop)?;
    revalidate_selected(&service.files, selected)?;
    for expected in repository_preconditions {
        let current = child_by_entry(&service.files, expected.parent, &expected.name)?
            .ok_or(DesktopFileErrorCode::Changed)?;
        if Some(current.entry) != expected.entry
            || Some(current.revision.as_str()) != expected.revision.as_deref()
            || Some(git_pull_kind(current.kind)?) != expected.kind
        {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    }
    service
        .revalidate_entry(&repository.root_meta, control)
        .and_then(|()| service.revalidate_entry(&repository.git_marker, control))
        .map_err(map_service_error)?;
    repository
        .git_dir
        .revalidate_binding()
        .and_then(|()| repository.common_dir.revalidate_binding())
        .map_err(map_file_error_to_desktop)?;
    for condition in metadata {
        let root = match condition.role {
            OwnerGitMetadataRole::GitDir => &repository.git_dir,
            OwnerGitMetadataRole::CommonDir => &repository.common_dir,
        };
        root.check(condition).map_err(map_file_error_to_desktop)?;
    }
    check_control(control)?;
    if Instant::now() >= deadline {
        return Err(DesktopFileErrorCode::DeadlineExceeded.into());
    }
    service
        .files
        .pin_native_directory(service.files.root_entry(), &service.root_path)
        .map_err(map_file_error_to_desktop)?;
    Ok(())
}

fn revalidate_external_ignore_target(
    service: &GitService,
    repository: &ExternalDesktopRepository,
    target: &OwnerGitIgnoreTarget,
) -> Result<(), DesktopMutationError> {
    match target {
        OwnerGitIgnoreTarget::Worktree { expected } => {
            let current = child_by_entry(&service.files, expected.parent, &expected.name)?;
            match (
                expected.entry,
                expected.revision.as_deref(),
                expected.kind,
                current,
            ) {
                (None, None, None, None) => Ok(()),
                (Some(entry), Some(revision), Some(kind), Some(current))
                    if current.entry == entry
                        && current.revision == revision
                        && git_pull_kind(current.kind)? == kind =>
                {
                    Ok(())
                }
                _ => Err(DesktopFileErrorCode::Changed.into()),
            }
        }
        OwnerGitIgnoreTarget::CommonExclude { expected } => {
            repository
                .common_dir
                .check(expected)
                .map_err(map_file_error_to_desktop)?;
            Ok(())
        }
    }
}

fn external_desktop_pull_file(
    repository: &ExternalDesktopRepository,
    snapshot: &PrivateSnapshot,
    path: &RelPath,
    contents: Vec<u8>,
    kind: GitPullNodeKind,
    executable: bool,
) -> Result<lomi_files::GitPullFile, DesktopMutationError> {
    let (name, parents) = path.0.split_last().ok_or(DesktopFileErrorCode::Invalid)?;
    let nearest = (0..=parents.len())
        .rev()
        .find_map(|existing_len| {
            let parent_path = RelPath(parents[..existing_len].to_vec());
            snapshot_directory(snapshot, &parent_path)
                .filter(|meta| meta.kind == Kind::Directory)
                .map(|meta| (existing_len, meta.entry))
        })
        .ok_or(DesktopFileErrorCode::Changed)?;
    let (existing_len, parent) = nearest;
    let (parent_suffix, expected) = if existing_len == parents.len() {
        let entry = snapshot.files.get(path);
        if entry.is_some_and(|meta| !matches!(meta.kind, Kind::File | Kind::Symlink)) {
            return Err(DesktopFileErrorCode::Unsupported.into());
        }
        (
            Vec::new(),
            GitPullPrecondition {
                parent,
                name: name.clone(),
                entry: entry.map(|meta| meta.entry),
                revision: entry.map(|meta| meta.revision.clone()),
                kind: entry.map(|meta| match meta.kind {
                    Kind::File => GitPullNodeKind::File,
                    Kind::Symlink => GitPullNodeKind::Symlink,
                    _ => unreachable!(),
                }),
            },
        )
    } else {
        (
            parents[existing_len..].to_vec(),
            GitPullPrecondition {
                parent,
                name: parents[existing_len].clone(),
                entry: None,
                revision: None,
                kind: None,
            },
        )
    };
    let mut workspace_path = repository.path.0.clone();
    workspace_path.extend(path.0.iter().cloned());
    Ok(lomi_files::GitPullFile {
        path: workspace_path,
        parent,
        parent_suffix,
        name: name.clone(),
        expected,
        contents: Some(contents),
        kind,
        executable,
    })
}

fn external_local_ignore_target(
    repository: &ExternalDesktopRepository,
    common_entries: &[OwnerMetadataSnapshotEntry],
    control: &RequestControl,
) -> Result<
    (
        OwnerGitIgnoreTarget,
        Vec<u8>,
        Option<OwnerGitMetadataCondition>,
    ),
    DesktopMutationError,
> {
    let info_path = vec![b"info".to_vec()];
    let info = common_entries
        .iter()
        .find(|entry| entry.source_path.components() == info_path);
    if info.is_some_and(|entry| entry.kind != Kind::Directory) {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let exclude_path = vec![b"info".to_vec(), b"exclude".to_vec()];
    let exclude = common_entries
        .iter()
        .find(|entry| entry.source_path.components() == exclude_path);
    if exclude.is_some_and(|entry| entry.kind != Kind::File || entry.nlink != 1) {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let condition = owner_condition(
        OwnerGitMetadataRole::CommonDir,
        exclude_path,
        exclude.map(owner_snapshot_entry).as_ref(),
    )?;
    let parent_condition = info
        .map(|entry| {
            owner_condition(
                OwnerGitMetadataRole::CommonDir,
                info_path,
                Some(&owner_snapshot_entry(entry)),
            )
        })
        .transpose()?;
    let bytes = if let Some(exclude) = exclude {
        read_owner_metadata_file(
            &repository.common_dir,
            &exclude.source_path,
            &exclude.revision,
            MAX_IGNORE_BYTES,
            control,
        )?
    } else {
        Vec::new()
    };
    Ok((
        OwnerGitIgnoreTarget::CommonExclude {
            expected: condition,
        },
        bytes,
        parent_condition,
    ))
}

fn external_worktree_ignore_target(
    service: &GitService,
    repository: &ExternalDesktopRepository,
    snapshot: &PrivateSnapshot,
    control: &RequestControl,
) -> Result<(OwnerGitIgnoreTarget, Vec<u8>), DesktopMutationError> {
    let ignore_path = RelPath(vec![b".gitignore".to_vec()]);
    let current = service
        .lookup_optional_child(repository.entry, &repository.path, b".gitignore", control)
        .map_err(map_service_error)?;
    let expected = match (snapshot.files.get(&ignore_path), current.as_ref()) {
        (Some(snapshot), Some(current))
            if snapshot.entry == current.entry
                && snapshot.revision == current.revision
                && current.kind == Kind::File
                && current.nlink == 1 =>
        {
            GitPullPrecondition {
                parent: repository.entry,
                name: b".gitignore".to_vec(),
                entry: Some(current.entry),
                revision: Some(current.revision.clone()),
                kind: Some(GitPullNodeKind::File),
            }
        }
        (None, None) => GitPullPrecondition {
            parent: repository.entry,
            name: b".gitignore".to_vec(),
            entry: None,
            revision: None,
            kind: None,
        },
        _ => return Err(DesktopFileErrorCode::Changed.into()),
    };
    let bytes = read_optional_git_file(service, current.as_ref(), control)?;
    Ok((OwnerGitIgnoreTarget::Worktree { expected }, bytes))
}

fn owner_snapshot_entry(entry: &OwnerMetadataSnapshotEntry) -> OwnerGitMetadataEntry {
    OwnerGitMetadataEntry {
        path: entry.source_path.clone(),
        kind: entry.kind,
        size: entry.size,
        revision: entry.revision.clone(),
        nlink: entry.nlink,
    }
}

fn external_metadata_preconditions(
    repository: &ExternalDesktopRepository,
    snapshot: &PrivateSnapshot,
    common_entries: &[OwnerMetadataSnapshotEntry],
    gitdir_entries: &[OwnerMetadataSnapshotEntry],
    control: &RequestControl,
) -> Result<Vec<OwnerGitMetadataCondition>, DesktopMutationError> {
    let mut conditions = Vec::new();
    conditions.push(repository.commondir_condition.clone());
    for (role, entries, name, required) in [
        (
            OwnerGitMetadataRole::GitDir,
            gitdir_entries,
            b"HEAD".as_slice(),
            true,
        ),
        (
            OwnerGitMetadataRole::GitDir,
            gitdir_entries,
            b"index".as_slice(),
            false,
        ),
        (
            OwnerGitMetadataRole::GitDir,
            gitdir_entries,
            b"config.worktree".as_slice(),
            false,
        ),
        (
            OwnerGitMetadataRole::CommonDir,
            common_entries,
            b"config".as_slice(),
            false,
        ),
    ] {
        let path = vec![name.to_vec()];
        let entry = entries
            .iter()
            .find(|entry| entry.source_path.components() == path);
        if entry.is_some_and(|entry| entry.kind != Kind::File || entry.nlink != 1) {
            return Err(DesktopFileErrorCode::Protected.into());
        }
        if required && entry.is_none() {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        conditions.push(owner_condition(
            role,
            path,
            entry.map(owner_snapshot_entry).as_ref(),
        )?);
    }

    let head = read_bounded_private_file(
        &snapshot.path().join(".git").join("HEAD"),
        MAX_GIT_POINTER_BYTES,
    )?;
    let head_text = std::str::from_utf8(&head).map_err(|_| DesktopFileErrorCode::Changed)?;
    if head_text.starts_with("ref: ") {
        let mut path =
            reference_rel_path(parse_pointer(head_text, "ref: ").map_err(map_service_error)?)
                .map_err(map_service_error)?;
        let separate_gitdir =
            repository.git_dir.physical_identity() != repository.common_dir.physical_identity();
        let mut seen = HashSet::new();
        let mut terminated = false;
        for _ in 0..8 {
            if !seen.insert(path.clone()) {
                return Err(DesktopFileErrorCode::Changed.into());
            }
            let private = separate_gitdir && is_worktree_local_git_path(&path);
            let (role, root, entries) = if private {
                (
                    OwnerGitMetadataRole::GitDir,
                    &repository.git_dir,
                    gitdir_entries,
                )
            } else {
                (
                    OwnerGitMetadataRole::CommonDir,
                    &repository.common_dir,
                    common_entries,
                )
            };
            let components = path.0.get(1..).ok_or(DesktopFileErrorCode::Changed)?;
            let (captured, bytes) = owner_metadata_path_conditions(
                root,
                role,
                entries,
                components,
                Some(MAX_GIT_POINTER_BYTES),
                &mut conditions,
                control,
            )?;
            let Some(bytes) = bytes else {
                terminated = true;
                break;
            };
            let text = std::str::from_utf8(&bytes).map_err(|_| DesktopFileErrorCode::Changed)?;
            if text.starts_with("ref: ") {
                path = reference_rel_path(parse_pointer(text, "ref: ").map_err(map_service_error)?)
                    .map_err(map_service_error)?;
            } else {
                terminated = true;
                break;
            }
            let _ = captured;
        }
        if !terminated {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    }
    owner_metadata_path_conditions(
        &repository.common_dir,
        OwnerGitMetadataRole::CommonDir,
        common_entries,
        &[b"packed-refs".to_vec()],
        None,
        &mut conditions,
        control,
    )?;
    let mut unique = Vec::new();
    for condition in conditions {
        if !unique.contains(&condition) {
            unique.push(condition);
        }
    }
    if unique.len() > 32 {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    Ok(unique)
}

fn owner_metadata_path_conditions(
    root: &OwnerGitMetadataRoot,
    role: OwnerGitMetadataRole,
    entries: &[OwnerMetadataSnapshotEntry],
    components: &[Vec<u8>],
    max_content: Option<usize>,
    conditions: &mut Vec<OwnerGitMetadataCondition>,
    control: &RequestControl,
) -> Result<(Option<OwnerGitMetadataEntry>, Option<Vec<u8>>), DesktopMutationError> {
    if components.is_empty() {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    let mut prefix = Vec::new();
    let mut leaf = None;
    for (index, component) in components.iter().enumerate() {
        prefix.push(component.clone());
        let source_path = OwnerGitMetadataPath::from_components(prefix.clone())
            .map_err(map_file_error_to_desktop)?;
        let entry = entries
            .iter()
            .find(|entry| entry.source_path == source_path);
        if let Some(entry) = entry {
            let is_leaf = index + 1 == components.len();
            if (!is_leaf && entry.kind != Kind::Directory)
                || (is_leaf && entry.kind != Kind::File)
                || (entry.kind == Kind::File && entry.nlink != 1)
            {
                return Err(DesktopFileErrorCode::Protected.into());
            }
            conditions.push(owner_condition(
                role,
                prefix.clone(),
                Some(&owner_snapshot_entry(entry)),
            )?);
            leaf = Some(entry);
        } else {
            conditions.push(owner_condition(role, prefix.clone(), None)?);
            return Ok((None, None));
        }
    }
    let entry = leaf.ok_or(DesktopFileErrorCode::Changed)?;
    let metadata = owner_snapshot_entry(entry);
    if metadata.kind != Kind::File {
        return Ok((Some(metadata), None));
    }
    let bytes = if let Some(maximum) = max_content {
        Some(read_owner_metadata_file(
            root,
            &metadata.path,
            &metadata.revision,
            maximum,
            control,
        )?)
    } else {
        None
    };
    Ok((Some(metadata), bytes))
}

fn create_owner_snapshot(
    service: &GitService,
    repository: &Repository,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<OwnerLocalSnapshot, DesktopMutationError> {
    check_control(control)?;
    if repository.root_meta.kind != Kind::Directory
        || repository.git_marker.kind == Kind::Symlink
        || repository.gitdir.kind != Kind::Directory
        || repository.commondir.kind != Kind::Directory
    {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    service
        .revalidate_entry(&repository.root_meta, control)
        .map_err(map_service_error)?;
    service
        .revalidate_entry(&repository.git_marker, control)
        .map_err(map_service_error)?;
    service
        .revalidate_entry(&repository.gitdir, control)
        .map_err(map_service_error)?;
    service
        .revalidate_entry(&repository.commondir, control)
        .map_err(map_service_error)?;
    if let Some(marker) = repository.commondir_marker.as_ref() {
        service
            .revalidate_entry(marker, control)
            .map_err(map_service_error)?;
    }

    let mut worktree_entries = Vec::new();
    let mut common_entries = Vec::new();
    let mut gitdir_entries = Vec::new();
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    service
        .collect_snapshot_entries(
            repository.entry,
            RelPath::root(),
            0,
            &mut count,
            &mut total_bytes,
            &mut worktree_entries,
            control,
        )
        .map_err(map_service_error)?;

    let linked = repository.git_marker.kind == Kind::File
        || repository.gitdir_identity != repository.common_identity;
    if linked {
        service
            .collect_snapshot_entries(
                repository.commondir.entry,
                RelPath(vec![b".git".to_vec()]),
                0,
                &mut count,
                &mut total_bytes,
                &mut common_entries,
                control,
            )
            .map_err(map_service_error)?;
        if repository.gitdir_identity != repository.common_identity {
            service
                .collect_snapshot_entries(
                    repository.gitdir.entry,
                    RelPath(vec![b".git".to_vec()]),
                    0,
                    &mut count,
                    &mut total_bytes,
                    &mut gitdir_entries,
                    control,
                )
                .map_err(map_service_error)?;
        }
    }

    for entry in &worktree_entries {
        check_control(control)?;
        if entry.path.0.len() > 1 && entry.path.0[1..].iter().any(|part| part == b".git") {
            return Err(DesktopFileErrorCode::Protected.into());
        }
        if entry.path.0.first().is_some_and(|part| part == b".git")
            && entry.meta.kind == Kind::Symlink
        {
            return Err(DesktopFileErrorCode::Protected.into());
        }
    }
    validate_git_metadata_entries(&common_entries)?;
    validate_git_metadata_entries(&gitdir_entries)?;

    let directory = tempfile::Builder::new()
        .prefix("lomi-desktop-git-")
        .tempdir()
        .map_err(|_| DesktopFileErrorCode::Io)?;
    if linked {
        fs::create_dir(directory.path().join(".git")).map_err(|_| DesktopFileErrorCode::Io)?;
    }

    let mut executable = HashMap::<RelPath, bool>::new();
    let mut files = HashMap::<RelPath, Meta>::new();
    for entry in &worktree_entries {
        check_phase(
            phase_check,
            control.deadline,
            LocalNativeFileCheckPhase::Progress,
        )?;
        if linked && entry.path.0.first().is_some_and(|part| part == b".git") {
            continue;
        }
        files.insert(entry.path.clone(), entry.meta.clone());
        match entry.meta.kind {
            Kind::Directory => {
                let destination = entry
                    .path
                    .to_host_path(directory.path())
                    .map_err(map_service_error)?;
                fs::create_dir(&destination).map_err(|_| DesktopFileErrorCode::Io)?;
            }
            Kind::File => {
                if entry.meta.size > MAX_SNAPSHOT_FILE_BYTES {
                    return Err(DesktopFileErrorCode::Limit.into());
                }
                let destination = entry
                    .path
                    .to_host_path(directory.path())
                    .map_err(map_service_error)?;
                let (is_executable, copied) = copy_snapshot_file(
                    service,
                    &entry.meta,
                    &destination,
                    false,
                    control,
                    phase_check,
                )?;
                if copied != entry.meta.size {
                    return Err(DesktopFileErrorCode::Changed.into());
                }
                executable.insert(entry.path.clone(), is_executable);
            }
            Kind::Symlink => {
                let target = service
                    .files
                    .readlink_snapshot(
                        entry.meta.entry,
                        &entry.meta.revision,
                        MAX_SNAPSHOT_SYMLINK_BYTES,
                    )
                    .map_err(|error| match error {
                        FileError::Unsupported => DesktopFileErrorCode::Unsupported,
                        other => map_file_error_to_desktop(other),
                    })?;
                if target.is_empty() || target.contains(&0) {
                    return Err(DesktopFileErrorCode::Protected.into());
                }
                let destination = entry
                    .path
                    .to_host_path(directory.path())
                    .map_err(map_service_error)?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)
                    .map_err(|_| DesktopFileErrorCode::Io)?;
                output
                    .write_all(&target)
                    .map_err(|_| DesktopFileErrorCode::Io)?;
                output.flush().map_err(|_| DesktopFileErrorCode::Io)?;
                executable.insert(entry.path.clone(), false);
            }
            Kind::Other => return Err(DesktopFileErrorCode::Unsupported.into()),
        }
    }

    if linked {
        for entry in common_entries.iter().chain(gitdir_entries.iter()) {
            check_phase(
                phase_check,
                control.deadline,
                LocalNativeFileCheckPhase::Progress,
            )?;
            if entry.path.0.len() > 1 && entry.path.0[1..].iter().any(|part| part == b".git") {
                return Err(DesktopFileErrorCode::Protected.into());
            }
        }
        // Common metadata provides objects/refs/config. Per-worktree metadata
        // omits HEAD/index/config.worktree and worktree-private ref namespaces.
        for entry in &common_entries {
            if repository.gitdir_identity != repository.common_identity
                && is_worktree_local_git_path(&entry.path)
            {
                continue;
            }
            copy_metadata_entry(
                service,
                entry,
                directory.path(),
                false,
                control,
                phase_check,
            )?;
            files.insert(entry.path.clone(), entry.meta.clone());
        }
        for entry in &gitdir_entries {
            if (!is_worktree_local_git_path(&entry.path)
                && !is_worktree_local_git_ancestor(&entry.path, &gitdir_entries))
                || is_root_git_pointer(&entry.path)
            {
                continue;
            }
            copy_metadata_entry(service, entry, directory.path(), true, control, phase_check)?;
            files.insert(entry.path.clone(), entry.meta.clone());
        }
        files.insert(RelPath(vec![b".git".to_vec()]), repository.gitdir.clone());
    }

    if linked {
        for pointer in ["commondir", "gitdir"] {
            let path = directory.path().join(".git").join(pointer);
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(DesktopFileErrorCode::Io.into()),
            }
        }
    }

    for entry in &worktree_entries {
        if entry.meta.kind == Kind::File {
            let path = entry
                .path
                .to_host_path(directory.path())
                .map_err(map_service_error)?;
            if let Some(executable) = executable.get(&entry.path) {
                set_snapshot_executable(&path, *executable).map_err(map_service_error)?;
            }
        }
    }
    for entry in common_entries.iter().chain(gitdir_entries.iter()) {
        if entry.meta.kind == Kind::File {
            let path = entry
                .path
                .to_host_path(directory.path())
                .map_err(map_service_error)?;
            if let Some(meta) = fs::metadata(&path).ok()
                && meta.is_file()
            {
                set_snapshot_executable(&path, false).map_err(map_service_error)?;
            }
        }
    }

    // Check both source trees again after all bytes have been copied. A linked
    // common directory is admitted only when FileRoot can pin every component
    // below the trusted workspace root.
    let mut after_worktree = Vec::new();
    let mut after_common = Vec::new();
    let mut after_gitdir = Vec::new();
    let mut after_count = 0usize;
    let mut after_bytes = 0u64;
    service
        .collect_snapshot_entries(
            repository.entry,
            RelPath::root(),
            0,
            &mut after_count,
            &mut after_bytes,
            &mut after_worktree,
            control,
        )
        .map_err(map_service_error)?;
    if linked {
        service
            .collect_snapshot_entries(
                repository.commondir.entry,
                RelPath(vec![b".git".to_vec()]),
                0,
                &mut after_count,
                &mut after_bytes,
                &mut after_common,
                control,
            )
            .map_err(map_service_error)?;
        if repository.gitdir_identity != repository.common_identity {
            service
                .collect_snapshot_entries(
                    repository.gitdir.entry,
                    RelPath(vec![b".git".to_vec()]),
                    0,
                    &mut after_count,
                    &mut after_bytes,
                    &mut after_gitdir,
                    control,
                )
                .map_err(map_service_error)?;
        }
    }
    if !same_manifest(&worktree_entries, &after_worktree)
        || (linked && !same_manifest(&common_entries, &after_common))
        || (linked && !same_manifest(&gitdir_entries, &after_gitdir))
    {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    service
        .revalidate_entry(&repository.root_meta, control)
        .and_then(|()| service.revalidate_entry(&repository.git_marker, control))
        .and_then(|()| service.revalidate_entry(&repository.gitdir, control))
        .and_then(|()| service.revalidate_entry(&repository.commondir, control))
        .map_err(map_service_error)?;
    if let Some(marker) = repository.commondir_marker.as_ref() {
        service
            .revalidate_entry(marker, control)
            .map_err(map_service_error)?;
    }

    let mut digest = Sha256::new();
    digest.update(b"lomi-desktop-git-snapshot-v1\0");
    digest.update(repository.id.to_bytes());
    digest.update(repository.root_meta.revision.as_bytes());
    for entry in worktree_entries
        .iter()
        .chain(common_entries.iter())
        .chain(gitdir_entries.iter())
    {
        update_path_hash(&mut digest, &entry.path);
        digest.update([kind_tag(entry.meta.kind)]);
        digest.update(entry.meta.size.to_le_bytes());
        digest.update(entry.meta.nlink.to_le_bytes());
        digest.update(entry.meta.revision.as_bytes());
        digest.update([u8::from(
            executable.get(&entry.path).copied().unwrap_or(false),
        )]);
    }
    let state_token = token_hex(digest.finalize().as_slice());
    Ok(OwnerLocalSnapshot {
        snapshot: PrivateSnapshot {
            directory,
            state_token,
            root: repository.root_meta.clone(),
            files,
            executable,
        },
        worktree_entries,
        common_entries,
        gitdir_entries,
    })
}

fn create_owner_worker_context(
    snapshot: &PrivateSnapshot,
    selected_path: &RelPath,
) -> Result<(worker::OwnerLocalGitContext, tempfile::TempDir), DesktopMutationError> {
    let selected_kind = match snapshot.files.get(selected_path).map(|meta| meta.kind) {
        None => worker::GuestSelectedNodeKind::Absent,
        Some(Kind::File) => worker::GuestSelectedNodeKind::File,
        Some(Kind::Symlink) => worker::GuestSelectedNodeKind::Symlink,
        Some(Kind::Directory) => worker::GuestSelectedNodeKind::Directory,
        Some(Kind::Other) => return Err(DesktopFileErrorCode::Unsupported.into()),
    };
    let common_config = read_optional_worker_config(&snapshot.path().join(".git/config"))?;
    let worktree_config =
        read_optional_worker_config(&snapshot.path().join(".git/config.worktree"))?;
    let context = worker::OwnerLocalGitContext::new(
        selected_kind,
        common_config.as_deref(),
        worktree_config.as_deref(),
    )
    .map_err(map_service_error)?;
    let bytes = serde_json::to_vec(&context).map_err(|_| DesktopFileErrorCode::Io)?;
    if bytes.len() > MAX_OWNER_CONTEXT_BYTES {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    let input = tempfile::Builder::new()
        .prefix("lomi-desktop-git-input-")
        .tempdir()
        .map_err(|_| DesktopFileErrorCode::Io)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(input.path().join("context.json"))
        .map_err(|_| DesktopFileErrorCode::Io)?;
    file.write_all(&bytes)
        .and_then(|_| file.flush())
        .map_err(|_| DesktopFileErrorCode::Io)?;
    Ok((context, input))
}

fn read_optional_worker_config(path: &Path) -> Result<Option<Vec<u8>>, DesktopMutationError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(DesktopFileErrorCode::Io.into()),
    };
    if !metadata.file_type().is_file() {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    if metadata.len() > MAX_IGNORE_BYTES as u64 {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    let bytes = fs::read(path).map_err(|_| DesktopFileErrorCode::Io)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    Ok(Some(bytes))
}

fn read_bounded_private_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, DesktopMutationError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DesktopFileErrorCode::Changed)?;
    if !metadata.file_type().is_file() {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    if metadata.len() > max_bytes as u64 {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    let bytes = fs::read(path).map_err(|_| DesktopFileErrorCode::Io)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    Ok(bytes)
}

fn copy_snapshot_file(
    service: &GitService,
    meta: &Meta,
    destination: &Path,
    replace: bool,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<(bool, u64), DesktopMutationError> {
    if meta.nlink != 1 {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if replace {
        options.truncate(true);
    } else {
        options.create_new(true);
    }
    let mut output = options
        .open(destination)
        .map_err(|_| DesktopFileErrorCode::Io)?;
    let mut offset = 0u64;
    let mut executable = None;
    while offset < meta.size || (meta.size == 0 && executable.is_none()) {
        check_phase(
            phase_check,
            control.deadline,
            LocalNativeFileCheckPhase::Progress,
        )?;
        let chunk = service
            .files
            .read_snapshot_chunk(meta.entry, &meta.revision, offset, SNAPSHOT_READ_CHUNK)
            .map_err(map_file_error_to_desktop)?;
        if chunk.meta.revision != meta.revision
            || chunk.offset != offset
            || chunk.bytes.len() > SNAPSHOT_READ_CHUNK
        {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        match executable {
            Some(previous) if previous != chunk.executable => {
                return Err(DesktopFileErrorCode::Changed.into());
            }
            None => executable = Some(chunk.executable),
            _ => {}
        }
        if chunk.bytes.is_empty() && offset < meta.size {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        output
            .write_all(&chunk.bytes)
            .map_err(|_| DesktopFileErrorCode::Io)?;
        offset = offset
            .checked_add(chunk.bytes.len() as u64)
            .ok_or(DesktopFileErrorCode::Limit)?;
        if offset > meta.size {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        if meta.size == 0 {
            break;
        }
    }
    output.flush().map_err(|_| DesktopFileErrorCode::Io)?;
    Ok((executable.unwrap_or(false), offset))
}

fn copy_metadata_entry(
    service: &GitService,
    entry: &SnapshotEntry,
    snapshot_root: &Path,
    replace: bool,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<(), DesktopMutationError> {
    let path = entry
        .path
        .to_host_path(snapshot_root)
        .map_err(map_service_error)?;
    match entry.meta.kind {
        Kind::Directory => match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error)
                if replace
                    && error.kind() == std::io::ErrorKind::AlreadyExists
                    && fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) => {}
            Err(_) => return Err(DesktopFileErrorCode::Io.into()),
        },
        Kind::File => {
            if entry.meta.size > MAX_SNAPSHOT_FILE_BYTES {
                return Err(DesktopFileErrorCode::Limit.into());
            }
            copy_snapshot_file(service, &entry.meta, &path, replace, control, phase_check)?;
        }
        Kind::Symlink | Kind::Other => return Err(DesktopFileErrorCode::Protected.into()),
    }
    Ok(())
}

fn validate_git_metadata_entries(entries: &[SnapshotEntry]) -> Result<(), DesktopMutationError> {
    for entry in entries {
        if entry.path.0.first().is_some_and(|part| part == b".git")
            && (entry.meta.kind == Kind::Symlink
                || entry.meta.kind == Kind::Other
                || (entry.meta.kind == Kind::File && entry.meta.nlink != 1))
        {
            return Err(DesktopFileErrorCode::Protected.into());
        }
    }
    Ok(())
}

fn is_worktree_local_git_path(path: &RelPath) -> bool {
    if path.0.len() == 2
        && path.0[0] == b".git"
        && matches!(
            path.0[1].as_slice(),
            b"HEAD" | b"index" | b"config.worktree"
        )
    {
        return true;
    }
    if path.0.len() >= 3 && path.0[0] == b".git" {
        if path.0[1] == b"refs"
            && matches!(path.0[2].as_slice(), b"bisect" | b"rewritten" | b"worktree")
        {
            return true;
        }
        if path.0[1] == b"logs"
            && (path.0[2] == b"HEAD"
                || (path.0[2] == b"refs"
                    && path.0.len() >= 4
                    && matches!(path.0[3].as_slice(), b"bisect" | b"rewritten" | b"worktree")))
        {
            return true;
        }
    }
    false
}

fn is_worktree_local_git_ancestor(path: &RelPath, entries: &[SnapshotEntry]) -> bool {
    path.0.len() >= 2
        && entries.iter().any(|entry| {
            entry.path.0.len() > path.0.len()
                && entry.path.0.starts_with(&path.0)
                && is_worktree_local_git_path(&entry.path)
        })
}

fn is_root_git_pointer(path: &RelPath) -> bool {
    path.0.len() == 2
        && path.0[0] == b".git"
        && matches!(path.0[1].as_slice(), b"commondir" | b"gitdir")
}

#[cfg(windows)]
fn restored_worktree_kind(
    mode: u32,
    core_symlinks: Option<bool>,
) -> Result<(GitPullNodeKind, bool), DesktopMutationError> {
    match mode {
        0o100644 => Ok((GitPullNodeKind::File, false)),
        0o100755 => Ok((GitPullNodeKind::File, true)),
        0o120000 if core_symlinks == Some(false) => Ok((GitPullNodeKind::File, false)),
        0o120000 if core_symlinks == Some(true) => Ok((GitPullNodeKind::Symlink, false)),
        0o120000 => Err(DesktopFileErrorCode::Unsupported.into()),
        _ => Err(DesktopFileErrorCode::Unsupported.into()),
    }
}

#[cfg(not(windows))]
fn restored_worktree_kind(
    mode: u32,
    _core_symlinks: Option<bool>,
) -> Result<(GitPullNodeKind, bool), DesktopMutationError> {
    match mode {
        0o100644 => Ok((GitPullNodeKind::File, false)),
        0o100755 => Ok((GitPullNodeKind::File, true)),
        0o120000 => Ok((GitPullNodeKind::Symlink, false)),
        _ => Err(DesktopFileErrorCode::Unsupported.into()),
    }
}

fn desktop_metadata_preconditions(
    service: &GitService,
    repository: &Repository,
    snapshot: &PrivateSnapshot,
    worktree_entries: &[SnapshotEntry],
    common_entries: &[SnapshotEntry],
    gitdir_entries: &[SnapshotEntry],
    control: &RequestControl,
) -> Result<Vec<GitFilePrecondition>, DesktopMutationError> {
    let mut conditions = Vec::with_capacity(4);

    let commondir_condition = match repository.commondir_marker.as_ref() {
        Some(marker) => GitFilePrecondition {
            parent: repository.gitdir.entry,
            name: b"commondir".to_vec(),
            entry: Some(marker.entry),
            revision: Some(marker.revision.clone()),
        },
        None => GitFilePrecondition {
            parent: repository.gitdir.entry,
            name: b"commondir".to_vec(),
            entry: None,
            revision: None,
        },
    };
    conditions.push(commondir_condition);

    for name in [b"HEAD".as_slice(), b"index".as_slice()] {
        let path = RelPath(vec![b".git".to_vec(), name.to_vec()]);
        let in_snapshot = snapshot.files.get(&path);
        let current = service
            .lookup_optional_child(
                repository.gitdir.entry,
                &repository.gitdir_path,
                name,
                control,
            )
            .map_err(map_service_error)?;
        match (in_snapshot, current) {
            (Some(expected), Some(current))
                if expected.entry == current.entry
                    && expected.revision == current.revision
                    && current.kind == Kind::File =>
            {
                service
                    .revalidate_entry(&current, control)
                    .map_err(map_service_error)?;
                conditions.push(GitFilePrecondition {
                    parent: repository.gitdir.entry,
                    name: name.to_vec(),
                    entry: Some(current.entry),
                    revision: Some(current.revision),
                });
            }
            (None, None) if name == b"index" => conditions.push(GitFilePrecondition {
                parent: repository.gitdir.entry,
                name: name.to_vec(),
                entry: None,
                revision: None,
            }),
            _ => return Err(DesktopFileErrorCode::Changed.into()),
        }
    }
    let common_config = service
        .lookup_optional_child(
            repository.commondir.entry,
            &repository.common_path,
            b"config",
            control,
        )
        .map_err(map_service_error)?;
    push_snapshot_file_condition(
        service,
        repository.commondir.entry,
        &repository.common_path,
        b"config",
        &RelPath(vec![b".git".to_vec(), b"config".to_vec()]),
        common_config,
        snapshot,
        control,
        &mut conditions,
    )?;
    let config_worktree = service
        .lookup_optional_child(
            repository.gitdir.entry,
            &repository.gitdir_path,
            b"config.worktree",
            control,
        )
        .map_err(map_service_error)?;
    push_snapshot_file_condition(
        service,
        repository.gitdir.entry,
        &repository.gitdir_path,
        b"config.worktree",
        &RelPath(vec![b".git".to_vec(), b"config.worktree".to_vec()]),
        config_worktree,
        snapshot,
        control,
        &mut conditions,
    )?;
    // Selected status follows symbolic HEAD through its loose ref chain and
    // packed-refs. Resolve those guards against the real common-dir or
    // worktree gitdir; the synthetic linked snapshot flattens both trees.
    let reference_preconditions = desktop_reference_preconditions(
        service,
        repository,
        snapshot,
        worktree_entries,
        common_entries,
        gitdir_entries,
        control,
    )?;
    for precondition in reference_preconditions {
        if !conditions.contains(&precondition) {
            conditions.push(precondition);
        }
    }
    if conditions.len() > 16 {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    Ok(conditions)
}

fn desktop_reference_preconditions(
    service: &GitService,
    repository: &Repository,
    snapshot: &PrivateSnapshot,
    worktree_entries: &[SnapshotEntry],
    common_entries: &[SnapshotEntry],
    gitdir_entries: &[SnapshotEntry],
    control: &RequestControl,
) -> Result<Vec<GitFilePrecondition>, DesktopMutationError> {
    let head_path = snapshot.path().join(".git").join("HEAD");
    let head_bytes = read_bounded_private_file(&head_path, MAX_GIT_POINTER_BYTES)?;
    let head_text = std::str::from_utf8(&head_bytes).map_err(|_| DesktopFileErrorCode::Changed)?;
    if !head_text.starts_with("ref: ") {
        return Ok(Vec::new());
    }
    let reference = parse_pointer(head_text, "ref: ").map_err(map_service_error)?;
    let mut path = reference_rel_path(reference).map_err(map_service_error)?;
    let separate_worktree_gitdir = repository.gitdir_identity != repository.common_identity;
    let synthetic_metadata = repository.git_marker.kind == Kind::File || separate_worktree_gitdir;
    let mut seen = HashSet::new();
    let mut conditions = Vec::new();
    let mut terminated = false;
    for _ in 0..8 {
        if !seen.insert(path.clone()) {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        let private_worktree_ref = separate_worktree_gitdir && is_worktree_local_git_path(&path);
        let (root, root_path, source_entries) = if private_worktree_ref {
            (
                repository.gitdir.entry,
                &repository.gitdir_path,
                gitdir_entries,
            )
        } else if synthetic_metadata {
            (
                repository.commondir.entry,
                &repository.common_path,
                common_entries,
            )
        } else {
            (
                repository.commondir.entry,
                &repository.common_path,
                worktree_entries,
            )
        };
        let components = path.0.get(1..).ok_or(DesktopFileErrorCode::Changed)?;
        let (condition, bytes) = capture_git_metadata_path(
            service,
            root,
            root_path,
            components,
            &path,
            snapshot,
            source_entries,
            control,
            Some(MAX_GIT_POINTER_BYTES),
        )?;
        conditions.push(condition);
        let Some(bytes) = bytes else {
            terminated = true;
            break;
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| DesktopFileErrorCode::Changed)?;
        if text.starts_with("ref: ") {
            let target = parse_pointer(text, "ref: ").map_err(map_service_error)?;
            path = reference_rel_path(target).map_err(map_service_error)?;
        } else {
            terminated = true;
            break;
        }
    }
    if !terminated {
        return Err(DesktopFileErrorCode::Changed.into());
    }

    let packed_path = RelPath(vec![b".git".to_vec(), b"packed-refs".to_vec()]);
    let (packed_refs, _) = capture_git_metadata_path(
        service,
        repository.commondir.entry,
        &repository.common_path,
        &[b"packed-refs".to_vec()],
        &packed_path,
        snapshot,
        if synthetic_metadata {
            common_entries
        } else {
            worktree_entries
        },
        control,
        None,
    )?;
    conditions.push(packed_refs);
    Ok(conditions)
}

#[allow(clippy::too_many_arguments)]
fn capture_git_metadata_path(
    service: &GitService,
    root: EntryRef,
    root_path: &RelPath,
    components: &[Vec<u8>],
    snapshot_path: &RelPath,
    snapshot: &PrivateSnapshot,
    source_entries: &[SnapshotEntry],
    control: &RequestControl,
    max_content: Option<usize>,
) -> Result<(GitFilePrecondition, Option<Vec<u8>>), DesktopMutationError> {
    let (name, parents) = components
        .split_last()
        .ok_or(DesktopFileErrorCode::Changed)?;
    let mut parent_entry = root;
    let mut parent_path = root_path.clone();
    for (index, component) in parents.iter().enumerate() {
        let expected_path = RelPath(
            std::iter::once(b".git".to_vec())
                .chain(components[..=index].iter().cloned())
                .collect(),
        );
        let expected = source_entries
            .iter()
            .find(|entry| entry.path == expected_path)
            .map(|entry| &entry.meta);
        let current = service
            .lookup_optional_child(parent_entry, &parent_path, component, control)
            .map_err(map_service_error)?;
        match (expected, current) {
            (Some(expected), Some(current))
                if expected.entry == current.entry
                    && expected.revision == current.revision
                    && expected.kind == Kind::Directory
                    && current.kind == Kind::Directory =>
            {
                parent_entry = current.entry;
                parent_path = parent_path.joined(component);
            }
            (None, None) => {
                return Ok((
                    GitFilePrecondition {
                        parent: parent_entry,
                        name: component.clone(),
                        entry: None,
                        revision: None,
                    },
                    None,
                ));
            }
            _ => return Err(DesktopFileErrorCode::Changed.into()),
        }
    }

    let expected = source_entries
        .iter()
        .find(|entry| &entry.path == snapshot_path)
        .map(|entry| &entry.meta);
    let current = service
        .lookup_optional_child(parent_entry, &parent_path, name, control)
        .map_err(map_service_error)?;
    match (expected, current) {
        (Some(expected), Some(current))
            if expected.entry == current.entry
                && expected.revision == current.revision
                && expected.kind == Kind::File
                && current.kind == Kind::File
                && current.nlink == 1 =>
        {
            let bytes = if let Some(limit) = max_content {
                let contents = service.read_pointer(&current).map_err(map_service_error)?;
                if contents.len() > limit {
                    return Err(DesktopFileErrorCode::Limit.into());
                }
                let snapshot_bytes = read_bounded_private_file(
                    &snapshot_path
                        .to_host_path(snapshot.path())
                        .map_err(map_service_error)?,
                    limit,
                )?;
                if snapshot_bytes != contents.as_bytes() {
                    return Err(DesktopFileErrorCode::Changed.into());
                }
                Some(snapshot_bytes)
            } else {
                None
            };
            Ok((
                GitFilePrecondition {
                    parent: parent_entry,
                    name: name.clone(),
                    entry: Some(current.entry),
                    revision: Some(current.revision),
                },
                bytes,
            ))
        }
        (None, None) => Ok((
            GitFilePrecondition {
                parent: parent_entry,
                name: name.clone(),
                entry: None,
                revision: None,
            },
            None,
        )),
        _ => Err(DesktopFileErrorCode::Changed.into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn push_snapshot_file_condition(
    service: &GitService,
    parent: EntryRef,
    parent_path: &RelPath,
    name: &[u8],
    snapshot_path: &RelPath,
    current: Option<Meta>,
    snapshot: &PrivateSnapshot,
    control: &RequestControl,
    conditions: &mut Vec<GitFilePrecondition>,
) -> Result<(), DesktopMutationError> {
    let expected = snapshot.files.get(snapshot_path);
    match (expected, current) {
        (Some(expected), Some(current))
            if expected.entry == current.entry
                && expected.revision == current.revision
                && current.kind == Kind::File
                && current.nlink == 1 =>
        {
            service
                .revalidate_entry(&current, control)
                .map_err(map_service_error)?;
            conditions.push(GitFilePrecondition {
                parent,
                name: name.to_vec(),
                entry: Some(current.entry),
                revision: Some(current.revision),
            });
        }
        (None, None) => conditions.push(GitFilePrecondition {
            parent,
            name: name.to_vec(),
            entry: None,
            revision: None,
        }),
        _ => return Err(DesktopFileErrorCode::Changed.into()),
    }
    let _ = parent_path;
    Ok(())
}

fn repository_preconditions(
    repository: &Repository,
) -> Result<Vec<GitPullPrecondition>, DesktopMutationError> {
    let marker_kind = match repository.git_marker.kind {
        Kind::Directory => GitPullNodeKind::Directory,
        Kind::File => GitPullNodeKind::File,
        Kind::Symlink | Kind::Other => return Err(DesktopFileErrorCode::Protected.into()),
    };
    let mut conditions = vec![GitPullPrecondition {
        parent: repository.entry,
        name: b".git".to_vec(),
        entry: Some(repository.git_marker.entry),
        revision: Some(repository.git_marker.revision.clone()),
        kind: Some(marker_kind),
    }];
    if repository.commondir.entry != repository.gitdir.entry {
        let marker = repository
            .commondir_marker
            .as_ref()
            .filter(|marker| marker.kind == Kind::File)
            .ok_or(DesktopFileErrorCode::Changed)?;
        conditions.push(GitPullPrecondition {
            parent: repository.gitdir.entry,
            name: b"commondir".to_vec(),
            entry: Some(marker.entry),
            revision: Some(marker.revision.clone()),
            kind: Some(GitPullNodeKind::File),
        });
    }
    Ok(conditions)
}

fn local_ignore_target(
    service: &GitService,
    repository: &Repository,
    control: &RequestControl,
) -> Result<(GitIgnoreTarget, GitFilePrecondition, Vec<Vec<u8>>, Vec<u8>), DesktopMutationError> {
    let info = service
        .lookup_optional_child(
            repository.commondir.entry,
            &repository.common_path,
            b"info",
            control,
        )
        .map_err(map_service_error)?;
    match info {
        Some(info) if info.kind == Kind::Directory => {
            let exclude = service
                .lookup_optional_child(
                    info.entry,
                    &repository.common_path.joined(b"info"),
                    b"exclude",
                    control,
                )
                .map_err(map_service_error)?;
            let expected =
                child_precondition(info.entry, b"exclude", exclude.as_ref(), Kind::File)?;
            let bytes = read_optional_git_file(service, exclude.as_ref(), control)?;
            Ok((
                GitIgnoreTarget::LocalExclude {
                    common_dir: repository.commondir.entry,
                },
                expected,
                Vec::new(),
                bytes,
            ))
        }
        Some(_) => Err(DesktopFileErrorCode::Protected.into()),
        None => Ok((
            GitIgnoreTarget::LocalExclude {
                common_dir: repository.commondir.entry,
            },
            GitFilePrecondition {
                parent: repository.commondir.entry,
                name: b"info".to_vec(),
                entry: None,
                revision: None,
            },
            vec![b"info".to_vec()],
            Vec::new(),
        )),
    }
}

fn worktree_ignore_target(
    service: &GitService,
    repository: &Repository,
    control: &RequestControl,
) -> Result<(GitIgnoreTarget, GitFilePrecondition, Vec<Vec<u8>>, Vec<u8>), DesktopMutationError> {
    let ignore = service
        .lookup_optional_child(repository.entry, &repository.path, b".gitignore", control)
        .map_err(map_service_error)?;
    let expected =
        child_precondition(repository.entry, b".gitignore", ignore.as_ref(), Kind::File)?;
    let bytes = read_optional_git_file(service, ignore.as_ref(), control)?;
    Ok((
        GitIgnoreTarget::Worktree {
            repository: repository.entry,
        },
        expected,
        Vec::new(),
        bytes,
    ))
}

fn child_precondition(
    parent: EntryRef,
    name: &[u8],
    entry: Option<&Meta>,
    expected_kind: Kind,
) -> Result<GitFilePrecondition, DesktopMutationError> {
    if entry.is_some_and(|meta| meta.kind != expected_kind || meta.nlink != 1) {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    Ok(GitFilePrecondition {
        parent,
        name: name.to_vec(),
        entry: entry.map(|meta| meta.entry),
        revision: entry.map(|meta| meta.revision.clone()),
    })
}

fn read_optional_git_file(
    service: &GitService,
    entry: Option<&Meta>,
    control: &RequestControl,
) -> Result<Vec<u8>, DesktopMutationError> {
    let Some(entry) = entry else {
        return Ok(Vec::new());
    };
    if entry.kind != Kind::File || entry.nlink != 1 || entry.size > MAX_IGNORE_BYTES as u64 {
        return Err(if entry.size > MAX_IGNORE_BYTES as u64 {
            DesktopFileErrorCode::Limit
        } else {
            DesktopFileErrorCode::Protected
        }
        .into());
    }
    let mut bytes = Vec::with_capacity(entry.size as usize);
    let mut offset = 0u64;
    while offset < entry.size || (entry.size == 0 && offset == 0) {
        check_control(control)?;
        let chunk = service
            .files
            .read_snapshot_chunk(entry.entry, &entry.revision, offset, DESKTOP_READ_CHUNK)
            .map_err(map_file_error_to_desktop)?;
        if chunk.meta.revision != entry.revision || chunk.offset != offset {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        if chunk.bytes.is_empty() && offset < entry.size {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        bytes.extend_from_slice(&chunk.bytes);
        offset += chunk.bytes.len() as u64;
        if bytes.len() > MAX_IGNORE_BYTES {
            return Err(DesktopFileErrorCode::Limit.into());
        }
        if entry.size == 0 {
            break;
        }
    }
    if offset != entry.size {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    service
        .revalidate_entry(entry, control)
        .map_err(map_service_error)?;
    Ok(bytes)
}

fn desktop_pull_file(
    repository: &Repository,
    snapshot: &PrivateSnapshot,
    path: &RelPath,
    contents: Vec<u8>,
    kind: GitPullNodeKind,
    executable: bool,
) -> Result<lomi_files::GitPullFile, DesktopMutationError> {
    let (name, parents) = path.0.split_last().ok_or(DesktopFileErrorCode::Invalid)?;
    let nearest = (0..=parents.len())
        .rev()
        .find_map(|existing_len| {
            let parent_path = RelPath(parents[..existing_len].to_vec());
            snapshot_directory(snapshot, &parent_path)
                .filter(|meta| meta.kind == Kind::Directory)
                .map(|meta| (existing_len, meta.entry))
        })
        .ok_or(DesktopFileErrorCode::Changed)?;
    let (existing_len, parent) = nearest;
    let (parent_suffix, expected) = if existing_len == parents.len() {
        let entry = snapshot.files.get(path);
        if entry.is_some_and(|meta| !matches!(meta.kind, Kind::File | Kind::Symlink)) {
            return Err(DesktopFileErrorCode::Unsupported.into());
        }
        (
            Vec::new(),
            GitPullPrecondition {
                parent,
                name: name.clone(),
                entry: entry.map(|meta| meta.entry),
                revision: entry.map(|meta| meta.revision.clone()),
                kind: entry.map(|meta| match meta.kind {
                    Kind::File => GitPullNodeKind::File,
                    Kind::Symlink => GitPullNodeKind::Symlink,
                    _ => unreachable!(),
                }),
            },
        )
    } else {
        (
            parents[existing_len..].to_vec(),
            GitPullPrecondition {
                parent,
                name: parents[existing_len].clone(),
                entry: None,
                revision: None,
                kind: None,
            },
        )
    };
    let mut workspace_path = repository.path.0.clone();
    workspace_path.extend(path.0.iter().cloned());
    Ok(lomi_files::GitPullFile {
        path: workspace_path,
        parent,
        parent_suffix,
        name: name.clone(),
        expected,
        contents: Some(contents),
        kind,
        executable,
    })
}

fn selected_precondition(
    snapshot: &PrivateSnapshot,
    path: &RelPath,
    kind: GitPullNodeKind,
) -> Result<GitPullPrecondition, DesktopMutationError> {
    let (name, parents) = path.0.split_last().ok_or(DesktopFileErrorCode::Invalid)?;
    let parent = if parents.is_empty() {
        &snapshot.root
    } else {
        snapshot
            .files
            .get(&RelPath(parents.to_vec()))
            .filter(|meta| meta.kind == Kind::Directory)
            .ok_or(DesktopFileErrorCode::NotFound)?
    };
    let meta = snapshot
        .files
        .get(path)
        .ok_or(DesktopFileErrorCode::NotFound)?;
    if meta.kind == Kind::Other {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }
    Ok(GitPullPrecondition {
        parent: parent.entry,
        name: name.clone(),
        entry: Some(meta.entry),
        revision: Some(meta.revision.clone()),
        kind: Some(kind),
    })
}

fn revalidate_preconditions(
    files: &FileRoot,
    preconditions: &[GitFilePrecondition],
) -> Result<(), DesktopMutationError> {
    for condition in preconditions {
        let current = child_by_entry(files, condition.parent, &condition.name)?;
        match (condition.entry, condition.revision.as_deref(), current) {
            (Some(expected), Some(revision), Some(current))
                if current.entry == expected
                    && current.revision == revision
                    && current.kind == Kind::File => {}
            (None, None, None) => {}
            _ => return Err(DesktopFileErrorCode::Changed.into()),
        }
    }
    Ok(())
}

fn revalidate_selected(
    files: &FileRoot,
    selected: &GitPullPrecondition,
) -> Result<(), DesktopMutationError> {
    let current = child_by_entry(files, selected.parent, &selected.name)?;
    let (Some(expected), Some(revision), Some(current), Some(expected_kind)) = (
        selected.entry,
        selected.revision.as_deref(),
        current,
        selected.kind,
    ) else {
        return Err(DesktopFileErrorCode::Changed.into());
    };
    if current.entry != expected
        || current.revision != revision
        || git_pull_kind(current.kind)? != expected_kind
    {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    Ok(())
}

fn revalidate_desktop_trash_snapshot(
    service: &GitService,
    selected: &GitPullPrecondition,
    repository: &[GitPullPrecondition],
    metadata: &[GitFilePrecondition],
    control: &RequestControl,
    deadline: Instant,
) -> Result<(), DesktopMutationError> {
    check_control(control)?;
    if Instant::now() >= deadline {
        return Err(DesktopFileErrorCode::DeadlineExceeded.into());
    }
    service
        .files
        .pin_native_directory(service.files.root_entry(), &service.root_path)
        .map_err(map_file_error_to_desktop)?;
    revalidate_selected(&service.files, selected)?;
    revalidate_repository_preconditions(&service.files, repository)?;
    revalidate_preconditions(&service.files, metadata)?;
    check_control(control)?;
    if Instant::now() >= deadline {
        return Err(DesktopFileErrorCode::DeadlineExceeded.into());
    }
    service
        .files
        .pin_native_directory(service.files.root_entry(), &service.root_path)
        .map_err(map_file_error_to_desktop)?;
    Ok(())
}

fn revalidate_repository_preconditions(
    files: &FileRoot,
    preconditions: &[GitPullPrecondition],
) -> Result<(), DesktopMutationError> {
    for expected in preconditions {
        let current = child_by_entry(files, expected.parent, &expected.name)?;
        let (Some(entry), Some(revision), Some(kind), Some(current)) = (
            expected.entry,
            expected.revision.as_deref(),
            expected.kind,
            current,
        ) else {
            return Err(DesktopFileErrorCode::Changed.into());
        };
        if current.entry != entry
            || current.revision != revision
            || git_pull_kind(current.kind)? != kind
        {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    }
    Ok(())
}

fn git_pull_kind(kind: Kind) -> Result<GitPullNodeKind, DesktopMutationError> {
    match kind {
        Kind::File => Ok(GitPullNodeKind::File),
        Kind::Directory => Ok(GitPullNodeKind::Directory),
        Kind::Symlink => Ok(GitPullNodeKind::Symlink),
        Kind::Other => Err(DesktopFileErrorCode::Unsupported.into()),
    }
}

fn desktop_mutation_error_code(error: DesktopMutationError) -> DesktopFileErrorCode {
    match error {
        DesktopMutationError::Before(code) => code,
        DesktopMutationError::Uncertain => DesktopFileErrorCode::Changed,
    }
}

fn child_by_entry(
    files: &FileRoot,
    parent: EntryRef,
    name: &[u8],
) -> Result<Option<Meta>, DesktopMutationError> {
    let mut cursor = None;
    let mut seen = HashSet::new();
    loop {
        let page = files
            .list(parent, cursor.as_deref(), MAX_PAGE_SIZE)
            .map_err(map_file_error_to_desktop)?;
        if let Some(meta) = page.entries.into_iter().find(|entry| entry.name == name) {
            return Ok(Some(meta));
        }
        match page.next {
            Some(next) if page.truncated && seen.insert(next.clone()) => cursor = Some(next),
            Some(_) | None if page.truncated => return Err(DesktopFileErrorCode::Changed.into()),
            None => return Ok(None),
            Some(_) => return Err(DesktopFileErrorCode::Changed.into()),
        }
    }
}

fn read_restore_blob(
    output_root: &Path,
    expected_size: u64,
    expected_hash: &str,
    deadline: Instant,
    control: &RequestControl,
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<Vec<u8>, DesktopMutationError> {
    if expected_size > MAX_RESTORE_BYTES {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    let path = output_root.join(worker::RESTORE_INDEX_OUTPUT_FILE);
    let metadata = fs::symlink_metadata(&path).map_err(|_| DesktopFileErrorCode::Io)?;
    if !metadata.file_type().is_file() || metadata.len() != expected_size {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    let mut file = fs::File::open(path).map_err(|_| DesktopFileErrorCode::Io)?;
    let opened = file.metadata().map_err(|_| DesktopFileErrorCode::Io)?;
    if !opened.is_file() || opened.len() != expected_size {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    let reserve = usize::try_from(expected_size).map_err(|_| DesktopFileErrorCode::Limit)?;
    let mut contents = Vec::with_capacity(reserve);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; DESKTOP_READ_CHUNK];
    loop {
        check_phase(phase_check, deadline, LocalNativeFileCheckPhase::Progress)?;
        check_control(control)?;
        let count = file
            .read(&mut buffer)
            .map_err(|_| DesktopFileErrorCode::Io)?;
        if count == 0 {
            break;
        }
        if contents.len().saturating_add(count) > reserve {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        hasher.update(&buffer[..count]);
        contents.extend_from_slice(&buffer[..count]);
    }
    if contents.len() as u64 != expected_size || hex_digest(&hasher.finalize()) != expected_hash {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    Ok(contents)
}

fn ignore_pattern(path: &[u8], directory: bool) -> Result<Vec<u8>, DesktopMutationError> {
    if path.is_empty() || path.contains(&b'\r') || path.contains(&b'\n') {
        return Err(DesktopFileErrorCode::Invalid.into());
    }
    let mut pattern = Vec::with_capacity(path.len() + 3);
    pattern.push(b'/');
    for byte in path {
        if matches!(*byte, b' ' | b'\\' | b'*' | b'?' | b'[' | b']') {
            pattern.push(b'\\');
        }
        pattern.push(*byte);
    }
    if directory {
        pattern.push(b'/');
    }
    Ok(pattern)
}

fn contains_ignore_pattern(existing: &[u8], pattern: &[u8]) -> bool {
    existing
        .split(|byte| *byte == b'\n')
        .any(|line| line.strip_suffix(b"\r").unwrap_or(line) == pattern)
}

fn append_ignore_pattern(
    mut existing: Vec<u8>,
    pattern: &[u8],
) -> Result<Vec<u8>, DesktopMutationError> {
    if !contains_ignore_pattern(&existing, pattern) {
        if !existing.is_empty() && !existing.ends_with(b"\n") {
            existing.push(b'\n');
        }
        existing.extend_from_slice(pattern);
        existing.push(b'\n');
    }
    if existing.len() > MAX_IGNORE_BYTES {
        return Err(DesktopFileErrorCode::Limit.into());
    }
    Ok(existing)
}

fn verify_expected_change(
    actual: &worker::GuestSelectedChange,
    expected: &lomi_files::desktop::DesktopGitChange,
) -> Result<(), DesktopMutationError> {
    let expected_path = expected.path.as_bytes();
    let expected_original = expected.original_path.as_deref().map(str::as_bytes);
    if actual.path_hex != hex_bytes(expected_path)
        || actual.original_path_hex.as_deref() != expected_original.map(hex_bytes).as_deref()
        || actual.index != expected.index
        || actual.worktree != expected.worktree
    {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    Ok(())
}

fn selected_repository_path<'a>(
    request: &'a DesktopMutationRequest,
    repository_relative: &str,
) -> Result<String, DesktopMutationError> {
    let repository = normalized_relative(repository_relative)?;
    let selected = normalized_relative(&request.relative_path)?;
    if repository.is_empty() {
        return Ok(selected);
    }
    selected
        .strip_prefix(&format!("{repository}/"))
        .map(str::to_owned)
        .ok_or_else(|| DesktopFileErrorCode::Invalid.into())
}

fn parse_workspace_relative(path: &str) -> Result<RelPath, DesktopMutationError> {
    let normalized = normalized_relative(path)?;
    if normalized.is_empty() {
        return Ok(RelPath::root());
    }
    parse_repository_relative(&normalized)
}

fn parse_repository_relative(path: &str) -> Result<RelPath, DesktopMutationError> {
    let normalized = normalized_relative(path)?;
    if normalized.is_empty() {
        return Err(DesktopFileErrorCode::Invalid.into());
    }
    let parsed = RelPath::root()
        .resolve_relative(&normalized)
        .map_err(map_service_error)?;
    if parsed
        .0
        .iter()
        .any(|component| !allowed_git_path(component))
    {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    Ok(parsed)
}

fn normalized_relative(path: &str) -> Result<String, DesktopMutationError> {
    let mut parts = Vec::new();
    for component in std::path::Path::new(path).components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                let name = name.to_str().ok_or(DesktopFileErrorCode::Invalid)?;
                if name.contains(['\\', ':', '\0']) {
                    return Err(DesktopFileErrorCode::Invalid.into());
                }
                parts.push(name);
            }
            _ => return Err(DesktopFileErrorCode::Invalid.into()),
        }
    }
    Ok(parts.join("/"))
}

fn check_phase(
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
    deadline: Instant,
    phase: LocalNativeFileCheckPhase,
) -> Result<(), DesktopMutationError> {
    check_local_phase(phase_check, deadline, phase).map_err(DesktopMutationError::Before)
}

fn check_workspace_named_binding(service: &GitService) -> Result<(), DesktopFileErrorCode> {
    service
        .files
        .pin_native_directory(service.files.root_entry(), &service.root_path)
        .map(|_| ())
        .map_err(map_file_error_to_desktop)
}

fn check_local_phase(
    phase_check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
    deadline: Instant,
    phase: LocalNativeFileCheckPhase,
) -> Result<(), DesktopFileErrorCode> {
    if Instant::now() >= deadline {
        return Err(DesktopFileErrorCode::DeadlineExceeded);
    }
    phase_check(phase)?;
    if Instant::now() >= deadline {
        return Err(DesktopFileErrorCode::DeadlineExceeded);
    }
    Ok(())
}

fn check_control(control: &RequestControl) -> Result<(), DesktopMutationError> {
    control.check().map_err(map_service_error)
}

fn empty_desktop_change(operation_id: &str) -> DesktopFileChange {
    DesktopFileChange {
        operation_id: operation_id.to_owned(),
        old_path: None,
        new_path: None,
        trash: None,
    }
}

fn map_service_error(error: GitServiceError) -> DesktopMutationError {
    use GitServiceError as Git;
    DesktopMutationError::Before(match error {
        Git::Cancelled => DesktopFileErrorCode::Revoked,
        Git::DeadlineExceeded | Git::InvalidDeadline => DesktopFileErrorCode::DeadlineExceeded,
        Git::ContextMismatch | Git::RepositoryNotFound => DesktopFileErrorCode::NotFound,
        Git::InvalidCursor => DesktopFileErrorCode::Invalid,
        Git::RepositoryChanged | Git::StaleState | Git::MutationConflict => {
            DesktopFileErrorCode::Changed
        }
        Git::UnsafeRepository => DesktopFileErrorCode::Protected,
        Git::ResourceLimit => DesktopFileErrorCode::Limit,
        Git::UnsupportedCapability | Git::ExecutorUnavailable => DesktopFileErrorCode::Unsupported,
        Git::MutationOutcomeUnknown | Git::NetworkOutcomeUnknown => {
            return DesktopMutationError::Uncertain;
        }
        Git::DiscoveryFailed
        | Git::ExecutorFailed
        | Git::InvalidObjectId
        | Git::IdentityRequired
        | Git::MutationFailed
        | Git::CredentialsRequired
        | Git::NetworkFailed
        | Git::PushRejected => DesktopFileErrorCode::Io,
    })
}

fn map_file_error_to_desktop(error: FileError) -> DesktopFileErrorCode {
    match error {
        FileError::NotFound => DesktopFileErrorCode::NotFound,
        FileError::Changed => DesktopFileErrorCode::Changed,
        FileError::Protected => DesktopFileErrorCode::Protected,
        FileError::Exists => DesktopFileErrorCode::Exists,
        FileError::NotEmpty => DesktopFileErrorCode::NotEmpty,
        FileError::Invalid => DesktopFileErrorCode::Invalid,
        FileError::Unsupported => DesktopFileErrorCode::Unsupported,
        FileError::Limit => DesktopFileErrorCode::Limit,
        FileError::Io(_) => DesktopFileErrorCode::Io,
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn hex_digest(bytes: &[u8]) -> String {
    hex_bytes(bytes)
}
