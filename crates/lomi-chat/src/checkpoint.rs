//! Git-backed per-turn checkpoints of a working tree.
//!
//! A checkpoint is a commit built from a private, temporary index (so the
//! user's index, HEAD, branches and stash are never touched) and stored under
//! a hidden `refs/lomi/chat/...` ref. All git calls are blocking, argv-based
//! (no shell) and must be run off the async runtime by the caller.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

const REF_PREFIX: &str = "refs/lomi/chat/";
const MAX_FILES: usize = 2000;
const MAX_DIFF_BYTES: usize = 512 * 1024;
const MAX_ERR_CHARS: usize = 500;
const COMMIT_MESSAGE: &str = "Lomi chat checkpoint";
const IDENTITY_NAME: &str = "Lomi";
const IDENTITY_EMAIL: &str = "lomi@localhost";
/// Shadow repositories refuse folders with more candidate files than this.
const MAX_SHADOW_FILES: usize = 20_000;
/// Total size above which a folder without Git gets no undo snapshot.
const MAX_SHADOW_BYTES: u64 = 200 * 1024 * 1024;
/// Kept out of shadow snapshots: bulky, regenerable, or noise.
const SHADOW_EXCLUDES: &str = "# Bulky or regenerable paths; snapshots would be slow and huge.\nnode_modules/\n.DS_Store\ntarget/\n.venv/\n__pycache__/\n.next/\n.cache/\n";

static SHADOW_ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Enables checkpoints in folders that are not git repositories: they get a
/// private git dir under `root`. The first call wins.
pub fn set_shadow_root(root: PathBuf) {
    if SHADOW_ROOT.set(root.clone()).is_ok() {
        // Off the caller's thread: a scan of many shadows must not delay startup.
        std::thread::spawn(move || prune_shadows(&root));
    }
}

/// File in a shadow git dir naming the folder it tracks.
const SHADOW_FOLDER_FILE: &str = "lomi-folder";

/// Removes shadows whose recorded folder no longer exists; older shadows without
/// a record are kept (thread deletion still removes them once empty).
fn prune_shadows(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root.join("checkpoints")) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let folder = std::fs::read_to_string(dir.join(SHADOW_FOLDER_FILE)).ok();
        if folder.is_some_and(|f| !Path::new(f.trim_end()).is_dir()) {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

#[cfg(not(test))]
fn shadow_root() -> Option<PathBuf> {
    SHADOW_ROOT.get().cloned()
}

#[cfg(not(test))]
fn shadow_limit() -> usize {
    MAX_SHADOW_FILES
}

// Tests configure these per thread so they never fight over the global.
#[cfg(test)]
thread_local! {
    static TEST_ROOT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static TEST_LIMIT: std::cell::Cell<usize> = const { std::cell::Cell::new(MAX_SHADOW_FILES) };
}

#[cfg(test)]
fn shadow_root() -> Option<PathBuf> {
    TEST_ROOT.with(|r| r.borrow().clone())
}

#[cfg(test)]
fn shadow_limit() -> usize {
    TEST_LIMIT.with(|l| l.get())
}

/// A work tree plus, for non-git folders, the shadow git dir that tracks it.
#[derive(Clone)]
struct Repo {
    top: PathBuf,
    git_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeStatus {
    Added,
    Modified,
    Deleted,
    /// Never produced today: `changes` disables rename detection, so a rename
    /// is reported as a delete plus an add.
    Renamed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileChange {
    pub path: String,
    pub status: ChangeStatus,
    pub additions: u32,
    pub deletions: u32,
    pub binary: bool,
    /// The turn's own edit activities touched this path (not the user or another process).
    #[serde(default)]
    pub agent: bool,
    /// Restored by a selective undo.
    #[serde(default)]
    pub undone: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoReport {
    pub restored: Vec<String>,
    pub skipped: Vec<String>,
}

fn command(dir: &Path) -> Command {
    command_with(dir, true)
}

/// `literal` off lets pathspec magic such as `:(exclude)` work.
fn command_with(dir: &Path, literal: bool) -> Command {
    let mut c = Command::new("git");
    if literal {
        c.arg("--literal-pathspecs");
    }
    c.args([
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "gc.auto=0",
        "-c",
        "commit.gpgsign=false",
    ])
    .arg("-C")
    .arg(dir)
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("LC_ALL", "C")
    .env("GIT_LITERAL_PATHSPECS", if literal { "1" } else { "0" })
    .env_remove("GIT_INDEX_FILE")
    .env_remove("GIT_DIR")
    .env_remove("GIT_WORK_TREE")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    c
}

fn exec(c: &mut Command) -> Result<Output, String> {
    c.output().map_err(|e| format!("failed to run git: {e}"))
}

fn ok(c: &mut Command) -> Result<Vec<u8>, String> {
    let out = exec(c)?;
    if out.status.success() {
        return Ok(out.stdout);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let msg: String = stderr.trim().chars().take(MAX_ERR_CHARS).collect();
    Err(format!("git failed ({}): {msg}", out.status))
}

fn cmd(repo: &Repo) -> Command {
    cmd_with(repo, true)
}

fn cmd_with(repo: &Repo, literal: bool) -> Command {
    let mut c = command_with(&repo.top, literal);
    if let Some(git_dir) = &repo.git_dir {
        c.env("GIT_DIR", git_dir).env("GIT_WORK_TREE", &repo.top);
    }
    c
}

fn git(repo: &Repo, args: &[&str]) -> Result<Vec<u8>, String> {
    ok(cmd(repo).args(args))
}

fn git_text(repo: &Repo, args: &[&str]) -> Result<String, String> {
    let out = git(repo, args)?;
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// `None` when `cwd` is not inside a git work tree.
fn toplevel(cwd: &Path) -> Result<Option<PathBuf>, String> {
    let out = exec(command(cwd).args(["rev-parse", "--show-toplevel"]))?;
    if !out.status.success() {
        return Ok(None);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(Some(PathBuf::from(s.trim_end_matches(['\n', '\r']))))
}

/// The git work tree containing `cwd`, else the shadow repo of `cwd` (created
/// only when `create`). `None` when neither applies.
fn resolve(cwd: &Path, create: bool) -> Result<Option<Repo>, String> {
    if let Some(top) = toplevel(cwd)? {
        return Ok(Some(Repo { top, git_dir: None }));
    }
    let Some(root) = shadow_root() else {
        return Ok(None);
    };
    let top = cwd
        .canonicalize()
        .map_err(|e| format!("failed to resolve the folder: {e}"))?;
    let hash = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(top.to_string_lossy().as_bytes()))
    };
    let git_dir = root.join("checkpoints").join(format!("{hash}.git"));
    if !git_dir.join("HEAD").exists() {
        if !create {
            return Ok(None);
        }
        std::fs::create_dir_all(&git_dir)
            .map_err(|e| format!("failed to create the checkpoint store: {e}"))?;
        ok(command(&git_dir).args(["init", "-q", "--bare"]))?;
        ok(command(&git_dir).args(["config", "core.bare", "false"]))?;
        std::fs::create_dir_all(git_dir.join("info"))
            .and_then(|()| std::fs::write(git_dir.join("info/exclude"), SHADOW_EXCLUDES))
            .and_then(|()| {
                std::fs::write(
                    git_dir.join(SHADOW_FOLDER_FILE),
                    top.to_string_lossy().as_bytes(),
                )
            })
            .map_err(|e| format!("failed to write the checkpoint excludes: {e}"))?;
    }
    Ok(Some(Repo {
        top,
        git_dir: Some(git_dir),
    }))
}

fn require_repo(cwd: &Path) -> Result<Repo, String> {
    resolve(cwd, false)?.ok_or_else(|| "no checkpoints for this folder".to_string())
}

fn validate_ref(r: &str) -> Result<(), String> {
    if !r.starts_with(REF_PREFIX)
        || r.len() == REF_PREFIX.len()
        || r.contains("..")
        || r.chars().any(|c| c.is_control() || c == ' ')
    {
        return Err(format!("invalid checkpoint ref: {r:?}"));
    }
    let valid = exec(command(Path::new(".")).args(["check-ref-format", r]))?;
    if valid.status.success() {
        Ok(())
    } else {
        Err(format!("invalid checkpoint ref: {r:?}"))
    }
}

fn validate_ish(s: &str) -> Result<(), String> {
    if s.is_empty() || s.starts_with('-') || s.chars().any(|c| c.is_control()) {
        return Err(format!("invalid revision: {s:?}"));
    }
    Ok(())
}

fn validate_rel(path: &str) -> Result<(), String> {
    let ok = !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(n) if !n.eq_ignore_ascii_case(".git")));
    if ok {
        Ok(())
    } else {
        Err(format!("path escapes the work tree: {path:?}"))
    }
}

/// Whether the repository's own config (with its includes) defines a content
/// filter. `git add` and `hash-object` would run its `clean` command outside the
/// agent's sandbox, and an agent with write access to the repository could have
/// planted it in `.git/config`, so Lomi then takes no checkpoints. Global and
/// system filters (e.g. Git LFS) belong to the user and stay allowed.
fn has_filters(top: &Repo) -> Result<bool, String> {
    let out = exec(cmd(top).args([
        "config",
        "--local",
        "--includes",
        "--get-regexp",
        r"^filter\.",
    ]))?;
    match out.status.code() {
        Some(0) => Ok(!out.stdout.is_empty()),
        Some(1) => Ok(false), // no match
        _ => Err("failed to read the git config".to_string()),
    }
}

/// Builds a tree of the full working state (tracked + untracked, minus
/// ignored) using a private index. `skip` lists nested repositories (paths
/// relative to the top) that are left out; they have checkpoints of their own.
/// Returns `(tree, head)`.
fn write_tree(top: &Repo, skip: &[String]) -> Result<(String, Option<String>), String> {
    let git_dir = git_text(top, &["rev-parse", "--absolute-git-dir"])?;
    let tmp = tempfile::tempdir_in(&git_dir)
        .or_else(|_| tempfile::tempdir())
        .map_err(|e| format!("failed to create temporary index: {e}"))?;
    // A not-yet-existing path: git treats a 0-byte index file as corrupt.
    let index = tmp.path().join("index");
    let with_index = |args: &[&str]| ok(cmd(top).args(args).env("GIT_INDEX_FILE", &index));

    let head = exec(cmd(top).args(["rev-parse", "--verify", "-q", "HEAD^{commit}"]))?;
    let head = head
        .status
        .success()
        .then(|| String::from_utf8_lossy(&head.stdout).trim().to_string());
    if head.is_some() {
        with_index(&["read-tree", "HEAD"])?;
    }
    if top.git_dir.is_some() {
        let listing = with_index(&[
            "ls-files",
            "--others",
            "--cached",
            "--exclude-standard",
            "-z",
        ])?;
        if listing.iter().filter(|b| **b == 0).count() > shadow_limit() {
            return Err(
                "This folder is too large to snapshot for undo (over 20,000 files).".to_string(),
            );
        }
        // Every snapshot copies new content into the private store: refuse big media folders.
        let bytes: u64 = listing
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .filter_map(|p| {
                std::fs::symlink_metadata(top.top.join(String::from_utf8_lossy(p).as_ref())).ok()
            })
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum();
        if bytes > MAX_SHADOW_BYTES {
            return Err("This folder is too large to snapshot for undo (over 200 MB).".to_string());
        }
    }
    if skip.is_empty() {
        with_index(&["add", "-A"])?;
    } else {
        // `git add` aborts on an embedded repository without commits, so exclude them.
        let specs: Vec<String> = skip
            .iter()
            .map(|k| format!(":(exclude,literal){k}"))
            .collect();
        ok(cmd_with(top, false)
            .args(["add", "-A", "--", "."])
            .args(&specs)
            .env("GIT_INDEX_FILE", &index))?;
    }
    let tree = String::from_utf8_lossy(&with_index(&["write-tree"])?)
        .trim()
        .to_string();
    Ok((tree, head))
}

/// Commits the working state of one repository at `reference`; `None` when its
/// config defines content filters.
fn capture_repo(top: &Repo, reference: &str, skip: &[String]) -> Result<Option<String>, String> {
    if has_filters(top)? {
        return Ok(None);
    }
    let (tree, head) = write_tree(top, skip)?;
    let mut c = cmd(top);
    c.args(["commit-tree", &tree]);
    if let Some(h) = &head {
        c.args(["-p", h]);
    }
    c.args(["-m", COMMIT_MESSAGE])
        .env("GIT_AUTHOR_NAME", IDENTITY_NAME)
        .env("GIT_AUTHOR_EMAIL", IDENTITY_EMAIL)
        .env("GIT_COMMITTER_NAME", IDENTITY_NAME)
        .env("GIT_COMMITTER_EMAIL", IDENTITY_EMAIL);
    let sha = String::from_utf8_lossy(&ok(&mut c)?).trim().to_string();
    git(top, &["update-ref", reference, &sha])?;
    Ok(Some(sha))
}

const NESTED_MAX_DEPTH: usize = 4;
const NESTED_MAX_ENTRIES: usize = 20_000;
const NESTED_MAX_REPOS: usize = 32;

/// Git repositories below `cwd` (breadth first), as paths relative to `top`,
/// the primary repo's work tree. Nested repos are not searched themselves and
/// symlinks are not followed. shortcut: bounded walk (depth, entries, count),
/// so repos beyond those limits get no checkpoints of their own.
fn nested_repos(top: &Path, cwd: &Path) -> Vec<PathBuf> {
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let (top, start) = (canon(top), canon(cwd));
    let mut found = Vec::new();
    let mut visited = 0usize;
    let mut queue = VecDeque::from([(start, 0usize)]);
    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > NESTED_MAX_ENTRIES {
                return found;
            }
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || SHADOW_EXCLUDES.contains(&format!("\n{name}/\n")) {
                continue;
            }
            let path = entry.path();
            if std::fs::symlink_metadata(path.join(".git")).is_ok() {
                if let Ok(rel) = path.strip_prefix(&top) {
                    found.push(rel.to_path_buf());
                    if found.len() >= NESTED_MAX_REPOS {
                        return found;
                    }
                }
            } else if depth + 1 < NESTED_MAX_DEPTH {
                queue.push_back((path, depth + 1));
            }
        }
    }
    found
}

/// `nested_repos` as "/"-joined keys; names that are not UTF-8 are dropped.
fn nested_keys(top: &Path, cwd: &Path) -> Vec<String> {
    nested_repos(top, cwd)
        .iter()
        .filter_map(|p| {
            let parts: Option<Vec<&str>> = p.components().map(|c| c.as_os_str().to_str()).collect();
            Some(parts?.join("/"))
        })
        .collect()
}

/// Checkpoint token: a plain sha (primary repo only) or, when nested repos
/// exist, a JSON object `{"": primary, "app": sha, ...}` keyed by path.
fn parse_token(token: &str) -> Result<BTreeMap<String, String>, String> {
    let map = if token.starts_with('{') {
        serde_json::from_str::<BTreeMap<String, String>>(token)
            .map_err(|e| format!("invalid checkpoint token: {e}"))?
    } else {
        BTreeMap::from([(String::new(), token.to_string())])
    };
    for (key, sha) in &map {
        if !key.is_empty() {
            validate_rel(key)?;
        }
        validate_ish(sha)?;
    }
    if !map.contains_key("") {
        return Err("checkpoint token has no primary repository".to_string());
    }
    Ok(map)
}

/// The repo for `key` ("" = primary). A nested repo must still be a real
/// repository reached without symlinks, or git would fall back to the parent.
fn sub_repo(top: &Repo, key: &str) -> Result<Repo, String> {
    if key.is_empty() {
        return Ok(top.clone());
    }
    let mut dir = top.top.clone();
    for part in Path::new(key).components() {
        dir.push(part);
        if std::fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!("nested repository moved: {key}"));
        }
    }
    if std::fs::symlink_metadata(dir.join(".git")).is_err() {
        return Err(format!("nested repository is gone: {key}"));
    }
    Ok(Repo {
        top: dir,
        git_dir: None,
    })
}

/// Repos present in both tokens as `(key, from sha, to sha)`.
fn common<'a>(
    from: &'a BTreeMap<String, String>,
    to: &'a BTreeMap<String, String>,
) -> Vec<(&'a str, &'a str, &'a str)> {
    from.iter()
        .filter_map(|(k, f)| Some((k.as_str(), f.as_str(), to.get(k)?.as_str())))
        .collect()
}

/// The repo owning `path` (longest key prefix) and the path inside it.
fn route<'a>(
    repos: &[(&'a str, &'a str, &'a str)],
    path: &str,
) -> Option<((&'a str, &'a str, &'a str), String)> {
    let hit = repos
        .iter()
        .filter(|(k, ..)| k.is_empty() || path.starts_with(&format!("{k}/")))
        .max_by_key(|(k, ..)| k.len())?;
    let rel = path.get(hit.0.len() + usize::from(!hit.0.is_empty())..)?;
    Some((*hit, rel.to_string()))
}

/// Snapshots the working tree into a commit stored at `reference`
/// (must be under `refs/lomi/chat/`). `None` when not in a git work tree.
/// Git repositories nested in the folder are captured too (see `parse_token`).
pub fn capture(cwd: &Path, reference: &str) -> Result<Option<String>, String> {
    validate_ref(reference)?;
    let Some(top) = resolve(cwd, true)? else {
        return Ok(None);
    };
    let keys = nested_keys(&top.top, cwd);
    let Some(sha) = capture_repo(&top, reference, &keys)? else {
        return Ok(None);
    };
    let mut map = BTreeMap::from([(String::new(), sha.clone())]);
    for key in keys {
        // A nested repo failing its own guards only loses its own undo.
        if let Ok(sub) = sub_repo(&top, &key)
            && let Ok(Some(s)) = capture_repo(&sub, reference, &[])
        {
            map.insert(key, s);
        }
    }
    if map.len() == 1 {
        return Ok(Some(sha));
    }
    serde_json::to_string(&map)
        .map(Some)
        .map_err(|e| format!("failed to encode the checkpoint: {e}"))
}

/// Like `capture` but only returns the tree sha (no commit, no ref).
pub fn snapshot_tree(cwd: &Path) -> Result<Option<String>, String> {
    match resolve(cwd, true)? {
        Some(top) if !has_filters(&top)? => {
            Ok(Some(write_tree(&top, &nested_keys(&top.top, cwd))?.0))
        }
        _ => Ok(None),
    }
}

/// All changed paths between two trees (rename detection off), uncapped.
fn name_status(top: &Repo, from: &str, to: &str) -> Result<Vec<(String, ChangeStatus)>, String> {
    validate_ish(from)?;
    validate_ish(to)?;
    let out = git(
        top,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-status",
            "-z",
            from,
            to,
            "--",
        ],
    )?;
    let text = String::from_utf8_lossy(&out);
    let mut tokens = text.split('\0').filter(|t| !t.is_empty());
    let mut result = Vec::new();
    while let (Some(status), Some(path)) = (tokens.next(), tokens.next()) {
        let status = match status.chars().next() {
            Some('A') => ChangeStatus::Added,
            Some('D') => ChangeStatus::Deleted,
            _ => ChangeStatus::Modified,
        };
        result.push((path.to_string(), status));
    }
    Ok(result)
}

/// Per-file changes between two checkpoint tokens (or plain ishes), capped at
/// 2000 files. Nested repos appear with their path prefixed; their gitlink
/// entries in the primary repo are dropped.
pub fn changes(cwd: &Path, from: &str, to: &str) -> Result<Vec<FileChange>, String> {
    let (from, to) = (parse_token(from)?, parse_token(to)?);
    let top = require_repo(cwd)?;
    let gitlinks: HashSet<&str> = from.keys().chain(to.keys()).map(String::as_str).collect();
    let mut all = Vec::new();
    for (key, f, t) in common(&from, &to) {
        let mut list = changes_in(&sub_repo(&top, key)?, f, t)?;
        if key.is_empty() {
            list.retain(|c| !gitlinks.contains(c.path.as_str()));
        }
        for c in &mut list {
            if !key.is_empty() {
                c.path = format!("{key}/{}", c.path);
            }
        }
        all.extend(list);
    }
    all.truncate(MAX_FILES);
    Ok(all)
}

fn changes_in(top: &Repo, from: &str, to: &str) -> Result<Vec<FileChange>, String> {
    let statuses = name_status(top, from, to)?;
    let out = git(
        top,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--numstat",
            "-z",
            from,
            to,
            "--",
        ],
    )?;
    let mut stats: HashMap<String, (u32, u32, bool)> = HashMap::new();
    for rec in String::from_utf8_lossy(&out).split('\0') {
        let mut p = rec.splitn(3, '\t');
        if let (Some(a), Some(d), Some(path)) = (p.next(), p.next(), p.next()) {
            let stat = match (a.parse(), d.parse()) {
                (Ok(a), Ok(d)) => (a, d, false),
                _ => (0, 0, true), // "-\t-" marks binary
            };
            stats.insert(path.to_string(), stat);
        }
    }
    Ok(statuses
        .into_iter()
        .take(MAX_FILES)
        .map(|(path, status)| {
            let (additions, deletions, binary) = stats.get(&path).copied().unwrap_or_default();
            FileChange {
                path,
                status,
                additions,
                deletions,
                binary,
                agent: false,
                undone: false,
            }
        })
        .collect())
}

/// Unified diff of one path between two ishes, capped at 512 KiB.
pub fn file_diff(cwd: &Path, from: &str, to: &str, path: &str) -> Result<String, String> {
    let (from, to) = (parse_token(from)?, parse_token(to)?);
    validate_rel(path)?;
    let top = require_repo(cwd)?;
    let Some(((key, from, to), path)) = route(&common(&from, &to), path) else {
        return Ok(String::new());
    };
    validate_rel(&path)?;
    let top = sub_repo(&top, key)?;
    let path = path.as_str();
    let mut child = cmd(&top)
        .args([
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            from,
            to,
            "--",
            path,
        ])
        .spawn()
        .map_err(|e| format!("failed to run git: {e}"))?;
    // Read at most one byte past the cap, then stop git instead of buffering a huge diff.
    let mut out = Vec::new();
    let read = child
        .stdout
        .take()
        .map(|o| o.take(MAX_DIFF_BYTES as u64 + 1).read_to_end(&mut out));
    if out.len() > MAX_DIFF_BYTES {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if let Some(Err(e)) = read {
        return Err(format!("failed to read git output: {e}"));
    }
    if out.len() <= MAX_DIFF_BYTES {
        if !status.success() {
            let mut err = String::new();
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_string(&mut err);
            }
            let msg: String = err.trim().chars().take(MAX_ERR_CHARS).collect();
            return Err(format!("git failed ({status}): {msg}"));
        }
        return Ok(String::from_utf8_lossy(&out).into_owned());
    }
    let mut text = String::from_utf8_lossy(&out[..MAX_DIFF_BYTES]).into_owned();
    text.push_str("\n... [diff truncated at 512 KiB]\n");
    Ok(text)
}

/// Blob entry (`mode`, `sha`) of `path` in `ish`; `None` if absent or a directory.
fn tree_entry(top: &Repo, ish: &str, path: &str) -> Result<Option<(String, String)>, String> {
    let out = git(top, &["ls-tree", "-z", "--full-tree", ish, "--", path])?;
    let text = String::from_utf8_lossy(&out);
    let Some(rec) = text.split('\0').find(|r| !r.is_empty()) else {
        return Ok(None);
    };
    let Some((meta, _)) = rec.split_once('\t') else {
        return Ok(None);
    };
    let mut f = meta.split(' ');
    match (f.next(), f.next(), f.next()) {
        (Some(mode), Some("blob" | "commit"), Some(sha)) => {
            Ok(Some((mode.to_string(), sha.to_string())))
        }
        _ => Ok(None),
    }
}

enum Current {
    Absent,
    Blob(String),
    Unsafe,
}

fn current_state(top: &Repo, path: &str) -> Result<Current, String> {
    let mut dir = PathBuf::new();
    let parts: Vec<_> = Path::new(path).components().collect();
    for part in &parts[..parts.len() - 1] {
        dir.push(part);
        if let Ok(m) = std::fs::symlink_metadata(top.top.join(&dir))
            && m.file_type().is_symlink()
        {
            return Ok(Current::Unsafe);
        }
    }
    match std::fs::symlink_metadata(top.top.join(path)) {
        Err(_) => Ok(Current::Absent),
        Ok(m) if m.is_file() => Ok(Current::Blob(git_text(top, &["hash-object", "--", path])?)),
        Ok(_) => Ok(Current::Unsafe),
    }
}

/// Flags the files whose path appears in `edited` (paths from the turn's edit
/// activities, absolute or relative to `cwd`) as the agent's own changes.
pub fn mark_agent(cwd: &Path, files: &mut [FileChange], edited: &[String]) {
    let Ok(Some(top)) = resolve(cwd, false) else {
        return;
    };
    let top = top.top;
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let (top_c, cwd_c) = (canon(&top), canon(cwd));
    let rel: std::collections::HashSet<String> = edited
        .iter()
        .filter_map(|e| {
            let p = Path::new(e);
            let abs = if p.is_absolute() {
                p.to_path_buf()
            } else {
                cwd_c.join(p)
            };
            // The file may be gone (deleted by the turn), so only its parent resolves.
            let abs = match (abs.parent(), abs.file_name()) {
                (Some(dir), Some(name)) => canon(dir).join(name),
                _ => abs,
            };
            let r = abs.strip_prefix(&top_c).ok()?;
            Some(
                r.components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
            )
        })
        .collect();
    for f in files {
        f.agent = rel.contains(&f.path);
    }
}

/// Reverts the turn `before` -> `after`, path by path, but only where the
/// working tree still matches `after`; `only` limits it to those paths.
/// The index is never touched. Nested repos are reverted on their own, with
/// reported paths prefixed by the repo path.
pub fn undo(
    cwd: &Path,
    before: &str,
    after: &str,
    only: Option<&[String]>,
) -> Result<UndoReport, String> {
    let (before, after) = (parse_token(before)?, parse_token(after)?);
    let top = require_repo(cwd)?;
    let repos = common(&before, &after);
    let gitlinks: Vec<String> = before
        .keys()
        .chain(after.keys())
        .filter(|k| !k.is_empty())
        .cloned()
        .collect();
    let mut report = UndoReport::default();
    for &(key, b, a) in &repos {
        let sub_only: Option<Vec<String>> = only.map(|only| {
            only.iter()
                .filter_map(|p| route(&repos, p))
                .filter(|((k, ..), _)| *k == key)
                .map(|(_, rel)| rel)
                .collect()
        });
        if sub_only.as_ref().is_some_and(Vec::is_empty) {
            continue;
        }
        let prefix = |p: String| {
            if key.is_empty() {
                p
            } else {
                format!("{key}/{p}")
            }
        };
        let sub =
            sub_repo(&top, key).and_then(|r| undo_in(&r, b, a, sub_only.as_deref(), &gitlinks));
        match sub {
            Ok(r) => {
                report.restored.extend(r.restored.into_iter().map(prefix));
                report.skipped.extend(r.skipped.into_iter().map(prefix));
            }
            Err(e) if key.is_empty() => return Err(e),
            Err(_) => report.skipped.push(key.to_string()),
        }
    }
    report.restored.sort();
    Ok(report)
}

fn undo_in(
    top: &Repo,
    before: &str,
    after: &str,
    only: Option<&[String]>,
    gitlinks: &[String],
) -> Result<UndoReport, String> {
    let top = top.clone();
    // `hash-object` would run a configured clean filter; see `has_filters`.
    if has_filters(&top)? {
        return Err("the repository defines content filters; undo is unavailable".into());
    }
    let mut paths = name_status(&top, before, after)?;
    paths.retain(|(p, _)| !gitlinks.contains(p));
    if let Some(only) = only {
        paths.retain(|(p, _)| only.contains(p));
    }
    for (p, _) in &paths {
        validate_rel(p)?;
    }
    let mut report = UndoReport::default();
    let mut deletes = Vec::new();
    let mut writes = Vec::new();
    for (path, _) in paths {
        // A path that cannot be inspected (e.g. a non-UTF-8 name) is skipped, not fatal.
        let plan = (|| -> Result<bool, String> {
            let after_e = tree_entry(&top, after, &path)?;
            let before_e = tree_entry(&top, before, &path)?;
            let special = |e: &Option<(String, String)>| matches!(e, Some((m, _)) if m == "120000" || m == "160000");
            let equal = match (current_state(&top, &path)?, &after_e) {
                (Current::Absent, None) => true,
                (Current::Blob(cur), Some((_, sha))) => cur == *sha,
                _ => false,
            };
            // shortcut: symlink and submodule changes are never undone.
            if !equal || special(&before_e) || special(&after_e) {
                return Ok(false);
            }
            match before_e {
                Some(entry) => writes.push((path.clone(), entry)),
                None => deletes.push(path.clone()),
            }
            Ok(true)
        })();
        if !matches!(plan, Ok(true)) {
            report.skipped.push(path);
        }
    }
    // A case-only rename would delete the only copy on a case-insensitive filesystem.
    let planned: Vec<&String> = deletes
        .iter()
        .chain(writes.iter().map(|(p, _)| p))
        .collect();
    let clash = case_collisions(&planned);
    deletes.retain(|p| !clash.contains(p));
    writes.retain(|(p, _)| !clash.contains(p));
    report.skipped.extend(clash);
    // Deletions first so a file <-> directory swap can be reverted.
    for path in deletes {
        match remove_path(&top, &path) {
            Ok(()) => report.restored.push(path),
            Err(_) => report.skipped.push(path),
        }
    }
    for (path, (mode, sha)) in writes {
        match restore_path(&top, &path, &mode, &sha) {
            Ok(()) => report.restored.push(path),
            Err(_) => report.skipped.push(path),
        }
    }
    report.restored.sort();
    Ok(report)
}

/// Paths that share a lowercase form with another path, sorted.
fn case_collisions(paths: &[&String]) -> std::collections::BTreeSet<String> {
    let mut seen: HashMap<String, &String> = HashMap::new();
    let mut clash = std::collections::BTreeSet::new();
    for p in paths {
        if let Some(other) = seen.insert(p.to_lowercase(), p) {
            clash.insert(other.clone());
            clash.insert((*p).clone());
        }
    }
    clash
}

fn remove_path(top: &Repo, path: &str) -> Result<(), String> {
    let top = &top.top;
    let full = top.join(path);
    std::fs::remove_file(&full).map_err(|e| format!("failed to delete {path}: {e}"))?;
    let mut parent = full.parent();
    while let Some(dir) = parent.filter(|d| *d != top) {
        if std::fs::remove_dir(dir).is_err() {
            break;
        }
        parent = dir.parent();
    }
    Ok(())
}

fn restore_path(top: &Repo, path: &str, mode: &str, sha: &str) -> Result<(), String> {
    let full = top.top.join(path);
    let blob = git(top, &["cat-file", "blob", sha])?;
    let fail = |e: std::io::Error| format!("failed to restore {path}: {e}");
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(fail)?;
    }
    std::fs::write(&full, blob).map_err(fail)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&full).map_err(fail)?.permissions();
        let bits = if mode == "100755" {
            perms.mode() | 0o111
        } else {
            perms.mode() & !0o111
        };
        std::fs::set_permissions(&full, std::fs::Permissions::from_mode(bits)).map_err(fail)?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

/// Deletes every ref under `prefix` (e.g. `refs/lomi/chat/<thread>/`) in the
/// primary repo and in the nested repos currently found below `cwd`.
pub fn remove_refs(cwd: &Path, prefix: &str) -> Result<(), String> {
    let prefix = prefix.trim_end_matches('/');
    validate_ref(prefix)?;
    let Some(top) = resolve(cwd, false)? else {
        return Ok(());
    };
    for key in nested_keys(&top.top, cwd) {
        if let Ok(sub) = sub_repo(&top, &key) {
            // Best effort: one broken nested repo must not keep the rest.
            let _ = remove_prefix_refs(&sub, prefix);
        }
    }
    remove_prefix_refs(&top, prefix)?;
    // A shadow only holds checkpoints: drop it when none is left, else free the
    // objects only the removed checkpoints used.
    if let Some(dir) = &top.git_dir {
        let left = git_text(&top, &["for-each-ref", "--count=1", REF_PREFIX])?;
        if left.is_empty() {
            std::fs::remove_dir_all(dir)
                .map_err(|e| format!("failed to remove the checkpoint store: {e}"))?;
        } else {
            git(&top, &["gc", "--prune=now", "--quiet"])?;
        }
    }
    Ok(())
}

fn remove_prefix_refs(top: &Repo, prefix: &str) -> Result<(), String> {
    let listing = git_text(
        top,
        &["for-each-ref", "--format=%(refname)", &format!("{prefix}/")],
    )?;
    for r in listing.lines().filter(|l| !l.is_empty()) {
        git(top, &["update-ref", "-d", r])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn have_git() -> bool {
        Command::new("git").arg("--version").output().is_ok()
    }

    fn g(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn repo(commit: bool) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        g(p, &["init", "-q"]);
        g(p, &["config", "user.name", "Tester"]);
        g(p, &["config", "user.email", "t@example.com"]);
        g(p, &["config", "commit.gpgsign", "false"]);
        if commit {
            fs::write(p.join("a.txt"), "one\ntwo\n").unwrap();
            fs::write(p.join("b.txt"), "b\n").unwrap();
            fs::write(p.join(".gitignore"), "ignored.log\n").unwrap();
            g(p, &["add", "-A"]);
            g(p, &["commit", "-q", "-m", "init"]);
        }
        dir
    }

    const R1: &str = "refs/lomi/chat/t1/1-before";
    const R2: &str = "refs/lomi/chat/t1/1-after";

    #[test]
    fn capture_leaves_repo_untouched() {
        if !have_git() {
            return;
        }
        let dir = repo(true);
        let p = dir.path();
        fs::write(p.join("a.txt"), "one\nTWO\n").unwrap();
        fs::write(p.join("b.txt"), "b2\n").unwrap();
        g(p, &["add", "b.txt"]);
        fs::write(p.join("b.txt"), "b3\n").unwrap();
        fs::write(p.join("u.txt"), "untracked\n").unwrap();
        fs::write(p.join("ignored.log"), "x\n").unwrap();
        let snap = |p: &Path| {
            (
                g(p, &["status", "--porcelain"]),
                g(p, &["diff", "--cached"]),
                g(p, &["rev-parse", "HEAD"]),
                g(p, &["branch", "--list"]),
                g(p, &["stash", "list"]),
            )
        };
        let before = snap(p);
        let sha = capture(p, R1).unwrap().unwrap();
        assert_eq!(before, snap(p));
        assert_eq!(g(p, &["rev-parse", R1]).trim(), sha);
        let files = g(p, &["ls-tree", "-r", "--name-only", &sha]);
        assert!(files.contains("u.txt") && !files.contains("ignored.log"));
        assert_eq!(g(p, &["show", &format!("{sha}:b.txt")]), "b3\n");
        assert_eq!(
            g(p, &["rev-parse", &format!("{sha}^")]).trim(),
            before.2.trim()
        );
        assert_eq!(
            g(p, &["log", "-1", "--format=%an <%ae>", &sha]).trim(),
            "Lomi <lomi@localhost>"
        );
        assert!(!g(p, &["config", "--local", "--list"]).contains("Lomi"));
        let tree = snapshot_tree(p).unwrap().unwrap();
        assert_eq!(
            tree,
            g(p, &["rev-parse", &format!("{sha}^{{tree}}")]).trim()
        );
        let leftovers = fs::read_dir(p.join(".git"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn unborn_repo_and_non_git() {
        if !have_git() {
            return;
        }
        let dir = repo(false);
        let p = dir.path();
        fs::write(p.join("f.txt"), "hi\n").unwrap();
        let sha = capture(p, R1).unwrap().unwrap();
        assert_eq!(g(p, &["rev-list", "--parents", "-n1", &sha]).trim(), sha);
        assert!(g(p, &["ls-tree", "-r", "--name-only", &sha]).contains("f.txt"));
        assert!(g(p, &["status", "--porcelain"]).contains("?? f.txt"));
        assert!(snapshot_tree(p).unwrap().is_some());

        let plain = tempfile::tempdir().unwrap();
        assert_eq!(capture(plain.path(), R1).unwrap(), None);
        assert_eq!(snapshot_tree(plain.path()).unwrap(), None);
        remove_refs(plain.path(), "refs/lomi/chat/t1/").unwrap();
    }

    #[test]
    fn rejects_bad_refs_and_paths() {
        if !have_git() {
            return;
        }
        let dir = repo(true);
        let p = dir.path();
        for bad in [
            "refs/heads/main",
            "refs/lomi/chat/",
            "refs/lomi/chat/a..b",
            "refs/lomi/chat/a b",
            "refs/lomi/chat/a\nb",
            "refs/lomi/chat/a~1",
            "refs/lomi/chat/a.lock",
        ] {
            assert!(capture(p, bad).is_err(), "{bad:?}");
        }
        let sha = capture(p, R1).unwrap().unwrap();
        for bad in ["../x", "/etc/passwd", "a/../../x", "", ".git/config"] {
            assert!(file_diff(p, &sha, &sha, bad).is_err(), "{bad:?}");
        }
        assert!(changes(p, "--output=x", &sha).is_err());
        assert!(remove_refs(p, "refs/heads/").is_err());
    }

    #[test]
    fn changes_and_file_diff() {
        if !have_git() {
            return;
        }
        let dir = repo(true);
        let p = dir.path();
        let before = capture(p, R1).unwrap().unwrap();
        fs::write(p.join("a.txt"), "one\nthree\nfour\n").unwrap();
        fs::remove_file(p.join("b.txt")).unwrap();
        fs::write(p.join("new.txt"), "n1\nn2\n").unwrap();
        fs::write(p.join("bin.dat"), [0u8, 1, 2, 0]).unwrap();
        let after = capture(p, R2).unwrap().unwrap();
        let list = changes(p, &before, &after).unwrap();
        let get = |n: &str| list.iter().find(|c| c.path == n).unwrap().clone();
        let a = get("a.txt");
        assert_eq!(
            (a.status, a.additions, a.deletions),
            (ChangeStatus::Modified, 2, 1)
        );
        let b = get("b.txt");
        assert_eq!(
            (b.status, b.additions, b.deletions),
            (ChangeStatus::Deleted, 0, 1)
        );
        let n = get("new.txt");
        assert_eq!(
            (n.status, n.additions, n.deletions),
            (ChangeStatus::Added, 2, 0)
        );
        assert!(get("bin.dat").binary);
        assert_eq!(list.len(), 4);
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"status\":\"added\"") && json.contains("\"additions\":2"));

        let d = file_diff(p, &before, &after, "a.txt").unwrap();
        assert!(d.contains("-two") && d.contains("+three") && d.contains("+four"));
        assert_eq!(file_diff(p, &before, &after, "nope.txt").unwrap(), "");

        fs::write(p.join("big.txt"), "x\n".repeat(600 * 1024)).unwrap();
        let big = capture(p, "refs/lomi/chat/t1/2-after").unwrap().unwrap();
        let d = file_diff(p, &after, &big, "big.txt").unwrap();
        assert!(d.ends_with("[diff truncated at 512 KiB]\n") && d.len() < MAX_DIFF_BYTES + 100);
    }

    #[test]
    fn undo_restores_only_agent_changes() {
        if !have_git() {
            return;
        }
        let dir = repo(true);
        let p = dir.path();
        fs::write(p.join("user.txt"), "u\n").unwrap();
        fs::write(p.join("gone.txt"), "gone\n").unwrap();
        fs::write(p.join("run.sh"), "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(p.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let before = capture(p, R1).unwrap().unwrap();
        fs::write(p.join("a.txt"), "agent\n").unwrap();
        fs::write(p.join("user.txt"), "agent\n").unwrap();
        fs::remove_file(p.join("gone.txt")).unwrap();
        fs::remove_file(p.join("run.sh")).unwrap();
        fs::create_dir_all(p.join("d/e")).unwrap();
        fs::write(p.join("d/e/created.txt"), "c\n").unwrap();
        let after = capture(p, R2).unwrap().unwrap();
        fs::write(p.join("user.txt"), "agent\nuser edit\n").unwrap();
        let index_before = g(p, &["diff", "--cached"]);

        let report = undo(p, &before, &after, None).unwrap();
        assert_eq!(report.skipped, vec!["user.txt"]);
        assert_eq!(
            report.restored,
            vec!["a.txt", "d/e/created.txt", "gone.txt", "run.sh"]
        );
        assert_eq!(fs::read_to_string(p.join("a.txt")).unwrap(), "one\ntwo\n");
        assert_eq!(fs::read_to_string(p.join("gone.txt")).unwrap(), "gone\n");
        assert_eq!(
            fs::read_to_string(p.join("user.txt")).unwrap(),
            "agent\nuser edit\n"
        );
        assert!(!p.join("d").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(p.join("run.sh")).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111);
        }
        assert_eq!(index_before, g(p, &["diff", "--cached"]));
    }

    #[test]
    fn content_filters_disable_checkpoints() {
        if !have_git() {
            return;
        }
        let dir = repo(true);
        let p = dir.path();
        let before = capture(p, R1).unwrap().unwrap();
        fs::write(p.join("a.txt"), "agent\n").unwrap();
        let after = capture(p, R2).unwrap().unwrap();
        // An agent-planted filter must never be executed by Lomi's git calls.
        let marker = p.join("marker");
        fs::write(p.join(".gitattributes"), "* filter=evil\n").unwrap();
        g(
            p,
            &[
                "config",
                "filter.evil.clean",
                &format!("touch {}; cat", marker.display()),
            ],
        );
        assert_eq!(capture(p, "refs/lomi/chat/t1/3-before").unwrap(), None);
        assert_eq!(snapshot_tree(p).unwrap(), None);
        assert!(undo(p, &before, &after, None).is_err());
        assert!(!marker.exists());
        assert_eq!(fs::read_to_string(p.join("a.txt")).unwrap(), "agent\n");
    }

    #[test]
    fn case_only_renames_collide() {
        let (a, b, c) = (
            "Foo.txt".to_string(),
            "foo.txt".to_string(),
            "x".to_string(),
        );
        let clash = case_collisions(&[&a, &b, &c]);
        assert_eq!(
            clash.into_iter().collect::<Vec<_>>(),
            vec!["Foo.txt", "foo.txt"]
        );
        assert!(case_collisions(&[&a, &c]).is_empty());
    }

    #[test]
    fn undo_skips_paths_it_cannot_restore() {
        if !have_git() {
            return;
        }
        let dir = repo(true);
        let p = dir.path();
        let before = capture(p, R1).unwrap().unwrap();
        fs::write(p.join("new.txt"), "n\n").unwrap();
        fs::write(p.join("a.txt"), "agent\n").unwrap();
        let after = capture(p, R2).unwrap().unwrap();
        // A read-only root makes the delete of new.txt fail; a.txt must still be restored.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(p, fs::Permissions::from_mode(0o555)).unwrap();
            let report = undo(p, &before, &after, None);
            fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
            let report = report.unwrap();
            assert_eq!(report.skipped, vec!["new.txt"]);
            assert_eq!(report.restored, vec!["a.txt"]);
        }
    }

    #[test]
    fn remove_refs_by_prefix() {
        if !have_git() {
            return;
        }
        let dir = repo(true);
        let p = dir.path();
        for r in [
            R1,
            R2,
            "refs/lomi/chat/t10/1-before",
            "refs/lomi/chat/t2/1-before",
        ] {
            capture(p, r).unwrap().unwrap();
        }
        remove_refs(p, "refs/lomi/chat/t1/").unwrap();
        let left = g(p, &["for-each-ref", "--format=%(refname)", "refs/lomi/"]);
        assert_eq!(
            left.lines().collect::<Vec<_>>(),
            vec!["refs/lomi/chat/t10/1-before", "refs/lomi/chat/t2/1-before"]
        );
    }

    fn plain(limit: usize) -> (tempfile::TempDir, tempfile::TempDir) {
        let (dir, root) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        TEST_ROOT.with(|r| *r.borrow_mut() = Some(root.path().to_path_buf()));
        TEST_LIMIT.with(|l| l.set(limit));
        (dir, root)
    }

    #[test]
    fn shadow_repo_captures_and_undoes_in_plain_folder() {
        if !have_git() {
            return;
        }
        let (dir, root) = plain(MAX_SHADOW_FILES);
        let p = dir.path();
        fs::write(p.join("a.txt"), "one\n").unwrap();
        fs::write(p.join("b.txt"), "b\n").unwrap();
        fs::create_dir_all(p.join("node_modules")).unwrap();
        fs::write(p.join("node_modules/x.js"), "x\n").unwrap();
        let before = capture(p, R1).unwrap().unwrap();
        fs::write(p.join("a.txt"), "two\n").unwrap();
        fs::remove_file(p.join("b.txt")).unwrap();
        fs::write(p.join("c.txt"), "c\n").unwrap();
        fs::write(p.join("node_modules/y.js"), "y\n").unwrap();
        let after = capture(p, R2).unwrap().unwrap();
        let mut list: Vec<_> = changes(p, &before, &after)
            .unwrap()
            .into_iter()
            .map(|c| (c.path, c.status))
            .collect();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            list,
            vec![
                ("a.txt".to_string(), ChangeStatus::Modified),
                ("b.txt".to_string(), ChangeStatus::Deleted),
                ("c.txt".to_string(), ChangeStatus::Added),
            ]
        );
        let report = undo(p, &before, &after, None).unwrap();
        assert_eq!(report.restored, vec!["a.txt", "b.txt", "c.txt"]);
        assert!(report.skipped.is_empty());
        assert_eq!(fs::read_to_string(p.join("a.txt")).unwrap(), "one\n");
        assert_eq!(fs::read_to_string(p.join("b.txt")).unwrap(), "b\n");
        assert!(!p.join("c.txt").exists());
        assert!(!p.join(".git").exists());
        let shadow = fs::read_dir(root.path().join("checkpoints"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let files = g(&shadow, &["ls-tree", "-r", "--name-only", &after]);
        assert!(files.contains("c.txt") && !files.contains("node_modules"));
        remove_refs(p, "refs/lomi/chat/t1/").unwrap();
        // No checkpoint left: the whole shadow is gone.
        assert!(!shadow.exists());
    }

    #[test]
    fn shadows_keep_other_threads_and_drop_vanished_folders() {
        if !have_git() {
            return;
        }
        let (dir, root) = plain(MAX_SHADOW_FILES);
        let p = dir.path();
        fs::write(p.join("a.txt"), "a\n").unwrap();
        capture(p, "refs/lomi/chat/t1/m/before").unwrap().unwrap();
        capture(p, "refs/lomi/chat/t2/m/before").unwrap().unwrap();
        let shadows = root.path().join("checkpoints");
        remove_refs(p, "refs/lomi/chat/t1/").unwrap();
        let shadow = fs::read_dir(&shadows)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(
            !g(&shadow, &["for-each-ref", "refs/lomi/chat/t2/"])
                .trim()
                .is_empty()
        );
        // The folder still exists: kept; once it is gone, startup pruning removes the shadow.
        prune_shadows(root.path());
        assert!(shadow.exists());
        drop(dir);
        prune_shadows(root.path());
        assert!(!shadow.exists());
    }

    #[test]
    fn shadow_repo_size_guard() {
        if !have_git() {
            return;
        }
        let (dir, _root) = plain(2);
        for n in ["a", "b", "c"] {
            fs::write(dir.path().join(n), n).unwrap();
        }
        let err = capture(dir.path(), R1).unwrap_err();
        assert!(err.contains("too large"), "{err}");
        assert!(snapshot_tree(dir.path()).is_err());
    }

    #[test]
    fn real_repos_do_not_use_the_shadow() {
        if !have_git() {
            return;
        }
        let (_plain, root) = plain(MAX_SHADOW_FILES);
        let dir = repo(true);
        assert!(capture(dir.path(), R1).unwrap().is_some());
        assert!(!root.path().join("checkpoints").exists());
    }

    fn init_at(p: &Path, file: Option<(&str, &str)>) {
        fs::create_dir_all(p).unwrap();
        g(p, &["init", "-q"]);
        g(p, &["config", "user.name", "Tester"]);
        g(p, &["config", "user.email", "t@example.com"]);
        g(p, &["config", "commit.gpgsign", "false"]);
        if let Some((n, c)) = file {
            fs::write(p.join(n), c).unwrap();
            g(p, &["add", "-A"]);
            g(p, &["commit", "-q", "-m", "init"]);
        }
    }

    /// Edits root, app/ (committed file) and server/x/ (fresh repo), then checks
    /// prefixed changes, subset undo, full undo and ref cleanup.
    fn nested_round_trip(p: &Path) {
        init_at(&p.join("app"), Some(("lib.txt", "old\n")));
        init_at(&p.join("server/x"), None);
        fs::write(p.join("server/x/new.txt"), "fresh\n").unwrap();
        fs::write(p.join("root.txt"), "root\n").unwrap();
        let before = capture(p, R1).unwrap().unwrap();
        assert!(before.starts_with('{'), "{before}");
        fs::write(p.join("root.txt"), "root2\n").unwrap();
        fs::write(p.join("app/lib.txt"), "new\n").unwrap();
        fs::write(p.join("server/x/new.txt"), "fresh2\n").unwrap();
        fs::write(p.join("server/x/extra.txt"), "e\n").unwrap();
        let after = capture(p, R2).unwrap().unwrap();
        let mut paths: Vec<_> = changes(p, &before, &after)
            .unwrap()
            .into_iter()
            .map(|c| c.path)
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            [
                "app/lib.txt",
                "root.txt",
                "server/x/extra.txt",
                "server/x/new.txt"
            ]
        );
        assert!(
            file_diff(p, &before, &after, "app/lib.txt")
                .unwrap()
                .contains("+new")
        );
        let mut files = changes(p, &before, &after).unwrap();
        mark_agent(
            p,
            &mut files,
            &[p.join("app/lib.txt").to_string_lossy().into_owned()],
        );
        assert!(files.iter().all(|f| f.agent == (f.path == "app/lib.txt")));

        let only = ["app/lib.txt".to_string(), "root.txt".to_string()];
        let r = undo(p, &before, &after, Some(&only)).unwrap();
        assert_eq!(r.restored, ["app/lib.txt", "root.txt"]);
        assert_eq!(fs::read_to_string(p.join("app/lib.txt")).unwrap(), "old\n");
        assert_eq!(
            fs::read_to_string(p.join("server/x/new.txt")).unwrap(),
            "fresh2\n"
        );
        let r = undo(p, &before, &after, None).unwrap();
        assert_eq!(r.restored, ["server/x/extra.txt", "server/x/new.txt"]);
        assert_eq!(
            fs::read_to_string(p.join("server/x/new.txt")).unwrap(),
            "fresh\n"
        );
        assert!(!p.join("server/x/extra.txt").exists());

        remove_refs(p, "refs/lomi/chat/t1/").unwrap();
        for sub in ["app", "server/x"] {
            assert!(
                g(&p.join(sub), &["for-each-ref", "refs/lomi/"])
                    .trim()
                    .is_empty()
            );
        }
    }

    #[test]
    fn nested_repos_in_plain_folder() {
        if !have_git() {
            return;
        }
        let (dir, root) = plain(MAX_SHADOW_FILES);
        nested_round_trip(dir.path());
        assert!(
            !root
                .path()
                .join("checkpoints")
                .read_dir()
                .unwrap()
                .any(|_| true)
        );
    }

    #[test]
    fn nested_repo_inside_git_work_tree() {
        if !have_git() {
            return;
        }
        let dir = repo(true);
        let p = dir.path();
        init_at(&p.join("emb"), Some(("e.txt", "e\n")));
        g(p, &["add", "-A"]);
        g(p, &["commit", "-q", "-m", "emb"]);
        let before = capture(p, R1).unwrap().unwrap();
        fs::write(p.join("emb/e.txt"), "e2\n").unwrap();
        g(&p.join("emb"), &["commit", "-qam", "bump"]);
        fs::write(p.join("a.txt"), "x\n").unwrap();
        let after = capture(p, R2).unwrap().unwrap();
        let mut paths: Vec<_> = changes(p, &before, &after)
            .unwrap()
            .into_iter()
            .map(|c| c.path)
            .collect();
        paths.sort();
        assert_eq!(paths, ["a.txt", "emb/e.txt"]);
        undo(p, &before, &after, None).unwrap();
        assert_eq!(fs::read_to_string(p.join("emb/e.txt")).unwrap(), "e\n");
        assert_eq!(fs::read_to_string(p.join("a.txt")).unwrap(), "one\ntwo\n");
    }

    #[test]
    fn token_parsing() {
        let sha = "a".repeat(40);
        assert_eq!(parse_token(&sha).unwrap()[""], sha);
        let ok = format!("{{\"\":\"{sha}\",\"app\":\"{sha}\"}}");
        assert_eq!(parse_token(&ok).unwrap().len(), 2);
        for bad in [
            format!("{{\"\":\"{sha}\",\"../x\":\"{sha}\"}}"),
            format!("{{\"\":\"{sha}\",\"/etc\":\"{sha}\"}}"),
            format!("{{\"app\":\"{sha}\"}}"),
            "{\"\":\"--x\"}".to_string(),
            "{".to_string(),
        ] {
            assert!(parse_token(&bad).is_err(), "{bad}");
        }
    }
}
