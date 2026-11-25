//! Git-backed per-turn checkpoints of a working tree.
//!
//! A checkpoint is a commit built from a private, temporary index (so the
//! user's index, HEAD, branches and stash are never touched) and stored under
//! a hidden `refs/lomi/chat/...` ref. All git calls are blocking, argv-based
//! (no shell) and must be run off the async runtime by the caller.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};

const REF_PREFIX: &str = "refs/lomi/chat/";
const MAX_FILES: usize = 2000;
const MAX_DIFF_BYTES: usize = 512 * 1024;
const MAX_ERR_CHARS: usize = 500;
const COMMIT_MESSAGE: &str = "Lomi chat checkpoint";
const IDENTITY_NAME: &str = "Lomi";
const IDENTITY_EMAIL: &str = "lomi@localhost";

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
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoReport {
    pub restored: Vec<String>,
    pub skipped: Vec<String>,
}

fn command(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.args([
        "--no-pager",
        "--no-optional-locks",
        "--literal-pathspecs",
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

fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    ok(command(dir).args(args))
}

fn git_text(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = git(dir, args)?;
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

fn require_toplevel(cwd: &Path) -> Result<PathBuf, String> {
    toplevel(cwd)?.ok_or_else(|| "not inside a git work tree".to_string())
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
fn has_filters(top: &Path) -> Result<bool, String> {
    let out = exec(command(top).args([
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
/// ignored) using a private index. Returns `(tree, head)`.
fn write_tree(top: &Path) -> Result<(String, Option<String>), String> {
    let git_dir = git_text(top, &["rev-parse", "--absolute-git-dir"])?;
    let tmp = tempfile::tempdir_in(&git_dir)
        .or_else(|_| tempfile::tempdir())
        .map_err(|e| format!("failed to create temporary index: {e}"))?;
    // A not-yet-existing path: git treats a 0-byte index file as corrupt.
    let index = tmp.path().join("index");
    let with_index = |args: &[&str]| ok(command(top).args(args).env("GIT_INDEX_FILE", &index));

    let head = exec(command(top).args(["rev-parse", "--verify", "-q", "HEAD^{commit}"]))?;
    let head = head
        .status
        .success()
        .then(|| String::from_utf8_lossy(&head.stdout).trim().to_string());
    if head.is_some() {
        with_index(&["read-tree", "HEAD"])?;
    }
    with_index(&["add", "-A"])?;
    let tree = String::from_utf8_lossy(&with_index(&["write-tree"])?)
        .trim()
        .to_string();
    Ok((tree, head))
}

/// Snapshots the working tree into a commit stored at `reference`
/// (must be under `refs/lomi/chat/`). `None` when not in a git work tree.
pub fn capture(cwd: &Path, reference: &str) -> Result<Option<String>, String> {
    validate_ref(reference)?;
    let Some(top) = toplevel(cwd)? else {
        return Ok(None);
    };
    if has_filters(&top)? {
        return Ok(None);
    }
    let (tree, head) = write_tree(&top)?;
    let mut c = command(&top);
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
    git(&top, &["update-ref", reference, &sha])?;
    Ok(Some(sha))
}

/// Like `capture` but only returns the tree sha (no commit, no ref).
pub fn snapshot_tree(cwd: &Path) -> Result<Option<String>, String> {
    match toplevel(cwd)? {
        Some(top) if !has_filters(&top)? => Ok(Some(write_tree(&top)?.0)),
        _ => Ok(None),
    }
}

/// All changed paths between two trees (rename detection off), uncapped.
fn name_status(top: &Path, from: &str, to: &str) -> Result<Vec<(String, ChangeStatus)>, String> {
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

/// Per-file changes between two commit/tree ishes, capped at 2000 files.
pub fn changes(cwd: &Path, from: &str, to: &str) -> Result<Vec<FileChange>, String> {
    let top = require_toplevel(cwd)?;
    let statuses = name_status(&top, from, to)?;
    let out = git(
        &top,
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
            }
        })
        .collect())
}

/// Unified diff of one path between two ishes, capped at 512 KiB.
pub fn file_diff(cwd: &Path, from: &str, to: &str, path: &str) -> Result<String, String> {
    validate_ish(from)?;
    validate_ish(to)?;
    validate_rel(path)?;
    let top = require_toplevel(cwd)?;
    let mut child = command(&top)
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
fn tree_entry(top: &Path, ish: &str, path: &str) -> Result<Option<(String, String)>, String> {
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

fn current_state(top: &Path, path: &str) -> Result<Current, String> {
    let mut dir = PathBuf::new();
    let parts: Vec<_> = Path::new(path).components().collect();
    for part in &parts[..parts.len() - 1] {
        dir.push(part);
        if let Ok(m) = std::fs::symlink_metadata(top.join(&dir))
            && m.file_type().is_symlink()
        {
            return Ok(Current::Unsafe);
        }
    }
    match std::fs::symlink_metadata(top.join(path)) {
        Err(_) => Ok(Current::Absent),
        Ok(m) if m.is_file() => Ok(Current::Blob(git_text(top, &["hash-object", "--", path])?)),
        Ok(_) => Ok(Current::Unsafe),
    }
}

/// Reverts the turn `before` -> `after`, path by path, but only where the
/// working tree still matches `after`. The index is never touched.
pub fn undo(cwd: &Path, before: &str, after: &str) -> Result<UndoReport, String> {
    let top = require_toplevel(cwd)?;
    // `hash-object` would run a configured clean filter; see `has_filters`.
    if has_filters(&top)? {
        return Err("the repository defines content filters; undo is unavailable".into());
    }
    let paths = name_status(&top, before, after)?;
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

fn remove_path(top: &Path, path: &str) -> Result<(), String> {
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

fn restore_path(top: &Path, path: &str, mode: &str, sha: &str) -> Result<(), String> {
    let full = top.join(path);
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

/// Deletes every ref under `prefix` (e.g. `refs/lomi/chat/<thread>/`).
pub fn remove_refs(cwd: &Path, prefix: &str) -> Result<(), String> {
    let prefix = prefix.trim_end_matches('/');
    validate_ref(prefix)?;
    let Some(top) = toplevel(cwd)? else {
        return Ok(());
    };
    let listing = git_text(
        &top,
        &["for-each-ref", "--format=%(refname)", &format!("{prefix}/")],
    )?;
    for r in listing.lines().filter(|l| !l.is_empty()) {
        git(&top, &["update-ref", "-d", r])?;
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

        let report = undo(p, &before, &after).unwrap();
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
        assert!(undo(p, &before, &after).is_err());
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
            let report = undo(p, &before, &after);
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
}
