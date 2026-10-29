#![cfg(unix)]
use lomi_admission_spike::{Kind, Reply, Request, send};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const BIN: &str = env!("CARGO_BIN_EXE_lomi-admission-spike");
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn host(dir: &Path) -> Process {
    let mut p = Process(
        Command::new(BIN)
            .arg("host")
            .arg(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "host startup timeout"
        );
        assert!(p.0.try_wait().unwrap().is_none(), "host exited");
        if UnixStream::connect(dir.join("host.sock")).is_ok() {
            return p;
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn request(dir: &Path, req: Request) -> Reply {
    let out = Command::new(BIN)
        .arg("request")
        .arg(dir)
        .arg(serde_json::to_string(&req).unwrap())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "request client failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
fn probe(dir: &Path, path: &Path, kind: Kind) -> bool {
    request(
        dir,
        Request::Acquire {
            path: path.to_owned(),
            kind,
        },
    )
    .ok
}
struct Writer {
    process: Process,
    out: BufReader<std::process::ChildStdout>,
    token: String,
}
impl Writer {
    fn new(dir: &Path, path: &Path) -> Self {
        let mut process = Process(
            Command::new(BIN)
                .arg("writer")
                .arg(dir)
                .arg(path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut out = BufReader::new(process.0.stdout.take().unwrap());
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        let reply: Reply = serde_json::from_str(&line).unwrap();
        assert!(reply.ok);
        Self {
            process,
            out,
            token: reply.token.unwrap(),
        }
    }
    fn command(&mut self, cmd: &str) -> String {
        writeln!(self.process.0.stdin.as_mut().unwrap(), "{cmd}").unwrap();
        let mut line = String::new();
        self.out.read_line(&mut line).unwrap();
        line
    }
    fn terminate_confirmed(&mut self) {
        writeln!(self.process.0.stdin.as_mut().unwrap(), "exit").unwrap();
        assert!(self.process.0.wait().unwrap().success());
    }
}
fn runtime(base: &Path) -> PathBuf {
    let path = base.join("run");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
#[test]
fn disconnect_live_writer_crash_restart_and_explicit_reconciliation() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let dir = runtime(&base);
    let root = base.join("project");
    fs::create_dir(&root).unwrap();
    let h = host(&dir);
    let mut writer = Writer::new(&dir, &root);
    assert!(!probe(&dir, &root.join("rename-target"), Kind::File));
    assert!(!probe(&dir, &root, Kind::Git));
    assert!(probe(&dir, &base.join("outside-file"), Kind::File));
    assert!(
        !request(
            &dir,
            Request::Finish {
                token: writer.token.clone()
            }
        )
        .ok,
        "other connection cannot release"
    );
    assert_eq!(writer.command("disconnect").trim(), "disconnected");
    assert!(writer.process.0.try_wait().unwrap().is_none());
    assert!(!probe(&dir, &root, Kind::File));
    drop(h);
    let _h = host(&dir);
    assert!(writer.process.0.try_wait().unwrap().is_none());
    assert!(!probe(&dir, &root, Kind::Git));
    assert!(
        !request(
            &dir,
            Request::Reconcile {
                token: writer.token.clone(),
                confirmed_terminated: false
            }
        )
        .ok
    );
    writer.terminate_confirmed();
    assert!(
        request(
            &dir,
            Request::Reconcile {
                token: writer.token.clone(),
                confirmed_terminated: true
            }
        )
        .ok
    );
    assert!(probe(&dir, &root, Kind::File));
}
#[test]
fn directory_aliases_git_common_and_worktree_aliases_collide() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let dir = runtime(&base);
    let _h = host(&dir);
    let root = base.join("main");
    fs::create_dir_all(root.join("nested")).unwrap();
    fs::create_dir_all(root.join(".git/worktrees/linked")).unwrap();
    let linked = base.join("linked");
    fs::create_dir(&linked).unwrap();
    fs::write(
        linked.join(".git"),
        format!("gitdir: {}\n", root.join(".git/worktrees/linked").display()),
    )
    .unwrap();
    fs::write(root.join(".git/worktrees/linked/commondir"), "../..\n").unwrap();
    let alias = base.join("alias");
    symlink(&root, &alias).unwrap();
    let linked_alias = base.join("linked-alias");
    symlink(&linked, &linked_alias).unwrap();
    let mut writer = Writer::new(&dir, &root);
    for path in [
        &base,
        &root.join("nested"),
        &alias,
        &linked,
        &linked_alias,
        &root.join(".git/refs/new"),
    ] {
        assert!(
            !probe(&dir, path, Kind::Git),
            "must conflict: {}",
            path.display()
        );
    }
    let reply: Reply = serde_json::from_str(&writer.command("finish")).unwrap();
    assert!(reply.ok);
    writer.terminate_confirmed();
    assert!(probe(&dir, &linked, Kind::Git));
}
#[test]
fn expiry_fences_live_writer_and_owner_lock_and_bounds_hold() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let dir = runtime(&base);
    let _h = host(&dir);
    let root = base.join("project");
    fs::create_dir(&root).unwrap();
    let second = Command::new(BIN).arg("host").arg(&dir).output().unwrap();
    assert!(!second.status.success());
    let mut writer = Writer::new(&dir, &root);
    thread::sleep(Duration::from_millis(2300));
    assert!(writer.process.0.try_wait().unwrap().is_none());
    assert!(!probe(&dir, &root, Kind::File));
    writer.terminate_confirmed();
    assert!(
        request(
            &dir,
            Request::Reconcile {
                token: writer.token.clone(),
                confirmed_terminated: true
            }
        )
        .ok
    );
    let mut stream = UnixStream::connect(dir.join("host.sock")).unwrap();
    stream.write_all(&u32::MAX.to_be_bytes()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut b = [0];
    use std::io::Read;
    assert_eq!(stream.read(&mut b).unwrap(), 0);
    let mut stream = UnixStream::connect(dir.join("host.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(&[0]).unwrap();
    assert_eq!(stream.read(&mut b).unwrap(), 0);
    assert!(probe(&dir, &root, Kind::File));
}
#[test]
fn renew_stays_owned_and_namespace_drift_fences() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let dir = runtime(&base);
    let _h = host(&dir);
    let root = base.join("project");
    fs::create_dir(&root).unwrap();
    let mut stream = UnixStream::connect(dir.join("host.sock")).unwrap();
    let token = send(
        &mut stream,
        &Request::Acquire {
            path: root.clone(),
            kind: Kind::Native,
        },
    )
    .unwrap()
    .token
    .unwrap();
    assert!(
        send(
            &mut stream,
            &Request::Renew {
                token: token.clone()
            }
        )
        .unwrap()
        .ok
    );
    fs::rename(&root, base.join("moved")).unwrap();
    fs::create_dir(&root).unwrap();
    assert!(!probe(&dir, &base.join("unrelated"), Kind::File));
    assert!(send(&mut stream, &Request::Finish { token }).unwrap().ok);
    assert!(probe(&dir, &root, Kind::File));
}
