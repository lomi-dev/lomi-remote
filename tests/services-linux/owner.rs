#![cfg(unix)]
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const BIN: &str = env!("CARGO_BIN_EXE_lomi-service-fixture");
struct Owner {
    child: Child,
}
impl Owner {
    fn spawn(dir: &Path) -> Self {
        Self {
            child: Command::new(BIN)
                .args(["owner"])
                .arg(dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        }
    }
    fn stop(&mut self) {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let end = Instant::now() + Duration::from_secs(8);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < end, "owner shutdown timeout");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let end = Instant::now() + Duration::from_secs(8);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < end {
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn temp() -> tempfile::TempDir {
    tempfile::TempDir::new_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
}
fn call(dir: &Path, command: &str) -> Option<Value> {
    let out = Command::new(BIN)
        .arg("client")
        .arg(dir)
        .arg(command)
        .output()
        .unwrap();
    if !out.status.success() {
        return None;
    }
    Some(serde_json::from_slice(&out.stdout).unwrap())
}
fn until(dir: &Path, predicate: impl Fn(&Value) -> bool) -> Value {
    let end = Instant::now() + Duration::from_secs(6);
    loop {
        if let Some(v) = call(dir, "status")
            && predicate(&v)
        {
            return v;
        }
        assert!(Instant::now() < end, "fixture condition deadline exceeded");
        thread::sleep(Duration::from_millis(10));
    }
}
fn ready(dir: &Path) -> Value {
    until(dir, |s| {
        s["stats"]["ready"] == true
            && s["stats"]["cwdDetected"] == true
            && s["stats"]["workerPid"].as_i64().is_some()
    })
}
fn gone(pid: i32) {
    let end = Instant::now() + Duration::from_secs(3);
    while unsafe { libc::kill(pid, 0) } == 0 {
        assert!(Instant::now() < end, "fixture process survived cleanup");
        thread::sleep(Duration::from_millis(10));
    }
}
fn state(t: &tempfile::TempDir) -> PathBuf {
    t.path().join("state")
}
#[test]
fn persistent_native_pty_survives_clients_resize_and_ctrl_c() {
    let t = temp();
    let dir = state(&t);
    let mut owner = Owner::spawn(&dir);
    until(&dir, |v| v["state"] == "idle");
    call(&dir, "start").unwrap();
    let first = ready(&dir);
    let a = call(&dir, "status").unwrap();
    let b = call(&dir, "status").unwrap();
    assert_eq!(a["sessionEpoch"], b["sessionEpoch"]);
    assert_eq!(a["childPid"], b["childPid"]);
    assert!(first["stats"]["outputBytes"].as_u64().unwrap() > 0);
    assert!(first["stats"]["modelNonemptyCells"].as_u64().unwrap() > 0);
    call(&dir, "after-detach").unwrap();
    until(&dir, |v| v["stats"]["detachObserved"] == true);
    call(&dir, "resize").unwrap();
    let resized = until(&dir, |v| v["stats"]["resizeObserved"] == true);
    assert_eq!(resized["modelRows"], 37);
    assert_eq!(resized["modelCols"], 101);
    call(&dir, "ctrl-c").unwrap();
    let exited = until(&dir, |v| {
        v["state"] == "exited"
            && v["stats"]["ctrlCObserved"] == true
            && v["stats"]["cleanupComplete"] == true
    });
    assert_eq!(exited["stats"]["exitCode"], 0);
    gone(first["childPid"].as_i64().unwrap() as i32);
    gone(first["stats"]["workerPid"].as_i64().unwrap() as i32);
    call(&dir, "start").unwrap();
    let fresh = ready(&dir);
    assert_ne!(fresh["sessionEpoch"], first["sessionEpoch"]);
    assert_eq!(fresh["stats"]["inputWrites"], 0);
    call(&dir, "exit").unwrap();
    until(&dir, |v| {
        v["state"] == "exited" && v["stats"]["cleanupComplete"] == true
    });
    owner.stop();
}
#[test]
fn sigterm_cleans_owned_group_and_restart_requires_explicit_fresh_start() {
    let t = temp();
    let dir = state(&t);
    let mut owner = Owner::spawn(&dir);
    until(&dir, |v| v["state"] == "idle");
    call(&dir, "start").unwrap();
    let previous = ready(&dir);
    call(&dir, "after-detach").unwrap();
    until(&dir, |v| v["stats"]["detachObserved"] == true);
    owner.stop();
    gone(previous["childPid"].as_i64().unwrap() as i32);
    gone(previous["stats"]["workerPid"].as_i64().unwrap() as i32);
    let mut next = Owner::spawn(&dir);
    let lost = until(&dir, |v| v["state"] == "lost");
    assert_eq!(lost["sessionEpoch"], previous["sessionEpoch"]);
    assert_ne!(lost["ownerEpoch"], previous["ownerEpoch"]);
    assert!(lost["childPid"].is_null());
    assert!(lost["stats"].is_null());
    assert_eq!(lost["requiresExplicitStart"], true);
    assert!(call(&dir, "after-detach").is_none());
    call(&dir, "start").unwrap();
    let fresh = ready(&dir);
    assert_ne!(fresh["sessionEpoch"], previous["sessionEpoch"]);
    assert_eq!(fresh["stats"]["inputWrites"], 0);
    assert_eq!(fresh["stats"]["detachObserved"], false);
    next.stop();
    gone(fresh["childPid"].as_i64().unwrap() as i32);
    gone(fresh["stats"]["workerPid"].as_i64().unwrap() as i32);
}
#[test]
fn exclusive_owner_and_minimal_descriptor_without_pid_adoption() {
    let t = temp();
    let dir = state(&t);
    let mut owner = Owner::spawn(&dir);
    until(&dir, |v| v["state"] == "idle");
    let second = Command::new(BIN).arg("owner").arg(&dir).output().unwrap();
    assert!(!second.status.success());
    assert_eq!(call(&dir, "status").unwrap()["state"], "idle");
    call(&dir, "start").unwrap();
    ready(&dir);
    let descriptor: Value =
        serde_json::from_slice(&fs::read(dir.join("session.json")).unwrap()).unwrap();
    assert_eq!(descriptor.as_object().unwrap().len(), 2);
    assert!(descriptor.get("session_epoch").is_some());
    assert!(descriptor.get("version").is_some());
    owner.stop();
    fs::write(dir.join("session.json"), b"{").unwrap();
    let bad = Command::new(BIN).arg("owner").arg(&dir).output().unwrap();
    assert!(!bad.status.success());
    assert_eq!(fs::read(dir.join("session.json")).unwrap(), b"{");
}

#[test]
fn fifo_descriptor_rejects_startup_without_holding_the_owner_lock() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::DirBuilderExt},
    };
    let t = temp();
    let dir = state(&t);
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let name = CString::new(dir.join("session.json").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let mut child = Command::new(BIN)
        .arg("owner")
        .arg(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("FIFO descriptor blocked startup under the owner lock");
        }
        thread::sleep(Duration::from_millis(10));
    }
    fs::remove_file(dir.join("session.json")).unwrap();
    let mut owner = Owner::spawn(&dir);
    until(&dir, |v| v["state"] == "idle");
    owner.stop();
}

#[test]
fn incomplete_requests_never_execute_a_partial_start_command() {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    let t = temp();
    let dir = state(&t);
    let mut owner = Owner::spawn(&dir);
    until(&dir, |v| v["state"] == "idle");
    let mut socket = UnixStream::connect(dir.join("fixture.sock")).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    for byte in b"start" {
        if socket.write_all(&[*byte]).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(75));
    }
    let mut reply = Vec::new();
    socket.read_to_end(&mut reply).unwrap();
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    assert!(reply.get("error").is_some());
    assert_eq!(call(&dir, "status").unwrap()["state"], "idle");
    let mut oversized = UnixStream::connect(dir.join("fixture.sock")).unwrap();
    oversized
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    oversized.write_all(&[b'x'; 129]).unwrap();
    let mut reply = Vec::new();
    // The server may reset a socket with unread overlong bytes.
    let _ = oversized.read_to_end(&mut reply);
    assert_eq!(call(&dir, "status").unwrap()["state"], "idle");
    owner.stop();
}

#[test]
fn slow_ipc_peer_cannot_delay_sigterm_or_owned_descendant_cleanup() {
    use std::{io::Write, os::unix::net::UnixStream, sync::mpsc};
    let t = temp();
    let dir = state(&t);
    let mut owner = Owner::spawn(&dir);
    until(&dir, |v| v["state"] == "idle");
    call(&dir, "start").unwrap();
    let running = ready(&dir);
    let mut socket = UnixStream::connect(dir.join("fixture.sock")).unwrap();
    let (tx, rx) = mpsc::channel();
    let trickle = thread::spawn(move || {
        for n in 0..128 {
            if socket.write_all(b"x").is_err() {
                break;
            }
            if n == 1 {
                let _ = tx.send(());
            }
            thread::sleep(Duration::from_millis(75));
        }
    });
    rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let begin = Instant::now();
    owner.stop();
    assert!(
        begin.elapsed() < Duration::from_secs(3),
        "slow peer delayed shutdown"
    );
    gone(running["childPid"].as_i64().unwrap() as i32);
    gone(running["stats"]["workerPid"].as_i64().unwrap() as i32);
    trickle.join().unwrap();
}
