#![cfg(unix)]
use lomi_remote_protocol::{SessionEpoch, TerminalSessionId};
use lomi_terminal::{Error, SpawnProfile, TerminalService};
use std::os::unix::process::CommandExt;
use std::{
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const FIXTURE: &str = env!("CARGO_BIN_EXE_lomi-pty-supervision-fixture");
fn profile(root: &Path) -> SpawnProfile {
    SpawnProfile {
        executable: "/bin/sh".into(),
        args: vec!["-c".into(), "sleep 120".into()],
        cwd: root.into(),
        environment: vec![],
        shell_integration: None,
        rows: 8,
        cols: 40,
        history: 0,
    }
}
fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !predicate() {
        assert!(Instant::now() < deadline, "synthetic supervision deadline");
        thread::sleep(Duration::from_millis(10));
    }
}
fn live(pid: &str) -> bool {
    let output = Command::new("/bin/ps")
        .args(["-p", pid, "-o", "stat="])
        .output()
        .unwrap();
    let state = String::from_utf8_lossy(&output.stdout);
    !state.trim().is_empty() && !state.trim().starts_with('Z')
}
struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn crash(mode: &str, files: &[&str]) {
    crash_shell(mode, files, "/bin/sh");
}
fn crash_shell(mode: &str, files: &[&str], shell: &str) {
    crash_case(mode, files, shell, false);
}
fn crash_case(mode: &str, files: &[&str], shell: &str, group_signal: bool) {
    let root = tempfile::tempdir().unwrap();
    let mut sentinel = OwnedChild(Command::new("/bin/sleep").arg("120").spawn().unwrap());
    let mut owner = OwnedChild(
        Command::new(FIXTURE)
            .process_group(0)
            .arg(mode)
            .env("LOMI_PTY_FIXTURE_ROOT", root.path())
            .env("LOMI_PTY_FIXTURE_SHELL", shell)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(|| {
        root.path().join("ready").exists() && files.iter().all(|f| root.path().join(f).exists())
    });
    let pids: Vec<String> = files
        .iter()
        .map(|f| {
            std::fs::read_to_string(root.path().join(f))
                .unwrap()
                .trim()
                .to_owned()
        })
        .collect();
    assert!(pids.iter().all(|pid| live(pid)));
    if group_signal {
        // The unreaped owned fixture leader pins this exact test-created group.
        assert_eq!(
            unsafe { libc::kill(-(owner.0.id() as i32), libc::SIGTERM) },
            0
        );
    } else {
        owner.0.kill().unwrap();
    }
    owner.0.wait().unwrap();
    wait_for(|| pids.iter().all(|pid| !live(pid)));
    assert!(
        sentinel.0.try_wait().unwrap().is_none(),
        "unrelated same-user sentinel must survive"
    );
    sentinel.0.kill().unwrap();
    sentinel.0.wait().unwrap();
}
#[test]
fn host_sigkill_cleans_ordinary_shell_background_and_pipeline() {
    crash(
        "ordinary",
        &[
            "worker.pid",
            "shell.pid",
            "background.pid",
            "pipeline.pid",
            "foreground.pid",
        ],
    );
}
#[cfg(target_os = "linux")]
#[test]
fn subreaper_cleans_session_escape_that_ignores_hangup() {
    crash(
        "detached",
        &["worker.pid", "shell.pid", "background.pid", "escaped.pid"],
    );
}
#[test]
fn explicit_stop_acknowledges_and_worker_exits() {
    let root = tempfile::tempdir().unwrap();
    let status = Command::new(FIXTURE)
        .arg("stop")
        .env("LOMI_PTY_FIXTURE_ROOT", root.path())
        .status()
        .unwrap();
    assert!(status.success());
    let pid = std::fs::read_to_string(root.path().join("worker.pid")).unwrap();
    assert!(!live(pid.trim()));
}
#[test]
fn rejected_fence_and_exec_failure_are_known_and_worker_startup_is_bounded() {
    let root = tempfile::tempdir().unwrap();
    let id = TerminalSessionId::from_bytes([1; 16]).unwrap();
    let epoch = SessionEpoch::from_bytes([2; 16]).unwrap();
    let service = TerminalService::with_worker(FIXTURE.into());
    assert_eq!(
        service.spawn_with_checks(id, epoch, &profile(root.path()), || false, || Ok(())),
        Err(Error::SpawnFailed)
    );
    let mut missing = profile(root.path());
    missing.executable = root.path().join("missing");
    assert_eq!(service.spawn(id, epoch, &missing), Err(Error::SpawnFailed));
    let unavailable = TerminalService::with_worker(root.path().join("missing-worker"));
    assert_eq!(
        unavailable.spawn(id, epoch, &profile(root.path())),
        Err(Error::SpawnFailed)
    );
    let hung = TerminalService::with_worker("/bin/sleep".into());
    let start = Instant::now();
    assert_eq!(
        hung.spawn(id, epoch, &profile(root.path())),
        Err(Error::SpawnFailed)
    );
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn host_death_during_startup_closes_private_lifetime_endpoint() {
    let root = tempfile::tempdir().unwrap();
    let mut owner = OwnedChild(
        Command::new(FIXTURE)
            .arg("ordinary")
            .env("LOMI_PTY_FIXTURE_ROOT", root.path())
            .env("LOMI_PTY_FIXTURE_DELAY", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(|| root.path().join("worker.pid").exists());
    let pid = std::fs::read_to_string(root.path().join("worker.pid")).unwrap();
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    wait_for(|| !live(pid.trim()));
    assert!(!root.path().join("shell.pid").exists());
}
#[test]
fn stalled_worker_handshake_has_a_startup_deadline() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("stalled-worker");
    std::fs::write(&executable, "#!/bin/sh\nexec /bin/sleep 4\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let service = TerminalService::with_worker(executable);
    let start = Instant::now();
    assert_eq!(
        service.spawn(
            TerminalSessionId::from_bytes([1; 16]).unwrap(),
            SessionEpoch::from_bytes([2; 16]).unwrap(),
            &profile(root.path())
        ),
        Err(Error::SpawnFailed)
    );
    assert!(start.elapsed() >= Duration::from_secs(2));
    assert!(start.elapsed() < Duration::from_secs(4));
}
#[test]
fn post_exec_integrity_rejection_is_unknown_and_cleans_worker() {
    let root = tempfile::tempdir().unwrap();
    let service = TerminalService::with_worker(FIXTURE.into());
    assert_eq!(
        service.spawn_with_startup_check(
            TerminalSessionId::from_bytes([1; 16]).unwrap(),
            SessionEpoch::from_bytes([2; 16]).unwrap(),
            &profile(root.path()),
            || Err(Error::StateFailed)
        ),
        Err(Error::SpawnOutcomeUnknown)
    );
}

#[test]
fn supervised_fd_keeps_host_parser_replies_input_fences_and_resize() {
    use lomi_remote_protocol::ConsumerAuthorizationId;
    use lomi_terminal::{AuthenticatedConnection, InputOutcome};
    let root = tempfile::tempdir().unwrap();
    let service = TerminalService::with_worker(FIXTURE.into());
    let id = TerminalSessionId::from_bytes([1; 16]).unwrap();
    let epoch = SessionEpoch::from_bytes([2; 16]).unwrap();
    let mut spawn = profile(root.path());
    spawn.executable = "/usr/bin/python3".into();
    spawn.args = vec![
        "-I".into(),
        "-u".into(),
        "-c".into(),
        r#"
import os,tty,fcntl,termios,struct
assert os.isatty(0)
tty.setraw(0)
os.write(1,b'READY\r\n\x1b[6n')
while True:
    data=os.read(0,4096)
    for c in data:
        if c==65: os.write(1,b'ACCEPTED\r\n')
        if c==83:
            rows,cols,_,_=struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,b'\0'*8))
            os.write(1,('SIZE_%d_%d\r\n'%(rows,cols)).encode())
        if c==88:
            os.write(1,b'FINAL\r\n')
            raise SystemExit(0)
"#
        .into(),
    ];
    service.spawn(id, epoch, &spawn).unwrap();
    let visible = |needle: &str| {
        let snapshot = service.snapshot(id, epoch).unwrap();
        snapshot
            .normal
            .lines
            .iter()
            .flat_map(|line| line.cells.iter().map(|cell| cell.text.as_str()))
            .collect::<String>()
            .contains(needle)
    };
    wait_for(|| visible("READY") && service.stats(id).unwrap().host_replies == 1);
    let connection =
        AuthenticatedConnection::new(ConsumerAuthorizationId::from_bytes([3; 16]).unwrap());
    let attachment = service.attach(id, epoch, &connection).unwrap();
    attachment
        .acknowledge(&connection, attachment.snapshot.sequence.0)
        .unwrap();
    let lease = service.claim(id, epoch, &connection).unwrap();
    let accepted = service
        .input(id, epoch, &connection, &lease, 1, 1, b"A", || true)
        .unwrap();
    assert_eq!(accepted.outcome, InputOutcome::Accepted);
    assert_eq!(
        service.input(id, epoch, &connection, &lease, 1, 1, b"A", || panic!(
            "replayed input"
        )),
        Ok(accepted)
    );
    wait_for(|| visible("ACCEPTED"));
    service
        .resize(id, epoch, &connection, &lease, 1, 11, 55, || true)
        .unwrap();
    service
        .input(id, epoch, &connection, &lease, 2, 2, b"S", || true)
        .unwrap();
    wait_for(|| visible("SIZE_11_55"));
    service
        .input(id, epoch, &connection, &lease, 3, 3, b"X", || true)
        .unwrap();
    wait_for(|| visible("FINAL"));
    service.stop(id).unwrap();
}

#[test]
fn host_sigkill_cleans_interactive_job_control_groups() {
    crash(
        "interactive",
        &[
            "worker.pid",
            "shell.pid",
            "background.pid",
            "pipeline.pid",
            "foreground.pid",
        ],
    );
}

#[test]
fn host_sigkill_cleans_bash_interactive_job_control_groups() {
    if Path::new("/bin/bash").is_file() {
        crash_shell(
            "interactive",
            &[
                "worker.pid",
                "shell.pid",
                "background.pid",
                "pipeline.pid",
                "foreground.pid",
            ],
            "/bin/bash",
        );
    }
}
#[test]
fn host_sigkill_cleans_zsh_interactive_job_control_groups() {
    if Path::new("/bin/zsh").is_file() {
        crash_shell(
            "interactive",
            &[
                "worker.pid",
                "shell.pid",
                "background.pid",
                "pipeline.pid",
                "foreground.pid",
            ],
            "/bin/zsh",
        );
    }
}

#[test]
fn natural_exit_drains_output_and_records_platform_containment_boundary() {
    if !Path::new("/bin/bash").is_file() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let service = TerminalService::with_worker(FIXTURE.into());
    let id = TerminalSessionId::from_bytes([1; 16]).unwrap();
    let epoch = SessionEpoch::from_bytes([2; 16]).unwrap();
    let mut spawn = profile(root.path());
    spawn.executable = "/bin/bash".into();
    spawn.environment = vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("HOME".into(), root.path().to_str().unwrap().into()),
    ];
    spawn.args = vec!["--noprofile".into(), "--norc".into(), "-i".into(), "-c".into(), "sleep 4 & echo $! > inherited.pid; python3 -c 'print(\"X\"*17000)'; printf '\\nFINAL_DRAINED\\n'; exit".into()];
    service.spawn(id, epoch, &spawn).unwrap();
    wait_for(|| {
        service
            .exited_sessions()
            .unwrap()
            .iter()
            .any(|exit| exit.session_id == id)
    });
    let snapshot = service.snapshot(id, epoch).unwrap();
    let visible: String = snapshot
        .normal
        .lines
        .iter()
        .flat_map(|line| line.cells.iter().map(|cell| cell.text.as_str()))
        .collect();
    assert!(visible.contains("FINAL_DRAINED"));
    assert!(service.stats(id).unwrap().output_bytes >= 17000);
    let inherited = std::fs::read_to_string(root.path().join("inherited.pid")).unwrap();
    #[cfg(target_os = "linux")]
    assert!(
        !live(inherited.trim()),
        "Linux subreaper must also clean the inherited slave holder"
    );
    #[cfg(all(
        target_os = "macos",
        not(feature = "experimental-macos-session-cleanup")
    ))]
    assert!(
        live(inherited.trim()),
        "default macOS remains an explicitly rejected full-containment candidate: natural-exit background survives until its bounded timer"
    );
    #[cfg(all(target_os = "macos", feature = "experimental-macos-session-cleanup"))]
    assert!(
        !live(inherited.trim()),
        "experimental token-bound cleanup must clean this observed ordinary job; this is not a fork-churn completeness proof"
    );
    service.stop(id).unwrap();
    // Preserve the bounded counterexample without leaving a live fixture behind.
    wait_for(|| !live(inherited.trim()));
}

#[cfg(target_os = "linux")]
#[test]
fn natural_exit_reaps_hup_ignoring_session_escape_before_cleanup_ack() {
    natural_escape_with_worker(Path::new(FIXTURE));
}
#[cfg(target_os = "linux")]
fn natural_escape_with_worker(worker: &Path) {
    let root = tempfile::tempdir().unwrap();
    let service = TerminalService::with_worker(worker.into());
    let id = TerminalSessionId::from_bytes([1; 16]).unwrap();
    let epoch = SessionEpoch::from_bytes([2; 16]).unwrap();
    let mut spawn = profile(root.path());
    spawn.executable = "/usr/bin/python3".into();
    spawn.args = vec![
        "-I".into(),
        "-u".into(),
        "-c".into(),
        r#"
import os,signal,time
pid=os.fork()
if pid==0:
    os.setsid()
    signal.signal(signal.SIGHUP,signal.SIG_IGN)
    open('escaped.pid','w').write(str(os.getpid()))
    time.sleep(20)
    os._exit(0)
while not os.path.exists('escaped.pid'): time.sleep(.001)
os.write(1,b'X'*17000+b'\r\nFINAL_DRAINED\r\n')
"#
        .into(),
    ];
    service.spawn(id, epoch, &spawn).unwrap();
    wait_for(|| {
        service
            .exited_sessions()
            .unwrap()
            .iter()
            .any(|exit| exit.session_id == id)
    });
    let snapshot = service.snapshot(id, epoch).unwrap();
    let visible: String = snapshot
        .normal
        .lines
        .iter()
        .flat_map(|line| line.cells.iter().map(|cell| cell.text.as_str()))
        .collect();
    assert!(visible.contains("FINAL_DRAINED"));
    assert!(service.stats(id).unwrap().output_bytes >= 17000);
    let pid = std::fs::read_to_string(root.path().join("escaped.pid")).unwrap();
    assert!(!live(pid.trim()));
    service.stop(id).unwrap();
}

#[test]
fn host_group_signal_keeps_isolated_watchdog_alive_for_cleanup() {
    crash_case(
        "interactive",
        &[
            "worker.pid",
            "shell.pid",
            "background.pid",
            "pipeline.pid",
            "foreground.pid",
        ],
        "/bin/sh",
        true,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn worker_resets_inherited_sigchld_ignore_before_pinning_leader() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let wrapper = root.path().join("ignored-sigchld-worker");
    let quoted = FIXTURE.replace('\'', r#"'\''"#);
    std::fs::write(
        &wrapper,
        format!("#!/bin/sh\ntrap '' CHLD\nexec '{quoted}' --internal-pty-worker\n"),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    natural_escape_with_worker(&wrapper);
}

fn prepare_output_flood(root: &Path) -> SpawnProfile {
    std::fs::write(
        root.join("flood.py"),
        r#"
import os,signal,time
signal.signal(signal.SIGHUP,signal.SIG_IGN)
signal.alarm(4)
while not os.path.exists('flood.start'): time.sleep(.001)
open('flood.pid','w').write(str(os.getpid()))
open('flood.ready','w').write('ready')
while True:
    try: os.write(1,b'X'*65536)
    except OSError: time.sleep(.005)
"#,
    )
    .unwrap();
    let mut spawn = profile(root);
    spawn.executable = "/usr/bin/python3".into();
    spawn.args = vec![
        "-I".into(),
        "-u".into(),
        root.join("flood.py").to_str().unwrap().into(),
    ];
    spawn
}
fn flood_control(
    service: &TerminalService,
    id: TerminalSessionId,
    epoch: SessionEpoch,
) -> (
    lomi_terminal::AuthenticatedConnection,
    lomi_terminal::Attachment,
    lomi_terminal::ControlLease,
) {
    let connection = lomi_terminal::AuthenticatedConnection::new(
        lomi_remote_protocol::ConsumerAuthorizationId::from_bytes([3; 16]).unwrap(),
    );
    let attachment = service.attach(id, epoch, &connection).unwrap();
    attachment
        .acknowledge(&connection, attachment.snapshot.sequence.0)
        .unwrap();
    let lease = service.claim(id, epoch, &connection).unwrap();
    (connection, attachment, lease)
}
#[test]
fn continuous_output_cannot_hide_owned_worker_crash_or_keep_input_live() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let wrapper = root.path().join("crash-owned-worker");
    let fixture = FIXTURE.replace('\'', r#"'\''"#);
    let directory = root.path().to_str().unwrap().replace('\'', r#"'\''"#);
    std::fs::write(&wrapper,format!("#!/bin/sh\nLOMI_PTY_FIXTURE_ROOT='{directory}' exec '{fixture}' --internal-pty-worker --test-owned-worker-crash\n")).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut sentinel = OwnedChild(Command::new("/bin/sleep").arg("10").spawn().unwrap());
    let service = TerminalService::with_worker(wrapper);
    let id = TerminalSessionId::from_bytes([1; 16]).unwrap();
    let epoch = SessionEpoch::from_bytes([2; 16]).unwrap();
    service
        .spawn(id, epoch, &prepare_output_flood(root.path()))
        .unwrap();
    let (connection, _attachment, lease) = flood_control(&service, id, epoch);
    std::fs::write(root.path().join("flood.start"), b"start").unwrap();
    wait_for(|| root.path().join("worker.killed").exists());
    let deadline = Instant::now() + Duration::from_secs(2);
    while service.renew(id, epoch, &connection, &lease) != Err(Error::SessionExited) {
        assert!(
            Instant::now() < deadline,
            "continuous output hid worker EOF"
        );
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        service.input(id, epoch, &connection, &lease, 1, 1, b"A", || panic!(
            "input fence entered after supervision loss"
        )),
        Err(Error::SessionExited)
    );
    assert!(matches!(
        service.exited_sessions(),
        Err(Error::CleanupFailed)
    ));
    assert_eq!(service.stop(id), Err(Error::CleanupFailed));
    assert!(sentinel.0.try_wait().unwrap().is_none());
    let pid = std::fs::read_to_string(root.path().join("flood.pid")).unwrap();
    wait_for(|| !live(pid.trim()));
}
#[cfg(all(
    target_os = "macos",
    not(feature = "experimental-macos-session-cleanup")
))]
#[test]
fn clean_original_group_ack_bounds_final_drain_with_surviving_output_flood() {
    let root = tempfile::tempdir().unwrap();
    prepare_output_flood(root.path());
    let service = TerminalService::with_worker(FIXTURE.into());
    let id = TerminalSessionId::from_bytes([1; 16]).unwrap();
    let epoch = SessionEpoch::from_bytes([2; 16]).unwrap();
    let mut spawn = profile(root.path());
    spawn.executable = "/bin/bash".into();
    spawn.environment = vec![
        ("HOME".into(), root.path().to_str().unwrap().into()),
        ("PATH".into(), "/usr/bin:/bin".into()),
    ];
    spawn.args=vec!["--noprofile".into(),"--norc".into(),"-i".into(),"-c".into(),"/usr/bin/python3 -I -u flood.py & while [ ! -f flood.ready ]; do /bin/sleep .01; done; exit".into()];
    service.spawn(id, epoch, &spawn).unwrap();
    let (connection, _attachment, lease) = flood_control(&service, id, epoch);
    let start = Instant::now();
    std::fs::write(root.path().join("flood.start"), b"start").unwrap();
    while service.exited_sessions().unwrap().is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "continuous writer retained model after cleanup ACK"
        );
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        service.claim(id, epoch, &connection),
        Err(Error::SessionExited)
    );
    assert_eq!(
        service.input(id, epoch, &connection, &lease, 1, 1, b"A", || panic!(
            "input fence entered during final drain"
        )),
        Err(Error::SessionExited)
    );
    service.stop(id).unwrap();
    let pid = std::fs::read_to_string(root.path().join("flood.pid")).unwrap();
    assert!(
        live(pid.trim()),
        "this regression must exercise ACK while a timed slave writer remains alive"
    );
    wait_for(|| !live(pid.trim()));
}
