//! Self-owned integrated fixture; it never accepts a numeric cleanup PID.
#[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
#[path = "../../../../tests/product-pty-macos/fixture_fault.rs"]
mod fixture_fault;
#[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
fn main() {
    use lomi_remote_protocol::{SessionEpoch, TerminalSessionId};
    use lomi_terminal::{SpawnProfile, TerminalService};
    use std::{
        io::Write,
        path::PathBuf,
        time::{Duration, Instant},
    };
    let args: Vec<_> = std::env::args_os().collect();
    if args
        .get(1)
        .is_some_and(|value| value == "--internal-pty-coalition")
    {
        std::process::exit(lomi_terminal::internal_pty_coalition(std::path::Path::new(
            args.get(2).expect("generation"),
        )));
    }
    if args.get(1).is_some_and(|value| value == "--leaf") {
        let root = PathBuf::from(args.get(2).expect("root"));
        let remaining: u32 = args.get(3).unwrap().to_str().unwrap().parse().unwrap();
        // Every fork installs its own bounded expiry; exec preserves this timer.
        unsafe {
            libc::alarm(5);
        }
        if remaining > 0 {
            use std::os::unix::process::CommandExt;
            let error = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--leaf")
                .arg(&root)
                .arg((remaining - 1).to_string())
                .exec();
            panic!("owned leaf exec failed: {error}");
        }
        let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) },
            0
        );
        let armed_ns = clock.tv_sec as u64 * 1_000_000_000 + clock.tv_nsec as u64;
        unsafe {
            libc::alarm(5);
        }
        std::fs::write(
            root.join("leaf.ready"),
            serde_json::to_vec(&serde_json::json!({
                "armedAtNs": armed_ns, "deadlineNs": armed_ns + 5_000_000_000u64
            }))
            .unwrap(),
        )
        .unwrap();
        println!("PTY_READY");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if args.get(1).is_some_and(|value| value == "--workload") {
        let root = PathBuf::from(args.get(2).expect("root"));
        let kind = args
            .get(3)
            .and_then(|value| value.to_str())
            .unwrap_or("ordinary");
        if matches!(kind, "background" | "escaped") {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let executable =
                CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes()).unwrap();
            let root_arg = CString::new(root.as_os_str().as_bytes()).unwrap();
            let leaf_arg = CString::new("--leaf").unwrap();
            let count_arg = CString::new(if kind == "escaped" { "3" } else { "0" }).unwrap();
            let argv = [
                executable.as_ptr(),
                leaf_arg.as_ptr(),
                root_arg.as_ptr(),
                count_arg.as_ptr(),
                std::ptr::null(),
            ];
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                unsafe {
                    libc::alarm(5);
                    if kind == "escaped" {
                        if libc::setsid() < 0 {
                            libc::_exit(51);
                        }
                        let leaf = libc::fork();
                        if leaf < 0 {
                            libc::_exit(52);
                        }
                        if leaf > 0 {
                            libc::_exit(0);
                        }
                        // alarm is not inherited across fork.
                        libc::alarm(5);
                    }
                    libc::execv(executable.as_ptr(), argv.as_ptr());
                    libc::_exit(53);
                }
            }
            if kind == "escaped" {
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                assert_eq!(status, 0);
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while !root.join("host.ready").exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
            // Deliberate normal leader exit leaves the self-expiring owned leaf.
            return;
        }
        if kind == "fault-nofork" {
            // This source-known fixture never forks/execs. Ignore terminal HUP
            // so controller death leaves a real live orphan until its own alarm.
            unsafe {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                libc::signal(libc::SIGALRM, libc::SIG_DFL);
                libc::alarm(20);
            }
        }
        std::fs::write(
            root.join(format!("{kind}.pid")),
            std::process::id().to_string(),
        )
        .unwrap();
        println!("PTY_READY");
        std::io::stdout().flush().unwrap();
        let deadline =
            Instant::now() + Duration::from_secs(if kind == "sentinel" { 60 } else { 20 });
        let mut sequence = 0u64;
        while Instant::now() < deadline {
            std::fs::write(root.join(format!("{kind}.heartbeat")), sequence.to_string()).unwrap();
            sequence += 1;
            std::thread::sleep(Duration::from_millis(20));
        }
        return;
    }
    // Establish real kernel child retention before the service creates threads.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) },
        0
    );
    let mode = args.get(1).and_then(|value| value.to_str()).expect("mode");
    let root = PathBuf::from(args.get(2).expect("root"));
    let profile = root.join("Library/Application Support/LomiRemote");
    if mode == "recover" {
        std::process::exit(
            if lomi_terminal::internal_pty_coalition_recover(&profile).is_ok() {
                0
            } else {
                4
            },
        );
    }
    assert!(matches!(
        mode,
        "stop"
            | "host-eof"
            | "leader-exit"
            | "escaped-leader-exit"
            | "fence-reject"
            | "controller-death"
    ));
    std::fs::create_dir_all(&profile).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Explicit recovery before the first new spawn, never replaying old intent.
    lomi_terminal::internal_pty_coalition_recover(&profile).unwrap();
    let executable = std::env::current_exe().unwrap();
    let service = TerminalService::with_worker_in_profile(executable.clone(), profile);
    let id = TerminalSessionId::from_bytes([1; 16]).unwrap();
    let epoch = SessionEpoch::from_bytes([2; 16]).unwrap();
    let payload = SpawnProfile {
        executable,
        args: vec![
            "--workload".into(),
            root.to_str().unwrap().into(),
            match mode {
                "leader-exit" => "background",
                "escaped-leader-exit" => "escaped",
                "controller-death" => "fault-nofork",
                _ => "ordinary",
            }
            .into(),
        ],
        cwd: root.clone(),
        environment: vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            (
                "LOMI_FIXTURE_PROTECTED".into(),
                "never-persist-this-fixture-value".into(),
            ),
        ],
        shell_integration: None,
        rows: 10,
        cols: 80,
        history: 0,
    };
    let outcome =
        service.spawn_with_checks(id, epoch, &payload, || mode != "fence-reject", || Ok(()));
    if mode == "fence-reject" {
        assert!(matches!(outcome, Err(lomi_terminal::Error::SpawnFailed)));
        let deadline = Instant::now() + Duration::from_secs(8);
        while lomi_terminal::internal_pty_coalition_recover(
            &root.join("Library/Application Support/LomiRemote"),
        )
        .is_err()
        {
            assert!(Instant::now() < deadline, "cancelled generation unresolved");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!root.join("ordinary.pid").exists());
        std::fs::write(root.join("fence.rejected"), b"no-workload-granted").unwrap();
        return;
    }
    outcome.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = service.snapshot(id, epoch).unwrap();
        let text: String = snapshot
            .normal
            .lines
            .iter()
            .flat_map(|line| &line.cells)
            .map(|cell| cell.text.as_str())
            .collect();
        if text.contains("PTY_READY") {
            break;
        }
        assert!(Instant::now() < deadline, "actual PTY output not observed");
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::write(root.join("host.ready"), b"actual-pty-ready").unwrap();
    if mode == "controller-death" {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !root.join("fault.injected").exists() {
            assert!(
                Instant::now() < deadline,
                "observer did not authorize fault"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let shutdown_failed = service.shutdown().is_err();
        let recovery_failed = lomi_terminal::internal_pty_coalition_recover(
            &root.join("Library/Application Support/LomiRemote"),
        )
        .is_err();
        let reservations = fixture_fault::reservations(
            &service,
            &root.join("Library/Application Support/LomiRemote"),
            &payload,
        );
        let report = serde_json::json!({"shutdownReportedCleanupFailure":shutdown_failed,
            "recoveryReportedUncertainty":recovery_failed,"reservations":reservations});
        std::fs::write(
            root.join("host.negative.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(50);
        while !root.join("operator.release").exists() {
            assert!(Instant::now() < deadline, "operator proof unavailable");
            std::thread::sleep(Duration::from_millis(10));
        }
        return;
    }
    if mode != "host-eof" {
        if mode != "stop" {
            let deadline = Instant::now() + Duration::from_secs(8);
            while service.exited_sessions().unwrap().is_empty() {
                assert!(Instant::now() < deadline, "leader exit cleanup unresolved");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        service.stop(id).unwrap();
        std::fs::write(root.join("host.stopped"), b"cleaned").unwrap();
    } else {
        // The native driver kills only this retained host group. launchd's
        // controller is outside it and must converge on authenticated IPC EOF.
        std::thread::sleep(Duration::from_secs(15));
    }
}
#[cfg(not(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup")))]
fn main() {
    std::process::exit(3);
}
