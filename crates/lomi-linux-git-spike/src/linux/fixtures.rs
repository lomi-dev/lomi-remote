use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
struct Fixture {
    temporary: tempfile::TempDir,
    root: PathBuf,
}
fn git(root: &Path, args: &[&str]) -> Vec<u8> {
    let result = Command::new(GIT)
        .arg("-C")
        .arg(root)
        .args(args)
        .env_clear()
        .env("HOME", root)
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(result.status.success(), "synthetic fixture setup failed");
    result.stdout
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        fs::create_dir(&root).unwrap();
        fs::write(temporary.path().join("private"), "synthetic outside data\n").unwrap();
        git(&root, &["init", "-q"]);
        fs::write(root.join("fixture.txt"), "original\n").unwrap();
        git(&root, &["add", "--", "fixture.txt"]);
        git(
            &root,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
        );
        fs::write(root.join("fixture.txt"), "modified\n").unwrap();
        Self { temporary, root }
    }
    fn outside(&self, name: &str) -> PathBuf {
        self.temporary.path().join(name)
    }
    fn observe(&self, observation: Observation) -> Result<Vec<u8>> {
        read(&self.root, observation, Probe::None, None)
    }
}
pub(super) fn run() -> i32 {
    let outcome = std::panic::catch_unwind(|| {
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "fixture must run unprivileged"
        );
        abi().unwrap();
        runtime().unwrap();
        let mut checks = Vec::new();
        let f = Fixture::new();
        let index = fs::metadata(f.root.join(".git/index")).unwrap();
        let result = f.observe(Observation::Status);
        assert!(result.is_ok(), "positive status rejected: {result:?}");
        assert!(result.unwrap().starts_with(b"1 .M "));
        assert!(
            String::from_utf8(f.observe(Observation::Diff).unwrap())
                .unwrap()
                .contains("+modified")
        );
        let after = fs::metadata(f.root.join(".git/index")).unwrap();
        assert_eq!(
            (index.ino(), index.mtime(), index.mtime_nsec()),
            (after.ino(), after.mtime(), after.mtime_nsec())
        );
        checks.push("positive-status-diff-no-index-write");
        assert!(
            read(&f.root, Observation::Status, Probe::Syscalls, None).is_ok(),
            "syscall restriction probe failed"
        );
        assert!(!f.root.join("write-denied").exists());
        checks.push("syscall-allowlist-tcp-udp-unix-fork-thread-exec-writes-denied");
        assert_eq!(
            read(&f.root, Observation::Status, Probe::CloseBefore, None),
            Err(Error::Rejected)
        );
        assert_eq!(
            read(&f.root, Observation::Status, Probe::CloseAfter, None),
            Ok(Vec::new())
        );
        checks.push("listener-teardown-before-after-one-shot-approval");
        let private = File::open(f.outside("private")).unwrap();
        assert!(
            read(
                &f.root,
                Observation::Status,
                Probe::InheritedFd,
                Some(private.as_raw_fd())
            )
            .is_ok()
        );
        checks.push("inherited-private-fd-closed-before-git");
        for kind in ["clean", "process"] {
            for observation in [Observation::Status, Observation::Diff] {
                let f = Fixture::new();
                let helper = f.root.join("helper");
                fs::write(&helper, "#!/bin/sh\nprintf ran > HELPER_RAN\ncat\n").unwrap();
                fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
                git(
                    &f.root,
                    &[
                        "config",
                        &format!("filter.fixture.{kind}"),
                        helper.to_str().unwrap(),
                    ],
                );
                fs::write(f.root.join(".gitattributes"), "*.txt filter=fixture\n").unwrap();
                assert_eq!(f.observe(observation), Err(Error::Rejected));
                assert!(!f.root.join("HELPER_RAN").exists());
            }
        }
        checks.push("clean-process-filters-status-diff-no-silent-fallback");
        let f = Fixture::new();
        let helper = f.root.join("helper");
        fs::write(&helper, "#!/bin/sh\nprintf ran > HELPER_RAN\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        for key in ["core.fsmonitor", "diff.external", "diff.fixture.textconv"] {
            git(&f.root, &["config", key, helper.to_str().unwrap()]);
        }
        git(
            &f.root,
            &["config", "alias.status", &format!("!{}", helper.display())],
        );
        fs::write(f.root.join(".gitattributes"), "*.txt diff=fixture\n").unwrap();
        assert!(f.observe(Observation::Status).is_ok());
        assert!(f.observe(Observation::Diff).is_ok());
        assert!(!f.root.join("HELPER_RAN").exists());
        checks.push("closed-argv-alias-fsmonitor-diff-textconv-disabled");
        let f = Fixture::new();
        let outside = f.outside("include");
        fs::write(&outside, "[fixture]\nsecret = synthetic\n").unwrap();
        git(
            &f.root,
            &["config", "include.path", outside.to_str().unwrap()],
        );
        assert_eq!(f.observe(Observation::Status), Err(Error::Rejected));
        fs::remove_file(f.root.join(".git/config")).unwrap();
        symlink(&outside, f.root.join(".git/config")).unwrap();
        assert_eq!(f.observe(Observation::Status), Err(Error::Rejected));
        checks.push("outside-config-include-and-symlink-denied");
        let f = Fixture::new();
        let objects = f.outside("objects");
        fs::rename(f.root.join(".git/objects"), &objects).unwrap();
        fs::create_dir_all(f.root.join(".git/objects/info")).unwrap();
        fs::write(
            f.root.join(".git/objects/info/alternates"),
            format!("{}\n", objects.display()),
        )
        .unwrap();
        assert_eq!(f.observe(Observation::Diff), Err(Error::Rejected));
        let gitdir = f.outside("gitdir");
        fs::rename(f.root.join(".git"), &gitdir).unwrap();
        symlink(gitdir, f.root.join(".git")).unwrap();
        assert_eq!(f.observe(Observation::Status), Err(Error::Repository));
        checks.push("outside-alternates-and-linked-gitdir-denied");
        let f = Fixture::new();
        fs::write(f.root.join("fixture.txt"), vec![b'x'; LIMIT + 65536]).unwrap();
        assert_eq!(f.observe(Observation::Diff), Err(Error::Limit));
        fs::remove_file(f.root.join(".git/config")).unwrap();
        let fifo = CString::new(f.root.join(".git/config").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert_eq!(f.observe(Observation::Status), Err(Error::Deadline));
        assert!(start.elapsed() < Duration::from_secs(7));
        checks.push("bounded-output-and-fifo-deadline-owned-group-cleanup");
        let f = Fixture::new();
        assert_eq!(
            read(&f.root, Observation::Status, Probe::WrongRuntime, None),
            Err(Error::Rejected)
        );
        checks.push("passed-runtime-fd-binding-mismatch-rejected");
        let config = fs::read(f.root.join(".git/config")).unwrap();
        assert_eq!(
            read(&f.root, Observation::Status, Probe::Write, None),
            Err(Error::Rejected)
        );
        assert_eq!(fs::read(f.root.join(".git/config")).unwrap(), config);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        git(
            &f.root,
            &[
                "config",
                "remote.origin.url",
                &format!("http://{}/synthetic.git", listener.local_addr().unwrap()),
            ],
        );
        assert_eq!(
            read(&f.root, Observation::Status, Probe::Network, None),
            Err(Error::Rejected)
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        checks.push("git-config-write-network-transport-no-side-effects");
        let replaced = Fixture::new();
        fs::remove_file(replaced.root.join(".git/config")).unwrap();
        let fifo = CString::new(
            replaced
                .root
                .join(".git/config")
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        thread::scope(|scope| {
            let pending = scope.spawn(|| replaced.observe(Observation::Status));
            thread::sleep(Duration::from_millis(300));
            fs::rename(&replaced.root, replaced.outside("moved-repository")).unwrap();
            fs::create_dir(&replaced.root).unwrap();
            assert_eq!(pending.join().unwrap(), Err(Error::Changed));
        });
        checks.push("ordinary-root-path-replacement-detected");
        let outside = f.outside("private-hardlink");
        fs::write(&outside, "synthetic hardlink alias\n").unwrap();
        fs::remove_file(f.root.join("fixture.txt")).unwrap();
        fs::hard_link(outside, f.root.join("fixture.txt")).unwrap();
        assert!(
            String::from_utf8(f.observe(Observation::Diff).unwrap())
                .unwrap()
                .contains("+synthetic hardlink alias")
        );
        serde_json::json!({"profile":"linux-git-abi4-seccomp-experimental","qualified":false,"checks":checks,"checksPassed":checks.len(),"landlockAbi":4,"uid":unsafe{libc::geteuid()},"gitVersion":"2.43.0","runtimePins":RUNTIME.iter().map(|(path,sha)|serde_json::json!({"path":path,"sha256":sha})).collect::<Vec<_>>(),"knownLimitsObserved":{"outsideMetadataVisible":true,"hardlinkAliasContentReadable":true},"not_run":["race-free hardlink/live-tree secrecy","other kernels/architectures/distributions","production git.read qualification"]})
    });
    match outcome {
        Ok(report) => {
            println!("{report}");
            0
        }
        Err(_) => {
            eprintln!("synthetic Linux Git regression failed");
            1
        }
    }
}

pub(super) fn cancel_probe() -> i32 {
    CANCEL_FIXTURE.store(true, Ordering::SeqCst);
    let f = Fixture::new();
    fs::remove_file(f.root.join(".git/config")).unwrap();
    let path = CString::new(f.root.join(".git/config").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    println!("synthetic-cancellation-ready");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    let result = f.observe(Observation::Status);
    let pid = LAST_WORKER.load(Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(3);
    while unsafe { libc::kill(-pid, 0) } == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    let passed =
        result == Err(Error::Interrupted) && pid > 0 && unsafe { libc::kill(-pid, 0) } == -1;
    println!(
        "{}",
        serde_json::json!({"qualified":false,"cancellationPassed":passed})
    );
    if passed { 0 } else { 1 }
}

pub(super) fn review_regressions() -> i32 {
    let outcome = std::panic::catch_unwind(|| {
        for probe in [Probe::PostflightFifo, Probe::PostflightFile] {
            let fixture = Fixture::new();
            let started = Instant::now();
            assert_eq!(
                read(&fixture.root, Observation::Status, probe, None),
                Err(Error::Changed)
            );
            assert!(
                started.elapsed() < DEADLINE,
                "postflight replacement was not bounded"
            );
            // The same replacement must also fail authorization immediately.
            let started = Instant::now();
            assert_eq!(fixture.observe(Observation::Status), Err(Error::Repository));
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "initial replacement was not bounded"
            );
        }
        let fixture = Fixture::new();
        fs::remove_file(fixture.root.join(".git/config")).unwrap();
        let path = CString::new(
            fixture
                .root
                .join(".git/config")
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        SECOND_DRAINER_FAILURE_OBSERVED.store(false, Ordering::SeqCst);
        let started = Instant::now();
        assert_eq!(
            read(
                &fixture.root,
                Observation::Status,
                Probe::SecondDrainerFailure,
                None
            ),
            Err(Error::Setup)
        );
        assert!(
            SECOND_DRAINER_FAILURE_OBSERVED.load(Ordering::SeqCst),
            "second drainer failure was not injected after Git launched"
        );
        assert!(
            started.elapsed() < DEADLINE,
            "drainer startup cleanup was not bounded"
        );
        let group = LAST_WORKER.load(Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(3);
        while unsafe { libc::kill(-group, 0) } == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            group > 0 && unsafe { libc::kill(-group, 0) } == -1,
            "owned group survived drainer startup failure"
        );
    });
    if outcome.is_err() {
        eprintln!("synthetic Linux review regressions failed");
        return 1;
    }
    println!(
        "{}",
        serde_json::json!({"qualified":false,"reviewChecksPassed":2,"checks":["fifo-and-file-root-replacement-initial-postflight-bounded","second-drainer-failure-kills-reaps-before-joining-blocked-stdout"]})
    );
    0
}
