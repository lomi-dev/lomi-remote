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
    let result = std::panic::catch_unwind(|| {
        abi().unwrap();
        runtime().unwrap();
        namespace_prerequisite().unwrap();
        let helper_dir = tempfile::tempdir().unwrap();
        let helper = helper_dir.path().join("static-helper");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/git-linux-isolation/helper.c");
        assert!(
            Command::new("/usr/bin/cc")
                .args(["-static", "-O2", "-o"])
                .arg(&helper)
                .arg(source)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .status()
                .unwrap()
                .success()
        );
        let elf = fs::read(&helper).unwrap();
        assert_eq!(&elf[..4], b"\x7fELF");
        let offset = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
        let size = u16::from_le_bytes(elf[54..56].try_into().unwrap()) as usize;
        let count = u16::from_le_bytes(elf[56..58].try_into().unwrap()) as usize;
        for n in 0..count {
            assert_ne!(
                u32::from_le_bytes(
                    elf[offset + n * size..offset + n * size + 4]
                        .try_into()
                        .unwrap()
                ),
                3,
                "helper must have no PT_INTERP"
            );
        }
        let mut checks = Vec::new();
        let f = Fixture::new();
        symlink(f.outside("private"), f.root.join("outside-link")).unwrap();
        let index = fs::read(f.root.join(".git/index")).unwrap();
        let mut before = snapshot::Snapshot::capture(&f.root).expect("capture before status");
        before.validate().expect("revalidate before status");
        let status = f.observe(Observation::Status);
        assert!(status.is_ok(), "positive status: {status:?}");
        assert!(status.unwrap().starts_with(b"1 .M "));
        assert!(
            String::from_utf8(f.observe(Observation::Diff).unwrap())
                .unwrap()
                .contains("+modified")
        );
        assert_eq!(index, fs::read(f.root.join(".git/index")).unwrap());
        checks.push("positive-status-diff-symlink-and-source-index-unchanged");
        let f = Fixture::new();
        let pinned = open_root(&f.root).unwrap();
        let held = f.outside("held-original");
        fs::rename(&f.root, &held).unwrap();
        fs::create_dir(&f.root).unwrap();
        fs::write(f.root.join("substitute"), b"not the pinned tree").unwrap();
        let mut snapshot = snapshot::Snapshot::capture_pinned(&pinned).unwrap();
        assert!(
            snapshot
                .entries
                .iter()
                .any(|e| e.path == Path::new("fixture.txt"))
        );
        assert!(
            !snapshot
                .entries
                .iter()
                .any(|e| e.path == Path::new("substitute"))
        );
        fs::rename(&f.root, f.outside("substitute-root")).unwrap();
        fs::rename(&held, &f.root).unwrap();
        assert_eq!(snapshot.validate(), Err(Error::Changed));
        checks.push("pinned-root-survives-path-substitution-before-capture");
        let ordinary = File::create(f.outside("ordinary-manifest")).unwrap();
        assert!(!setup::sealed_manifest(ordinary.as_raw_fd()));
        let sealed = snapshot::sealed(b"[]".as_slice(), 0o400, (0, 0), 128).unwrap();
        assert!(setup::sealed_manifest(sealed.as_raw_fd()));
        checks.push("manifest-requires-valid-sealed-memfd");
        fs::copy(&helper, f.root.join("helper-static")).unwrap();
        let result = read(&f.root, Observation::Status, Probe::Syscalls, None);
        assert!(result.is_ok(), "syscalls: {result:?}");
        checks.push("outside-open-stat-statx-access-readlink-absolute-and-relative-absent");
        assert_eq!(
            read(&f.root, Observation::Status, Probe::CloseBefore, None),
            Err(Error::Rejected)
        );
        assert_eq!(
            read(&f.root, Observation::Status, Probe::CloseAfter, None),
            Ok(Vec::new())
        );
        checks.push("listener-teardown-before-and-after-one-approved-exec");
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
        checks.push("inherited-outside-descriptor-closed");
        for process in [false, true] {
            let f = Fixture::new();
            fs::write(
                f.root.join(".gitattributes"),
                "fixture.txt filter=blocked\n",
            )
            .unwrap();
            let mut config = fs::read_to_string(f.root.join(".git/config")).unwrap();
            config.push_str(if process {
                "\n[filter \"blocked\"]\n process = /repo/helper\n"
            } else {
                "\n[filter \"blocked\"]\n clean = /repo/helper\n"
            });
            fs::write(f.root.join(".git/config"), config).unwrap();
            // Actual ELF helper, rather than relying on a missing shell/interpreter.
            fs::copy(&helper, f.root.join("helper")).unwrap();
            fs::set_permissions(f.root.join("helper"), fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(f.observe(Observation::Status), Err(Error::Rejected));
            assert_eq!(f.observe(Observation::Diff), Err(Error::Rejected));
        }
        checks.push("preserved-clean-process-filters-with-elf-helper-fail-no-fallback");
        let f = Fixture::new();
        fs::hard_link(f.outside("private"), f.root.join("private-alias")).unwrap();
        assert_eq!(f.observe(Observation::Diff), Err(Error::Repository));
        checks.push("outside-hardlink-rejected-before-copy");
        for path in [".git/objects/info/alternates", ".git/commondir"] {
            let f = Fixture::new();
            fs::write(f.root.join(path), "/outside\n").unwrap();
            assert_eq!(f.observe(Observation::Status), Err(Error::Repository));
        }
        let f = Fixture::new();
        let mut config = fs::read_to_string(f.root.join(".git/config")).unwrap();
        config.push_str("\n[include]\n path = /etc/passwd\n");
        fs::write(f.root.join(".git/config"), config).unwrap();
        assert_eq!(f.observe(Observation::Status), Err(Error::Repository));
        checks.push("alternates-commondir-unsafe-include-config-refused");
        let f = Fixture::new();
        let name = CString::new(f.root.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert_eq!(f.observe(Observation::Status), Err(Error::Repository));
        checks.push("special-files-nonblocking-refusal");
        for mutation in 0..4 {
            let f = Fixture::new();
            let mut snapshot = snapshot::Snapshot::capture(&f.root).unwrap();
            match mutation {
                0 => fs::write(f.root.join("fixture.txt"), "changed!\n").unwrap(),
                1 => {
                    fs::rename(f.root.join("fixture.txt"), f.root.join("moved")).unwrap();
                }
                2 => {
                    fs::remove_file(f.root.join("fixture.txt")).unwrap();
                    symlink(f.outside("private"), f.root.join("fixture.txt")).unwrap();
                }
                _ => {
                    fs::hard_link(f.outside("private"), f.root.join("new-alias")).unwrap();
                }
            }
            assert_eq!(snapshot.validate(), Err(Error::Changed));
        }
        checks.push("held-fd-content-rename-symlink-hardlink-races-discarded");
        let f = Fixture::new();
        let snapshot = snapshot::Snapshot::capture(&f.root).unwrap();
        for entry in &snapshot.entries {
            if let Some(file) = &entry.data {
                let m = file.metadata().unwrap();
                let original = fs::metadata(f.root.join(&entry.path)).unwrap();
                assert_eq!(
                    (m.mode() & 0o777, m.mtime(), m.mtime_nsec()),
                    (
                        original.mode() & 0o777,
                        original.mtime(),
                        original.mtime_nsec()
                    )
                );
                let n = unsafe { libc::pwrite(file.as_raw_fd(), c"x".as_ptr().cast(), 1, 0) };
                assert_eq!(n, -1);
                assert_eq!(unsafe { *libc::__errno_location() }, libc::EPERM);
            }
        }
        checks.push("sealed-snapshot-preserves-file-mode-and-mtime");
        let f = Fixture::new();
        assert_eq!(
            read(&f.root, Observation::Status, Probe::Write, None),
            Err(Error::Rejected)
        );
        assert_eq!(
            read(&f.root, Observation::Status, Probe::Network, None),
            Err(Error::Rejected)
        );
        checks.push("git-config-write-and-network-transport-refused");
        let f = Fixture::new();
        let file = File::create(f.root.join("oversize")).unwrap();
        file.set_len(8 * 1024 * 1024 + 1).unwrap();
        assert_eq!(f.observe(Observation::Status), Err(Error::Limit));
        checks.push("snapshot-byte-limit-refused");
        let f = Fixture::new();
        fs::write(f.root.join("fixture.txt"), "large-line\n".repeat(300000)).unwrap();
        assert_eq!(f.observe(Observation::Diff), Err(Error::Limit));
        checks.push("output-limit-kills-owned-namespace");
        for probe in [Probe::PostflightFifo, Probe::PostflightFile] {
            let f = Fixture::new();
            let start = Instant::now();
            assert_eq!(
                read(&f.root, Observation::Status, probe, None),
                Err(Error::Changed)
            );
            assert!(start.elapsed() < Duration::from_secs(3));
            assert_eq!(f.observe(Observation::Status), Err(Error::Repository));
        }
        checks.push("fifo-and-regular-root-replacement-nonblocking-refused");
        let f = Fixture::new();
        assert_eq!(
            read(
                &f.root,
                Observation::Status,
                Probe::SecondDrainerFailure,
                None
            ),
            Err(Error::Setup)
        );
        assert!(SECOND_DRAINER_FAILURE_OBSERVED.load(Ordering::SeqCst));
        let group = LAST_WORKER.load(Ordering::SeqCst);
        assert_eq!(unsafe { libc::kill(-group, 0) }, -1);
        checks.push("second-drainer-start-failure-reaps-before-join");
        let f = Fixture::new();
        let start = Instant::now();
        assert_eq!(
            read(&f.root, Observation::Status, Probe::Hang, None),
            Err(Error::Deadline)
        );
        assert!(start.elapsed() < Duration::from_secs(8));
        let group = LAST_WORKER.load(Ordering::SeqCst);
        assert_eq!(unsafe { libc::kill(-group, 0) }, -1);
        assert_eq!(unsafe { *libc::__errno_location() }, libc::ESRCH);
        checks.push("timeout-listener-stall-reaps-owned-namespace");
        println!(
            "{}",
            serde_json::json!({"qualified":false,"checksPassed":checks.len(),"checks":checks,"isolationRoute":"sealed-snapshot-private-namespaces-one-shot-seccomp","ordinaryRepositoriesOnly":true})
        );
    });
    if result.is_ok() { 0 } else { 1 }
}

pub(super) fn cancel_probe() -> i32 {
    let f = Fixture::new();
    CANCEL_FIXTURE.store(true, Ordering::SeqCst);
    let result = read(&f.root, Observation::Status, Probe::Hang, None);
    if result == Err(Error::Interrupted) {
        println!("{}", serde_json::json!({"cancellationPassed":true}));
        0
    } else {
        1
    }
}
