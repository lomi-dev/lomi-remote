use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

struct Fixture {
    _temporary: tempfile::TempDir,
    root: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        fs::create_dir(&root).unwrap();
        git(&root, &["init", "-q"]);
        fs::write(root.join("Zażółć.txt"), "original\n").unwrap();
        git(&root, &["add", "--", "Zażółć.txt"]);
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
        fs::write(root.join("Zażółć.txt"), "modified\n").unwrap();
        Self {
            _temporary: temporary,
            root,
        }
    }
    fn outside(&self, name: &str) -> std::path::PathBuf {
        self._temporary.path().join(name)
    }
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
    assert!(
        result.status.success(),
        "fixture git failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    result.stdout
}
#[test]
fn ordinary_status_and_diff_succeed_without_index_writes() {
    let f = Fixture::new();
    let before = identity(&fs::metadata(f.root.join(".git/index")).unwrap());
    let status = read(&f.root, Observation::Status).unwrap();
    assert!(status.starts_with(b"1 .M "));
    assert!(status.ends_with("Zażółć.txt\0".as_bytes()));
    let diff = read(&f.root, Observation::Diff).unwrap();
    assert!(String::from_utf8_lossy(&diff).contains("+modified"));
    assert_eq!(
        identity(&fs::metadata(f.root.join(".git/index")).unwrap()),
        before
    );
    assert!(!f.root.join(".git/index.lock").exists());
}
#[test]
fn clean_and_process_filters_are_rejected_without_silent_raw_diff() {
    for kind in ["clean", "process"] {
        for observation in [Observation::Status, Observation::Diff] {
            let f = Fixture::new();
            let helper = f.root.join("helper.sh");
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
            assert_eq!(
                read(&f.root, observation),
                Err(Error::Rejected),
                "{kind} filter must fail closed"
            );
            assert!(!f.root.join("HELPER_RAN").exists());
        }
    }
}
#[test]
fn private_includes_and_symlinked_config_are_denied() {
    let f = Fixture::new();
    let outside = f.outside("private-config");
    fs::write(&outside, "[fixture]\nsecret = fixture-private-value\n").unwrap();
    git(
        &f.root,
        &["config", "include.path", outside.to_str().unwrap()],
    );
    assert_eq!(
        execute(&f.root, &["config", "--get", "fixture.secret"]),
        Err(Error::Rejected)
    );
    git(
        &f.root,
        &["config", "--no-includes", "--unset", "include.path"],
    );
    fs::remove_file(f.root.join(".git/config")).unwrap();
    symlink(&outside, f.root.join(".git/config")).unwrap();
    assert_eq!(read(&f.root, Observation::Status), Err(Error::Rejected));
}
#[test]
fn private_alternate_objects_and_linked_git_directory_are_denied() {
    let f = Fixture::new();
    let outside = f.outside("private-objects");
    fs::rename(f.root.join(".git/objects"), &outside).unwrap();
    fs::create_dir_all(f.root.join(".git/objects/info")).unwrap();
    fs::write(
        f.root.join(".git/objects/info/alternates"),
        format!("{}\n", outside.display()),
    )
    .unwrap();
    assert_eq!(read(&f.root, Observation::Diff), Err(Error::Rejected));
    let gitdir = f.outside("gitdir");
    fs::rename(f.root.join(".git"), &gitdir).unwrap();
    symlink(gitdir, f.root.join(".git")).unwrap();
    assert_eq!(
        read(&f.root, Observation::Status),
        Err(Error::UnsupportedRepository)
    );
}
#[test]
fn writes_and_configured_network_transport_are_denied() {
    let f = Fixture::new();
    let original = fs::read(f.root.join(".git/config")).unwrap();
    assert_eq!(
        execute(&f.root, &["config", "fixture.write", "denied"]),
        Err(Error::Rejected)
    );
    assert_eq!(fs::read(f.root.join(".git/config")).unwrap(), original);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/fixture.git", listener.local_addr().unwrap());
    // HTTP Git would spawn git-remote-http; exec/fork and network are denied.
    assert_eq!(execute(&f.root, &["ls-remote", &url]), Err(Error::Rejected));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
#[test]
fn oversized_output_and_blocked_config_reads_are_bounded() {
    let f = Fixture::new();
    fs::write(f.root.join("Zażółć.txt"), vec![b'x'; OUTPUT_LIMIT + 65536]).unwrap();
    assert_eq!(read(&f.root, Observation::Diff), Err(Error::LimitExceeded));
    fs::remove_file(f.root.join(".git/config")).unwrap();
    let path =
        std::ffi::CString::new(f.root.join(".git/config").as_os_str().as_encoded_bytes()).unwrap();
    // No writer opens this FIFO; the executor must time out and reap Git.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let start = Instant::now();
    assert_eq!(
        read(&f.root, Observation::Status),
        Err(Error::DeadlineExceeded)
    );
    assert!(start.elapsed() < TIMEOUT + Duration::from_secs(2));
}
