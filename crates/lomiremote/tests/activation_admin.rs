#![cfg(target_os = "macos")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
};

struct InstallFixture {
    directory: PathBuf,
    executable: PathBuf,
}

impl InstallFixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "lomiremote-activation-admin-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&directory).expect("create private activation fixture");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("secure activation fixture directory");

        let executable = directory.join("lomiremote");
        fs::copy(env!("CARGO_BIN_EXE_lomiremote"), &executable)
            .expect("copy CLI into activation fixture");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("make fixture CLI executable");
        fs::write(
            directory.join("activation.pending"),
            b"test activation marker",
        )
        .expect("create pending activation marker");
        fs::set_permissions(
            directory.join("activation.pending"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("secure activation marker");

        Self {
            directory,
            executable,
        }
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(&self.executable)
            .args(arguments)
            .output()
            .expect("run fixture CLI")
    }

    fn missing_registration(&self) -> String {
        self.directory
            .join("missing-registration.json")
            .to_str()
            .expect("fixture path is UTF-8")
            .to_owned()
    }
}

impl Drop for InstallFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_activation_blocked(output: &Output) {
    assert_eq!(output.status.code(), Some(4));
    assert!(stderr(output).contains("INSTALLATION_ACTIVATION_INCOMPLETE"));
}

#[test]
fn pending_activation_blocks_ordinary_and_non_admin_internal_entrypoints() {
    let fixture = InstallFixture::new();
    for arguments in [
        vec!["version"],
        vec!["--internal-privileged-pty-broker", "/tmp/registration.json"],
        vec![
            "--internal-privileged-pty-controller",
            "/tmp/registration.json",
            "/tmp/generation",
        ],
        vec!["--internal-privileged-pty-child", "3"],
    ] {
        assert_activation_blocked(&fixture.run(&arguments));
    }
}

#[test]
fn pending_activation_allows_only_exact_admin_status_and_drain_dispatch() {
    let fixture = InstallFixture::new();
    let registration = fixture.missing_registration();
    for mode in [
        "--internal-privileged-pty-admin-status",
        "--internal-privileged-pty-admin-drain",
    ] {
        let output = fixture.run(&[mode, &registration]);
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("PRIVILEGED_PTY_SERVICE_UNAVAILABLE"));
        assert!(!stderr(&output).contains("INSTALLATION_ACTIVATION_INCOMPLETE"));
    }
}

#[test]
fn pending_activation_admin_dispatch_rejects_wrong_argument_counts() {
    let fixture = InstallFixture::new();
    let registration = fixture.missing_registration();
    for arguments in [
        vec!["--internal-privileged-pty-admin-status"],
        vec![
            "--internal-privileged-pty-admin-drain",
            &registration,
            "extra",
        ],
    ] {
        let output = fixture.run(&arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(!stderr(&output).contains("INSTALLATION_ACTIVATION_INCOMPLETE"));
    }
}
