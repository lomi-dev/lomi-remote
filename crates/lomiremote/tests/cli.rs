use std::process::{Command, Stdio};
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lomiremote"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}
fn no_escapes(bytes: &[u8]) {
    assert!(!bytes.contains(&0x1b));
}
#[test]
fn no_tty_no_command_returns_plain_help_on_stderr() {
    let output = cli(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(stderr.contains("Usage: lomiremote"));
    no_escapes(&output.stderr);
}
#[test]
fn help_and_version_are_redirectable_without_host_or_terminal() {
    for args in [&["--help"][..], &["--version"][..], &["version"][..]] {
        let output = cli(args);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8_lossy(&output.stdout).contains("lomiremote"));
        no_escapes(&output.stdout);
    }
}
#[test]
#[cfg(unix)]
fn json_diagnostics_remain_parseable_when_daemon_is_absent() {
    let path = std::env::temp_dir().join(format!("lomi-cli-absent-profile-{}", std::process::id()));
    assert!(!path.exists());
    for action in ["status", "doctor"] {
        let output = cli(&["--profile-dir", path.to_str().unwrap(), action, "--json"]);
        assert_eq!(output.status.code(), Some(4));
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["version"]["major"], 1);
        assert_eq!(json["error"]["code"], "DAEMON_UNAVAILABLE");
        no_escapes(&output.stdout);
        no_escapes(&output.stderr);
    }
    assert!(
        !path.exists(),
        "reading diagnostics must not create a profile"
    );
}
#[test]
fn removal_requires_explicit_confirmation_before_connecting() {
    let output = cli(&[
        "workspace",
        "remove",
        "11111111-1111-4111-8111-111111111111",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("CONFIRMATION_REQUIRED"));
}
#[test]
fn daemon_stop_requires_confirmation_before_contacting_host() {
    let output = cli(&["daemon", "stop"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("CONFIRMATION_REQUIRED"));
}
#[test]
fn noninteractive_setup_does_not_claim_configuration_was_applied() {
    let output = cli(&["setup", "--non-interactive"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("UNSUPPORTED_LOCAL_OPERATION"));
}

#[test]
fn arbitrary_commands_and_remote_upload_arguments_are_rejected() {
    for args in [
        &[
            "terminal",
            "create",
            "--workspace",
            "id",
            "--profile",
            "default",
            "--command",
            "sh",
        ][..],
        &[
            "workspace",
            "add",
            "--name",
            "x",
            "--path",
            "/tmp",
            "--content",
            "secret",
        ][..],
    ] {
        let output = cli(args);
        assert_eq!(output.status.code(), Some(2));
        no_escapes(&output.stderr);
    }
}
#[test]
fn terminal_close_restart_and_attach_reject_unconfirmed_or_noninteractive_actions() {
    let id = "11111111-1111-4111-8111-111111111111";
    for action in ["close", "restart"] {
        let output = cli(&[
            "terminal",
            action,
            "--workspace",
            id,
            "--pane",
            id,
            "--json",
        ]);
        assert_eq!(output.status.code(), Some(2));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["error"]["code"], "CONFIRMATION_REQUIRED");
        assert!(value["operationId"].is_null());
        no_escapes(&output.stdout);
    }
    let output = cli(&["terminal", "attach", "--workspace", id, "--pane", id]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("INTERACTIVE_TERMINAL_REQUIRED"));
    no_escapes(&output.stderr);
}

#[test]
fn service_install_requires_explicit_mode_and_account() {
    for args in [
        vec!["service", "install"],
        vec!["service", "install", "--mode", "login"],
        vec!["service", "install", "--account", "alice"],
        vec![
            "service",
            "install",
            "--mode",
            "system",
            "--account",
            "alice",
        ],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        no_escapes(&output.stderr);
    }
}
#[test]
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn service_adapter_does_not_claim_support_on_unimplemented_platforms() {
    let output = cli(&["service", "status"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("SERVICE_ADAPTER_UNIMPLEMENTED_ON_THIS_PLATFORM")
    );
}

#[test]
#[cfg(target_os = "macos")]
fn macos_service_rejects_boot_and_foreign_account_before_profile_effects() {
    let profile =
        std::env::temp_dir().join(format!("lomi-service-selection-{}", uuid::Uuid::new_v4()));
    assert!(!profile.exists());
    for (mode, account) in [
        ("boot", "unused"),
        ("login", "lomi-nonexistent-service-account-1cc2c0f4"),
    ] {
        let output = cli(&[
            "--profile-dir",
            profile.to_str().unwrap(),
            "service",
            "install",
            "--mode",
            mode,
            "--account",
            account,
        ]);
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("SERVICE_ADAPTER_UNIMPLEMENTED_FOR_MODE_OR_ACCOUNT")
        );
        no_escapes(&output.stderr);
        assert!(!profile.exists());
    }
}

#[test]
#[cfg(unix)]
fn login_diagnostics_are_json_and_setup_and_logout_require_intent() {
    let path = std::env::temp_dir().join(format!("lomi-cli-auth-absent-{}", std::process::id()));
    assert!(!path.exists());
    for args in [
        vec!["login", "--json"],
        vec!["login", "status", "--json"],
        vec!["login", "code", "--json"],
    ] {
        let mut command = vec!["--profile-dir", path.to_str().unwrap()];
        command.extend(args);
        let output = cli(&command);
        assert_eq!(output.status.code(), Some(4));
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["error"]["code"], "DAEMON_UNAVAILABLE");
    }
    let output = cli(&["--profile-dir", path.to_str().unwrap(), "logout", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["error"]["code"], "CONFIRMATION_REQUIRED");
    let output = cli(&[
        "--profile-dir",
        path.to_str().unwrap(),
        "auth",
        "configure",
        "--origin",
        "https://identity.example",
        "--client-id",
        "host",
        "--provider",
        "protected-file",
        "--confirm",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["error"]["code"], "INVALID_ARGUMENT");
}
