//! Appearance-only preview of the first-run setup wizard (quick and custom).
//! Uses sample data; no Host, service, profile, network or browser is touched.
//! Run: cargo run --locked -p lomiremote --example setup_preview

use lomi_remote_protocol::{
    DecimalU64,
    ipc::{LocalHostName, LocalLoginPresentation, LocalRootPath, LocalStartMode},
};
use lomiremote::{
    setup::{
        HostPreflight, ServiceBinding, SetupAccount, SetupInteraction, SetupNetworkState,
        SetupProgress, SetupReview, SetupStage, ShellCandidate,
    },
    setup_view::SetupView,
};
use std::{
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn main() {
    let mut view = SetupView::new();
    view.disable_browser();
    let Ok(mode) = view.select_start_mode(LocalStartMode::Manual) else {
        return println!("Setup preview cancelled.");
    };
    let account = SetupAccount::Unix { uid: 501, gid: 20 };
    let binding = ServiceBinding {
        mode,
        account_name: "preview".to_owned(),
        account: account.clone(),
        profile_path: PathBuf::from("/preview/Library/Application Support/LomiRemote"),
        executable_path: PathBuf::from("/preview/bin/lomiremote"),
    };
    let current_directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));
    let preflight = HostPreflight {
        existing_configuration: false,
        existing_host_id: None,
        identity_pending_recovery: false,
        suggested_host_name: LocalHostName::try_from("My MacBook".to_owned()).unwrap(),
        current_directory,
        release_version: "0.1.10 (preview)".to_owned(),
        network: SetupNetworkState::Available,
        interactive_terminal: true,
    };
    // auth_generation: Some skips the storage prompts, which need release pins.
    let progress = SetupProgress {
        setup_id: "preview".to_owned(),
        stage: SetupStage::Draft,
        account_name: "preview".to_owned(),
        account: account.clone(),
        mode,
        host_id: None,
        host_name: None,
        auth_generation: Some(1),
        workspace_import_id: "preview".to_owned(),
        workspace_id: None,
        workspace_name: String::new(),
        workspace_root: String::new(),
        shell_profile_id: None,
        share_remote: false,
        share_attempted: false,
    };
    let shells = ["/bin/zsh", "/bin/bash", "/bin/sh"].map(|path| ShellCandidate {
        label: path.rsplit('/').next().unwrap().to_owned(),
        executable: PathBuf::from(path),
    });
    let Ok(choices) = view.collect_choices(&binding, &preflight, Some(&progress), &shells) else {
        return println!("Setup preview cancelled.");
    };
    let review = SetupReview {
        release_version: preflight.release_version.clone(),
        host_id: None,
        host_name: choices.host_name.clone().unwrap(),
        mode,
        account_name: binding.account_name.clone(),
        account,
        profile_path: binding.profile_path.clone(),
        workspace_name: choices.workspace_name.clone(),
        workspace_root: choices.workspace_root.clone(),
        create_missing_workspace: choices.create_missing_workspace,
        git_repository_detected: choices.workspace_root.join(".git").exists(),
        shell_name: choices.shell.name.clone(),
        shell_executable: choices.shell.executable.clone(),
        shell_args: choices.shell.args.0.clone(),
        environment_names: Vec::new(),
        storage_provider: Some("protectedFile"),
        share_remote: choices.share_remote,
        disable_existing_share: choices.disable_existing_share,
    };
    if !view.confirm_review(&review).unwrap_or(false) {
        return println!("Setup preview cancelled at review.");
    }
    if view.reveal_login_presentation() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        view.show_login_presentation(&LocalLoginPresentation {
            user_code: "DEMO-1234".to_owned().try_into().unwrap(),
            verification_url: LocalRootPath::try_from(
                "https://example.invalid/lomi-sign-in-preview".to_owned(),
            )
            .unwrap(),
            expires_at: DecimalU64(now + 600),
            next_poll_at: DecimalU64(now + 1),
        });
    }
    // Simulate approval in the browser after about five seconds.
    let approved_at = Instant::now() + Duration::from_secs(5);
    while Instant::now() < approved_at {
        if !view.wait_for_login_update().unwrap_or(false) {
            return println!("Setup preview: sign-in left for later.");
        }
    }
    drop(view);
    println!(
        "Setup complete (preview). \"{}\" is now available in the Lomi app.",
        review.workspace_name.as_str()
    );
}
