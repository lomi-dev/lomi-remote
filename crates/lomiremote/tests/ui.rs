use lomi_remote_protocol::{
    HostId, RuntimeId, WorkspaceId,
    ipc::{LocalProjectName, LocalSharing, LocalStatus, LocalWorkspaceSummary},
};
use lomiremote::ui::{Dashboard, safe_label};
use ratatui::{Terminal, backend::TestBackend};
const ID: &str = "11111111-1111-4111-8111-111111111111";
fn dashboard() -> Dashboard {
    Dashboard {
        status: Some(LocalStatus {
            host_id: HostId::try_from(ID.to_owned()).unwrap(),
            runtime_id: RuntimeId::try_from(ID.to_owned()).unwrap(),
            sharing: LocalSharing::Disabled,
        }),
        workspaces: vec![LocalWorkspaceSummary {
            workspace_id: WorkspaceId::try_from(ID.to_owned()).unwrap(),
            name: LocalProjectName::try_from("api-service".to_owned()).unwrap(),
            sharing: LocalSharing::Disabled,
        }],
        ..Dashboard::default()
    }
}
#[test]
fn labels_replace_every_terminal_control_and_bound_display_length() {
    let label = safe_label("bad\x1b]52;data\x07\n\r\t\u{7f}\u{85}title");
    assert!(!label.chars().any(char::is_control));
    assert!(label.contains("title"));
    assert!(label.contains('�'));
    assert_eq!(safe_label(&"é".repeat(200)).chars().count(), 120);
}
#[test]
fn dashboard_is_readable_and_keyboard_controls_fit_80_by_24() {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| dashboard().draw(frame)).unwrap();
    let buffer = terminal.backend().buffer();
    let snapshot = buffer
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert_eq!(buffer.area.width, 80);
    assert_eq!(buffer.area.height, 24);
    let lines = buffer
        .content
        .chunks(80)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>() + "\n")
        .collect::<String>();
    if std::env::var_os("LOMI_UPDATE_UI_SNAPSHOTS").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/snapshots/dashboard80x24.txt"
            ),
            &lines,
        )
        .unwrap();
        return;
    }
    assert_eq!(lines, include_str!("snapshots/dashboard80x24.txt"));

    for expected in [
        "Lomi Remote",
        "Local IPC connected",
        "api-service",
        "Local host",
        "Workspaces",
        "[q] close",
    ] {
        assert!(
            snapshot.contains(expected),
            "missing {expected}: {snapshot}"
        );
    }
    assert!(!snapshot.contains('\x1b'));
    // The host context and selected workspace must both fit, without dropping
    // the independent-host lifecycle message from the keyboard help screen.
    let mut state = dashboard();
    state.help = true;
    terminal.draw(|frame| state.draw(frame)).unwrap();
    let snapshot = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(snapshot.contains("host keeps running"));
    assert!(snapshot.contains("Ctrl-C"));
}

#[test]
fn setup_draft_names_the_start_plan_without_claiming_it_was_applied() {
    use lomi_remote_protocol::ipc::LocalStartMode;
    use lomiremote::ui::SetupDraft;
    for (mode, label) in [
        (LocalStartMode::Manual, "Manual start"),
        (LocalStartMode::Login, "After OS login"),
        (LocalStartMode::Boot, "At OS boot"),
    ] {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut state = dashboard();
        state.setup_draft = Some(SetupDraft {
            start_mode: mode,
            saved_start_mode: Some(mode),
        });
        terminal.draw(|frame| state.draw(frame)).unwrap();
        let snapshot = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(snapshot.contains(label));
        assert!(snapshot.contains("Saved preference"));
        assert!(snapshot.contains("does not install"));
    }
}
