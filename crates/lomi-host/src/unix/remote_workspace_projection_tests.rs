//! Projection regressions only; no transport or authority is synthesized here.
use super::*;
use lomi_remote_protocol::{
    PaneId, RuntimeId, SessionEpoch, TabId, TerminalProfile, TerminalSessionId, WorkspaceContext,
    WorkspaceEpoch,
    rpc::{PaneState, SplitAxis, TerminalLayout, TerminalPane, TerminalTab},
};
fn context() -> WorkspaceContext {
    WorkspaceContext {
        workspace_id: WorkspaceId::from_bytes([1; 16]).unwrap(),
        workspace_epoch: WorkspaceEpoch::from_bytes([2; 16]).unwrap(),
        runtime_id: RuntimeId::from_bytes([3; 16]).unwrap(),
        runtime_generation: DecimalU64(4),
        host_access_epoch: DecimalU64(5),
        grant_revision: DecimalU64(6),
    }
}
fn state() -> WorkspaceState {
    WorkspaceState {
        context: context(),
        domain_revision: DecimalU64(7),
        name: "workspace name".to_owned().try_into().unwrap(),
        tabs: lomi_remote_protocol::rpc::BoundedList(Vec::new()),
    }
}
fn remote_context() -> WorkspaceContext {
    WorkspaceContext {
        runtime_id: RuntimeId::from_bytes([8; 16]).unwrap(),
        runtime_generation: DecimalU64(9),
        host_access_epoch: DecimalU64(10),
        grant_revision: DecimalU64(11),
        ..context()
    }
}
#[test]
fn project_empty_workspace_preserves_metadata_and_rebinds_context() {
    let local = state();
    let remote = remote_context();
    let projected = project_remote_workspace(&local, &remote).unwrap();
    assert_eq!(projected.context, remote);
    assert_eq!(projected.domain_revision, local.domain_revision);
    assert_eq!(projected.name, local.name);
    assert!(projected.tabs.0.is_empty());
    assert!(projected.validate().is_ok());
    assert!(
        !serde_json::to_string(&projected)
            .unwrap()
            .contains("local_root")
    );
}
fn pane(id: u8, context: &WorkspaceContext) -> TerminalLayout {
    TerminalLayout::Pane {
        pane: TerminalPane {
            pane_id: PaneId::from_bytes([id; 16]).unwrap(),
            session: Some(TerminalContext {
                workspace: context.clone(),
                pane_id: PaneId::from_bytes([id; 16]).unwrap(),
                session_id: TerminalSessionId::from_bytes([id + 1; 16]).unwrap(),
                session_epoch: SessionEpoch::from_bytes([id + 2; 16]).unwrap(),
                profile: TerminalProfile::ExperimentalRustGridV1,
            }),
            state: PaneState::Running,
        },
    }
}
#[test]
fn project_split_workspace_preserves_layout_and_every_session_identity() {
    let mut local = state();
    local.tabs.0.push(TerminalTab {
        tab_id: TabId::from_bytes([12; 16]).unwrap(),
        name: "tab name".to_owned().try_into().unwrap(),
        layout: TerminalLayout::Split {
            axis: SplitAxis::Horizontal,
            first: Box::new(pane(20, &local.context)),
            second: Box::new(TerminalLayout::Split {
                axis: SplitAxis::Vertical,
                first: Box::new(pane(30, &local.context)),
                second: Box::new(pane(40, &local.context)),
            }),
        },
    });
    let projected = project_remote_workspace(&local, &remote_context()).unwrap();
    assert_eq!(projected.context, remote_context());
    assert!(projected.validate().is_ok());
    // Reversing just the workspace tuple must recover the entire original DTO.
    assert_eq!(
        project_remote_workspace(&projected, &local.context).unwrap(),
        local
    );
    let encoded = serde_json::to_value(&projected).unwrap();
    assert!(encoded.get("localRoot").is_none());
}
#[test]
fn projection_rejects_changed_workspace_epoch_and_mixed_session_context() {
    let mut remote = remote_context();
    remote.workspace_epoch = WorkspaceEpoch::from_bytes([99; 16]).unwrap();
    assert!(matches!(
        project_remote_workspace(&state(), &remote),
        Err(Error::Domain(domain::Error::Stale))
    ));
    let mut local = state();
    local.tabs.0.push(TerminalTab {
        tab_id: TabId::from_bytes([12; 16]).unwrap(),
        name: "invalid mixed tuple".to_owned().try_into().unwrap(),
        layout: pane(20, &remote_context()),
    });
    assert!(matches!(
        project_remote_workspace(&local, &remote_context()),
        Err(Error::Domain(domain::Error::Stale))
    ));
}
