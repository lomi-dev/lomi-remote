//! Source coverage for durable cloud intent; these tests perform no networking.
use lomi_host_store::*;
use lomi_remote_protocol::{http::*, rpc::*, *};
use std::path::PathBuf;
use uuid::Uuid;

struct Directory(
    PathBuf,
    #[cfg(windows)] Option<lomi_platform::windows::OwnerLock>,
);
impl Directory {
    fn new() -> Self {
        #[cfg(not(windows))]
        let path = std::env::temp_dir().join(format!("lomi-cloud-publication-{}", Uuid::new_v4()));
        #[cfg(windows)]
        let path = PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
            .join(format!("lomi-cloud-publication-{}", Uuid::new_v4()));
        #[cfg(not(windows))]
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        #[cfg(not(windows))]
        builder.create(&path).unwrap();
        #[cfg(windows)]
        {
            let owner = lomi_platform::windows::OwnerLock::acquire(&path).unwrap();
            owner.prepare_database().unwrap();
            Self(path, Some(owner))
        }
        #[cfg(not(windows))]
        Self(path)
    }
    fn db(&self) -> PathBuf {
        #[cfg(windows)]
        return self.0.join("host.sqlite3");
        #[cfg(not(windows))]
        self.0.join("host.sqlite")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        #[cfg(windows)]
        drop(self.1.take());
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn install(store: &mut HostStore, generation: u64, sequence: u64) -> CloudRuntimeState {
    store.enable_authorization(generation).unwrap();
    let scope = store
        .cloud_runtime_scope(generation, "https://remote.example".into())
        .unwrap();
    let runtime = RuntimeBinding {
        runtime_id: scope.owner_runtime_id,
        runtime_generation: DecimalU64(41),
        host_access_epoch: DecimalU64(3),
    };
    store
        .compare_and_set_cloud_runtime(&scope, None, runtime, DecimalU64(sequence))
        .unwrap()
}
fn shared(store: &mut HostStore, dir: &Directory, name: &str) -> WorkspaceId {
    let path = dir.0.join(name);
    std::fs::create_dir(&path).unwrap();
    let workspace = store
        .add_project(&path, name.to_owned().try_into().unwrap())
        .unwrap()
        .state
        .context
        .workspace_id;
    store.share(workspace, 0).unwrap();
    workspace
}
fn response(intent: &HostPublicationIntent) -> PublicationResult {
    PublicationResult {
        runtime: intent.params.runtime.clone(),
        publication_seq: intent.params.publication_seq,
    }
}
fn get_response(intent: &HostPublicationIntent) -> HostRuntimeGetResult {
    HostRuntimeGetResult {
        host_id: intent.scope.host_id,
        host_access_epoch: intent.params.runtime.host_access_epoch,
        runtime_generation: intent.params.runtime.runtime_generation,
        runtime: Some(intent.params.runtime.clone()),
        publication_seq: intent.params.publication_seq,
        lease_ms: DecimalU64(0),
        freshness_ms: DecimalU64(0),
    }
}

#[test]
fn acknowledged_membership_is_exact_historical_and_shared_by_both_ack_paths() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 17);
    assert_eq!(store.acknowledged_host_publication(&state).unwrap(), None);
    let workspace = shared(&mut store, &dir, "workspace");
    let intent = store.prepare_host_publication(&state).unwrap();
    assert_eq!(store.acknowledged_host_publication(&state).unwrap(), None);
    let state = store
        .acknowledge_host_publication(&intent, &response(&intent))
        .unwrap();
    let acknowledged = HostAcknowledgedPublication {
        state: state.clone(),
        workspaces: intent.params.workspaces.clone(),
    };
    assert_eq!(
        store.acknowledged_host_publication(&state).unwrap(),
        Some(acknowledged.clone())
    );
    let terminal = running_terminal(&mut store, workspace);
    let next = store.prepare_host_publication(&state).unwrap();
    assert_eq!(store.prepare_host_publication(&state).unwrap(), next);
    assert_eq!(
        store.acknowledged_host_publication(&state).unwrap(),
        Some(acknowledged)
    );
    assert!(
        intent.params.workspaces.as_slice()[0]
            .terminals
            .as_slice()
            .is_empty()
    );
    assert_eq!(
        next.params.workspaces.as_slice()[0].terminals.as_slice()[0].session_id,
        terminal.session_id
    );
    let previous = state;
    let state = store
        .acknowledge_host_publication_from_runtime(&next, &get_response(&next))
        .unwrap();
    let acknowledged = HostAcknowledgedPublication {
        state: state.clone(),
        workspaces: next.params.workspaces.clone(),
    };
    assert_eq!(
        store.acknowledged_host_publication(&previous),
        Err(StoreError::RevisionConflict)
    );
    assert_eq!(
        store.acknowledged_host_publication(&state).unwrap(),
        Some(acknowledged.clone())
    );
    store.unshare(workspace).unwrap();
    let revoked = store.workspace(workspace).unwrap();
    assert!(!revoked.consent);
    assert_ne!(
        revoked.state.context.workspace_epoch,
        acknowledged.workspaces.as_slice()[0].workspace_epoch
    );
    assert_eq!(
        store.acknowledged_host_publication(&state).unwrap(),
        Some(acknowledged.clone())
    );
    store.share(workspace, revoked.fence).unwrap();
    assert_ne!(
        store
            .workspace(workspace)
            .unwrap()
            .state
            .context
            .workspace_epoch,
        acknowledged.workspaces.as_slice()[0].workspace_epoch
    );
    assert_eq!(
        store.acknowledged_host_publication(&state).unwrap(),
        Some(acknowledged)
    );
    store.seal_authorization();
    assert_eq!(
        store.acknowledged_host_publication(&state),
        Err(StoreError::Fenced)
    );
}

#[test]
fn acknowledged_membership_cannot_be_adopted_by_a_new_owner_or_claim() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 0);
    shared(&mut store, &dir, "workspace");
    let intent = store.prepare_host_publication(&state).unwrap();
    let state = store
        .acknowledge_host_publication(&intent, &response(&intent))
        .unwrap();
    let pending = store.prepare_host_publication(&state).unwrap();
    drop(store);
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(
        store.acknowledged_host_publication(&state),
        Err(StoreError::Fenced)
    );
    let scope = store
        .cloud_runtime_scope(0, "https://remote.example".into())
        .unwrap();
    let mut adopted = state.clone();
    adopted.scope = scope.clone();
    assert_eq!(
        store.acknowledged_host_publication(&adopted),
        Err(StoreError::RevisionConflict)
    );
    let outbox = store.pending_publications().unwrap();
    assert_eq!(
        store.invalidate_cloud_runtime(&scope, &state, None),
        Err(StoreError::RevisionConflict)
    );
    store
        .invalidate_cloud_runtime(&scope, &state, Some(&pending))
        .unwrap();
    assert_eq!(store.pending_publications().unwrap(), outbox);
    let fresh = install(&mut store, 0, 99);
    assert_eq!(store.acknowledged_host_publication(&fresh).unwrap(), None);
}

#[test]
fn acknowledged_membership_write_and_invalidation_failures_are_atomic() {
    for fault in [
        "cloud_runtime_state",
        "host_acknowledged_publication",
        "delete",
    ] {
        let dir = Directory::new();
        let store = HostStore::open(&dir.db(), Limits::default()).unwrap();
        drop(store);
        let db = rusqlite::Connection::open(dir.db()).unwrap();
        let trigger = if fault == "delete" {
            "CREATE TRIGGER fail_ack BEFORE DELETE ON metadata WHEN OLD.key='host_acknowledged_publication' BEGIN SELECT RAISE(ABORT,'synthetic ACK delete fault'); END;".to_owned()
        } else {
            format!(
                "CREATE TRIGGER fail_ack BEFORE UPDATE ON metadata WHEN NEW.key='{fault}' AND EXISTS(SELECT 1 FROM metadata WHERE key='host_acknowledged_publication') BEGIN SELECT RAISE(ABORT,'synthetic ACK update fault'); END;"
            )
        };
        db.execute_batch(&trigger).unwrap();
        drop(db);
        let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
        let state = install(&mut store, 0, 0);
        let workspace = shared(&mut store, &dir, "workspace");
        let intent = store.prepare_host_publication(&state).unwrap();
        let state = store
            .acknowledge_host_publication(&intent, &response(&intent))
            .unwrap();
        let acknowledged = store.acknowledged_host_publication(&state).unwrap();
        store.unshare(workspace).unwrap();
        let pending = store.prepare_host_publication(&state).unwrap();
        let outbox = store.pending_publications().unwrap();
        if fault == "delete" {
            assert_eq!(
                store.invalidate_cloud_runtime(&state.scope, &state, Some(&pending)),
                Err(StoreError::Storage)
            );
        } else {
            assert_eq!(
                store.acknowledge_host_publication(&pending, &response(&pending)),
                Err(StoreError::Storage)
            );
        }
        assert_eq!(
            store.acknowledged_host_publication(&state).unwrap(),
            acknowledged
        );
        assert_eq!(
            store.cloud_runtime_state(&state.scope).unwrap(),
            Some(state)
        );
        assert_eq!(store.pending_host_publication().unwrap(), Some(pending));
        assert_eq!(store.pending_publications().unwrap(), outbox);
    }
}

#[test]
fn malformed_or_mixed_acknowledged_records_fail_closed() {
    for corruption in 0..13 {
        let dir = Directory::new();
        let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
        let state = install(&mut store, 0, 0);
        shared(&mut store, &dir, "workspace");
        let intent = store.prepare_host_publication(&state).unwrap();
        let state = store
            .acknowledge_host_publication(&intent, &response(&intent))
            .unwrap();
        let acknowledged = store
            .acknowledged_host_publication(&state)
            .unwrap()
            .unwrap();
        drop(store);
        let db = rusqlite::Connection::open(dir.db()).unwrap();
        let mut wire = serde_json::json!({"version":1,"value":acknowledged});
        match corruption {
            0 => wire["version"] = serde_json::json!(2),
            1 => wire["unexpected"] = serde_json::json!(true),
            2 => wire["value"]["unexpected"] = serde_json::json!(true),
            3 => wire["value"]["state"]["acknowledged_publication_seq"] = serde_json::json!("2"),
            4 => {
                wire["value"]["state"]["scope"]["remote_api_origin"] =
                    serde_json::json!("https://another.example")
            }
            5 => {
                wire["value"]["state"]["server_runtime"]["hostAccessEpoch"] = serde_json::json!("9")
            }
            6 => wire["value"]["state"]["acknowledged_publication_seq"] = serde_json::json!("0"),
            7 => {
                db.execute("DELETE FROM metadata WHERE key='cloud_runtime_state'", [])
                    .unwrap();
            }
            8 => {
                let workspace = wire["value"]["workspaces"][0].clone();
                wire["value"]["workspaces"] = serde_json::json!(vec![workspace; 257]);
            }
            9 => wire["value"]["workspaces"][0]["unexpected"] = serde_json::json!(true),
            10 => {
                wire["value"]["state"]["server_runtime"]["runtimeGeneration"] =
                    serde_json::json!("0")
            }
            _ => (),
        }
        let text = match corruption {
            11 => " ".repeat(2 * 1024 * 1024 + 1),
            12 => "{bad".to_owned(),
            _ => wire.to_string(),
        };
        db.execute(
            "UPDATE metadata SET value=?1 WHERE key='host_acknowledged_publication'",
            [text],
        )
        .unwrap();
        drop(db);
        let store = HostStore::open(&dir.db(), Limits::default()).unwrap();
        let mut expected = state;
        expected.scope = store
            .cloud_runtime_scope(0, "https://remote.example".into())
            .unwrap();
        assert_eq!(
            store.acknowledged_host_publication(&expected),
            Err(StoreError::Storage),
            "corruption {corruption}"
        );
        assert_eq!(store.pending_host_publication(), Err(StoreError::Storage));
    }
}

fn running_terminal(store: &mut HostStore, workspace: WorkspaceId) -> TerminalContext {
    running_terminal_with_layout(store, workspace, false)
}
fn running_terminal_with_layout(
    store: &mut HostStore,
    workspace: WorkspaceId,
    nested: bool,
) -> TerminalContext {
    let binding = OperationBinding {
        rights: StoredOperationRights::new(
            OperationId::from_bytes([1; 16]).unwrap(),
            ConsumerAuthorizationId::from_bytes([2; 16]).unwrap(),
            workspace,
            Method::TerminalCreate,
            CapabilitySet::control_with_workspace_tools(),
            false,
        )
        .unwrap(),
        parameter_hash: parameter_hash(&(Method::TerminalCreate, workspace)).unwrap(),
    };
    let mut state = store.workspace(workspace).unwrap().state;
    store
        .admit_external(&binding, state.domain_revision)
        .unwrap();
    let permit = store.start_external(&binding).unwrap();
    state.domain_revision = DecimalU64(state.domain_revision.0 + 1);
    let terminal = TerminalContext {
        workspace: state.context.clone(),
        pane_id: PaneId::from_bytes([3; 16]).unwrap(),
        session_id: TerminalSessionId::from_bytes([4; 16]).unwrap(),
        session_epoch: SessionEpoch::from_bytes([5; 16]).unwrap(),
        profile: TerminalProfile::ExperimentalRustGridV1,
    };
    let mut layout = TerminalLayout::Pane {
        pane: TerminalPane {
            pane_id: terminal.pane_id,
            session: Some(terminal.clone()),
            state: PaneState::Running,
        },
    };
    if nested {
        for byte in [7, 8] {
            layout = TerminalLayout::Split {
                axis: SplitAxis::Horizontal,
                first: Box::new(TerminalLayout::Pane {
                    pane: TerminalPane {
                        pane_id: PaneId::from_bytes([byte; 16]).unwrap(),
                        session: None,
                        state: PaneState::Stopped,
                    },
                }),
                second: Box::new(layout),
            };
        }
    }
    state.tabs = BoundedList(vec![TerminalTab {
        tab_id: TabId::from_bytes([6; 16]).unwrap(),
        name: "private-terminal-title".to_owned().try_into().unwrap(),
        layout,
    }]);
    store
        .complete_external(
            &permit,
            OperationState::Succeeded,
            Effect::Committed,
            Some(OperationResult::Terminal {
                domain_revision: state.domain_revision,
                pane_id: terminal.pane_id,
                session_id: terminal.session_id,
                session_epoch: terminal.session_epoch,
            }),
            Some(state),
        )
        .unwrap();
    terminal
}

#[test]
fn consent_epoch_and_fence_roll_back_with_event_or_outbox_failure() {
    for sharing in [false, true] {
        for table in ["events", "outbox"] {
            let dir = Directory::new();
            let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
            let workspace = store
                .add_project(&dir.0, "workspace".to_owned().try_into().unwrap())
                .unwrap()
                .state
                .context
                .workspace_id;
            if !sharing {
                store.share(workspace, 0).unwrap();
            }
            let fence = store.workspace(workspace).unwrap().fence;
            drop(store);
            let db = rusqlite::Connection::open(dir.db()).unwrap();
            // Recovery may requeue the existing fence; fail only the attempted
            // consent transition, after its project and event writes.
            let condition = if table == "outbox" {
                format!("WHEN json_extract(NEW.publication,'$.fence') > {fence}")
            } else {
                String::new()
            };
            db.execute_batch(&format!("CREATE TRIGGER fail_consent BEFORE INSERT ON {table} {condition} BEGIN SELECT RAISE(ABORT,'synthetic consent fault'); END;")).unwrap();
            drop(db);
            let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
            let before = store.workspace(workspace).unwrap();
            let outbox = store.pending_publications().unwrap();
            let events = store.events_after(0).unwrap();
            let result = if sharing {
                store.share(workspace, before.fence)
            } else {
                store.unshare(workspace)
            };
            assert_eq!(result, Err(StoreError::Storage));
            let after = store.workspace(workspace).unwrap();
            assert_eq!(after.state, before.state);
            assert_eq!(after.fence, before.fence);
            assert_eq!(after.consent, before.consent);
            assert_eq!(store.pending_publications().unwrap(), outbox);
            let after_events = store.events_after(0).unwrap();
            assert_eq!(after_events.low_watermark, events.low_watermark);
            assert_eq!(after_events.resync_required, events.resync_required);
            let event_rows = |page: EventPage| {
                page.events
                    .into_iter()
                    .map(|event| {
                        (
                            event.sequence,
                            event.workspace_id,
                            event.operation_id,
                            event.domain_revision,
                        )
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(event_rows(after_events), event_rows(events));
            drop(store);
            let db = rusqlite::Connection::open(dir.db()).unwrap();
            db.execute_batch("DROP TRIGGER fail_consent").unwrap();
            drop(db);
            let store = HostStore::open(&dir.db(), Limits::default()).unwrap();
            let after = store.workspace(workspace).unwrap();
            assert_eq!(
                after.state.context.workspace_epoch,
                before.state.context.workspace_epoch
            );
            assert_eq!(after.fence, before.fence);
            assert_eq!(after.consent, before.consent);
        }
    }
}

#[test]
fn coalesced_consent_boundaries_publish_a_new_epoch_and_preserve_new_tokens() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 0);
    let workspace = shared(&mut store, &dir, "workspace");
    let first = store
        .workspace(workspace)
        .unwrap()
        .state
        .context
        .workspace_epoch;
    let old_intent = store.prepare_host_publication(&state).unwrap();
    assert_eq!(store.unshare(workspace).unwrap(), 2);
    let revoked = store.workspace(workspace).unwrap();
    assert!(!revoked.consent);
    assert_ne!(revoked.state.context.workspace_epoch, first);
    assert_eq!(store.share(workspace, 2).unwrap(), 3);
    let renewed = store.workspace(workspace).unwrap();
    let epoch = renewed.state.context.workspace_epoch;
    assert!(renewed.consent);
    assert_ne!(epoch, first);
    assert_ne!(epoch, revoked.state.context.workspace_epoch);
    // Repeating an already granted share preserves its epoch and fence CAS.
    assert_eq!(store.share(workspace, 2), Err(StoreError::Fenced));
    assert_eq!(store.share(workspace, 3).unwrap(), 4);
    assert_eq!(
        store
            .workspace(workspace)
            .unwrap()
            .state
            .context
            .workspace_epoch,
        epoch
    );
    let outbox = store.pending_publications().unwrap();
    assert_eq!(outbox.len(), 1);
    assert!(outbox[0].enabled);
    let state = store
        .acknowledge_host_publication(&old_intent, &response(&old_intent))
        .unwrap();
    assert_eq!(store.pending_publications().unwrap(), outbox);
    let current_intent = store.prepare_host_publication(&state).unwrap();
    assert_eq!(
        current_intent.params.workspaces.as_slice()[0].workspace_epoch,
        epoch
    );
    drop(store);
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(
        store
            .workspace(workspace)
            .unwrap()
            .state
            .context
            .workspace_epoch,
        epoch
    );
    let reopened_outbox = store.pending_publications().unwrap();
    assert_eq!(reopened_outbox.len(), 1);
    assert!(reopened_outbox[0].enabled);
    assert_eq!(reopened_outbox[0].fence, 4);
    assert_eq!(
        store.acknowledge_host_publication(&old_intent, &response(&old_intent)),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.acknowledge_host_publication(&current_intent, &response(&current_intent)),
        Err(StoreError::Fenced)
    );
    assert_eq!(store.pending_publications().unwrap(), reopened_outbox);
}

#[test]
fn nested_running_sessions_follow_consent_epochs_without_restarting() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 0);
    let workspace = shared(&mut store, &dir, "workspace");
    let terminal = running_terminal_with_layout(&mut store, workspace, true);
    for shared in [false, true] {
        if shared {
            store.share(workspace, 2).unwrap();
        } else {
            store.unshare(workspace).unwrap();
        }
        let project = store.workspace(workspace).unwrap();
        project.state.validate().unwrap();
        assert_eq!(project.consent, shared);
        assert_ne!(
            project.state.context.workspace_epoch,
            terminal.workspace.workspace_epoch
        );
        let mut layout = &project.state.tabs.0[0].layout;
        while let TerminalLayout::Split { second, .. } = layout {
            layout = second;
        }
        let TerminalLayout::Pane { pane } = layout else {
            unreachable!()
        };
        let current = pane.session.as_ref().unwrap();
        assert_eq!(current.workspace, project.state.context);
        assert_eq!(current.session_id, terminal.session_id);
        assert_eq!(current.session_epoch, terminal.session_epoch);
        assert_eq!(current.pane_id, terminal.pane_id);
        assert_eq!(pane.state, PaneState::Running);
        assert_eq!(store.record_terminal_exit(&terminal), Ok(false));
    }
    let intent = store.prepare_host_publication(&state).unwrap();
    let published = &intent.params.workspaces.as_slice()[0];
    assert_eq!(
        published.workspace_epoch,
        store
            .workspace(workspace)
            .unwrap()
            .state
            .context
            .workspace_epoch
    );
    assert_eq!(
        published.terminals.as_slice()[0].session_id,
        terminal.session_id
    );
    assert_eq!(
        published.terminals.as_slice()[0].session_epoch,
        terminal.session_epoch
    );
}

#[test]
fn freeze_empty_workspace_then_unshare_preserves_the_new_token() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 0);
    let workspace = shared(&mut store, &dir, "private-title");
    let intent = store.prepare_host_publication(&state).unwrap();
    assert_eq!(intent.params.workspaces.as_slice().len(), 1);
    assert!(
        intent.params.workspaces.as_slice()[0]
            .terminals
            .as_slice()
            .is_empty()
    );
    let wire = serde_json::to_string(&intent).unwrap();
    assert!(!wire.contains("private-title"));
    assert!(!wire.contains(dir.0.to_str().unwrap()));
    store.unshare(workspace).unwrap();
    let tombstone = store.pending_publications().unwrap();
    assert_ne!(tombstone, intent.workspace_publications);
    assert_eq!(store.prepare_host_publication(&state).unwrap(), intent);
    let acknowledged = store
        .acknowledge_host_publication(&intent, &response(&intent))
        .unwrap();
    assert_eq!(store.pending_publications().unwrap(), tombstone);
    assert_eq!(acknowledged.acknowledged_publication_seq, DecimalU64(1));
    let next = store.prepare_host_publication(&acknowledged).unwrap();
    assert!(next.params.workspaces.as_slice().is_empty());
    assert_eq!(next.workspace_publications, tombstone);
    store
        .acknowledge_host_publication(&next, &response(&next))
        .unwrap();
    assert!(store.pending_publications().unwrap().is_empty());
    assert_eq!(
        store.acknowledge_host_publication(&next, &response(&next)),
        Err(StoreError::RevisionConflict)
    );
}

#[test]
fn reopening_retains_evidence_without_adopting_predecessor_runtime() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let old = install(&mut store, 0, 0);
    let workspace = shared(&mut store, &dir, "workspace");
    running_terminal(&mut store, workspace);
    let intent = store.prepare_host_publication(&old).unwrap();
    assert_eq!(
        intent.params.workspaces.as_slice()[0]
            .terminals
            .as_slice()
            .len(),
        1
    );
    drop(store);
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(
        store.pending_host_publication().unwrap(),
        Some(intent.clone())
    );
    assert_eq!(
        store.acknowledge_host_publication(&intent, &response(&intent)),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.prepare_host_publication(&old),
        Err(StoreError::Fenced)
    );
    let scope = store
        .cloud_runtime_scope(0, "https://remote.example".into())
        .unwrap();
    assert_ne!(scope.owner_runtime_id, old.scope.owner_runtime_id);
    assert_eq!(store.cloud_runtime_state(&scope), Err(StoreError::Fenced));
    assert_eq!(
        store.cloud_runtime_reconciliation_state(&scope).unwrap(),
        Some(old.clone())
    );
    assert_eq!(
        store.compare_and_set_cloud_runtime(
            &scope,
            Some(&old),
            old.server_runtime.clone(),
            DecimalU64(0)
        ),
        Err(StoreError::Invalid)
    );
    store
        .invalidate_cloud_runtime(&scope, &old, Some(&intent))
        .unwrap();
    assert!(!store.pending_publications().unwrap().is_empty());
    let current = install(&mut store, 0, 0);
    assert_eq!(current.server_runtime.runtime_id, scope.owner_runtime_id);
    assert!(
        store
            .prepare_host_publication(&current)
            .unwrap()
            .params
            .workspaces
            .as_slice()[0]
            .terminals
            .as_slice()
            .is_empty()
    );
}

#[test]
fn exit_after_prepare_keeps_the_new_token_and_next_snapshot_omits_the_session() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 0);
    let workspace = shared(&mut store, &dir, "workspace");
    let terminal = running_terminal(&mut store, workspace);
    let intent = store.prepare_host_publication(&state).unwrap();
    assert_eq!(
        intent.params.workspaces.as_slice()[0].terminals.as_slice()[0].session_id,
        terminal.session_id
    );
    assert!(
        !serde_json::to_string(&intent)
            .unwrap()
            .contains("private-terminal-title")
    );
    assert!(store.record_terminal_exit(&terminal).unwrap());
    let outbox = store.pending_publications().unwrap();
    let state = store
        .acknowledge_host_publication(&intent, &response(&intent))
        .unwrap();
    assert_eq!(store.pending_publications().unwrap(), outbox);
    let next = store.prepare_host_publication(&state).unwrap();
    assert!(
        next.params.workspaces.as_slice()[0]
            .terminals
            .as_slice()
            .is_empty()
    );
}

#[test]
fn scope_and_exact_intent_checks_leave_the_transaction_unchanged() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 0);
    shared(&mut store, &dir, "workspace");
    let intent = store.prepare_host_publication(&state).unwrap();
    let outbox = store.pending_publications().unwrap();
    let mut wrong_origin = intent.clone();
    wrong_origin.scope.remote_api_origin = "https://another.example".into();
    assert_eq!(
        store.acknowledge_host_publication(&wrong_origin, &response(&wrong_origin)),
        Err(StoreError::RevisionConflict)
    );
    let mut wrong_token = intent.clone();
    wrong_token.token = Uuid::new_v4().to_string();
    assert_eq!(
        store.acknowledge_host_publication(&wrong_token, &response(&wrong_token)),
        Err(StoreError::RevisionConflict)
    );
    let mut wrong_auth = intent.clone();
    wrong_auth.scope.authorization_generation += 1;
    assert_eq!(
        store.acknowledge_host_publication(&wrong_auth, &response(&wrong_auth)),
        Err(StoreError::Fenced)
    );
    let mut wrong = response(&intent);
    wrong.runtime.host_access_epoch = DecimalU64(4);
    assert_eq!(
        store.acknowledge_host_publication(&intent, &wrong),
        Err(StoreError::Fenced)
    );
    wrong = response(&intent);
    wrong.runtime.runtime_id = RuntimeId::from_bytes(*Uuid::new_v4().as_bytes()).unwrap();
    assert_eq!(
        store.acknowledge_host_publication(&intent, &wrong),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.invalidate_cloud_runtime(&state.scope, &state, Some(&wrong_token)),
        Err(StoreError::RevisionConflict)
    );
    assert_eq!(store.pending_publications().unwrap(), outbox);
    assert_eq!(
        store.cloud_runtime_state(&state.scope).unwrap(),
        Some(state)
    );
    assert_eq!(store.pending_host_publication().unwrap(), Some(intent));
}

#[test]
fn logout_and_process_local_seal_fence_acknowledgements() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 0);
    shared(&mut store, &dir, "workspace");
    let intent = store.prepare_host_publication(&state).unwrap();
    store.seal_authorization();
    assert_eq!(
        store.acknowledge_host_publication(&intent, &response(&intent)),
        Err(StoreError::Fenced)
    );
    store.enable_authorization(0).unwrap();
    let auth = store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    assert_eq!(
        store.acknowledge_host_publication(&intent, &response(&intent)),
        Err(StoreError::Fenced)
    );
    store
        .acknowledge_authorization_revoke(auth.generation)
        .unwrap();
    store.enable_authorization(auth.generation).unwrap();
    let current = store
        .cloud_runtime_scope(auth.generation, "https://remote.example".into())
        .unwrap();
    let outbox = store.pending_publications().unwrap();
    store
        .invalidate_cloud_runtime(&current, &state, Some(&intent))
        .unwrap();
    assert_eq!(store.pending_publications().unwrap(), outbox);
}

#[test]
fn lost_put_accepts_only_exact_get_sequence_and_binding() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 7);
    let intent = store.prepare_host_publication(&state).unwrap();
    let exact = get_response(&intent);
    for sequence in [7, 9] {
        let mut wrong = exact.clone();
        wrong.publication_seq = DecimalU64(sequence);
        assert_eq!(
            store.acknowledge_host_publication_from_runtime(&intent, &wrong),
            Err(StoreError::Fenced)
        );
    }
    let mut wrong = exact.clone();
    wrong.runtime_generation = DecimalU64(42);
    assert_eq!(
        store.acknowledge_host_publication_from_runtime(&intent, &wrong),
        Err(StoreError::Fenced)
    );
    let mut wrong = exact.clone();
    wrong.runtime = None;
    assert_eq!(
        store.acknowledge_host_publication_from_runtime(&intent, &wrong),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store
            .acknowledge_host_publication_from_runtime(&intent, &exact)
            .unwrap()
            .acknowledged_publication_seq,
        DecimalU64(8)
    );
}

#[test]
fn sequence_overflow_and_binding_cas_fail_without_creating_intent() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, i64::MAX as u64);
    assert_eq!(
        store.prepare_host_publication(&state),
        Err(StoreError::ResourceExhausted)
    );
    assert!(store.pending_host_publication().unwrap().is_none());
    assert_eq!(
        store.compare_and_set_cloud_runtime(
            &state.scope,
            None,
            state.server_runtime.clone(),
            DecimalU64(0)
        ),
        Err(StoreError::RevisionConflict)
    );
    assert_eq!(
        store.cloud_runtime_state(&state.scope).unwrap(),
        Some(state)
    );
}

#[test]
fn removal_is_excluded_but_its_outbox_token_is_captured() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 0);
    let workspace = shared(&mut store, &dir, "removed");
    store.remove_project(workspace).unwrap();
    let intent = store.prepare_host_publication(&state).unwrap();
    assert!(intent.params.workspaces.as_slice().is_empty());
    assert_eq!(intent.workspace_publications.len(), 1);
    assert!(!intent.workspace_publications[0].enabled);
    store
        .acknowledge_host_publication(&intent, &response(&intent))
        .unwrap();
    assert!(store.pending_publications().unwrap().is_empty());
}

#[test]
fn unknown_version_unknown_fields_and_mismatched_records_fail_closed() {
    for corruption in 0..4 {
        let dir = Directory::new();
        let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
        let state = install(&mut store, 0, 0);
        let intent = store.prepare_host_publication(&state).unwrap();
        drop(store);
        let db = rusqlite::Connection::open(dir.db()).unwrap();
        let wire = match corruption {
            0 => "{bad".to_owned(),
            1 => serde_json::json!({"version": 99, "value": intent}).to_string(),
            2 => serde_json::json!({"version": 1, "value": intent, "unexpected": true}).to_string(),
            _ => {
                let mut changed = intent;
                changed.params.expected_publication_seq = DecimalU64(2);
                changed.params.publication_seq = DecimalU64(3);
                serde_json::json!({"version": 1, "value": changed}).to_string()
            }
        };
        db.execute(
            "UPDATE metadata SET value=?1 WHERE key='host_publication_intent'",
            [wire],
        )
        .unwrap();
        drop(db);
        let store = HostStore::open(&dir.db(), Limits::default()).unwrap();
        assert_eq!(store.pending_host_publication(), Err(StoreError::Storage));
    }
}

#[test]
fn ack_storage_failure_rolls_back_sequence_and_all_token_deletes() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let state = install(&mut store, 0, 0);
    shared(&mut store, &dir, "workspace");
    let intent = store.prepare_host_publication(&state).unwrap();
    drop(store);
    // Install the fault while closed, then create a fresh current-owner intent.
    let db = rusqlite::Connection::open(dir.db()).unwrap();
    db.execute_batch("CREATE TRIGGER fail_cloud_ack BEFORE UPDATE ON metadata WHEN NEW.key='cloud_runtime_state' BEGIN SELECT RAISE(ABORT,'synthetic ACK fault'); END;").unwrap();
    drop(db);
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let scope = store
        .cloud_runtime_scope(0, "https://remote.example".into())
        .unwrap();
    store
        .invalidate_cloud_runtime(&scope, &state, Some(&intent))
        .unwrap();
    let state = install(&mut store, 0, 0);
    let intent = store.prepare_host_publication(&state).unwrap();
    let outbox = store.pending_publications().unwrap();
    assert_eq!(
        store.acknowledge_host_publication(&intent, &response(&intent)),
        Err(StoreError::Storage)
    );
    assert_eq!(store.pending_publications().unwrap(), outbox);
    assert_eq!(store.pending_host_publication().unwrap(), Some(intent));
    assert_eq!(
        store.cloud_runtime_state(&state.scope).unwrap(),
        Some(state)
    );
}
