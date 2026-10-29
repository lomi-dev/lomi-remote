//! Private SQLite fixtures only. No crypto authority or networking is claimed.
use lomi_host_store::*;
use lomi_remote_protocol::{rpc::*, *};
use std::path::{Path, PathBuf};
use uuid::Uuid;

struct Directory(
    PathBuf,
    #[cfg(windows)] Option<lomi_platform::windows::OwnerLock>,
);
impl Directory {
    fn new() -> Self {
        #[cfg(not(windows))]
        let path = std::env::temp_dir().join(format!("lomi-channel-{}", Uuid::new_v4()));
        #[cfg(windows)]
        let path = PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
            .join(format!("lomi-channel-{}", Uuid::new_v4()));
        #[cfg(not(windows))]
        {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&path).unwrap();
            Self(path)
        }
        #[cfg(windows)]
        {
            let owner = lomi_platform::windows::OwnerLock::acquire(&path).unwrap();
            owner.prepare_database().unwrap();
            Self(path, Some(owner))
        }
    }
    fn db(&self) -> PathBuf {
        #[cfg(windows)]
        {
            self.0.join("host.sqlite3")
        }
        #[cfg(not(windows))]
        {
            self.0.join("host.sqlite")
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        #[cfg(windows)]
        drop(self.1.take());
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn id(n: usize) -> [u8; 16] {
    (n as u128 + 1).to_be_bytes()
}
fn install(store: &mut HostStore) -> CloudRuntimeState {
    store.enable_authorization(0).unwrap();
    let scope = store
        .cloud_runtime_scope(0, "https://remote.example".into())
        .unwrap();
    if let Some(old) = store.cloud_runtime_reconciliation_state(&scope).unwrap() {
        store.invalidate_cloud_runtime(&scope, &old, None).unwrap();
    }
    store
        .compare_and_set_cloud_runtime(
            &scope,
            None,
            RuntimeBinding {
                runtime_id: scope.owner_runtime_id,
                runtime_generation: DecimalU64(41),
                host_access_epoch: DecimalU64(3),
            },
            DecimalU64(0),
        )
        .unwrap()
}
fn workspace(store: &mut HostStore, root: &Path) -> WorkspaceId {
    let project = store
        .add_project(root, "private-project-title".to_owned().try_into().unwrap())
        .unwrap();
    store.share(project.state.context.workspace_id, 0).unwrap();
    project.state.context.workspace_id
}
fn proof_identity(cbor: &str) -> EnrollmentProof {
    EnrollmentProof {
        canonical_cbor: cbor.to_owned().try_into().unwrap(),
        signature: "11".repeat(64).try_into().unwrap(),
    }
}
fn preparation(
    store: &HostStore,
    state: &CloudRuntimeState,
    workspace: WorkspaceId,
    n: usize,
    approve: bool,
) -> PairingDecisionPreparation {
    let local = store.workspace(workspace).unwrap();
    let identities = PeerIdentities {
        host: proof_identity("01"),
        consumer: proof_identity("02"),
        host_fingerprint: "12".repeat(32).try_into().unwrap(),
        consumer_fingerprint: "13".repeat(32).try_into().unwrap(),
    };
    let authority = CurrentAuthorityBinding {
        host_authorization_id: HostAuthorizationId::from_bytes(id(4)).unwrap(),
        consumer_authorization_id: ConsumerAuthorizationId::from_bytes(id(5)).unwrap(),
        account_session_id: "synthetic-session-id".to_owned().try_into().unwrap(),
        access_epoch: state.server_runtime.host_access_epoch,
        grant_revision: DecimalU64(1),
        workspace_epoch: local.state.context.workspace_epoch,
        runtime_id: state.server_runtime.runtime_id,
        runtime_generation: state.server_runtime.runtime_generation,
        terminal_membership: None,
    };
    PairingDecisionPreparation {
        scope: CloudPairingScope {
            runtime_scope: state.scope.clone(),
            runtime: state.server_runtime.clone(),
            workspace_id: workspace,
            workspace_epoch: local.state.context.workspace_epoch,
            workspace_fence: local.fence,
        },
        pairing_id: PairingId::from_bytes(id(n)).unwrap(),
        grant_id: GrantId::from_bytes(id(n + 1000)).unwrap(),
        account_id: AccountId::from_bytes(id(1)).unwrap(),
        window_identity_id: WindowIdentityId::from_bytes(id(2)).unwrap(),
        proposal: PairingProposal {
            maximum_grant: "03".to_owned().try_into().unwrap(),
            identities,
            authority,
        },
        original_expires_at: 1100,
        params: if approve {
            PairingDecisionParams::Approve {
                grant: SignedGrantWire {
                    canonical_cbor: "04".to_owned().try_into().unwrap(),
                    signature: "22".repeat(64).try_into().unwrap(),
                },
                runtime: state.server_runtime.clone(),
            }
        } else {
            PairingDecisionParams::Deny {
                runtime: state.server_runtime.clone(),
            }
        },
    }
}
fn response(intent: &PairingDecisionIntent) -> PairingResult {
    let p = &intent.preparation;
    match &p.params {
        PairingDecisionParams::Approve { grant, .. } => PairingResult::Approved {
            pairing_id: p.pairing_id,
            proposal: p.proposal.clone(),
            grant: grant.clone(),
            identities: p.proposal.identities.clone(),
            authority: p.proposal.authority.clone(),
        },
        PairingDecisionParams::Deny { .. } => PairingResult::Denied {
            pairing_id: p.pairing_id,
        },
    }
}
fn record(value: &impl serde::Serialize) -> String {
    serde_json::to_string(&serde_json::json!({"version":1,"value":value})).unwrap()
}

fn running_terminal(store: &mut HostStore, workspace: WorkspaceId, seed: u8) -> TerminalContext {
    let binding = OperationBinding {
        rights: StoredOperationRights::new(
            OperationId::from_bytes([seed; 16]).unwrap(),
            ConsumerAuthorizationId::from_bytes([seed; 16]).unwrap(),
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
        pane_id: PaneId::from_bytes([seed; 16]).unwrap(),
        session_id: TerminalSessionId::from_bytes([seed; 16]).unwrap(),
        session_epoch: SessionEpoch::from_bytes([seed; 16]).unwrap(),
        profile: TerminalProfile::ExperimentalRustGridV1,
    };
    let layout = TerminalLayout::Pane {
        pane: TerminalPane {
            pane_id: terminal.pane_id,
            session: Some(terminal.clone()),
            state: PaneState::Running,
        },
    };
    state.tabs.0.push(TerminalTab {
        tab_id: TabId::from_bytes([seed; 16]).unwrap(),
        name: "private-terminal-title".to_owned().try_into().unwrap(),
        layout,
    });
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
fn publish(store: &mut HostStore, state: &CloudRuntimeState) -> CloudRuntimeState {
    let intent = store.prepare_host_publication(state).unwrap();
    store
        .acknowledge_host_publication(
            &intent,
            &PublicationResult {
                runtime: intent.params.runtime.clone(),
                publication_seq: intent.params.publication_seq,
            },
        )
        .unwrap()
}
fn grant(
    store: &mut HostStore,
    state: &CloudRuntimeState,
    workspace: WorkspaceId,
) -> AcknowledgedWorkspaceGrant {
    let intent = store
        .prepare_pairing_decision(preparation(store, state, workspace, 10, true), 1000)
        .unwrap();
    store
        .acknowledge_pairing_decision(&intent, &response(&intent), 1000)
        .unwrap()
        .unwrap()
}
fn channel(
    source: &AcknowledgedWorkspaceGrant,
    n: usize,
    terminal: Option<&TerminalContext>,
) -> ChannelAdmissionPreparation {
    let original = &source.intent.preparation;
    let PairingResult::Approved {
        grant,
        identities,
        authority,
        ..
    } = &source.response
    else {
        unreachable!()
    };
    let mut authority = authority.clone();
    let target = match terminal {
        Some(t) => {
            authority.terminal_membership = Some(ChannelTerminalMembership {
                pane_id: t.pane_id,
                session_id: t.session_id,
                session_epoch: t.session_epoch,
                terminal_profile: t.profile.clone(),
            });
            ChannelTarget::Terminal {
                workspace_id: original.scope.workspace_id,
                workspace_epoch: original.scope.workspace_epoch,
                pane_id: t.pane_id,
                session_id: t.session_id,
                session_epoch: t.session_epoch,
            }
        }
        None => ChannelTarget::Workspace {
            workspace_id: original.scope.workspace_id,
            workspace_epoch: original.scope.workspace_epoch,
        },
    };
    ChannelAdmissionPreparation {
        scope: original.scope.clone(),
        channel_id: ChannelId::from_bytes(id(n)).unwrap(),
        source_grant_id: original.grant_id,
        source_grant_token: source.intent.token.clone(),
        target,
        inputs: ChannelAdmissionInputs {
            expected_context: "05".to_owned().try_into().unwrap(),
            expected_context_json: serde_json::Map::new(),
            grant: grant.clone(),
            identities: identities.clone(),
            authority,
        },
        issued_at: 1000,
        expires_at: 1020,
        params: ChannelAdmissionParams {
            runtime: original.scope.runtime.clone(),
            admission: SignedChannelAdmissionWire {
                canonical_cbor: "06".to_owned().try_into().unwrap(),
                signature: "33".repeat(64).try_into().unwrap(),
            },
        },
    }
}
fn admitted(intent: &ChannelAdmissionIntent) -> ChannelResult {
    ChannelResult::Admitted {
        channel_id: intent.preparation.channel_id,
        inputs: intent.preparation.inputs.clone(),
        admission: intent.preparation.params.admission.clone(),
    }
}
fn channel_pending_key(intent: &ChannelAdmissionIntent) -> String {
    format!(
        "host_channel_intent:{}",
        String::from(intent.preparation.channel_id)
    )
}
fn channel_ack_key(ack: &AcknowledgedChannelAdmission) -> String {
    format!(
        "host_channel_admission:{}",
        String::from(ack.intent.preparation.channel_id)
    )
}

#[test]
fn exact_retry_and_ack_preserve_signed_request_and_separate_historical_evidence() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let source = grant(&mut store, &state, workspace);
    let state = publish(&mut store, &state);
    let p = channel(&source, 30, None);
    let intent = store.prepare_channel_admission(p.clone(), 1000).unwrap();
    let bytes = serde_json::to_vec(&intent).unwrap();
    assert_eq!(store.prepare_channel_admission(p, 1001).unwrap(), intent);
    assert_eq!(
        serde_json::to_vec(&store.channel_admission_for_send(&intent, 1001).unwrap()).unwrap(),
        bytes
    );
    assert!(store.acknowledged_channel_admissions().unwrap().is_empty());
    let outbox = store.pending_publications().unwrap();
    let ack = store
        .acknowledge_channel_admission(&intent, &admitted(&intent), 1001)
        .unwrap();
    assert!(store.pending_channel_admissions().unwrap().is_empty());
    assert_eq!(
        store.acknowledged_channel_admissions().unwrap().as_slice(),
        std::slice::from_ref(&ack)
    );
    assert_eq!(
        store
            .acknowledge_channel_admission(&intent, &admitted(&intent), 1001)
            .unwrap(),
        ack
    );
    assert_eq!(store.pending_publications().unwrap(), outbox);
    assert_eq!(
        store.cloud_runtime_state(&state.scope).unwrap(),
        Some(state)
    );
    assert!(
        !String::from_utf8(bytes)
            .unwrap()
            .contains("private-project-title")
    );
}
#[test]
fn changed_context_signature_source_scope_target_or_expiry_never_rewrites_pending_bytes() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let source = grant(&mut store, &state, workspace);
    publish(&mut store, &state);
    let p = channel(&source, 30, None);
    let intent = store.prepare_channel_admission(p.clone(), 1000).unwrap();
    for change in 0..11 {
        let mut changed = p.clone();
        match change {
            0 => changed.inputs.expected_context = "07".to_owned().try_into().unwrap(),
            1 => changed.params.admission.signature = "44".repeat(64).try_into().unwrap(),
            2 => changed.source_grant_token = Uuid::new_v4().to_string(),
            3 => changed.source_grant_id = GrantId::from_bytes(id(98)).unwrap(),
            4 => changed.expires_at += 1,
            5 => changed.issued_at -= 1,
            6 => changed.scope.workspace_fence += 1,
            7 => changed.inputs.authority.grant_revision.0 += 1,
            8 => {
                changed.target = ChannelTarget::Workspace {
                    workspace_id: WorkspaceId::from_bytes(id(99)).unwrap(),
                    workspace_epoch: p.scope.workspace_epoch,
                }
            }
            9 => {
                changed.inputs.authority.host_authorization_id =
                    HostAuthorizationId::from_bytes(id(99)).unwrap()
            }
            10 => {
                changed.inputs.identities.consumer_fingerprint = "44".repeat(32).try_into().unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            store.prepare_channel_admission(changed, 1001).is_err(),
            "mutation {change}"
        );
        assert_eq!(
            store.pending_channel_admissions().unwrap().as_slice(),
            std::slice::from_ref(&intent)
        );
    }
    let mut wrong = intent.clone();
    wrong.token = Uuid::new_v4().to_string();
    assert_eq!(
        store.channel_admission_for_send(&wrong, 1001),
        Err(StoreError::RevisionConflict)
    );
    assert_eq!(
        store.acknowledge_channel_admission(&wrong, &admitted(&wrong), 1001),
        Err(StoreError::RevisionConflict)
    );
}
#[test]
fn ack_requires_exact_context_grant_identity_authority_admission_and_channel() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let source = grant(&mut store, &state, workspace);
    publish(&mut store, &state);
    let intent = store
        .prepare_channel_admission(channel(&source, 30, None), 1000)
        .unwrap();
    for change in 0..7 {
        let mut result = admitted(&intent);
        if let ChannelResult::Admitted {
            channel_id,
            inputs,
            admission,
        } = &mut result
        {
            match change {
                0 => *channel_id = ChannelId::from_bytes(id(99)).unwrap(),
                1 => inputs.expected_context = "07".to_owned().try_into().unwrap(),
                2 => inputs.grant.signature = "44".repeat(64).try_into().unwrap(),
                3 => inputs.identities.consumer_fingerprint = "44".repeat(32).try_into().unwrap(),
                4 => {
                    inputs.authority.account_session_id =
                        "changed-session".to_owned().try_into().unwrap()
                }
                5 => admission.signature = "44".repeat(64).try_into().unwrap(),
                6 => {
                    result = ChannelResult::Expired {
                        channel_id: *channel_id,
                    }
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(
            store.acknowledge_channel_admission(&intent, &result, 1001),
            Err(StoreError::Fenced)
        );
        assert_eq!(
            store.pending_channel_admissions().unwrap().as_slice(),
            std::slice::from_ref(&intent)
        );
        assert!(store.acknowledged_channel_admissions().unwrap().is_empty());
    }
}
#[test]
fn current_and_acknowledged_terminal_membership_are_both_required_without_binding_sequence() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let source = grant(&mut store, &state, workspace);
    assert_eq!(
        store.prepare_channel_admission(channel(&source, 30, None), 1000),
        Err(StoreError::Fenced)
    );
    let state = publish(&mut store, &state);
    let terminal = running_terminal(&mut store, workspace, 50);
    let p = channel(&source, 30, Some(&terminal));
    assert_eq!(
        store.prepare_channel_admission(p.clone(), 1000),
        Err(StoreError::Fenced)
    );
    let state = publish(&mut store, &state);
    let intent = store.prepare_channel_admission(p, 1000).unwrap();
    running_terminal(&mut store, workspace, 51);
    publish(&mut store, &state);
    assert_eq!(
        store.channel_admission_for_send(&intent, 1001).unwrap(),
        intent
    );
    store.record_terminal_exit(&terminal).unwrap();
    assert_eq!(
        store.channel_admission_for_send(&intent, 1001),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.acknowledge_channel_admission(&intent, &admitted(&intent), 1001),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.pending_channel_admissions().unwrap().as_slice(),
        std::slice::from_ref(&intent)
    );
}
#[test]
fn consent_logout_runtime_source_and_terminal_races_fence_send_and_ack() {
    for change in 0..7 {
        let d = Directory::new();
        let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
        let state = install(&mut store);
        let workspace = workspace(&mut store, &d.0);
        let terminal = running_terminal(&mut store, workspace, 50);
        let source = grant(&mut store, &state, workspace);
        let state = publish(&mut store, &state);
        let intent = store
            .prepare_channel_admission(channel(&source, 30, Some(&terminal)), 1000)
            .unwrap();
        match change {
            0 => {
                store.unshare(workspace).unwrap();
                let fence = store.workspace(workspace).unwrap().fence;
                store.share(workspace, fence).unwrap();
            }
            1 => {
                store
                    .fence_authorization(AuthorizationFenceReason::LocalLogout)
                    .unwrap();
            }
            2 => store.seal_authorization(),
            3 => {
                store
                    .invalidate_cloud_runtime(&state.scope, &state, None)
                    .unwrap();
            }
            4 => {
                store.retire_acknowledged_workspace_grant(&source).unwrap();
            }
            5 => {
                store.record_terminal_exit(&terminal).unwrap();
                running_terminal(&mut store, workspace, 51);
                publish(&mut store, &state);
            }
            6 => {
                let auth = store
                    .fence_authorization(AuthorizationFenceReason::AuthorityRejected)
                    .unwrap();
                store.enable_authorization(auth.generation).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            store.channel_admission_for_send(&intent, 1001).is_err(),
            "mutation {change}"
        );
        assert!(
            store
                .acknowledge_channel_admission(&intent, &admitted(&intent), 1001)
                .is_err()
        );
        assert_eq!(
            store.pending_channel_admissions().unwrap().as_slice(),
            std::slice::from_ref(&intent)
        );
        let outbox = store.pending_publications().unwrap();
        store.retire_channel_admission(&intent).unwrap();
        assert_eq!(store.pending_publications().unwrap(), outbox);
    }
}
#[test]
fn expiry_and_future_issue_reject_and_durable_clock_rollback_cannot_revive() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let source = grant(&mut store, &state, workspace);
    publish(&mut store, &state);
    let p = channel(&source, 30, None);
    let mut future = p.clone();
    future.issued_at = 1001;
    assert_eq!(
        store.prepare_channel_admission(future, 1000),
        Err(StoreError::Fenced)
    );
    let mut long = p.clone();
    long.expires_at = 1031;
    assert_eq!(
        store.prepare_channel_admission(long, 1000),
        Err(StoreError::Invalid)
    );
    let mut past_grant = p.clone();
    past_grant.issued_at = 1090;
    past_grant.expires_at = 1110;
    assert_eq!(
        store.prepare_channel_admission(past_grant, 1000),
        Err(StoreError::Fenced)
    );
    let intent = store.prepare_channel_admission(p.clone(), 1000).unwrap();
    assert_eq!(
        store.channel_admission_for_send(&intent, 1020),
        Err(StoreError::Fenced)
    );
    assert_eq!(store.authorization_state().unwrap().clock_floor, 1020);
    assert_eq!(
        store.prepare_channel_admission(p, 1001),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.channel_admission_for_send(&intent, 1001),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.acknowledge_channel_admission(&intent, &admitted(&intent), 1001),
        Err(StoreError::Fenced)
    );
    let mut beyond_grant = channel(&source, 31, None);
    beyond_grant.issued_at = 1090;
    beyond_grant.expires_at = 1110;
    assert_eq!(
        store.prepare_channel_admission(beyond_grant, 1090),
        Err(StoreError::Fenced)
    );
    assert_eq!(store.authorization_state().unwrap().clock_floor, 1090);
}
#[test]
fn reopen_and_source_retirement_preserve_evidence_but_never_adopt_authority() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let source = grant(&mut store, &state, workspace);
    publish(&mut store, &state);
    let pending = store
        .prepare_channel_admission(channel(&source, 30, None), 1000)
        .unwrap();
    let completed = store
        .prepare_channel_admission(channel(&source, 31, None), 1000)
        .unwrap();
    let ack = store
        .acknowledge_channel_admission(&completed, &admitted(&completed), 1001)
        .unwrap();
    store.retire_acknowledged_workspace_grant(&source).unwrap();
    assert_eq!(
        store.pending_channel_admissions().unwrap().as_slice(),
        std::slice::from_ref(&pending)
    );
    assert_eq!(
        store.acknowledged_channel_admissions().unwrap().as_slice(),
        std::slice::from_ref(&ack)
    );
    drop(store);
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    assert_eq!(
        store.pending_channel_admissions().unwrap().as_slice(),
        std::slice::from_ref(&pending)
    );
    assert_eq!(
        store.acknowledged_channel_admissions().unwrap().as_slice(),
        std::slice::from_ref(&ack)
    );
    assert!(store.channel_admission_for_send(&pending, 1001).is_err());
    assert!(
        store
            .acknowledge_channel_admission(&pending, &admitted(&pending), 1001)
            .is_err()
    );
    assert!(
        store
            .acknowledge_channel_admission(&completed, &admitted(&completed), 1001)
            .is_err()
    );
    store.retire_channel_admission(&pending).unwrap();
    store.retire_acknowledged_channel_admission(&ack).unwrap();
    assert!(store.pending_channel_admissions().unwrap().is_empty());
    assert!(store.acknowledged_channel_admissions().unwrap().is_empty());
}
#[test]
fn post_write_sql_failure_rolls_ack_back_but_keeps_clock_and_exact_request() {
    let d = Directory::new();
    drop(HostStore::open(&d.db(), Limits::default()).unwrap());
    let sql = rusqlite::Connection::open(d.db()).unwrap();
    sql.execute_batch("CREATE TRIGGER reject_channel_delete BEFORE DELETE ON metadata WHEN OLD.key GLOB 'host_channel_intent:*' AND EXISTS(SELECT 1 FROM metadata WHERE key GLOB 'host_channel_admission:*') BEGIN SELECT RAISE(ABORT,'synthetic post-admission failure'); END;").unwrap();
    drop(sql);
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let source = grant(&mut store, &state, workspace);
    publish(&mut store, &state);
    let intent = store
        .prepare_channel_admission(channel(&source, 30, None), 1000)
        .unwrap();
    assert_eq!(
        store.acknowledge_channel_admission(&intent, &admitted(&intent), 1001),
        Err(StoreError::Storage)
    );
    assert!(store.acknowledged_channel_admissions().unwrap().is_empty());
    assert_eq!(
        store.pending_channel_admissions().unwrap().as_slice(),
        std::slice::from_ref(&intent)
    );
    assert_eq!(store.authorization_state().unwrap().clock_floor, 1001);
}
#[test]
fn malformed_version_unknown_fields_oversized_wrong_key_or_mixed_records_fail_closed() {
    for change in 0..8 {
        let d = Directory::new();
        let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
        let state = install(&mut store);
        let workspace = workspace(&mut store, &d.0);
        let source = grant(&mut store, &state, workspace);
        publish(&mut store, &state);
        let intent = store
            .prepare_channel_admission(channel(&source, 30, None), 1000)
            .unwrap();
        drop(store);
        let sql = rusqlite::Connection::open(d.db()).unwrap();
        let mut value = serde_json::to_value(&intent).unwrap();
        let mut wire = record(&intent);
        match change {
            0 => wire = serde_json::json!({"version":2,"value":value}).to_string(),
            1 => wire = serde_json::json!({"version":1,"value":value,"extra":true}).to_string(),
            2 => {
                value["preparation"]["extra"] = true.into();
                wire = serde_json::json!({"version":1,"value":value}).to_string();
            }
            3 => wire = "x".repeat(256 * 1024 + 1),
            4 => {
                sql.execute(
                    "UPDATE metadata SET key=?1 WHERE key=?2",
                    rusqlite::params![
                        format!(
                            "host_channel_intent:{}",
                            String::from(ChannelId::from_bytes(id(99)).unwrap())
                        ),
                        channel_pending_key(&intent)
                    ],
                )
                .unwrap();
            }
            5 => {
                wire = record(&AcknowledgedChannelAdmission {
                    intent: intent.clone(),
                    response: admitted(&intent),
                })
            }
            6 => {
                let ack = AcknowledgedChannelAdmission {
                    intent: intent.clone(),
                    response: admitted(&intent),
                };
                sql.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    rusqlite::params![channel_ack_key(&ack), record(&ack)],
                )
                .unwrap();
            }
            7 => {
                value["preparation"]["scope"]["runtime_scope"]["host_id"] =
                    serde_json::to_value(HostId::from_bytes(id(99)).unwrap()).unwrap();
                wire = serde_json::json!({"version":1,"value":value}).to_string();
            }
            _ => unreachable!(),
        }
        if change != 4 {
            sql.execute(
                "UPDATE metadata SET value=?1 WHERE key=?2",
                rusqlite::params![wire, channel_pending_key(&intent)],
            )
            .unwrap();
        }
        drop(sql);
        let store = HostStore::open(&d.db(), Limits::default()).unwrap();
        assert_eq!(
            store.pending_channel_admissions(),
            Err(StoreError::Storage),
            "mutation {change}"
        );
        assert_eq!(
            store.acknowledged_channel_admissions(),
            Err(StoreError::Storage)
        );
    }
}
#[test]
fn pending_count_limit_preserves_all_unresolved_requests_until_explicit_retirement() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let source = grant(&mut store, &state, workspace);
    publish(&mut store, &state);
    for n in 0..MAX_CHANNEL_ADMISSION_INTENTS {
        store
            .prepare_channel_admission(channel(&source, n, None), 1000)
            .unwrap();
    }
    let original = store.pending_channel_admissions().unwrap();
    assert_eq!(original.len(), 64);
    assert_eq!(
        store.prepare_channel_admission(channel(&source, 99, None), 1000),
        Err(StoreError::ResourceExhausted)
    );
    assert_eq!(store.pending_channel_admissions().unwrap(), original);
    store.retire_channel_admission(&original[0]).unwrap();
    store
        .prepare_channel_admission(channel(&source, 99, None), 1000)
        .unwrap();
    assert_eq!(store.pending_channel_admissions().unwrap().len(), 64);
}
#[test]
fn retained_count_limit_reserves_every_ack_and_requires_exact_retirement() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let source = grant(&mut store, &state, workspace);
    publish(&mut store, &state);
    let intent = store
        .prepare_channel_admission(channel(&source, 30, None), 1000)
        .unwrap();
    let ack = store
        .acknowledge_channel_admission(&intent, &admitted(&intent), 1000)
        .unwrap();
    drop(store);
    let mut sql = rusqlite::Connection::open(d.db()).unwrap();
    let tx = sql.transaction().unwrap();
    tx.execute(
        "DELETE FROM metadata WHERE key GLOB 'host_channel_admission:*'",
        [],
    )
    .unwrap();
    for n in 0..256 {
        let mut ack = ack.clone();
        ack.intent.token = Uuid::new_v4().to_string();
        ack.intent.preparation.channel_id = ChannelId::from_bytes(id(n)).unwrap();
        ack.response = admitted(&ack.intent);
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            rusqlite::params![channel_ack_key(&ack), record(&ack)],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    drop(sql);
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    store.retire_acknowledged_workspace_grant(&source).unwrap();
    let source = grant(&mut store, &state, workspace);
    publish(&mut store, &state);
    let p = channel(&source, 50_000, None);
    assert_eq!(
        store.prepare_channel_admission(p.clone(), 1000),
        Err(StoreError::ResourceExhausted)
    );
    let ack = store.acknowledged_channel_admissions().unwrap().remove(0);
    store.retire_acknowledged_channel_admission(&ack).unwrap();
    let pending = store.prepare_channel_admission(p, 1000).unwrap();
    assert_eq!(
        store.prepare_channel_admission(channel(&source, 50_001, None), 1000),
        Err(StoreError::ResourceExhausted)
    );
    store
        .acknowledge_channel_admission(&pending, &admitted(&pending), 1000)
        .unwrap();
    assert_eq!(store.acknowledged_channel_admissions().unwrap().len(), 256);
}
#[test]
fn aggregate_budget_reserves_final_ack_bytes_for_all_pending_and_both_ack_orders() {
    const BYTE_BUDGET: usize = 8 * 1024 * 1024;
    const RECORD_BUDGET: usize = 256 * 1024;
    for reverse in [false, true] {
        let d = Directory::new();
        let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
        let state = install(&mut store);
        let workspace = workspace(&mut store, &d.0);
        let source = grant(&mut store, &state, workspace);
        publish(&mut store, &state);
        let large = |source: &AcknowledgedWorkspaceGrant, n| {
            let mut p = channel(source, n, None);
            p.params.admission.canonical_cbor = "ab".repeat(8192).try_into().unwrap();
            p
        };
        let prototype = ChannelAdmissionIntent {
            token: Uuid::new_v4().to_string(),
            preparation: large(&source, 90_000),
        };
        let reserved = record(&AcknowledgedChannelAdmission {
            intent: prototype.clone(),
            response: admitted(&prototype),
        })
        .len();
        let retained = BYTE_BUDGET - 2 * reserved;
        drop(store);
        let mut sql = rusqlite::Connection::open(d.db()).unwrap();
        let tx = sql.transaction().unwrap();
        let mut acks = Vec::new();
        for n in 0..32 {
            let mut intent = prototype.clone();
            intent.token = Uuid::new_v4().to_string();
            intent.preparation.channel_id = ChannelId::from_bytes(id(n + 100_000)).unwrap();
            acks.push(AcknowledgedChannelAdmission {
                response: admitted(&intent),
                intent,
            });
        }
        let mut padding = retained - acks.iter().map(|ack| record(ack).len()).sum::<usize>();
        for ack in acks {
            let mut wire = record(&ack);
            let extra = padding.min(RECORD_BUDGET - wire.len());
            wire.push_str(&" ".repeat(extra));
            padding -= extra;
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                rusqlite::params![channel_ack_key(&ack), wire],
            )
            .unwrap();
        }
        assert_eq!(padding, 0);
        tx.execute_batch("CREATE TRIGGER reject_first_channel_ack BEFORE DELETE ON metadata WHEN OLD.key GLOB 'host_channel_intent:*' AND (SELECT clock_floor FROM authorization_state WHERE id=1)='1001' AND EXISTS(SELECT 1 FROM metadata WHERE key GLOB 'host_channel_admission:*') BEGIN SELECT RAISE(ABORT,'synthetic post-admission failure'); END;").unwrap();
        tx.commit().unwrap();
        drop(sql);
        let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
        let state = install(&mut store);
        store.retire_acknowledged_workspace_grant(&source).unwrap();
        let source = grant(&mut store, &state, workspace);
        publish(&mut store, &state);
        let first = store
            .prepare_channel_admission(large(&source, 90_001), 1000)
            .unwrap();
        let second = store
            .prepare_channel_admission(large(&source, 90_002), 1000)
            .unwrap();
        let extra = large(&source, 90_003);
        assert_eq!(
            store.prepare_channel_admission(extra.clone(), 1000),
            Err(StoreError::ResourceExhausted)
        );
        assert_eq!(
            store.acknowledge_channel_admission(&first, &admitted(&first), 1001),
            Err(StoreError::Storage)
        );
        assert_eq!(store.acknowledged_channel_admissions().unwrap().len(), 32);
        assert_eq!(
            store.prepare_channel_admission(extra.clone(), 1001),
            Err(StoreError::ResourceExhausted)
        );
        assert_eq!(
            store.channel_admission_for_send(&first, 1001).unwrap(),
            first
        );
        store.observe_authorization_clock(1002).unwrap();
        store.retire_channel_admission(&second).unwrap();
        let replacement = store.prepare_channel_admission(extra, 1002).unwrap();
        let order = if reverse {
            [&replacement, &first]
        } else {
            [&first, &replacement]
        };
        for intent in order {
            store
                .acknowledge_channel_admission(intent, &admitted(intent), 1002)
                .unwrap();
        }
        assert!(store.pending_channel_admissions().unwrap().is_empty());
        assert_eq!(store.acknowledged_channel_admissions().unwrap().len(), 34);
    }
}
