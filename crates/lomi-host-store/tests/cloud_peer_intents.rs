//! Private SQLite fixtures only. No crypto authority or networking is claimed.
use lomi_host_store::*;
use lomi_remote_protocol::*;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use uuid::Uuid;

struct Directory(
    PathBuf,
    #[cfg(windows)] Option<lomi_platform::windows::OwnerLock>,
);
impl Directory {
    fn new() -> Self {
        #[cfg(not(windows))]
        let path = std::env::temp_dir().join(format!("lomi-peer-{}", Uuid::new_v4()));
        #[cfg(windows)]
        let path = PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
            .join(format!("lomi-peer-{}", Uuid::new_v4()));
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
fn pending_key(intent: &PairingDecisionIntent) -> String {
    format!(
        "host_pairing_intent:{}",
        String::from(intent.preparation.pairing_id)
    )
}
fn grant_key(grant: &AcknowledgedWorkspaceGrant) -> String {
    format!(
        "host_workspace_grant:{}",
        String::from(grant.intent.preparation.grant_id)
    )
}
fn record(value: &impl serde::Serialize) -> String {
    serde_json::to_string(&serde_json::json!({"version":1,"value":value})).unwrap()
}

#[test]
fn exact_lost_response_retry_freezes_request_and_approved_evidence_is_separate() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let p = preparation(&store, &state, workspace, 10, true);
    let intent = store.prepare_pairing_decision(p.clone(), 1000).unwrap();
    assert!(store.acknowledged_workspace_grants().unwrap().is_empty());
    let bytes = serde_json::to_vec(&intent.preparation.params).unwrap();
    assert_eq!(store.prepare_pairing_decision(p, 1001).unwrap(), intent);
    assert_eq!(
        serde_json::to_vec(
            &store
                .pairing_decision_for_send(&intent, 1002)
                .unwrap()
                .preparation
                .params
        )
        .unwrap(),
        bytes
    );
    let outbox = store.pending_publications().unwrap();
    let acknowledged = store
        .acknowledge_pairing_decision(&intent, &response(&intent), 1003)
        .unwrap()
        .unwrap();
    assert_eq!(acknowledged.intent, intent);
    assert!(store.pending_pairing_decisions().unwrap().is_empty());
    assert_eq!(
        store.acknowledged_workspace_grants().unwrap(),
        std::slice::from_ref(&acknowledged)
    );
    assert_eq!(
        store
            .acknowledge_pairing_decision(&intent, &response(&intent), 1004)
            .unwrap(),
        Some(acknowledged)
    );
    assert_eq!(store.pending_publications().unwrap(), outbox);
    let public = serde_json::to_string(&intent).unwrap();
    assert!(!public.contains("private-project-title"));
    assert!(!public.contains(d.0.to_str().unwrap()));
}
#[test]
fn changed_decision_signature_expiry_proof_or_scope_never_rewrites_intent() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let p = preparation(&store, &state, workspace, 10, true);
    let intent = store.prepare_pairing_decision(p.clone(), 1000).unwrap();
    for change in 0..9 {
        let mut changed = p.clone();
        match change {
            0 => {
                changed.params = PairingDecisionParams::Deny {
                    runtime: state.server_runtime.clone(),
                }
            }
            1 => {
                if let PairingDecisionParams::Approve { grant, .. } = &mut changed.params {
                    grant.signature = "33".repeat(64).try_into().unwrap();
                }
            }
            2 => changed.original_expires_at += 1,
            3 => changed.scope.workspace_fence += 1,
            4 => changed.scope.runtime_scope.remote_api_origin = "https://other.example".into(),
            5 => changed.proposal.maximum_grant = "05".to_owned().try_into().unwrap(),
            6 => changed.window_identity_id = WindowIdentityId::from_bytes(id(99)).unwrap(),
            7 => changed.grant_id = GrantId::from_bytes(id(99)).unwrap(),
            8 => changed.account_id = AccountId::from_bytes(id(99)).unwrap(),
            _ => unreachable!(),
        }
        assert!(store.prepare_pairing_decision(changed, 1001).is_err());
        assert_eq!(
            store.pending_pairing_decisions().unwrap(),
            std::slice::from_ref(&intent)
        );
    }
    let mut wrong = intent.clone();
    wrong.token = Uuid::new_v4().to_string();
    assert_eq!(
        store.pairing_decision_for_send(&wrong, 1001),
        Err(StoreError::RevisionConflict)
    );
    assert_eq!(
        store.acknowledge_pairing_decision(&wrong, &response(&wrong), 1001),
        Err(StoreError::RevisionConflict)
    );
}
#[test]
fn denial_ack_removes_only_the_exact_pending_request_without_a_grant() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let deny = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 10, false), 1000)
        .unwrap();
    let other = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 11, true), 1000)
        .unwrap();
    assert_eq!(
        store
            .acknowledge_pairing_decision(&deny, &response(&deny), 1001)
            .unwrap(),
        None
    );
    assert_eq!(store.pending_pairing_decisions().unwrap(), [other]);
    assert!(store.acknowledged_workspace_grants().unwrap().is_empty());
    assert_eq!(
        store.acknowledge_pairing_decision(&deny, &response(&deny), 1001),
        Err(StoreError::RevisionConflict)
    );
}
#[test]
fn mismatched_ack_pairing_grant_identity_authority_or_outcome_cannot_clear_request() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let intent = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 10, true), 1000)
        .unwrap();
    for change in 0..7 {
        let mut ack = response(&intent);
        if let PairingResult::Approved {
            pairing_id,
            proposal,
            grant,
            identities,
            authority,
        } = &mut ack
        {
            match change {
                0 => *pairing_id = PairingId::from_bytes(id(99)).unwrap(),
                1 => grant.signature = "33".repeat(64).try_into().unwrap(),
                2 => identities.consumer_fingerprint = "44".repeat(32).try_into().unwrap(),
                3 => authority.grant_revision = DecimalU64(2),
                4 => {
                    authority.account_session_id =
                        "different-session".to_owned().try_into().unwrap()
                }
                5 => proposal.maximum_grant = "05".to_owned().try_into().unwrap(),
                6 => {
                    ack = PairingResult::Expired {
                        pairing_id: intent.preparation.pairing_id,
                    }
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(
            store.acknowledge_pairing_decision(&intent, &ack, 1001),
            Err(StoreError::Fenced)
        );
        assert_eq!(
            store.pending_pairing_decisions().unwrap(),
            std::slice::from_ref(&intent)
        );
        assert!(store.acknowledged_workspace_grants().unwrap().is_empty());
    }
}
#[test]
fn unshare_reshare_logout_and_runtime_replacement_fence_old_send_and_ack() {
    for change in 0..4 {
        let d = Directory::new();
        let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
        let state = install(&mut store);
        let workspace = workspace(&mut store, &d.0);
        let intent = store
            .prepare_pairing_decision(preparation(&store, &state, workspace, 10, true), 1000)
            .unwrap();
        match change {
            0 => {
                let fence = store.unshare(workspace).unwrap();
                store.share(workspace, fence).unwrap();
            }
            1 => {
                store
                    .fence_authorization(AuthorizationFenceReason::LocalLogout)
                    .unwrap();
            }
            2 => {
                store
                    .invalidate_cloud_runtime(&state.scope, &state, None)
                    .unwrap();
                let mut next = state.server_runtime.clone();
                next.runtime_generation.0 += 1;
                next.host_access_epoch.0 += 1;
                store
                    .compare_and_set_cloud_runtime(&state.scope, None, next, DecimalU64(0))
                    .unwrap();
            }
            3 => {
                let fence = store
                    .fence_authorization(AuthorizationFenceReason::AuthorityRejected)
                    .unwrap();
                store.enable_authorization(fence.generation).unwrap();
                assert!(!store.authorization_state().unwrap().locked);
            }
            _ => unreachable!(),
        }
        assert!(store.pairing_decision_for_send(&intent, 1001).is_err());
        assert!(
            store
                .acknowledge_pairing_decision(&intent, &response(&intent), 1001)
                .is_err()
        );
        assert_eq!(
            store.pending_pairing_decisions().unwrap(),
            std::slice::from_ref(&intent)
        );
        let outbox = store.pending_publications().unwrap();
        store.retire_pairing_decision(&intent).unwrap();
        assert!(store.pending_pairing_decisions().unwrap().is_empty());
        assert_eq!(store.pending_publications().unwrap(), outbox);
    }
}
#[test]
fn publication_progress_does_not_change_the_pairing_runtime_scope() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let intent = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 10, true), 1000)
        .unwrap();
    let publication = store.prepare_host_publication(&state).unwrap();
    store
        .acknowledge_host_publication(
            &publication,
            &PublicationResult {
                runtime: publication.params.runtime.clone(),
                publication_seq: publication.params.publication_seq,
            },
        )
        .unwrap();
    assert_eq!(
        store.pairing_decision_for_send(&intent, 1001).unwrap(),
        intent
    );
    store
        .acknowledge_pairing_decision(&intent, &response(&intent), 1001)
        .unwrap();
}
#[test]
fn expired_or_failed_action_keeps_a_durable_clock_floor_that_rollback_cannot_revive() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let p = preparation(&store, &state, workspace, 10, true);
    let intent = store.prepare_pairing_decision(p.clone(), 1000).unwrap();
    assert_eq!(
        store.pairing_decision_for_send(&intent, 1100),
        Err(StoreError::Fenced)
    );
    assert_eq!(store.authorization_state().unwrap().clock_floor, 1100);
    assert_eq!(
        store.pairing_decision_for_send(&intent, 1001),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.prepare_pairing_decision(p, 1001),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.acknowledge_pairing_decision(&intent, &response(&intent), 1001),
        Err(StoreError::Fenced)
    );
    assert_eq!(store.pending_pairing_decisions().unwrap(), [intent]);
}
#[test]
fn reopen_keeps_exact_evidence_but_never_adopts_old_owner_requests_or_grants() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let pending = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 10, true), 1000)
        .unwrap();
    let second = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 11, true), 1000)
        .unwrap();
    let approved = store
        .acknowledge_pairing_decision(&second, &response(&second), 1001)
        .unwrap()
        .unwrap();
    drop(store);
    let mut reopened = HostStore::open(&d.db(), Limits::default()).unwrap();
    assert_ne!(reopened.runtime_id(), state.scope.owner_runtime_id);
    assert_eq!(
        reopened.pending_pairing_decisions().unwrap(),
        std::slice::from_ref(&pending)
    );
    assert_eq!(
        reopened.acknowledged_workspace_grants().unwrap(),
        std::slice::from_ref(&approved)
    );
    assert!(reopened.pairing_decision_for_send(&pending, 1001).is_err());
    assert!(
        reopened
            .acknowledge_pairing_decision(&pending, &response(&pending), 1001)
            .is_err()
    );
    let current = install(&mut reopened);
    let replacement = preparation(&reopened, &current, workspace, 10, true);
    assert_eq!(
        reopened.prepare_pairing_decision(replacement, 1001),
        Err(StoreError::IdempotencyConflict)
    );
    reopened.retire_pairing_decision(&pending).unwrap();
    reopened
        .retire_acknowledged_workspace_grant(&approved)
        .unwrap();
    assert!(reopened.acknowledged_workspace_grants().unwrap().is_empty());
}
#[test]
fn pairing_crash_child() {
    let Some(path) = std::env::var_os("LOMI_PAIRING_CRASH_FIXTURE_DB") else {
        return;
    };
    let path = PathBuf::from(path);
    let mut store = HostStore::open(&path, Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, path.parent().unwrap());
    let intent = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 10, true), 1000)
        .unwrap();
    std::fs::write(
        path.with_extension("pairing-intent.json"),
        serde_json::to_vec(&intent).unwrap(),
    )
    .unwrap();
    std::process::exit(73);
}
#[test]
fn abrupt_child_exit_retains_the_exact_request_but_a_new_owner_cannot_send_or_ack() {
    let d = Directory::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "pairing_crash_child", "--nocapture"])
        .env("LOMI_PAIRING_CRASH_FIXTURE_DB", d.db())
        .spawn()
        .unwrap();
    let mut status = None;
    for _ in 0..200 {
        if let Some(done) = child.try_wait().unwrap() {
            status = Some(done);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("bounded child fixture timed out");
    }
    assert_eq!(status.unwrap().code(), Some(73));
    let original: PairingDecisionIntent = serde_json::from_slice(
        &std::fs::read(d.db().with_extension("pairing-intent.json")).unwrap(),
    )
    .unwrap();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let intent = store.pending_pairing_decisions().unwrap().pop().unwrap();
    assert_eq!(intent, original);
    let bytes = serde_json::to_vec(&original.preparation.params).unwrap();
    assert_eq!(store.pending_pairing_decisions().unwrap()[0], intent);
    assert_eq!(
        serde_json::to_vec(&intent.preparation.params).unwrap(),
        bytes
    );
    assert!(store.pairing_decision_for_send(&intent, 1001).is_err());
    assert!(
        store
            .acknowledge_pairing_decision(&intent, &response(&intent), 1001)
            .is_err()
    );
    assert!(store.acknowledged_workspace_grants().unwrap().is_empty());
}
#[test]
fn sql_failure_after_grant_write_rolls_back_both_grant_and_intent_removal() {
    let d = Directory::new();
    drop(HostStore::open(&d.db(), Limits::default()).unwrap());
    let sql = rusqlite::Connection::open(d.db()).unwrap();
    sql.execute_batch("CREATE TRIGGER reject_pairing_delete BEFORE DELETE ON metadata WHEN OLD.key GLOB 'host_pairing_intent:*' AND EXISTS(SELECT 1 FROM metadata WHERE key GLOB 'host_workspace_grant:*') BEGIN SELECT RAISE(ABORT,'synthetic post-grant failure'); END;").unwrap();
    drop(sql);
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let intent = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 10, true), 1000)
        .unwrap();
    assert_eq!(
        store.acknowledge_pairing_decision(&intent, &response(&intent), 1001),
        Err(StoreError::Storage)
    );
    assert_eq!(store.pending_pairing_decisions().unwrap(), [intent]);
    assert!(store.acknowledged_workspace_grants().unwrap().is_empty());
    assert_eq!(store.authorization_state().unwrap().clock_floor, 1001);
}
#[test]
fn malformed_version_oversized_wrong_key_or_mixed_records_fail_closed() {
    for change in 0..8 {
        let d = Directory::new();
        let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
        let state = install(&mut store);
        let workspace = workspace(&mut store, &d.0);
        let intent = store
            .prepare_pairing_decision(preparation(&store, &state, workspace, 10, true), 1000)
            .unwrap();
        drop(store);
        let sql = rusqlite::Connection::open(d.db()).unwrap();
        let mut value = serde_json::to_value(&intent).unwrap();
        let mut wire = record(&intent);
        match change {
            0 => wire = serde_json::json!({"version":2,"value":intent}).to_string(),
            1 => {
                wire = serde_json::json!({"version":1,"value":intent,"unexpected":true}).to_string()
            }
            2 => {
                value["preparation"]["unexpected"] = true.into();
                wire = serde_json::json!({"version":1,"value":value}).to_string();
            }
            3 => wire = "x".repeat(128 * 1024 + 1),
            4 => {
                let wrong = format!(
                    "host_pairing_intent:{}",
                    String::from(PairingId::from_bytes(id(99)).unwrap())
                );
                sql.execute(
                    "UPDATE metadata SET key=?1 WHERE key=?2",
                    rusqlite::params![wrong, pending_key(&intent)],
                )
                .unwrap();
            }
            5 => {
                wire = record(&AcknowledgedWorkspaceGrant {
                    intent: intent.clone(),
                    response: response(&intent),
                })
            }
            6 => {
                let acknowledged = AcknowledgedWorkspaceGrant {
                    intent: intent.clone(),
                    response: response(&intent),
                };
                sql.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    rusqlite::params![grant_key(&acknowledged), record(&acknowledged)],
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
                rusqlite::params![wire, pending_key(&intent)],
            )
            .unwrap();
        }
        drop(sql);
        let store = HostStore::open(&d.db(), Limits::default()).unwrap();
        assert_eq!(
            store.pending_pairing_decisions(),
            Err(StoreError::Storage),
            "mutation {change}"
        );
        assert_eq!(
            store.acknowledged_workspace_grants(),
            Err(StoreError::Storage)
        );
    }
}
#[test]
fn pending_count_limit_never_evicts_unresolved_or_expired_requests() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    for n in 0..MAX_PAIRING_DECISION_INTENTS {
        store
            .prepare_pairing_decision(preparation(&store, &state, workspace, n, true), 1000)
            .unwrap();
    }
    let original = store.pending_pairing_decisions().unwrap();
    assert_eq!(original.len(), 64);
    assert_eq!(
        store.prepare_pairing_decision(preparation(&store, &state, workspace, 99, true), 1001),
        Err(StoreError::ResourceExhausted)
    );
    assert_eq!(store.pending_pairing_decisions().unwrap(), original);
    assert_eq!(
        store.pairing_decision_for_send(&original[0], 1100),
        Err(StoreError::Fenced)
    );
    assert_eq!(store.pending_pairing_decisions().unwrap(), original);
    store.retire_pairing_decision(&original[0]).unwrap();
    let mut fresh = preparation(&store, &state, workspace, 99, false);
    fresh.original_expires_at = 1200;
    store.prepare_pairing_decision(fresh, 1100).unwrap();
    assert_eq!(store.pending_pairing_decisions().unwrap().len(), 64);
}
#[test]
fn retained_grant_count_limit_reserves_approval_capacity_and_requires_explicit_retirement() {
    let d = Directory::new();
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let workspace = workspace(&mut store, &d.0);
    let intent = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 10, true), 1000)
        .unwrap();
    let acknowledged = store
        .acknowledge_pairing_decision(&intent, &response(&intent), 1001)
        .unwrap()
        .unwrap();
    drop(store);
    let mut sql = rusqlite::Connection::open(d.db()).unwrap();
    let tx = sql.transaction().unwrap();
    tx.execute(
        "DELETE FROM metadata WHERE key GLOB 'host_workspace_grant:*'",
        [],
    )
    .unwrap();
    for n in 0..MAX_ACKNOWLEDGED_WORKSPACE_GRANTS {
        let mut grant = acknowledged.clone();
        grant.intent.token = Uuid::new_v4().to_string();
        grant.intent.preparation.pairing_id = PairingId::from_bytes(id(n)).unwrap();
        grant.intent.preparation.grant_id = GrantId::from_bytes(id(n + 1000)).unwrap();
        grant.response = response(&grant.intent);
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            rusqlite::params![grant_key(&grant), record(&grant)],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    drop(sql);
    let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
    let state = install(&mut store);
    let p = preparation(&store, &state, workspace, 50_000, true);
    assert_eq!(store.acknowledged_workspace_grants().unwrap().len(), 256);
    assert_eq!(
        store.prepare_pairing_decision(p.clone(), 1001),
        Err(StoreError::ResourceExhausted)
    );
    let deny = store
        .prepare_pairing_decision(preparation(&store, &state, workspace, 50_001, false), 1001)
        .unwrap();
    store
        .acknowledge_pairing_decision(&deny, &response(&deny), 1001)
        .unwrap();
    assert_eq!(store.acknowledged_workspace_grants().unwrap().len(), 256);
    let first = store.acknowledged_workspace_grants().unwrap().remove(0);
    store.retire_acknowledged_workspace_grant(&first).unwrap();
    store.prepare_pairing_decision(p, 1001).unwrap();
}

#[test]
fn byte_budget_reserves_every_pending_approval_before_send_and_ack_order_is_irrelevant() {
    const BYTE_BUDGET: usize = 8 * 1024 * 1024;
    const RECORD_BUDGET: usize = 128 * 1024;
    for reverse in [false, true] {
        let d = Directory::new();
        let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
        let state = install(&mut store);
        let workspace = workspace(&mut store, &d.0);
        let large = |store: &HostStore, state: &CloudRuntimeState, n| {
            let mut p = preparation(store, state, workspace, n, true);
            if let PairingDecisionParams::Approve { grant, .. } = &mut p.params {
                grant.canonical_cbor = "ab".repeat(8192).try_into().unwrap();
            }
            p
        };
        let prototype = PairingDecisionIntent {
            token: Uuid::new_v4().to_string(),
            preparation: large(&store, &state, 90_000),
        };
        let reserved = record(&AcknowledgedWorkspaceGrant {
            intent: prototype.clone(),
            response: response(&prototype),
        })
        .len();
        let deny = PairingDecisionIntent {
            token: Uuid::new_v4().to_string(),
            preparation: preparation(&store, &state, workspace, 90_001, false),
        };
        let retained_bytes = BYTE_BUDGET - 2 * reserved - record(&deny).len();
        drop(store);
        let mut sql = rusqlite::Connection::open(d.db()).unwrap();
        let tx = sql.transaction().unwrap();
        let mut grants = Vec::new();
        for n in 0..64 {
            let mut intent = prototype.clone();
            intent.token = Uuid::new_v4().to_string();
            intent.preparation.pairing_id = PairingId::from_bytes(id(n + 100_000)).unwrap();
            intent.preparation.grant_id = GrantId::from_bytes(id(n + 101_000)).unwrap();
            grants.push(AcknowledgedWorkspaceGrant {
                response: response(&intent),
                intent,
            });
        }
        let mut padding = retained_bytes - grants.iter().map(|g| record(g).len()).sum::<usize>();
        for grant in grants {
            let mut wire = record(&grant);
            let extra = padding.min(RECORD_BUDGET - wire.len());
            wire.push_str(&" ".repeat(extra));
            padding -= extra;
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                rusqlite::params![grant_key(&grant), wire],
            )
            .unwrap();
        }
        assert_eq!(padding, 0);
        // A failed post-write ACK leaves its capacity reserved. The later clock
        // observation releases this synthetic fault without reopening the owner.
        tx.execute_batch("CREATE TRIGGER reject_first_pairing_ack BEFORE DELETE ON metadata WHEN OLD.key GLOB 'host_pairing_intent:*' AND (SELECT clock_floor FROM authorization_state WHERE id=1)='1001' AND EXISTS(SELECT 1 FROM metadata WHERE key GLOB 'host_workspace_grant:*') BEGIN SELECT RAISE(ABORT,'synthetic post-grant failure'); END;").unwrap();
        tx.commit().unwrap();
        drop(sql);
        let mut store = HostStore::open(&d.db(), Limits::default()).unwrap();
        let state = install(&mut store);
        let denial = store
            .prepare_pairing_decision(preparation(&store, &state, workspace, 90_001, false), 1000)
            .unwrap();
        let first = store
            .prepare_pairing_decision(large(&store, &state, 90_002), 1000)
            .unwrap();
        let second = store
            .prepare_pairing_decision(large(&store, &state, 90_003), 1000)
            .unwrap();
        let extra = large(&store, &state, 90_004);
        assert_eq!(
            store.prepare_pairing_decision(extra.clone(), 1000),
            Err(StoreError::ResourceExhausted)
        );
        assert_eq!(
            store.acknowledge_pairing_decision(&first, &response(&first), 1001),
            Err(StoreError::Storage)
        );
        assert_eq!(store.acknowledged_workspace_grants().unwrap().len(), 64);
        assert_eq!(
            store.prepare_pairing_decision(extra.clone(), 1001),
            Err(StoreError::ResourceExhausted)
        );
        assert_eq!(
            store.pairing_decision_for_send(&first, 1001).unwrap(),
            first
        );
        store.observe_authorization_clock(1002).unwrap();
        store.retire_pairing_decision(&second).unwrap();
        let replacement = store.prepare_pairing_decision(extra, 1002).unwrap();
        store
            .acknowledge_pairing_decision(&denial, &response(&denial), 1002)
            .unwrap();
        let next_denial = store
            .prepare_pairing_decision(preparation(&store, &state, workspace, 90_005, false), 1002)
            .unwrap();
        let approvals = if reverse {
            [&replacement, &first]
        } else {
            [&first, &replacement]
        };
        for intent in approvals {
            store
                .acknowledge_pairing_decision(intent, &response(intent), 1002)
                .unwrap()
                .unwrap();
        }
        store
            .acknowledge_pairing_decision(&next_denial, &response(&next_denial), 1002)
            .unwrap();
        assert!(store.pending_pairing_decisions().unwrap().is_empty());
        assert_eq!(store.acknowledged_workspace_grants().unwrap().len(), 66);
    }
}
