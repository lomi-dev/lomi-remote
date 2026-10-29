//! Synthetic/protected fixtures with actual signatures, canonical CBOR and Noise.
//! Pure gates and actual in-memory protected HostAuth/Noise fixtures remain unwired
//! to production transport; owner observations are synthetic trusted caller data.
use super::*;
use lomi_host_auth::Config;
use lomi_host_store::CloudRuntimeState;
use lomi_remote_crypto::{GrantPurposeV3, GrantV3, Identity, Role, TerminalTargetV3};
use lomi_remote_protocol::{
    http::{PublicationTerminals, PublicationWorkspaces, PublishedTerminal, PublishedWorkspace},
    ipc::IpcProfileId,
};

struct Fixture {
    host: PublicHostIdentity,
    origin: RemoteOrigin,
    scope: CloudRuntimeScope,
    runtime: RuntimeBinding,
    heartbeat: HeartbeatObservation,
    acknowledged: HostAcknowledgedPublication,
    local: LocalWorkspace,
    running: Vec<TerminalContext>,
    consumer: EnrollmentProof,
    consumer_pin: [u8; 32],
    authority: CurrentAuthorityV3,
    signed: SignedGrantV3,
    admission: SignedChannelAdmissionV3,
    context: ChannelContextV3,
    start: Instant,
    gate_denied: AtomicBool,
    paused: AtomicBool,
    stopping: AtomicBool,
    cancelled: AtomicBool,
}
fn caps(rights: &[Capability]) -> CapabilitySet {
    rights.to_vec().try_into().unwrap()
}
fn observe() -> CapabilitySet {
    caps(&[Capability::WorkspaceRead, Capability::TerminalObserve])
}
fn control() -> CapabilitySet {
    caps(&[
        Capability::WorkspaceRead,
        Capability::TerminalObserve,
        Capability::TerminalControl,
    ])
}
fn manage() -> CapabilitySet {
    caps(&[
        Capability::WorkspaceRead,
        Capability::TerminalObserve,
        Capability::TerminalManage,
    ])
}
fn published(t: &TerminalContext) -> PublishedTerminal {
    PublishedTerminal {
        pane_id: t.pane_id,
        session_id: t.session_id,
        session_epoch: t.session_epoch,
    }
}
impl Fixture {
    fn new(rights: CapabilitySet, terminal: bool) -> Self {
        Self::with_expiry(rights, terminal, 1100, 1030)
    }
    fn with_expiry(
        rights: CapabilitySet,
        terminal: bool,
        grant_expires: u64,
        context_expires: u64,
    ) -> Self {
        let host = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
        let consumer = Identity::generate([1; 16], [3; 16], Role::Device, 1).unwrap();
        let pin = host.public_bundle().bundle.fingerprint().unwrap();
        let consumer_pin = consumer.public_bundle().bundle.fingerprint().unwrap();
        let host_id = HostId::from_bytes([2; 16]).unwrap();
        let protected = PublicHostIdentity {
            account_id: AccountId::from_bytes([1; 16]).unwrap(),
            host_id,
            identity: host.public_bundle().to_wire().unwrap(),
            fingerprint: pin,
            host_authorization_id: HostAuthorizationId::from_bytes([4; 16]).unwrap(),
            access_epoch: 12,
        };
        let config = Config::new(
            host_id,
            IpcProfileId::from_bytes([20; 16]).unwrap(),
            "https://identity.example".into(),
            "host".to_owned().try_into().unwrap(),
        )
        .unwrap();
        let origin = RemoteOrigin::new(&config, "https://remote.example".into()).unwrap();
        let runtime = RuntimeBinding {
            runtime_id: RuntimeId::from_bytes([8; 16]).unwrap(),
            runtime_generation: DecimalU64(17),
            host_access_epoch: DecimalU64(12),
        };
        let scope = CloudRuntimeScope {
            authorization_generation: 2,
            remote_api_origin: origin.as_str().into(),
            host_id,
            owner_runtime_id: runtime.runtime_id,
            owner_generation: 9,
        };
        let workspace = WorkspaceContext {
            workspace_id: WorkspaceId::from_bytes([6; 16]).unwrap(),
            workspace_epoch: WorkspaceEpoch::from_bytes([7; 16]).unwrap(),
            runtime_id: runtime.runtime_id,
            runtime_generation: runtime.runtime_generation,
            host_access_epoch: runtime.host_access_epoch,
            grant_revision: DecimalU64(2),
        };
        let running = vec![
            TerminalContext {
                workspace: workspace.clone(),
                pane_id: PaneId::from_bytes([11; 16]).unwrap(),
                session_id: TerminalSessionId::from_bytes([12; 16]).unwrap(),
                session_epoch: SessionEpoch::from_bytes([13; 16]).unwrap(),
                profile: TerminalProfile::ExperimentalRustGridV1,
            },
            TerminalContext {
                workspace: workspace.clone(),
                pane_id: PaneId::from_bytes([14; 16]).unwrap(),
                session_id: TerminalSessionId::from_bytes([15; 16]).unwrap(),
                session_epoch: SessionEpoch::from_bytes([16; 16]).unwrap(),
                profile: TerminalProfile::ExperimentalRustGridV1,
            },
        ];
        let terminals =
            PublicationTerminals::try_from(running.iter().map(published).collect::<Vec<_>>())
                .unwrap();
        let local = LocalWorkspace {
            workspace_id: workspace.workspace_id,
            workspace_epoch: workspace.workspace_epoch,
            fence: 3,
            consent: true,
            running_terminals: terminals.clone(),
            capability_ceiling: None,
        };
        let acknowledged = HostAcknowledgedPublication {
            state: CloudRuntimeState {
                scope: scope.clone(),
                server_runtime: runtime.clone(),
                acknowledged_publication_seq: DecimalU64(1),
            },
            workspaces: PublicationWorkspaces::try_from(vec![PublishedWorkspace {
                workspace_id: local.workspace_id,
                workspace_epoch: local.workspace_epoch,
                terminals,
            }])
            .unwrap(),
        };
        let grant = GrantV3 {
            version: 3,
            api_major: 2,
            application_major: 2,
            account_id: [1; 16],
            host_id: [2; 16],
            host_fingerprint: pin,
            host_authorization_id: [4; 16],
            access_epoch: 12,
            consumer_authorization_id: [5; 16],
            account_session_id: "synthetic-current-session".into(),
            consumer_id: [3; 16],
            consumer_fingerprint: consumer_pin,
            grant_id: [19; 16],
            grant_revision: 2,
            workspace_id: [6; 16],
            workspace_epoch: [7; 16],
            runtime_id: [8; 16],
            runtime_generation: 17,
            capabilities: rights,
            nonce: [10; 32],
            expires_at: grant_expires,
            purpose: GrantPurposeV3::Workspace,
        };
        let context = ChannelContextV3 {
            version: 3,
            grant: grant.clone(),
            channel_id: [21; 16],
            initiator_role: Role::Device,
            responder_role: Role::Host,
            purpose: if terminal {
                ChannelPurposeV3::Terminal
            } else {
                ChannelPurposeV3::Workspace
            },
            terminal: terminal.then(|| target_v3(&running[0])),
            issued_at: 1000,
            expires_at: context_expires,
        };
        let authority = CurrentAuthorityV3 {
            host_authorization_id: grant.host_authorization_id,
            consumer_authorization_id: grant.consumer_authorization_id,
            account_session_id: grant.account_session_id.clone(),
            access_epoch: grant.access_epoch,
            grant_revision: grant.grant_revision,
            workspace_epoch: grant.workspace_epoch,
            runtime_id: grant.runtime_id,
            runtime_generation: grant.runtime_generation,
            terminal_membership: context.terminal.clone(),
        };
        let start = Instant::now();
        let heartbeat = HeartbeatObservation {
            scope: scope.clone(),
            runtime: runtime.clone(),
            request_started: start,
            wall_at_request_start: 1000,
            lease_ms: 30_000,
            freshness_ms: 5_000,
        };
        Self {
            host: protected,
            origin,
            scope,
            runtime,
            heartbeat,
            acknowledged,
            local,
            running,
            consumer: consumer.public_bundle().to_wire().unwrap(),
            consumer_pin,
            authority,
            signed: host.sign_grant_v3(&grant).unwrap(),
            admission: host.sign_channel_admission_v3(&context).unwrap(),
            context,
            start,
            gate_denied: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }
    fn now(&self, millis: u64) -> TrustedNow {
        TrustedNow {
            wall: Duration::from_secs(1000) + Duration::from_millis(millis),
            monotonic: self.start + Duration::from_millis(millis),
        }
    }
    fn facts(&self) -> OwnerFacts<'_> {
        OwnerFacts {
            protected_host: &self.host,
            origin: &self.origin,
            scope: &self.scope,
            runtime: &self.runtime,
            heartbeat: &self.heartbeat,
            acknowledged: &self.acknowledged,
            local: &self.local,
            running: &self.running,
            auth_ready: true,
            access_expires_at: 2000,
            refresh_at: 1900,
            authorization_locked: false,
            pending_login: false,
            pending_logout: false,
            pending_revoke: false,
            pending_publication: false,
            peer_revoked: false,
            gate_denied: &self.gate_denied,
            paused: &self.paused,
            stopping: &self.stopping,
            cancelled: &self.cancelled,
        }
    }
    fn read<'a>(&'a self, millis: u64, heartbeat: &'a HeartbeatObservation) -> PeerRead<'a> {
        PeerRead {
            origin: &self.origin,
            request_started: self.start + Duration::from_millis(millis),
            wall_at_request_start: 1000 + millis / 1000,
            original_heartbeat: heartbeat,
            consumer_window: WindowIdentityId::from_bytes([3; 16]).unwrap(),
            consumer_identity: &self.consumer,
            consumer_pin: self.consumer_pin,
            signed_grant: &self.signed,
            authority: &self.authority,
            authority_expires_at: 1080,
        }
    }
    fn core(&self) -> GateCore {
        self.try_core().unwrap()
    }
    fn try_core(&self) -> Result<GateCore> {
        let canonical = self.context.canonical().map_err(|_| GateError::Disposed)?;
        GateCore::new(
            &canonical,
            &self.signed,
            &self.admission,
            self.read(0, &self.heartbeat),
            &self.facts(),
            &mut || self.now(0),
        )
    }
    fn snapshot(&self, index: usize) -> RpcCall {
        RpcCall::TerminalSnapshot(TerminalReadParams {
            terminal: self.running[index].clone(),
        })
    }
    fn input(&self, index: usize) -> RpcCall {
        RpcCall::TerminalInput(TerminalInputParams {
            terminal: self.running[index].clone(),
            lease: LeaseBinding {
                token: "synthetic-lease".to_owned().try_into().unwrap(),
                version: DecimalU64(1),
            },
            input_id: DecimalU64(1),
            input_seq: lomi_remote_protocol::streams::InputSeq(DecimalU64(1)),
            bytes: BoundedList(vec![1u8]),
        })
    }
    fn close(&self, index: usize) -> RpcCall {
        let terminal = self.running[index].clone();
        RpcCall::TerminalClose(TerminalCloseParams {
            mutation: MutationContext {
                operation_id: OperationId::from_bytes([26; 16]).unwrap(),
                context: terminal.workspace.clone(),
                expected_revision: DecimalU64(1),
            },
            pane_id: terminal.pane_id,
            expected_session: Some(terminal),
        })
    }
    fn request(&self, call: RpcCall, timeout: u64) -> RpcRequest {
        RpcRequest {
            v: ApplicationMajor,
            r#type: RequestKind::Request,
            request_id: "synthetic-request-27".to_owned().try_into().unwrap(),
            timeout_ms: TimeoutMs::new(timeout).unwrap(),
            call,
        }
    }
    fn renew(&mut self, core: &mut GateCore, millis: u64) {
        self.heartbeat.request_started = self.start + Duration::from_millis(millis);
        self.heartbeat.wall_at_request_start = 1000 + millis / 1000;
        core.refresh(
            self.read(millis, &self.heartbeat),
            &self.facts(),
            &mut || self.now(millis + 1),
        )
        .unwrap();
    }
}

#[test]
fn consumer_actor_exact_context_and_narrowed_capabilities_are_retained() {
    let f = Fixture::new(observe(), true);
    let core = f.core();
    assert_eq!(core.binding.actor.to_bytes(), [5; 16]);
    assert_ne!(core.binding.actor.to_bytes(), f.host.host_id.to_bytes());
    assert_eq!(core.binding.canonical, f.context.canonical().unwrap());
    assert_eq!(core.binding.context.grant.capabilities, observe());
}
#[test]
fn one_field_protected_owner_and_runtime_mismatches_poison_without_revival() {
    for scenario in 0..10 {
        let mut f = Fixture::new(observe(), true);
        let mut core = f.core();
        match scenario {
            0 => f.host.account_id = AccountId::from_bytes([31; 16]).unwrap(),
            1 => f.host.host_authorization_id = HostAuthorizationId::from_bytes([31; 16]).unwrap(),
            2 => f.host.fingerprint[0] ^= 1,
            3 => f.host.access_epoch += 1,
            4 => f.scope.authorization_generation += 1,
            5 => f.scope.owner_generation += 1,
            6 => f.scope.owner_runtime_id = RuntimeId::from_bytes([31; 16]).unwrap(),
            7 => f.runtime.runtime_generation.0 += 1,
            8 => f.runtime.runtime_id = RuntimeId::from_bytes([31; 16]).unwrap(),
            _ => f.scope.remote_api_origin = "https://other.example".into(),
        }
        assert_eq!(
            core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
            Err(GateError::Disposed)
        );
        f.host = core.binding.host.clone();
        f.scope = core.binding.scope.clone();
        f.runtime = f.heartbeat.runtime.clone();
        assert_eq!(
            core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(2)),
            Err(GateError::Disposed)
        );
    }
}
#[test]
fn current_peer_family_session_revision_pin_and_membership_changes_poison() {
    for scenario in 0..7 {
        let mut f = Fixture::new(observe(), true);
        let mut core = f.core();
        match scenario {
            0 => f.authority.consumer_authorization_id = [31; 16],
            1 => f.authority.account_session_id = "different-session".into(),
            2 => f.authority.grant_revision += 1,
            3 => f.consumer_pin[0] ^= 1,
            4 => f.authority.host_authorization_id = [31; 16],
            5 => {
                let mut membership = f.context.terminal.clone().unwrap();
                membership.session_epoch = [31; 16];
                f.authority.terminal_membership = Some(membership);
            }
            _ => f.authority.workspace_epoch = [31; 16],
        }
        assert_eq!(
            core.refresh(f.read(1, &f.heartbeat), &f.facts(), &mut || f.now(2)),
            Err(GateError::Disposed)
        );
        assert!(core.disposed);
    }
}
#[test]
fn observe_control_manage_rights_are_registry_derived_and_denials_do_not_poison() {
    for (rights, input, close) in [
        (observe(), false, false),
        (control(), true, false),
        (manage(), false, true),
    ] {
        let f = Fixture::new(rights, true);
        let mut core = f.core();
        assert_eq!(
            core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
            Ok(())
        );
        assert_eq!(
            core.evaluate(&f.input(0), &f.facts(), &mut || f.now(1))
                .is_ok(),
            input
        );
        assert_eq!(
            core.evaluate(&f.close(0), &f.facts(), &mut || f.now(1))
                .is_ok(),
            close
        );
        assert!(!core.disposed);
        assert_eq!(
            core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
            Ok(())
        );
    }
}
/// Lifecycle calls over a workspace channel; `stale` swaps the CAS token for a
/// session that is no longer running anywhere.
fn lifecycle_calls(f: &Fixture, stale: bool) -> [RpcCall; 4] {
    let mutation = |id: u8| MutationContext {
        operation_id: OperationId::from_bytes([id; 16]).unwrap(),
        context: f.running[0].workspace.clone(),
        expected_revision: DecimalU64(1),
    };
    let mut token = f.running[0].clone();
    if stale {
        token.session_id = TerminalSessionId::from_bytes([77; 16]).unwrap();
    }
    let profile: HostProfileId = "default".to_owned().try_into().unwrap();
    [
        RpcCall::TerminalCreate(TerminalCreateParams {
            mutation: mutation(41),
            tab_name: "t".to_owned().try_into().unwrap(),
            profile_id: profile.clone(),
        }),
        RpcCall::TerminalSplit(TerminalSplitParams {
            mutation: mutation(42),
            tab_id: TabId::from_bytes([1; 16]).unwrap(),
            pane_id: f.running[0].pane_id,
            axis: SplitAxis::Horizontal,
            profile_id: profile.clone(),
        }),
        RpcCall::TerminalClose(TerminalCloseParams {
            mutation: mutation(43),
            pane_id: token.pane_id,
            expected_session: Some(token.clone()),
        }),
        RpcCall::TerminalRestart(TerminalRestartParams {
            mutation: mutation(44),
            pane_id: token.pane_id,
            expected_session: Some(token),
            profile_id: profile,
        }),
    ]
}

#[test]
fn lifecycle_methods_need_manage_and_a_workspace_channel_and_never_poison() {
    // manage on a workspace channel: allowed, even for a CAS token whose
    // session is gone (an exact retry must reach duplicate lookup).
    for stale in [false, true] {
        let f = Fixture::new(manage(), false);
        let mut core = f.core();
        for call in lifecycle_calls(&f, stale) {
            assert_eq!(
                core.evaluate(&call, &f.facts(), &mut || f.now(1)),
                Ok(()),
                "{:?} stale={stale}",
                call.method()
            );
        }
        assert!(!core.disposed);
    }
    // Missing terminal.manage: every lifecycle method is a non-poisoning denial.
    for rights in [observe(), control()] {
        let f = Fixture::new(rights, false);
        let mut core = f.core();
        for call in lifecycle_calls(&f, false) {
            assert_eq!(
                core.evaluate(&call, &f.facts(), &mut || f.now(1)),
                Err(GateError::Denied),
                "{:?}",
                call.method()
            );
        }
        assert!(!core.disposed);
        assert_eq!(
            core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
            Ok(())
        );
    }
    // A terminal-scoped channel can never create/split, and close/restart
    // keep the strict live-target requirement.
    let f = Fixture::new(manage(), true);
    let mut core = f.core();
    let [create, split, close, restart] = lifecycle_calls(&f, false);
    for call in [create, split] {
        assert_eq!(
            core.evaluate(&call, &f.facts(), &mut || f.now(1)),
            Err(GateError::Denied)
        );
    }
    for call in [close, restart] {
        assert_eq!(core.evaluate(&call, &f.facts(), &mut || f.now(1)), Ok(()));
    }
    let [_, _, close, restart] = lifecycle_calls(&f, true);
    for call in [close, restart] {
        assert_eq!(
            core.evaluate(&call, &f.facts(), &mut || f.now(1)),
            Err(GateError::Denied)
        );
    }
    assert!(!core.disposed);
}
#[test]
fn terminal_purpose_rejects_sibling_and_workspace_scope_but_stays_usable() {
    let mut f = Fixture::new(observe(), true);
    // The fresh current-pairing read deliberately carries no terminal
    // membership. GateCore must derive it from the exact live target instead.
    f.authority.terminal_membership = None;
    let mut core = f.core();
    assert_eq!(
        core.peer.authority.terminal_membership, f.context.terminal,
        "the established proof stores the locally verified target projection"
    );
    assert_eq!(
        core.evaluate(&f.snapshot(1), &f.facts(), &mut || f.now(1)),
        Err(GateError::Denied)
    );
    let workspace = RpcCall::WorkspaceGet(WorkspaceReadParams {
        context: f.running[0].workspace.clone(),
    });
    assert_eq!(
        core.evaluate(&workspace, &f.facts(), &mut || f.now(1)),
        Err(GateError::Denied)
    );
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
        Ok(())
    );
}

#[test]
fn terminal_projection_requires_running_local_and_acknowledged_target_membership() {
    for missing_source in ["running", "local", "acknowledged"] {
        let mut f = Fixture::new(observe(), true);
        f.authority.terminal_membership = None;
        match missing_source {
            "running" => {
                f.running.remove(0);
            }
            "local" => {
                f.local.running_terminals =
                    PublicationTerminals::try_from(vec![published(&f.running[1])]).unwrap();
            }
            "acknowledged" => {
                f.acknowledged.workspaces =
                    PublicationWorkspaces::try_from(vec![PublishedWorkspace {
                        workspace_id: f.local.workspace_id,
                        workspace_epoch: f.local.workspace_epoch,
                        terminals: PublicationTerminals::try_from(vec![published(&f.running[1])])
                            .unwrap(),
                    }])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            f.try_core().is_err(),
            "terminal proof accepted target absent from {missing_source}"
        );
    }
}

#[test]
fn terminal_projection_rejects_nonmatching_remote_membership_and_invalid_purpose_shape() {
    let mut f = Fixture::new(observe(), true);
    let mut mismatched = f.context.terminal.clone().unwrap();
    mismatched.session_epoch = [31; 16];
    f.authority.terminal_membership = Some(mismatched);
    assert!(
        f.try_core().is_err(),
        "mismatched remote membership was accepted"
    );

    let f = Fixture::new(observe(), false);
    let mut terminal_without_target = f.context.clone();
    terminal_without_target.purpose = ChannelPurposeV3::Terminal;
    assert!(!RemoteConnectionState::active_rpc_purpose(
        &terminal_without_target
    ));
    assert!(terminal_without_target.canonical().is_err());

    let mut workspace_with_target = f.context.clone();
    workspace_with_target.terminal = Some(TerminalTargetV3 {
        pane_id: [11; 16],
        session_id: [12; 16],
        session_epoch: [13; 16],
        terminal_profile: "lomi-rust-grid-v1-experimental".into(),
    });
    assert!(!RemoteConnectionState::active_rpc_purpose(
        &workspace_with_target
    ));
    assert!(workspace_with_target.canonical().is_err());

    let mut wrong_profile = Fixture::new(observe(), true);
    wrong_profile
        .context
        .terminal
        .as_mut()
        .unwrap()
        .terminal_profile = "other".into();
    assert!(wrong_profile.try_core().is_err());
}

#[test]
fn terminal_projection_does_not_bypass_workspace_fence_or_runtime_checks() {
    for mismatch in ["workspace", "runtime"] {
        let mut f = Fixture::new(observe(), true);
        f.authority.terminal_membership = None;
        match mismatch {
            "workspace" => {
                f.running[0].workspace.workspace_epoch =
                    WorkspaceEpoch::from_bytes([31; 16]).unwrap();
            }
            "runtime" => f.runtime.runtime_generation.0 += 1,
            _ => unreachable!(),
        }
        assert!(
            f.try_core().is_err(),
            "terminal projection bypassed the {mismatch} fence"
        );
    }
    let mut f = Fixture::new(observe(), true);
    f.authority.terminal_membership = None;
    let mut core = f.core();
    f.local.fence += 1;
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
        Err(GateError::Disposed)
    );
    f.local.fence -= 1;
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(2)),
        Err(GateError::Disposed),
        "restoring a fence must not revive a disposed terminal connection"
    );
}

#[test]
fn terminal_projection_rejects_each_changed_target_tuple_in_every_membership_source() {
    for source in ["running", "local", "acknowledged"] {
        for field in ["pane", "session", "epoch"] {
            let mut f = Fixture::new(observe(), true);
            f.authority.terminal_membership = None;
            let mutate = |entry: &mut PublishedTerminal| match field {
                "pane" => entry.pane_id = PaneId::from_bytes([31; 16]).unwrap(),
                "session" => entry.session_id = TerminalSessionId::from_bytes([31; 16]).unwrap(),
                "epoch" => entry.session_epoch = SessionEpoch::from_bytes([31; 16]).unwrap(),
                _ => unreachable!(),
            };
            match source {
                "running" => match field {
                    "pane" => f.running[0].pane_id = PaneId::from_bytes([31; 16]).unwrap(),
                    "session" => {
                        f.running[0].session_id = TerminalSessionId::from_bytes([31; 16]).unwrap()
                    }
                    "epoch" => {
                        f.running[0].session_epoch = SessionEpoch::from_bytes([31; 16]).unwrap()
                    }
                    _ => unreachable!(),
                },
                "local" => {
                    let mut entries = f.local.running_terminals.as_slice().to_vec();
                    mutate(&mut entries[0]);
                    f.local.running_terminals = PublicationTerminals::try_from(entries).unwrap();
                }
                "acknowledged" => {
                    let mut entry = published(&f.running[0]);
                    mutate(&mut entry);
                    f.acknowledged.workspaces =
                        PublicationWorkspaces::try_from(vec![PublishedWorkspace {
                            workspace_id: f.local.workspace_id,
                            workspace_epoch: f.local.workspace_epoch,
                            terminals: PublicationTerminals::try_from(vec![
                                entry,
                                published(&f.running[1]),
                            ])
                            .unwrap(),
                        }])
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                f.try_core().is_err(),
                "terminal projection accepted a changed {field} in {source}"
            );
        }
    }
}

#[test]
fn terminal_proof_refresh_remains_live_after_channel_admission_expiry() {
    // Deterministic owner-clock coverage only; this is not a wall-clock or
    // production heartbeat qualification run.
    let mut f = Fixture::with_expiry(observe(), true, 1100, 1030);
    f.authority.terminal_membership = None;
    let mut core = f.core();
    for millis in (4_000..=32_000).step_by(4_000) {
        f.heartbeat.request_started = f.start + Duration::from_millis(millis);
        f.heartbeat.wall_at_request_start = 1000 + millis / 1000;
        core.refresh(f.read(millis, &f.heartbeat), &f.facts(), &mut || {
            f.now(millis + 1)
        })
        .unwrap();
    }
    assert!(f.now(32_002).wall >= Duration::from_secs(1032));
    assert!(core.live(&f.facts(), &mut || f.now(32_002)).is_ok());
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(32_003)),
        Ok(()),
        "an established terminal channel must not reapply its short admission expiry"
    );
}

#[test]
fn expired_terminal_peer_proof_cannot_be_revived_by_a_fresh_pairing_read() {
    let mut f = Fixture::new(observe(), true);
    f.authority.terminal_membership = None;
    let mut core = f.core();
    f.heartbeat.request_started = f.start + Duration::from_millis(6_000);
    f.heartbeat.wall_at_request_start = 1006;
    assert_eq!(
        core.refresh(f.read(6_000, &f.heartbeat), &f.facts(), &mut || f
            .now(6_001),),
        Err(GateError::Disposed)
    );
    assert!(core.disposed);
    f.heartbeat.request_started = f.start + Duration::from_millis(7_000);
    f.heartbeat.wall_at_request_start = 1007;
    assert_eq!(
        core.refresh(f.read(7_000, &f.heartbeat), &f.facts(), &mut || f
            .now(7_001),),
        Err(GateError::Disposed)
    );
}
#[test]
fn unsupported_stored_operation_rights_have_no_static_or_local_owner_fallback() {
    let f = Fixture::new(manage(), false);
    let mut core = f.core();
    let call = RpcCall::OperationStatus(OperationStatusParams {
        context: f.running[0].workspace.clone(),
        operation_id: OperationId::from_bytes([28; 16]).unwrap(),
    });
    assert_eq!(
        core.evaluate(&call, &f.facts(), &mut || f.now(1)),
        Err(GateError::Denied)
    );
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
        Ok(())
    );
}
#[test]
fn old_get_cannot_be_extended_by_new_heartbeat_or_revive_after_loss() {
    let mut f = Fixture::new(observe(), true);
    let mut core = f.core();
    let original = f.heartbeat.clone();
    f.heartbeat.request_started = f.start + Duration::from_secs(4);
    f.heartbeat.wall_at_request_start = 1004;
    assert_eq!(
        core.refresh(f.read(0, &original), &f.facts(), &mut || f.now(4001)),
        Err(GateError::Denied)
    );
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(5000)),
        Err(GateError::Disposed)
    );
    assert_eq!(
        core.refresh(f.read(4000, &f.heartbeat), &f.facts(), &mut || f.now(5001)),
        Err(GateError::Disposed)
    );
}
#[test]
fn new_matching_get_refreshes_before_loss_and_healthy_established_gate_outlives_admission() {
    let mut f = Fixture::new(observe(), true);
    let mut core = f.core();
    for millis in (4000..=32000).step_by(4000) {
        f.renew(&mut core, millis);
    }
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(32002)),
        Ok(())
    );
    assert!(core.binding.context.expires_at < 1032);
    assert!(!core.disposed);
    // A pending completion at this time must fail, despite healthy ongoing grant.
    assert_eq!(core.admission_live(f.now(32002)), Err(GateError::Disposed));
}
#[test]
fn initial_or_late_handshake_admission_cannot_start_after_original_expiry() {
    let f = Fixture::new(observe(), true);
    assert!(
        GateCore::new(
            &f.context.canonical().unwrap(),
            &f.signed,
            &f.admission,
            f.read(0, &f.heartbeat),
            &f.facts(),
            &mut || f.now(30000)
        )
        .is_err()
    );
    let mut core = f.core();
    assert_eq!(core.admission_live(f.now(30000)), Err(GateError::Disposed));
}
#[test]
fn grant_or_recipient_expiry_while_waiting_poison_before_effect() {
    for recipient in [false, true] {
        let f = Fixture::with_expiry(control(), true, if recipient { 1100 } else { 1001 }, 1001);
        let mut read = f.read(0, &f.heartbeat);
        if recipient {
            read.authority_expires_at = 1001;
        }
        let mut core = GateCore::new(
            &f.context.canonical().unwrap(),
            &f.signed,
            &f.admission,
            read,
            &f.facts(),
            &mut || f.now(0),
        )
        .unwrap();
        let operation = Operation::new(Instant::now() + Duration::from_secs(120), &f.cancelled);
        let queued = core
            .queue(
                &f.request(f.input(0), 120000),
                &operation,
                &f.facts(),
                &mut || f.now(1),
            )
            .unwrap();
        assert!(matches!(
            core.after_wait(&queued, &operation, &f.facts(), &mut || f.now(1000)),
            Err(GateError::Disposed)
        ));
        assert!(core.disposed);
    }
}
#[test]
fn request_deadline_and_authority_are_resampled_after_wait_without_resigning_request() {
    let f = Fixture::new(control(), true);
    let mut core = f.core();
    let request = f.request(f.input(0), 1000);
    let operation = Operation::new(Instant::now() + Duration::from_secs(120), &f.cancelled);
    let queued = core
        .queue(&request, &operation, &f.facts(), &mut || f.now(0))
        .unwrap();
    assert_eq!(queued.request(), &request);
    assert!(matches!(
        core.after_wait(&queued, &operation, &f.facts(), &mut || f.now(1000)),
        Err(GateError::Denied)
    ));
    assert!(!core.disposed);
    // The expired admission is never renewed. A distinct request admission is explicit.
    let operation = Operation::new(Instant::now() + Duration::from_secs(120), &f.cancelled);
    let q = core
        .queue(&request, &operation, &f.facts(), &mut || f.now(1001))
        .unwrap();
    assert_eq!(
        core.after_wait(&q, &operation, &f.facts(), &mut || f.now(1002))
            .unwrap(),
        request
    );
}
#[test]
fn original_freshness_consumed_during_validation_or_lock_wait_is_not_refreshed() {
    let f = Fixture::new(observe(), true);
    let mut core = f.core();
    let mut samples = 0;
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || {
            samples += 1;
            f.now(if samples == 1 { 4999 } else { 5000 })
        }),
        Err(GateError::Disposed)
    );
    assert_eq!(samples, 2);
}
#[test]
fn volatile_latches_and_all_pending_or_locked_owner_states_poison() {
    for scenario in 0..11 {
        let f = Fixture::new(observe(), true);
        let mut core = f.core();
        let mut facts = f.facts();
        match scenario {
            0 => f.gate_denied.store(true, Ordering::Release),
            1 => f.paused.store(true, Ordering::Release),
            2 => f.stopping.store(true, Ordering::Release),
            3 => f.cancelled.store(true, Ordering::Release),
            4 => facts.authorization_locked = true,
            5 => facts.pending_logout = true,
            6 => facts.pending_revoke = true,
            7 => facts.pending_publication = true,
            8 => facts.pending_login = true,
            9 => facts.auth_ready = false,
            _ => facts.peer_revoked = true,
        }
        assert_eq!(
            core.evaluate(&f.snapshot(0), &facts, &mut || f.now(1)),
            Err(GateError::Disposed)
        );
    }
}
#[test]
fn unshare_reshare_fence_and_ack_runtime_membership_or_local_exit_poison() {
    for scenario in 0..6 {
        let mut f = Fixture::new(observe(), true);
        let mut core = f.core();
        match scenario {
            0 => f.local.consent = false,
            1 => f.local.fence += 1,
            2 => f.local.workspace_epoch = WorkspaceEpoch::from_bytes([31; 16]).unwrap(),
            3 => f.acknowledged.state.server_runtime.runtime_generation.0 += 1,
            4 => f.acknowledged.workspaces = PublicationWorkspaces::try_from(vec![]).unwrap(),
            _ => {
                f.running.remove(0);
            }
        };
        assert_eq!(
            core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
            Err(GateError::Disposed)
        );
    }
}
#[test]
fn ordinary_ack_sequence_growth_does_not_bind_channel_to_historical_publication() {
    let mut f = Fixture::new(observe(), true);
    let mut core = f.core();
    f.acknowledged.state.acknowledged_publication_seq.0 += 1;
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
        Ok(())
    );
}
#[test]
fn clock_rollback_or_new_hb_cannot_revive_disposed_connection() {
    let mut f = Fixture::new(observe(), true);
    let mut core = f.core();
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(2)),
        Ok(())
    );
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1)),
        Err(GateError::Disposed)
    );
    f.heartbeat.request_started = f.start + Duration::from_millis(3);
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(3)),
        Err(GateError::Disposed)
    );
}
#[test]
fn cached_response_and_stream_equivalent_gates_reject_new_exit_and_revocation() {
    let mut f = Fixture::new(observe(), false);
    let mut core = f.core();
    let cached = f.request(f.snapshot(0), 1000);
    assert_eq!(
        core.evaluate(&cached.call, &f.facts(), &mut || f.now(1)),
        Ok(())
    );
    f.running.remove(0);
    assert_eq!(
        core.evaluate(&cached.call, &f.facts(), &mut || f.now(2)),
        Err(GateError::Denied)
    );
    assert!(!core.disposed);
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(3)),
        Ok(())
    );
    f.gate_denied.store(true, Ordering::Release);
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(4)),
        Err(GateError::Disposed)
    );
}
#[test]
fn queue_capacity_is_one_and_ticket_cannot_cross_connection_instance() {
    let f = Fixture::new(observe(), true);
    let mut a = f.core();
    let mut b = f.core();
    let operation = Operation::new(Instant::now() + Duration::from_secs(120), &f.cancelled);
    let queued = a
        .queue(
            &f.request(f.snapshot(0), 1000),
            &operation,
            &f.facts(),
            &mut || f.now(0),
        )
        .unwrap();
    assert!(matches!(
        a.queue(
            &f.request(f.snapshot(0), 1000),
            &operation,
            &f.facts(),
            &mut || f.now(0)
        ),
        Err(GateError::Busy)
    ));
    assert!(matches!(
        b.after_wait(&queued, &operation, &f.facts(), &mut || f.now(1)),
        Err(GateError::Denied)
    ));
    assert!(!b.disposed);
}
#[test]
fn malformed_canonical_context_signature_and_default_git_execute_are_rejected() {
    let f = Fixture::new(observe(), true);
    let mut bad = f.context.canonical().unwrap();
    bad.push(0);
    assert!(
        GateCore::new(
            &bad,
            &f.signed,
            &f.admission,
            f.read(0, &f.heartbeat),
            &f.facts(),
            &mut || f.now(0)
        )
        .is_err()
    );
    let mut bad_admission = f.admission.clone();
    bad_admission.signature[0] ^= 1;
    assert!(
        GateCore::new(
            &f.context.canonical().unwrap(),
            &f.signed,
            &bad_admission,
            f.read(0, &f.heartbeat),
            &f.facts(),
            &mut || f.now(0)
        )
        .is_err()
    );
    let f = Fixture::new(
        CapabilitySet::try_from(Capability::ALL.to_vec()).unwrap(),
        true,
    );
    assert!(
        GateCore::new(
            &f.context.canonical().unwrap(),
            &f.signed,
            &f.admission,
            f.read(0, &f.heartbeat),
            &f.facts(),
            &mut || f.now(0)
        )
        .is_err()
    );
}

#[test]
fn exact_channel_grant_id_revision_and_capability_context_are_not_replaceable() {
    for scenario in 0..4 {
        let f = Fixture::new(observe(), true);
        let mut context = f.context.clone();
        match scenario {
            0 => context.channel_id = [31; 16],
            1 => context.grant.grant_id = [31; 16],
            2 => context.grant.grant_revision += 1,
            _ => context.grant.capabilities = control(),
        }
        assert!(
            GateCore::new(
                &context.canonical().unwrap(),
                &f.signed,
                &f.admission,
                f.read(0, &f.heartbeat),
                &f.facts(),
                &mut || f.now(0)
            )
            .is_err()
        );
    }
}
#[test]
fn consumer_role_or_registered_key_substitution_is_rejected() {
    for role in [Role::Host, Role::Device] {
        let mut f = Fixture::new(observe(), true);
        let mut core = f.core();
        f.consumer = Identity::generate([1; 16], [3; 16], role, 1)
            .unwrap()
            .public_bundle()
            .to_wire()
            .unwrap();
        assert_eq!(
            core.refresh(f.read(1, &f.heartbeat), &f.facts(), &mut || f.now(2)),
            Err(GateError::Disposed)
        );
    }
}
#[test]
fn shortened_current_recipient_ceiling_or_refresh_deadline_is_not_ignored() {
    for refresh in [false, true] {
        let f = Fixture::new(observe(), true);
        let mut core = f.core();
        let mut facts = f.facts();
        if refresh {
            facts.refresh_at = 1001;
        } else {
            facts.access_expires_at = 1001;
        }
        assert_eq!(
            core.evaluate(&f.snapshot(0), &facts, &mut || f.now(1000)),
            Err(GateError::Disposed)
        );
    }
    let f = Fixture::new(observe(), true);
    let mut core = f.core();
    let mut read = f.read(1, &f.heartbeat);
    read.authority_expires_at = 1001;
    // Established authority may narrow below historical context expiry; do not
    // re-run 30s admission validation while refreshing a healthy connection.
    assert_eq!(core.refresh(read, &f.facts(), &mut || f.now(2)), Ok(()));
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(1000)),
        Err(GateError::Disposed)
    );
}
#[test]
fn admission_never_exceeds_current_recipient_ceiling_and_profile_is_canonical() {
    let f = Fixture::new(observe(), true);
    let mut read = f.read(0, &f.heartbeat);
    read.authority_expires_at = 1001;
    assert!(
        GateCore::new(
            &f.context.canonical().unwrap(),
            &f.signed,
            &f.admission,
            read,
            &f.facts(),
            &mut || f.now(0)
        )
        .is_err()
    );
    let mut bad = f.context.clone();
    bad.terminal.as_mut().unwrap().terminal_profile = "other-profile".into();
    assert!(bad.canonical().is_err());
}
#[test]
fn atomic_logout_during_validation_poison_is_not_hidden_by_unchanged_durable_facts() {
    let f = Fixture::new(observe(), true);
    let mut core = f.core();
    let mut samples = 0;
    assert_eq!(
        core.evaluate(&f.snapshot(0), &f.facts(), &mut || {
            samples += 1;
            if samples == 2 {
                f.gate_denied.store(true, Ordering::Release);
            }
            f.now(1)
        }),
        Err(GateError::Disposed)
    );
    assert!(core.disposed);
    assert_eq!(samples, 2);
}
#[test]
fn forward_wall_then_backward_correction_and_monotonic_regression_cannot_revive() {
    for wall in [true, false] {
        let f = Fixture::new(observe(), true);
        let mut core = f.core();
        assert_eq!(
            core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(3)),
            Ok(())
        );
        let mut regressed = f.now(4);
        if wall {
            regressed.wall = Duration::from_secs(1000);
        } else {
            regressed.monotonic = f.start + Duration::from_millis(2);
        }
        assert_eq!(
            core.evaluate(&f.snapshot(0), &f.facts(), &mut || regressed),
            Err(GateError::Disposed)
        );
        assert_eq!(
            core.evaluate(&f.snapshot(0), &f.facts(), &mut || f.now(5)),
            Err(GateError::Disposed)
        );
    }
}

#[test]
fn queued_request_rejects_another_admission_without_consuming_original_and_busy_caps_budget() {
    let f = Fixture::new(observe(), true);
    let mut core = f.core();
    let request = f.request(f.snapshot(0), 120000);
    let cancellation = AtomicBool::new(false);
    let original_deadline = Instant::now() + Duration::from_secs(60);
    let operation = Operation::new(original_deadline, &cancellation);
    let queued = core
        .queue(&request, &operation, &f.facts(), &mut || f.now(0))
        .unwrap();
    let other = Operation::new(original_deadline, &cancellation);
    assert_eq!(
        core.after_wait(&queued, &other, &f.facts(), &mut || f.now(1)),
        Err(GateError::Denied)
    );
    assert_eq!(core.pending, Some(queued.sequence));
    assert!(operation.is_same_admission(&queued.operation));
    let waiting = Operation::new(original_deadline, &cancellation);
    assert!(matches!(
        core.queue(&request, &waiting, &f.facts(), &mut || f.now(2)),
        Err(GateError::Busy)
    ));
    assert_eq!(waiting.deadline(), original_deadline);
    assert_eq!(queued.request(), &request);
    assert_eq!(
        core.after_wait(&queued, &operation, &f.facts(), &mut || f.now(3))
            .unwrap(),
        request
    );
    let retried = core
        .queue(&request, &waiting, &f.facts(), &mut || f.now(100))
        .unwrap();
    assert_eq!(retried.deadline, original_deadline);
    assert!(waiting.is_same_admission(&retried.operation));
    assert_eq!(
        core.after_wait(&retried, &waiting, &f.facts(), &mut || f.now(101))
            .unwrap(),
        request
    );
    assert_eq!(
        core.after_wait(&retried, &waiting, &f.facts(), &mut || f.now(102)),
        Err(GateError::Denied)
    );
}

#[test]
fn queued_original_cancellation_is_sticky_after_external_latch_reset() {
    let f = Fixture::new(observe(), true);
    let mut core = f.core();
    let request = f.request(f.snapshot(0), 120000);
    let cancellation = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(60);
    let operation = Operation::new(deadline, &cancellation);
    let queued = core
        .queue(&request, &operation, &f.facts(), &mut || f.now(0))
        .unwrap();
    cancellation.store(true, Ordering::Release);
    assert_eq!(
        core.after_wait(&queued, &operation, &f.facts(), &mut || f.now(1)),
        Err(GateError::Denied)
    );
    cancellation.store(false, Ordering::Release);
    assert!(operation.check().is_err());
    assert_eq!(
        core.after_wait(&queued, &operation, &f.facts(), &mut || f.now(2)),
        Err(GateError::Denied)
    );
    let replacement = Operation::new(deadline + Duration::from_secs(60), &cancellation);
    assert_eq!(
        core.after_wait(&queued, &replacement, &f.facts(), &mut || f.now(3)),
        Err(GateError::Denied)
    );
    assert_eq!(queued.deadline, deadline);
    assert!(!core.disposed);
}

// Actual protected HostAuth object ownership + real consumer Noise cryptography.
// The reused provider is a trusted IN-MEMORY synthetic SecretStorage fixture;
// its declared ProtectedFile kind is not proof of an OS keyring/file provider.
// PeerRead/ACK/Running/owner facts below are synthetic, NOT TLS/endpoint/Store
// snapshot provenance. There is no dispatcher, terminal effect or live transport.
mod protected_noise {
    use super::*;
    use lomi_remote_crypto::{Channel, Handshake};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn actual_now() -> TrustedNow {
        let monotonic = Instant::now();
        let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        TrustedNow { wall, monotonic }
    }
    fn ready(test: impl FnOnce(&mut HostAuth<'_, dyn SecretStorage + '_>, &Config)) {
        use super::super::super::tests::{test_store, unconfirmed_storage};
        let (_dir, store, config) = test_store();
        let host = store.lock().unwrap().identity().host_id;
        let mut provider = unconfirmed_storage(&config, host);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1005,
        )
        .unwrap();
        auth.confirm_registration(HostRegisterResult {
            host_id: host,
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
        // Public rotation migrates the legitimate fixture to current wall time.
        // No Ready record, key, channel, verified token or secret bundle is forged.
        auth.prepare_rotation(actual_now().wall.as_secs()).unwrap();
        let rotation = auth.rotation_request(actual_now().wall.as_secs()).unwrap();
        auth.accept_rotation(
            HostAuthorizationResult {
                account_id: AccountId::from_bytes([4; 16]).unwrap(),
                host_id: host,
                host_authorization_id: rotation.host_authorization_id,
                access: "synthetic_gate_rotated_access"
                    .to_owned()
                    .try_into()
                    .unwrap(),
                refresh: "synthetic_gate_rotated_refresh"
                    .to_owned()
                    .try_into()
                    .unwrap(),
                rotation_id: rotation.rotation_id,
                expires_in_seconds: DecimalU64(300),
            },
            actual_now().wall.as_secs(),
        )
        .unwrap();
        assert_eq!(auth.status(), lomi_host_auth::Status::Ready);
        test(&mut auth, &config);
    }
    struct NoiseFixture {
        f: Fixture,
        consumer: Identity,
        access_expires_at: u64,
        refresh_at: u64,
        original_admission_deadline: Instant,
    }
    impl NoiseFixture {
        fn new(auth: &HostAuth<'_, dyn SecretStorage + '_>, config: &Config, ttl: u64) -> Self {
            assert!((1..=30).contains(&ttl));
            // Setup the unrelated reusable DTO layout before channel observation.
            let mut f = Fixture::new(control(), true);
            let observed = actual_now();
            f.start = observed.monotonic;
            let now = observed.wall.as_secs();
            f.host = auth
                .public_host_identity(actual_now().wall.as_secs())
                .unwrap();
            f.origin = RemoteOrigin::new(config, "https://remote.example".into()).unwrap();
            f.scope.host_id = f.host.host_id;
            f.scope.remote_api_origin = f.origin.as_str().into();
            f.acknowledged.state.scope = f.scope.clone();
            f.heartbeat.scope = f.scope.clone();
            let consumer =
                Identity::generate(f.host.account_id.to_bytes(), [3; 16], Role::Device, 1).unwrap();
            f.consumer = consumer.public_bundle().to_wire().unwrap();
            f.consumer_pin = consumer.public_bundle().bundle.fingerprint().unwrap();
            let mut grant = f.context.grant.clone();
            grant.account_id = f.host.account_id.to_bytes();
            grant.host_id = f.host.host_id.to_bytes();
            grant.host_fingerprint = f.host.fingerprint;
            grant.host_authorization_id = f.host.host_authorization_id.to_bytes();
            grant.access_epoch = f.host.access_epoch;
            grant.consumer_fingerprint = f.consumer_pin;
            grant.expires_at = now + 100;
            f.context.grant = grant;
            f.context.issued_at = now;
            f.context.expires_at = now + ttl;
            f.authority.host_authorization_id = f.host.host_authorization_id.to_bytes();
            f.authority.access_epoch = f.host.access_epoch;
            f.heartbeat.request_started = observed.monotonic;
            f.heartbeat.wall_at_request_start = now;
            f.signed = auth
                .sign_grant_v3(&f.context.grant, actual_now().wall.as_secs())
                .unwrap();
            f.admission = auth
                .sign_channel_admission_v3(&f.context, actual_now().wall.as_secs())
                .unwrap();
            let deadlines = auth.credential_deadlines().unwrap();
            let original_admission_deadline = observed
                .monotonic
                .checked_add(
                    Duration::from_secs(f.context.expires_at)
                        .checked_sub(observed.wall)
                        .unwrap(),
                )
                .unwrap();
            Self {
                f,
                consumer,
                access_expires_at: deadlines.access_expires_at,
                refresh_at: deadlines.refresh_at,
                original_admission_deadline,
            }
        }
        fn facts(&self) -> OwnerFacts<'_> {
            let mut facts = self.f.facts();
            facts.access_expires_at = self.access_expires_at;
            facts.refresh_at = self.refresh_at;
            facts
        }
        fn peer(&self) -> PeerRead<'_> {
            let mut read = self.f.read(0, &self.f.heartbeat);
            read.wall_at_request_start = self.f.heartbeat.wall_at_request_start;
            read.authority_expires_at = self.f.context.grant.expires_at;
            read
        }
        fn begin(
            &self,
            auth: &HostAuth<'_, dyn SecretStorage + '_>,
        ) -> Result<PendingRemoteConnection> {
            PendingRemoteConnection::begin(
                auth,
                AdmissionInputs {
                    canonical_context: &self.f.context.canonical().unwrap(),
                    signed_grant: &self.f.signed,
                    admission: &self.f.admission,
                    peer: self.peer(),
                },
                &self.facts(),
                &mut actual_now,
            )
        }
        fn initiator(&self) -> Handshake {
            let host = SignedBundle::from_wire(&self.f.host.identity).unwrap();
            let consumer = self.consumer.public_bundle();
            let verified = self
                .f
                .admission
                .verify(
                    &self.f.signed,
                    &self.f.context,
                    &host,
                    &self.f.host.fingerprint,
                    &consumer,
                    &self.f.consumer_pin,
                    &self.f.authority,
                    actual_now().wall.as_secs(),
                )
                .unwrap();
            Handshake::new_v3(
                true,
                &self.consumer,
                verified,
                &host,
                &self.f.host.fingerprint,
                actual_now().wall.as_secs(),
            )
            .unwrap()
        }
        fn complete(
            &self,
            auth: &HostAuth<'_, dyn SecretStorage + '_>,
        ) -> (RemoteConnectionState, Channel) {
            let mut pending = self.begin(auth).unwrap();
            let mut consumer = self.initiator();
            pending
                .read(&consumer.write().unwrap(), &self.facts(), &mut actual_now)
                .unwrap();
            consumer
                .read(&pending.write(&self.facts(), &mut actual_now).unwrap())
                .unwrap();
            pending
                .read(&consumer.write().unwrap(), &self.facts(), &mut actual_now)
                .unwrap();
            let completed = pending.finish(&self.facts(), &mut actual_now).unwrap();
            (completed, consumer.finish().unwrap())
        }
    }

    #[test]
    fn genuine_protected_host_responder_and_consumer_noise_roundtrip_remain_gated() {
        ready(|auth, config| {
            let n = NoiseFixture::new(auth, config, 30);
            let (mut state, mut consumer) = n.complete(auth);
            assert_eq!(
                state.consumer_actor(),
                ConsumerAuthorizationId::from_bytes([5; 16]).unwrap()
            );
            assert_ne!(
                state.consumer_actor().to_bytes(),
                n.f.host.host_id.to_bytes()
            );
            assert_eq!(state.canonical_context(), n.f.context.canonical().unwrap());
            let request = n.f.request(n.f.input(0), 1000);
            let wire = serde_json::to_vec(&request).unwrap();
            let frame = consumer.seal_binary(n.f.context.channel_id, &wire).unwrap();
            state
                .cached_response(&request, &n.facts(), &mut actual_now)
                .unwrap();
            let plain = state
                .open_frame(&frame, &n.facts(), &mut actual_now)
                .unwrap();
            assert_eq!(plain.as_ref(), wire.as_slice());
            let decoded: RpcRequest = serde_json::from_slice(plain.as_ref()).unwrap();
            let operation =
                Operation::new(Instant::now() + Duration::from_secs(120), &n.f.cancelled);
            let queued = state
                .before_queue(&decoded, &operation, &n.facts(), &mut actual_now)
                .unwrap();
            assert_eq!(
                state
                    .after_wait(&queued, &operation, &n.facts(), &mut actual_now)
                    .unwrap(),
                request
            );
            state
                .cached_response(&request, &n.facts(), &mut actual_now)
                .unwrap();
            let reply = state
                .seal_frame(
                    b"gated response bytes; no effect",
                    &n.facts(),
                    &mut actual_now,
                )
                .unwrap();
            assert_eq!(
                &**consumer
                    .open_binary(n.f.context.channel_id, &reply)
                    .unwrap(),
                b"gated response bytes; no effect"
            );
            let sibling = n.f.request(n.f.snapshot(1), 1000);
            assert!(matches!(
                state.before_queue(&sibling, &operation, &n.facts(), &mut actual_now),
                Err(GateError::Denied)
            ));
            assert!(!state.core.disposed);
            state
                .terminal_stream(&n.f.running[0], &n.facts(), &mut actual_now)
                .unwrap();
            // New SYNTHETIC independently labelled observation, not an endpoint.
            let observed = actual_now();
            let mut peer = n.peer();
            peer.request_started = observed.monotonic;
            peer.wall_at_request_start = observed.wall.as_secs();
            state
                .refresh_peer(peer, &n.facts(), &mut actual_now)
                .unwrap();
            let stream = state
                .seal_frame(b"gated stream bytes", &n.facts(), &mut actual_now)
                .unwrap();
            assert_eq!(
                &**consumer
                    .open_binary(n.f.context.channel_id, &stream)
                    .unwrap(),
                b"gated stream bytes"
            );
            state.dispose();
            assert!(state.completed_channel.seal(b"disposed output").is_err());
        });
    }
    #[test]
    fn protected_begin_rejects_wrong_registered_pin_actor_and_exact_target() {
        ready(|auth, config| {
            for scenario in 0..3 {
                let mut n = NoiseFixture::new(auth, config, 30);
                match scenario {
                    0 => n.f.consumer_pin[0] ^= 1,
                    1 => n.f.authority.consumer_authorization_id = [55; 16],
                    _ => {
                        n.f.running[0].session_epoch = SessionEpoch::from_bytes([55; 16]).unwrap();
                    }
                }
                assert!(matches!(n.begin(auth), Err(GateError::Disposed)));
            }
        });
    }
    #[test]
    fn owned_protected_responder_cannot_construct_connection_before_noise_completion() {
        ready(|auth, config| {
            let n = NoiseFixture::new(auth, config, 30);
            let pending = n.begin(auth).unwrap();
            assert!(matches!(
                pending.finish(&n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
        });
    }
    #[test]
    fn authority_loss_during_real_noise_poison_is_irreversible() {
        ready(|auth, config| {
            let n = NoiseFixture::new(auth, config, 30);
            let mut pending = n.begin(auth).unwrap();
            let mut consumer = n.initiator();
            pending
                .read(&consumer.write().unwrap(), &n.facts(), &mut actual_now)
                .unwrap();
            n.f.gate_denied.store(true, Ordering::Release);
            assert!(matches!(
                pending.write(&n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
            n.f.gate_denied.store(false, Ordering::Release);
            assert!(matches!(
                pending.write(&n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
            assert!(matches!(
                pending.finish(&n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
        });
    }
    #[test]
    fn completed_real_noise_channel_disposes_on_current_authority_loss_without_effect() {
        ready(|auth, config| {
            let n = NoiseFixture::new(auth, config, 30);
            let (mut state, mut consumer) = n.complete(auth);
            let request = n.f.request(n.f.input(0), 1000);
            let operation =
                Operation::new(Instant::now() + Duration::from_secs(120), &n.f.cancelled);
            let queued = state
                .before_queue(&request, &operation, &n.facts(), &mut actual_now)
                .unwrap();
            n.f.cancelled.store(true, Ordering::Release);
            assert!(matches!(
                state.after_wait(&queued, &operation, &n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
            assert!(state.completed_channel.seal(b"no late output").is_err());
            let incoming = consumer
                .seal_binary(n.f.context.channel_id, b"late incoming")
                .unwrap();
            assert!(state.completed_channel.open(&incoming).is_err());
            n.f.cancelled.store(false, Ordering::Release);
            assert!(matches!(
                state.cached_response(&request, &n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
        });
    }
    #[test]
    fn real_elapsed_original_admission_deadline_blocks_pending_completion_and_late_begin() {
        ready(|auth, config| {
            let mut n = NoiseFixture::new(auth, config, 4);
            let mut pending = n.begin(auth).unwrap();
            let mut consumer = n.initiator();
            let first = consumer.write().unwrap();
            let deadline = n
                .original_admission_deadline
                .checked_add(Duration::from_millis(40))
                .unwrap();
            let outer = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
            while Instant::now() < deadline && Instant::now() < outer {
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(20)),
                );
            }
            assert!(Instant::now() >= deadline);
            assert!(actual_now().wall >= Duration::from_secs(n.f.context.expires_at));
            assert!(
                Instant::now() < n.f.start + Duration::from_secs(5),
                "original peer observation still fresh at admission expiry"
            );
            // A newer synthetic HB cannot rebase the ORIGINAL context deadline.
            let renewed = actual_now();
            n.f.heartbeat.request_started = renewed.monotonic;
            n.f.heartbeat.wall_at_request_start = renewed.wall.as_secs();
            assert!(matches!(
                pending.read(&first, &n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
            assert!(matches!(
                pending.finish(&n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
            // Supply a genuinely NEW (synthetic) matching read as well. Its
            // freshness cannot make the old signed admission valid again.
            let late = actual_now();
            let mut peer = n.peer();
            peer.request_started = late.monotonic;
            peer.wall_at_request_start = late.wall.as_secs();
            assert!(matches!(
                PendingRemoteConnection::begin(
                    auth,
                    AdmissionInputs {
                        canonical_context: &n.f.context.canonical().unwrap(),
                        signed_grant: &n.f.signed,
                        admission: &n.f.admission,
                        peer,
                    },
                    &n.facts(),
                    &mut actual_now
                ),
                Err(GateError::Disposed)
            ));
        });
    }
    #[test]
    fn protected_factory_rejects_another_actual_hostauth_even_with_valid_signed_facts() {
        ready(|first, config| {
            let n = NoiseFixture::new(first, config, 30);
            ready(|other, _| {
                assert_ne!(
                    first
                        .public_host_identity(actual_now().wall.as_secs())
                        .unwrap()
                        .host_id,
                    other
                        .public_host_identity(actual_now().wall.as_secs())
                        .unwrap()
                        .host_id
                );
                assert!(matches!(n.begin(other), Err(GateError::Disposed)));
            });
        });
    }
    #[test]
    fn completed_pending_noise_cannot_finish_after_original_admission_without_prior_failure() {
        ready(|auth, config| {
            let mut n = NoiseFixture::new(auth, config, 4);
            let mut pending = n.begin(auth).unwrap();
            let mut consumer = n.initiator();
            pending
                .read(&consumer.write().unwrap(), &n.facts(), &mut actual_now)
                .unwrap();
            consumer
                .read(&pending.write(&n.facts(), &mut actual_now).unwrap())
                .unwrap();
            pending
                .read(&consumer.write().unwrap(), &n.facts(), &mut actual_now)
                .unwrap();
            // Consumer transport completion proves all three real Noise messages
            // were processed BEFORE waiting; host still owns its pending responder.
            let _completed_consumer = consumer.finish().unwrap();
            assert!(!pending.core.disposed);
            assert!(pending.handshake.is_some());
            let deadline = n
                .original_admission_deadline
                .checked_add(Duration::from_millis(40))
                .unwrap();
            let outer = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
            while Instant::now() < deadline && Instant::now() < outer {
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(20)),
                );
            }
            assert!(Instant::now() >= deadline);
            assert!(actual_now().wall >= Duration::from_secs(n.f.context.expires_at));
            assert!(
                Instant::now() < n.f.start + Duration::from_secs(5),
                "original peer observation still fresh at late finish"
            );
            let renewed = actual_now();
            n.f.heartbeat.request_started = renewed.monotonic;
            n.f.heartbeat.wall_at_request_start = renewed.wall.as_secs();
            // No read/write/check/failure/dispose ran between completion and this
            // direct finish. Expired original admission alone prevents construction.
            assert!(!pending.core.disposed);
            assert!(pending.handshake.is_some());
            assert!(matches!(
                pending.finish(&n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
        });
    }
    #[test]
    fn real_noise_frame_bounds_roundtrip_and_replay_disposes_permanently() {
        ready(|auth, config| {
            let n = NoiseFixture::new(auth, config, 30);
            let (mut state, mut consumer) = n.complete(auth);
            let bytes = vec![7; lomi_remote_protocol::message_framing::MAX_PLAINTEXT_FRAME_LEN];
            let incoming = consumer
                .seal_binary(n.f.context.channel_id, &bytes)
                .unwrap();
            let plain = state
                .open_frame(&incoming, &n.facts(), &mut actual_now)
                .unwrap();
            assert_eq!(plain.as_ref(), bytes.as_slice());
            let outgoing = state
                .seal_frame(&bytes, &n.facts(), &mut actual_now)
                .unwrap();
            assert!(
                outgoing.len() <= lomi_remote_protocol::message_framing::MAX_TRANSPORT_FRAME_LEN
            );
            assert_eq!(
                &**consumer
                    .open_binary(n.f.context.channel_id, &outgoing)
                    .unwrap(),
                bytes.as_slice()
            );
            assert!(matches!(
                state.open_frame(&incoming, &n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
            assert!(state.core.disposed);
            assert!(matches!(
                state.seal_frame(b"no revival", &n.facts(), &mut actual_now),
                Err(GateError::Disposed)
            ));
        });
    }

    #[test]
    fn real_noise_pre_post_revocation_never_returns_plaintext_or_ciphertext_and_cannot_revive() {
        for opening in [true, false] {
            ready(|auth, config| {
                let n = NoiseFixture::new(auth, config, 30);
                let (mut state, mut consumer) = n.complete(auth);
                let incoming = consumer
                    .seal_binary(n.f.context.channel_id, b"protected plaintext")
                    .unwrap();
                let mut samples = 0;
                let mut revoke_after_precheck = || {
                    samples += 1;
                    // live() takes two samples before crypto; revoke at its first post sample.
                    if samples == 3 {
                        n.f.gate_denied.store(true, Ordering::Release);
                    }
                    actual_now()
                };
                let result = if opening {
                    state
                        .open_frame(&incoming, &n.facts(), &mut revoke_after_precheck)
                        .map(|_| ())
                } else {
                    state
                        .seal_frame(b"protected output", &n.facts(), &mut revoke_after_precheck)
                        .map(|_| ())
                };
                assert_eq!(result, Err(GateError::Disposed));
                assert!(samples >= 3);
                assert!(state.core.disposed);
                n.f.gate_denied.store(false, Ordering::Release);
                assert!(matches!(
                    state.open_frame(&incoming, &n.facts(), &mut actual_now),
                    Err(GateError::Disposed)
                ));
                assert!(matches!(
                    state.seal_frame(b"no revival", &n.facts(), &mut actual_now),
                    Err(GateError::Disposed)
                ));
                assert!(state.completed_channel.seal(b"disposed transport").is_err());
            });
        }
    }

    #[test]
    fn real_noise_oversized_or_tampered_frames_dispose_without_late_disclosure() {
        for failure in ["open-size", "seal-size", "tampered"] {
            ready(|auth, config| {
                let n = NoiseFixture::new(auth, config, 30);
                let (mut state, mut consumer) = n.complete(auth);
                let mut incoming = consumer
                    .seal_binary(n.f.context.channel_id, b"authenticated")
                    .unwrap();
                let result = match failure {
                    "open-size" => state
                        .open_frame(
                            &vec![
                                0;
                                lomi_remote_protocol::message_framing::MAX_TRANSPORT_FRAME_LEN + 1
                            ],
                            &n.facts(),
                            &mut actual_now,
                        )
                        .map(|_| ()),
                    "seal-size" => state
                        .seal_frame(
                            &vec![
                                0;
                                lomi_remote_protocol::message_framing::MAX_PLAINTEXT_FRAME_LEN + 1
                            ],
                            &n.facts(),
                            &mut actual_now,
                        )
                        .map(|_| ()),
                    _ => {
                        *incoming.last_mut().unwrap() ^= 1;
                        state
                            .open_frame(&incoming, &n.facts(), &mut actual_now)
                            .map(|_| ())
                    }
                };
                assert_eq!(result, Err(GateError::Disposed));
                assert!(state.core.disposed);
                assert!(matches!(
                    state.seal_frame(b"no late response", &n.facts(), &mut actual_now),
                    Err(GateError::Disposed)
                ));
            });
        }
    }
}

#[path = "remote_connection_rename_tests.rs"]
mod rename_tests;
