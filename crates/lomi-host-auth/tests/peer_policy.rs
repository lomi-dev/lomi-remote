//! Portable pure-policy fixtures: actual self-signed identities and v3 CBOR.
use lomi_host_auth::{Config, PublicHostIdentity, peer_policy::*};
use lomi_remote_crypto::{
    ChannelContextV3, ChannelPurposeV3, GrantPurposeV3, GrantV3, Identity, Role, TerminalTargetV3,
};
use lomi_remote_protocol::{ipc::IpcProfileId, *};
use std::time::{Duration, Instant};

struct Fixture {
    host: Identity,
    consumer: Identity,
    start: Instant,
}
fn all() -> CapabilitySet {
    CapabilitySet::try_from(Capability::ALL.to_vec()).unwrap()
}
fn read() -> CapabilitySet {
    CapabilitySet::try_from(vec![Capability::WorkspaceRead]).unwrap()
}
impl Fixture {
    fn new() -> Self {
        Self {
            host: Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap(),
            consumer: Identity::generate([1; 16], [3; 16], Role::Device, 1).unwrap(),
            start: Instant::now(),
        }
    }
    fn input(&self) -> SnapshotInput {
        let runtime = RuntimeBinding {
            runtime_id: RuntimeId::from_bytes([8; 16]).unwrap(),
            runtime_generation: DecimalU64(17),
            host_access_epoch: DecimalU64(12),
        };
        let workspace_id = WorkspaceId::from_bytes([6; 16]).unwrap();
        let workspace_epoch = WorkspaceEpoch::from_bytes([7; 16]).unwrap();
        let host_id = HostId::from_bytes([2; 16]).unwrap();
        let config = Config::new(
            host_id,
            IpcProfileId::from_bytes([11; 16]).unwrap(),
            "https://identity.example".into(),
            "lomi-remote-host".to_owned().try_into().unwrap(),
        )
        .unwrap();
        let terminals = PublicationTerminals::try_from(vec![self.terminal()]).unwrap();
        SnapshotInput {
            protected_host: PublicHostIdentity {
                account_id: AccountId::from_bytes([1; 16]).unwrap(),
                host_id,
                identity: self.host.public_bundle().to_wire().unwrap(),
                fingerprint: self.host.public_bundle().bundle.fingerprint().unwrap(),
                host_authorization_id: HostAuthorizationId::from_bytes([4; 16]).unwrap(),
                access_epoch: 12,
            },
            remote_origin: RemoteOrigin::new(&config, "https://remote.example".into()).unwrap(),
            owner: OwnerScope {
                authorization_generation: 2,
                owner_runtime_id: runtime.runtime_id,
                owner_generation: 9,
                runtime: runtime.clone(),
            },
            acknowledged_runtime: runtime.clone(),
            acknowledged_workspaces: PublicationWorkspaces::try_from(vec![PublishedWorkspace {
                workspace_id,
                workspace_epoch,
                terminals: terminals.clone(),
            }])
            .unwrap(),
            local: LocalWorkspace {
                workspace_id,
                workspace_epoch,
                fence: 3,
                consent: true,
                running_terminals: terminals,
                capability_ceiling: None,
            },
            peer: PeerObservation {
                account_id: AccountId::from_bytes([1; 16]).unwrap(),
                window_id: WindowIdentityId::from_bytes([3; 16]).unwrap(),
                identity: self.consumer.public_bundle().to_wire().unwrap(),
                fingerprint: self.consumer.public_bundle().bundle.fingerprint().unwrap(),
                authority: CurrentAuthorityBinding {
                    host_authorization_id: HostAuthorizationId::from_bytes([4; 16]).unwrap(),
                    consumer_authorization_id: ConsumerAuthorizationId::from_bytes([5; 16])
                        .unwrap(),
                    account_session_id: "current-session".to_owned().try_into().unwrap(),
                    access_epoch: DecimalU64(12),
                    grant_revision: DecimalU64(2),
                    workspace_epoch,
                    runtime_id: runtime.runtime_id,
                    runtime_generation: runtime.runtime_generation,
                    terminal_membership: None,
                },
                authority_expires_at: 1020,
            },
            request_started: self.start,
            wall_at_request_start: 1000,
            lease_ms: 30_000,
            freshness_ms: 5_000,
        }
    }
    fn maximum(&self) -> GrantV3 {
        GrantV3 {
            version: 3,
            api_major: 2,
            application_major: 2,
            account_id: [1; 16],
            host_id: [2; 16],
            host_fingerprint: self.host.public_bundle().bundle.fingerprint().unwrap(),
            host_authorization_id: [4; 16],
            access_epoch: 12,
            consumer_authorization_id: [5; 16],
            account_session_id: "current-session".into(),
            consumer_id: [3; 16],
            consumer_fingerprint: self.consumer.public_bundle().bundle.fingerprint().unwrap(),
            grant_id: [9; 16],
            grant_revision: 2,
            workspace_id: [6; 16],
            workspace_epoch: [7; 16],
            runtime_id: [8; 16],
            runtime_generation: 17,
            capabilities: all(),
            nonce: [10; 32],
            expires_at: 1030,
            purpose: GrantPurposeV3::Workspace,
        }
    }
    fn clock(&self) -> PolicyClock {
        PolicyClock::new(1000, self.start).unwrap()
    }
    fn terminal(&self) -> PublishedTerminal {
        PublishedTerminal {
            pane_id: PaneId::from_bytes([13; 16]).unwrap(),
            session_id: TerminalSessionId::from_bytes([14; 16]).unwrap(),
            session_epoch: SessionEpoch::from_bytes([15; 16]).unwrap(),
        }
    }
    fn prepare(&self, snapshot: &PolicySnapshot, clock: &mut PolicyClock) -> PreparedGrant {
        snapshot
            .prepare_grant(
                &self.maximum().canonical().unwrap(),
                GrantNarrowing {
                    capabilities: all(),
                    expires_at: 1010,
                },
                clock,
                1000,
                self.start,
            )
            .unwrap()
    }
    fn approved(&self, snapshot: &PolicySnapshot, clock: &mut PolicyClock) -> ApprovedGrant {
        let p = self.prepare(snapshot, clock);
        snapshot
            .retain_approved_grant(
                &p,
                self.host.sign_grant_v3(p.grant()).unwrap(),
                clock,
                1000,
                self.start,
            )
            .unwrap()
    }
    fn context(
        &self,
        approved: &ApprovedGrant,
        terminal: Option<TerminalTargetV3>,
    ) -> ChannelContextV3 {
        ChannelContextV3 {
            version: 3,
            grant: approved.signed().grant.clone(),
            channel_id: [16; 16],
            initiator_role: Role::Device,
            responder_role: Role::Host,
            purpose: if terminal.is_some() {
                ChannelPurposeV3::Terminal
            } else {
                ChannelPurposeV3::Workspace
            },
            terminal,
            issued_at: 1000,
            expires_at: 1008,
        }
    }
    fn target(&self) -> TerminalTargetV3 {
        let t = self.terminal();
        TerminalTargetV3 {
            pane_id: t.pane_id.to_bytes(),
            session_id: t.session_id.to_bytes(),
            session_epoch: t.session_epoch.to_bytes(),
            terminal_profile: "lomi-rust-grid-v1-experimental".into(),
        }
    }
    fn terminal_input(&self, target: &TerminalTargetV3) -> SnapshotInput {
        let mut i = self.input();
        i.peer.authority.terminal_membership = Some(ChannelTerminalMembership {
            pane_id: PaneId::from_bytes(target.pane_id).unwrap(),
            session_id: TerminalSessionId::from_bytes(target.session_id).unwrap(),
            session_epoch: SessionEpoch::from_bytes(target.session_epoch).unwrap(),
            terminal_profile: TerminalProfile::ExperimentalRustGridV1,
        });
        i
    }
}

#[test]
fn same_account_prepares_frozen_narrowed_grant_and_workspace_channel() {
    let f = Fixture::new();
    let s = PolicySnapshot::new(f.input()).unwrap();
    let mut clock = f.clock();
    let p = f.prepare(&s, &mut clock);
    assert!(!p.grant().capabilities.contains(Capability::GitExecute));
    assert_eq!(p.grant().expires_at, 1010);
    assert_eq!(p.workspace_fence(), 3);
    assert_eq!(p.owner_scope().owner_generation, 9);
    assert_eq!(p.owner_scope().runtime.runtime_generation.0, 17);
    let bytes = p.canonical().to_vec();
    let signed = f.host.sign_grant_v3(p.grant()).unwrap();
    let approved = s
        .retain_approved_grant(&p, signed, &mut clock, 1000, f.start)
        .unwrap();
    let context = f.context(&approved, None);
    let channel = s
        .prepare_channel(
            &approved,
            &context.canonical().unwrap(),
            &mut clock,
            1000,
            f.start,
        )
        .unwrap();
    assert_eq!(channel.context(), &context);
    assert_eq!(channel.canonical(), context.canonical().unwrap());
    assert_eq!(p.canonical(), bytes);
}
#[test]
fn immutable_grant_fields_must_match_independently_observed_authority() {
    let f = Fixture::new();
    let s = PolicySnapshot::new(f.input()).unwrap();
    for change in 0..15 {
        let mut g = f.maximum();
        match change {
            0 => g.account_id = [20; 16],
            1 => g.host_id = [20; 16],
            2 => g.host_fingerprint = [20; 32],
            3 => g.host_authorization_id = [20; 16],
            4 => g.access_epoch += 1,
            5 => g.consumer_authorization_id = [20; 16],
            6 => g.account_session_id = "other-session".into(),
            7 => g.consumer_id = [20; 16],
            8 => g.consumer_fingerprint = [20; 32],
            9 => g.grant_revision += 1,
            10 => g.workspace_id = [20; 16],
            11 => g.workspace_epoch = [20; 16],
            12 => g.runtime_id = [20; 16],
            13 => g.runtime_generation += 1,
            14 => g.expires_at = u64::MAX,
            _ => unreachable!(),
        }
        assert!(
            s.prepare_grant(
                &g.canonical().unwrap(),
                GrantNarrowing {
                    capabilities: all(),
                    expires_at: 1010
                },
                &mut f.clock(),
                1000,
                f.start
            )
            .is_err(),
            "mutation {change}"
        );
    }
}
#[test]
fn independently_observed_identity_account_role_key_pin_and_owner_binding_are_required() {
    let f = Fixture::new();
    for change in 0..15 {
        let mut i = f.input();
        match change {
            0 => i.peer.account_id = AccountId::from_bytes([20; 16]).unwrap(),
            1 => {
                i.peer.identity = Identity::generate([1; 16], [3; 16], Role::Host, 1)
                    .unwrap()
                    .public_bundle()
                    .to_wire()
                    .unwrap()
            }
            2 => {
                i.peer.identity = Identity::generate([1; 16], [3; 16], Role::Device, 2)
                    .unwrap()
                    .public_bundle()
                    .to_wire()
                    .unwrap()
            }
            3 => i.peer.fingerprint = [20; 32],
            4 => i.peer.window_id = WindowIdentityId::from_bytes([20; 16]).unwrap(),
            5 => i.protected_host.fingerprint = [20; 32],
            6 => i.protected_host.account_id = AccountId::from_bytes([20; 16]).unwrap(),
            7 => i.protected_host.host_id = HostId::from_bytes([20; 16]).unwrap(),
            8 => i.owner.owner_runtime_id = RuntimeId::from_bytes([20; 16]).unwrap(),
            9 => i.acknowledged_runtime.runtime_generation = DecimalU64(99),
            10 => {
                i.peer.authority.host_authorization_id =
                    HostAuthorizationId::from_bytes([20; 16]).unwrap()
            }
            11 => i.peer.authority.access_epoch = DecimalU64(99),
            12 => i.peer.authority.runtime_generation = DecimalU64(99),
            13 => i.peer.authority.workspace_epoch = WorkspaceEpoch::from_bytes([20; 16]).unwrap(),
            14 => i.local.consent = false,
            _ => unreachable!(),
        }
        assert!(PolicySnapshot::new(i).is_err(), "mutation {change}");
    }
}
#[test]
fn narrowing_intersects_dependency_closed_sets_and_cannot_default_to_git_execute() {
    let f = Fixture::new();
    let mut i = f.input();
    i.local.capability_ceiling = Some(read());
    let s = PolicySnapshot::new(i).unwrap();
    let p = s
        .prepare_grant(
            &f.maximum().canonical().unwrap(),
            GrantNarrowing {
                capabilities: all(),
                expires_at: 9999,
            },
            &mut f.clock(),
            1000,
            f.start,
        )
        .unwrap();
    assert_eq!(p.grant().capabilities, read());
    assert_eq!(p.grant().expires_at, 1020);
    let s = PolicySnapshot::new(f.input()).unwrap();
    let p = f.prepare(&s, &mut f.clock());
    assert_eq!(
        p.grant().capabilities,
        CapabilitySet::control_with_workspace_tools()
    );
    let mut changed = p.grant().clone();
    changed.nonce = [99; 32];
    assert!(
        s.retain_approved_grant(
            &p,
            f.host.sign_grant_v3(&changed).unwrap(),
            &mut f.clock(),
            1000,
            f.start
        )
        .is_err()
    );
    changed = p.grant().clone();
    changed.expires_at -= 1;
    assert!(
        s.retain_approved_grant(
            &p,
            f.host.sign_grant_v3(&changed).unwrap(),
            &mut f.clock(),
            1000,
            f.start
        )
        .is_err()
    );
}
#[test]
fn channel_requires_exact_retained_approval_and_current_local_and_acked_terminal() {
    let f = Fixture::new();
    let s = PolicySnapshot::new(f.input()).unwrap();
    let approved = f.approved(&s, &mut f.clock());
    let target = f.target();
    let context = f.context(&approved, Some(target.clone()));
    let bytes = context.canonical().unwrap();
    let terminal = PolicySnapshot::new(f.terminal_input(&target)).unwrap();
    assert!(
        terminal
            .prepare_channel(&approved, &bytes, &mut f.clock(), 1000, f.start)
            .is_ok()
    );
    for change in 0..8 {
        let mut i = f.terminal_input(&target);
        match change {
            0 => i.local.running_terminals = PublicationTerminals::try_from(vec![]).unwrap(),
            1 => {
                i.acknowledged_workspaces =
                    PublicationWorkspaces::try_from(vec![PublishedWorkspace {
                        workspace_id: i.local.workspace_id,
                        workspace_epoch: i.local.workspace_epoch,
                        terminals: PublicationTerminals::try_from(vec![]).unwrap(),
                    }])
                    .unwrap()
            }
            2 => i.local.fence += 1,
            3 => i.owner.authorization_generation += 1,
            4 => {
                i.peer.authority.consumer_authorization_id =
                    ConsumerAuthorizationId::from_bytes([20; 16]).unwrap()
            }
            5 => i.peer.authority.account_session_id = "new-session".to_owned().try_into().unwrap(),
            6 => i.peer.authority.grant_revision = DecimalU64(3),
            7 => i.peer.authority.terminal_membership = None,
            _ => unreachable!(),
        }
        let s = PolicySnapshot::new(i).unwrap();
        assert!(
            s.prepare_channel(&approved, &bytes, &mut f.clock(), 1000, f.start)
                .is_err(),
            "mutation {change}"
        );
    }
    let mut changed = context.clone();
    changed.grant.nonce = [99; 32];
    assert!(
        terminal
            .prepare_channel(
                &approved,
                &changed.canonical().unwrap(),
                &mut f.clock(),
                1000,
                f.start
            )
            .is_err()
    );
}
#[test]
fn approved_workspace_grant_survives_membership_growth_but_new_terminal_must_be_acked() {
    let f = Fixture::new();
    let s = PolicySnapshot::new(f.input()).unwrap();
    let approved = f.approved(&s, &mut f.clock());
    let mut target = f.target();
    target.pane_id = [21; 16];
    target.session_id = [22; 16];
    target.session_epoch = [23; 16];
    let new = PublishedTerminal {
        pane_id: PaneId::from_bytes(target.pane_id).unwrap(),
        session_id: TerminalSessionId::from_bytes(target.session_id).unwrap(),
        session_epoch: SessionEpoch::from_bytes(target.session_epoch).unwrap(),
    };
    let context = f
        .context(&approved, Some(target.clone()))
        .canonical()
        .unwrap();
    let mut i = f.terminal_input(&target);
    i.local.running_terminals =
        PublicationTerminals::try_from(vec![f.terminal(), new.clone()]).unwrap();
    assert!(
        PolicySnapshot::new(i)
            .unwrap()
            .prepare_channel(&approved, &context, &mut f.clock(), 1000, f.start)
            .is_err()
    );
    let mut i = f.terminal_input(&target);
    let terminals = PublicationTerminals::try_from(vec![f.terminal(), new]).unwrap();
    i.local.running_terminals = terminals.clone();
    i.acknowledged_workspaces = PublicationWorkspaces::try_from(vec![PublishedWorkspace {
        workspace_id: i.local.workspace_id,
        workspace_epoch: i.local.workspace_epoch,
        terminals,
    }])
    .unwrap();
    assert!(
        PolicySnapshot::new(i)
            .unwrap()
            .prepare_channel(&approved, &context, &mut f.clock(), 1000, f.start)
            .is_ok()
    );
}
#[test]
fn unshare_reshare_epoch_and_missing_acked_workspace_deny() {
    let f = Fixture::new();
    let s = PolicySnapshot::new(f.input()).unwrap();
    let approved = f.approved(&s, &mut f.clock());
    for change in 0..3 {
        let mut i = f.input();
        match change {
            0 => i.local.consent = false,
            1 => i.acknowledged_workspaces = PublicationWorkspaces::try_from(vec![]).unwrap(),
            2 => {
                i.local.workspace_epoch = WorkspaceEpoch::from_bytes([20; 16]).unwrap();
                i.peer.authority.workspace_epoch = i.local.workspace_epoch;
                i.acknowledged_workspaces =
                    PublicationWorkspaces::try_from(vec![PublishedWorkspace {
                        workspace_id: i.local.workspace_id,
                        workspace_epoch: i.local.workspace_epoch,
                        terminals: i.local.running_terminals.clone(),
                    }])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        match PolicySnapshot::new(i) {
            Err(_) => (),
            Ok(s) => assert!(
                s.prepare_channel(
                    &approved,
                    &f.context(&approved, None).canonical().unwrap(),
                    &mut f.clock(),
                    1000,
                    f.start
                )
                .is_err()
            ),
        }
    }
}
#[test]
fn strict_existing_decoders_reject_noncanonical_trailing_oversized_and_malformed_inputs() {
    let f = Fixture::new();
    let s = PolicySnapshot::new(f.input()).unwrap();
    let canonical = f.maximum().canonical().unwrap();
    let mut trailing = canonical.clone();
    trailing.push(0);
    let mut noncanonical = vec![0x98, 23];
    noncanonical.extend_from_slice(&canonical[1..]);
    for bytes in [vec![], vec![0; 8193], trailing, noncanonical] {
        assert!(
            s.prepare_grant(
                &bytes,
                GrantNarrowing {
                    capabilities: all(),
                    expires_at: 1010
                },
                &mut f.clock(),
                1000,
                f.start
            )
            .is_err()
        );
    }
    let approved = f.approved(&s, &mut f.clock());
    let canonical = f.context(&approved, None).canonical().unwrap();
    let mut trailing = canonical.clone();
    trailing.push(0);
    let mut noncanonical = vec![0x98, 10];
    noncanonical.extend_from_slice(&canonical[1..]);
    for bytes in [vec![], vec![0; 8193], trailing, noncanonical] {
        assert!(
            s.prepare_channel(&approved, &bytes, &mut f.clock(), 1000, f.start)
                .is_err()
        );
    }
}
#[test]
fn elapsed_freshness_expiry_and_clock_rollback_cannot_revive_preparation() {
    let f = Fixture::new();
    let s = PolicySnapshot::new(f.input()).unwrap();
    let bytes = f.maximum().canonical().unwrap();
    let mut clock = f.clock();
    assert!(matches!(
        s.prepare_grant(
            &bytes,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1010
            },
            &mut clock,
            1005,
            f.start + Duration::from_secs(5)
        ),
        Err(PolicyError::Stale)
    ));
    assert!(matches!(
        s.prepare_grant(
            &bytes,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1010
            },
            &mut clock,
            1000,
            f.start + Duration::from_secs(6)
        ),
        Err(PolicyError::ClockRollback)
    ));
    let mut clock = f.clock();
    assert!(matches!(
        s.prepare_grant(
            &bytes,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1002
            },
            &mut clock,
            1003,
            f.start + Duration::from_secs(3)
        ),
        Err(PolicyError::Stale)
    ));
    assert!(matches!(
        s.prepare_grant(
            &bytes,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1002
            },
            &mut clock,
            1000,
            f.start + Duration::from_secs(3)
        ),
        Err(PolicyError::ClockRollback)
    ));
    let mut i = f.input();
    i.request_started = f.start + Duration::from_secs(1);
    assert!(matches!(
        PolicySnapshot::new(i).unwrap().prepare_grant(
            &bytes,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1010
            },
            &mut f.clock(),
            1000,
            f.start
        ),
        Err(PolicyError::ClockRollback)
    ));
}
#[test]
fn retained_approval_cannot_adopt_new_peer_keys_family_owner_origin_or_caps() {
    let f = Fixture::new();
    let s = PolicySnapshot::new(f.input()).unwrap();
    let mut clock = f.clock();
    let prepared = f.prepare(&s, &mut clock);
    let signed = f.host.sign_grant_v3(prepared.grant()).unwrap();
    let approved = s
        .retain_approved_grant(&prepared, signed.clone(), &mut clock, 1000, f.start)
        .unwrap();
    let context = f.context(&approved, None).canonical().unwrap();
    for change in 0..6 {
        let mut input = f.input();
        match change {
            0 => {
                let identity = Identity::generate([1; 16], [3; 16], Role::Device, 2)
                    .unwrap()
                    .public_bundle();
                input.peer.identity = identity.to_wire().unwrap();
                input.peer.fingerprint = identity.bundle.fingerprint().unwrap();
            }
            1 => {
                let family = HostAuthorizationId::from_bytes([29; 16]).unwrap();
                input.protected_host.host_authorization_id = family;
                input.peer.authority.host_authorization_id = family;
            }
            2 => input.owner.owner_generation += 1,
            3 => {
                input.owner.runtime.runtime_generation.0 += 1;
                input.acknowledged_runtime = input.owner.runtime.clone();
                input.peer.authority.runtime_generation = input.owner.runtime.runtime_generation;
            }
            4 => {
                let cfg = Config::new(
                    input.protected_host.host_id,
                    IpcProfileId::from_bytes([11; 16]).unwrap(),
                    "https://identity.example".into(),
                    "host".to_owned().try_into().unwrap(),
                )
                .unwrap();
                input.remote_origin =
                    RemoteOrigin::new(&cfg, "https://other-remote.example".into()).unwrap();
            }
            5 => input.local.capability_ceiling = Some(read()),
            _ => unreachable!(),
        }
        let current = PolicySnapshot::new(input).unwrap();
        assert!(
            current
                .prepare_channel(&approved, &context, &mut f.clock(), 1000, f.start)
                .is_err(),
            "channel mutation {change}"
        );
        assert!(
            current
                .retain_approved_grant(&prepared, signed.clone(), &mut f.clock(), 1000, f.start)
                .is_err(),
            "approval mutation {change}"
        );
    }
}

#[test]
fn remote_pin_and_duration_bounds_are_independent_and_nonserialized() {
    let f = Fixture::new();
    let config = Config::new(
        HostId::from_bytes([2; 16]).unwrap(),
        IpcProfileId::from_bytes([11; 16]).unwrap(),
        "https://identity.example".into(),
        "lomi-remote-host".to_owned().try_into().unwrap(),
    )
    .unwrap();
    for pin in [
        "https://identity.example",
        "http://remote.example",
        "https://remote.example/path",
        "https://user@remote.example",
    ] {
        assert!(RemoteOrigin::new(&config, pin.into()).is_err());
    }
    for change in 0..5 {
        let mut i = f.input();
        match change {
            0 => i.lease_ms = 30_001,
            1 => i.freshness_ms = 5_001,
            2 => i.freshness_ms = 0,
            3 => i.lease_ms = 1,
            4 => i.owner.owner_generation = 0,
            _ => unreachable!(),
        };
        assert!(PolicySnapshot::new(i).is_err());
    }
}

#[test]
fn forward_wall_observation_reanchors_elapsed_expiry_without_extending_retry() {
    let f = Fixture::new();
    let snapshot = PolicySnapshot::new(f.input()).unwrap();
    let maximum = f.maximum().canonical().unwrap();
    let mut clock = f.clock();
    let prepared = snapshot
        .prepare_grant(
            &maximum,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1007,
            },
            &mut clock,
            1005,
            f.start,
        )
        .unwrap();
    let frozen = prepared.canonical().to_vec();
    assert!(matches!(
        snapshot.prepare_grant(
            &maximum,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1007
            },
            &mut clock,
            1005,
            f.start + Duration::from_secs(3)
        ),
        Err(PolicyError::Stale)
    ));
    assert_eq!(prepared.canonical(), frozen);
    assert!(matches!(
        snapshot.prepare_grant(
            &maximum,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1007
            },
            &mut clock,
            1005,
            f.start + Duration::from_secs(4)
        ),
        Err(PolicyError::ClockRollback)
    ));
}

#[test]
fn clock_projection_cannot_fall_behind_the_authenticated_request_start_observation() {
    let f = Fixture::new();
    let mut input = f.input();
    input.request_started = f.start.checked_sub(Duration::from_secs(2)).unwrap();
    input.wall_at_request_start = 1005;
    let snapshot = PolicySnapshot::new(input).unwrap();
    assert!(matches!(
        snapshot.prepare_grant(
            &f.maximum().canonical().unwrap(),
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1006
            },
            &mut f.clock(),
            1005,
            f.start
        ),
        Err(PolicyError::ClockRollback)
    ));
}

#[test]
fn shortened_authority_ceiling_rejects_fresh_approval_but_caps_historical_grant_channels() {
    let f = Fixture::new();
    let original = PolicySnapshot::new(f.input()).unwrap();
    let prepared = f.prepare(&original, &mut f.clock());
    let frozen = prepared.canonical().to_vec();
    let signed = f.host.sign_grant_v3(prepared.grant()).unwrap();
    let historical = original
        .retain_approved_grant(&prepared, signed.clone(), &mut f.clock(), 1000, f.start)
        .unwrap();
    let mut input = f.input();
    input.peer.authority_expires_at = 1008;
    let current = PolicySnapshot::new(input).unwrap();
    assert!(matches!(
        current.retain_approved_grant(&prepared, signed, &mut f.clock(), 1000, f.start),
        Err(PolicyError::Denied)
    ));
    assert_eq!(prepared.canonical(), frozen);
    assert_eq!(prepared.grant().expires_at, 1010);
    let mut context = f.context(&historical, None);
    context.expires_at = 1007;
    assert!(
        current
            .prepare_channel(
                &historical,
                &context.canonical().unwrap(),
                &mut f.clock(),
                1000,
                f.start
            )
            .is_ok()
    );
    context.expires_at = 1009;
    assert!(
        current
            .prepare_channel(
                &historical,
                &context.canonical().unwrap(),
                &mut f.clock(),
                1000,
                f.start
            )
            .is_err()
    );
}

#[test]
fn aligned_runtime_anchor_preserves_second_boundary_without_weakening_clock_guards() {
    let f = Fixture::new();
    let snapshot = PolicySnapshot::new(f.input()).unwrap();
    let maximum = f.maximum().canonical().unwrap();
    let runtime_base = 1000;
    let runtime_anchor = f.start;
    let initialization = runtime_anchor + Duration::from_millis(750);
    let live_sample = runtime_anchor + Duration::from_millis(999);
    let policy_evaluation = runtime_anchor + Duration::from_millis(1001);
    let sampled_wall = runtime_base + live_sample.duration_since(runtime_anchor).as_secs();
    assert_eq!(sampled_wall, 1000);

    // A later initialization Instant loses Runtime's fractional second. The
    // authenticated heartbeat still projects from its original request start.
    let mut phase_lagged = PolicyClock::new(sampled_wall, initialization).unwrap();
    assert!(matches!(
        snapshot.prepare_grant(
            &maximum,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1010
            },
            &mut phase_lagged,
            sampled_wall,
            policy_evaluation,
        ),
        Err(PolicyError::ClockRollback)
    ));

    // Use the trusted Runtime pair exactly once, preserving its original phase.
    let mut aligned = PolicyClock::new(runtime_base, runtime_anchor).unwrap();
    let prepared = snapshot
        .prepare_grant(
            &maximum,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1010,
            },
            &mut aligned,
            sampled_wall,
            policy_evaluation,
        )
        .unwrap();
    let frozen = prepared.canonical().to_vec();
    let signed = f.host.sign_grant_v3(prepared.grant()).unwrap();
    let approved = snapshot
        .retain_approved_grant(
            &prepared,
            signed,
            &mut aligned,
            1001,
            runtime_anchor + Duration::from_millis(1002),
        )
        .unwrap();
    assert_eq!(&approved.signed().grant, prepared.grant());

    // This SAME clock has observed 1001. A genuine lower wall sample must still
    // fail; alignment neither resets its watermark nor forgives rollback.
    assert!(matches!(
        snapshot.prepare_grant(
            &maximum,
            GrantNarrowing {
                capabilities: all(),
                expires_at: 1010
            },
            &mut aligned,
            1000,
            runtime_anchor + Duration::from_millis(1003),
        ),
        Err(PolicyError::ClockRollback)
    ));
    // Preserve the SAME heartbeat's original 5s cutoff and the SAME clock. The
    // grant and authority expire later, so this is actual heartbeat expiry.
    assert!(matches!(
        snapshot.retain_approved_grant(
            &prepared,
            f.host.sign_grant_v3(prepared.grant()).unwrap(),
            &mut aligned,
            1005,
            runtime_anchor + Duration::from_secs(5),
        ),
        Err(PolicyError::Stale)
    ));
    assert_eq!(prepared.canonical(), frozen);
}
