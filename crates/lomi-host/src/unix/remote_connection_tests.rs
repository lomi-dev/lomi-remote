use super::*;
use lomi_host_auth::{Config, HostAuth};
use lomi_host_store::CloudRuntimeState;
use lomi_platform::secrets::{ProviderKind, ProviderStatus, SecretBundle, StorageState};
use lomi_remote_crypto::{
    GrantPurposeV3, GrantV3, Handshake, HostEnrollmentChallengeContext, Identity, Role,
    prepare_host_enrollment_challenge, verify_host_key_initiation,
};
use lomi_remote_protocol::{
    EnrollmentInitiateResult, HostAuthorizationResult, HostEnrollmentTokenContext,
    HostRegisterResult,
    http::{PublicationWorkspaces, PublishedWorkspace},
    ipc::IpcProfileId,
};
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

struct MemoryStorage(Option<Vec<u8>>);
impl lomi_platform::secrets::SecretStorage for MemoryStorage {
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            kind: Some(ProviderKind::ProtectedFile),
            state: StorageState::Available,
        }
    }

    fn load(&self) -> std::result::Result<Option<SecretBundle>, lomi_platform::secrets::Error> {
        self.0.clone().map(SecretBundle::new).transpose()
    }

    fn replace(
        &mut self,
        bundle: &SecretBundle,
    ) -> std::result::Result<(), lomi_platform::secrets::Error> {
        self.0 = Some(bundle.expose().to_vec());
        Ok(())
    }
}

fn with_ready_auth(test: impl FnOnce(&mut HostAuth<'_, dyn SecretStorage + '_>, &Config)) {
    let host_id = HostId::from_bytes([2; 16]).unwrap();
    let config = Config::new(
        host_id,
        IpcProfileId::from_bytes([20; 16]).unwrap(),
        "https://identity.example".into(),
        "host".to_owned().try_into().unwrap(),
    )
    .unwrap();
    let mut storage = MemoryStorage(None);
    let mut auth = HostAuth::open(
        &mut storage as &mut dyn SecretStorage,
        config.clone(),
        wall_now(),
    )
    .unwrap();
    auth.initialize().unwrap();
    let initiation = auth.init_request().unwrap();
    let committed = verify_host_key_initiation(&initiation).unwrap();
    let pin = committed.descriptor.commitment().unwrap();
    let started = wall_now();
    auth.accept_initiation(
        EnrollmentInitiateResult {
            enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
            device_code: "synthetic_device".to_owned().try_into().unwrap(),
            user_code: "SYNTHETIC-CODE".to_owned().try_into().unwrap(),
            expires_in_seconds: DecimalU64(600),
            poll_interval_seconds: DecimalU64(5),
        },
        started,
    )
    .unwrap();
    let challenge = prepare_host_enrollment_challenge(
        &committed,
        &pin,
        [4; 16],
        &HostEnrollmentChallengeContext {
            enrollment_id: [3; 16],
            bootstrap_session_id: [5; 16],
            operation_id: [6; 16],
            nonce: [7; 32],
            audience: config.exchange_audience(),
            expires_at: DecimalU64(started + 500),
        },
    )
    .unwrap();
    let encoded: String = challenge
        .canonical()
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    auth.accept_tls_approval(
        config.origin(),
        HostEnrollmentTokenContext {
            account_id: AccountId::from_bytes([4; 16]).unwrap(),
            challenge: encoded.try_into().unwrap(),
        },
        "synthetic_bootstrap".to_owned().try_into().unwrap(),
        wall_now(),
    )
    .unwrap();
    auth.prepare_exchange(wall_now()).unwrap();
    let exchange = auth.exchange_request(wall_now()).unwrap();
    auth.accept_exchange(
        HostAuthorizationResult {
            account_id: AccountId::from_bytes([4; 16]).unwrap(),
            host_id,
            host_authorization_id: HostAuthorizationId::from_bytes([8; 16]).unwrap(),
            access: "synthetic_access".to_owned().try_into().unwrap(),
            refresh: "synthetic_refresh".to_owned().try_into().unwrap(),
            rotation_id: exchange.operation_id,
            expires_in_seconds: DecimalU64(300),
        },
        wall_now(),
    )
    .unwrap();
    auth.confirm_registration(HostRegisterResult {
        host_id,
        host_access_epoch: DecimalU64(12),
    })
    .unwrap();
    test(&mut auth, &config);
}

fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Fixture {
    host: PublicHostIdentity,
    origin: RemoteOrigin,
    scope: CloudRuntimeScope,
    runtime: RuntimeBinding,
    heartbeat: HeartbeatObservation,
    acknowledged: HostAcknowledgedPublication,
    local: LocalWorkspace,
    consumer: Identity,
    consumer_proof: EnrollmentProof,
    consumer_pin: [u8; 32],
    authority: CurrentAuthorityV3,
    signed: SignedGrantV3,
    admission: SignedChannelAdmissionV3,
    context: ChannelContextV3,
    start: Instant,
    access_expires_at: u64,
    refresh_at: u64,
    gate_denied: AtomicBool,
    paused: AtomicBool,
    stopping: AtomicBool,
    cancelled: AtomicBool,
}
impl Fixture {
    fn new(auth: &HostAuth<'_, dyn SecretStorage + '_>, config: &Config, ttl: u64) -> Self {
        let wall = wall_now();
        let host = auth.public_host_identity(wall).unwrap();
        let origin = RemoteOrigin::new(config, "https://remote.example".into()).unwrap();
        let runtime = RuntimeBinding {
            runtime_id: RuntimeId::from_bytes([8; 16]).unwrap(),
            runtime_generation: DecimalU64(17),
            host_access_epoch: DecimalU64(12),
        };
        let scope = CloudRuntimeScope {
            authorization_generation: 2,
            remote_api_origin: origin.as_str().into(),
            host_id: host.host_id,
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
        let local = LocalWorkspace {
            workspace_id: workspace.workspace_id,
            workspace_epoch: workspace.workspace_epoch,
            fence: 3,
            consent: true,
            running_terminals: PublicationTerminals::try_from(Vec::new()).unwrap(),
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
                terminals: local.running_terminals.clone(),
            }])
            .unwrap(),
        };
        let consumer =
            Identity::generate(host.account_id.to_bytes(), [3; 16], Role::Device, 1).unwrap();
        let consumer_pin = consumer.public_bundle().bundle.fingerprint().unwrap();
        let grant = GrantV3 {
            version: 3,
            api_major: 2,
            application_major: 2,
            account_id: host.account_id.to_bytes(),
            host_id: host.host_id.to_bytes(),
            host_fingerprint: host.fingerprint,
            host_authorization_id: host.host_authorization_id.to_bytes(),
            access_epoch: host.access_epoch,
            consumer_authorization_id: [5; 16],
            account_session_id: "synthetic-current-session".into(),
            consumer_id: [3; 16],
            consumer_fingerprint: consumer_pin,
            grant_id: [19; 16],
            grant_revision: 2,
            workspace_id: workspace.workspace_id.to_bytes(),
            workspace_epoch: workspace.workspace_epoch.to_bytes(),
            runtime_id: runtime.runtime_id.to_bytes(),
            runtime_generation: runtime.runtime_generation.0,
            capabilities: vec![Capability::WorkspaceRead].try_into().unwrap(),
            nonce: [10; 32],
            expires_at: wall + 120,
            purpose: GrantPurposeV3::Workspace,
        };
        let context = ChannelContextV3 {
            version: 3,
            grant: grant.clone(),
            channel_id: [21; 16],
            initiator_role: Role::Device,
            responder_role: Role::Host,
            purpose: ChannelPurposeV3::Workspace,
            terminal: None,
            issued_at: wall,
            expires_at: wall + ttl,
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
            terminal_membership: None,
        };
        let start = Instant::now();
        let heartbeat = HeartbeatObservation {
            scope: scope.clone(),
            runtime: runtime.clone(),
            request_started: start,
            wall_at_request_start: wall,
            lease_ms: 30_000,
            freshness_ms: 5_000,
        };
        let deadlines = auth.credential_deadlines().unwrap();
        Self {
            host,
            origin,
            scope,
            runtime,
            heartbeat,
            acknowledged,
            local,
            consumer_proof: consumer.public_bundle().to_wire().unwrap(),
            consumer,
            consumer_pin,
            authority,
            signed: auth.sign_grant_v3(&grant, wall).unwrap(),
            admission: auth.sign_channel_admission_v3(&context, wall).unwrap(),
            context,
            start,
            access_expires_at: deadlines.access_expires_at,
            refresh_at: deadlines.refresh_at,
            gate_denied: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }

    fn now(&self, millis: u64) -> TrustedNow {
        TrustedNow {
            wall: Duration::from_secs(self.context.issued_at) + Duration::from_millis(millis),
            monotonic: self.start + Duration::from_millis(millis),
        }
    }

    fn renew_heartbeat(&mut self, millis: u64) {
        self.heartbeat.request_started = self.start + Duration::from_millis(millis);
        self.heartbeat.wall_at_request_start = self.context.issued_at + millis / 1000;
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
            running: &[],
            auth_ready: true,
            access_expires_at: self.access_expires_at,
            refresh_at: self.refresh_at,
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

    fn peer(&self, millis: u64) -> PeerRead<'_> {
        PeerRead {
            origin: &self.origin,
            request_started: self.start + Duration::from_millis(millis),
            wall_at_request_start: self.context.issued_at + millis / 1000,
            original_heartbeat: &self.heartbeat,
            consumer_window: WindowIdentityId::from_bytes([3; 16]).unwrap(),
            consumer_identity: &self.consumer_proof,
            consumer_pin: self.consumer_pin,
            signed_grant: &self.signed,
            authority: &self.authority,
            authority_expires_at: self.context.grant.expires_at,
        }
    }

    fn begin(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
    ) -> Result<PendingRemoteConnection> {
        PendingRemoteConnection::begin(
            auth,
            AdmissionInputs {
                canonical_context: &self.context.canonical().unwrap(),
                signed_grant: &self.signed,
                admission: &self.admission,
                peer: self.peer(0),
            },
            &self.facts(),
            &mut || self.now(0),
        )
    }

    fn established_connection(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
    ) -> RemoteConnectionState {
        let facts = self.facts();
        let mut pending = self.begin(auth).unwrap();
        let mut consumer = self.initiator();
        let first = consumer.write().unwrap();
        pending.read(&first, &facts, &mut || self.now(200)).unwrap();
        let second = pending.write(&facts, &mut || self.now(400)).unwrap();
        consumer.read(&second).unwrap();
        let third = consumer.write().unwrap();
        pending.read(&third, &facts, &mut || self.now(600)).unwrap();
        pending.finish(&facts, &mut || self.now(800)).unwrap()
    }

    fn initiator(&self) -> Handshake {
        let host = SignedBundle::from_wire(&self.host.identity).unwrap();
        let consumer = self.consumer.public_bundle();
        let verified = self
            .admission
            .verify(
                &self.signed,
                &self.context,
                &host,
                &self.host.fingerprint,
                &consumer,
                &self.consumer_pin,
                &self.authority,
                self.context.issued_at,
            )
            .unwrap();
        Handshake::new_v3(
            true,
            &self.consumer,
            verified,
            &host,
            &self.host.fingerprint,
            self.context.issued_at,
        )
        .unwrap()
    }
}

#[test]
fn pending_noise_refresh_before_expiry_survives_a_late_third_message() {
    with_ready_auth(|auth, config| {
        let mut fixture = Fixture::new(auth, config, 30);
        let facts = fixture.facts();
        let mut pending = fixture.begin(auth).unwrap();
        let mut consumer = fixture.initiator();

        let first = consumer.write().unwrap();
        pending
            .read(&first, &facts, &mut || fixture.now(250))
            .unwrap();
        consumer
            .read(&pending.write(&facts, &mut || fixture.now(500)).unwrap())
            .unwrap();
        let third = consumer.write().unwrap();

        drop(facts);
        fixture.renew_heartbeat(4_000);
        let renewed_facts = fixture.facts();
        pending
            .refresh_peer(fixture.peer(4_000), &renewed_facts, &mut || {
                fixture.now(4_500)
            })
            .unwrap();
        pending
            .read(&third, &renewed_facts, &mut || fixture.now(5_100))
            .unwrap();
        pending
            .finish(&renewed_facts, &mut || fixture.now(5_200))
            .unwrap();
    });
}

#[test]
fn pending_noise_cannot_renew_after_the_original_peer_proof_expires() {
    with_ready_auth(|auth, config| {
        let mut fixture = Fixture::new(auth, config, 30);
        let facts = fixture.facts();
        let mut pending = fixture.begin(auth).unwrap();
        let mut consumer = fixture.initiator();
        let first = consumer.write().unwrap();
        pending
            .read(&first, &facts, &mut || fixture.now(250))
            .unwrap();
        drop(facts);
        fixture.renew_heartbeat(4_500);
        let renewed_facts = fixture.facts();

        assert_eq!(
            pending.refresh_peer(fixture.peer(4_500), &renewed_facts, &mut || fixture
                .now(5_100)),
            Err(GateError::Disposed)
        );
        assert!(pending.handshake.is_none());
        assert_eq!(
            pending.refresh_peer(fixture.peer(5_200), &renewed_facts, &mut || fixture
                .now(5_300)),
            Err(GateError::Disposed)
        );
    });
}

#[test]
fn an_early_peer_renewal_does_not_extend_the_original_admission_deadline() {
    with_ready_auth(|auth, config| {
        let mut fixture = Fixture::new(auth, config, 5);
        let facts = fixture.facts();
        let mut pending = fixture.begin(auth).unwrap();
        let mut consumer = fixture.initiator();
        let first = consumer.write().unwrap();
        pending
            .read(&first, &facts, &mut || fixture.now(250))
            .unwrap();
        consumer
            .read(&pending.write(&facts, &mut || fixture.now(500)).unwrap())
            .unwrap();
        let third = consumer.write().unwrap();
        drop(facts);
        fixture.renew_heartbeat(1_000);
        let renewed_facts = fixture.facts();
        pending
            .refresh_peer(fixture.peer(1_000), &renewed_facts, &mut || {
                fixture.now(1_500)
            })
            .unwrap();

        assert_eq!(
            pending.read(&third, &renewed_facts, &mut || fixture.now(5_001)),
            Err(GateError::Disposed)
        );
        assert!(pending.core.disposed);
        assert!(
            pending
                .finish(&renewed_facts, &mut || fixture.now(5_002))
                .is_err()
        );
    });
}

#[test]
fn established_operation_response_uses_refreshed_peer_proof() {
    with_ready_auth(|auth, config| {
        let mut fixture = Fixture::new(auth, config, 30);
        let mut refreshed = fixture.established_connection(auth);
        let mut unrefreshed = fixture.established_connection(auth);
        fixture.renew_heartbeat(4_000);
        let facts = fixture.facts();

        refreshed
            .refresh_peer(fixture.peer(4_000), &facts, &mut || fixture.now(4_500))
            .unwrap();

        let grant = &fixture.context.grant;
        let workspace = WorkspaceContext {
            workspace_id: WorkspaceId::from_bytes(grant.workspace_id).unwrap(),
            workspace_epoch: WorkspaceEpoch::from_bytes(grant.workspace_epoch).unwrap(),
            runtime_id: RuntimeId::from_bytes(grant.runtime_id).unwrap(),
            runtime_generation: DecimalU64(grant.runtime_generation),
            host_access_epoch: DecimalU64(grant.access_epoch),
            grant_revision: DecimalU64(grant.grant_revision),
        };
        let request = RpcRequest {
            v: ApplicationMajor,
            r#type: RequestKind::Request,
            request_id: "refresh-test".to_owned().try_into().unwrap(),
            timeout_ms: TimeoutMs::new(10_000).unwrap(),
            call: RpcCall::OperationStatus(OperationStatusParams {
                context: workspace,
                operation_id: OperationId::from_bytes([42; 16]).unwrap(),
            }),
        };

        assert!(
            refreshed
                .cached_operation_response(&request, None, &facts, &mut || fixture.now(5_100))
                .is_ok()
        );
        assert!(!refreshed.core.disposed);

        assert_eq!(
            unrefreshed
                .cached_operation_response(&request, None, &facts, &mut || fixture.now(5_100)),
            Err(GateError::Disposed)
        );
        assert!(unrefreshed.core.disposed);
    });
}
