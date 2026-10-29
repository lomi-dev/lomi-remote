//! Synthetic protected identity + real private Store, no external HTTP/providers.
use super::super::tests::unconfirmed_storage;
use super::*;
use crate::testsupport::BuilderExt as _;
use lomi_remote_crypto::{GrantPurposeV3, Identity, Role};
use std::cell::RefCell;
pub(in super::super) struct Fixture<'a> {
    pub(in super::super) owner: Arc<shared_owner::SharedOwner>,
    operation: &'a owner_domain::Operation<'a>,
    public_io: &'a super::super::public_configuration::WorkerPublicIo<'a>,
    aborted: std::cell::Cell<bool>,
    _dir: tempfile::TempDir,
    endpoint: Arc<OwnerEndpoint>,
    pub(in super::super) store: Arc<shared_owner::PeerStoreForTest>,
    pub(in super::super) config: Config,
    pub(in super::super) state: Mutex<View>,
    pub(in super::super) stopping: Arc<AtomicBool>,
    pub(in super::super) gate: &'a AtomicBool,
    pub(in super::super) paused: &'a AtomicBool,
    pub(in super::super) retry: AtomicBool,
    receiver: mpsc::Receiver<Command>,
    pub(in super::super) anchor: Instant,
    base: u64,
    pub(in super::super) workspace: WorkspaceId,
    pub(in super::super) eligibility: PeerEligibility,
}
impl Fixture<'_> {
    pub(in super::super) fn runtime(&self) -> Runtime<'_> {
        Runtime {
            owner: &self.owner,
            operation: self.operation,
            public_io: self.public_io,
            aborted: &self.aborted,
            state: &self.state,
            stopping: &self.stopping,
            receiver: &self.receiver,
            retry_requested: &self.retry,
            gate: self.gate,
            paused: self.paused,
            base: self.base,
            anchor: self.anchor,
        }
    }
    pub(in super::super) fn refresh_eligibility_using_cloud(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    ) {
        let original_operation = self.operation.retained_identity();
        let original_deadline = self.operation.deadline();
        let original_base = self.base;
        let original_anchor = self.anchor;
        let original_owner = self.owner.clone();
        let original_public_io = self.public_io;
        let previous_heartbeat = self.eligibility.heartbeat.request_started;
        let api = RuntimeApi {
            binding: self.eligibility.binding.clone(),
            requests: RefCell::new(vec![]),
        };
        let mut worker = cloud::Worker::default();
        let generation = self.eligibility.binding.scope.authorization_generation;
        // Actual current-runtime GET, actual heartbeat, then PeerEligible. These
        // are three prescribed Cloud turns, not a retry or clock-budget reset.
        for stage in 0..3 {
            let outcome = worker
                .step_using(auth, &api, &self.config, self.runtime(), generation)
                .unwrap_or_else(|_| panic!("fixture Cloud refresh stage={stage}"));
            match (stage, outcome) {
                (0 | 1, cloud::StepOutcome::Network) => {}
                (2, cloud::StepOutcome::PeerEligible(eligibility)) => {
                    self.eligibility = *eligibility
                }
                _ => panic!("fixture expected GET/heartbeat/PeerEligible stage={stage}"),
            }
            let current = self.runtime();
            assert!(current.operation.is_same_admission(&original_operation));
            assert_eq!(current.operation.deadline(), original_deadline);
            assert_eq!(current.base, original_base);
            assert_eq!(current.anchor, original_anchor);
            assert!(std::ptr::eq(current.owner, original_owner.as_ref()));
            assert!(std::ptr::eq(current.public_io, original_public_io));
        }
        assert_eq!(*api.requests.borrow(), ["GET", "HB"]);
        assert!(self.eligibility.heartbeat.request_started > previous_heartbeat);
        assert_eq!(self.eligibility.binding, api.binding);
    }
    pub(in super::super) fn original_scope(&self) -> Arc<owner_domain::PeerContinuation> {
        self.owner
            .peer_continuation_for_test(self.operation)
            .unwrap()
    }
    // Direct fixture auth/Store calls share Runtime's nondecreasing wall sample.
    // Do not refresh heartbeat/request observations or reset any time budget.
    pub(in super::super) fn now(&self) -> u64 {
        let runtime = self.runtime();
        runtime
            .base
            .saturating_add(runtime.anchor.elapsed().as_secs())
    }
    pub(in super::super) fn proposal(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
    ) -> PairingProposal {
        let host = auth.public_host_identity(self.now()).unwrap();
        let consumer =
            Identity::generate(host.account_id.to_bytes(), [22; 16], Role::Device, 1).unwrap();
        let store = self.store.lock().unwrap();
        let local = store.workspace(self.workspace).unwrap();
        let runtime = &self.eligibility.binding.server_runtime;
        let maximum = GrantV3 {
            version: 3,
            api_major: 2,
            application_major: 2,
            account_id: host.account_id.to_bytes(),
            host_id: host.host_id.to_bytes(),
            host_fingerprint: host.fingerprint,
            host_authorization_id: host.host_authorization_id.to_bytes(),
            access_epoch: host.access_epoch,
            consumer_authorization_id: [23; 16],
            account_session_id: "synthetic-owner-session".into(),
            consumer_id: [22; 16],
            consumer_fingerprint: consumer.public_bundle().bundle.fingerprint().unwrap(),
            grant_id: [24; 16],
            grant_revision: 1,
            workspace_id: self.workspace.to_bytes(),
            workspace_epoch: local.state.context.workspace_epoch.to_bytes(),
            runtime_id: runtime.runtime_id.to_bytes(),
            runtime_generation: runtime.runtime_generation.0,
            capabilities: CapabilitySet::try_from(Capability::ALL.to_vec()).unwrap(),
            nonce: [25; 32],
            expires_at: self.base + 95,
            purpose: GrantPurposeV3::Workspace,
        };
        PairingProposal {
            maximum_grant: hex(&maximum.canonical().unwrap()).try_into().unwrap(),
            identities: PeerIdentities {
                host: host.identity,
                consumer: consumer.public_bundle().to_wire().unwrap(),
                host_fingerprint: hex(&host.fingerprint).try_into().unwrap(),
                consumer_fingerprint: hex(&maximum.consumer_fingerprint).try_into().unwrap(),
            },
            authority: CurrentAuthorityBinding {
                host_authorization_id: host.host_authorization_id,
                consumer_authorization_id: ConsumerAuthorizationId::from_bytes([23; 16]).unwrap(),
                account_session_id: "synthetic-owner-session".to_owned().try_into().unwrap(),
                access_epoch: DecimalU64(host.access_epoch),
                grant_revision: DecimalU64(1),
                workspace_epoch: local.state.context.workspace_epoch,
                runtime_id: runtime.runtime_id,
                runtime_generation: runtime.runtime_generation,
                terminal_membership: None,
            },
        }
    }
    fn step(
        &self,
        worker: &mut Worker,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        api: &dyn PeerApi,
    ) -> Result<(), StepError> {
        worker.step(
            auth,
            &self.config,
            self.runtime(),
            &self.eligibility,
            Some(api),
        )
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn pairing() -> PairingId {
    PairingId::from_bytes([26; 16]).unwrap()
}
pub(in super::super) fn fixture(
    test: impl FnOnce(&mut Fixture, &mut HostAuth<'_, dyn SecretStorage + '_>),
) {
    fixture_at_wall(1005, test);
}
// Current-wall Noise uses the same owner/Ready/IO fixture; old synthetic tests
// keep their original clock. No operation/deadline is recreated by this seam.
pub(in super::super) fn fixture_at_wall(
    base: u64,
    test: impl FnOnce(&mut Fixture, &mut HostAuth<'_, dyn SecretStorage + '_>),
) {
    fixture_at_wall_with_relay(base, None, test);
}
pub(in super::super) fn fixture_at_wall_with_relay(
    base: u64,
    relay: Option<lomi_remote_protocol::ipc::LocalRelayEndpoint>,
    test: impl FnOnce(&mut Fixture, &mut HostAuth<'_, dyn SecretStorage + '_>),
) {
    #[cfg(feature = "cloud-fixture")]
    fixture_at_wall_with_options(base, relay, None, test);
    #[cfg(not(feature = "cloud-fixture"))]
    fixture_at_wall_with_options(base, relay, None, test);
}
#[cfg(feature = "cloud-fixture")]
pub(in super::super) struct CloudFixtureOptions {
    pub host_id: HostId,
    pub runtime_id: RuntimeId,
    pub generation: u64,
    pub epoch: u64,
    pub publication_seq: u64,
    pub access: lomi_remote_protocol::http::HostAccessCredential,
    pub origin: String,
}
#[cfg(feature = "cloud-fixture")]
pub(in super::super) fn fixture_at_wall_with_cloud(
    base: u64,
    relay: Option<lomi_remote_protocol::ipc::LocalRelayEndpoint>,
    cloud: CloudFixtureOptions,
    test: impl FnOnce(&mut Fixture, &mut HostAuth<'_, dyn SecretStorage + '_>),
) {
    fixture_at_wall_with_options(base, relay, Some(cloud), test);
}
fn fixture_at_wall_with_options(
    base: u64,
    relay: Option<lomi_remote_protocol::ipc::LocalRelayEndpoint>,
    #[cfg(feature = "cloud-fixture")] cloud: Option<CloudFixtureOptions>,
    #[cfg(not(feature = "cloud-fixture"))] _cloud: Option<()>,
    test: impl FnOnce(&mut Fixture, &mut HostAuth<'_, dyn SecretStorage + '_>),
) {
    let dir = tempfile::Builder::new()
        .prefix("lomi-peer-owner-")
        .private_tempdir()
        .unwrap();
    let mut raw = HostStore::open(
        &dir.path().join("host.sqlite"),
        lomi_host_store::Limits::default(),
    )
    .unwrap();
    #[cfg(feature = "cloud-fixture")]
    if let Some(cloud) = cloud.as_ref() {
        raw.rebind_identity_for_fixture(cloud.host_id, cloud.runtime_id)
            .expect("fresh shared peer identity");
    }
    let selected = lomi_remote_protocol::ipc::LocalAuthConfiguration {
        version: 1,
        origin: "https://identity.example".to_owned().try_into().unwrap(),
        remote_api_origin: {
            #[cfg(feature = "cloud-fixture")]
            {
                cloud
                    .as_ref()
                    .map(|value| value.origin.clone().try_into().unwrap())
            }
            #[cfg(not(feature = "cloud-fixture"))]
            {
                None
            }
        },
        relay_endpoint: relay,
        client_id: "lomi-remote-host".to_owned().try_into().unwrap(),
        provider: crate::testsupport::provider(),
        keychain_path: None,
        protected_file_acknowledgement: crate::testsupport::file_acknowledgement(),
    };
    raw.configure_auth(&selected).unwrap();
    let config = configuration(raw.identity(), &selected).unwrap();
    let store = Arc::new(Mutex::new(raw));
    let host = store.lock().unwrap().identity().host_id;
    let mut provider = unconfirmed_storage(&config, host);
    let mut auth = HostAuth::open(
        &mut provider as &mut dyn SecretStorage,
        config.clone(),
        1005,
    )
    .unwrap();
    if base != 1005 {
        // Public transitions, rather than manufacturing a Ready/provider token.
        auth.confirm_registration(HostRegisterResult {
            host_id: host,
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
        auth.prepare_rotation(base).unwrap();
        let rotation = auth.rotation_request(base).unwrap();
        auth.accept_rotation(
            HostAuthorizationResult {
                account_id: AccountId::from_bytes([4; 16]).unwrap(),
                host_id: host,
                host_authorization_id: rotation.host_authorization_id,
                access: "synthetic_current_access".to_owned().try_into().unwrap(),
                refresh: "synthetic_current_refresh".to_owned().try_into().unwrap(),
                rotation_id: rotation.rotation_id,
                expires_in_seconds: DecimalU64(300),
            },
            base,
        )
        .unwrap();
    }
    let mut s = store.lock().unwrap();
    s.enable_authorization(0).unwrap();
    s.begin_login(OperationId::from_bytes(*uuid::Uuid::new_v4().as_bytes()).unwrap())
        .unwrap();
    let mut configuration = s.auth_configuration().unwrap().unwrap();
    #[cfg(feature = "cloud-fixture")]
    let remote_origin = cloud.as_ref().map_or_else(
        || "https://remote.example".to_owned(),
        |value| value.origin.clone(),
    );
    #[cfg(not(feature = "cloud-fixture"))]
    let remote_origin = "https://remote.example".to_owned();
    configuration.remote_api_origin = Some(remote_origin.clone().try_into().unwrap());
    s.configure_auth(&configuration).unwrap();
    let project = s
        .add_project(dir.path(), "private-title".to_owned().try_into().unwrap())
        .unwrap();
    let workspace = project.state.context.workspace_id;
    s.share(workspace, 0).unwrap();
    let scope = s.cloud_runtime_scope(0, remote_origin.clone()).unwrap();
    let runtime = RuntimeBinding {
        #[cfg(feature = "cloud-fixture")]
        runtime_id: cloud
            .as_ref()
            .map_or(scope.owner_runtime_id, |value| value.runtime_id),
        #[cfg(not(feature = "cloud-fixture"))]
        runtime_id: scope.owner_runtime_id,
        #[cfg(feature = "cloud-fixture")]
        runtime_generation: DecimalU64(cloud.as_ref().map_or(18, |value| value.generation)),
        #[cfg(not(feature = "cloud-fixture"))]
        runtime_generation: DecimalU64(18),
        #[cfg(feature = "cloud-fixture")]
        host_access_epoch: DecimalU64(cloud.as_ref().map_or(12, |value| value.epoch)),
        #[cfg(not(feature = "cloud-fixture"))]
        host_access_epoch: DecimalU64(12),
    };
    #[cfg(feature = "cloud-fixture")]
    let initial_publication_seq = cloud.as_ref().map_or(1, |value| value.publication_seq);
    #[cfg(not(feature = "cloud-fixture"))]
    let initial_publication_seq = 1;
    assert!(
        initial_publication_seq > 0,
        "fixture publication sequence must be positive"
    );
    let binding = s
        .compare_and_set_cloud_runtime(
            &scope,
            None,
            runtime.clone(),
            DecimalU64(initial_publication_seq - 1),
        )
        .unwrap();
    let intent = s.prepare_host_publication(&binding).unwrap();
    let binding = s
        .acknowledge_host_publication(
            &intent,
            &PublicationResult {
                runtime: runtime.clone(),
                publication_seq: DecimalU64(initial_publication_seq),
            },
        )
        .unwrap();
    let publication = s.acknowledged_host_publication(&binding).unwrap().unwrap();
    drop(s);
    let owner_lock = OwnerLock::acquire(&dir.path().canonicalize().unwrap()).unwrap();
    let mut raw = Arc::try_unwrap(store).ok().unwrap().into_inner().unwrap();
    super::super::public_configuration::startup(&mut raw, owner_lock.profile()).unwrap();
    let endpoint = Arc::new(
        OwnerEndpoint::bind(
            owner_lock,
            LocalDiscovery {
                version: LocalIpcVersion::CURRENT,
                profile_id: raw.identity().profile_id,
                host_id: raw.identity().host_id,
                runtime_id: raw.runtime_id(),
                build_id: "test".to_owned(),
            },
        )
        .unwrap(),
    );
    let owner = shared_owner::SharedOwner::new(raw).unwrap();
    let setup = super::super::public_configuration::PublicSetup::new(endpoint.clone());
    let paused = AtomicBool::new(false);
    let gate = AtomicBool::new(true);
    let io = setup.enter_owned(&paused).unwrap().unwrap();
    let cancelled = AtomicBool::new(false);
    let operation =
        owner_domain::Operation::new(Instant::now() + Duration::from_secs(60), &cancelled);
    {
        let mut attempt = shared_owner::ConfiguredWorkerAttempt::from_existing_worker(
            &mut auth,
            &io,
            &gate,
            &paused,
            base,
            Instant::now(),
        )
        .unwrap();
        attempt.install_ready_http_script_for_test(
            std::rc::Rc::new(std::cell::Cell::new(0)),
            std::rc::Rc::new(std::cell::RefCell::new(None)),
            base,
        );
        let mut ready = attempt.begin_ready(&owner, &operation).unwrap();
        while !ready.try_step().unwrap() {}
    }
    #[cfg(feature = "cloud-fixture")]
    if let Some(cloud) = cloud {
        auth.replace_ready_access_for_fixture(
            cloud.access,
            DecimalU64(cloud.epoch),
            base.saturating_add(300),
        )
        .unwrap_or_else(|_| panic!("fixture CloudWorker access setup failed"));
    }
    let store = owner.peer_store_for_test();
    let (.., receiver) = mpsc::sync_channel(1);
    let start = Instant::now();
    let eligibility = PeerEligibility {
        identity: auth.public_host_identity(base).unwrap(),
        binding,
        publication,
        heartbeat: HeartbeatObservation {
            scope,
            runtime,
            request_started: start,
            wall_at_request_start: base,
            lease_ms: 30000,
            freshness_ms: 5000,
        },
    };
    test(
        &mut Fixture {
            _dir: dir,
            endpoint,
            owner,
            operation: &operation,
            public_io: &io,
            aborted: std::cell::Cell::new(false),
            store,
            config,
            state: Mutex::new(initial()),
            stopping: Arc::new(AtomicBool::new(false)),
            gate: &gate,
            paused: &paused,
            retry: AtomicBool::new(false),
            receiver,
            anchor: start,
            base,
            workspace,
            eligibility,
        },
        &mut auth,
    );
}
enum Reply {
    Poll(PairingPendingResult),
    State(Box<PairingResult>),
    Error(lomi_host_http::Error),
}
impl Reply {
    fn state(value: PairingResult) -> Self {
        Self::State(Box::new(value))
    }
}
pub(super) struct Api<'a> {
    replies: RefCell<VecDeque<Reply>>,
    requests: RefCell<Vec<&'static str>>,
    params: RefCell<Vec<PairingDecisionParams>>,
    hook: RefCell<Option<Box<dyn FnOnce() + 'a>>>,
}
impl Api<'_> {
    pub(super) fn poll(proposal: PairingProposal) -> Self {
        Self {
            replies: RefCell::new(
                vec![Reply::Poll(PairingPendingResult {
                    pairings: PendingPairings::try_from(vec![PendingPairing {
                        pairing_id: pairing(),
                        proposal,
                    }])
                    .unwrap(),
                })]
                .into(),
            ),
            requests: RefCell::new(vec![]),
            params: RefCell::new(vec![]),
            hook: RefCell::new(None),
        }
    }
    fn reply(&self, name: &'static str) -> Result<Reply, lomi_host_http::Error> {
        self.requests.borrow_mut().push(name);
        if let Some(hook) = self.hook.borrow_mut().take() {
            hook();
        }
        match self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("bounded peer script")
        {
            Reply::Error(error) => Err(error),
            r => Ok(r),
        }
    }
}
impl PeerApi for Api<'_> {
    fn pending(
        &self,
        _: HostId,
        _: &HostAccessCredential,
    ) -> Result<PairingPendingResult, lomi_host_http::Error> {
        match self.reply("POLL")? {
            Reply::Poll(p) => Ok(p),
            _ => panic!("poll reply"),
        }
    }
    fn get(
        &self,
        _: PairingId,
        _: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        match self.reply("GET")? {
            Reply::State(p) => Ok(*p),
            _ => panic!("get reply"),
        }
    }
    fn decide(
        &self,
        _: PairingId,
        p: &PairingDecisionParams,
        _: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        self.params.borrow_mut().push(p.clone());
        match self.reply("POST")? {
            Reply::State(p) => Ok(*p),
            _ => panic!("decision reply"),
        }
    }
}
fn approved(intent: &PairingDecisionIntent) -> PairingResult {
    let PairingDecisionParams::Approve { grant, .. } = &intent.preparation.params else {
        panic!("approval")
    };
    PairingResult::Approved {
        pairing_id: intent.preparation.pairing_id,
        proposal: intent.preparation.proposal.clone(),
        grant: grant.clone(),
        identities: intent.preparation.proposal.identities.clone(),
        authority: intent.preparation.proposal.authority.clone(),
    }
}
fn prepared(
    f: &Fixture,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
) -> (Worker, Api<'static>, PairingDecisionIntent) {
    let api = Api::poll(f.proposal(auth));
    let mut worker = Worker::default();
    assert!(f.step(&mut worker, auth, &api).is_ok());
    assert!(f.step(&mut worker, auth, &api).is_ok());
    let intent = f
        .store
        .lock()
        .unwrap()
        .pending_pairing_decisions()
        .unwrap()
        .remove(0);
    (worker, api, intent)
}
#[test]
fn automatic_pairing_uses_one_request_per_turn_and_excludes_git_execute() {
    fixture(|f, auth| {
        let (mut worker, api, intent) = prepared(f, auth);
        assert_eq!(*api.requests.borrow(), ["POLL"]);
        let PairingDecisionParams::Approve { grant, .. } = &intent.preparation.params else {
            panic!("approval")
        };
        let signed = SignedGrantV3::from_wire(grant).unwrap();
        assert!(!signed.grant.capabilities.contains(Capability::GitExecute));
        assert_eq!(signed.grant.expires_at, 1100);
        api.replies
            .borrow_mut()
            .push_back(Reply::state(approved(&intent)));
        let store = f.store.clone();
        *api.hook.borrow_mut() = Some(Box::new(move || {
            assert!(store.try_lock().is_ok(), "no Store lock across peer HTTP")
        }));
        assert!(f.step(&mut worker, auth, &api).is_ok());
        assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
        assert!(
            f.store
                .lock()
                .unwrap()
                .pending_pairing_decisions()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .acknowledged_workspace_grants()
                .unwrap()
                .len(),
            1
        );
        assert!(f.step(&mut worker, auth, &api).is_ok());
        assert_eq!(api.requests.borrow().len(), 2);
    });
}
#[test]
fn lost_post_requires_exact_get_recovery_and_never_resigns_or_rebases() {
    for approved_on_get in [false, true] {
        fixture(|f, auth| {
            let (mut worker, api, intent) = prepared(f, auth);
            let bytes = serde_json::to_vec(&intent).unwrap();
            api.replies
                .borrow_mut()
                .push_back(Reply::Error(lomi_host_http::Error::Timeout));
            assert!(f.step(&mut worker, auth, &api).is_ok());
            api.replies
                .borrow_mut()
                .push_back(Reply::state(if approved_on_get {
                    approved(&intent)
                } else {
                    PairingResult::Pending {
                        pairing_id: pairing(),
                        proposal: intent.preparation.proposal.clone(),
                    }
                }));
            assert!(f.step(&mut worker, auth, &api).is_ok());
            assert_eq!(*api.requests.borrow(), ["POLL", "POST", "GET"]);
            if !approved_on_get {
                assert_eq!(
                    serde_json::to_vec(
                        &f.store.lock().unwrap().pending_pairing_decisions().unwrap()[0]
                    )
                    .unwrap(),
                    bytes
                );
                api.replies
                    .borrow_mut()
                    .push_back(Reply::state(approved(&intent)));
                assert!(f.step(&mut worker, auth, &api).is_ok());
                assert_eq!(api.params.borrow()[0], api.params.borrow()[1]);
            }
            assert_eq!(
                f.store
                    .lock()
                    .unwrap()
                    .acknowledged_workspace_grants()
                    .unwrap()
                    .len(),
                1
            );
        });
    }
}
#[test]
fn restart_of_coordinator_gets_durable_intent_before_any_send() {
    fixture(|f, auth| {
        let (_, api, intent) = prepared(f, auth);
        let mut worker = Worker::default();
        api.replies
            .borrow_mut()
            .push_back(Reply::state(approved(&intent)));
        assert!(f.step(&mut worker, auth, &api).is_ok());
        assert_eq!(*api.requests.borrow(), ["POLL", "GET"]);
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .acknowledged_workspace_grants()
                .unwrap()
                .len(),
            1
        );
    });
}
#[test]
fn resource_local_errors_and_invalid_proposals_leave_owner_unlocked() {
    for change in 0..9 {
        fixture(|f, auth| {
            let mut proposal = f.proposal(auth);
            match change {
                0 => (),
                1 => proposal.identities.host_fingerprint = "ff".repeat(32).try_into().unwrap(),
                2 => {
                    proposal.authority.account_session_id =
                        "different-session".to_owned().try_into().unwrap()
                }
                3 => {
                    proposal.authority.host_authorization_id =
                        HostAuthorizationId::from_bytes([99; 16]).unwrap()
                }
                4 => {
                    let mut maximum = GrantV3::from_canonical(
                        &hex_bytes(proposal.maximum_grant.expose_wire())
                            .ok()
                            .unwrap(),
                    )
                    .unwrap();
                    maximum.workspace_id = [99; 16];
                    proposal.maximum_grant = hex(&maximum.canonical().unwrap()).try_into().unwrap();
                }
                5 => proposal.identities.consumer_fingerprint = "ff".repeat(32).try_into().unwrap(),
                6 => {
                    proposal.identities.consumer =
                        Identity::generate([99; 16], [22; 16], Role::Device, 1)
                            .unwrap()
                            .public_bundle()
                            .to_wire()
                            .unwrap()
                }
                7 => {
                    proposal.identities.consumer = Identity::generate(
                        f.eligibility.identity.account_id.to_bytes(),
                        [22; 16],
                        Role::Host,
                        1,
                    )
                    .unwrap()
                    .public_bundle()
                    .to_wire()
                    .unwrap()
                }
                8 => {
                    proposal.identities.consumer = Identity::generate(
                        f.eligibility.identity.account_id.to_bytes(),
                        [99; 16],
                        Role::Device,
                        1,
                    )
                    .unwrap()
                    .public_bundle()
                    .to_wire()
                    .unwrap()
                }
                _ => unreachable!(),
            }
            let api = Api::poll(proposal);
            if change == 0 {
                *api.replies.borrow_mut() = vec![Reply::Error(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::AuthRequired,
                ))]
                .into();
            }
            let mut worker = Worker::default();
            assert!(f.step(&mut worker, auth, &api).is_ok());
            assert!(f.step(&mut worker, auth, &api).is_ok());
            let state = f.store.lock().unwrap().authorization_state().unwrap();
            assert!(!state.locked && !state.pending_cloud_revoke);
            assert!(!f.gate.load(Ordering::Acquire));
            assert!(
                f.store
                    .lock()
                    .unwrap()
                    .pending_pairing_decisions()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(*api.requests.borrow(), ["POLL"]);
        });
    }
}
#[test]
fn local_gates_and_membership_changes_suppress_post_and_preserve_exact_intent() {
    for change in 0..8 {
        fixture(|f, auth| {
            let (mut worker, api, intent) = prepared(f, auth);
            match change {
                0 => f.gate.store(true, Ordering::Release),
                1 => f.paused.store(true, Ordering::Release),
                2 => f.stopping.store(true, Ordering::Release),
                3 => {
                    f.store.lock().unwrap().unshare(f.workspace).unwrap();
                }
                4 => {
                    f.store
                        .lock()
                        .unwrap()
                        .fence_authorization(lomi_host_store::AuthorizationFenceReason::LocalLogout)
                        .unwrap();
                }
                5 => {
                    let mut store = f.store.lock().unwrap();
                    store
                        .prepare_host_publication(&f.eligibility.binding)
                        .unwrap();
                }
                6 => {
                    let mut store = f.store.lock().unwrap();
                    store
                        .invalidate_cloud_runtime(
                            &f.eligibility.binding.scope,
                            &f.eligibility.binding,
                            None,
                        )
                        .unwrap();
                }
                7 => {
                    auth.prepare_rotation(f.now()).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(f.step(&mut worker, auth, &api).is_err());
            assert_eq!(*api.requests.borrow(), ["POLL"]);
            assert_eq!(
                f.store.lock().unwrap().pending_pairing_decisions().unwrap(),
                vec![intent]
            );
        });
    }
}
#[test]
fn slow_poll_sign_and_post_consume_original_freshness_without_local_authority_effects() {
    for stage in 0..3 {
        fixture(|f, auth| {
            let proposal = f.proposal(auth);
            let api = Api::poll(proposal);
            let mut worker = Worker::default();
            if stage == 0 {
                f.eligibility.heartbeat.freshness_ms = 50;
                *api.hook.borrow_mut() =
                    Some(Box::new(|| thread::sleep(Duration::from_millis(75))));
                assert!(f.step(&mut worker, auth, &api).is_err());
                assert!(worker.cache.is_empty());
            } else {
                assert!(f.step(&mut worker, auth, &api).is_ok());
                if stage == 1 {
                    f.eligibility.heartbeat.freshness_ms = 50;
                    worker.cache.front_mut().unwrap().observation = std::sync::Arc::new(
                        Observation::new(&f.eligibility, Instant::now(), f.original_scope()),
                    );
                    worker.after_sign = Some(Box::new(|| thread::sleep(Duration::from_millis(75))));
                    assert!(f.step(&mut worker, auth, &api).is_err());
                    assert!(
                        f.store
                            .lock()
                            .unwrap()
                            .pending_pairing_decisions()
                            .unwrap()
                            .is_empty()
                    );
                } else {
                    assert!(f.step(&mut worker, auth, &api).is_ok());
                    let intent = f
                        .store
                        .lock()
                        .unwrap()
                        .pending_pairing_decisions()
                        .unwrap()
                        .remove(0);
                    f.eligibility.heartbeat.freshness_ms = 50;
                    api.replies
                        .borrow_mut()
                        .push_back(Reply::state(approved(&intent)));
                    *api.hook.borrow_mut() =
                        Some(Box::new(|| thread::sleep(Duration::from_millis(75))));
                    assert!(f.step(&mut worker, auth, &api).is_err());
                    assert_eq!(
                        f.store.lock().unwrap().pending_pairing_decisions().unwrap(),
                        vec![intent]
                    );
                }
            }
            assert!(
                f.store
                    .lock()
                    .unwrap()
                    .acknowledged_workspace_grants()
                    .unwrap()
                    .is_empty()
            );
            assert!(
                !f.store
                    .lock()
                    .unwrap()
                    .authorization_state()
                    .unwrap()
                    .locked
            );
        });
    }
}
#[test]
fn later_heartbeat_cannot_extend_an_old_tls_observation() {
    fixture(|f, auth| {
        let (mut worker, api, intent) = prepared(f, auth);
        let work = worker.active.as_mut().unwrap();
        let mut old = Observation::new(
            &f.eligibility,
            Instant::now() - Duration::from_secs(6),
            f.original_scope(),
        );
        old.heartbeat.request_started = Instant::now() - Duration::from_secs(6);
        work.observation = std::sync::Arc::new(old);
        f.eligibility.heartbeat.request_started = Instant::now();
        assert!(f.step(&mut worker, auth, &api).is_ok());
        assert_eq!(*api.requests.borrow(), ["POLL"]);
        assert_eq!(
            f.store.lock().unwrap().pending_pairing_decisions().unwrap(),
            vec![intent]
        );
    });
}
#[test]
fn mismatched_approved_or_pending_get_never_acknowledges_or_changes_frozen_body() {
    for pending in [false, true] {
        fixture(|f, auth| {
            let (_, api, intent) = prepared(f, auth);
            let mut worker = Worker::default();
            let mut response = if pending {
                PairingResult::Pending {
                    pairing_id: pairing(),
                    proposal: intent.preparation.proposal.clone(),
                }
            } else {
                approved(&intent)
            };
            match &mut response {
                PairingResult::Pending { proposal, .. } => proposal.authority.grant_revision.0 += 1,
                PairingResult::Approved { grant, .. } => {
                    grant.signature = "44".repeat(64).try_into().unwrap()
                }
                _ => unreachable!(),
            };
            api.replies.borrow_mut().push_back(Reply::state(response));
            assert!(f.step(&mut worker, auth, &api).is_ok());
            assert_eq!(
                f.store.lock().unwrap().pending_pairing_decisions().unwrap(),
                vec![intent]
            );
            assert!(
                f.store
                    .lock()
                    .unwrap()
                    .acknowledged_workspace_grants()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(*api.requests.borrow(), ["POLL", "GET"]);
        });
    }
}

#[test]
fn gate_during_post_drops_response_without_ack_or_intent_loss() {
    fixture(|f, auth| {
        let (mut worker, api, intent) = prepared(f, auth);
        api.replies
            .borrow_mut()
            .push_back(Reply::state(approved(&intent)));
        let gate = &f.gate;
        let api = Api {
            replies: api.replies,
            requests: api.requests,
            params: api.params,
            hook: RefCell::new(Some(Box::new(|| gate.store(true, Ordering::Release)))),
        };
        assert!(f.step(&mut worker, auth, &api).is_err());
        assert_eq!(
            f.store.lock().unwrap().pending_pairing_decisions().unwrap(),
            vec![intent]
        );
        assert!(
            f.store
                .lock()
                .unwrap()
                .acknowledged_workspace_grants()
                .unwrap()
                .is_empty()
        );
        assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
    });
}
#[test]
fn storage_failure_is_sealed_while_actual_sql_ack_rollback_is_covered_by_store_tests() {
    fixture(|f, auth| {
        let (_, _, intent) = prepared(f, auth);
        let result: ResultPeer<()> = durable(Err(StoreError::Storage));
        assert!(matches!(
            result,
            Err(PeerError::Fatal(StepError::Auth(
                lomi_host_auth::Error::Sealed
            )))
        ));
        assert_eq!(
            f.store.lock().unwrap().pending_pairing_decisions().unwrap(),
            vec![intent]
        );
    });
}
#[test]
fn peer_auth_required_on_get_or_post_never_globally_fences_owner_or_retries_blindly() {
    for failure in [
        lomi_host_http::DataFailure::AuthRequired,
        lomi_host_http::DataFailure::ScopeDenied,
    ] {
        fixture(|f, auth| {
            let (mut worker, api, intent) = prepared(f, auth);
            api.replies
                .borrow_mut()
                .push_back(Reply::Error(lomi_host_http::Error::DataRemote(failure)));
            assert!(f.step(&mut worker, auth, &api).is_ok());
            api.replies
                .borrow_mut()
                .push_back(Reply::Error(lomi_host_http::Error::DataRemote(failure)));
            assert!(f.step(&mut worker, auth, &api).is_ok());
            assert_eq!(*api.requests.borrow(), ["POLL", "POST", "GET"]);
            assert_eq!(
                f.store.lock().unwrap().pending_pairing_decisions().unwrap(),
                vec![intent]
            );
            assert!(
                !f.store
                    .lock()
                    .unwrap()
                    .authorization_state()
                    .unwrap()
                    .locked
            );
            assert!(!f.gate.load(Ordering::Acquire));
        });
    }
}
fn fill_pending(
    f: &Fixture,
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    count: usize,
) -> Vec<PairingDecisionIntent> {
    let base = f.proposal(auth);
    let local = f.store.lock().unwrap().workspace(f.workspace).unwrap();
    let mut intents = Vec::new();
    for n in 0..count {
        let mut proposal = base.clone();
        let mut maximum = GrantV3::from_canonical(
            &hex_bytes(proposal.maximum_grant.expose_wire())
                .ok()
                .unwrap(),
        )
        .unwrap();
        maximum.grant_id = (n as u128 + 100).to_be_bytes();
        proposal.maximum_grant = hex(&maximum.canonical().unwrap()).try_into().unwrap();
        let mut narrowed = maximum.clone();
        narrowed.capabilities = CapabilitySet::control_with_workspace_tools();
        let signed = auth.sign_grant_v3(&narrowed, f.now()).unwrap();
        let request = PairingDecisionPreparation {
            scope: CloudPairingScope {
                runtime_scope: f.eligibility.binding.scope.clone(),
                runtime: f.eligibility.binding.server_runtime.clone(),
                workspace_id: f.workspace,
                workspace_epoch: local.state.context.workspace_epoch,
                workspace_fence: local.fence,
            },
            pairing_id: PairingId::from_bytes((n as u128 + 200).to_be_bytes()).unwrap(),
            grant_id: GrantId::from_bytes(maximum.grant_id).unwrap(),
            account_id: f.eligibility.identity.account_id,
            window_identity_id: WindowIdentityId::from_bytes(maximum.consumer_id).unwrap(),
            proposal,
            original_expires_at: signed.grant.expires_at,
            params: PairingDecisionParams::Approve {
                grant: signed.to_wire().unwrap(),
                runtime: f.eligibility.binding.server_runtime.clone(),
            },
        };
        intents.push(
            f.store
                .lock()
                .unwrap()
                .prepare_pairing_decision(request, f.now())
                .unwrap(),
        );
    }
    intents
}
#[test]
fn sixty_four_resource_local_unknowns_still_allow_a_due_fresh_poll() {
    fixture(|f, auth| {
        let original = fill_pending(f, auth, 64);
        let mut worker = Worker::default();
        let api = Api::poll(f.proposal(auth));
        let poll = api.replies.borrow_mut().pop_front().unwrap();
        for _ in 0..3 {
            api.replies
                .borrow_mut()
                .push_back(Reply::Error(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::AuthRequired,
                )));
        }
        api.replies.borrow_mut().push_back(poll);
        for expected in 1..=4 {
            assert!(f.step(&mut worker, auth, &api).is_ok());
            assert_eq!(api.requests.borrow().len(), expected);
        }
        assert_eq!(*api.requests.borrow(), ["GET", "GET", "GET", "POLL"]);
        assert_eq!(worker.cache.len(), 1);
        assert_eq!(
            f.store.lock().unwrap().pending_pairing_decisions().unwrap(),
            original
        );
        assert!(
            !f.store
                .lock()
                .unwrap()
                .authorization_state()
                .unwrap()
                .locked
        );
    });
}
#[test]
fn sixty_four_expired_current_or_old_runtime_intents_release_slots_and_fresh_work_progresses() {
    for old_runtime in [false, true] {
        fixture(|f, auth| {
            fill_pending(f, auth, 64);
            if old_runtime {
                let mut store = f.store.lock().unwrap();
                let previous = f.eligibility.binding.clone();
                store
                    .invalidate_cloud_runtime(&previous.scope, &previous, None)
                    .unwrap();
                let mut runtime = previous.server_runtime.clone();
                runtime.runtime_generation.0 += 1;
                let binding = store
                    .compare_and_set_cloud_runtime(
                        &previous.scope,
                        None,
                        runtime.clone(),
                        DecimalU64(0),
                    )
                    .unwrap();
                let intent = store.prepare_host_publication(&binding).unwrap();
                let binding = store
                    .acknowledge_host_publication(
                        &intent,
                        &PublicationResult {
                            runtime: runtime.clone(),
                            publication_seq: intent.params.publication_seq,
                        },
                    )
                    .unwrap();
                f.eligibility.publication = store
                    .acknowledged_host_publication(&binding)
                    .unwrap()
                    .unwrap();
                f.eligibility.binding = binding;
                f.eligibility.heartbeat.runtime = runtime;
            }
            let mut proposal = f.proposal(auth);
            let mut maximum = GrantV3::from_canonical(
                &hex_bytes(proposal.maximum_grant.expose_wire())
                    .ok()
                    .unwrap(),
            )
            .unwrap();
            maximum.expires_at = 1200;
            proposal.maximum_grant = hex(&maximum.canonical().unwrap()).try_into().unwrap();
            let api = Api::poll(proposal);
            let mut worker = Worker::default();
            f.eligibility.heartbeat.request_started = Instant::now();
            let runtime = Runtime {
                base: 1100,
                ..f.runtime()
            };
            let signed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let signed_hook = signed.clone();
            worker.after_sign = Some(Box::new(move || {
                signed_hook.fetch_add(1, Ordering::SeqCst);
            }));
            let mut trace = Vec::new();
            let mut found = None;
            for turn in 0..12 {
                let before = api.requests.borrow().len();
                let result = worker.step(auth, &f.config, runtime, &f.eligibility, Some(&api));
                assert!(
                    result.is_ok(),
                    "old_runtime={old_runtime} turn={} prior_trace={trace:?}",
                    turn + 1
                );
                assert!(api.requests.borrow().len() <= before + 1);
                let pending = f.store.lock().unwrap().pending_pairing_decisions().unwrap();
                trace.push(format!(
                    "turn={} pending={} cache={} active={} failures={} poll_turns={} poll_wait_ms={:?} signed={} requests={:?}",
                    turn + 1,
                    pending.len(),
                    worker.cache.len(),
                    worker.active.is_some(),
                    worker.failures,
                    worker.turns_since_poll,
                    worker.poll_at.map(|at| at.saturating_duration_since(Instant::now()).as_millis()),
                    signed.load(Ordering::SeqCst),
                    api.requests.borrow(),
                ));
                assert_eq!(
                    worker.failures, 0,
                    "old_runtime={old_runtime} trace={trace:?}"
                );
                found = f
                    .store
                    .lock()
                    .unwrap()
                    .pending_pairing_decisions()
                    .unwrap()
                    .into_iter()
                    .find(|p| p.preparation.pairing_id == pairing());
                if found.is_some() {
                    break;
                }
            }
            let fresh = found.unwrap_or_else(|| {
                panic!("bounded expiry retirement and poll fairness: old_runtime={old_runtime} trace={trace:?}")
            });
            assert_eq!(
                signed.load(Ordering::SeqCst),
                1,
                "old_runtime={old_runtime} trace={trace:?}"
            );
            assert_eq!(*api.requests.borrow(), ["POLL"]);
            api.replies
                .borrow_mut()
                .push_back(Reply::state(approved(&fresh)));
            assert!(
                worker
                    .step(auth, &f.config, runtime, &f.eligibility, Some(&api))
                    .is_ok()
            );
            assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
            assert_eq!(
                f.store
                    .lock()
                    .unwrap()
                    .acknowledged_workspace_grants()
                    .unwrap()
                    .len(),
                1
            );
        });
    }
}
#[test]
fn exact_signed_expiry_retires_ack_evidence_without_http_or_revocation() {
    fixture(|f, auth| {
        let (mut worker, api, intent) = prepared(f, auth);
        api.replies
            .borrow_mut()
            .push_back(Reply::state(approved(&intent)));
        assert!(f.step(&mut worker, auth, &api).is_ok());
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .acknowledged_workspace_grants()
                .unwrap()
                .len(),
            1
        );
        worker.capacity_blocked = true;
        worker.turns_since_poll = 0;
        let runtime = Runtime {
            base: 1100,
            ..f.runtime()
        };
        assert!(
            worker
                .step(auth, &f.config, runtime, &f.eligibility, Some(&api))
                .is_ok()
        );
        assert!(
            f.store
                .lock()
                .unwrap()
                .acknowledged_workspace_grants()
                .unwrap()
                .is_empty()
        );
        assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
        let mut false_expiry = intent.clone();
        false_expiry.preparation.original_expires_at -= 1;
        assert!(verify_expired_intent(&false_expiry, &f.eligibility.identity, 1100).is_err());
        assert!(verify_expired_intent(&intent, &f.eligibility.identity, 1099).is_err());
    });
}

pub(in super::super) struct PriorityAuth<'a> {
    pub(in super::super) stop: &'a AtomicBool,
    pub(in super::super) refreshes: RefCell<usize>,
}
impl AuthTransport for PriorityAuth<'_> {
    fn revoke(
        &self,
        _: HostId,
        _: &HostRevokeParams,
        _: &HostAccessCredential,
    ) -> Result<HostRevokeResult, lomi_host_http::Error> {
        panic!("unexpected revoke")
    }
    fn initiate(
        &self,
        _: &EnrollmentInitiateParams,
    ) -> Result<EnrollmentInitiateResult, lomi_host_http::Error> {
        panic!("unexpected initiation")
    }
    fn poll(&self, _: &DeviceCode) -> Result<lomi_host_http::PollOutcome, lomi_host_http::Error> {
        panic!("unexpected identity poll")
    }
    fn exchange(
        &self,
        _: &HostAuthorizationExchangeParams,
    ) -> Result<HostAuthorizationResult, lomi_host_http::Error> {
        panic!("unexpected exchange")
    }
    fn register(
        &self,
        _: &HostRegisterParams,
        _: &HostAccessCredential,
    ) -> Result<HostRegisterResult, lomi_host_http::Error> {
        panic!("unexpected registration")
    }
    fn refresh(
        &self,
        _: &HostAuthorizationRefreshParams,
    ) -> Result<HostAuthorizationResult, lomi_host_http::Error> {
        *self.refreshes.borrow_mut() += 1;
        self.stop.store(true, Ordering::Release);
        Err(lomi_host_http::Error::Network)
    }
}
pub(in super::super) struct RuntimeApi {
    pub(in super::super) binding: lomi_host_store::CloudRuntimeState,
    pub(in super::super) requests: RefCell<Vec<&'static str>>,
}
impl cloud::DataApi for RuntimeApi {
    fn get(
        &self,
        host: HostId,
        _: &HostAccessCredential,
    ) -> Result<HostRuntimeGetResult, lomi_host_http::Error> {
        self.requests.borrow_mut().push("GET");
        Ok(HostRuntimeGetResult {
            host_id: host,
            host_access_epoch: self.binding.server_runtime.host_access_epoch,
            runtime_generation: self.binding.server_runtime.runtime_generation,
            runtime: Some(self.binding.server_runtime.clone()),
            publication_seq: self.binding.acknowledged_publication_seq,
            lease_ms: DecimalU64(30000),
            freshness_ms: DecimalU64(5000),
        })
    }
    fn claim(
        &self,
        _: HostId,
        _: &RuntimeClaimParams,
        _: &HostAccessCredential,
    ) -> Result<RuntimeClaimResult, lomi_host_http::Error> {
        panic!("unexpected claim")
    }
    fn heartbeat(
        &self,
        _: HostId,
        _: &HeartbeatParams,
        _: &HostAccessCredential,
    ) -> Result<HeartbeatResult, lomi_host_http::Error> {
        self.requests.borrow_mut().push("HB");
        Ok(HeartbeatResult {
            runtime: self.binding.server_runtime.clone(),
            lease_ms: DecimalU64(30000),
            freshness_ms: DecimalU64(5000),
        })
    }
    fn publish(
        &self,
        _: HostId,
        _: &PublicationParams,
        _: &HostAccessCredential,
    ) -> Result<PublicationResult, lomi_host_http::Error> {
        panic!("unexpected publication")
    }
}
#[test]
fn combined_owner_loop_runs_runtime_get_heartbeat_and_refresh_before_peer_http() {
    for refresh in [false, true] {
        fixture(|f, auth| {
            let transport = PriorityAuth {
                stop: &f.stopping,
                refreshes: RefCell::new(0),
            };
            let data = RuntimeApi {
                binding: f.eligibility.binding.clone(),
                requests: RefCell::new(vec![]),
            };
            let api = Api::poll(f.proposal(auth));
            if refresh {
                auth.prepare_rotation(f.now()).unwrap();
            } else {
                *api.hook.borrow_mut() = Some(Box::new(|| {
                    assert_eq!(*data.requests.borrow(), ["GET", "HB"]);
                    f.stopping.store(true, Ordering::Release);
                }));
            }
            run_with_apis(
                auth,
                &transport,
                &f.config,
                f.runtime(),
                InjectedApis {
                    data: Some(&data),
                    pairing: Some(&api),
                    channel: None,
                    enabled: true,
                    channels_enabled: false,
                },
            );
            if refresh {
                assert_eq!(*transport.refreshes.borrow(), 1);
                assert!(data.requests.borrow().is_empty());
                assert!(api.requests.borrow().is_empty());
            } else {
                assert_eq!(*transport.refreshes.borrow(), 0);
                assert_eq!(*data.requests.borrow(), ["GET", "HB"]);
                assert_eq!(*api.requests.borrow(), ["POLL"]);
            }
        });
    }
}

#[test]
fn real_store_reopen_preserves_request_but_new_owner_never_sends_or_acks_old_approval() {
    fixture(|f, auth| {
        let (_, api, intent) = prepared(f, auth);
        let old_continuation = f.original_scope();
        let original_operation = f.runtime().operation.retained_identity();
        let original_deadline = f.runtime().operation.deadline();
        let reopened = {
            let mut store = f.store.lock().unwrap();
            let placeholder = HostStore::open(
                &f._dir.path().join("placeholder.sqlite"),
                lomi_host_store::Limits::default(),
            )
            .unwrap();
            drop(std::mem::replace(&mut *store, placeholder));
            let mut reopened = HostStore::open(
                &f._dir.path().join("host.sqlite"),
                lomi_host_store::Limits::default(),
            )
            .unwrap();
            // Reopening deliberately drops volatile public-file readiness.
            // Reconcile and confirm the exact existing profile file while the
            // raw Store is still exclusive, before restoring authorization.
            assert!(!reopened.public_configuration_ready().unwrap());
            super::super::public_configuration::startup(&mut reopened, f.endpoint.profile())
                .unwrap();
            assert!(reopened.public_configuration_ready().unwrap());
            drop(std::mem::replace(&mut *store, reopened));
            store.enable_authorization(0).unwrap();
            let scope = store
                .cloud_runtime_scope(0, "https://remote.example".into())
                .unwrap();
            let previous = store
                .cloud_runtime_reconciliation_state(&scope)
                .unwrap()
                .unwrap();
            store
                .invalidate_cloud_runtime(&scope, &previous, None)
                .unwrap();
            let runtime = RuntimeBinding {
                runtime_id: scope.owner_runtime_id,
                runtime_generation: DecimalU64(19),
                host_access_epoch: DecimalU64(13),
            };
            let binding = store
                .compare_and_set_cloud_runtime(&scope, None, runtime.clone(), DecimalU64(0))
                .unwrap();
            let publication = store.prepare_host_publication(&binding).unwrap();
            let binding = store
                .acknowledge_host_publication(
                    &publication,
                    &PublicationResult {
                        runtime: runtime.clone(),
                        publication_seq: publication.params.publication_seq,
                    },
                )
                .unwrap();
            auth.accept_runtime_observation(
                DecimalU64(12),
                HostRuntimeGetResult {
                    host_id: scope.host_id,
                    host_access_epoch: runtime.host_access_epoch,
                    runtime_generation: runtime.runtime_generation,
                    runtime: Some(runtime.clone()),
                    publication_seq: binding.acknowledged_publication_seq,
                    lease_ms: DecimalU64(30000),
                    freshness_ms: DecimalU64(5000),
                },
                f.now(),
            )
            .unwrap();
            f.eligibility.identity = auth.public_host_identity(f.now()).unwrap();
            f.eligibility.publication = store
                .acknowledged_host_publication(&binding)
                .unwrap()
                .unwrap();
            f.eligibility.binding = binding;
            f.eligibility.heartbeat.scope = scope;
            f.eligibility.heartbeat.runtime = runtime;
            f.eligibility.heartbeat.request_started = Instant::now();
            let retired = HostStore::open(
                &f._dir.path().join("retired-owner.sqlite"),
                lomi_host_store::Limits::default(),
            )
            .unwrap();
            std::mem::replace(&mut *store, retired)
        };
        // A real Store reopen creates a new ownership domain. Keeping the old
        // SharedOwner would reject the new runtime before any recovery GET.
        f.owner = shared_owner::SharedOwner::new(reopened).unwrap();
        f.store = f.owner.peer_store_for_test();
        let runtime = f.runtime();
        assert!(runtime.operation.is_same_admission(&original_operation));
        assert_eq!(runtime.operation.deadline(), original_deadline);
        assert!(
            f.owner
                .peer_original_boundary(runtime.operation, &old_continuation)
                .is_err()
        );
        {
            // Re-establish Ready through the real provider/IO handoff. Retain
            // the original operation, clock and deadlines; no Ready bit is set.
            let mut attempt = shared_owner::ConfiguredWorkerAttempt::from_existing_worker(
                auth,
                runtime.public_io,
                runtime.gate,
                runtime.paused,
                runtime.base,
                runtime.anchor,
            )
            .unwrap();
            attempt.install_ready_http_script_for_test(
                std::rc::Rc::new(std::cell::Cell::new(0)),
                std::rc::Rc::new(std::cell::RefCell::new(None)),
                f.now(),
            );
            let mut ready = attempt.begin_ready(&f.owner, runtime.operation).unwrap();
            while !ready.try_step().unwrap() {}
        }
        let mut worker = Worker::default();
        api.replies
            .borrow_mut()
            .push_back(Reply::state(approved(&intent)));
        assert!(f.step(&mut worker, auth, &api).is_ok());
        assert_eq!(*api.requests.borrow(), ["POLL", "GET"]);
        assert_eq!(
            f.store.lock().unwrap().pending_pairing_decisions().unwrap(),
            vec![intent]
        );
        assert!(
            f.store
                .lock()
                .unwrap()
                .acknowledged_workspace_grants()
                .unwrap()
                .is_empty()
        );
    });
}

struct MixedApi {
    store: Arc<shared_owner::PeerStoreForTest>,
    requests: RefCell<Vec<(&'static str, PairingId)>>,
}
impl PeerApi for MixedApi {
    fn pending(
        &self,
        _: HostId,
        _: &HostAccessCredential,
    ) -> Result<PairingPendingResult, lomi_host_http::Error> {
        panic!(
            "poll timing is covered separately; cache is replenished through the private authenticated-observation seam"
        )
    }
    fn get(
        &self,
        pairing: PairingId,
        _: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        self.requests.borrow_mut().push(("GET", pairing));
        let store = self.store.try_lock().expect("no Store lock across GET");
        let intent = store
            .pending_pairing_decisions()
            .unwrap()
            .into_iter()
            .find(|p| p.preparation.pairing_id == pairing)
            .unwrap();
        Ok(PairingResult::Pending {
            pairing_id: pairing,
            proposal: intent.preparation.proposal,
        })
    }
    fn decide(
        &self,
        pairing: PairingId,
        params: &PairingDecisionParams,
        _: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        self.requests.borrow_mut().push(("POST", pairing));
        let store = self.store.try_lock().expect("no Store lock across POST");
        let intent = store
            .pending_pairing_decisions()
            .unwrap()
            .into_iter()
            .find(|p| p.preparation.pairing_id == pairing)
            .unwrap();
        assert_eq!(params, &intent.preparation.params);
        Ok(approved(&intent))
    }
}
#[test]
fn continuously_replenished_valid_cache_cannot_starve_lost_post_recovery_or_expiry() {
    for expired in [false, true] {
        fixture(|f, auth| {
            let old = if expired {
                fill_pending(f, auth, 1).remove(0)
            } else {
                let (mut prior, api, intent) = prepared(f, auth);
                api.replies
                    .borrow_mut()
                    .push_back(Reply::Error(lomi_host_http::Error::Timeout));
                assert!(f.step(&mut prior, auth, &api).is_ok());
                assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
                intent
            };
            let mut proposal = f.proposal(auth);
            let mut maximum = GrantV3::from_canonical(
                &hex_bytes(proposal.maximum_grant.expose_wire())
                    .ok()
                    .unwrap(),
            )
            .unwrap();
            maximum.expires_at = 1200;
            let api = MixedApi {
                store: f.store.clone(),
                requests: RefCell::new(vec![]),
            };
            let mut worker = Worker {
                scope: Some(f.eligibility.binding.scope.clone()),
                poll_at: Some(Instant::now() + Duration::from_secs(30)),
                ..Worker::default()
            };
            let runtime = Runtime {
                base: if expired { 1100 } else { 1005 },
                ..f.runtime()
            };
            let mut serviced_at = None;
            for turn in 0..8 {
                // Model successful fresh authenticated polls that keep all64 cache
                // positions valid. Poll-rate/backoff fairness is tested separately.
                worker.cache.clear();
                for n in 0..64 {
                    let sequence = 1000 + turn * 64 + n;
                    let mut maximum = maximum.clone();
                    maximum.grant_id = (sequence as u128).to_be_bytes();
                    proposal.maximum_grant = hex(&maximum.canonical().unwrap()).try_into().unwrap();
                    worker.cache.push_back(Work {
                        pairing: PairingId::from_bytes((sequence as u128 + 10_000).to_be_bytes())
                            .unwrap(),
                        proposal: proposal.clone(),
                        observation: std::sync::Arc::new(Observation::new(
                            &f.eligibility,
                            Instant::now(),
                            f.original_scope(),
                        )),
                        intent: None,
                    });
                }
                let before = api.requests.borrow().len();
                assert!(
                    worker
                        .step(auth, &f.config, runtime, &f.eligibility, Some(&api))
                        .is_ok()
                );
                assert!(api.requests.borrow().len() <= before + 1);
                if !f
                    .store
                    .lock()
                    .unwrap()
                    .pending_pairing_decisions()
                    .unwrap()
                    .iter()
                    .any(|p| p.token == old.token)
                {
                    serviced_at = Some(turn + 1);
                    break;
                }
            }
            assert!(
                serviced_at.is_some_and(|turn| turn <= 4),
                "recovery/expiry must precede cache exhaustion or capacity pressure"
            );
            if expired {
                assert!(
                    !api.requests
                        .borrow()
                        .iter()
                        .any(|(_, id)| *id == old.preparation.pairing_id)
                );
            } else {
                assert!(
                    api.requests
                        .borrow()
                        .contains(&("GET", old.preparation.pairing_id))
                );
                assert!(
                    api.requests
                        .borrow()
                        .contains(&("POST", old.preparation.pairing_id))
                );
                assert!(
                    f.store
                        .lock()
                        .unwrap()
                        .acknowledged_workspace_grants()
                        .unwrap()
                        .iter()
                        .any(|g| g.intent.token == old.token)
                );
            }
        });
    }
}
pub(in super::super) struct JoinContentionThreads(
    pub(in super::super) Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
);
impl JoinContentionThreads {
    pub(in super::super) fn join_all(&self) -> bool {
        let owned =
            std::mem::take(&mut *self.0.lock().unwrap_or_else(|poison| poison.into_inner()));
        let mut all_joined = true;
        for owned in owned {
            if owned.join().is_err() {
                all_joined = false;
            }
        }
        all_joined
    }
}
impl Drop for JoinContentionThreads {
    fn drop(&mut self) {
        let _ = self.join_all();
    }
}
pub(in super::super) fn hold_store_for_final_lock(
    store: Arc<shared_owner::PeerStoreForTest>,
    threads: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    original_expiry: Instant,
) -> Box<dyn FnOnce()> {
    Box::new(move || {
        let (ready, receiver) = mpsc::sync_channel(1);
        let owned = thread::spawn(move || {
            let guard = store.lock().unwrap();
            ready.send(()).unwrap();
            let release_at = original_expiry + Duration::from_millis(50);
            let hard_stop = Instant::now() + Duration::from_secs(3);
            for _ in 0..128 {
                let now = Instant::now();
                if now >= release_at {
                    break;
                }
                assert!(now < hard_stop, "bounded original-deadline contention");
                thread::sleep(
                    release_at
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(25)),
                );
            }
            assert!(
                Instant::now() >= release_at,
                "original deadline actually elapsed before releasing Store"
            );
            drop(guard);
        });
        // Register ownership before any assertion/wait can unwind this hook.
        threads.lock().unwrap().push(owned);
        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("bounded Store contention starts");
    })
}
#[test]
fn original_observation_expiring_during_final_store_lock_blocks_prepare_and_ack() {
    for ack in [false, true] {
        fixture(|f, auth| {
            let mut worker;
            let api;
            let mut original = None;
            if ack {
                let (w, a, intent) = prepared(f, auth);
                worker = w;
                api = a;
                original = Some(intent);
            } else {
                worker = Worker::default();
                api = Api::poll(f.proposal(auth));
                assert!(f.step(&mut worker, auth, &api).is_ok());
            }
            let work = if ack {
                worker.active.as_mut().unwrap()
            } else {
                worker.cache.front_mut().unwrap()
            };
            let mut old =
                Observation::new(&f.eligibility, work.observation.started, f.original_scope());
            old.heartbeat.freshness_ms = 2_000;
            let original_expiry =
                old.heartbeat.request_started + Duration::from_millis(old.heartbeat.freshness_ms);
            assert!(
                Instant::now() < original_expiry,
                "original setup budget is still future"
            );
            work.observation = std::sync::Arc::new(old);
            assert!(work.observation.current(&f.eligibility));
            // A later HB is healthy for the current handoff, but cannot refresh the
            // original TLS observation whose deadline will elapse under contention.
            f.eligibility.heartbeat.request_started = Instant::now();
            let threads = Arc::new(Mutex::new(Vec::new()));
            let owned_cleanup = JoinContentionThreads(threads.clone());
            let hook = hold_store_for_final_lock(f.store.clone(), threads.clone(), original_expiry);
            if ack {
                worker.before_ack_lock = Some(hook);
                api.replies
                    .borrow_mut()
                    .push_back(Reply::state(approved(original.as_ref().unwrap())));
            } else {
                worker.before_prepare_lock = Some(hook);
            }
            let result = f.step(&mut worker, auth, &api);
            assert_eq!(
                threads.lock().unwrap().len(),
                1,
                "the original observation must reach the final-lock contention hook"
            );
            assert!(
                owned_cleanup.join_all(),
                "every owned contention thread joined successfully"
            );
            assert!(
                Instant::now() > original_expiry,
                "original observation expired under final-lock contention"
            );
            assert!(result.is_err());
            assert!(
                Instant::now()
                    < f.eligibility.heartbeat.request_started
                        + Duration::from_millis(f.eligibility.heartbeat.freshness_ms)
            );
            let store = f.store.lock().unwrap();
            assert!(store.acknowledged_workspace_grants().unwrap().is_empty());
            assert_eq!(
                store.pending_pairing_decisions().unwrap(),
                original.into_iter().collect::<Vec<_>>()
            );
            assert!(!store.authorization_state().unwrap().locked);
        });
    }
}

// The hook captures the actual snapshot watermark, then waits for the trusted
// Runtime projection to cross it while both original observations remain fresh.
pub(in super::super) fn cross_snapshot_second(
    store: Arc<shared_owner::PeerStoreForTest>,
    base: u64,
    anchor: Instant,
    crossed: Arc<Mutex<Vec<(u64, u64)>>>,
) -> SnapshotHook {
    Box::new(move |original, runtime| {
        let before = store
            .observe_clock_for_test(
                runtime.operation,
                base.saturating_add(anchor.elapsed().as_secs()),
            )
            .expect("trusted clock observation");
        assert!(before >= original, "coherent trusted snapshot watermark");
        let stop = Instant::now() + Duration::from_secs(2);
        for _ in 0..256 {
            if base.saturating_add(anchor.elapsed().as_secs()) > original {
                break;
            }
            assert!(Instant::now() < stop, "bounded trusted second crossing");
            thread::sleep(Duration::from_millis(5));
        }
        let projection = base.saturating_add(anchor.elapsed().as_secs());
        assert!(
            projection > original,
            "shared Runtime/PolicyClock anchor crossed snapshot watermark"
        );
        let after = store
            .observe_clock_for_test(
                runtime.operation,
                base.saturating_add(anchor.elapsed().as_secs()),
            )
            .expect("trusted clock observation");
        assert!(
            after >= projection,
            "durable trusted clock includes shared projection"
        );
        assert!(
            after > original,
            "actual trusted wall crossed snapshot watermark"
        );
        crossed.lock().unwrap().push((original, after));
    })
}
#[test]
fn fresh_trusted_wall_samples_survive_snapshot_second_crossing_for_prepare_send_and_ack() {
    for stage in ["prepare", "send", "ack"] {
        fixture(|f, auth| {
            // Initialize ONCE before any work, with exactly Runtime's anchor.
            // Crossing the snapshot wall therefore crosses PolicyClock's own
            // projection too; a later policy anchor cannot mask stale callers.
            let mut worker = Worker {
                clock: Some(PolicyClock::new(1005, f.anchor).unwrap()),
                ..Worker::default()
            };
            let api = Api::poll(f.proposal(auth));
            assert!(f.step(&mut worker, auth, &api).is_ok());
            let original = if stage == "prepare" {
                None
            } else {
                assert!(f.step(&mut worker, auth, &api).is_ok());
                let intent = f
                    .store
                    .lock()
                    .unwrap()
                    .pending_pairing_decisions()
                    .unwrap()
                    .remove(0);
                if stage == "ack" {
                    api.replies
                        .borrow_mut()
                        .push_back(Reply::Error(lomi_host_http::Error::Timeout));
                    assert!(f.step(&mut worker, auth, &api).is_ok());
                    assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
                }
                Some(intent)
            };
            if stage == "send" {
                api.replies
                    .borrow_mut()
                    .push_back(Reply::Error(lomi_host_http::Error::Timeout));
            } else if stage == "ack" {
                api.replies
                    .borrow_mut()
                    .push_back(Reply::state(approved(original.as_ref().unwrap())));
            }
            let crossed = Arc::new(Mutex::new(Vec::new()));
            worker.after_snapshot = Some(cross_snapshot_second(
                f.store.clone(),
                1005,
                f.anchor,
                crossed.clone(),
            ));
            let original_heartbeat = f.eligibility.heartbeat.request_started;
            assert!(f.step(&mut worker, auth, &api).is_ok(), "stage={stage}");
            let crossings = crossed.lock().unwrap();
            assert_eq!(crossings.len(), 1, "stage={stage} reached snapshot seam");
            assert!(
                crossings[0].1 > crossings[0].0,
                "stage={stage} crossed prior watermark"
            );
            assert_eq!(worker.failures, 0, "stage={stage} no policy backoff");
            assert!(
                worker
                    .active
                    .as_ref()
                    .is_none_or(|w| w.observation.current(&f.eligibility))
            );
            assert!(Instant::now() < original_heartbeat + Duration::from_millis(5000));
            assert_eq!(f.eligibility.heartbeat.request_started, original_heartbeat);
            let store = f.store.lock().unwrap();
            let pending = store.pending_pairing_decisions().unwrap();
            let grants = store.acknowledged_workspace_grants().unwrap();
            if stage == "ack" {
                assert!(pending.is_empty());
                assert_eq!(grants.len(), 1);
                assert_eq!(grants[0].intent, original.clone().unwrap());
                assert_eq!(*api.requests.borrow(), ["POLL", "POST", "GET"]);
            } else {
                assert_eq!(pending.len(), 1);
                assert!(grants.is_empty());
                assert_eq!(pending[0].preparation.original_expires_at, 1100);
                let PairingDecisionParams::Approve { grant, .. } = &pending[0].preparation.params
                else {
                    panic!("fixed approval")
                };
                let signed = SignedGrantV3::from_wire(grant).unwrap();
                assert_eq!(signed.grant.expires_at, 1100);
                let mut expected = GrantV3::from_canonical(
                    &hex_bytes(pending[0].preparation.proposal.maximum_grant.expose_wire())
                        .ok()
                        .unwrap(),
                )
                .unwrap();
                expected.capabilities = CapabilitySet::control_with_workspace_tools();
                assert_eq!(signed.grant, expected);
                assert_eq!(signed.to_wire().unwrap(), *grant);
                if stage == "send" {
                    assert_eq!(pending, vec![original.clone().unwrap()]);
                    assert_eq!(
                        api.params.borrow().as_slice(),
                        std::slice::from_ref(&pending[0].preparation.params)
                    );
                    assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
                } else {
                    assert_eq!(*api.requests.borrow(), ["POLL"]);
                }
            }
            assert_eq!(
                original
                    .as_ref()
                    .map(|i| i.preparation.original_expires_at)
                    .unwrap_or(1100),
                1100
            );
        });
    }
}

#[test]
fn fixture_direct_auth_and_journal_calls_keep_the_original_runtime_clock_after_a_real_crossing() {
    fixture(|f, auth| {
        let original_heartbeat = f.eligibility.heartbeat.request_started;
        let before = f.now();
        let crossed = Arc::new(Mutex::new(Vec::new()));
        cross_snapshot_second(f.store.clone(), 1005, f.anchor, crossed.clone())(
            before,
            f.runtime(),
        );
        let after = f.now();
        assert!(after > before, "the actual shared Runtime second crossed");
        auth.public_host_identity(after).unwrap();
        // Both helpers used to send literal1005 after Runtime/Auth advanced.
        // They must use the same original anchor, without resetting observations.
        let proposal = f.proposal(auth);
        let intents = fill_pending(f, auth, 1);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].preparation.original_expires_at, 1100);
        assert_eq!(proposal.authority.access_epoch, DecimalU64(12));
        assert_eq!(f.eligibility.heartbeat.request_started, original_heartbeat);
        assert!(
            matches!(
                auth.public_host_identity(1005),
                Err(lomi_host_auth::Error::ClockRollback)
            ),
            "the production rollback guard must still reject a genuinely older caller"
        );
        assert_eq!(crossed.lock().unwrap().len(), 1);
    });
}

#[test]
fn cached_get_scope_rejects_replacement_operation_with_later_deadline() {
    fixture(|f, auth| {
        let (mut worker, api, _) = prepared(f, auth);
        assert!(worker.has_retained_operation());
        let cancel = AtomicBool::new(false);
        let replacement =
            owner_domain::Operation::new(Instant::now() + Duration::from_secs(120), &cancel);
        let aborted = std::cell::Cell::new(false);
        let runtime = Runtime {
            operation: &replacement,
            aborted: &aborted,
            ..f.runtime()
        };
        assert!(
            worker
                .step(auth, &f.config, runtime, &f.eligibility, Some(&api))
                .is_ok()
        );
        assert_eq!(*api.requests.borrow(), ["POLL"]);
        assert!(!worker.has_retained_operation());
    });
}
#[test]
fn actual_owner_unshare_after_signature_fences_original_get_before_prepare_or_post() {
    fixture(|f, auth| {
        let api = Api::poll(f.proposal(auth));
        let mut worker = Worker::default();
        assert!(f.step(&mut worker, auth, &api).is_ok());
        let owner = f.owner.clone();
        let workspace = f.workspace;
        worker.after_sign = Some(Box::new(move || {
            let cancel = AtomicBool::new(false);
            let operation =
                owner_domain::Operation::new(Instant::now() + Duration::from_secs(2), &cancel);
            owner
                .begin_unshare(&operation, workspace)
                .unwrap()
                .try_commit()
                .unwrap();
        }));
        assert!(f.step(&mut worker, auth, &api).is_err());
        assert_eq!(*api.requests.borrow(), ["POLL"]);
        assert!(
            f.store
                .lock()
                .unwrap()
                .pending_pairing_decisions()
                .unwrap()
                .is_empty()
        );
    });
}
#[test]
fn returned_pairing_post_response_survives_busy_without_another_http_or_signature() {
    fixture(|f, auth| {
        let (mut worker, api, intent) = prepared(f, auth);
        api.replies
            .borrow_mut()
            .push_back(Reply::state(approved(&intent)));
        let threads = Arc::new(Mutex::new(Vec::new()));
        let joined = JoinContentionThreads(threads.clone());
        worker.before_ack_lock = Some(hold_store_for_final_lock(
            f.store.clone(),
            threads,
            Instant::now() + Duration::from_millis(30),
        ));
        assert!(f.step(&mut worker, auth, &api).is_ok());
        assert!(joined.join_all());
        assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .acknowledged_workspace_grants()
                .unwrap()
                .len(),
            1
        );
    });
}
