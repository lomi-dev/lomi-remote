use super::*;
use lomi_host_auth::{Config, HostAuth};
use lomi_host_store::{CloudPairingScope, HostStore, Limits, PairingDecisionPreparation};
use lomi_platform::secrets::{
    ProviderKind, ProviderStatus, SecretBundle, SecretStorage, StorageState,
};
use lomi_remote_crypto::{
    ChannelContextV3, ChannelPurposeV3, GrantPurposeV3, GrantV3, HostEnrollmentChallengeContext,
    Identity, Role, prepare_host_enrollment_challenge, verify_host_key_initiation,
};
use lomi_remote_protocol::{
    DecimalU64, HostAuthorizationResult, HostEnrollmentTokenContext, HostId, HostRegisterResult,
    LocalIpcVersion,
    ipc::{LocalAuthConfiguration, LocalAuthProvider, LocalFileAcknowledgement},
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex, atomic::AtomicBool, mpsc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct MemoryStorage(Option<Vec<u8>>);
impl SecretStorage for MemoryStorage {
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            kind: Some(ProviderKind::ProtectedFile),
            state: StorageState::Available,
        }
    }

    fn load(&self) -> Result<Option<SecretBundle>, lomi_platform::secrets::Error> {
        self.0.clone().map(SecretBundle::new).transpose()
    }

    fn replace(&mut self, bundle: &SecretBundle) -> Result<(), lomi_platform::secrets::Error> {
        self.0 = Some(bundle.expose().to_vec());
        Ok(())
    }
}

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        #[cfg(target_os = "macos")]
        let temp_root = PathBuf::from("/private/tmp");
        #[cfg(not(target_os = "macos"))]
        let temp_root = std::env::temp_dir().canonicalize().unwrap();
        let path = temp_root.join(format!(
            "lomi-channel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
struct Calls {
    pending: usize,
    get: usize,
    admit: usize,
}
struct TestApi {
    pending: Mutex<ChannelPendingResult>,
    pending_error: Option<lomi_host_http::Error>,
    by_id: BTreeMap<ChannelId, ChannelAdmissionInputs>,
    calls: Mutex<Calls>,
    pending_delay: Mutex<Duration>,
}
impl TestApi {
    fn calls(&self) -> Calls {
        *self.calls.lock().unwrap()
    }

    fn set_pending(&self, pending: ChannelPendingResult) {
        *self.pending.lock().unwrap() = pending;
    }

    fn delay_pending_for(&self, delay: Duration) {
        *self.pending_delay.lock().unwrap() = delay;
    }
}
impl ChannelApi for TestApi {
    fn pending(
        &self,
        _host: HostId,
        _access: &HostAccessCredential,
    ) -> Result<ChannelPendingResult, lomi_host_http::Error> {
        self.calls.lock().unwrap().pending += 1;
        let pending_delay = *self.pending_delay.lock().unwrap();
        if !pending_delay.is_zero() {
            std::thread::sleep(pending_delay);
        }
        match self.pending_error {
            Some(error) => Err(error),
            None => Ok(self.pending.lock().unwrap().clone()),
        }
    }

    fn get(
        &self,
        id: ChannelId,
        _access: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error> {
        self.calls.lock().unwrap().get += 1;
        let inputs = self.by_id.get(&id).ok_or(lomi_host_http::Error::Network)?;
        Ok(ChannelResult::Pending {
            channel_id: id,
            inputs: inputs.clone(),
        })
    }

    fn admit(
        &self,
        _id: ChannelId,
        _params: &ChannelAdmissionParams,
        _access: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error> {
        self.calls.lock().unwrap().admit += 1;
        Err(lomi_host_http::Error::Network)
    }
}

fn with_fixture(
    count: usize,
    duplicate: bool,
    test: impl FnOnce(
        &mut HostAuth<'_, dyn SecretStorage + '_>,
        &Config,
        Runtime<'_>,
        &PeerEligibility,
        &SharedOwner,
        &TestApi,
    ),
) {
    assert!((1..=3).contains(&count));
    let directory = TestDirectory::new();
    let database = directory.0.join("host.sqlite3");
    let mut store = HostStore::open(&database, Limits::default()).unwrap();
    let identity = store.identity().clone();
    let config = Config::new(
        identity.host_id,
        identity.profile_id,
        "https://identity.example".into(),
        "host".to_owned().try_into().unwrap(),
    )
    .unwrap();
    let local_config = LocalAuthConfiguration {
        version: 1,
        origin: "https://identity.example".to_owned().try_into().unwrap(),
        remote_api_origin: Some("https://remote.example".to_owned().try_into().unwrap()),
        relay_endpoint: None,
        client_id: "host".to_owned().try_into().unwrap(),
        provider: LocalAuthProvider::ProtectedFile,
        keychain_path: None,
        protected_file_acknowledgement: Some(LocalFileAcknowledgement::OsPermissionsOnly),
    };
    store.configure_auth(&local_config).unwrap();

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
    let challenge: String = challenge
        .canonical()
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    auth.accept_tls_approval(
        config.origin(),
        HostEnrollmentTokenContext {
            account_id: AccountId::from_bytes([4; 16]).unwrap(),
            challenge: challenge.try_into().unwrap(),
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
            host_id: identity.host_id,
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
        host_id: identity.host_id,
        host_access_epoch: DecimalU64(12),
    })
    .unwrap();

    let wall = wall_now();
    // Seed actual durable cloud records through the Store's named interfaces.
    store.enable_authorization(0).unwrap();
    let workspace_root = directory.0.join("workspace");
    fs::create_dir(&workspace_root).unwrap();
    let project = store
        .add_project(
            &workspace_root,
            "channel tests".to_owned().try_into().unwrap(),
        )
        .unwrap();
    store
        .share(project.state.context.workspace_id, project.fence)
        .unwrap();
    let project = store.workspace(project.state.context.workspace_id).unwrap();
    let scope = store
        .cloud_runtime_scope(0, "https://remote.example".to_owned())
        .unwrap();
    let runtime_binding = RuntimeBinding {
        runtime_id: store.runtime_id(),
        runtime_generation: project.state.context.runtime_generation,
        host_access_epoch: DecimalU64(12),
    };
    let state = store
        .compare_and_set_cloud_runtime(&scope, None, runtime_binding.clone(), DecimalU64(0))
        .unwrap();
    let publication_intent = store.prepare_host_publication(&state).unwrap();
    let state = store
        .acknowledge_host_publication(
            &publication_intent,
            &PublicationResult {
                runtime: runtime_binding.clone(),
                publication_seq: publication_intent.params.publication_seq,
            },
        )
        .unwrap();
    let publication = store
        .acknowledged_host_publication(&state)
        .unwrap()
        .unwrap();
    let host = auth.public_host_identity(wall).unwrap();
    let consumer =
        Identity::generate(host.account_id.to_bytes(), [3; 16], Role::Device, 1).unwrap();
    let consumer_bundle = consumer.public_bundle();
    let consumer_pin = consumer_bundle.bundle.fingerprint().unwrap();
    let identities = PeerIdentities {
        host: host.identity.clone(),
        consumer: consumer_bundle.to_wire().unwrap(),
        host_fingerprint: hex(&host.fingerprint).try_into().unwrap(),
        consumer_fingerprint: hex(&consumer_pin).try_into().unwrap(),
    };
    let authority = CurrentAuthorityBinding {
        host_authorization_id: host.host_authorization_id,
        consumer_authorization_id: ConsumerAuthorizationId::from_bytes([5; 16]).unwrap(),
        account_session_id: "synthetic-current-session".to_owned().try_into().unwrap(),
        access_epoch: DecimalU64(12),
        grant_revision: DecimalU64(2),
        workspace_epoch: project.state.context.workspace_epoch,
        runtime_id: runtime_binding.runtime_id,
        runtime_generation: runtime_binding.runtime_generation,
        terminal_membership: None,
    };
    let grant = GrantV3 {
        version: 3,
        api_major: 2,
        application_major: 2,
        account_id: host.account_id.to_bytes(),
        host_id: host.host_id.to_bytes(),
        host_fingerprint: host.fingerprint,
        host_authorization_id: host.host_authorization_id.to_bytes(),
        access_epoch: 12,
        consumer_authorization_id: [5; 16],
        account_session_id: authority.account_session_id.as_str().to_owned(),
        consumer_id: [3; 16],
        consumer_fingerprint: consumer_pin,
        grant_id: [19; 16],
        grant_revision: 2,
        workspace_id: project.state.context.workspace_id.to_bytes(),
        workspace_epoch: project.state.context.workspace_epoch.to_bytes(),
        runtime_id: runtime_binding.runtime_id.to_bytes(),
        runtime_generation: runtime_binding.runtime_generation.0,
        capabilities: vec![Capability::WorkspaceRead].try_into().unwrap(),
        nonce: [10; 32],
        expires_at: wall + 120,
        purpose: GrantPurposeV3::Workspace,
    };
    let signed = auth.sign_grant_v3(&grant, wall).unwrap();
    let signed_wire = signed.to_wire().unwrap();
    let proposal = PairingProposal {
        maximum_grant: hex(&grant.canonical().unwrap()).try_into().unwrap(),
        identities: identities.clone(),
        authority: authority.clone(),
    };
    let pairing_scope = CloudPairingScope {
        runtime_scope: scope.clone(),
        runtime: runtime_binding.clone(),
        workspace_id: project.state.context.workspace_id,
        workspace_epoch: project.state.context.workspace_epoch,
        workspace_fence: project.fence,
    };
    let pairing = PairingDecisionPreparation {
        scope: pairing_scope,
        pairing_id: PairingId::from_bytes([22; 16]).unwrap(),
        grant_id: GrantId::from_bytes(grant.grant_id).unwrap(),
        account_id: host.account_id,
        window_identity_id: WindowIdentityId::from_bytes([3; 16]).unwrap(),
        proposal: proposal.clone(),
        original_expires_at: grant.expires_at,
        params: PairingDecisionParams::Approve {
            grant: signed_wire.clone(),
            runtime: runtime_binding.clone(),
        },
    };
    let pairing_intent = store.prepare_pairing_decision(pairing, wall).unwrap();
    store
        .acknowledge_pairing_decision(
            &pairing_intent,
            &PairingResult::Approved {
                pairing_id: pairing_intent.preparation.pairing_id,
                proposal,
                grant: signed_wire.clone(),
                identities: identities.clone(),
                authority: authority.clone(),
            },
            wall,
        )
        .unwrap();

    let worker = SharedOwner::new(store).unwrap();
    let cancelled = AtomicBool::new(false);
    let operation =
        owner_domain::Operation::new(Instant::now() + Duration::from_secs(30), &cancelled);
    worker.seed_test_ready(&operation, &auth).unwrap();
    let started = Instant::now();
    let heartbeat = cloud::HeartbeatObservation {
        scope: scope.clone(),
        runtime: runtime_binding.clone(),
        request_started: started,
        wall_at_request_start: wall,
        lease_ms: 30_000,
        freshness_ms: 5_000,
    };
    let eligibility = PeerEligibility {
        identity: host,
        binding: state,
        publication,
        heartbeat,
    };

    let mut channels = Vec::new();
    let mut by_id = BTreeMap::new();
    for index in 0..count {
        let channel_id = ChannelId::from_bytes([31 + index as u8; 16]).unwrap();
        let context = ChannelContextV3 {
            version: 3,
            grant: grant.clone(),
            channel_id: channel_id.to_bytes(),
            initiator_role: Role::Device,
            responder_role: Role::Host,
            purpose: ChannelPurposeV3::Workspace,
            terminal: None,
            issued_at: wall,
            expires_at: wall + 30,
        };
        let context_value = serde_json::to_value(&context).unwrap();
        let inputs = ChannelAdmissionInputs {
            expected_context: hex(&context.canonical().unwrap()).try_into().unwrap(),
            expected_context_json: context_value.as_object().unwrap().clone(),
            grant: signed_wire.clone(),
            identities: identities.clone(),
            authority: authority.clone(),
        };
        by_id.insert(channel_id, inputs.clone());
        channels.push(PendingChannel { channel_id, inputs });
    }
    let api = TestApi {
        pending: Mutex::new(ChannelPendingResult {
            channels: PendingChannels::try_from(channels).unwrap(),
        }),
        pending_error: duplicate.then_some(lomi_host_http::Error::InvalidResponse),
        by_id,
        calls: Mutex::new(Calls {
            pending: 0,
            get: 0,
            admit: 0,
        }),
        pending_delay: Mutex::new(Duration::ZERO),
    };

    let profile = directory.0.join("profile");
    fs::create_dir(&profile).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let owner_lock = platform::OwnerLock::acquire(&profile).unwrap();
    let endpoint = Arc::new(
        platform::OwnerEndpoint::bind(
            owner_lock,
            platform::LocalDiscovery {
                version: LocalIpcVersion::CURRENT,
                profile_id: identity.profile_id,
                host_id: identity.host_id,
                runtime_id: runtime_binding.runtime_id,
                build_id: "channel-tests".to_owned(),
            },
        )
        .unwrap(),
    );
    let setup = public_configuration::PublicSetup::new(endpoint);
    let paused = AtomicBool::new(false);
    let public_io = setup.enter_owned(&paused).unwrap().unwrap();
    let state_view = Mutex::new(initial());
    let stopping = AtomicBool::new(false);
    let (_sender, receiver) = mpsc::channel::<Command>();
    let retry_requested = AtomicBool::new(false);
    let gate = AtomicBool::new(false);
    let anchor = started;
    let aborted = std::cell::Cell::new(false);
    let runtime = RuntimeWithOperation {
        owner: &worker,
        operation: &operation,
        public_io: &public_io,
        state: &state_view,
        stopping: &stopping,
        receiver: &receiver,
        retry_requested: &retry_requested,
        gate: &gate,
        paused: &paused,
        base: wall,
        anchor,
        aborted: &aborted,
    };
    test(&mut auth, &config, runtime, &eligibility, &worker, &api);
}

fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn fresh_poll_prepares_one_intent_before_any_get_or_admission_post() {
    with_fixture(
        3,
        false,
        |auth, config, runtime, eligibility, owner, api| {
            let mut worker = Worker::default();
            worker
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();

            let calls = api.calls();
            assert_eq!((calls.pending, calls.get, calls.admit), (1, 0, 0));
            assert_eq!(
                owner
                    .peer_pending_channels(runtime.operation, eligibility)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                worker.active.as_ref().map(|work| work.id),
                Some(ChannelId::from_bytes([31; 16]).unwrap())
            );
            assert!(worker.active.as_ref().unwrap().intent.is_some());
            assert_eq!(
                worker.cache.iter().map(|work| work.id).collect::<Vec<_>>(),
                vec![
                    ChannelId::from_bytes([32; 16]).unwrap(),
                    ChannelId::from_bytes([33; 16]).unwrap()
                ]
            );
            assert!(Arc::ptr_eq(
                &worker.active.as_ref().unwrap().observation,
                &worker.cache.front().unwrap().observation,
            ));
            assert_eq!(
                worker.proposal_cursor,
                Some(ChannelId::from_bytes([31; 16]).unwrap())
            );

            worker
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();
            let calls = api.calls();
            assert_eq!((calls.pending, calls.get, calls.admit), (1, 0, 1));
            assert_eq!(
                owner
                    .peer_pending_channels(runtime.operation, eligibility)
                    .unwrap()
                    .len(),
                1
            );

            worker
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();
            let calls = api.calls();
            assert_eq!((calls.pending, calls.get, calls.admit), (1, 0, 1));
            assert_eq!(
                owner
                    .peer_pending_channels(runtime.operation, eligibility)
                    .unwrap()
                    .len(),
                2
            );
            assert_eq!(
                worker.active.as_ref().map(|work| work.id),
                Some(ChannelId::from_bytes([32; 16]).unwrap())
            );
            assert_eq!(
                worker.cache.iter().map(|work| work.id).collect::<Vec<_>>(),
                vec![ChannelId::from_bytes([33; 16]).unwrap()]
            );
            assert_eq!(
                worker.proposal_cursor,
                Some(ChannelId::from_bytes([32; 16]).unwrap())
            );
        },
    );
}

#[test]
fn duplicate_pending_response_creates_no_intent() {
    with_fixture(1, true, |auth, config, runtime, eligibility, owner, api| {
        let first = api.pending.lock().unwrap().channels.as_slice()[0].clone();
        assert!(
            serde_json::from_value::<ChannelPendingResult>(serde_json::json!({
                "channels": [first.clone(), first]
            }))
            .is_err()
        );

        let mut worker = Worker::default();
        worker
            .step(auth, config, runtime, eligibility, Some(api))
            .unwrap();

        let calls = api.calls();
        assert_eq!((calls.pending, calls.get, calls.admit), (1, 0, 0));
        assert!(
            owner
                .peer_pending_channels(runtime.operation, eligibility)
                .unwrap()
                .is_empty()
        );
        assert!(worker.active.is_none());
        assert!(worker.cache.is_empty());
    });
}

#[test]
fn recovery_preference_does_not_block_a_fresh_proposal_with_no_pending_intents() {
    with_fixture(
        1,
        false,
        |auth, config, runtime, eligibility, owner, api| {
            let mut worker = Worker::default();
            worker.prefer_recovery = true;
            worker
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();

            let calls = api.calls();
            assert_eq!((calls.pending, calls.get, calls.admit), (1, 0, 0));
            assert_eq!(
                owner
                    .peer_pending_channels(runtime.operation, eligibility)
                    .unwrap()
                    .len(),
                1
            );
            assert!(worker.active.as_ref().unwrap().intent.is_some());
        },
    );
}

#[test]
fn capacity_blocking_leaves_a_fresh_proposal_cached_without_preparing_it() {
    with_fixture(
        1,
        false,
        |auth, config, runtime, eligibility, owner, api| {
            let mut worker = Worker::default();
            worker.capacity_blocked = true;
            worker
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();

            let calls = api.calls();
            assert_eq!((calls.pending, calls.get, calls.admit), (1, 0, 0));
            assert!(
                owner
                    .peer_pending_channels(runtime.operation, eligibility)
                    .unwrap()
                    .is_empty()
            );
            assert!(worker.active.is_none());
            assert!(worker.has_cached_work());
        },
    );
}

#[test]
fn existing_intent_is_recovered_without_fresh_inline_preparation() {
    with_fixture(
        1,
        false,
        |auth, config, runtime, eligibility, owner, api| {
            let mut initial = Worker::default();
            initial
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();
            let before = owner
                .peer_pending_channels(runtime.operation, eligibility)
                .unwrap();
            assert_eq!(before.len(), 1);

            let mut recovery = Worker::default();
            recovery
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();

            let calls = api.calls();
            assert_eq!((calls.pending, calls.get, calls.admit), (1, 1, 0));
            assert_eq!(
                owner
                    .peer_pending_channels(runtime.operation, eligibility)
                    .unwrap(),
                before
            );
            assert_eq!(
                recovery.active.as_ref().map(|work| work.id),
                Some(before[0].preparation.channel_id)
            );
            assert!(recovery.active.as_ref().unwrap().intent.is_some());
        },
    );
}

#[test]
fn due_poll_with_a_durable_intent_caches_new_work_then_recovers_old_intent() {
    with_fixture(
        2,
        false,
        |auth, config, runtime, eligibility, owner, api| {
            let mut first = Worker::default();
            first
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();
            let pending_before = owner
                .peer_pending_channels(runtime.operation, eligibility)
                .unwrap();
            assert_eq!(pending_before.len(), 1);
            let old_id = pending_before[0].preparation.channel_id;

            // The next poll offers only a different proposal while the old
            // admission intent remains durable.
            let new_proposal = api.pending.lock().unwrap().channels.as_slice()[1].clone();
            api.set_pending(ChannelPendingResult {
                channels: PendingChannels::try_from(vec![new_proposal.clone()]).unwrap(),
            });

            // A restarted worker has no in-memory active/cache state. The
            // fourth actor pass must poll before attempting recovery.
            let mut recovery = Worker::default();
            recovery.scope = Some(eligibility.binding.scope.clone());
            recovery.turns_since_poll = 3;
            recovery.prefer_recovery = true;
            recovery
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();

            assert_eq!(
                (api.calls().pending, api.calls().get, api.calls().admit),
                (2, 0, 0)
            );
            assert!(recovery.active.is_none());
            assert_eq!(
                recovery
                    .cache
                    .iter()
                    .map(|work| work.id)
                    .collect::<Vec<_>>(),
                vec![new_proposal.channel_id]
            );
            assert!(recovery.cached_first_due);
            assert_eq!(
                owner
                    .peer_pending_channels(runtime.operation, eligibility)
                    .unwrap(),
                pending_before
            );

            // The next actor turn consumes the old durable intent first.
            recovery
                .step(auth, config, runtime, eligibility, Some(api))
                .unwrap();
            assert_eq!(
                (api.calls().pending, api.calls().get, api.calls().admit),
                (2, 1, 0)
            );
            assert_eq!(recovery.active.as_ref().map(|work| work.id), Some(old_id));
            assert!(recovery.active.as_ref().unwrap().intent.is_some());
            assert_eq!(
                recovery
                    .cache
                    .iter()
                    .map(|work| work.id)
                    .collect::<Vec<_>>(),
                vec![new_proposal.channel_id]
            );
            assert_eq!(
                owner
                    .peer_pending_channels(runtime.operation, eligibility)
                    .unwrap(),
                pending_before
            );
        },
    );
}

#[test]
fn original_five_second_api_observation_bound_expires_even_with_fresh_heartbeat() {
    with_fixture(
        1,
        false,
        |auth, config, runtime, eligibility, owner, api| {
            let mut fresh_heartbeat = eligibility.clone();
            fresh_heartbeat.heartbeat.freshness_ms = 20_000;
            api.delay_pending_for(Duration::from_millis(5_100));

            let mut worker = Worker::default();
            worker
                .step(auth, config, runtime, &fresh_heartbeat, Some(api))
                .unwrap();

            assert_eq!(
                (api.calls().pending, api.calls().get, api.calls().admit),
                (1, 0, 0)
            );
            assert!(worker.active.is_none());
            assert!(worker.cache.is_empty());
            assert!(
                owner
                    .peer_pending_channels(runtime.operation, &fresh_heartbeat)
                    .unwrap()
                    .is_empty()
            );
        },
    );
}

#[test]
fn expired_peer_proof_and_durable_fence_block_fresh_preparation() {
    with_fixture(
        1,
        false,
        |auth, config, runtime, eligibility, owner, api| {
            let mut expired = eligibility.clone();
            expired.heartbeat.request_started = Instant::now() - Duration::from_secs(10);
            let mut worker = Worker::default();
            assert!(
                worker
                    .step(auth, config, runtime, &expired, Some(api))
                    .is_err()
            );
            assert_eq!(
                (api.calls().pending, api.calls().get, api.calls().admit),
                (0, 0, 0)
            );

            let mut logout = owner.begin_local_logout(runtime.operation).unwrap();
            logout.try_commit().unwrap();
            let mut after_fence = Worker::default();
            assert!(
                after_fence
                    .step(auth, config, runtime, eligibility, Some(api))
                    .is_err()
            );
            assert_eq!(
                (api.calls().pending, api.calls().get, api.calls().admit),
                (0, 0, 0)
            );
            assert!(after_fence.active.is_none());
            assert!(
                owner
                    .peer_pending_channels(runtime.operation, eligibility)
                    .is_err()
            );
        },
    );
}
