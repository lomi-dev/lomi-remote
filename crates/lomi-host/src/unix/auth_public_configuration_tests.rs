//! Model an existing bounded provider attempt with its actual exclusion guard.
//! These tests perform no network requests and open no secret provider.
use super::*;
use crate::testsupport::BuilderExt as _;

fn fixture() -> (
    tempfile::TempDir,
    Arc<SharedOwner>,
    Handle,
    mpsc::Receiver<Command>,
) {
    let root = tempfile::Builder::new().private_tempdir().unwrap();
    let profile = root.path().canonicalize().unwrap();
    let owner = OwnerLock::acquire(&profile).unwrap();
    let mut store = HostStore::open(&owner.prepare_database().unwrap(), Limits::default()).unwrap();
    super::super::public_configuration::startup(&mut store, owner.profile()).unwrap();
    let endpoint = Arc::new(
        OwnerEndpoint::bind(
            owner,
            LocalDiscovery {
                version: LocalIpcVersion::CURRENT,
                profile_id: store.identity().profile_id,
                host_id: store.identity().host_id,
                runtime_id: store.runtime_id(),
                build_id: "fixture".to_owned(),
            },
        )
        .unwrap(),
    );
    let shared_owner = SharedOwner::new(store).unwrap();
    let (wake, receiver) = mpsc::sync_channel(8);
    let handle = Handle {
        owner: shared_owner.clone(),
        wake,
        state: Arc::new(Mutex::new(initial())),
        retry_requested: Arc::new(AtomicBool::new(false)),
        gate: Arc::new(AtomicBool::new(true)),
        paused: Arc::new(AtomicBool::new(false)),
        public_setup: Some(Arc::new(
            super::super::public_configuration::PublicSetup::new(endpoint),
        )),
    };
    (root, shared_owner, handle, receiver)
}
fn configuration_value() -> LocalAuthConfiguration {
    LocalAuthConfiguration {
        version: 1,
        origin: "https://identity.example".to_owned().try_into().unwrap(),
        remote_api_origin: None,
        relay_endpoint: None,
        client_id: "host-client".to_owned().try_into().unwrap(),
        provider: crate::testsupport::provider(),
        keychain_path: None,
        protected_file_acknowledgement: crate::testsupport::file_acknowledgement(),
    }
}
#[test]
fn configure_waits_for_provider_scope_without_holding_store_and_logout_stays_callable() {
    let (_root, owner, handle, receiver) = fixture();
    let cancel = AtomicBool::new(false);
    let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(10), &cancel);
    let setup = handle.public_setup.as_ref().unwrap().clone();
    let attempt = setup.enter_owned(&handle.paused).unwrap().unwrap();
    let worker_handle = handle.clone();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let configure = thread::spawn(move || {
        let cancel = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(10), &cancel);
        let outcome = worker_handle.dispatch(
            &operation,
            LocalCall::AuthConfigure(LocalAuthConfigure {
                configuration: configuration_value(),
                operator_intent: Confirmed::Confirmed,
            }),
        );
        done_tx.send(outcome).unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !setup.pending.load(Ordering::Acquire) {
        assert!(
            Instant::now() < deadline,
            "configure did not pause provider entry"
        );
        thread::yield_now();
    }
    assert!(done_rx.try_recv().is_err());
    // This must succeed while configure waits for the provider guard.
    assert!(owner.probe_both_locks_for_test(&operation).is_ok());
    assert!(matches!(
        handle.dispatch(
            &operation,
            LocalCall::LoginStart(LocalLoginStart {
                operation_id: OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).unwrap(),
            })
        ),
        Err(LocalError::Unavailable)
    ));
    handle
        .dispatch(
            &operation,
            LocalCall::Logout(LocalOperatorIntent {
                operator_intent: Confirmed::Confirmed,
            }),
        )
        .unwrap();
    assert!(matches!(receiver.try_recv().unwrap(), Command::Logout));
    assert!(receiver.try_recv().is_err());
    drop(attempt);
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Ok(LocalResult::AuthConfigured {})
    ));
    configure.join().unwrap();
    assert!(matches!(receiver.try_recv().unwrap(), Command::Configure));
    assert_eq!(
        owner.auth_selection(&operation).unwrap().configuration,
        Some(configuration_value())
    );
    // Successful configuration returns only after exact file confirmation and
    // the typed public-finalize phase, not merely after a database row update.

    assert!(!setup.pending.load(Ordering::Acquire));
}
#[test]
fn waiting_shared_entry_rechecks_pause_after_acquiring_the_guard() {
    let (_root, _store, handle, _receiver) = fixture();
    let setup = handle.public_setup.as_ref().unwrap().clone();
    let exclusive = setup.io.write().unwrap();
    let waiting_setup = setup.clone();
    let waiting_pause = handle.paused.clone();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        entered_tx.send(()).unwrap();
        waiting_setup.enter_owned(&waiting_pause).unwrap().is_none()
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    setup.pending.store(true, Ordering::Release);
    handle.paused.store(true, Ordering::Release);
    drop(exclusive);
    assert!(worker.join().unwrap());
    assert!(handle.paused.load(Ordering::Acquire));
}
#[test]
fn changed_public_file_blocks_configure_and_login_but_leaves_logout_available() {
    let (root, owner, handle, _receiver) = fixture();
    let cancel = AtomicBool::new(false);
    let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(10), &cancel);
    std::fs::write(
        root.path().join("host-public.toml"),
        b"version=1\nrevision=1\n# unexpected edit\n",
    )
    .unwrap();
    assert!(
        handle
            .dispatch(
                &operation,
                LocalCall::AuthConfigure(LocalAuthConfigure {
                    configuration: configuration_value(),
                    operator_intent: Confirmed::Confirmed,
                })
            )
            .is_err()
    );
    assert!(handle.paused.load(Ordering::Acquire));
    assert!(matches!(
        owner.auth_selection(&operation),
        Err(OwnerError::Store(StoreError::Fenced))
    ));
    let coordinator = Coordinator {
        owner: owner.clone(),
        deferred_completions: Mutex::new(rpc::CompletionQueue::new()),
        auth: Mutex::new(Some(handle.clone())),
        terminals: TerminalService::new(),
        stopping: Arc::new(AtomicBool::new(false)),
        workspace_locks: Mutex::new(std::collections::BTreeMap::new()),
        files: super::remote_files::Roots::default(),
        git_reads: super::remote_git::Reads::default(),
        git_mutations: super::remote_git_mutations::Mutations::default(),
    };
    // A public-file failure blocks credential/remote work while local status,
    // diagnosis and fencing remain callable through the same SharedOwner.
    assert!(matches!(
        coordinator.dispatch(&operation, LocalCall::Status {}),
        Ok(LocalResult::Status(_))
    ));
    assert!(matches!(
        coordinator.dispatch(&operation, LocalCall::Doctor {}),
        Ok(LocalResult::Doctor(_))
    ));
    assert!(matches!(
        handle.dispatch(
            &operation,
            LocalCall::LoginStart(LocalLoginStart {
                operation_id: OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).unwrap(),
            })
        ),
        Err(LocalError::Unavailable)
    ));
    handle
        .dispatch(
            &operation,
            LocalCall::Logout(LocalOperatorIntent {
                operator_intent: Confirmed::Confirmed,
            }),
        )
        .unwrap();
    assert!(
        owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .pending_cloud_revoke
    );
}
