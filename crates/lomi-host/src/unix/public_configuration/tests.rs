use super::*;
use lomi_remote_protocol::OperationId;
use std::cell::Cell;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Read,
    BeforeRename,
    AfterRename,
    Confirm,
}
struct Memory {
    current: Option<PublicDocument>,
    fault: Fault,
    publications: usize,
    confirmations: Cell<usize>,
}
impl Memory {
    fn empty() -> Self {
        Self {
            current: None,
            fault: Fault::None,
            publications: 0,
            confirmations: Cell::new(0),
        }
    }
}
impl PublicIo for Memory {
    type Token = PublicDocument;
    fn load(&self) -> Result<Option<Observed<PublicDocument>>, Error> {
        if self.fault == Fault::Read {
            return Err(Error::Storage);
        }
        Ok(self.current.clone().map(|document| Observed {
            token: document.clone(),
            document,
        }))
    }
    fn publish(
        &mut self,
        expected: Option<&PublicDocument>,
        desired: &PublicDocument,
    ) -> Result<Publication<PublicDocument>, Error> {
        if self.current.as_ref() != expected {
            return Err(Error::Conflict);
        }
        if self.fault == Fault::BeforeRename {
            return Err(Error::Storage);
        }
        self.current = Some(desired.clone());
        self.publications += 1;
        if self.fault == Fault::AfterRename {
            return Ok(Publication::Uncertain);
        }
        Ok(Publication::Durable(Observed {
            token: desired.clone(),
            document: desired.clone(),
        }))
    }
    fn confirm(&self, observed: &Observed<PublicDocument>) -> Result<(), Error> {
        self.confirmations.set(self.confirmations.get() + 1);
        if self.fault == Fault::Confirm {
            return Err(Error::Uncertain);
        }
        if self.current.as_ref() != Some(&observed.token) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
fn fixture() -> (tempfile::TempDir, HostStore, Memory) {
    let root = tempfile::tempdir().unwrap();
    let store = HostStore::open(&root.path().join("store.sqlite"), Limits::default()).unwrap();
    (root, store, Memory::empty())
}
fn reopen(root: &tempfile::TempDir, store: HostStore) -> HostStore {
    drop(store);
    HostStore::open(&root.path().join("store.sqlite"), Limits::default()).unwrap()
}
fn config() -> LocalAuthConfiguration {
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
fn document(revision: u64, authentication: Option<LocalAuthConfiguration>) -> PublicDocument {
    PublicDocument::encode(&Configuration {
        version: 1,
        revision,
        authentication,
    })
    .unwrap()
}
#[test]
fn empty_profile_bootstraps_revision_one_and_restart_requires_file_reconciliation() {
    let (root, mut store, mut file) = fixture();
    reconcile(&mut store, &mut file).unwrap();
    assert!(file.current.as_ref() == Some(&document(1, None)));
    assert_eq!(file.publications, 1);
    assert!(store.public_configuration_ready().unwrap());
    let mut store = reopen(&root, store);
    assert!(matches!(
        store.auth_configuration(),
        Err(StoreError::Fenced)
    ));
    reconcile(&mut store, &mut file).unwrap();
    assert_eq!(file.publications, 1);
    assert!(store.public_configuration_ready().unwrap());
}
#[test]
fn migration_adopts_exact_matching_existing_source_without_overwriting() {
    let (_root, mut store, mut file) = fixture();
    store.configure_auth(&config()).unwrap();
    let canonical = document(9, Some(config()));
    let mut source = canonical.bytes().to_vec();
    source.extend_from_slice(b"\n# preserve operator formatting\n");
    let existing = PublicDocument::from_bytes(&source).unwrap();
    file.current = Some(existing.clone());
    reconcile(&mut store, &mut file).unwrap();
    assert!(file.current.as_ref() == Some(&existing));
    assert_eq!(file.publications, 0);
    assert!(file.confirmations.get() > 0);
    assert_eq!(store.auth_configuration().unwrap(), Some(config()));
}
#[test]
fn migration_conflict_never_overwrites_existing_file_or_changes_binding() {
    let (_root, mut store, mut file) = fixture();
    store.configure_auth(&config()).unwrap();
    let unrelated = document(1, None);
    file.current = Some(unrelated.clone());
    assert!(reconcile(&mut store, &mut file).is_err());
    assert_eq!(file.publications, 0);
    assert!(file.current.as_ref() == Some(&unrelated));
    assert!(store.public_configuration_state().unwrap().is_none());
}
#[test]
fn bootstrap_prepared_intent_recovers_absence_and_exact_desired_without_guessing() {
    for already_published in [false, true] {
        let (root, mut store, mut file) = fixture();
        let desired = document(1, None);
        store.public_prepare(None, &desired).unwrap();
        if already_published {
            file.current = Some(desired.clone());
        }
        let mut store = reopen(&root, store);
        reconcile(&mut store, &mut file).unwrap();
        assert!(store.public_configuration_ready().unwrap());
        assert_eq!(file.publications, usize::from(!already_published));
        assert!(file.current.as_ref() == Some(&desired));
    }
}
#[test]
fn prepared_configure_recovery_matrix_accepts_only_exact_old_or_exact_new() {
    for actual in ["old", "new", "missing", "stale", "conflict", "malformed"] {
        let (root, mut store, mut file) = fixture();
        reconcile(&mut store, &mut file).unwrap();
        let old = store.public_current().unwrap();
        let desired = document(2, Some(config()));
        store.public_prepare(Some(&old), &desired).unwrap();
        match actual {
            "old" => {}
            "new" => file.current = Some(desired.clone()),
            "missing" => file.current = None,
            "stale" => file.current = Some(document(3, Some(config()))),
            "conflict" => {
                let mut bytes = old.bytes().to_vec();
                bytes.extend_from_slice(b"\n# changed same revision\n");
                file.current = Some(PublicDocument::from_bytes(&bytes).unwrap());
            }
            "malformed" => file.fault = Fault::Read,
            _ => unreachable!(),
        }
        let before = file.current.clone();
        let publications = file.publications;
        let mut store = reopen(&root, store);
        let result = reconcile(&mut store, &mut file);
        if actual == "old" || actual == "new" {
            result.unwrap();
            assert_eq!(store.auth_configuration().unwrap(), Some(config()));
            assert_eq!(
                file.publications,
                publications + usize::from(actual == "old")
            );
            assert!(
                store
                    .public_configuration_state()
                    .unwrap()
                    .unwrap()
                    .prepared
                    .is_none()
            );
        } else {
            assert!(result.is_err());
            assert!(matches!(
                store.auth_configuration(),
                Err(StoreError::Fenced)
            ));
            assert!(
                store
                    .public_configuration_state()
                    .unwrap()
                    .unwrap()
                    .prepared
                    .is_some()
            );
            assert!(file.current == before);
            assert_eq!(file.publications, publications);
        }
    }
}
#[test]
fn pre_and_post_rename_failures_keep_intent_and_reconcile_without_rollback() {
    for fault in [Fault::BeforeRename, Fault::AfterRename, Fault::Confirm] {
        let (root, mut store, mut file) = fixture();
        reconcile(&mut store, &mut file).unwrap();
        let old = file.current.clone();
        file.fault = fault;
        assert!(configure(&mut store, &mut file, &config()).is_err());
        assert!(
            store
                .public_configuration_state()
                .unwrap()
                .unwrap()
                .prepared
                .is_some()
        );
        assert!(matches!(
            store.auth_configuration(),
            Err(StoreError::Fenced)
        ));
        if fault == Fault::BeforeRename {
            assert!(file.current == old);
        } else {
            assert!(file.current.as_ref() == Some(&document(2, Some(config()))));
        }
        let publications = file.publications;
        file.fault = Fault::None;
        let mut store = reopen(&root, store);
        reconcile(&mut store, &mut file).unwrap();
        assert_eq!(
            file.publications,
            publications + usize::from(fault == Fault::BeforeRename)
        );
        assert_eq!(store.auth_configuration().unwrap(), Some(config()));
    }
}
#[test]
fn migrated_missing_malformed_or_changed_source_has_no_sqlite_fallback() {
    for fault in ["missing", "malformed", "changed"] {
        let (root, mut store, mut file) = fixture();
        store.configure_auth(&config()).unwrap();
        reconcile(&mut store, &mut file).unwrap();
        match fault {
            "missing" => file.current = None,
            "malformed" => file.fault = Fault::Read,
            _ => file.current = Some(document(2, Some(config()))),
        }
        let mut store = reopen(&root, store);
        assert!(reconcile(&mut store, &mut file).is_err());
        assert!(matches!(
            store.auth_configuration(),
            Err(StoreError::Fenced)
        ));
        assert!(!store.public_configuration_ready().unwrap());
    }
}
#[test]
fn configure_idempotency_and_binding_rejection_do_not_publish_or_leave_intent() {
    let (_root, mut store, mut file) = fixture();
    store.configure_auth(&config()).unwrap();
    reconcile(&mut store, &mut file).unwrap();
    let publications = file.publications;
    configure(&mut store, &mut file, &config()).unwrap();
    let mut changed = config();
    changed.client_id = "changed".to_owned().try_into().unwrap();
    assert!(configure(&mut store, &mut file, &changed).is_err());
    assert_eq!(file.publications, publications);
    assert!(store.public_configuration_ready().unwrap());
    assert!(
        store
            .public_configuration_state()
            .unwrap()
            .unwrap()
            .prepared
            .is_none()
    );
}
#[test]
fn interrupted_adoption_requires_the_same_existing_file_without_recreation() {
    for actual in ["same", "missing", "conflict"] {
        let (root, mut store, mut file) = fixture();
        store.configure_auth(&config()).unwrap();
        let desired = document(9, Some(config()));
        store.public_prepare(Some(&desired), &desired).unwrap();
        match actual {
            "same" => file.current = Some(desired.clone()),
            "missing" => file.current = None,
            _ => file.current = Some(document(10, Some(config()))),
        }
        let mut store = reopen(&root, store);
        let result = reconcile(&mut store, &mut file);
        assert_eq!(result.is_ok(), actual == "same");
        assert_eq!(file.publications, 0);
        assert_eq!(
            store.public_configuration_ready().unwrap(),
            actual == "same"
        );
    }
}

// Shared-Mutex production engine tests. The IO model is synthetic; these are
// authored concurrency/CAS tests, not native filesystem/provider qualification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PausePoint {
    InitialLoad,
    PreparedLoad,
    Publish,
    Confirm,
}
struct PausedIo {
    inner: Memory,
    point: PausePoint,
    loads: Cell<usize>,
    entered: std::sync::mpsc::SyncSender<PausePoint>,
    release: std::sync::mpsc::Receiver<()>,
}
impl PausedIo {
    fn pause(&self, point: PausePoint) -> Result<(), Error> {
        if self.point == point {
            self.entered.send(point).map_err(|_| Error::Storage)?;
            self.release
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
}
impl PublicIo for PausedIo {
    type Token = PublicDocument;
    fn load(&self) -> Result<Option<Observed<Self::Token>>, Error> {
        self.loads.set(self.loads.get() + 1);
        let result = self.inner.load();
        match self.loads.get() {
            1 => self.pause(PausePoint::InitialLoad)?,
            2 => self.pause(PausePoint::PreparedLoad)?,
            _ => {}
        }
        result
    }
    fn publish(
        &mut self,
        expected: Option<&Self::Token>,
        desired: &PublicDocument,
    ) -> Result<Publication<Self::Token>, Error> {
        let result = self.inner.publish(expected, desired);
        self.pause(PausePoint::Publish)?;
        result
    }
    fn confirm(&self, observed: &Observed<Self::Token>) -> Result<(), Error> {
        let result = self.inner.confirm(observed);
        self.pause(PausePoint::Confirm)?;
        result
    }
}
struct PausedResult<T> {
    store: Arc<Mutex<HostStore>>,
    file: Memory,
    outcome: Result<(), Error>,
    observed: Option<T>,
    reached: bool,
    root: tempfile::TempDir, // Drop Store before removing its private directory.
}
fn paused_configure<T>(
    point: PausePoint,
    already_configured: bool,
    fault: Fault,
    change: impl FnOnce(&mut HostStore) -> T,
) -> PausedResult<T> {
    let (root, mut store, mut file) = fixture();
    if already_configured {
        store.configure_auth(&config()).unwrap();
    }
    reconcile(&mut store, &mut file).unwrap();
    file.fault = fault;
    let store = Arc::new(Mutex::new(store));
    let worker_store = store.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut file = PausedIo {
            inner: file,
            point,
            loads: Cell::new(0),
            entered: entered_tx,
            release: release_rx,
        };
        let outcome = configure_shared(&worker_store, &mut file, &config());
        (outcome, file.inner)
    });
    let reached = entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .ok()
        == Some(point);
    // Never wait for Store: an old implementation holding it across IO must
    // fail the later assertion, release the barrier and join, rather than hang.
    let changed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if reached {
            store.try_lock().ok().map(|mut store| change(&mut store))
        } else {
            None
        }
    }));
    // Always release and join, even if an injected Store mutation panics.
    let _ = release_tx.try_send(());
    let joined = worker.join();
    let observed = match changed {
        Ok(observed) => observed,
        Err(error) => std::panic::resume_unwind(error),
    };
    let (outcome, file) = joined.unwrap();
    PausedResult {
        root,
        store,
        file,
        outcome,
        observed,
        reached,
    }
}
#[test]
fn shared_store_is_available_during_every_public_file_io_phase() {
    for point in [
        PausePoint::InitialLoad,
        PausePoint::PreparedLoad,
        PausePoint::Publish,
        PausePoint::Confirm,
    ] {
        let result = paused_configure(point, false, Fault::None, |store| {
            store.observe_authorization_clock(1005).unwrap()
        });
        assert!(result.reached, "IO barrier not reached: {point:?}");
        assert_eq!(result.observed, Some(1005), "Store retained: {point:?}");
        assert!(result.outcome.is_ok(), "clock-only progress is not a fence");
        let store = result.store.lock().unwrap();
        assert!(store.public_configuration_ready().unwrap());
        assert_eq!(store.auth_configuration().unwrap(), Some(config()));
        assert_eq!(store.authorization_state().unwrap().clock_floor, 1005);
    }
}
#[test]
fn logout_during_initial_load_prevents_prepare_and_keeps_readiness_closed() {
    let result = paused_configure(PausePoint::InitialLoad, false, Fault::None, |store| {
        store
            .fence_authorization(lomi_host_store::AuthorizationFenceReason::LocalLogout)
            .unwrap()
    });
    assert!(result.reached);
    let fence = result.observed.unwrap();
    assert!(result.outcome.is_err());
    assert_eq!(result.file.publications, 1); // Only original bootstrap.
    assert!(result.file.current.as_ref() == Some(&document(1, None)));
    let store = result.store.lock().unwrap();
    assert!(!store.public_configuration_ready().unwrap());
    assert!(
        store
            .public_configuration_state()
            .unwrap()
            .unwrap()
            .prepared
            .is_none()
    );
    assert_eq!(
        store.authorization_state().unwrap().generation,
        fence.generation
    );
    assert!(store.authorization_state().unwrap().pending_cloud_revoke);
}
#[test]
fn logout_after_prepare_never_finishes_or_discards_exact_durable_intent() {
    for point in [
        PausePoint::PreparedLoad,
        PausePoint::Publish,
        PausePoint::Confirm,
    ] {
        let mut result = paused_configure(point, false, Fault::None, |store| {
            let intent = store
                .public_configuration_state()
                .unwrap()
                .unwrap()
                .prepared
                .unwrap();
            let fence = store
                .fence_authorization(lomi_host_store::AuthorizationFenceReason::LocalLogout)
                .unwrap();
            (intent, fence)
        });
        assert!(result.reached);
        let (intent, fence) = result.observed.unwrap();
        assert!(matches!(result.outcome, Err(Error::Conflict)));
        {
            let store = result.store.lock().unwrap();
            let state = store.public_configuration_state().unwrap().unwrap();
            assert!(state.prepared.as_ref() == Some(&intent));
            assert!(state.current.as_ref() == intent.expected.as_ref());
            assert!(!store.public_configuration_ready().unwrap());
        }
        // Restart is an exclusive reconciliation, not a late in-flight ACK.
        let store = Arc::try_unwrap(result.store)
            .ok()
            .unwrap()
            .into_inner()
            .unwrap();
        let mut store = reopen(&result.root, store);
        reconcile(&mut store, &mut result.file).unwrap();
        assert!(store.public_configuration_ready().unwrap());
        assert_eq!(store.auth_configuration().unwrap(), Some(config()));
        let actual = store.authorization_state().unwrap();
        assert_eq!(actual.generation, fence.generation);
        assert!(actual.locked && actual.pending_cloud_revoke);
    }
}
#[test]
fn concurrent_preparation_during_load_is_not_replaced_by_stale_work() {
    let result = paused_configure(PausePoint::InitialLoad, false, Fault::None, |store| {
        let current = store.public_current().unwrap();
        store
            .public_prepare(Some(&current), &document(2, Some(config())))
            .unwrap()
    });
    assert!(result.reached);
    let concurrent = result.observed.unwrap();
    assert!(result.outcome.is_err());
    let store = result.store.lock().unwrap();
    assert!(
        store
            .public_configuration_state()
            .unwrap()
            .unwrap()
            .prepared
            .as_ref()
            == Some(&concurrent)
    );
    assert!(!store.public_configuration_ready().unwrap());
    assert!(result.file.current.as_ref() == Some(&document(1, None)));
}
#[test]
fn separately_finished_revision_during_confirm_is_not_acknowledged_again() {
    let result = paused_configure(PausePoint::Confirm, false, Fault::None, |store| {
        // The synthetic IO model already confirmed before this barrier. Model a
        // separate completed reconciliation to test the final exact-state CAS.
        let intent = store
            .public_configuration_state()
            .unwrap()
            .unwrap()
            .prepared
            .unwrap();
        store
            .public_finish(intent.operation_id, &intent.desired)
            .unwrap();
        intent
    });
    assert!(result.reached);
    let completed = result.observed.unwrap();
    assert!(matches!(result.outcome, Err(Error::Conflict)));
    let store = result.store.lock().unwrap();
    let state = store.public_configuration_state().unwrap().unwrap();
    assert!(state.current.as_ref() == Some(&completed.desired));
    assert!(state.prepared.is_none());
    assert!(!store.public_configuration_ready().unwrap());
}
#[test]
fn io_failures_keep_their_error_and_intent_even_when_logout_also_invalidates_scope() {
    for fault in [Fault::BeforeRename, Fault::AfterRename, Fault::Confirm] {
        let point = if fault == Fault::Confirm {
            PausePoint::Confirm
        } else {
            PausePoint::Publish
        };
        let mut result = paused_configure(point, false, fault, |store| {
            let intent = store
                .public_configuration_state()
                .unwrap()
                .unwrap()
                .prepared
                .unwrap();
            let fence = store
                .fence_authorization(lomi_host_store::AuthorizationFenceReason::LocalLogout)
                .unwrap();
            (intent, fence)
        });
        assert!(result.reached);
        let (intent, fence) = result.observed.unwrap();
        match fault {
            Fault::BeforeRename => assert!(matches!(result.outcome, Err(Error::Storage))),
            _ => assert!(matches!(result.outcome, Err(Error::Uncertain))),
        }
        {
            let store = result.store.lock().unwrap();
            assert!(
                store
                    .public_configuration_state()
                    .unwrap()
                    .unwrap()
                    .prepared
                    .as_ref()
                    == Some(&intent)
            );
            assert!(!store.public_configuration_ready().unwrap());
        }
        let publications = result.file.publications;
        result.file.fault = Fault::None;
        let store = Arc::try_unwrap(result.store)
            .ok()
            .unwrap()
            .into_inner()
            .unwrap();
        let mut store = reopen(&result.root, store);
        reconcile(&mut store, &mut result.file).unwrap();
        assert_eq!(
            result.file.publications,
            publications + usize::from(fault == Fault::BeforeRename)
        );
        assert!(store.public_configuration_ready().unwrap());
        let actual = store.authorization_state().unwrap();
        assert_eq!(actual.generation, fence.generation);
        assert!(actual.locked && actual.pending_cloud_revoke);
    }
}
#[test]
fn idempotent_confirm_still_rechecks_current_auth_scope_before_success() {
    let result = paused_configure(PausePoint::Confirm, true, Fault::None, |store| {
        store
            .fence_authorization(lomi_host_store::AuthorizationFenceReason::LocalLogout)
            .unwrap()
    });
    assert!(result.reached && result.observed.is_some());
    assert!(result.outcome.is_err());
    let store = result.store.lock().unwrap();
    assert!(!store.public_configuration_ready().unwrap());
    assert!(
        store
            .public_configuration_state()
            .unwrap()
            .unwrap()
            .prepared
            .is_none()
    );
    assert_eq!(result.file.publications, 1); // Only original bootstrap.
}
#[test]
fn wrong_operation_token_cannot_finish_or_remove_the_exact_prepared_intent() {
    let (_root, mut store, mut file) = fixture();
    reconcile(&mut store, &mut file).unwrap();
    let current = store.public_current().unwrap();
    let intent = store
        .public_prepare(Some(&current), &document(2, Some(config())))
        .unwrap();
    let scope = PublicAuthFence::read(&store).unwrap();
    let mut wrong = intent.clone();
    wrong.operation_id = OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).unwrap();
    assert!(matches!(
        check_prepared(&mut store, &wrong, scope),
        Err(Error::Conflict)
    ));
    assert!(
        store
            .public_configuration_state()
            .unwrap()
            .unwrap()
            .prepared
            .as_ref()
            == Some(&intent)
    );
    assert!(!store.public_configuration_ready().unwrap());
}
#[test]
fn poisoned_shared_store_is_only_blocked_never_used_to_prepare_or_publish() {
    let (_root, mut store, mut file) = fixture();
    reconcile(&mut store, &mut file).unwrap();
    let store = Arc::new(Mutex::new(store));
    let poison = store.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("intentional private fixture Store poison");
        })
        .join()
        .is_err()
    );
    let publications = file.publications;
    assert!(matches!(
        configure_shared(&store, &mut file, &config()),
        Err(Error::Storage)
    ));
    assert!(store.is_poisoned());
    assert_eq!(file.publications, publications);
    let guard = store.lock().err().unwrap().into_inner();
    assert!(!guard.public_configuration_ready().unwrap());
    assert!(
        guard
            .public_configuration_state()
            .unwrap()
            .unwrap()
            .prepared
            .is_none()
    );
}

#[test]
fn same_generation_lock_transition_cannot_finish_an_older_preparation() {
    let result = paused_configure(PausePoint::Confirm, false, Fault::None, |store| {
        // Private trusted Store fixture only; no login/HostAuth authority claim.
        let generation = store.authorization_state().unwrap().generation;
        store.enable_authorization(generation).unwrap()
    });
    assert!(result.reached);
    let changed = result.observed.unwrap();
    assert!(!changed.locked);
    assert!(matches!(result.outcome, Err(Error::Conflict)));
    let store = result.store.lock().unwrap();
    assert_eq!(
        store.authorization_state().unwrap().generation,
        changed.generation
    );
    assert!(!store.public_configuration_ready().unwrap());
    assert!(
        store
            .public_configuration_state()
            .unwrap()
            .unwrap()
            .prepared
            .is_some()
    );
}

// Authored source-only coverage for the inactive owner path.
struct OwnerIo<'a> {
    inner: Memory,
    owner: &'a super::super::shared_owner::SharedOwner,
    operation: &'a super::super::owner_domain::Operation<'a>,
    phases: Cell<usize>,
}
impl OwnerIo<'_> {
    fn unlocked(&self) {
        // Acquire BOTH mutexes without treating shared-pending denial as a lock.
        self.owner
            .probe_both_locks_for_test(self.operation)
            .unwrap();
        assert!(matches!(
            self.owner.remote_authorization(self.operation),
            Err(super::super::shared_owner::Error::Domain(
                super::super::owner_domain::Error::Denied
            ))
        ));
        self.phases.set(self.phases.get() + 1);
    }
}
impl PublicIo for OwnerIo<'_> {
    type Token = PublicDocument;
    fn load(&self) -> Result<Option<Observed<Self::Token>>, Error> {
        self.unlocked();
        self.inner.load()
    }
    fn publish(
        &mut self,
        expected: Option<&Self::Token>,
        desired: &PublicDocument,
    ) -> Result<Publication<Self::Token>, Error> {
        self.unlocked();
        self.inner.publish(expected, desired)
    }
    fn confirm(&self, observed: &Observed<Self::Token>) -> Result<(), Error> {
        self.unlocked();
        self.inner.confirm(observed)
    }
}
#[test]
fn owner_configuration_releases_both_domains_for_load_publish_and_confirm() {
    use super::super::{owner_domain::Operation, shared_owner::SharedOwner};
    let (_root, mut store, mut file) = fixture();
    reconcile(&mut store, &mut file).unwrap();
    let owner = SharedOwner::new(store).unwrap();
    let cancel = AtomicBool::new(false);
    let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancel);
    let mut file = OwnerIo {
        inner: file,
        owner: &owner,
        operation: &operation,
        phases: Cell::new(0),
    };
    let mut turn = owner
        .begin_public_configuration(&operation, config())
        .unwrap();
    turn.configure(&mut file).unwrap();
    assert_eq!(file.phases.get(), 4); // initial load, prepared load, publish, confirm
    assert!(matches!(
        turn.configure(&mut file),
        Err(Error::Owner(super::super::shared_owner::Error::Domain(
            super::super::owner_domain::Error::Stale
        )))
    ));
    assert_eq!(file.phases.get(), 4);
    assert!(owner.remote_authorization(&operation).is_err());
}
#[test]
fn owner_noop_still_confirms_and_never_publishes() {
    use super::super::{owner_domain::Operation, shared_owner::SharedOwner};
    let (_root, mut store, mut file) = fixture();
    store.configure_auth(&config()).unwrap();
    reconcile(&mut store, &mut file).unwrap();
    let owner = SharedOwner::new(store).unwrap();
    let cancel = AtomicBool::new(false);
    let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancel);
    let publications = file.publications;
    let confirmations = file.confirmations.get();
    owner
        .begin_public_configuration(&operation, config())
        .unwrap()
        .configure(&mut file)
        .unwrap();
    assert_eq!(file.publications, publications);
    assert_eq!(file.confirmations.get(), confirmations + 1);
    assert!(owner.remote_authorization(&operation).is_err());
}
#[test]
fn owner_uncertain_file_outcome_is_terminal_and_never_republished() {
    use super::super::{owner_domain::Operation, shared_owner::SharedOwner};
    for fault in [
        Fault::Read,
        Fault::BeforeRename,
        Fault::AfterRename,
        Fault::Confirm,
    ] {
        let (_root, mut store, mut file) = fixture();
        reconcile(&mut store, &mut file).unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancel);
        file.fault = fault;
        let mut turn = owner
            .begin_public_configuration(&operation, config())
            .unwrap();
        assert!(turn.configure(&mut file).is_err());
        let publications = file.publications;
        file.fault = Fault::None;
        assert!(turn.configure(&mut file).is_err());
        assert_eq!(file.publications, publications);
        assert!(owner.remote_authorization(&operation).is_err());
    }
}

struct BusyFinal<'a> {
    store: BorrowedStore<'a>,
    busy: bool,
    finishes: usize,
}
impl PublicPhases for BusyFinal<'_> {
    fn snapshot(&mut self) -> Result<(PublicDocument, PublicAuthFence), Error> {
        self.store.snapshot()
    }
    fn current(&mut self, current: &PublicDocument, scope: PublicAuthFence) -> Result<(), Error> {
        if self.busy {
            self.busy = false;
            return Err(Error::Store(StoreError::Busy));
        }
        self.store.current(current, scope)
    }
    fn prepare(
        &mut self,
        current: &PublicDocument,
        scope: PublicAuthFence,
        desired: &PublicDocument,
    ) -> Result<(PublicPreparation, PublicAuthFence), Error> {
        self.store.prepare(current, scope, desired)
    }
    fn finish(
        &mut self,
        intent: &PublicPreparation,
        scope: PublicAuthFence,
        published: &PublicDocument,
    ) -> Result<(), Error> {
        self.finishes += 1;
        if self.busy {
            self.busy = false;
            return Err(Error::Store(StoreError::Busy));
        }
        self.store.finish(intent, scope, published)
    }
    fn block(&mut self) {
        self.store.block();
    }
}
#[test]
fn owned_progress_busy_finalization_never_repeats_publication_or_confirmation() {
    for noop in [false, true] {
        let (_root, mut store, mut file) = fixture();
        if noop {
            store.configure_auth(&config()).unwrap();
        }
        reconcile(&mut store, &mut file).unwrap();
        let mut phases = BusyFinal {
            store: BorrowedStore(&mut store),
            busy: true,
            finishes: 0,
        };
        let mut progress = Progress::Snapshot;
        assert!(matches!(
            advance(&mut phases, &mut progress, &mut file, &config()),
            Err(Error::Store(StoreError::Busy))
        ));
        let publications = file.publications;
        let confirmations = file.confirmations.get();
        advance(&mut phases, &mut progress, &mut file, &config()).unwrap();
        assert_eq!(file.publications, publications);
        assert_eq!(file.confirmations.get(), confirmations);
        assert_eq!(phases.finishes, if noop { 0 } else { 2 });
    }
}

#[derive(Clone, Copy)]
enum TerminalPoint {
    InitialLoad,
    PreparedLoad,
    Publish,
    Confirm,
}
struct TerminalIo<'a> {
    inner: Memory,
    operation: &'a super::super::owner_domain::Operation<'a>,
    cancellation: &'a AtomicBool,
    cancel: bool,
    point: TerminalPoint,
    fail: bool,
    loads: Cell<usize>,
}
impl TerminalIo<'_> {
    fn terminate(&self) {
        if self.cancel {
            self.cancellation.store(true, Ordering::Release);
        } else {
            self.operation.expire_for_test();
        }
    }
}
impl PublicIo for TerminalIo<'_> {
    type Token = PublicDocument;
    fn load(&self) -> Result<Option<Observed<Self::Token>>, Error> {
        self.loads.set(self.loads.get() + 1);
        if matches!(
            (self.point, self.loads.get()),
            (TerminalPoint::InitialLoad, 1) | (TerminalPoint::PreparedLoad, 2)
        ) {
            self.terminate();
            if self.fail {
                return Err(Error::Storage);
            }
        }
        self.inner.load()
    }
    fn publish(
        &mut self,
        expected: Option<&Self::Token>,
        desired: &PublicDocument,
    ) -> Result<Publication<Self::Token>, Error> {
        let result = self.inner.publish(expected, desired);
        if matches!(self.point, TerminalPoint::Publish) {
            self.terminate();
        }
        result
    }
    fn confirm(&self, observed: &Observed<Self::Token>) -> Result<(), Error> {
        if matches!(self.point, TerminalPoint::Confirm) {
            self.terminate();
            if self.fail {
                return Err(Error::Uncertain);
            }
        }
        self.inner.confirm(observed)
    }
}
#[test]
fn owned_terminal_prepared_load_never_publishes_and_keeps_durable_intent() {
    use super::super::{
        owner_domain::{self, Operation},
        shared_owner::{self, SharedOwner},
    };
    for cancel in [false, true] {
        let (_root, mut store, mut file) = fixture();
        reconcile(&mut store, &mut file).unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let cancellation = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancellation);
        let publications = file.publications;
        let confirmations = file.confirmations.get();
        let original = file.current.clone();
        let mut file = TerminalIo {
            inner: file,
            operation: &operation,
            cancellation: &cancellation,
            cancel,
            point: TerminalPoint::PreparedLoad,
            fail: false,
            loads: Cell::new(0),
        };
        let mut turn = owner
            .begin_public_configuration(&operation, config())
            .unwrap();
        let outcome = turn.configure(&mut file);
        if cancel {
            assert!(matches!(
                outcome,
                Err(Error::Owner(shared_owner::Error::Domain(
                    owner_domain::Error::Cancelled
                )))
            ));
        } else {
            assert!(matches!(
                outcome,
                Err(Error::Owner(shared_owner::Error::Domain(
                    owner_domain::Error::Deadline
                )))
            ));
        }
        assert_eq!(file.loads.get(), 2);
        assert_eq!(file.inner.publications, publications);
        assert_eq!(file.inner.confirmations.get(), confirmations);
        assert!(file.inner.current == original);
        let (state, ready) = turn.turn.public_state_for_test();
        let state = state.unwrap();
        let intent = state.prepared.unwrap();
        assert!(state.current == original);
        assert!(intent.expected == original);
        assert!(intent.desired == document(2, Some(config())));
        assert!(!ready);
        assert!(!turn.is_pending());
        cancellation.store(false, Ordering::Release);
        assert!(turn.configure(&mut file).is_err());
        assert_eq!(file.loads.get(), 2);
        assert_eq!(file.inner.publications, publications);
        // This fresh context only inspects the closed remote gate; it never
        // replaces the expired/cancelled configuration request's budget.
        let inspection = Operation::new(Instant::now() + Duration::from_secs(5), &cancellation);
        assert!(owner.remote_authorization(&inspection).is_err());
    }
}
#[test]
fn owned_terminal_file_errors_keep_original_error_and_clear_store_readiness() {
    use super::super::{owner_domain::Operation, shared_owner::SharedOwner};
    for confirm in [false, true] {
        for cancel in [false, true] {
            let (_root, mut store, mut file) = fixture();
            if confirm {
                store.configure_auth(&config()).unwrap();
            }
            reconcile(&mut store, &mut file).unwrap();
            assert!(store.public_configuration_ready().unwrap());
            let owner = SharedOwner::new(store).unwrap();
            let cancellation = AtomicBool::new(false);
            let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancellation);
            let publications = file.publications;
            let mut file = TerminalIo {
                inner: file,
                operation: &operation,
                cancellation: &cancellation,
                cancel,
                point: if confirm {
                    TerminalPoint::Confirm
                } else {
                    TerminalPoint::InitialLoad
                },
                fail: true,
                loads: Cell::new(0),
            };
            let mut turn = owner
                .begin_public_configuration(&operation, config())
                .unwrap();
            let outcome = turn.configure(&mut file);
            if confirm {
                assert!(matches!(outcome, Err(Error::Uncertain)));
            } else {
                assert!(matches!(outcome, Err(Error::Storage)));
            }
            let (state, ready) = turn.turn.public_state_for_test();
            assert!(
                !ready,
                "free Store must be blocked even after Operation terminates"
            );
            assert!(state.unwrap().prepared.is_none());
            assert_eq!(file.inner.publications, publications);
            assert!(!turn.is_pending());
        }
    }
}
#[test]
fn owned_terminal_load_or_publication_prevents_the_next_file_phase() {
    use super::super::{owner_domain::Operation, shared_owner::SharedOwner};
    for publish in [false, true] {
        for cancel in [false, true] {
            let (_root, mut store, mut file) = fixture();
            reconcile(&mut store, &mut file).unwrap();
            let owner = SharedOwner::new(store).unwrap();
            let cancellation = AtomicBool::new(false);
            let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancellation);
            let publications = file.publications;
            let confirmations = file.confirmations.get();
            let mut file = TerminalIo {
                inner: file,
                operation: &operation,
                cancellation: &cancellation,
                cancel,
                point: if publish {
                    TerminalPoint::Publish
                } else {
                    TerminalPoint::InitialLoad
                },
                fail: false,
                loads: Cell::new(0),
            };
            let mut turn = owner
                .begin_public_configuration(&operation, config())
                .unwrap();
            assert!(turn.configure(&mut file).is_err());
            assert_eq!(file.inner.publications, publications + usize::from(publish));
            assert_eq!(file.inner.confirmations.get(), confirmations);
            let (state, ready) = turn.turn.public_state_for_test();
            assert_eq!(state.unwrap().prepared.is_some(), publish);
            assert!(!ready);
            assert!(!turn.is_pending());
        }
    }
}

struct RejectedInitialLoad {
    malformed: bool,
}
impl PublicIo for RejectedInitialLoad {
    type Token = PublicDocument;
    fn load(&self) -> Result<Option<Observed<Self::Token>>, Error> {
        if self.malformed {
            Err(Error::Store(StoreError::Invalid))
        } else {
            Err(Error::Storage)
        }
    }
    fn publish(
        &mut self,
        _expected: Option<&Self::Token>,
        _desired: &PublicDocument,
    ) -> Result<Publication<Self::Token>, Error> {
        panic!("rejected initial load must never publish")
    }
    fn confirm(&self, _observed: &Observed<Self::Token>) -> Result<(), Error> {
        panic!("rejected initial load must never confirm")
    }
}
#[test]
fn initial_file_error_classification_preserves_legacy_conflict_and_owned_original() {
    use super::super::{owner_domain::Operation, shared_owner::SharedOwner};
    for malformed in [false, true] {
        let (_root, mut store, mut file) = fixture();
        reconcile(&mut store, &mut file).unwrap();
        let legacy = Mutex::new(store);
        let mut rejected = RejectedInitialLoad { malformed };
        assert!(matches!(
            configure_shared(&legacy, &mut rejected, &config()),
            Err(Error::Conflict)
        ));
        assert!(!legacy.lock().unwrap().public_configuration_ready().unwrap());
        // Inspect a separate owned fixture; no operation or budget crosses
        // between the legacy and owned configurations.
        let (_owned_root, mut store, mut file) = fixture();
        reconcile(&mut store, &mut file).unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let cancellation = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancellation);
        let mut turn = owner
            .begin_public_configuration(&operation, config())
            .unwrap();
        let outcome = turn.configure(&mut rejected);
        if malformed {
            assert!(matches!(outcome, Err(Error::Store(StoreError::Invalid))));
        } else {
            assert!(matches!(outcome, Err(Error::Storage)));
        }
        assert!(!turn.turn.public_state_for_test().1);
        assert!(!turn.is_pending());
    }
}

#[cfg(unix)]
#[test]
fn public_setup_owned_entry_persists_real_file_and_releases_owner_locks() {
    use super::super::{owner_domain::Operation, shared_owner::SharedOwner};
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let profile = root.path().canonicalize().unwrap();
    let lock = OwnerLock::acquire(&profile).unwrap();
    let database = lock.prepare_database().unwrap();
    let mut store = HostStore::open(&database, Limits::default()).unwrap();
    startup(&mut store, lock.profile()).unwrap();
    assert!(store.public_current().unwrap() == document(1, None));
    let endpoint = Arc::new(
        OwnerEndpoint::bind(
            lock,
            LocalDiscovery {
                version: LocalIpcVersion::CURRENT,
                profile_id: store.identity().profile_id,
                host_id: store.identity().host_id,
                runtime_id: store.runtime_id(),
                build_id: "private-owned-public-configuration-fixture".to_owned(),
            },
        )
        .unwrap(),
    );
    let setup = PublicSetup::new(endpoint.clone());
    let owner = SharedOwner::new(store).unwrap();
    let cancellation = AtomicBool::new(false);
    let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancellation);
    let mut turn = owner
        .begin_public_configuration(&operation, config())
        .unwrap();
    // Retain the wrapper caller's request and credential-IO exclusion while
    // the real public file is loaded, replaced and durably confirmed.
    let request = setup.request.lock().unwrap();
    let io = setup.io.write().unwrap();
    setup.configure_owned(&mut turn).unwrap();
    assert!(!turn.is_pending());
    let desired = document(2, Some(config()));
    let file = PublicFile::new(endpoint.profile()).unwrap();
    let published = file.load().unwrap().unwrap();
    assert!(PublicDocument::from_bytes(published.source()).unwrap() == desired);
    file.confirm(&published).unwrap();
    // The exact original Operation must reacquire Domain and Store after
    // completion, even while the caller still owns both exclusion guards.
    owner.authorization_state(&operation).unwrap();
    let (state, ready) = turn.turn.public_state_for_test();
    let state = state.unwrap();
    assert!(ready);
    assert!(state.current.as_ref() == Some(&desired));
    assert!(state.prepared.is_none());
    assert!(matches!(
        setup.configure_owned(&mut turn),
        Err(LocalError::Unavailable)
    ));
    let unchanged = file.load().unwrap().unwrap();
    assert_eq!(unchanged.source(), published.source());
    drop(io);
    drop(request);
    assert!(setup.io.try_write().is_ok());
    assert!(setup.request.try_lock().is_ok());
    drop(turn);
    drop(owner);

    // Reopen the durable Store without replacing the profile owner. Opening
    // resets readiness; only reconciliation against the actual file restores it.
    let mut reopened = HostStore::open(&database, Limits::default()).unwrap();
    let state = reopened.public_configuration_state().unwrap().unwrap();
    assert!(state.current.as_ref() == Some(&desired));
    assert!(state.prepared.is_none());
    assert!(matches!(
        reopened.auth_configuration(),
        Err(StoreError::Fenced)
    ));
    assert!(!reopened.public_configuration_ready().unwrap());
    startup(&mut reopened, endpoint.profile()).unwrap();
    assert!(reopened.public_configuration_ready().unwrap());
    assert!(reopened.auth_configuration().unwrap().as_ref() == Some(&config()));
    assert!(reopened.public_current().unwrap() == desired);
    assert_eq!(file.load().unwrap().unwrap().source(), published.source());
}
