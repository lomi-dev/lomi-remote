//! Three durable phases: prepare intent, publish public file, finalize marker.
//! Caller owns OwnerLock and excludes credential IO before short Store closures.
//! Shared Store guards never span public-file or profile IO; startup is exclusive.
use super::*;
use lomi_host_store::{PublicDocument, PublicPreparation};
use lomi_platform::public_config::Configuration;
use platform::public_config::{CommitOutcome, PublicFile, Snapshot};
use std::sync::RwLock;

#[cfg(all(unix, test, feature = "cloud-fixture"))]
const TEST_REMOTE_API_ROOT_LIMIT: usize = 16 * 1024;

pub(super) struct PublicSetup {
    endpoint: Arc<OwnerEndpoint>,
    pub request: Mutex<()>,
    pub io: RwLock<()>,
    pub pending: AtomicBool,
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    test_remote_api_root_der: Option<Arc<[u8]>>,
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    test_relay_root_der: Option<Arc<[u8]>>,
}
// Operation-bound owner adapter. The actual read lease and its exact setup travel
// together; callers cannot construct, clone, serialize, or extract the guard.
pub(super) struct WorkerPublicIo<'a> {
    setup: &'a PublicSetup,
    _guard: std::sync::RwLockReadGuard<'a, ()>,
    lease_identity: Arc<()>,
}
pub(super) struct WorkerPublicIoIdentity(Arc<()>);
impl<'a> WorkerPublicIo<'a> {
    pub(super) fn retained_identity(&self) -> WorkerPublicIoIdentity {
        WorkerPublicIoIdentity(self.lease_identity.clone())
    }
    pub(super) fn is_same_lease(&self, identity: &WorkerPublicIoIdentity) -> bool {
        Arc::ptr_eq(&self.lease_identity, &identity.0)
    }
    pub(super) fn setup(&self) -> &'a PublicSetup {
        self.setup
    }
    pub(super) fn data_transport(
        &self,
        origin: lomi_host_http::RemoteApiOrigin,
    ) -> Result<lomi_host_http::DataTransport, lomi_host_http::Error> {
        self.setup.data_transport(origin)
    }
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    pub(super) fn cloud_fixture_ingress_roots(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        Some((
            self.setup.test_remote_api_root_der.as_deref()?.to_vec(),
            self.setup.test_relay_root_der.as_deref()?.to_vec(),
        ))
    }
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    pub(super) fn joined_cloud_fixture_selected(&self) -> bool {
        self.setup.test_remote_api_root_der.is_some() && self.setup.test_relay_root_der.is_some()
    }
}
impl PublicSetup {
    pub fn new(endpoint: Arc<OwnerEndpoint>) -> Self {
        Self {
            endpoint,
            request: Mutex::new(()),
            io: RwLock::new(()),
            pending: AtomicBool::new(false),
            #[cfg(all(unix, test, feature = "cloud-fixture"))]
            test_remote_api_root_der: None,
            #[cfg(all(unix, test, feature = "cloud-fixture"))]
            test_relay_root_der: None,
        }
    }
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    pub(super) fn with_remote_api_test_root(
        endpoint: Arc<OwnerEndpoint>,
        root_der: Vec<u8>,
    ) -> Result<Self, lomi_host_http::Error> {
        if root_der.is_empty() || root_der.len() > TEST_REMOTE_API_ROOT_LIMIT {
            return Err(lomi_host_http::Error::InvalidConfig);
        }
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(root_der.clone()))
            .map_err(|_| lomi_host_http::Error::InvalidConfig)?;
        Ok(Self {
            endpoint,
            request: Mutex::new(()),
            io: RwLock::new(()),
            pending: AtomicBool::new(false),
            test_remote_api_root_der: Some(Arc::from(root_der.into_boxed_slice())),
            test_relay_root_der: None,
        })
    }
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    pub(super) fn with_joined_cloud_test_roots(
        endpoint: Arc<OwnerEndpoint>,
        remote_api_root_der: Vec<u8>,
        relay_root_der: Vec<u8>,
    ) -> Result<Self, lomi_host_http::Error> {
        fn validate(root_der: &[u8]) -> Result<(), lomi_host_http::Error> {
            if root_der.is_empty() || root_der.len() > TEST_REMOTE_API_ROOT_LIMIT {
                return Err(lomi_host_http::Error::InvalidConfig);
            }
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(root_der.to_vec()))
                .map_err(|_| lomi_host_http::Error::InvalidConfig)
        }
        validate(&remote_api_root_der)?;
        validate(&relay_root_der)?;
        Ok(Self {
            endpoint,
            request: Mutex::new(()),
            io: RwLock::new(()),
            pending: AtomicBool::new(false),
            test_remote_api_root_der: Some(Arc::from(remote_api_root_der.into_boxed_slice())),
            test_relay_root_der: Some(Arc::from(relay_root_der.into_boxed_slice())),
        })
    }
    fn data_transport(
        &self,
        origin: lomi_host_http::RemoteApiOrigin,
    ) -> Result<lomi_host_http::DataTransport, lomi_host_http::Error> {
        #[cfg(all(unix, test, feature = "cloud-fixture"))]
        if let Some(root_der) = &self.test_remote_api_root_der {
            return lomi_host_http::DataTransport::with_test_root(origin, root_der.to_vec());
        }
        lomi_host_http::DataTransport::new(origin)
    }
    pub fn enter(
        &self,
        paused: &AtomicBool,
    ) -> Result<Option<std::sync::RwLockReadGuard<'_, ()>>, ()> {
        let guard = self.io.read().map_err(|_| ())?;
        // Clear only the previous attempt's pause BEFORE checking pending.
        // Configure may set pause immediately after the check; no later worker
        // clear may overwrite that request while configure waits for this guard.
        paused.store(false, Ordering::Release);
        if self.pending.load(Ordering::Acquire) {
            paused.store(true, Ordering::Release);
            return Ok(None);
        }
        Ok(Some(guard))
    }
    // The worker replaces its existing enter call with this
    // additive wrapper, never acquires a second/nested read lease.
    pub(super) fn enter_owned(
        &self,
        paused: &AtomicBool,
    ) -> Result<Option<WorkerPublicIo<'_>>, ()> {
        self.enter(paused).map(|guard| {
            guard.map(|guard| WorkerPublicIo {
                setup: self,
                _guard: guard,
                lease_identity: Arc::new(()),
            })
        })
    }
    // All workers receive the SAME SharedOwner Arc. Caller
    // retains request serialization and exclusive credential IO across retries.
    pub(super) fn configure_owned(
        &self,
        turn: &mut OwnerConfiguration<'_, '_>,
    ) -> Result<(), LocalError> {
        if !turn.is_pending() {
            return Err(LocalError::Unavailable);
        }
        if let Err(error) = turn.turn.check_operation() {
            turn.turn.block();
            turn.turn.abandon();
            turn.active = false;
            return Err(local_error(error));
        }
        let file = match PublicFile::new(self.endpoint.profile()) {
            Ok(file) => file,
            Err(_) => {
                turn.turn.block();
                turn.turn.abandon();
                turn.active = false;
                return Err(LocalError::Unavailable);
            }
        };
        turn.configure(&mut PlatformFile(file)).map_err(local_error)
    }
}
#[derive(Debug)]
pub(super) enum Error {
    Storage,
    Conflict,
    Uncertain,
    Store(StoreError),
    Owner(super::shared_owner::Error),
}
impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
fn local_error(error: Error) -> LocalError {
    match error {
        Error::Conflict => LocalError::Conflict,
        Error::Store(error) => store_error(error),
        Error::Owner(super::shared_owner::Error::Store(error)) => store_error(error),
        _ => LocalError::Unavailable,
    }
}
pub(super) struct Observed<T> {
    token: T,
    document: PublicDocument,
}
pub(super) enum Publication<T> {
    Durable(Observed<T>),
    Uncertain,
}
pub(super) trait PublicIo {
    type Token;
    fn load(&self) -> Result<Option<Observed<Self::Token>>, Error>;
    fn publish(
        &mut self,
        expected: Option<&Self::Token>,
        desired: &PublicDocument,
    ) -> Result<Publication<Self::Token>, Error>;
    fn confirm(&self, observed: &Observed<Self::Token>) -> Result<(), Error>;
}
struct PlatformFile<'a>(PublicFile<'a>);
fn observed(snapshot: Snapshot) -> Result<Observed<Snapshot>, Error> {
    let document = PublicDocument::from_bytes(snapshot.source())?;
    Ok(Observed {
        token: snapshot,
        document,
    })
}
impl PublicIo for PlatformFile<'_> {
    type Token = Snapshot;
    fn load(&self) -> Result<Option<Observed<Snapshot>>, Error> {
        self.0
            .load()
            .map_err(|_| Error::Storage)?
            .map(observed)
            .transpose()
    }
    fn publish(
        &mut self,
        expected: Option<&Snapshot>,
        desired: &PublicDocument,
    ) -> Result<Publication<Snapshot>, Error> {
        match self
            .0
            .replace(expected, &desired.configuration()?)
            .map_err(|_| Error::Storage)?
        {
            CommitOutcome::Committed(snapshot) => {
                let actual = observed(snapshot)?;
                if &actual.document != desired {
                    return Err(Error::Conflict);
                }
                Ok(Publication::Durable(actual))
            }
            CommitOutcome::Uncertain(_) => Ok(Publication::Uncertain),
        }
    }
    fn confirm(&self, observed: &Observed<Snapshot>) -> Result<(), Error> {
        self.0
            .confirm(&observed.token)
            .map_err(|_| Error::Uncertain)
    }
}
pub(super) fn startup(
    store: &mut HostStore,
    profile: &platform::PrivateProfile,
) -> Result<(), Error> {
    let file = PublicFile::new(profile).map_err(|_| Error::Storage)?;
    reconcile(store, &mut PlatformFile(file))
}
fn resume<F: PublicIo>(
    store: &mut HostStore,
    file: &mut F,
    intent: &PublicPreparation,
) -> Result<(), Error> {
    let actual = file.load()?;
    let desired = match actual {
        Some(actual) if actual.document == intent.desired => actual,
        Some(actual) if intent.expected.as_ref() == Some(&actual.document) => {
            match file.publish(Some(&actual.token), &intent.desired)? {
                Publication::Durable(desired) => desired,
                Publication::Uncertain => return Err(Error::Uncertain),
            }
        }
        None if intent.expected.is_none() => match file.publish(None, &intent.desired)? {
            Publication::Durable(desired) => desired,
            Publication::Uncertain => return Err(Error::Uncertain),
        },
        _ => return Err(Error::Conflict),
    };
    if desired.document != intent.desired {
        return Err(Error::Conflict);
    }
    // Includes migration adoption and exact post-rename restart reconciliation.
    // This fsync confirmation is mandatory even if desired bytes are already there.
    file.confirm(&desired)?;
    store.public_finish(intent.operation_id, &desired.document)?;
    Ok(())
}
pub(super) fn reconcile<F: PublicIo>(store: &mut HostStore, file: &mut F) -> Result<(), Error> {
    store.public_block();
    match store.public_configuration_state()? {
        None => {
            let found = file.load()?;
            let desired = match &found {
                Some(found) => found.document.clone(),
                None => PublicDocument::encode(&Configuration {
                    version: 1,
                    revision: 1,
                    authentication: store.public_legacy_binding()?,
                })?,
            };
            let intent =
                store.public_prepare(found.as_ref().map(|value| &value.document), &desired)?;
            resume(store, file, &intent)
        }
        Some(state) => match state.prepared {
            Some(intent) => resume(store, file, &intent),
            None => {
                let actual = file.load()?.ok_or(Error::Conflict)?;
                if Some(&actual.document) != state.current.as_ref() {
                    return Err(Error::Conflict);
                }
                file.confirm(&actual)?;
                store.public_accept_current(&actual.document)?;
                Ok(())
            }
        },
    }
}
// Private, named phases only. No caller can supply a Store callback.
// The legacy Mutex entry point remains until the one-graph handle activation.
trait PublicPhases {
    // Preserve the retained production adapter's original classification.
    // Only the inactive owned request path retains the original file error.
    fn map_initial_file_error(&self, _error: Error) -> Error {
        Error::Conflict
    }
    // Legacy adapters have no admitted owner Operation. The inactive owner
    // implementation overrides this with its original PendingWriter check.
    fn check_operation(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn snapshot(&mut self) -> Result<(PublicDocument, PublicAuthFence), Error>;
    fn current(&mut self, current: &PublicDocument, scope: PublicAuthFence) -> Result<(), Error>;
    fn prepare(
        &mut self,
        current: &PublicDocument,
        scope: PublicAuthFence,
        desired: &PublicDocument,
    ) -> Result<(PublicPreparation, PublicAuthFence), Error>;
    fn finish(
        &mut self,
        intent: &PublicPreparation,
        scope: PublicAuthFence,
        published: &PublicDocument,
    ) -> Result<(), Error>;
    fn block(&mut self);
}
#[cfg(test)]
struct SharedStore<'a>(&'a Mutex<HostStore>);
#[cfg(test)]
impl SharedStore<'_> {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HostStore>, Error> {
        match self.0.lock() {
            Ok(store) => Ok(store),
            Err(poisoned) => {
                poisoned.into_inner().public_block();
                Err(Error::Storage)
            }
        }
    }
}
#[cfg(test)]
fn snapshot_store(store: &mut HostStore) -> Result<(PublicDocument, PublicAuthFence), Error> {
    let result = (|| Ok((store.public_current()?, PublicAuthFence::read(store)?)))();
    if result.is_err() {
        store.public_block();
    }
    result
}
#[cfg(test)]
fn prepare_store(
    store: &mut HostStore,
    current: &PublicDocument,
    scope: PublicAuthFence,
    desired: &PublicDocument,
) -> Result<(PublicPreparation, PublicAuthFence), Error> {
    check_current(store, current, scope)?;
    let intent = store.public_prepare(Some(current), desired)?;
    match PublicAuthFence::read(store) {
        Ok(scope) => Ok((intent, scope)),
        Err(error) => {
            store.public_block();
            Err(error)
        }
    }
}
#[cfg(test)]
fn finish_store(
    store: &mut HostStore,
    intent: &PublicPreparation,
    scope: PublicAuthFence,
    published: &PublicDocument,
) -> Result<(), Error> {
    check_prepared(store, intent, scope)?;
    let result = store
        .public_finish(intent.operation_id, published)
        .map_err(Error::Store);
    if result.is_err() {
        store.public_block();
    }
    result
}
#[cfg(test)]
impl PublicPhases for SharedStore<'_> {
    fn snapshot(&mut self) -> Result<(PublicDocument, PublicAuthFence), Error> {
        snapshot_store(&mut *self.lock()?)
    }
    fn current(&mut self, current: &PublicDocument, scope: PublicAuthFence) -> Result<(), Error> {
        check_current(&mut *self.lock()?, current, scope)
    }
    fn prepare(
        &mut self,
        current: &PublicDocument,
        scope: PublicAuthFence,
        desired: &PublicDocument,
    ) -> Result<(PublicPreparation, PublicAuthFence), Error> {
        prepare_store(&mut *self.lock()?, current, scope, desired)
    }
    fn finish(
        &mut self,
        intent: &PublicPreparation,
        scope: PublicAuthFence,
        published: &PublicDocument,
    ) -> Result<(), Error> {
        finish_store(&mut *self.lock()?, intent, scope, published)
    }
    fn block(&mut self) {
        if let Ok(mut store) = self.lock() {
            store.public_block();
        }
    }
}
#[cfg(test)]
struct BorrowedStore<'a>(&'a mut HostStore);
#[cfg(test)]
impl PublicPhases for BorrowedStore<'_> {
    fn snapshot(&mut self) -> Result<(PublicDocument, PublicAuthFence), Error> {
        snapshot_store(self.0)
    }
    fn current(&mut self, current: &PublicDocument, scope: PublicAuthFence) -> Result<(), Error> {
        check_current(self.0, current, scope)
    }
    fn prepare(
        &mut self,
        current: &PublicDocument,
        scope: PublicAuthFence,
        desired: &PublicDocument,
    ) -> Result<(PublicPreparation, PublicAuthFence), Error> {
        prepare_store(self.0, current, scope, desired)
    }
    fn finish(
        &mut self,
        intent: &PublicPreparation,
        scope: PublicAuthFence,
        published: &PublicDocument,
    ) -> Result<(), Error> {
        finish_store(self.0, intent, scope, published)
    }
    fn block(&mut self) {
        self.0.public_block();
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PublicAuthFence {
    generation: u64,
    locked: bool,
    pending_cloud_revoke: bool,
}
impl PublicAuthFence {
    pub(super) fn read(store: &HostStore) -> Result<Self, Error> {
        let state = store.authorization_state()?;
        Ok(Self {
            generation: state.generation,
            locked: state.locked,
            pending_cloud_revoke: state.pending_cloud_revoke,
        })
    }
}
fn block<S: PublicPhases>(store: &mut S) {
    // Preserve the original IO error even if cleanup cannot acquire Store.
    store.block();
}
#[cfg(test)]
fn check_current(
    store: &mut HostStore,
    current: &PublicDocument,
    scope: PublicAuthFence,
) -> Result<(), Error> {
    let result = (|| {
        if PublicAuthFence::read(store)? != scope || store.public_current()? != *current {
            return Err(Error::Conflict);
        }
        Ok(())
    })();
    if result.is_err() {
        store.public_block();
    }
    result
}
#[cfg(test)]
fn check_prepared(
    store: &mut HostStore,
    intent: &PublicPreparation,
    scope: PublicAuthFence,
) -> Result<(), Error> {
    let result = (|| {
        let state = store.public_configuration_state()?.ok_or(Error::Conflict)?;
        if PublicAuthFence::read(store)? != scope
            || state.current.as_ref() != intent.expected.as_ref()
            || state.prepared.as_ref() != Some(intent)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    })();
    if result.is_err() {
        store.public_block();
    }
    result
}
/// File-only counterpart of startup's exact old/new reconciliation. No Store
/// reference or closure is passed into load, replace, reopen or fsync/confirm.
fn publish_preparation<S: PublicPhases, F: PublicIo>(
    store: &mut S,
    file: &mut F,
    intent: &PublicPreparation,
) -> Result<PublicDocument, Error> {
    store.check_operation()?;
    let actual = file.load()?;
    store.check_operation()?;
    let desired = match actual {
        Some(actual) if actual.document == intent.desired => actual,
        Some(actual) if intent.expected.as_ref() == Some(&actual.document) => {
            store.check_operation()?;
            match file.publish(Some(&actual.token), &intent.desired)? {
                Publication::Durable(desired) => desired,
                Publication::Uncertain => return Err(Error::Uncertain),
            }
        }
        None if intent.expected.is_none() => {
            store.check_operation()?;
            match file.publish(None, &intent.desired)? {
                Publication::Durable(desired) => desired,
                Publication::Uncertain => return Err(Error::Uncertain),
            }
        }
        _ => return Err(Error::Conflict),
    };
    if desired.document != intent.desired {
        return Err(Error::Conflict);
    }
    store.check_operation()?;
    file.confirm(&desired)?;
    store.check_operation()?;
    Ok(desired.document)
}
#[cfg(test)]
fn configure_shared<F: PublicIo>(
    store: &Mutex<HostStore>,
    file: &mut F,
    authentication: &LocalAuthConfiguration,
) -> Result<(), Error> {
    configure_with(&mut SharedStore(store), file, authentication)
}
#[cfg(test)]
pub(super) fn configure<F: PublicIo>(
    store: &mut HostStore,
    file: &mut F,
    authentication: &LocalAuthConfiguration,
) -> Result<(), Error> {
    // Existing exclusive fixture tests exercise the same production engine.
    configure_with(&mut BorrowedStore(store), file, authentication)
}
// Progress owns every cross-IO snapshot; there is no guard or borrowed Store.
enum Progress {
    Snapshot,
    Load(PublicDocument, PublicAuthFence),
    Prepare(PublicDocument, PublicAuthFence, PublicDocument),
    ConfirmCurrent(PublicDocument, PublicAuthFence),
    Publish(PublicPreparation, PublicAuthFence),
    Finish(PublicPreparation, PublicAuthFence, PublicDocument),
    Done,
}
#[cfg(test)]
fn configure_with<S: PublicPhases, F: PublicIo>(
    store: &mut S,
    file: &mut F,
    authentication: &LocalAuthConfiguration,
) -> Result<(), Error> {
    advance(store, &mut Progress::Snapshot, file, authentication)
}
fn advance<S: PublicPhases, F: PublicIo>(
    store: &mut S,
    progress: &mut Progress,
    file: &mut F,
    authentication: &LocalAuthConfiguration,
) -> Result<(), Error> {
    authentication
        .validate()
        .map_err(|_| Error::Store(StoreError::Invalid))?;
    loop {
        // Advance only AFTER a phase succeeds. Busy retains exact owned inputs;
        // retries of prepare/finalize cannot repeat a completed file IO phase.
        *progress = match progress {
            Progress::Snapshot => {
                let (current, scope) = store.snapshot()?;
                Progress::Load(current, scope)
            }
            Progress::Load(current, scope) => {
                if let Err(error) = store.check_operation() {
                    block(store);
                    return Err(error);
                }
                let actual = match file.load() {
                    Ok(Some(actual)) if actual.document == *current => actual,
                    Err(error) => {
                        block(store);
                        return Err(store.map_initial_file_error(error));
                    }
                    _ => {
                        block(store);
                        return Err(Error::Conflict);
                    }
                };
                if let Err(error) = store.check_operation() {
                    block(store);
                    return Err(error);
                }
                let mut next = current.configuration()?;
                if next.authentication.as_ref() == Some(authentication) {
                    if let Err(error) = store.check_operation() {
                        block(store);
                        return Err(error);
                    }
                    if let Err(error) = file.confirm(&actual) {
                        block(store);
                        return Err(error);
                    }
                    if let Err(error) = store.check_operation() {
                        block(store);
                        return Err(error);
                    }
                    Progress::ConfirmCurrent(current.clone(), *scope)
                } else {
                    next.revision = next
                        .revision
                        .checked_add(1)
                        .ok_or(Error::Store(StoreError::ResourceExhausted))?;
                    next.authentication = Some(authentication.clone());
                    Progress::Prepare(current.clone(), *scope, PublicDocument::encode(&next)?)
                }
            }
            Progress::ConfirmCurrent(current, scope) => {
                store.current(current, *scope)?;
                Progress::Done
            }
            Progress::Prepare(current, scope, desired) => {
                let (intent, scope) = store.prepare(current, *scope, desired)?;
                Progress::Publish(intent, scope)
            }
            Progress::Publish(intent, scope) => {
                let published = match publish_preparation(store, file, intent) {
                    Ok(published) => published,
                    Err(error) => {
                        block(store);
                        return Err(error);
                    }
                };
                Progress::Finish(intent.clone(), *scope, published)
            }
            Progress::Finish(intent, scope, published) => {
                store.finish(intent, *scope, published)?;
                Progress::Done
            }
            Progress::Done => return Ok(()),
        };
    }
}

/// Adapter for the single owner graph. The original operation,
/// announcement and phase survive Busy; file failures consume the turn.
#[must_use]
pub(super) struct OwnerConfiguration<'d, 'o> {
    turn: super::shared_owner::PublicConfigurationWrite<'d, 'o>,
    authentication: LocalAuthConfiguration,
    progress: Progress,
    active: bool,
}
impl<'d, 'o> OwnerConfiguration<'d, 'o> {
    pub(super) fn new(
        turn: super::shared_owner::PublicConfigurationWrite<'d, 'o>,
        authentication: LocalAuthConfiguration,
    ) -> Self {
        Self {
            turn,
            authentication,
            progress: Progress::Snapshot,
            active: true,
        }
    }
    // After a configure error, true means Busy retained this exact turn.
    pub(super) fn is_pending(&self) -> bool {
        self.active
    }
    fn configure<F: PublicIo>(&mut self, file: &mut F) -> Result<(), Error> {
        if !self.active {
            return Err(Error::Owner(super::shared_owner::Error::Domain(
                super::owner_domain::Error::Stale,
            )));
        }
        let result = advance(
            &mut self.turn,
            &mut self.progress,
            file,
            &self.authentication,
        );
        if matches!(
            &result,
            Err(Error::Owner(super::shared_owner::Error::Domain(
                super::owner_domain::Error::Busy
            ))) | Err(Error::Owner(super::shared_owner::Error::Store(
                StoreError::Busy
            )))
        ) {
            return result;
        }
        self.active = false;
        if result.is_ok() {
            self.turn.complete().map_err(Error::Owner)?;
        } else {
            self.turn.abandon();
        }
        result
    }
}
impl PublicPhases for super::shared_owner::PublicConfigurationWrite<'_, '_> {
    fn map_initial_file_error(&self, error: Error) -> Error {
        error
    }
    fn check_operation(&mut self) -> Result<(), Error> {
        self.check_operation()
    }
    fn snapshot(&mut self) -> Result<(PublicDocument, PublicAuthFence), Error> {
        self.snapshot()
    }
    fn current(&mut self, current: &PublicDocument, scope: PublicAuthFence) -> Result<(), Error> {
        self.current(current, scope)
    }
    fn prepare(
        &mut self,
        current: &PublicDocument,
        scope: PublicAuthFence,
        desired: &PublicDocument,
    ) -> Result<(PublicPreparation, PublicAuthFence), Error> {
        self.prepare(current, scope, desired)
    }
    fn finish(
        &mut self,
        intent: &PublicPreparation,
        scope: PublicAuthFence,
        published: &PublicDocument,
    ) -> Result<(), Error> {
        self.finish(intent, scope, published)
    }
    fn block(&mut self) {
        self.block();
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
mod remote_api_test_root_tests {
    use super::*;
    use crate::testsupport::BuilderExt as _;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, TcpListener},
        thread,
        time::{Duration, Instant},
    };

    fn endpoint_fixture() -> (tempfile::TempDir, Arc<OwnerEndpoint>) {
        let root = tempfile::Builder::new().private_tempdir().unwrap();
        let profile = root.path().canonicalize().unwrap();
        let owner = platform::OwnerLock::acquire(&profile).unwrap();
        let database = owner.prepare_database().unwrap();
        let mut store = HostStore::open(&database, Limits::default()).unwrap();
        startup(&mut store, owner.profile()).unwrap();
        let endpoint = Arc::new(
            platform::OwnerEndpoint::bind(
                owner,
                platform::LocalDiscovery {
                    version: lomi_remote_protocol::LocalIpcVersion::CURRENT,
                    profile_id: store.identity().profile_id,
                    host_id: store.identity().host_id,
                    runtime_id: store.runtime_id(),
                    build_id: "tls-root-fixture".to_owned(),
                },
            )
            .unwrap(),
        );
        drop(store);
        (root, endpoint)
    }

    fn tls_identity() -> lomi_host_auth::Config {
        lomi_host_auth::Config::new(
            lomi_remote_protocol::HostId::from_bytes([1; 16]).unwrap(),
            lomi_remote_protocol::ipc::IpcProfileId::from_bytes([2; 16]).unwrap(),
            "https://identity.example".to_owned(),
            "fixture-client".to_owned().try_into().unwrap(),
        )
        .unwrap()
    }

    fn fixture_certificate() -> (Vec<u8>, Arc<rustls::ServerConfig>) {
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate().unwrap();
        let root = ca.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca, ca_key);

        let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key.into())
        .unwrap();
        (root.der().to_vec(), Arc::new(server))
    }

    struct OneReplyServer {
        port: u16,
        join: Option<thread::JoinHandle<bool>>,
    }

    impl OneReplyServer {
        fn new(config: Arc<rustls::ServerConfig>) -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let join = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return false;
                            }
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => return false,
                    }
                };
                if socket.set_nonblocking(false).is_err() {
                    return false;
                }
                let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = socket.set_write_timeout(Some(Duration::from_secs(2)));
                let connection = match rustls::ServerConnection::new(config) {
                    Ok(connection) => connection,
                    Err(_) => return false,
                };
                let mut stream = rustls::StreamOwned::new(connection, socket);
                let mut request = [0u8; 4096];
                let received = matches!(stream.read(&mut request), Ok(count) if count > 0);
                if received {
                    let body = br#"{"code":"AUTH_REQUIRED","message":"Authentication required.","retryable":false,"effect":"none","details":{}}"#;
                    let response = format!(
                        "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).is_err()
                        || stream.write_all(body).is_err()
                        || stream.flush().is_err()
                    {
                        return false;
                    }
                }
                received
            });
            Self {
                port,
                join: Some(join),
            }
        }

        fn finish(mut self) -> bool {
            self.join.take().unwrap().join().unwrap()
        }
    }

    fn runtime_get(
        setup: &PublicSetup,
        server: OneReplyServer,
    ) -> (
        Result<lomi_remote_protocol::HostRuntimeGetResult, lomi_host_http::Error>,
        bool,
    ) {
        let identity = tls_identity();
        let origin = lomi_host_http::RemoteApiOrigin::new(
            &identity,
            format!("https://localhost:{}", server.port),
        )
        .unwrap();
        let paused = AtomicBool::new(false);
        let io = setup.enter_owned(&paused).unwrap().unwrap();
        let transport = io.data_transport(origin).unwrap();
        let host = lomi_remote_protocol::HostId::from_bytes([1; 16]).unwrap();
        let access = "fixture_access".to_owned().try_into().unwrap();
        let result = transport.runtime_get(host, &access);
        drop(io);
        (result, server.finish())
    }

    #[test]
    fn configured_worker_transport_uses_only_an_explicit_test_root() {
        let (_profile, endpoint) = endpoint_fixture();
        let (root_der, server_config) = fixture_certificate();
        let setup = PublicSetup::with_remote_api_test_root(endpoint.clone(), root_der.clone())
            .expect("valid fixture CA is accepted");
        let (result, request_received) =
            runtime_get(&setup, OneReplyServer::new(server_config.clone()));
        assert!(
            request_received,
            "fixture-root TLS reached the loopback API: {result:?}"
        );
        assert_eq!(
            result,
            Err(lomi_host_http::Error::DataRemote(
                lomi_host_http::DataFailure::AuthRequired
            ))
        );
        let paused = AtomicBool::new(false);
        let io = setup.enter_owned(&paused).unwrap().unwrap();
        assert_eq!(io.cloud_fixture_ingress_roots(), None);
        assert!(!io.joined_cloud_fixture_selected());
        drop(io);

        let (relay_root_der, _) = fixture_certificate();
        let joined_setup = PublicSetup::with_joined_cloud_test_roots(
            endpoint.clone(),
            root_der.clone(),
            relay_root_der.clone(),
        )
        .expect("both explicit JoinedCloud roots are accepted");
        let io = joined_setup.enter_owned(&paused).unwrap().unwrap();
        assert_eq!(
            io.cloud_fixture_ingress_roots(),
            Some((root_der.clone(), relay_root_der))
        );
        assert!(io.joined_cloud_fixture_selected());
        drop(io);
        let (result, request_received) =
            runtime_get(&joined_setup, OneReplyServer::new(server_config.clone()));
        assert!(
            request_received,
            "joined API root reached the real client: {result:?}"
        );
        assert_eq!(
            result,
            Err(lomi_host_http::Error::DataRemote(
                lomi_host_http::DataFailure::AuthRequired
            ))
        );

        let default_setup = PublicSetup::new(endpoint);
        let io = default_setup.enter_owned(&paused).unwrap().unwrap();
        assert_eq!(io.cloud_fixture_ingress_roots(), None);
        assert!(!io.joined_cloud_fixture_selected());
        drop(io);
        let (result, request_received) =
            runtime_get(&default_setup, OneReplyServer::new(server_config));
        assert_ne!(
            result,
            Err(lomi_host_http::Error::DataRemote(
                lomi_host_http::DataFailure::AuthRequired
            )),
            "the default setup must not inherit the fixture CA"
        );
        assert!(
            !request_received,
            "system-root TLS rejection happens before an HTTP request"
        );
    }

    #[test]
    fn test_root_constructor_rejects_empty_oversized_and_malformed_roots() {
        let (_profile, endpoint) = endpoint_fixture();
        assert!(matches!(
            PublicSetup::with_remote_api_test_root(endpoint.clone(), Vec::new()),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(matches!(
            PublicSetup::with_remote_api_test_root(
                endpoint.clone(),
                vec![0; TEST_REMOTE_API_ROOT_LIMIT + 1]
            ),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(matches!(
            PublicSetup::with_remote_api_test_root(endpoint, vec![0x30, 0x01, 0x00]),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
    }

    #[test]
    fn joined_root_constructor_rejects_each_invalid_downstream_root() {
        let (_profile, endpoint) = endpoint_fixture();
        let (remote_root, _) = fixture_certificate();
        let (relay_root, _) = fixture_certificate();
        assert!(matches!(
            PublicSetup::with_joined_cloud_test_roots(
                endpoint.clone(),
                Vec::new(),
                relay_root.clone()
            ),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(matches!(
            PublicSetup::with_joined_cloud_test_roots(
                endpoint.clone(),
                remote_root.clone(),
                vec![0x30, 0x01, 0x00]
            ),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(matches!(
            PublicSetup::with_joined_cloud_test_roots(
                endpoint.clone(),
                remote_root.clone(),
                vec![0; TEST_REMOTE_API_ROOT_LIMIT + 1]
            ),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(
            PublicSetup::with_joined_cloud_test_roots(endpoint, remote_root, relay_root).is_ok()
        );
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, windows))]
mod windows_startup_tests {
    use super::*;
    #[test]
    fn native_startup_preserves_existing_dpapi_selection_without_secret_io() {
        let root = tempfile::Builder::new()
            .prefix("lomi-public-startup-native-")
            .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
            .unwrap();
        let profile = root.path().canonicalize().unwrap().join("profile");
        let lock = OwnerLock::acquire(&profile).unwrap();
        let database = lock.prepare_database().unwrap();
        let mut store = HostStore::open(&database, Limits::default()).unwrap();
        let selection = LocalAuthConfiguration {
            version: 1,
            origin: "https://identity.example".to_owned().try_into().unwrap(),
            remote_api_origin: None,
            relay_endpoint: None,
            client_id: "host-client".to_owned().try_into().unwrap(),
            provider: LocalAuthProvider::WindowsDpapi,
            keychain_path: None,
            protected_file_acknowledgement: None,
        };
        // This is the existing SQLite selection, before public migration; no
        // credential provider is opened and no new secret is synthesized.
        store.configure_auth(&selection).unwrap();
        startup(&mut store, lock.profile()).unwrap();
        assert!(store.public_configuration_ready().unwrap());
        assert_eq!(store.auth_configuration().unwrap(), Some(selection.clone()));
        assert!(super::super::auth::configuration(store.identity(), &selection).is_ok());
        let file = PublicFile::new(lock.profile()).unwrap();
        let first = file.load().unwrap().unwrap();
        assert_eq!(
            first.configuration().authentication.as_ref(),
            Some(&selection)
        );
        assert_eq!(first.configuration().revision, 1);
        let bytes = first.source().to_vec();
        drop(store);
        let mut reopened = HostStore::open(&database, Limits::default()).unwrap();
        startup(&mut reopened, lock.profile()).unwrap();
        assert!(reopened.public_configuration_ready().unwrap());
        assert_eq!(reopened.auth_configuration().unwrap(), Some(selection));
        assert_eq!(file.load().unwrap().unwrap().source(), bytes);
        assert!(!profile.join("host-secrets.dpapi").exists());
        assert!(!profile.join("host-secrets.lock").exists());
    }
}
