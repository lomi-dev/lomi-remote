//! Three durable phases: prepare intent, publish public file, finalize marker.
//! Caller owns OwnerLock and excludes credential IO before short Store closures.
//! Shared Store guards never span public-file or profile IO; startup is exclusive.
use super::*;
use lomi_host_store::{PublicDocument, PublicPreparation};
use lomi_platform::public_config::Configuration;
use platform::public_config::{CommitOutcome, PublicFile, Snapshot};
use std::sync::RwLock;

pub(super) struct PublicSetup {
    endpoint: Arc<OwnerEndpoint>,
    pub request: Mutex<()>,
    pub io: RwLock<()>,
    pub pending: AtomicBool,
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
}
impl PublicSetup {
    pub fn new(endpoint: Arc<OwnerEndpoint>) -> Self {
        Self {
            endpoint,
            request: Mutex::new(()),
            io: RwLock::new(()),
            pending: AtomicBool::new(false),
        }
    }

    fn data_transport(
        &self,
        origin: lomi_host_http::RemoteApiOrigin,
    ) -> Result<lomi_host_http::DataTransport, lomi_host_http::Error> {
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
