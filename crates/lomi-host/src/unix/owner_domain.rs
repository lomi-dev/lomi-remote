//! Private unintegrated foundation; generic callbacks still require an audited
//! no-provider/no-network contract. Announcement is not durable revocation.
use std::sync::{
    Mutex, MutexGuard, TryLockError,
    atomic::{AtomicBool, AtomicU64, Ordering::SeqCst},
};
use std::time::Instant;

fn monotonic_ticks(origin: Instant, deadline: Instant) -> Result<u64, Error> {
    deadline
        .checked_duration_since(origin)
        .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
        .ok_or(Error::Deadline)
}

const MAX_PENDING: u64 = 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Busy,
    Cancelled,
    Deadline,
    Denied,
    Poisoned,
    Exhausted,
    Stale,
    Unfinished,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum StepError<E> {
    Domain(Error),
    Source(E),
}
/// A definite rejected transaction still invalidates older authority scopes,
/// but is not evidence of an uncertain durable state. Callers must classify
/// only audited Store outcomes; failure to read the resulting view is uncertain.
pub(super) enum StoreFailure<E> {
    Expected(E, StoreView),
    Uncertain(E),
    UncertainObserved(E, StoreView),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriterClass {
    Remote,
    Shared,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Intent {
    Mutation,
    FenceRemote,
    VerifyRemote,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Policy {
    Local,
    Remote,
}

/// Construct ONCE at operation admission from its original absolute budget and
/// actual cancellation latch. No phase accepts a replacement budget/latch.
/// Cancellation is sticky once observed, even if the external latch is reset.
#[cfg(any(unix, windows))]
#[derive(Clone)]
pub(super) struct OperationIdentity(std::sync::Arc<()>);
#[must_use]
pub(super) struct Operation<'a> {
    #[cfg(any(unix, windows))]
    admission_identity: std::sync::Arc<()>,
    deadline: Instant,
    cancelled: &'a AtomicBool,
    observed_cancel: std::sync::Arc<AtomicBool>,
    #[cfg(test)]
    expired_for_test: AtomicBool,
}
impl<'a> Operation<'a> {
    #[cfg(any(unix, windows))]
    pub(super) fn retained_identity(&self) -> OperationIdentity {
        OperationIdentity(self.admission_identity.clone())
    }
    #[cfg(any(unix, windows))]
    pub(super) fn is_same_admission(&self, identity: &OperationIdentity) -> bool {
        std::sync::Arc::ptr_eq(&self.admission_identity, &identity.0)
    }
    pub(super) fn new(deadline: Instant, cancelled: &'a AtomicBool) -> Self {
        Self {
            #[cfg(any(unix, windows))]
            admission_identity: std::sync::Arc::new(()),
            deadline,
            cancelled,
            observed_cancel: std::sync::Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            expired_for_test: AtomicBool::new(false),
        }
    }
    #[cfg(any(unix, windows))]
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Admission can only shorten the original budget. Borrowing rules prevent
    /// changing it while a pending writer or snapshot borrows this Operation.
    #[cfg(any(unix, windows))]
    pub(super) fn cap_deadline(&mut self, deadline: Instant) {
        self.deadline = self.deadline.min(deadline);
    }
    /// Actual original cancellation latch; never a fresh copied atomic. Callers
    /// must still use check() for sticky cancellation and the original deadline.
    #[cfg(any(unix, windows))]
    pub(super) fn cancellation_latch(&self) -> &'a AtomicBool {
        self.cancelled
    }
    pub(super) fn sticky_cancellation(&self) -> std::sync::Arc<AtomicBool> {
        self.observed_cancel.clone()
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        if self.cancelled.load(SeqCst) {
            self.observed_cancel.store(true, SeqCst);
        }
        if self.observed_cancel.load(SeqCst) {
            return Err(Error::Cancelled);
        }
        #[cfg(test)]
        if self.expired_for_test.load(SeqCst) {
            return Err(Error::Deadline);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn expire_for_test(&self) {
        self.expired_for_test.store(true, SeqCst);
    }
}

/// Owned values only; call under domain/Store BEFORE acquiring any Core guard.
#[derive(Debug, Clone, Copy)]
pub(super) struct StoreView {
    generation: u64,
    verified: Option<u64>,
    locked: bool,
    pending_revoke: bool,
}
impl StoreView {
    pub(super) fn read(
        store: &lomi_host_store::HostStore,
    ) -> Result<Self, lomi_host_store::StoreError> {
        let state = store.authorization_state()?;
        let verified = store.verified_authorization_generation()?;
        Ok(Self {
            generation: state.generation,
            verified,
            locked: state.locked,
            pending_revoke: state.pending_cloud_revoke,
        })
    }
}
#[derive(Clone, Copy)]
struct Ready {
    generation: u64,
    deny_epoch: u64,
}
struct State {
    revision: u64,
    authority_revision: u64,
    frame: u64,
    generation: u64,
    ready: Option<Ready>,
}
pub(super) struct OwnerDomain {
    #[cfg(any(unix, windows))]
    owner_identity: std::sync::Arc<()>,
    state: Mutex<State>,
    pending: std::sync::Arc<AtomicU64>,
    shared_pending: std::sync::Arc<AtomicU64>,
    issued: std::sync::Arc<AtomicU64>,
    generation: std::sync::Arc<AtomicU64>,
    deny_epoch: std::sync::Arc<AtomicU64>,
    deny_floor: std::sync::Arc<AtomicU64>,
    revoked_through: std::sync::Arc<AtomicU64>,
    failed_remote: std::sync::Arc<AtomicBool>,
}

/// An attenuation-only observation. SharedOwner validates the actual running
/// permit between capture and the first check; this value alone grants no
/// authority. Every writer announcement invalidates it, even if that writer
/// finishes before the filesystem reaches its final publication boundary.
pub(super) struct LocalExternalEffectGate<'a> {
    domain: &'a OwnerDomain,
    issued: u64,
    generation: u64,
    deny_epoch: u64,
}
impl LocalExternalEffectGate<'_> {
    pub(super) fn current(&self) -> bool {
        self.domain.pending.load(SeqCst) == 0
            && self.domain.issued.load(SeqCst) == self.issued
            && self.domain.generation.load(SeqCst) == self.generation
            && self.domain.deny_epoch.load(SeqCst) == self.deny_epoch
            && self.domain.pending.load(SeqCst) == 0
            && self.domain.issued.load(SeqCst) == self.issued
    }
}
impl OwnerDomain {
    pub(super) fn observe_local_external_effect(&self) -> LocalExternalEffectGate<'_> {
        LocalExternalEffectGate {
            domain: self,
            issued: self.issued.load(SeqCst),
            generation: self.generation.load(SeqCst),
            deny_epoch: self.deny_epoch.load(SeqCst),
        }
    }
    /// An observer wake-up hint only. It grants no authority or Store access;
    /// callers still read their workspace through the ordinary owner boundary.
    pub(super) fn projection_hint(&self) -> Option<u64> {
        self.state.try_lock().ok().map(|state| state.revision)
    }

    /// Start closed, with no synthetic revoke. Same-generation bootstrap or
    /// restart needs a NEW verification scope/provider proof, never cached Ready.
    pub(super) fn new(durable_generation: u64) -> Self {
        Self {
            #[cfg(any(unix, windows))]
            owner_identity: std::sync::Arc::new(()),
            state: Mutex::new(State {
                revision: 1,
                authority_revision: 1,
                frame: 0,
                generation: durable_generation,
                ready: None,
            }),
            pending: std::sync::Arc::new(AtomicU64::new(0)),
            shared_pending: std::sync::Arc::new(AtomicU64::new(0)),
            issued: std::sync::Arc::new(AtomicU64::new(0)),
            generation: std::sync::Arc::new(AtomicU64::new(durable_generation)),
            deny_epoch: std::sync::Arc::new(AtomicU64::new(0)),
            deny_floor: std::sync::Arc::new(AtomicU64::new(durable_generation)),
            revoked_through: std::sync::Arc::new(AtomicU64::new(durable_generation)),
            failed_remote: std::sync::Arc::new(AtomicBool::new(false)),
        }
    }
    pub(super) fn fail_remote(&self) {
        self.failed_remote.store(true, SeqCst);
    }
    /// Failure-only attenuation. No Operation is admitted or renewed, and no
    /// normal write/read capability or lock is returned. SharedOwner alone
    /// supplies its privately owned Store for this named cleanup operation.
    pub(super) fn try_block_public_configuration(
        &self,
        store: &Mutex<lomi_host_store::HostStore>,
    ) -> Result<(), Error> {
        self.fail_remote();
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(Error::Busy),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        state.ready = None;
        // Domain remains held while Store is tried. Poisoned guards may only
        // clear volatile readiness; neither poison flag is recovered.
        match store.try_lock() {
            Ok(mut store) => {
                store.public_block();
                Ok(())
            }
            Err(TryLockError::WouldBlock) => Err(Error::Busy),
            Err(TryLockError::Poisoned(poisoned)) => {
                poisoned.into_inner().public_block();
                Err(Error::Poisoned)
            }
        }
    }
    fn increment(&self, value: &AtomicU64, maximum: u64) -> Result<u64, Error> {
        value
            .fetch_update(SeqCst, SeqCst, |old| {
                old.checked_add(1).filter(|new| *new <= maximum)
            })
            .map(|old| old + 1)
            .map_err(|_| {
                self.fail_remote();
                Error::Exhausted
            })
    }
    fn decrement(&self, value: &AtomicU64) {
        if value
            .fetch_update(SeqCst, SeqCst, |old| old.checked_sub(1))
            .is_err()
        {
            self.fail_remote();
        }
    }
    fn generation_denied(&self, generation: u64) -> bool {
        self.deny_epoch.load(SeqCst) != 0
            && (generation < self.deny_floor.load(SeqCst)
                || generation <= self.revoked_through.load(SeqCst))
    }
    /// No mutex acquisition. Each returned token owns exactly its announcement.
    pub(super) fn announce<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        class: WriterClass,
        intent: Intent,
    ) -> Result<PendingWriter<'d, 'o>, Error> {
        operation.check().inspect_err(|_| {
            self.fail_remote();
        })?;
        self.register_writer(operation, class, intent)
    }
    /// The sole Ready worker has no Store/provider effect at admission. An
    /// already cancelled operation must not poison unrelated future attempts.
    pub(super) fn announce_worker_verification<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
    ) -> Result<PendingWriter<'d, 'o>, Error> {
        operation.check()?;
        self.register_writer(operation, WriterClass::Remote, Intent::VerifyRemote)
    }
    fn register_writer<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        class: WriterClass,
        intent: Intent,
    ) -> Result<PendingWriter<'d, 'o>, Error> {
        self.increment(&self.pending, MAX_PENDING)?;
        if class == WriterClass::Shared
            && self.increment(&self.shared_pending, MAX_PENDING).is_err()
        {
            self.decrement(&self.pending);
            return Err(Error::Exhausted);
        }
        let ticket = match self.increment(&self.issued, u64::MAX) {
            Ok(ticket) => ticket,
            Err(error) => {
                if class == WriterClass::Shared {
                    self.decrement(&self.shared_pending);
                }
                self.decrement(&self.pending);
                return Err(error);
            }
        };
        if intent == Intent::FenceRemote {
            self.deny_floor
                .fetch_max(self.generation.load(SeqCst), SeqCst);
            self.revoked_through
                .fetch_max(self.generation.load(SeqCst), SeqCst);
            self.deny_epoch.fetch_max(ticket, SeqCst);
        }
        Ok(PendingWriter {
            domain: self,
            operation,
            class,
            intent,
            ticket,
            active: true,
            committed: false,
            terminal: None,
        })
    }
    fn lock(&self, operation: &Operation<'_>) -> Result<MutexGuard<'_, State>, Error> {
        operation.check()?;
        match self.state.try_lock() {
            Ok(guard) => {
                operation.check()?;
                Ok(guard)
            }
            Err(TryLockError::WouldBlock) => Err(Error::Busy),
            Err(TryLockError::Poisoned(_)) => {
                self.fail_remote();
                Err(Error::Poisoned)
            }
        }
    }
    pub(super) fn try_read<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
    ) -> Result<OwnerGuard<'d, 'o>, Error> {
        let mut state = self.lock(operation)?;
        state.frame = state.frame.checked_add(1).ok_or_else(|| {
            self.fail_remote();
            Error::Exhausted
        })?;
        let frame = state.frame;
        Ok(OwnerGuard {
            domain: self,
            operation,
            state,
            frame,
        })
    }

    pub(super) fn try_started_git_read<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        control: &RemoteGitWriterControl,
    ) -> Result<StartedGitOwnerGuard<'d, 'o>, Error> {
        if !control.matches_operation(operation) {
            return Err(Error::Stale);
        }
        self.try_started_git_local_read(operation, control)
    }

    /// Authenticated local terminal calls have their own request deadline and
    /// cancellation identity. Bind them to the exact Started Git core without
    /// claiming that the local operation is the retained writer operation.
    pub(super) fn try_started_git_local_read<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        control: &RemoteGitWriterControl,
    ) -> Result<StartedGitOwnerGuard<'d, 'o>, Error> {
        let state = self.lock(operation)?;
        control.check_state_current(self, &state)?;
        Ok(StartedGitOwnerGuard {
            domain: self,
            operation,
            state,
            control: control.clone(),
        })
    }
}

#[must_use]
pub(super) struct PendingWriter<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    class: WriterClass,
    intent: Intent,
    ticket: u64,
    active: bool,
    committed: bool,
    terminal: Option<Error>,
}
impl<'d, 'o> PendingWriter<'d, 'o> {
    fn fail(&mut self, error: Error) -> Error {
        self.committed = false;
        if self.terminal.is_none() {
            self.terminal = Some(error);
        }
        self.domain.fail_remote();
        self.terminal.unwrap_or(error)
    }
    fn check(&mut self) -> Result<(), Error> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        self.operation.check().map_err(|error| self.fail(error))
    }
    /// Checks the SAME admitted Operation without acquiring Domain/Store.
    /// Used at owned file boundaries; cancellation remains sticky in check().
    pub(super) fn check_operation(&mut self) -> Result<(), Error> {
        self.check()
    }
    /// Busy is the sole retriable failure, always with this token's SAME context.
    pub(super) fn try_enter(&mut self) -> Result<WriterGuard<'_, 'd, 'o>, Error> {
        self.check()?;
        let domain = self.domain;
        let state = match domain.lock(self.operation) {
            Ok(state) => state,
            Err(Error::Busy) => return Err(Error::Busy),
            Err(error) => return Err(self.fail(error)),
        };
        Ok(WriterGuard {
            writer: self,
            state,
        })
    }
    /// These operations belong only to the sole worker's preaccept verification.
    /// They never clear the global uncertainty fence or mint normal authority.
    pub(super) fn check_worker_verification_operation(&self) -> Result<(), Error> {
        if self.class != WriterClass::Remote
            || self.intent != Intent::VerifyRemote
            || !self.active
            || self.committed
            || self.terminal.is_some()
        {
            return Err(Error::Stale);
        }
        self.operation.check()
    }
    pub(super) fn try_enter_worker_verification(
        &mut self,
    ) -> Result<WriterGuard<'_, 'd, 'o>, Error> {
        self.check_worker_verification_operation()?;
        let state = self.domain.lock(self.operation)?;
        Ok(WriterGuard {
            writer: self,
            state,
        })
    }
    /// Fixed no-effect abort: clear Ready while holding Domain, then release
    /// only this ticket. Busy keeps the original token for cleanup retry.
    /// Cancelled operations may clean up; no new operation is admitted here.
    pub(super) fn try_abandon_worker_verification(&mut self) -> Result<(), Error> {
        if self.class != WriterClass::Remote
            || self.intent != Intent::VerifyRemote
            || !self.active
            || self.committed
            || self.terminal.is_some()
        {
            return Err(Error::Stale);
        }
        let domain = self.domain;
        let mut state = match domain.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(Error::Busy),
            Err(TryLockError::Poisoned(_)) => {
                domain.fail_remote();
                return Err(Error::Poisoned);
            }
        };
        state.ready = None;
        self.release();
        Ok(())
    }
    fn release(&mut self) {
        self.active = false;
        if self.class == WriterClass::Shared {
            self.domain.decrement(&self.domain.shared_pending);
        }
        self.domain.decrement(&self.domain.pending);
    }
    pub(super) fn finish(mut self) -> Result<(), Error> {
        if self.check().is_err() {
            return Err(Error::Unfinished);
        }
        if !self.committed {
            self.fail(Error::Unfinished);
            return Err(Error::Unfinished);
        }
        self.release();
        Ok(())
    }
}
impl Drop for PendingWriter<'_, '_> {
    fn drop(&mut self) {
        if self.active {
            self.fail(Error::Unfinished);
            self.release();
        }
    }
}

pub(super) struct WriterGuard<'w, 'd, 'o> {
    writer: &'w mut PendingWriter<'d, 'o>,
    state: MutexGuard<'d, State>,
}
#[must_use]
pub(super) struct VerificationScope<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    ticket: u64,
    authority_revision: u64,
    generation: u64,
    deny_epoch: u64,
}
impl<'d, 'o> WriterGuard<'_, 'd, 'o> {
    fn begin_phase(&mut self) -> Result<(), Error> {
        self.writer.committed = false;
        self.writer.check()
    }
    /// Concrete authority rejection calls this only while holding Domain then
    /// Store, after its exact Store generation check. No lock is released between
    /// checking and arming. Keep Mutation intent across Busy retries: promoting
    /// the retained token to FenceRemote could revoke a later generation.
    pub(super) fn arm_authority_rejection(&mut self, generation: u64) -> Result<(), Error> {
        self.writer.check()?;
        if self.writer.class != WriterClass::Shared
            || self.writer.intent != Intent::Mutation
            || self.state.generation != generation
        {
            return Err(self.writer.fail(Error::Stale));
        }
        let domain = self.writer.domain;
        domain.deny_floor.fetch_max(generation, SeqCst);
        domain.revoked_through.fetch_max(generation, SeqCst);
        domain.deny_epoch.fetch_max(self.writer.ticket, SeqCst);
        self.state.ready = None;
        Ok(())
    }

    fn advance(&mut self) -> Result<(), Error> {
        let Some(revision) = self.state.revision.checked_add(1) else {
            return Err(self.writer.fail(Error::Exhausted));
        };
        let Some(authority_revision) = self.state.authority_revision.checked_add(1) else {
            return Err(self.writer.fail(Error::Exhausted));
        };
        self.state.revision = revision;
        self.state.authority_revision = authority_revision;
        if self.writer.intent == Intent::FenceRemote {
            // Store fence increments g -> g+1. Revoke the PRE-fence authority;
            // do not ban fresh login at g+1 after its durable revoke ACK.
            self.writer
                .domain
                .revoked_through
                .fetch_max(self.state.generation, SeqCst);
        }
        Ok(())
    }
    fn observe(&mut self, view: StoreView) -> Result<(), Error> {
        if view.generation < self.state.generation {
            return Err(self.writer.fail(Error::Stale));
        }
        self.state.generation = view.generation;
        self.writer.domain.generation.store(view.generation, SeqCst);
        if self.writer.intent == Intent::FenceRemote {
            self.writer
                .domain
                .deny_floor
                .fetch_max(view.generation, SeqCst);
        }
        if self
            .state
            .ready
            .is_some_and(|ready| ready.generation != view.generation)
            || view.locked
            || view.pending_revoke
        {
            self.state.ready = None;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn commit<T, E>(
        &mut self,
        write: impl FnOnce() -> Result<(T, StoreView), E>,
    ) -> Result<T, StepError<E>> {
        self.commit_classified(|| write().map_err(StoreFailure::Uncertain))
    }
    pub(super) fn commit_classified<T, E>(
        &mut self,
        write: impl FnOnce() -> Result<(T, StoreView), StoreFailure<E>>,
    ) -> Result<T, StepError<E>> {
        self.begin_phase().map_err(StepError::Domain)?;
        self.advance().map_err(StepError::Domain)?;
        let (value, view) = match write() {
            Ok(applied) => applied,
            Err(StoreFailure::Expected(error, view)) => {
                self.observe(view).map_err(StepError::Domain)?;
                self.writer.check().map_err(StepError::Domain)?;
                self.writer.committed = true;
                return Err(StepError::Source(error));
            }
            Err(StoreFailure::Uncertain(error)) => {
                self.writer.fail(Error::Denied);
                return Err(StepError::Source(error));
            }
            Err(StoreFailure::UncertainObserved(error, view)) => {
                // Deny before observing even a healthy/unlocked post-view.
                // Observation cannot restore Ready or hide the action error.
                self.writer.fail(Error::Denied);
                let _ = self.observe(view);
                return Err(StepError::Source(error));
            }
        };
        self.observe(view).map_err(StepError::Domain)?;
        self.writer.check().map_err(StepError::Domain)?;
        self.writer.committed = true;
        Ok(value)
    }
    fn sole_latest(&self) -> bool {
        self.writer.domain.pending.load(SeqCst) == 1
            && self.writer.domain.issued.load(SeqCst) == self.writer.ticket
    }
    /// Fixed read-only preparation for the actual worker. Expected competing
    /// writer/generation invalidation rejects only this attempt, not the owner.
    pub(super) fn prepare_worker_verification(
        &mut self,
        generation: u64,
        store: &lomi_host_store::HostStore,
    ) -> Result<VerificationScope<'d, 'o>, StepError<lomi_host_store::StoreError>> {
        self.writer
            .check_worker_verification_operation()
            .map_err(StepError::Domain)?;
        if self.writer.domain.failed_remote.load(SeqCst) || !self.sole_latest() {
            return Err(StepError::Domain(Error::Stale));
        }
        let view = StoreView::read(store).map_err(|error| {
            self.writer.fail(Error::Denied);
            StepError::Source(error)
        })?;
        self.writer
            .check_worker_verification_operation()
            .map_err(StepError::Domain)?;
        if view.generation != generation
            || generation < self.state.generation
            || view.pending_revoke
            || self.writer.domain.generation_denied(generation)
            || !self.sole_latest()
        {
            return Err(StepError::Domain(Error::Stale));
        }
        Ok(VerificationScope {
            domain: self.writer.domain,
            operation: self.writer.operation,
            ticket: self.writer.ticket,
            authority_revision: self.state.authority_revision,
            generation,
            deny_epoch: self.writer.domain.deny_epoch.load(SeqCst),
        })
    }
    fn check_worker_verification_scope(
        &self,
        scope: &VerificationScope<'d, 'o>,
    ) -> Result<(), Error> {
        self.writer.check_worker_verification_operation()?;
        let domain = self.writer.domain;
        if domain.failed_remote.load(SeqCst)
            || !std::ptr::eq(scope.domain, domain)
            || !std::ptr::eq(scope.operation, self.writer.operation)
            || scope.ticket != self.writer.ticket
            || scope.authority_revision != self.state.authority_revision
            || scope.generation != self.state.generation
            || scope.deny_epoch != domain.deny_epoch.load(SeqCst)
            || domain.generation_denied(scope.generation)
            || !self.sole_latest()
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Clock writes are not authority effects. A successful clock checkpoint
    /// followed by cancellation/staleness may be abandoned before provider
    /// acceptance. Every concrete Store/read failure still permanently fences.
    pub(super) fn checkpoint_worker_verification_clock(
        &mut self,
        scope: &VerificationScope<'d, 'o>,
        store: &mut lomi_host_store::HostStore,
        now: u64,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.check_worker_verification_scope(scope)
            .map_err(StepError::Domain)?;
        self.state.revision = self
            .state
            .revision
            .checked_add(1)
            .ok_or_else(|| StepError::Domain(self.writer.fail(Error::Exhausted)))?;
        self.state.ready = None;
        let outcome = store.observe_authorization_clock(now);
        let outcome = self.record_verification_clock_outcome(outcome);
        let post = StoreView::read(store);
        let observed = match post {
            Ok(view) => self.observe(view).map_err(StepError::Domain),
            Err(error) => {
                self.writer.fail(Error::Denied);
                Err(StepError::Source(error))
            }
        };
        let checked = self
            .check_worker_verification_scope(scope)
            .map_err(StepError::Domain);
        match outcome {
            Err(error) => Err(StepError::Source(error)),
            Ok(floor) => {
                observed?;
                checked?;
                Ok(floor)
            }
        }
    }
    #[cfg(test)]
    pub(super) fn prepare_verification<E>(
        &mut self,
        generation: u64,
        read: impl FnOnce() -> Result<StoreView, E>,
    ) -> Result<VerificationScope<'d, 'o>, StepError<E>> {
        self.begin_phase().map_err(StepError::Domain)?;
        if self.writer.class != WriterClass::Remote
            || self.writer.intent != Intent::VerifyRemote
            || self.writer.domain.failed_remote.load(SeqCst)
            || !self.sole_latest()
        {
            return Err(StepError::Domain(self.writer.fail(Error::Denied)));
        }
        let view = read().map_err(|error| {
            self.writer.fail(Error::Denied);
            StepError::Source(error)
        })?;
        self.writer.check().map_err(StepError::Domain)?;
        if view.generation != generation
            || generation < self.state.generation
            || view.pending_revoke
            || self.writer.domain.generation_denied(generation)
        {
            return Err(StepError::Domain(self.writer.fail(Error::Stale)));
        }
        Ok(VerificationScope {
            domain: self.writer.domain,
            operation: self.writer.operation,
            ticket: self.writer.ticket,
            authority_revision: self.state.authority_revision,
            generation,
            deny_epoch: self.writer.domain.deny_epoch.load(SeqCst),
        })
    }
    /// Integrating caller must bind the ACTUAL provider response to this scope.
    /// This callback is only a short fresh Store commit, never provider I/O.
    /// Validate the borrowed ORIGINAL provider scope; never refresh its values.
    /// Separate from commit_verified so every existing generic path is byteexact.
    fn check_verification_clock_scope(
        &mut self,
        scope: &VerificationScope<'d, 'o>,
    ) -> Result<(), Error> {
        self.writer.check()?;
        let domain = self.writer.domain;
        if self.writer.class != WriterClass::Remote
            || self.writer.intent != Intent::VerifyRemote
            || domain.failed_remote.load(SeqCst)
            || !std::ptr::eq(scope.domain, domain)
            || !std::ptr::eq(scope.operation, self.writer.operation)
            || scope.ticket != self.writer.ticket
            || scope.authority_revision != self.state.authority_revision
            || scope.generation != self.state.generation
            || scope.deny_epoch != domain.deny_epoch.load(SeqCst)
            || domain.generation_denied(scope.generation)
            || !self.sole_latest()
        {
            return Err(self.writer.fail(Error::Stale));
        }
        Ok(())
    }
    /// Record uncertain failure BEFORE the post-Store read. SQLite Busy here is
    /// terminal: the actual clock method already sealed Store authorization.
    /// Owned results only; this helper cannot execute IO or create a scope.
    fn record_verification_clock_outcome(
        &mut self,
        outcome: Result<u64, lomi_host_store::StoreError>,
    ) -> Result<u64, lomi_host_store::StoreError> {
        if outcome.is_err() {
            self.writer.fail(Error::Denied);
        }
        outcome
    }
    fn finish_verification_clock(
        &mut self,
        scope: &VerificationScope<'d, 'o>,
        outcome: Result<u64, lomi_host_store::StoreError>,
        post: Result<StoreView, lomi_host_store::StoreError>,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        // Always attenuate with a readable sealed poststate, even on failure.
        // A secondary read/observe/check failure must not hide the clock error.
        let observed = match post {
            Ok(view) => self.observe(view).map_err(StepError::Domain),
            Err(error) => {
                self.writer.fail(Error::Denied);
                Err(StepError::Source(error))
            }
        };
        let checked = self.check_verification_clock_scope(scope);
        match outcome {
            Err(error) => Err(StepError::Source(error)),
            Ok(floor) => {
                observed?;
                checked.map_err(StepError::Domain)?;
                Ok(floor)
            }
        }
    }
    /// Clock-only checkpoint while the caller holds Domain THEN Store.
    /// No provider/HTTP callback or lock may cross the external IO boundary.
    /// Mutex Busy before entry belongs to future SharedOwner and retains this
    /// same turn. Once called, Store errors terminate it; never replay response.
    /// Success leaves this writer uncommitted and cannot authorize finish/Ready.
    pub(super) fn checkpoint_verification_clock(
        &mut self,
        scope: &VerificationScope<'d, 'o>,
        store: &mut lomi_host_store::HostStore,
        projected_time: u64,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.begin_phase().map_err(StepError::Domain)?;
        self.check_verification_clock_scope(scope)
            .map_err(StepError::Domain)?;
        let revision = self
            .state
            .revision
            .checked_add(1)
            .ok_or_else(|| StepError::Domain(self.writer.fail(Error::Exhausted)))?;
        self.state.revision = revision;
        self.state.ready = None;
        // Fixed concrete method: no authority-preserving arbitrary callback.
        let outcome = store.observe_authorization_clock(projected_time);
        let outcome = self.record_verification_clock_outcome(outcome);
        // Exactly one post-view read for BOTH concrete method outcomes.
        let post = StoreView::read(store);
        self.finish_verification_clock(scope, outcome, post)
    }

    pub(super) fn commit_verified<T, E>(
        &mut self,
        scope: VerificationScope<'d, 'o>,
        commit: impl FnOnce() -> Result<(T, StoreView), E>,
    ) -> Result<T, StepError<E>> {
        self.begin_phase().map_err(StepError::Domain)?;
        let domain = self.writer.domain;
        if self.writer.intent != Intent::VerifyRemote
            || domain.failed_remote.load(SeqCst)
            || !std::ptr::eq(scope.domain, domain)
            || !std::ptr::eq(scope.operation, self.writer.operation)
            || scope.ticket != self.writer.ticket
            || scope.authority_revision != self.state.authority_revision
            || scope.deny_epoch != domain.deny_epoch.load(SeqCst)
            || domain.generation_denied(scope.generation)
            || !self.sole_latest()
        {
            return Err(StepError::Domain(self.writer.fail(Error::Stale)));
        }
        self.state.ready = None;
        self.advance().map_err(StepError::Domain)?;
        let (value, view) = commit().map_err(|error| {
            self.writer.fail(Error::Denied);
            StepError::Source(error)
        })?;
        self.observe(view).map_err(StepError::Domain)?;
        self.writer.check().map_err(StepError::Domain)?;
        if view.generation != scope.generation
            || view.verified != Some(scope.generation)
            || view.locked
            || view.pending_revoke
            || !self.sole_latest()
            || scope.deny_epoch != domain.deny_epoch.load(SeqCst)
            || domain.failed_remote.load(SeqCst)
        {
            return Err(StepError::Domain(self.writer.fail(Error::Denied)));
        }
        self.state.ready = Some(Ready {
            generation: scope.generation,
            deny_epoch: scope.deny_epoch,
        });
        self.writer.committed = true;
        Ok(value)
    }
}
impl Drop for WriterGuard<'_, '_, '_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.writer.fail(Error::Poisoned);
        }
    }
}

// Test-only deterministic scheduling seam at the old check-to-finish gap.
#[cfg(all(test, any(unix, windows)))]
std::thread_local! {
    pub(super) static CLOUD_NO_EFFECT_FINALIZE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}
#[cfg(all(test, any(unix, windows)))]
pub(super) fn cloud_no_effect_state_for_test(
    domain: &OwnerDomain,
) -> (u64, Option<(u64, u64)>, bool) {
    let state = domain.state.lock().unwrap();
    (
        domain.pending.load(SeqCst),
        state
            .ready
            .map(|ready| (ready.generation, ready.deny_epoch)),
        domain.failed_remote.load(SeqCst),
    )
}
/// Retained pre-TLS read admission. Dropping this scope has NO authority effect.
/// `issued` rejects an intervening announcement even if it never commits.
#[cfg(any(unix, windows))]
pub(super) struct CloudReadScope<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    authority_revision: u64,
    generation: u64,
    deny_epoch: u64,
    issued: u64,
}
#[cfg(any(unix, windows))]
impl OwnerDomain {
    fn check_cloud_read(&self, state: &State, scope: &CloudReadScope<'_, '_>) -> Result<(), Error> {
        scope.operation.check()?;
        if !std::ptr::eq(scope.domain, self)
            || self.failed_remote.load(SeqCst)
            || self.pending.load(SeqCst) != 0
            || self.issued.load(SeqCst) != scope.issued
            || state.authority_revision != scope.authority_revision
            || state.generation != scope.generation
            || self.deny_epoch.load(SeqCst) != scope.deny_epoch
            || self.generation_denied(scope.generation)
            || !state.ready.is_some_and(|ready| {
                ready.generation == scope.generation && ready.deny_epoch == scope.deny_epoch
            })
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn cloud_read_view(
        &self,
        state: &State,
        scope: &CloudReadScope<'_, '_>,
        view: StoreView,
    ) -> Result<(), Error> {
        self.check_cloud_read(state, scope)?;
        if view.generation != scope.generation
            || view.verified != Some(scope.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub(super) fn cloud_uncertain(&self) {
        self.fail_remote();
    }
    /// Fixed synchronous handoff: actual privately owned Store mutex only. No
    /// writer or guard crosses a network/provider stage or escapes this method.
    pub(super) fn try_commit_cloud_get<'d, 'o>(
        &'d self,
        scope: &CloudReadScope<'d, 'o>,
        store: &Mutex<lomi_host_store::HostStore>,
        plan: super::shared_owner::CloudGetPlan<'_>,
    ) -> Result<CloudGetSettlement, StepError<super::shared_owner::CloudGetError>> {
        let state = self.lock(scope.operation).map_err(StepError::Domain)?;
        self.check_cloud_read(&state, scope)
            .map_err(StepError::Domain)?;
        let mut store = match store.try_lock() {
            Ok(store) => store,
            Err(TryLockError::WouldBlock) => return Err(StepError::Domain(Error::Busy)),
            Err(TryLockError::Poisoned(_)) => {
                self.fail_remote();
                return Err(StepError::Domain(Error::Poisoned));
            }
        };
        let view = StoreView::read(&store).map_err(|error| {
            self.fail_remote();
            StepError::Source(super::shared_owner::CloudGetError::UncertainStore(error))
        })?;
        self.cloud_read_view(&state, scope, view)
            .map_err(StepError::Domain)?;
        plan.revalidate(&store).map_err(|error| {
            if error.is_uncertain() {
                self.fail_remote();
            }
            StepError::Source(error)
        })?;
        plan.check_current(
            store
                .authorization_state()
                .map_err(|error| {
                    self.fail_remote();
                    StepError::Source(super::shared_owner::CloudGetError::UncertainStore(error))
                })?
                .clock_floor,
        )
        .map_err(StepError::Source)?;
        // This is the only announcement in the GET path. It deliberately does
        // not call generic announce: an original cancellation before effects
        // must release its own ticket without permanently failing remote.
        scope.operation.check().map_err(StepError::Domain)?;
        self.increment(&self.pending, MAX_PENDING)
            .map_err(StepError::Domain)?;
        let ticket = match self.increment(&self.issued, u64::MAX) {
            Ok(ticket) => ticket,
            Err(error) => {
                self.decrement(&self.pending);
                return Err(StepError::Domain(error));
            }
        };
        let mut writer = PendingWriter {
            domain: self,
            operation: scope.operation,
            class: WriterClass::Remote,
            intent: Intent::Mutation,
            ticket,
            active: true,
            committed: false,
            terminal: None,
        };
        let mutation = CloudMutationScope {
            domain: scope.domain,
            operation: scope.operation,
            ticket,
            authority_revision: scope.authority_revision,
            generation: scope.generation,
            deny_epoch: scope.deny_epoch,
        };
        #[cfg(test)]
        if plan.handoff_race_for_test() {
            // Mechanical competing-announcement seam. The independent ticket
            // is explicitly completed without effects only inside this test.
            let mut racer = self
                .announce(scope.operation, WriterClass::Remote, Intent::Mutation)
                .unwrap();
            racer.committed = true;
            racer.finish().unwrap();
        }
        let mut guard = WriterGuard {
            writer: &mut writer,
            state,
        };
        let get_started = plan.request_started();
        let mut effect_started = false;
        let result =
            guard.commit_cloud_reconciliation(mutation, &mut store, plan, &mut effect_started);
        // The successful reconciliation checked the exact single advance while
        // retaining this guard. Carry its settled revision into Claim; the
        // pre-advance read scope is no longer the current authority revision.
        let settled_authority_revision = guard.state.authority_revision;
        drop(guard);
        // No fallible Store work or reacquisition follows the final freshness
        // check. Pre-effect race/cancel rejection releases ONLY this ticket.
        let original_boundary = writer.operation.check();
        if !effect_started {
            #[cfg(test)]
            match CLOUD_NO_EFFECT_FINALIZE.with(|fault| fault.replace(0)) {
                1 => writer.operation.cancelled.store(true, SeqCst),
                2 => writer.operation.expire_for_test(),
                _ => (),
            }
            // The last successful original check linearizes this nonminting
            // decision. Cancellation arriving afterward is checked by the
            // next worker stage before any request/effect, never by generic
            // writer.finish here. All no-effect outcomes release ONLY this
            // ticket; an already-latched uncertainty is never cleared.
            writer.release();
            return match result {
                Err(error) => Err(error),
                Ok(decision) => {
                    original_boundary.map_err(StepError::Domain)?;
                    let claim =
                        if matches!(&decision, super::shared_owner::CloudGetDecision::Claim(_)) {
                            Some(ClaimContinuation {
                                domain_identity: self.owner_identity.clone(),
                                operation_identity: scope.operation.retained_identity(),
                                authority_revision: settled_authority_revision,
                                generation: scope.generation,
                                deny_epoch: scope.deny_epoch,
                                settled_get_ticket: writer.ticket,
                                get_started,
                            })
                        } else {
                            None
                        };
                    Ok(CloudGetSettlement { decision, claim })
                }
            };
        }
        let finished = writer.finish().map_err(StepError::Domain);
        match result {
            Err(error) => Err(error),
            Ok(decision) => {
                finished?;
                Ok(CloudGetSettlement {
                    decision,
                    claim: None,
                })
            }
        }
    }
}
#[cfg(any(unix, windows))]
impl<'d, 'o> OwnerGuard<'d, 'o> {
    pub(super) fn prepare_cloud_read(
        &self,
        store: &lomi_host_store::HostStore,
    ) -> Result<CloudReadScope<'d, 'o>, StepError<lomi_host_store::StoreError>> {
        let scope = CloudReadScope {
            domain: self.domain,
            operation: self.operation,
            authority_revision: self.state.authority_revision,
            generation: self.state.generation,
            deny_epoch: self.domain.deny_epoch.load(SeqCst),
            issued: self.domain.issued.load(SeqCst),
        };
        let view = StoreView::read(store).map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        self.domain
            .cloud_read_view(&self.state, &scope, view)
            .map_err(StepError::Domain)?;
        Ok(scope)
    }
    /// Fixed nonminting final check, after provider preparation, under the
    /// original Domain then Store locks. No callback, writer or clock write.
    pub(super) fn check_cloud_read_send(
        &self,
        scope: &CloudReadScope<'d, 'o>,
        store: &lomi_host_store::HostStore,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        if !std::ptr::eq(self.operation, scope.operation) {
            return Err(StepError::Domain(Error::Stale));
        }
        self.domain
            .check_cloud_read(&self.state, scope)
            .map_err(StepError::Domain)?;
        let view = StoreView::read(store).map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        let floor = store
            .authorization_state()
            .map_err(|error| {
                self.domain.fail_remote();
                StepError::Source(error)
            })?
            .clock_floor;
        self.domain
            .cloud_read_view(&self.state, scope, view)
            .map_err(StepError::Domain)?;
        Ok(floor)
    }
    pub(super) fn checkpoint_cloud_read_clock(
        &mut self,
        scope: &CloudReadScope<'d, 'o>,
        store: &mut lomi_host_store::HostStore,
        now: u64,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        if !std::ptr::eq(scope.operation, self.operation) {
            return Err(StepError::Domain(Error::Stale));
        }
        self.domain
            .check_cloud_read(&self.state, scope)
            .map_err(StepError::Domain)?;
        let before = StoreView::read(store).map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        self.domain
            .cloud_read_view(&self.state, scope, before)
            .map_err(StepError::Domain)?;
        self.state.revision = self.state.revision.checked_add(1).ok_or_else(|| {
            self.domain.fail_remote();
            StepError::Domain(Error::Exhausted)
        })?;
        let outcome = store.observe_authorization_clock(now);
        if outcome.is_err() {
            self.domain.fail_remote();
        }
        let post = StoreView::read(store); // Exactly once after either actual outcome.
        let checked = match post {
            Err(error) => {
                self.domain.fail_remote();
                Err(StepError::Source(error))
            }
            Ok(view) => {
                // Observe even a sealed/error poststate, after attenuation. No
                // observation can mint Ready or clear the remote failure latch.
                if view.generation < self.state.generation {
                    self.domain.fail_remote();
                }
                self.state.generation = view.generation;
                self.domain.generation.store(view.generation, SeqCst);
                if view.locked
                    || view.pending_revoke
                    || self
                        .state
                        .ready
                        .is_some_and(|ready| ready.generation != view.generation)
                {
                    self.state.ready = None;
                }
                self.domain
                    .cloud_read_view(&self.state, scope, view)
                    .map_err(StepError::Domain)
            }
        };
        match outcome {
            Err(error) => Err(StepError::Source(error)),
            Ok(floor) => {
                checked?;
                Ok(floor)
            }
        }
    }
}
// BEGIN INACTIVE WRITER-BOUND CLOUD GET AUTHORITY
/// Mutation admission bound to the ORIGINAL actual Ready and admitted writer.
/// Distinct from VerificationScope: cannot verify, mint Ready, or renew values.
#[cfg(any(unix, windows))]
pub(super) struct CloudMutationScope<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    ticket: u64,
    authority_revision: u64,
    generation: u64,
    deny_epoch: u64,
}
#[cfg(any(unix, windows))]
impl<'d, 'o> WriterGuard<'_, 'd, 'o> {
    fn check_cloud_scope(
        &mut self,
        scope: &CloudMutationScope<'d, 'o>,
        advanced: bool,
    ) -> Result<(), Error> {
        self.writer.check()?;
        let domain = self.writer.domain;
        let expected_revision = scope
            .authority_revision
            .checked_add(if advanced { 1 } else { 0 })
            .ok_or_else(|| self.writer.fail(Error::Exhausted))?;
        if self.writer.class != WriterClass::Remote
            || self.writer.intent != Intent::Mutation
            || !std::ptr::eq(scope.domain, domain)
            || !std::ptr::eq(scope.operation, self.writer.operation)
            || scope.ticket != self.writer.ticket
            || expected_revision != self.state.authority_revision
            || scope.generation != self.state.generation
            || scope.deny_epoch != domain.deny_epoch.load(SeqCst)
            || domain.failed_remote.load(SeqCst)
            || domain.generation_denied(scope.generation)
            || !self.sole_latest()
            || !self.state.ready.is_some_and(|ready| {
                ready.generation == scope.generation && ready.deny_epoch == scope.deny_epoch
            })
        {
            return Err(self.writer.fail(Error::Stale));
        }
        Ok(())
    }
    fn check_cloud_view(
        &mut self,
        scope: &CloudMutationScope<'d, 'o>,
        advanced: bool,
        view: StoreView,
    ) -> Result<(), Error> {
        self.check_cloud_scope(scope, advanced)?;
        if view.generation != scope.generation
            || view.verified != Some(scope.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(self.writer.fail(Error::Stale));
        }
        Ok(())
    }
    /// Sole/latest own Mutation admission; ordinary remote snapshots still reject
    /// ANY pending writer. Store reads/actual Ready are fixed, not caller proof.
    #[cfg(test)]
    pub(super) fn prepare_cloud_mutation_scope(
        &mut self,
        store: &lomi_host_store::HostStore,
    ) -> Result<CloudMutationScope<'d, 'o>, StepError<lomi_host_store::StoreError>> {
        self.begin_phase().map_err(StepError::Domain)?;
        let view = StoreView::read(store).map_err(|error| {
            self.writer.fail(Error::Denied);
            StepError::Source(error)
        })?;
        let scope = CloudMutationScope {
            domain: self.writer.domain,
            operation: self.writer.operation,
            ticket: self.writer.ticket,
            authority_revision: self.state.authority_revision,
            generation: self.state.generation,
            deny_epoch: self.writer.domain.deny_epoch.load(SeqCst),
        };
        self.check_cloud_view(&scope, false, view)
            .map_err(StepError::Domain)?;
        Ok(scope)
    }
    #[cfg(test)]
    pub(super) fn validate_cloud_mutation(
        &mut self,
        scope: &CloudMutationScope<'d, 'o>,
        store: &lomi_host_store::HostStore,
    ) -> Result<(), StepError<lomi_host_store::StoreError>> {
        self.check_cloud_scope(scope, false)
            .map_err(StepError::Domain)?;
        let view = StoreView::read(store).map_err(|error| {
            self.writer.fail(Error::Denied);
            StepError::Source(error)
        })?;
        self.check_cloud_view(scope, false, view)
            .map_err(StepError::Domain)
    }
    /// Fixed nonminting clock for a Mutation, not VerifyRemote's checkpoint.
    /// No callback, replacement scope, authority advance or normal gate change.
    #[cfg(test)]
    pub(super) fn checkpoint_cloud_clock(
        &mut self,
        scope: &CloudMutationScope<'d, 'o>,
        store: &mut lomi_host_store::HostStore,
        now: u64,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.begin_phase().map_err(StepError::Domain)?;
        self.validate_cloud_mutation(scope, store)?;
        self.state.revision = self
            .state
            .revision
            .checked_add(1)
            .ok_or_else(|| StepError::Domain(self.writer.fail(Error::Exhausted)))?;
        let outcome = store.observe_authorization_clock(now);
        if outcome.is_err() {
            self.writer.fail(Error::Denied);
        }
        // One post-view after EITHER actual method outcome, failure denied first.
        let post = StoreView::read(store);
        let observed = match post {
            Ok(view) => {
                let checked = self.check_cloud_view(scope, false, view);
                let observed = self.observe(view);
                checked.and(observed).map_err(StepError::Domain)
            }
            Err(error) => {
                self.writer.fail(Error::Denied);
                Err(StepError::Source(error))
            }
        };
        match outcome {
            Err(error) => Err(StepError::Source(error)),
            Ok(floor) => {
                observed?;
                Ok(floor)
            }
        }
    }
    /// Owned fixed-action results only; not a callback or evidence constructor.
    /// Preserve the action error over read/observe/cancel/expiry/cleanup errors.
    #[expect(
        clippy::too_many_arguments,
        reason = "keep the original scope, exact action, Store result and post-view explicit"
    )]
    fn observe_cloud_get_action<T>(
        &mut self,
        scope: &CloudMutationScope<'d, 'o>,
        plan: &super::shared_owner::CloudGetPlan<'_>,
        floor: u64,
        kind: super::shared_owner::CloudGetStoreAction,
        store: &lomi_host_store::HostStore,
        outcome: Result<T, lomi_host_store::StoreError>,
        post: Result<StoreView, lomi_host_store::StoreError>,
    ) -> Result<T, StepError<super::shared_owner::CloudGetError>> {
        let primary = outcome.as_ref().err().copied();
        let expected = primary.is_some_and(|error| kind.expected(error));
        let mut secondary = self
            .check_cloud_scope(scope, true)
            .map_err(StepError::Domain);
        if let Err(error) = plan.check_fresh(floor) {
            store.seal_authorization();
            self.writer.fail(Error::Denied);
            if secondary.is_ok() {
                secondary = Err(StepError::Source(error));
            }
        }
        if primary.is_some() && !expected {
            self.writer.fail(Error::Denied);
        }
        let view = match post {
            Ok(view) => view,
            Err(error) => {
                self.writer.fail(Error::Denied);
                return Err(StepError::Source(
                    super::shared_owner::CloudGetError::UncertainStore(primary.unwrap_or(error)),
                ));
            }
        };
        // Any secondary invalidity attenuates BEFORE observing the readable view.
        let checked = self
            .check_cloud_view(scope, true, view)
            .map_err(StepError::Domain);
        if secondary.is_ok() {
            secondary = checked;
        }
        let observed = self.observe(view).map_err(StepError::Domain);
        if secondary.is_ok() {
            secondary = observed;
        }
        match outcome {
            Err(error) => {
                if expected && secondary.is_ok() {
                    self.writer.committed = true;
                }
                Err(StepError::Source(if expected {
                    super::shared_owner::CloudGetError::Store(error)
                } else {
                    super::shared_owner::CloudGetError::UncertainStore(error)
                }))
            }
            Ok(value) => {
                secondary?;
                Ok(value)
            }
        }
    }
    fn check_cloud_pre_effect(&self, scope: &CloudMutationScope<'d, 'o>) -> Result<(), Error> {
        self.check_cloud_pre_effect_revision(scope, scope.authority_revision)
    }
    fn check_cloud_pre_effect_advanced(
        &self,
        scope: &CloudMutationScope<'d, 'o>,
    ) -> Result<(), Error> {
        self.check_cloud_pre_effect_revision(
            scope,
            scope
                .authority_revision
                .checked_add(1)
                .ok_or(Error::Exhausted)?,
        )
    }
    fn check_cloud_pre_effect_revision(
        &self,
        scope: &CloudMutationScope<'d, 'o>,
        revision: u64,
    ) -> Result<(), Error> {
        self.writer.operation.check()?;
        let domain = self.writer.domain;
        if !std::ptr::eq(scope.domain, domain)
            || !std::ptr::eq(scope.operation, self.writer.operation)
            || scope.ticket != self.writer.ticket
            || !self.sole_latest()
            || self.state.authority_revision != revision
            || self.state.generation != scope.generation
            || domain.failed_remote.load(SeqCst)
            || domain.deny_epoch.load(SeqCst) != scope.deny_epoch
            || domain.generation_denied(scope.generation)
            || !self.state.ready.is_some_and(|ready| {
                ready.generation == scope.generation && ready.deny_epoch == scope.deny_epoch
            })
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Root-authorized fixed cloud-only committer. Consumes the ORIGINAL scope,
    /// revalidates the original pre-TLS tuple atomically under Domain -> Store,
    /// and advances normal authority ONCE. Only named Store calls can run here.
    fn commit_cloud_reconciliation(
        &mut self,
        scope: CloudMutationScope<'d, 'o>,
        store: &mut lomi_host_store::HostStore,
        plan: super::shared_owner::CloudGetPlan<'_>,
        effect_started: &mut bool,
    ) -> Result<super::shared_owner::CloudGetDecision, StepError<super::shared_owner::CloudGetError>>
    {
        // Read admission, tuple, clock and freshness were checked before the
        // local ticket was created. Recheck cancellation/announcement races
        // without generic fail() until the first named authoritative effect.
        self.check_cloud_pre_effect(&scope)
            .map_err(StepError::Domain)?;
        let floor = store
            .authorization_state()
            .map_err(|error| {
                self.writer.domain.fail_remote();
                StepError::Source(super::shared_owner::CloudGetError::UncertainStore(error))
            })?
            .clock_floor;
        // No field of scope is changed: advanced=true admits exactly THIS one
        // known normal advance while both locks remain continuously held.
        self.advance().map_err(StepError::Domain)?;
        let snapshot = plan.snapshot();
        let own = snapshot.runtime.as_ref().filter(|runtime| {
            runtime.runtime_id == plan.scope().owner_runtime_id && snapshot.lease_ms.0 > 0
        });
        let mut current = plan.previous().cloned();
        let mut blocked = plan.provider_invalid();
        if !blocked {
            if let Some(old) = plan.previous() {
                if old.scope != *plan.scope() || own != Some(&old.server_runtime) {
                    self.check_cloud_pre_effect_advanced(&scope)
                        .map_err(StepError::Domain)?;
                    *effect_started = true;
                    let outcome = store.invalidate_cloud_runtime(plan.scope(), old, plan.pending());
                    if outcome.as_ref().err().is_some_and(|error| {
                        !super::shared_owner::CloudGetStoreAction::Invalidate.expected(*error)
                    }) {
                        self.writer.fail(Error::Denied);
                    }
                    let post = StoreView::read(store);
                    self.observe_cloud_get_action(
                        &scope,
                        &plan,
                        floor,
                        super::shared_owner::CloudGetStoreAction::Invalidate,
                        store,
                        outcome,
                        post,
                    )?;
                    current = None;
                } else if let Some(intent) = plan.pending() {
                    if snapshot.publication_seq == intent.params.publication_seq {
                        self.check_cloud_pre_effect_advanced(&scope)
                            .map_err(StepError::Domain)?;
                        *effect_started = true;
                        let outcome =
                            store.acknowledge_host_publication_from_runtime(intent, snapshot);
                        if outcome.as_ref().err().is_some_and(|error| {
                            !super::shared_owner::CloudGetStoreAction::RecoveredAck.expected(*error)
                        }) {
                            self.writer.fail(Error::Denied);
                        }
                        let post = StoreView::read(store);
                        current = Some(self.observe_cloud_get_action(
                            &scope,
                            &plan,
                            floor,
                            super::shared_owner::CloudGetStoreAction::RecoveredAck,
                            store,
                            outcome,
                            post,
                        )?);
                    } else if snapshot.publication_seq != intent.params.expected_publication_seq {
                        blocked = true;
                    }
                } else if snapshot.publication_seq != old.acknowledged_publication_seq {
                    blocked = true;
                }
            }
            if !blocked
                && let Some(binding) = own
                && current.is_none()
            {
                if snapshot.publication_seq.0 != 0 {
                    blocked = true;
                } else {
                    self.check_cloud_pre_effect_advanced(&scope)
                        .map_err(StepError::Domain)?;
                    *effect_started = true;
                    let outcome = store.compare_and_set_cloud_runtime(
                        plan.scope(),
                        None,
                        binding.clone(),
                        snapshot.publication_seq,
                    );
                    if outcome.as_ref().err().is_some_and(|error| {
                        !super::shared_owner::CloudGetStoreAction::Install.expected(*error)
                    }) {
                        self.writer.fail(Error::Denied);
                    }
                    let post = StoreView::read(store);
                    current = Some(self.observe_cloud_get_action(
                        &scope,
                        &plan,
                        floor,
                        super::shared_owner::CloudGetStoreAction::Install,
                        store,
                        outcome,
                        post,
                    )?);
                }
            }
        }
        // After ALL blocking Store work, before writer release. No provider IO
        // or Store reacquisition follows this fresh check in the success path.
        if *effect_started {
            self.check_cloud_scope(&scope, true)
                .map_err(StepError::Domain)?;
        } else {
            self.check_cloud_pre_effect_advanced(&scope)
                .map_err(StepError::Domain)?;
        }
        plan.check_fresh(floor).map_err(|error| {
            if *effect_started {
                store.seal_authorization();
                self.writer.fail(Error::Denied);
            }
            StepError::Source(error)
        })?;
        self.writer.committed = true;
        Ok(if blocked {
            super::shared_owner::CloudGetDecision::Blocked
        } else if own.is_some() {
            super::shared_owner::CloudGetDecision::Online {
                binding: current,
                lease_until: plan
                    .request_started()
                    .checked_add(std::time::Duration::from_millis(snapshot.lease_ms.0)),
            }
        } else {
            super::shared_owner::CloudGetDecision::Claim(snapshot.runtime_generation)
        })
    }
}
// END INACTIVE WRITER-BOUND CLOUD GET AUTHORITY

// Mechanical owned-result seams only, not actual SQLite fault induction.
#[cfg(all(test, any(unix, windows)))]
std::thread_local! {
    pub(super) static PUBLICATION_ACTION_ERROR: std::cell::Cell<Option<(u8, lomi_host_store::StoreError)>> = const { std::cell::Cell::new(None) };
    pub(super) static PUBLICATION_POST_ERROR: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) };
}
#[cfg(all(test, any(unix, windows)))]
fn publication_test_action_error(action: u8) -> Option<lomi_host_store::StoreError> {
    PUBLICATION_ACTION_ERROR.with(|slot| match slot.get() {
        Some((which, error)) if which == action => {
            slot.set(None);
            Some(error)
        }
        _ => None,
    })
}
#[cfg(all(test, any(unix, windows)))]
fn publication_test_post_view(
    action: u8,
    post: Result<StoreView, lomi_host_store::StoreError>,
) -> Result<StoreView, lomi_host_store::StoreError> {
    PUBLICATION_POST_ERROR.with(|slot| {
        if slot.get() == Some(action) {
            slot.set(None);
            Err(lomi_host_store::StoreError::Storage)
        } else {
            post
        }
    })
}

// BEGIN INACTIVE FIXED NORMAL PUBLICATION DOMAIN
#[cfg(any(unix, windows))]
pub(super) struct PublicationContinuation<'d, 'o> {
    original: CloudReadScope<'d, 'o>,
    prepared: Option<(u64, lomi_host_store::HostPublicationIntent)>,
    acknowledged: bool,
}
/// Move-only attenuation of the original configured heartbeat read scope.
/// No public constructor and no Ready/epoch recapture on resumption.
#[cfg(any(unix, windows))]
pub(super) struct OwnedHeartbeatPublication {
    domain_identity: std::sync::Arc<()>,
    operation_identity: OperationIdentity,
    authority_revision: u64,
    generation: u64,
    deny_epoch: u64,
    issued: u64,
}
#[cfg(any(unix, windows))]
impl<'d, 'o> OwnerGuard<'d, 'o> {
    pub(super) fn retain_heartbeat_publication(
        &self,
        scope: CloudReadScope<'d, 'o>,
        store: &lomi_host_store::HostStore,
    ) -> Result<(OwnedHeartbeatPublication, u64), StepError<lomi_host_store::StoreError>> {
        let floor = self.check_cloud_read_send(&scope, store)?;
        Ok((
            OwnedHeartbeatPublication {
                domain_identity: self.domain.owner_identity.clone(),
                operation_identity: scope.operation.retained_identity(),
                authority_revision: scope.authority_revision,
                generation: scope.generation,
                deny_epoch: scope.deny_epoch,
                issued: scope.issued,
            },
            floor,
        ))
    }
}
#[cfg(any(unix, windows))]
impl OwnedHeartbeatPublication {
    /// Reborrow original values only. The caller validates the resulting cap
    /// under Domain then Store after provider work and before any effect.
    pub(super) fn reborrow<'d, 'o>(
        &self,
        domain: &'d OwnerDomain,
        operation: &'o Operation<'o>,
    ) -> Result<PublicationContinuation<'d, 'o>, Error> {
        operation.check()?;
        if !std::sync::Arc::ptr_eq(&self.domain_identity, &domain.owner_identity)
            || !operation.is_same_admission(&self.operation_identity)
        {
            return Err(Error::Stale);
        }
        Ok(PublicationContinuation {
            original: CloudReadScope {
                domain,
                operation,
                authority_revision: self.authority_revision,
                generation: self.generation,
                deny_epoch: self.deny_epoch,
                issued: self.issued,
            },
            prepared: None,
            acknowledged: false,
        })
    }
}
#[cfg(any(unix, windows))]
#[derive(Clone, Copy)]
enum PublicationAction {
    Prepare,
    Ack,
}
#[cfg(any(unix, windows))]
impl PublicationAction {
    fn expected(self, error: lomi_host_store::StoreError) -> bool {
        match self {
            Self::Prepare => matches!(
                error,
                lomi_host_store::StoreError::Fenced
                    | lomi_host_store::StoreError::RevisionConflict
                    | lomi_host_store::StoreError::ResourceExhausted
            ),
            Self::Ack => matches!(
                error,
                lomi_host_store::StoreError::Fenced | lomi_host_store::StoreError::RevisionConflict
            ),
        }
    }
}
#[cfg(any(unix, windows))]
impl<'d, 'o> OwnerGuard<'d, 'o> {
    /// Nonminting final read checkpoint after provider validation. Caller holds
    /// Domain then actual Store; no callback, new ticket, clock write or scope.
    /// Recheck the ORIGINAL continuation after both blocking Store reads.
    pub(super) fn check_publication_send(
        &self,
        continuation: &PublicationContinuation<'d, 'o>,
        store: &lomi_host_store::HostStore,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        if !std::ptr::eq(self.operation, continuation.original.operation) {
            return Err(StepError::Domain(Error::Stale));
        }
        self.domain
            .check_publication(&self.state, continuation, None, false)
            .map_err(StepError::Domain)?;
        let view = StoreView::read(store).map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        let floor = store
            .authorization_state()
            .map_err(|error| {
                self.domain.fail_remote();
                StepError::Source(error)
            })?
            .clock_floor;
        self.domain
            .publication_view(&self.state, continuation, None, false, view)
            .map_err(StepError::Domain)?;
        Ok(floor)
    }
    pub(super) fn checkpoint_publication_clock(
        &mut self,
        continuation: &PublicationContinuation<'d, 'o>,
        store: &mut lomi_host_store::HostStore,
        now: u64,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        if !std::ptr::eq(self.operation, continuation.original.operation) {
            return Err(StepError::Domain(Error::Stale));
        }
        self.domain
            .check_publication(&self.state, continuation, None, false)
            .map_err(StepError::Domain)?;
        let before = StoreView::read(store).map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        self.domain
            .publication_view(&self.state, continuation, None, false, before)
            .map_err(StepError::Domain)?;
        self.state.revision = self.state.revision.checked_add(1).ok_or_else(|| {
            self.domain.fail_remote();
            StepError::Domain(Error::Exhausted)
        })?;
        let outcome = store.observe_authorization_clock(now);
        if outcome.is_err() {
            self.domain.fail_remote();
        }
        let post = StoreView::read(store);
        let checked = match post {
            Err(error) => {
                self.domain.fail_remote();
                Err(StepError::Source(error))
            }
            Ok(view) => {
                if view.generation < self.state.generation {
                    self.domain.fail_remote();
                }
                self.state.generation = view.generation;
                self.domain.generation.store(view.generation, SeqCst);
                if view.locked
                    || view.pending_revoke
                    || self
                        .state
                        .ready
                        .is_some_and(|ready| ready.generation != view.generation)
                {
                    self.state.ready = None;
                }
                self.domain
                    .publication_view(&self.state, continuation, None, false, view)
                    .map_err(StepError::Domain)
            }
        };
        match outcome {
            Err(error) => Err(StepError::Source(error)),
            Ok(floor) => {
                checked?;
                Ok(floor)
            }
        }
    }
}
#[cfg(any(unix, windows))]
impl<'d, 'o> PublicationContinuation<'d, 'o> {
    #[cfg(test)]
    pub(super) fn original_for_test(&self) -> (usize, usize, u64, u64, u64, u64) {
        (
            self.original.domain as *const _ as usize,
            self.original.operation as *const _ as usize,
            self.original.authority_revision,
            self.original.generation,
            self.original.deny_epoch,
            self.original.issued,
        )
    }
    pub(super) fn intent(&self) -> Option<&lomi_host_store::HostPublicationIntent> {
        self.prepared.as_ref().map(|(_, intent)| intent)
    }
}
#[cfg(any(unix, windows))]
impl OwnerDomain {
    fn check_publication(
        &self,
        state: &State,
        cap: &PublicationContinuation<'_, '_>,
        ticket: Option<u64>,
        advanced: bool,
    ) -> Result<(), Error> {
        let original = &cap.original;
        original.operation.check()?;
        let known = if cap.prepared.is_some() { 1u64 } else { 0 };
        let revision = original
            .authority_revision
            .checked_add(known)
            .and_then(|n| n.checked_add(if advanced { 1 } else { 0 }))
            .ok_or(Error::Exhausted)?;
        let prior_ticket = cap
            .prepared
            .as_ref()
            .map_or(original.issued, |(ticket, _)| *ticket);
        let issued = match ticket {
            Some(ticket) if prior_ticket.checked_add(1) == Some(ticket) => ticket,
            Some(_) => return Err(Error::Stale),
            None => prior_ticket,
        };
        if !std::ptr::eq(original.domain, self)
            || cap.acknowledged
            || self.failed_remote.load(SeqCst)
            || self.pending.load(SeqCst) != if ticket.is_some() { 1 } else { 0 }
            || self.issued.load(SeqCst) != issued
            || state.authority_revision != revision
            || state.generation != original.generation
            || self.deny_epoch.load(SeqCst) != original.deny_epoch
            || self.generation_denied(original.generation)
            || !state.ready.is_some_and(|ready| {
                ready.generation == original.generation && ready.deny_epoch == original.deny_epoch
            })
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn publication_view(
        &self,
        state: &State,
        cap: &PublicationContinuation<'_, '_>,
        ticket: Option<u64>,
        advanced: bool,
        view: StoreView,
    ) -> Result<(), Error> {
        self.check_publication(state, cap, ticket, advanced)?;
        if view.generation != cap.original.generation
            || view.verified != Some(cap.original.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Fixed PREPARE only; no callback or guard escapes. Mutex Busy is before
    /// the named method and retains the original continuation unchanged.
    pub(super) fn try_prepare_publication<'d, 'o>(
        &'d self,
        cap: &mut PublicationContinuation<'d, 'o>,
        store: &Mutex<lomi_host_store::HostStore>,
        plan: super::shared_owner::PublicationPlan<'_, '_, '_>,
    ) -> Result<
        lomi_host_store::HostPublicationIntent,
        StepError<super::shared_owner::PublicationError>,
    > {
        if cap.prepared.is_some() {
            return Err(StepError::Domain(Error::Stale));
        }
        let state = self
            .lock(cap.original.operation)
            .map_err(StepError::Domain)?;
        self.check_publication(&state, cap, None, false)
            .map_err(StepError::Domain)?;
        let mut store = match store.try_lock() {
            Ok(store) => store,
            Err(TryLockError::WouldBlock) => return Err(StepError::Domain(Error::Busy)),
            Err(TryLockError::Poisoned(_)) => {
                self.fail_remote();
                return Err(StepError::Domain(Error::Poisoned));
            }
        };
        let view = StoreView::read(&store).map_err(|error| {
            self.fail_remote();
            StepError::Source(super::shared_owner::PublicationError::UncertainStore(error))
        })?;
        self.publication_view(&state, cap, None, false, view)
            .map_err(StepError::Domain)?;
        plan.check_operation(cap.original.operation)
            .map_err(StepError::Source)?;
        plan.revalidate(&store, None).map_err(|error| {
            if error.uncertain() {
                self.fail_remote();
            }
            StepError::Source(error)
        })?;
        let floor = store
            .authorization_state()
            .map_err(|error| {
                self.fail_remote();
                StepError::Source(super::shared_owner::PublicationError::UncertainStore(error))
            })?
            .clock_floor;
        plan.check_current(floor).map_err(StepError::Source)?;
        cap.original.operation.check().map_err(StepError::Domain)?;
        self.increment(&self.pending, MAX_PENDING)
            .map_err(StepError::Domain)?;
        let ticket = match self.increment(&self.issued, u64::MAX) {
            Ok(ticket) => ticket,
            Err(error) => {
                self.decrement(&self.pending);
                return Err(StepError::Domain(error));
            }
        };
        let mut writer = PendingWriter {
            domain: self,
            operation: cap.original.operation,
            class: WriterClass::Remote,
            intent: Intent::Mutation,
            ticket,
            active: true,
            committed: false,
            terminal: None,
        };
        let mut guard = WriterGuard {
            writer: &mut writer,
            state,
        };
        if let Err(error) = self.check_publication(&guard.state, cap, Some(ticket), false) {
            guard.writer.release();
            return Err(StepError::Domain(error));
        }
        if let Err(error) = guard.advance() {
            guard.writer.release();
            return Err(StepError::Domain(error));
        }
        if let Err(error) = self.check_publication(&guard.state, cap, Some(ticket), true) {
            guard.writer.release();
            return Err(StepError::Domain(error));
        }
        #[cfg(test)]
        let injected = publication_test_action_error(1);
        #[cfg(not(test))]
        let injected: Option<lomi_host_store::StoreError> = None;
        let outcome = match injected {
            Some(error) => Err(error),
            None => store.prepare_host_publication(plan.binding()),
        };
        let known_no_effect = outcome
            .as_ref()
            .err()
            .is_some_and(|error| PublicationAction::Prepare.expected(*error));
        if outcome.is_err() && !known_no_effect {
            store.seal_authorization();
            guard.writer.fail(Error::Denied);
        }
        let post = StoreView::read(&store); // Exactly once after either action outcome.
        #[cfg(test)]
        let post = publication_test_post_view(1, post);
        let result = guard.settle_publication(
            cap,
            &plan,
            ticket,
            floor,
            PublicationAction::Prepare,
            &store,
            outcome,
            post,
        );
        let result = guard.finish_publication_local(result, known_no_effect);
        match result {
            Err(error) => Err(error),
            Ok(intent) => {
                cap.prepared = Some((ticket, intent.clone()));
                Ok(intent)
            }
        }
    }
    /// Fixed ACK only, to the exact retained configured PUT request/response.
    pub(super) fn try_ack_publication<'d, 'o>(
        &'d self,
        cap: &mut PublicationContinuation<'d, 'o>,
        store: &Mutex<lomi_host_store::HostStore>,
        plan: super::shared_owner::PublicationPlan<'_, '_, '_>,
        response: &super::shared_owner::ConfiguredPublicationResponse,
    ) -> Result<lomi_host_store::CloudRuntimeState, StepError<super::shared_owner::PublicationError>>
    {
        let intent = cap.intent().ok_or(StepError::Domain(Error::Stale))?.clone();
        let state = self
            .lock(cap.original.operation)
            .map_err(StepError::Domain)?;
        self.check_publication(&state, cap, None, false)
            .map_err(StepError::Domain)?;
        let mut store = match store.try_lock() {
            Ok(store) => store,
            Err(TryLockError::WouldBlock) => return Err(StepError::Domain(Error::Busy)),
            Err(TryLockError::Poisoned(_)) => {
                self.fail_remote();
                return Err(StepError::Domain(Error::Poisoned));
            }
        };
        let view = StoreView::read(&store).map_err(|error| {
            self.fail_remote();
            StepError::Source(super::shared_owner::PublicationError::UncertainStore(error))
        })?;
        self.publication_view(&state, cap, None, false, view)
            .map_err(StepError::Domain)?;
        plan.check_operation(cap.original.operation)
            .map_err(StepError::Source)?;
        plan.revalidate(&store, Some(&intent)).map_err(|error| {
            if error.uncertain() {
                self.fail_remote();
            }
            StepError::Source(error)
        })?;
        response.validate(&intent).map_err(StepError::Source)?;
        let floor = store
            .authorization_state()
            .map_err(|error| {
                self.fail_remote();
                StepError::Source(super::shared_owner::PublicationError::UncertainStore(error))
            })?
            .clock_floor;
        plan.check_current(floor).map_err(StepError::Source)?;
        cap.original.operation.check().map_err(StepError::Domain)?;
        self.increment(&self.pending, MAX_PENDING)
            .map_err(StepError::Domain)?;
        let ticket = match self.increment(&self.issued, u64::MAX) {
            Ok(ticket) => ticket,
            Err(error) => {
                self.decrement(&self.pending);
                return Err(StepError::Domain(error));
            }
        };
        let mut writer = PendingWriter {
            domain: self,
            operation: cap.original.operation,
            class: WriterClass::Remote,
            intent: Intent::Mutation,
            ticket,
            active: true,
            committed: false,
            terminal: None,
        };
        let mut guard = WriterGuard {
            writer: &mut writer,
            state,
        };
        if let Err(error) = self.check_publication(&guard.state, cap, Some(ticket), false) {
            guard.writer.release();
            return Err(StepError::Domain(error));
        }
        if let Err(error) = guard.advance() {
            guard.writer.release();
            return Err(StepError::Domain(error));
        }
        if let Err(error) = self.check_publication(&guard.state, cap, Some(ticket), true) {
            guard.writer.release();
            return Err(StepError::Domain(error));
        }
        #[cfg(test)]
        let injected = publication_test_action_error(2);
        #[cfg(not(test))]
        let injected: Option<lomi_host_store::StoreError> = None;
        let outcome = match injected {
            Some(error) => Err(error),
            None => store.acknowledge_host_publication(&intent, response.result()),
        };
        let known_no_effect = outcome
            .as_ref()
            .err()
            .is_some_and(|error| PublicationAction::Ack.expected(*error));
        if outcome.is_err() && !known_no_effect {
            store.seal_authorization();
            guard.writer.fail(Error::Denied);
        }
        let post = StoreView::read(&store); // Exactly once after either action outcome.
        #[cfg(test)]
        let post = publication_test_post_view(2, post);
        let result = guard.settle_publication(
            cap,
            &plan,
            ticket,
            floor,
            PublicationAction::Ack,
            &store,
            outcome,
            post,
        );
        let result = guard.finish_publication_local(result, known_no_effect);
        match result {
            Err(error) => Err(error),
            Ok(binding) => {
                cap.acknowledged = true;
                Ok(binding)
            }
        }
    }
}
#[cfg(any(unix, windows))]
impl<'d, 'o> WriterGuard<'_, 'd, 'o> {
    /// Release the local ticket while BOTH actual guards remain held. Known
    /// no-effect rejects never invoke generic check/fail; successful/uncertain
    /// effects preserve the inherited conservative check/committed requirement.
    /// The original named-method error remains primary over finalization.
    fn finish_publication_local<T>(
        &mut self,
        result: Result<T, StepError<super::shared_owner::PublicationError>>,
        known_no_effect: bool,
    ) -> Result<T, StepError<super::shared_owner::PublicationError>> {
        if known_no_effect {
            self.writer.release();
            return result;
        }
        let checked = self.writer.check().and_then(|()| {
            if self.writer.committed {
                Ok(())
            } else {
                Err(self.writer.fail(Error::Unfinished))
            }
        });
        self.writer.release();
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                checked.map_err(StepError::Domain)?;
                Ok(value)
            }
        }
    }
    /// Owned named-action results only. This is not a generic callback/proof API.
    #[expect(
        clippy::too_many_arguments,
        reason = "keep the original continuation, action outcome and exact post-view explicit"
    )]
    fn settle_publication<T>(
        &mut self,
        cap: &PublicationContinuation<'d, 'o>,
        plan: &super::shared_owner::PublicationPlan<'_, '_, '_>,
        ticket: u64,
        floor: u64,
        action: PublicationAction,
        store: &lomi_host_store::HostStore,
        outcome: Result<T, lomi_host_store::StoreError>,
        post: Result<StoreView, lomi_host_store::StoreError>,
    ) -> Result<T, StepError<super::shared_owner::PublicationError>> {
        let primary = outcome.as_ref().err().copied();
        let expected = primary.is_some_and(|error| action.expected(error));
        let mut secondary = self
            .writer
            .domain
            .check_publication(&self.state, cap, Some(ticket), true)
            .map_err(StepError::Domain);
        if let Err(error) = plan.check_fresh(floor) {
            if !expected {
                store.seal_authorization();
                self.writer.fail(Error::Denied);
                self.state.ready = None;
            }
            if secondary.is_ok() {
                secondary = Err(StepError::Source(error));
            }
        }
        let view = match post {
            Ok(view) => view,
            Err(error) => {
                self.writer.fail(Error::Denied);
                return Err(StepError::Source(
                    super::shared_owner::PublicationError::UncertainStore(primary.unwrap_or(error)),
                ));
            }
        };
        let checked = self
            .writer
            .domain
            .publication_view(&self.state, cap, Some(ticket), true, view)
            .map_err(StepError::Domain);
        if secondary.is_ok() {
            secondary = checked;
        }
        if secondary.is_err() {
            if !expected {
                self.writer.fail(Error::Denied);
            } else if view.locked
                || view.pending_revoke
                || view.generation != cap.original.generation
            {
                self.state.ready = None;
            }
        }
        let observed = self.observe(view).map_err(StepError::Domain);
        if secondary.is_ok() {
            secondary = observed;
        }
        match outcome {
            Err(error) => Err(StepError::Source(if expected {
                super::shared_owner::PublicationError::Store(error)
            } else {
                super::shared_owner::PublicationError::UncertainStore(error)
            })),
            Ok(value) => {
                secondary?;
                self.writer.committed = true;
                Ok(value)
            }
        }
    }
}
// END INACTIVE FIXED NORMAL PUBLICATION DOMAIN

#[must_use]
pub(super) struct Snapshot<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    frame: u64,
    revision: u64,
    policy: Policy,
    view: Option<StoreView>,
}
pub(super) struct OwnerGuard<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    state: MutexGuard<'d, State>,
    frame: u64,
}

/// Read-only owner frame allowed while one exact Started Git writer owns the
/// global barrier. It cannot register or commit any additional writer.
pub(super) struct StartedGitOwnerGuard<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    state: MutexGuard<'d, State>,
    control: RemoteGitWriterControl,
}
impl StartedGitOwnerGuard<'_, '_> {
    fn check_current(&self) -> Result<(), Error> {
        self.operation.check()?;
        self.control.check_state_current(self.domain, &self.state)
    }

    pub(super) fn capture<E, T>(
        &self,
        read: impl FnOnce() -> Result<(T, StoreView), E>,
    ) -> Result<(T, StoreView), StepError<E>> {
        self.check_current().map_err(StepError::Domain)?;
        let (captured, view) = read().map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        self.check_current().map_err(StepError::Domain)?;
        if view.generation != self.state.generation
            || view.verified != Some(view.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(StepError::Domain(Error::Stale));
        }
        Ok((captured, view))
    }

    pub(super) fn capture_local<E, T>(
        &self,
        read: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, StepError<E>> {
        self.check_current().map_err(StepError::Domain)?;
        let captured = read().map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        self.check_current().map_err(StepError::Domain)?;
        Ok(captured)
    }

    pub(super) fn validate_current(&self) -> Result<(), Error> {
        self.check_current()
    }
    pub(super) fn validate_view(&self, view: StoreView) -> Result<(), Error> {
        self.check_current()?;
        if view.generation != self.state.generation
            || view.verified != Some(view.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
}
impl<'d, 'o> OwnerGuard<'d, 'o> {
    /// Validate an owned read under this same frame without inventing a Core.
    /// The caller must release Store/Domain before performing any external I/O.
    pub(super) fn validate(&self, snapshot: Snapshot<'d, 'o>) -> Result<(), Error> {
        self.validate_current(&snapshot)
    }
    /// Nonconsuming check of this exact retained frame/operation. Does not acquire
    /// Domain or Store; safe inside a checked Core callback while this guard lives.
    pub(super) fn validate_current(&self, snapshot: &Snapshot<'_, '_>) -> Result<(), Error> {
        self.check(snapshot)
    }
    pub(super) fn capture_local<E>(
        &self,
        read: impl FnOnce() -> Result<(), E>,
    ) -> Result<Snapshot<'d, 'o>, StepError<E>> {
        self.operation.check().map_err(StepError::Domain)?;
        read().map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        self.operation.check().map_err(StepError::Domain)?;
        Ok(Snapshot {
            domain: self.domain,
            operation: self.operation,
            frame: self.frame,
            revision: self.state.revision,
            policy: Policy::Local,
            view: None,
        })
    }
    pub(super) fn capture_remote<E>(
        &self,
        read: impl FnOnce() -> Result<StoreView, E>,
    ) -> Result<Snapshot<'d, 'o>, StepError<E>> {
        self.operation.check().map_err(StepError::Domain)?;
        if self.domain.failed_remote.load(SeqCst) {
            return Err(StepError::Domain(Error::Denied));
        }
        let view = read().map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        self.operation.check().map_err(StepError::Domain)?;
        Ok(Snapshot {
            domain: self.domain,
            operation: self.operation,
            frame: self.frame,
            revision: self.state.revision,
            policy: Policy::Remote,
            view: Some(view),
        })
    }
    fn check(&self, snapshot: &Snapshot<'_, '_>) -> Result<(), Error> {
        self.operation.check()?;
        if !std::ptr::eq(snapshot.domain, self.domain)
            || !std::ptr::eq(snapshot.operation, self.operation)
            || snapshot.frame != self.frame
            || snapshot.revision != self.state.revision
        {
            return Err(Error::Stale);
        }
        if snapshot.policy == Policy::Local {
            if self.domain.shared_pending.load(SeqCst) != 0 {
                return Err(Error::Denied);
            }
            return Ok(());
        }
        let view = snapshot.view.ok_or(Error::Denied)?;
        let ready = self.state.ready.ok_or(Error::Denied)?;
        if self.domain.failed_remote.load(SeqCst)
            || self.domain.pending.load(SeqCst) != 0
            || ready.deny_epoch != self.domain.deny_epoch.load(SeqCst)
            || view.generation != self.state.generation
            || ready.generation != view.generation
            || view.verified != Some(view.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    /// Exactly one Core try_lock. No replacement context accepted here or apply.
    #[cfg(test)]
    pub(super) fn try_effect<'c, C>(
        self,
        snapshot: Snapshot<'d, 'o>,
        core: &'c Mutex<C>,
        eligible: impl FnOnce(&C) -> bool,
    ) -> Result<EffectGuard<'d, 'o, 'c, C>, Error> {
        self.check(&snapshot)?;
        let core = match core.try_lock() {
            Ok(core) => core,
            Err(TryLockError::WouldBlock) => return Err(Error::Busy),
            Err(TryLockError::Poisoned(_)) => {
                self.domain.fail_remote();
                return Err(Error::Poisoned);
            }
        };
        if !eligible(&core) {
            return Err(Error::Denied);
        }
        self.check(&snapshot)?;
        Ok(EffectGuard {
            core,
            owner: self,
            snapshot,
        })
    }
}
impl Drop for OwnerGuard<'_, '_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.domain.fail_remote();
        }
    }
}
/// Process-local, noncloneable, nonserializable. Core drops before domain.
/// No Store/provider/network/blocking writes/backpressure inside apply.
#[must_use]
#[cfg(test)]
pub(super) struct EffectGuard<'d, 'o, 'c, C> {
    core: MutexGuard<'c, C>,
    owner: OwnerGuard<'d, 'o>,
    snapshot: Snapshot<'d, 'o>,
}
#[cfg(test)]
impl<C> EffectGuard<'_, '_, '_, C> {
    pub(super) fn apply<T, E>(
        mut self,
        effect: impl FnOnce(&mut C) -> Result<T, E>,
    ) -> Result<T, StepError<E>> {
        self.owner
            .check(&self.snapshot)
            .map_err(StepError::Domain)?;
        self.owner.state.revision = self.owner.state.revision.checked_add(1).ok_or_else(|| {
            self.owner.domain.fail_remote();
            StepError::Domain(Error::Exhausted)
        })?;
        // Physical Core effects invalidate cached effect snapshots, not provider
        // authority scopes. All authority mutations MUST use writer commits.
        // Announcement can race after check; durable commits still exclude us.
        effect(&mut self.core).map_err(|error| {
            self.owner.domain.fail_remote();
            StepError::Source(error)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn end() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }
    fn view(generation: u64) -> StoreView {
        StoreView {
            generation,
            verified: Some(generation),
            locked: false,
            pending_revoke: false,
        }
    }
    fn grant(domain: &OwnerDomain, generation: u64) {
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let scope = {
            let mut frame = writer.try_enter().unwrap();
            frame
                .prepare_verification(generation, || Ok::<_, ()>(view(generation)))
                .unwrap()
        };
        {
            let mut frame = writer.try_enter().unwrap();
            frame
                .commit_verified(scope, || Ok::<_, ()>(((), view(generation))))
                .unwrap();
        }
        writer.finish().unwrap();
    }
    fn local(domain: &OwnerDomain, core: &Mutex<u64>) -> Result<(), StepError<()>> {
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let owner = domain.try_read(&operation).map_err(StepError::Domain)?;
        let snapshot = owner.capture_local(|| Ok::<_, ()>(()))?;
        let effect = owner
            .try_effect(snapshot, core, |_| true)
            .map_err(StepError::Domain)?;
        effect.apply(|core| {
            *core += 1;
            Ok(())
        })
    }
    fn remote(
        domain: &OwnerDomain,
        generation: u64,
        core: &Mutex<u64>,
    ) -> Result<(), StepError<()>> {
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let owner = domain.try_read(&operation).map_err(StepError::Domain)?;
        let snapshot = owner.capture_remote(|| Ok::<_, ()>(view(generation)))?;
        let effect = owner
            .try_effect(snapshot, core, |_| true)
            .map_err(StepError::Domain)?;
        effect.apply(|core| {
            *core += 1;
            Ok(())
        })
    }

    #[test]
    fn starts_remote_closed_while_offline_local_remains_usable() {
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        assert!(matches!(
            remote(&domain, 0, &core),
            Err(StepError::Domain(Error::Denied))
        ));
        assert_eq!(local(&domain, &core), Ok(()));
        assert_eq!(*core.lock().unwrap(), 1);
    }
    #[test]
    fn classified_definite_rejection_preserves_remote_readiness() {
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        grant(&domain, 1);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut pending = domain
            .announce(&operation, WriterClass::Shared, Intent::Mutation)
            .unwrap();
        assert_eq!(
            pending.try_enter().unwrap().commit_classified(|| {
                Err::<((), StoreView), _>(StoreFailure::Expected("fenced", view(1)))
            }),
            Err(StepError::Source("fenced"))
        );
        pending.finish().unwrap();
        assert_eq!(remote(&domain, 1, &core), Ok(()));
        assert_eq!(local(&domain, &core), Ok(()));
    }
    #[test]
    fn classified_uncertain_failure_closes_remote_but_preserves_local() {
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        grant(&domain, 1);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut pending = domain
            .announce(&operation, WriterClass::Shared, Intent::Mutation)
            .unwrap();
        assert_eq!(
            pending.try_enter().unwrap().commit_classified(|| {
                Err::<((), StoreView), _>(StoreFailure::Uncertain("commit-unknown"))
            }),
            Err(StepError::Source("commit-unknown"))
        );
        assert_eq!(pending.finish(), Err(Error::Unfinished));
        assert!(matches!(
            remote(&domain, 1, &core),
            Err(StepError::Domain(Error::Denied))
        ));
        assert_eq!(local(&domain, &core), Ok(()));
    }
    #[test]
    fn read_validation_needs_no_core_and_rechecks_original_operation() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let owner = domain.try_read(&operation).unwrap();
        let snapshot = owner.capture_local(|| Ok::<_, ()>(())).unwrap();
        operation.expire_for_test();
        assert_eq!(owner.validate(snapshot), Err(Error::Deadline));
    }
    #[test]
    fn explicit_fresh_verified_scope_opens_only_exact_generation() {
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        grant(&domain, 1);
        assert_eq!(remote(&domain, 1, &core), Ok(()));
        assert!(matches!(
            remote(&domain, 2, &core),
            Err(StepError::Domain(Error::Denied))
        ));
    }
    #[test]
    fn writer_announces_before_trying_held_domain_without_waiting() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let held = domain.try_read(&operation).unwrap();
        std::thread::scope(|threads| {
            let (sent, received) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let domain_ref = &domain;
            let operation_ref = &operation;
            threads.spawn(move || {
                let mut pending = domain_ref
                    .announce(operation_ref, WriterClass::Shared, Intent::FenceRemote)
                    .unwrap();
                let busy = matches!(pending.try_enter(), Err(Error::Busy));
                sent.send(busy).unwrap();
                released.recv_timeout(Duration::from_secs(2)).unwrap();
                drop(pending);
            });
            assert!(received.recv_timeout(Duration::from_secs(2)).unwrap());
            assert_eq!(domain.pending.load(SeqCst), 1);
            assert_eq!(domain.shared_pending.load(SeqCst), 1);
            release.send(()).unwrap();
        });
        drop(held);
        assert_eq!(domain.pending.load(SeqCst), 0);
    }
    #[test]
    fn completing_writer_a_never_clears_pending_writer_b() {
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        grant(&domain, 1);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut a = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        let mut b = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        a.try_enter()
            .unwrap()
            .commit(|| Ok::<_, ()>(((), view(1))))
            .unwrap();
        a.finish().unwrap();
        assert_eq!(domain.pending.load(SeqCst), 1);
        assert!(remote(&domain, 1, &core).is_err());
        b.try_enter()
            .unwrap()
            .commit(|| Ok::<_, ()>(((), view(1))))
            .unwrap();
        b.finish().unwrap();
        assert_eq!(domain.pending.load(SeqCst), 0);
        assert_eq!(remote(&domain, 1, &core), Ok(()));
    }
    #[test]
    fn abandoned_writer_seals_remote_without_disabling_offline_local() {
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        grant(&domain, 1);
        drop(
            domain
                .announce(&operation, WriterClass::Remote, Intent::Mutation)
                .unwrap(),
        );
        assert!(domain.failed_remote.load(SeqCst));
        assert!(remote(&domain, 1, &core).is_err());
        assert_eq!(local(&domain, &core), Ok(()));
    }
    #[test]
    fn shared_pending_denies_local_but_remote_pending_alone_does_not() {
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        let remote_pending = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        assert_eq!(local(&domain, &core), Ok(()));
        let shared_pending = domain
            .announce(&operation, WriterClass::Shared, Intent::Mutation)
            .unwrap();
        assert!(local(&domain, &core).is_err());
        drop(shared_pending);
        drop(remote_pending);
        assert_eq!(local(&domain, &core), Ok(()));
    }
    #[test]
    fn pending_provider_work_holds_no_domain_and_cannot_block_logout_commit() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        std::thread::scope(|threads| {
            let (started, waiting) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let domain_ref = &domain;
            let operation_ref = &operation;
            threads.spawn(move || {
                let pending = domain_ref
                    .announce(operation_ref, WriterClass::Remote, Intent::VerifyRemote)
                    .unwrap();
                started.send(()).unwrap(); // stand-in for provider I/O OUTSIDE all guards
                released.recv_timeout(Duration::from_secs(2)).unwrap();
                drop(pending);
            });
            waiting.recv_timeout(Duration::from_secs(2)).unwrap();
            let mut logout = domain
                .announce(&operation, WriterClass::Shared, Intent::FenceRemote)
                .unwrap();
            let mut state = view(1);
            state.locked = true;
            state.pending_revoke = true;
            logout
                .try_enter()
                .unwrap()
                .commit(|| Ok::<_, ()>(((), state)))
                .unwrap();
            logout.finish().unwrap();
            assert_eq!(domain.deny_floor.load(SeqCst), 1);
            release.send(()).unwrap();
        });
    }
    #[test]
    fn stale_same_generation_ready_after_logout_never_reaches_store_commit() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        grant(&domain, 1);
        let mut old = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let scope = old
            .try_enter()
            .unwrap()
            .prepare_verification(1, || Ok::<_, ()>(view(1)))
            .unwrap();
        let mut logout = domain
            .announce(&operation, WriterClass::Shared, Intent::FenceRemote)
            .unwrap();
        let mut revoked = view(2);
        revoked.locked = true;
        revoked.pending_revoke = true;
        logout
            .try_enter()
            .unwrap()
            .commit(|| Ok::<_, ()>(((), revoked)))
            .unwrap();
        logout.finish().unwrap();
        let called = AtomicBool::new(false);
        let result = old.try_enter().unwrap().commit_verified(scope, || {
            called.store(true, SeqCst);
            Ok::<_, ()>(((), view(1)))
        });
        assert!(matches!(result, Err(StepError::Domain(Error::Stale))));
        assert!(!called.load(SeqCst));
        drop(old);
        assert!(remote(&domain, 1, &Mutex::new(0)).is_err());
    }
    #[test]
    fn verification_scope_cannot_be_used_by_another_writer() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut a = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let scope = a
            .try_enter()
            .unwrap()
            .prepare_verification(1, || Ok::<_, ()>(view(1)))
            .unwrap();
        let mut b = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let called = AtomicBool::new(false);
        assert!(
            b.try_enter()
                .unwrap()
                .commit_verified(scope, || {
                    called.store(true, SeqCst);
                    Ok::<_, ()>(((), view(1)))
                })
                .is_err()
        );
        assert!(!called.load(SeqCst));
        drop(b);
        drop(a);
    }
    #[test]
    fn newer_pending_writer_invalidates_verification_even_before_its_commit() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut a = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let scope = a
            .try_enter()
            .unwrap()
            .prepare_verification(1, || Ok::<_, ()>(view(1)))
            .unwrap();
        let b = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        assert!(
            a.try_enter()
                .unwrap()
                .commit_verified(scope, || Ok::<_, ()>(((), view(1))))
                .is_err()
        );
        assert_eq!(domain.pending.load(SeqCst), 2);
        drop(a);
        drop(b);
    }
    #[test]
    fn core_busy_releases_domain_so_logout_can_progress_without_waiting() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let core = Mutex::new(0);
        let held_core = core.lock().unwrap();
        let owner = domain.try_read(&operation).unwrap();
        let snapshot = owner.capture_local(|| Ok::<_, ()>(())).unwrap();
        assert!(matches!(
            owner.try_effect(snapshot, &core, |_| true),
            Err(Error::Busy)
        ));
        let mut logout = domain
            .announce(&operation, WriterClass::Shared, Intent::FenceRemote)
            .unwrap();
        logout
            .try_enter()
            .unwrap()
            .commit(|| Ok::<_, ()>(((), view(0))))
            .unwrap();
        logout.finish().unwrap();
        drop(held_core);
    }
    #[test]
    fn cached_snapshot_from_an_older_owner_frame_is_rejected() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let core = Mutex::new(0);
        let snapshot = {
            let owner = domain.try_read(&operation).unwrap();
            owner.capture_local(|| Ok::<_, ()>(())).unwrap()
        };
        let owner = domain.try_read(&operation).unwrap();
        assert!(matches!(
            owner.try_effect(snapshot, &core, |_| true),
            Err(Error::Stale)
        ));
    }
    #[test]
    fn cancellation_after_core_acquisition_prevents_the_effect() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let core = Mutex::new(0);
        let owner = domain.try_read(&operation).unwrap();
        let snapshot = owner.capture_local(|| Ok::<_, ()>(())).unwrap();
        let effect = owner.try_effect(snapshot, &core, |_| true).unwrap();
        cancel.store(true, SeqCst);
        assert!(matches!(
            effect.apply(|core| {
                *core += 1;
                Ok::<_, ()>(())
            }),
            Err(StepError::Domain(Error::Cancelled))
        ));
        assert_eq!(*core.lock().unwrap(), 0);
    }
    #[test]
    fn pending_announced_after_core_acquisition_prevents_the_effect() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let core = Mutex::new(0);
        let owner = domain.try_read(&operation).unwrap();
        let snapshot = owner.capture_local(|| Ok::<_, ()>(())).unwrap();
        let effect = owner.try_effect(snapshot, &core, |_| true).unwrap();
        let pending = domain
            .announce(&operation, WriterClass::Shared, Intent::FenceRemote)
            .unwrap();
        assert!(
            effect
                .apply(|core| {
                    *core += 1;
                    Ok::<_, ()>(())
                })
                .is_err()
        );
        assert_eq!(*core.lock().unwrap(), 0);
        drop(pending);
    }
    #[test]
    fn deadline_and_core_policy_denial_never_invoke_effect() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let core = Mutex::new(0);
        assert!(matches!(
            domain.try_read(&Operation::new(Instant::now(), &cancel)),
            Err(Error::Deadline)
        ));
        let owner = domain.try_read(&operation).unwrap();
        let snapshot = owner.capture_local(|| Ok::<_, ()>(())).unwrap();
        assert!(matches!(
            owner.try_effect(snapshot, &core, |_| false),
            Err(Error::Denied)
        ));
        assert_eq!(*core.lock().unwrap(), 0);
    }
    #[test]
    fn store_error_preserves_source_and_seals_remote() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        let result = writer
            .try_enter()
            .unwrap()
            .commit(|| Err::<((), StoreView), _>("store-failed"));
        assert_eq!(result, Err(StepError::Source("store-failed")));
        assert!(domain.failed_remote.load(SeqCst));
        assert_eq!(writer.finish(), Err(Error::Unfinished));
        assert_eq!(domain.pending.load(SeqCst), 0);
    }
    #[test]
    fn failed_effect_preserves_source_and_invalidates_revision() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let core = Mutex::new(0);
        let before = domain.state.lock().unwrap().revision;
        let owner = domain.try_read(&operation).unwrap();
        let snapshot = owner.capture_local(|| Ok::<_, ()>(())).unwrap();
        let effect = owner.try_effect(snapshot, &core, |_| true).unwrap();
        assert_eq!(
            effect.apply(|_| Err::<(), _>("effect-unknown")),
            Err(StepError::Source("effect-unknown"))
        );
        assert!(domain.failed_remote.load(SeqCst));
        assert!(domain.state.lock().unwrap().revision > before);
    }
    #[test]
    fn revision_wrap_rejects_before_store_io() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        domain.state.lock().unwrap().revision = u64::MAX;
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        let called = AtomicBool::new(false);
        let result = writer.try_enter().unwrap().commit(|| {
            called.store(true, SeqCst);
            Ok::<_, ()>(((), view(0)))
        });
        assert!(matches!(result, Err(StepError::Domain(Error::Exhausted))));
        assert!(!called.load(SeqCst));
        drop(writer);
    }
    #[test]
    fn ticket_wrap_releases_only_owned_announcements_and_seals_remote() {
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let domain = OwnerDomain::new(0);
        domain.issued.store(u64::MAX, SeqCst);
        assert!(matches!(
            domain.announce(&operation, WriterClass::Shared, Intent::Mutation),
            Err(Error::Exhausted)
        ));
        assert_eq!(domain.pending.load(SeqCst), 0);
        assert_eq!(domain.shared_pending.load(SeqCst), 0);
        assert!(domain.failed_remote.load(SeqCst));
    }
    #[test]
    fn pending_capacity_failure_does_not_decrement_other_writers() {
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let domain = OwnerDomain::new(0);
        domain.pending.store(MAX_PENDING, SeqCst);
        assert!(matches!(
            domain.announce(&operation, WriterClass::Remote, Intent::Mutation),
            Err(Error::Exhausted)
        ));
        assert_eq!(domain.pending.load(SeqCst), MAX_PENDING);
        assert!(domain.failed_remote.load(SeqCst));
    }
    #[test]
    fn poisoned_domain_never_reopens_and_core_cleanup_remains_separate() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let core = Mutex::new(5);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _owner = domain.try_read(&operation).unwrap();
            panic!("injected owner panic");
        }));
        assert!(matches!(domain.try_read(&operation), Err(Error::Poisoned)));
        assert!(domain.failed_remote.load(SeqCst));
        // Deny-only disposal/release does not request remote authorization.
        *core.lock().unwrap() = 0;
        assert_eq!(*core.lock().unwrap(), 0);
    }
    #[test]
    fn snapshot_read_failure_seals_remote_and_store_adapter_is_explicit() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let owner = domain.try_read(&operation).unwrap();
        assert!(matches!(
            owner.capture_remote(|| Err::<StoreView, _>("read-sealed-cell")),
            Err(StepError::Source("read-sealed-cell"))
        ));
        assert!(domain.failed_remote.load(SeqCst));
        let _reader: fn(
            &lomi_host_store::HostStore,
        ) -> Result<StoreView, lomi_host_store::StoreError> = StoreView::read;
    }
    #[test]
    fn cancelled_after_writer_acquisition_never_calls_store_commit() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Shared, Intent::FenceRemote)
            .unwrap();
        let mut guard = writer.try_enter().unwrap();
        cancel.store(true, SeqCst);
        let called = AtomicBool::new(false);
        assert!(matches!(
            guard.commit(|| {
                called.store(true, SeqCst);
                Ok::<_, ()>(((), view(0)))
            }),
            Err(StepError::Domain(Error::Cancelled))
        ));
        assert!(!called.load(SeqCst));
        drop(guard);
        assert_eq!(writer.finish(), Err(Error::Unfinished));
    }

    #[test]
    fn verification_scope_keeps_original_deadline_across_reacquisition() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let scope = writer
            .try_enter()
            .unwrap()
            .prepare_verification(1, || Ok::<_, ()>(view(1)))
            .unwrap();
        operation.expire_for_test(); // deterministic elapsed ORIGINAL operation
        let called = AtomicBool::new(false);
        assert!(matches!(
            writer
                .try_enter()
                .map_err(StepError::Domain)
                .and_then(|mut guard| guard.commit_verified(scope, || {
                    called.store(true, SeqCst);
                    Ok::<_, ()>(((), view(1)))
                })),
            Err(StepError::Domain(Error::Deadline))
        ));
        assert!(!called.load(SeqCst));
        assert_eq!(writer.finish(), Err(Error::Unfinished));
    }

    fn configured_store(path: &std::path::Path) -> lomi_host_store::HostStore {
        use lomi_remote_protocol::ipc::*;
        let mut store =
            lomi_host_store::HostStore::open(path, lomi_host_store::Limits::default()).unwrap();
        store
            .configure_auth(&LocalAuthConfiguration {
                version: 1,
                origin: "https://identity.example".to_owned().try_into().unwrap(),
                remote_api_origin: None,
                relay_endpoint: None,
                client_id: "lomi-remote-host".to_owned().try_into().unwrap(),
                provider: crate::testsupport::provider(),
                keychain_path: None,
                protected_file_acknowledgement: crate::testsupport::file_acknowledgement(),
            })
            .unwrap();
        store
    }
    fn actual_login(
        domain: &OwnerDomain,
        store: &mut lomi_host_store::HostStore,
        operation: &Operation<'_>,
    ) -> u64 {
        let generation = store.authorization_state().unwrap().generation;
        let mut writer = domain
            .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let intent = writer
            .try_enter()
            .unwrap()
            .commit(|| {
                let intent = store.begin_login(
                    lomi_remote_protocol::OperationId::from_bytes(*uuid::Uuid::new_v4().as_bytes())
                        .unwrap(),
                )?;
                Ok::<_, lomi_host_store::StoreError>((intent, StoreView::read(store)?))
            })
            .unwrap();
        assert_eq!(intent.generation, generation);
        let scope = writer
            .try_enter()
            .unwrap()
            .prepare_verification(generation, || StoreView::read(store))
            .unwrap();
        // Simulated fresh provider proof for the scope; no provider/network IO.
        writer
            .try_enter()
            .unwrap()
            .commit_verified(scope, || {
                assert_eq!(store.complete_login(intent)?.generation, generation);
                Ok::<_, lomi_host_store::StoreError>(((), StoreView::read(store)?))
            })
            .unwrap();
        writer.finish().unwrap();
        assert_eq!(store.authorization_state().unwrap().generation, generation);
        generation
    }
    #[test]
    fn actual_store_first_login_and_restart_need_fresh_proof_without_generation_bump() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host.sqlite");
        let mut store = configured_store(&path);
        let generation = store.authorization_state().unwrap().generation;
        let domain = OwnerDomain::new(generation);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        assert!(remote(&domain, generation, &Mutex::new(0)).is_err());
        assert_eq!(actual_login(&domain, &mut store, &operation), generation);
        assert_eq!(remote(&domain, generation, &Mutex::new(0)), Ok(()));
        drop(store);
        let mut store =
            lomi_host_store::HostStore::open(&path, lomi_host_store::Limits::default()).unwrap();
        let restarted = OwnerDomain::new(store.authorization_state().unwrap().generation);
        assert_eq!(
            store.verified_authorization_generation().unwrap(),
            Some(generation)
        );
        assert!(remote(&restarted, generation, &Mutex::new(0)).is_err()); // cached marker is insufficient
        assert_eq!(actual_login(&restarted, &mut store, &operation), generation);
        assert_eq!(remote(&restarted, generation, &Mutex::new(0)), Ok(()));
    }
    #[test]
    fn actual_revoke_ack_then_fresh_login_uses_fenced_generation_without_extra_bump() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = configured_store(&directory.path().join("host.sqlite"));
        let initial = store.authorization_state().unwrap().generation;
        let domain = OwnerDomain::new(initial);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        actual_login(&domain, &mut store, &operation);
        let mut revoke = domain
            .announce(&operation, WriterClass::Shared, Intent::FenceRemote)
            .unwrap();
        let fenced = revoke
            .try_enter()
            .unwrap()
            .commit(|| {
                let state = store
                    .fence_authorization(lomi_host_store::AuthorizationFenceReason::LocalLogout)?;
                Ok::<_, lomi_host_store::StoreError>((state.generation, StoreView::read(&store)?))
            })
            .unwrap();
        revoke.finish().unwrap();
        assert_eq!(fenced, initial + 1);
        assert_eq!(domain.revoked_through.load(SeqCst), initial);
        assert_eq!(domain.deny_floor.load(SeqCst), fenced);
        assert!(domain.generation_denied(initial));
        assert!(!domain.generation_denied(fenced));
        assert!(remote(&domain, initial, &Mutex::new(0)).is_err());
        assert!(remote(&domain, fenced, &Mutex::new(0)).is_err());
        let mut ack = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        ack.try_enter()
            .unwrap()
            .commit(|| {
                store.acknowledge_authorization_revoke(fenced)?;
                Ok::<_, lomi_host_store::StoreError>(((), StoreView::read(&store)?))
            })
            .unwrap();
        ack.finish().unwrap();
        assert!(remote(&domain, fenced, &Mutex::new(0)).is_err()); // ACK alone never grants
        assert_eq!(actual_login(&domain, &mut store, &operation), fenced);
        assert_eq!(remote(&domain, fenced, &Mutex::new(0)), Ok(()));
    }
    #[test]
    fn actual_store_suspend_resumes_same_generation_only_with_new_scope() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = configured_store(&directory.path().join("host.sqlite"));
        let generation = store.authorization_state().unwrap().generation;
        let domain = OwnerDomain::new(generation);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        actual_login(&domain, &mut store, &operation);
        let mut suspend = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        suspend
            .try_enter()
            .unwrap()
            .commit(|| {
                store.suspend_authorization(generation)?;
                Ok::<_, lomi_host_store::StoreError>(((), StoreView::read(&store)?))
            })
            .unwrap();
        suspend.finish().unwrap();
        assert!(remote(&domain, generation, &Mutex::new(0)).is_err());
        let mut resume = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let scope = resume
            .try_enter()
            .unwrap()
            .prepare_verification(generation, || StoreView::read(&store))
            .unwrap();
        resume
            .try_enter()
            .unwrap()
            .commit_verified(scope, || {
                assert_eq!(
                    store.enable_authorization(generation)?.generation,
                    generation
                );
                Ok::<_, lomi_host_store::StoreError>(((), StoreView::read(&store)?))
            })
            .unwrap();
        resume.finish().unwrap();
        assert_eq!(remote(&domain, generation, &Mutex::new(0)), Ok(()));
    }
    #[test]
    fn cancelled_reader_cannot_replace_actual_latch_in_snapshot() {
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        let actual = AtomicBool::new(false);
        let operation = Operation::new(end(), &actual);
        let other = AtomicBool::new(false);
        let replacement = Operation::new(end(), &other);
        let owner = domain.try_read(&operation).unwrap();
        let mut snapshot = owner.capture_local(|| Ok::<_, ()>(())).unwrap();
        actual.store(true, SeqCst);
        snapshot.operation = &replacement; // adversarial private-field injection, not public API
        assert!(matches!(
            owner.try_effect(snapshot, &core, |_| true),
            Err(Error::Cancelled)
        ));
        actual.store(false, SeqCst);
        assert_eq!(operation.check(), Err(Error::Cancelled)); // observed cancellation stays latched
        assert_eq!(replacement.check(), Ok(()));
        assert_eq!(*core.lock().unwrap(), 0);
    }
    #[test]
    fn expired_reader_cannot_refresh_budget_at_core_handoff() {
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let replacement = Operation::new(end(), &cancel);
        let owner = domain.try_read(&operation).unwrap();
        let mut snapshot = owner.capture_local(|| Ok::<_, ()>(())).unwrap();
        operation.expire_for_test();
        snapshot.operation = &replacement;
        assert!(matches!(
            owner.try_effect(snapshot, &core, |_| true),
            Err(Error::Deadline)
        ));
        assert_eq!(*core.lock().unwrap(), 0);
    }
    #[test]
    fn expired_writer_scope_cannot_substitute_context_even_inside_held_guard() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let replacement_cancel = AtomicBool::new(false);
        let replacement = Operation::new(end(), &replacement_cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let mut scope = writer
            .try_enter()
            .unwrap()
            .prepare_verification(0, || Ok::<_, ()>(view(0)))
            .unwrap();
        let mut guard = writer.try_enter().unwrap();
        operation.expire_for_test();
        scope.operation = &replacement;
        let called = AtomicBool::new(false);
        assert!(matches!(
            guard.commit_verified(scope, || {
                called.store(true, SeqCst);
                Ok::<_, ()>(((), view(0)))
            }),
            Err(StepError::Domain(Error::Deadline))
        ));
        assert!(!called.load(SeqCst));
        drop(guard);
        assert_eq!(writer.finish(), Err(Error::Unfinished));
    }
    #[test]
    fn busy_writer_retry_uses_original_context_and_expires_without_store_io() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let held = domain.try_read(&operation).unwrap();
        let mut writer = domain
            .announce(&operation, WriterClass::Shared, Intent::Mutation)
            .unwrap();
        assert!(matches!(writer.try_enter(), Err(Error::Busy)));
        assert_eq!(writer.terminal, None);
        drop(held);
        operation.expire_for_test();
        assert!(matches!(writer.try_enter(), Err(Error::Deadline)));
        assert!(domain.failed_remote.load(SeqCst));
        assert_eq!(writer.finish(), Err(Error::Unfinished));
    }
    #[test]
    fn stale_verification_then_noop_commit_cannot_launder_terminal_failure() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let mut scope = writer
            .try_enter()
            .unwrap()
            .prepare_verification(0, || Ok::<_, ()>(view(0)))
            .unwrap();
        scope.authority_revision += 1; // deterministic stale authority boundary
        let mut guard = writer.try_enter().unwrap();
        assert!(matches!(
            guard.commit_verified(scope, || Ok::<_, ()>(((), view(0)))),
            Err(StepError::Domain(Error::Stale))
        ));
        let called = AtomicBool::new(false);
        assert!(matches!(
            guard.commit(|| {
                called.store(true, SeqCst);
                Ok::<_, ()>(((), view(0)))
            }),
            Err(StepError::Domain(Error::Stale))
        ));
        assert!(!called.load(SeqCst));
        drop(guard);
        assert!(domain.failed_remote.load(SeqCst));
        assert_eq!(writer.finish(), Err(Error::Unfinished));
    }
    #[test]
    fn earlier_commit_then_failed_prepare_cannot_finish_or_recommit_successfully() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let mut guard = writer.try_enter().unwrap();
        guard.commit(|| Ok::<_, ()>(((), view(0)))).unwrap();
        assert!(matches!(
            guard.prepare_verification(1, || Ok::<_, ()>(view(0))),
            Err(StepError::Domain(Error::Stale))
        ));
        assert!(guard.commit(|| Ok::<_, ()>(((), view(0)))).is_err());
        drop(guard);
        assert!(matches!(writer.try_enter(), Err(Error::Stale)));
        assert_eq!(writer.finish(), Err(Error::Unfinished));
        assert!(domain.failed_remote.load(SeqCst));
    }
    #[test]
    fn prepare_source_failure_is_sticky_after_previous_successful_commit() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let mut guard = writer.try_enter().unwrap();
        guard.commit(|| Ok::<_, ()>(((), view(0)))).unwrap();
        assert!(matches!(
            guard.prepare_verification(0, || Err::<StoreView, _>("read-fault")),
            Err(StepError::Source("read-fault"))
        ));
        assert!(guard.commit(|| Ok::<_, ()>(((), view(0)))).is_err());
        drop(guard);
        assert_eq!(writer.finish(), Err(Error::Unfinished));
        assert!(domain.failed_remote.load(SeqCst));
    }
    #[test]
    fn verified_commit_source_failure_cannot_be_cleared_by_later_phase() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let scope = writer
            .try_enter()
            .unwrap()
            .prepare_verification(0, || Ok::<_, ()>(view(0)))
            .unwrap();
        let mut guard = writer.try_enter().unwrap();
        assert_eq!(
            guard.commit_verified(scope, || Err::<((), StoreView), _>("write-fault")),
            Err(StepError::Source("write-fault"))
        );
        assert!(guard.commit(|| Ok::<_, ()>(((), view(0)))).is_err());
        drop(guard);
        assert_eq!(writer.finish(), Err(Error::Unfinished));
        assert!(domain.failed_remote.load(SeqCst));
    }
    #[test]
    fn local_physical_effect_during_provider_io_does_not_stale_authority_scope() {
        let domain = OwnerDomain::new(0);
        let core = Mutex::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let scope = writer
            .try_enter()
            .unwrap()
            .prepare_verification(0, || Ok::<_, ()>(view(0)))
            .unwrap();
        let authority_revision = scope.authority_revision;
        assert_eq!(local(&domain, &core), Ok(()));
        assert_eq!(
            domain.state.lock().unwrap().authority_revision,
            authority_revision
        );
        writer
            .try_enter()
            .unwrap()
            .commit_verified(scope, || Ok::<_, ()>(((), view(0))))
            .unwrap();
        writer.finish().unwrap();
        assert_eq!(remote(&domain, 0, &core), Ok(()));
        assert_eq!(*core.lock().unwrap(), 2);
    }
    #[test]
    fn expired_before_capture_never_reads_store_callback() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let owner = domain.try_read(&operation).unwrap();
        operation.expire_for_test();
        let called = AtomicBool::new(false);
        assert!(matches!(
            owner.capture_local(|| {
                called.store(true, SeqCst);
                Ok::<_, ()>(())
            }),
            Err(StepError::Domain(Error::Deadline))
        ));
        assert!(!called.load(SeqCst));
    }
    #[test]
    fn authority_revision_wrap_is_terminal_before_store_callback() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        domain.state.lock().unwrap().authority_revision = u64::MAX;
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        let called = AtomicBool::new(false);
        assert!(matches!(
            writer.try_enter().unwrap().commit(|| {
                called.store(true, SeqCst);
                Ok::<_, ()>(((), view(0)))
            }),
            Err(StepError::Domain(Error::Exhausted))
        ));
        assert!(!called.load(SeqCst));
        assert_eq!(writer.finish(), Err(Error::Unfinished));
    }

    #[test]
    fn busy_writer_can_retry_successfully_only_before_original_context_expires() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let held = domain.try_read(&operation).unwrap();
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        assert!(matches!(writer.try_enter(), Err(Error::Busy)));
        drop(held);
        writer
            .try_enter()
            .unwrap()
            .commit(|| Ok::<_, ()>(((), view(0))))
            .unwrap();
        writer.finish().unwrap();
        assert!(!domain.failed_remote.load(SeqCst));
        assert_eq!(domain.pending.load(SeqCst), 0);
    }
    #[test]
    fn writer_cancellation_is_terminal_even_if_external_latch_is_reset() {
        let domain = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = domain
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        writer
            .try_enter()
            .unwrap()
            .commit(|| Ok::<_, ()>(((), view(0))))
            .unwrap();
        cancel.store(true, SeqCst);
        assert!(matches!(writer.try_enter(), Err(Error::Cancelled)));
        cancel.store(false, SeqCst);
        assert!(matches!(writer.try_enter(), Err(Error::Cancelled)));
        assert_eq!(writer.finish(), Err(Error::Unfinished));
        assert!(domain.failed_remote.load(SeqCst));
    }
    #[test]
    fn conditional_rejection_arms_only_checked_generation_without_promoting_intent() {
        let domain = OwnerDomain::new(4);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut rejection = domain
            .announce(&operation, WriterClass::Shared, Intent::Mutation)
            .unwrap();
        {
            let mut guard = rejection.try_enter().unwrap();
            guard.arm_authority_rejection(4).unwrap();
            assert_eq!(guard.writer.intent, Intent::Mutation);
            assert_eq!(domain.revoked_through.load(SeqCst), 4);
            assert!(domain.generation_denied(4));
            assert!(!domain.generation_denied(5));
            guard
                .commit(|| {
                    Ok::<_, ()>((
                        (),
                        StoreView {
                            generation: 5,
                            verified: None,
                            locked: true,
                            pending_revoke: false,
                        },
                    ))
                })
                .unwrap();
        }
        rejection.finish().unwrap();
        assert!(domain.generation_denied(4));
        assert!(!domain.generation_denied(5));
    }

    #[test]
    fn conditional_rejection_busy_then_new_generation_stale_retry_keeps_eligibility() {
        let domain = OwnerDomain::new(4);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut rejection = domain
            .announce(&operation, WriterClass::Shared, Intent::Mutation)
            .unwrap();
        {
            let mut guard = rejection.try_enter().unwrap();
            guard.arm_authority_rejection(4).unwrap();
            // Synthetic Store Busy plus its sealed post-view. This models the
            // retained token mechanically; it is not an actual SQL Busy test.
            assert_eq!(
                guard.commit_classified(|| Err::<((), StoreView), _>(StoreFailure::Expected(
                    "busy",
                    StoreView {
                        generation: 4,
                        verified: None,
                        locked: true,
                        pending_revoke: false,
                    }
                ))),
                Err(StepError::Source("busy"))
            );
        }
        assert_eq!(rejection.intent, Intent::Mutation);
        let mut newer = domain
            .announce(&operation, WriterClass::Shared, Intent::FenceRemote)
            .unwrap();
        newer
            .try_enter()
            .unwrap()
            .commit(|| {
                Ok::<_, ()>((
                    (),
                    StoreView {
                        generation: 5,
                        verified: None,
                        locked: true,
                        pending_revoke: false,
                    },
                ))
            })
            .unwrap();
        newer.finish().unwrap();
        {
            let mut guard = rejection.try_enter().unwrap();
            // Concrete owner code now sees Store generation 5 != expected 4;
            // it must take this definite branch without arming any fence.
            assert_eq!(
                guard.commit_classified(|| Err::<((), StoreView), _>(StoreFailure::Expected(
                    "stale",
                    StoreView {
                        generation: 5,
                        verified: None,
                        locked: true,
                        pending_revoke: false,
                    }
                ))),
                Err(StepError::Source("stale"))
            );
        }
        rejection.finish().unwrap();
        assert!(!domain.failed_remote.load(SeqCst));
        assert!(domain.generation_denied(4));
        assert!(!domain.generation_denied(5));
        // Mechanical scope admission only, with no qualified provider response.
        let mut verification = domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        assert!(
            verification
                .try_enter()
                .unwrap()
                .prepare_verification(5, || Ok::<_, ()>(StoreView {
                    generation: 5,
                    verified: None,
                    locked: true,
                    pending_revoke: false,
                }))
                .is_ok()
        );
    }
    // Authored source-only tests. No Rust test/compile/formatter has run.
    fn clock_fixture(
        run: impl FnOnce(&OwnerDomain, &Operation<'_>, &AtomicBool, &mut lomi_host_store::HostStore),
    ) {
        let directory = tempfile::tempdir().unwrap();
        let mut store = configured_store(&directory.path().join("clock.sqlite"));
        let owner = OwnerDomain::new(store.authorization_state().unwrap().generation);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + Duration::from_secs(60), &cancel);
        run(&owner, &operation, &cancel, &mut store);
    }
    fn clock_scope<'d, 'o>(
        writer: &mut PendingWriter<'d, 'o>,
        store: &lomi_host_store::HostStore,
    ) -> VerificationScope<'d, 'o> {
        let generation = store.authorization_state().unwrap().generation;
        writer
            .try_enter()
            .unwrap()
            .prepare_verification(generation, || StoreView::read(store))
            .unwrap()
    }
    #[test]
    fn original_clock_checkpoint_retains_exact_scope_until_verified_commit() {
        clock_fixture(|owner, operation, _, store| {
            let mut writer = owner
                .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                .unwrap();
            let scope = clock_scope(&mut writer, store);
            let captured = (
                scope.ticket,
                scope.authority_revision,
                scope.generation,
                scope.deny_epoch,
            );
            let scope_address = &scope as *const _;
            let issued = owner.issued.load(SeqCst);
            {
                let mut guard = writer.try_enter().unwrap();
                let revision = guard.state.revision;
                assert_eq!(
                    guard.checkpoint_verification_clock(&scope, store, 37),
                    Ok(37)
                );
                assert_eq!(guard.state.revision, revision + 1);
                assert_eq!(guard.state.authority_revision, captured.1);
                assert!(guard.state.ready.is_none());
                assert!(!guard.writer.committed);
            }
            assert_eq!(scope_address, &scope as *const _);
            assert_eq!(
                captured,
                (
                    scope.ticket,
                    scope.authority_revision,
                    scope.generation,
                    scope.deny_epoch
                )
            );
            assert_eq!(owner.issued.load(SeqCst), issued);
            assert_eq!(store.authorization_state().unwrap().clock_floor, 37);
            writer
                .try_enter()
                .unwrap()
                .commit_verified(scope, || Ok::<_, ()>(((), view(captured.2))))
                .unwrap();
            writer.finish().unwrap();
            assert!(owner.state.lock().unwrap().ready.is_some());
        });
    }
    #[test]
    fn original_clock_checkpoint_alone_cannot_finish() {
        clock_fixture(|owner, operation, _, store| {
            let mut writer = owner
                .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                .unwrap();
            let scope = clock_scope(&mut writer, store);
            writer
                .try_enter()
                .unwrap()
                .checkpoint_verification_clock(&scope, store, 9)
                .unwrap();
            assert_eq!(writer.finish(), Err(Error::Unfinished));
            assert!(owner.failed_remote.load(SeqCst));
            assert!(owner.state.lock().unwrap().ready.is_none());
        });
    }
    #[test]
    fn original_clock_checkpoint_rejects_changed_authority_generation_and_deny_epoch() {
        for change in 0..3 {
            clock_fixture(|owner, operation, _, store| {
                let mut writer = owner
                    .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                    .unwrap();
                let scope = clock_scope(&mut writer, store);
                let mut guard = writer.try_enter().unwrap();
                match change {
                    0 => {
                        guard
                            .commit(|| Ok::<_, ()>(((), view(scope.generation))))
                            .unwrap();
                    }
                    1 => {
                        guard.state.generation += 1;
                    }
                    _ => {
                        owner.deny_epoch.store(scope.ticket + 1, SeqCst);
                    }
                }
                let revision = guard.state.revision;
                assert_eq!(
                    guard.checkpoint_verification_clock(&scope, store, 41),
                    Err(StepError::Domain(Error::Stale))
                );
                assert_eq!(guard.state.revision, revision);
                assert_eq!(store.authorization_state().unwrap().clock_floor, 0);
                assert!(guard.writer.terminal.is_some());
            });
        }
    }
    #[test]
    fn original_clock_checkpoint_rejects_concurrent_and_completed_new_writer() {
        for concurrent in [true, false] {
            clock_fixture(|owner, operation, _, store| {
                let mut writer = owner
                    .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                    .unwrap();
                let scope = clock_scope(&mut writer, store);
                let mut other = Some(
                    owner
                        .announce(operation, WriterClass::Shared, Intent::Mutation)
                        .unwrap(),
                );
                if !concurrent {
                    let mut other = other.take().unwrap();
                    other
                        .try_enter()
                        .unwrap()
                        .commit(|| Ok::<_, ()>(((), view(scope.generation))))
                        .unwrap();
                    other.finish().unwrap();
                }
                assert_eq!(
                    writer
                        .try_enter()
                        .unwrap()
                        .checkpoint_verification_clock(&scope, store, 41),
                    Err(StepError::Domain(Error::Stale))
                );
                assert_eq!(store.authorization_state().unwrap().clock_floor, 0);
                drop(other);
            });
        }
    }
    #[test]
    fn original_clock_checkpoint_checks_original_cancel_deadline_and_revision_overflow_before_io() {
        for boundary in 0..3 {
            clock_fixture(|owner, operation, cancel, store| {
                let mut writer = owner
                    .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                    .unwrap();
                let scope = clock_scope(&mut writer, store);
                let mut guard = writer.try_enter().unwrap();
                let expected = match boundary {
                    0 => {
                        cancel.store(true, SeqCst);
                        Error::Cancelled
                    }
                    1 => {
                        operation.expire_for_test();
                        Error::Deadline
                    }
                    _ => {
                        guard.state.revision = u64::MAX;
                        Error::Exhausted
                    }
                };
                assert_eq!(
                    guard.checkpoint_verification_clock(&scope, store, 41),
                    Err(StepError::Domain(expected))
                );
                assert_eq!(store.authorization_state().unwrap().clock_floor, 0);
                assert!(!guard.writer.committed);
            });
        }
    }
    #[test]
    fn original_clock_checkpoint_checks_original_cancel_and_deadline_after_io() {
        for cancelled in [true, false] {
            clock_fixture(|owner, operation, cancel, store| {
                let mut writer = owner
                    .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                    .unwrap();
                let scope = clock_scope(&mut writer, store);
                let mut guard = writer.try_enter().unwrap();
                // Owned-result boundary fixture, no arbitrary IO callback.
                let outcome = store.observe_authorization_clock(43);
                let outcome = guard.record_verification_clock_outcome(outcome);
                let post = StoreView::read(store);
                let expected = if cancelled {
                    cancel.store(true, SeqCst);
                    Error::Cancelled
                } else {
                    operation.expire_for_test();
                    Error::Deadline
                };
                assert_eq!(
                    guard.finish_verification_clock(&scope, outcome, post),
                    Err(StepError::Domain(expected))
                );
                assert_eq!(store.authorization_state().unwrap().clock_floor, 43);
                assert!(!guard.writer.committed);
                assert!(guard.state.ready.is_none());
            });
        }
    }
    #[test]
    fn original_clock_checkpoint_borrows_foreign_scope_without_rebinding_it() {
        clock_fixture(|owner, operation, _, store| {
            let foreign = OwnerDomain::new(store.authorization_state().unwrap().generation);
            let mut original = foreign
                .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                .unwrap();
            let scope = clock_scope(&mut original, store);
            let mut writer = owner
                .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                .unwrap();
            assert_eq!(
                writer
                    .try_enter()
                    .unwrap()
                    .checkpoint_verification_clock(&scope, store, 41),
                Err(StepError::Domain(Error::Stale))
            );
            assert!(std::ptr::eq(scope.domain, &foreign));
            assert_eq!(store.authorization_state().unwrap().clock_floor, 0);
        });
    }
    #[test]
    fn original_clock_checkpoint_rejects_wrong_operation_and_ticket_without_scope_updates() {
        for wrong_operation in [true, false] {
            clock_fixture(|owner, operation, _, store| {
                let cancel = AtomicBool::new(false);
                let other_operation = Operation::new(end(), &cancel);
                let mut writer = owner
                    .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                    .unwrap();
                let scope = clock_scope(&mut writer, store);
                // Private corruption fixture changes writer context, NEVER scope.
                if wrong_operation {
                    writer.operation = &other_operation;
                } else {
                    writer.ticket += 1;
                }
                assert_eq!(
                    writer
                        .try_enter()
                        .unwrap()
                        .checkpoint_verification_clock(&scope, store, 41),
                    Err(StepError::Domain(Error::Stale))
                );
                assert!(std::ptr::eq(scope.operation, operation));
                assert_eq!(store.authorization_state().unwrap().clock_floor, 0);
            });
        }
    }
    #[test]
    fn original_clock_checkpoint_failure_seals_before_post_observation_and_preserves_primary() {
        for primary in [
            lomi_host_store::StoreError::Busy,
            lomi_host_store::StoreError::Storage,
        ] {
            for secondary in 0..3 {
                clock_fixture(|owner, operation, _, store| {
                    let mut writer = owner
                        .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                        .unwrap();
                    let scope = clock_scope(&mut writer, store);
                    let mut guard = writer.try_enter().unwrap();
                    // Synthetic actual-method failure boundary: Store's concrete
                    // method self-seals on ALL Err, including SQLite Busy. This
                    // fixture does not claim to induce an actual SQL Busy.
                    store.seal_authorization();
                    let outcome = guard.record_verification_clock_outcome(Err(primary));
                    assert!(owner.failed_remote.load(SeqCst));
                    assert_eq!(guard.writer.terminal, Some(Error::Denied));
                    if secondary == 0 {
                        guard.state.ready = Some(Ready {
                            generation: scope.generation,
                            deny_epoch: scope.deny_epoch,
                        });
                    }
                    let post = match secondary {
                        0 => StoreView::read(store),
                        1 => Err(lomi_host_store::StoreError::Invalid),
                        _ => {
                            guard.state.generation += 1;
                            StoreView::read(store)
                        }
                    };
                    assert_eq!(
                        guard.finish_verification_clock(&scope, outcome, post),
                        Err(StepError::Source(primary))
                    );
                    assert!(store.authorization_state().unwrap().locked);
                    if secondary == 0 {
                        assert!(guard.state.ready.is_none());
                    }
                    assert!(!guard.writer.committed);
                    assert_eq!(guard.writer.terminal, Some(Error::Denied));
                    drop(guard);
                    assert!(matches!(writer.try_enter(), Err(Error::Denied)));
                    assert_eq!(writer.finish(), Err(Error::Unfinished));
                });
            }
        }
    }
    #[test]
    fn original_clock_checkpoint_success_with_post_read_error_is_terminal() {
        clock_fixture(|owner, operation, _, store| {
            let mut writer = owner
                .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                .unwrap();
            let scope = clock_scope(&mut writer, store);
            let mut guard = writer.try_enter().unwrap();
            let outcome = store.observe_authorization_clock(47);
            let outcome = guard.record_verification_clock_outcome(outcome);
            assert_eq!(
                guard.finish_verification_clock(
                    &scope,
                    outcome,
                    Err(lomi_host_store::StoreError::Storage)
                ),
                Err(StepError::Source(lomi_host_store::StoreError::Storage))
            );
            assert!(owner.failed_remote.load(SeqCst));
            assert!(!guard.writer.committed);
            assert!(guard.state.ready.is_none());
        });
    }

    #[test]
    fn original_clock_checkpoint_does_not_increment_even_max_authority_revision() {
        clock_fixture(|owner, operation, _, store| {
            owner.state.lock().unwrap().authority_revision = u64::MAX;
            let mut writer = owner
                .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                .unwrap();
            let scope = clock_scope(&mut writer, store);
            let mut guard = writer.try_enter().unwrap();
            assert_eq!(
                guard.checkpoint_verification_clock(&scope, store, 53),
                Ok(53)
            );
            assert_eq!(guard.state.authority_revision, u64::MAX);
            assert_eq!(scope.authority_revision, u64::MAX);
            assert!(!guard.writer.committed);
        });
    }
    #[test]
    fn original_clock_checkpoint_poststate_generation_change_invalidates_original_scope() {
        clock_fixture(|owner, operation, _, store| {
            let mut writer = owner
                .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                .unwrap();
            let scope = clock_scope(&mut writer, store);
            let mut guard = writer.try_enter().unwrap();
            let outcome = guard.record_verification_clock_outcome(Ok(59));
            assert_eq!(
                guard.finish_verification_clock(&scope, outcome, Ok(view(scope.generation + 1))),
                Err(StepError::Domain(Error::Stale))
            );
            assert_eq!(scope.generation + 1, guard.state.generation);
            assert!(!guard.writer.committed);
            assert!(guard.state.ready.is_none());
        });
    }
    #[test]
    fn original_clock_checkpoint_post_boundary_new_writer_or_deny_invalidates_scope() {
        for new_writer in [true, false] {
            clock_fixture(|owner, operation, _, store| {
                let mut writer = owner
                    .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
                    .unwrap();
                let scope = clock_scope(&mut writer, store);
                let mut guard = writer.try_enter().unwrap();
                let outcome = store.observe_authorization_clock(61);
                let outcome = guard.record_verification_clock_outcome(outcome);
                let post = StoreView::read(store);
                // Announcement is mutex-free, including while Domain is held.
                let other = if new_writer {
                    Some(
                        owner
                            .announce(operation, WriterClass::Shared, Intent::Mutation)
                            .unwrap(),
                    )
                } else {
                    owner.deny_epoch.store(scope.ticket + 1, SeqCst);
                    None
                };
                assert_eq!(
                    guard.finish_verification_clock(&scope, outcome, post),
                    Err(StepError::Domain(Error::Stale))
                );
                assert!(!guard.writer.committed);
                assert!(guard.state.ready.is_none());
                drop(other);
            });
        }
    }

    // Mechanical Domain fixtures only: no TLS/provider provenance is claimed.
    #[cfg(any(unix, windows))]
    fn cloud_domain_store(path: &std::path::Path) -> lomi_host_store::HostStore {
        let mut store = configured_store(path);
        let mut selected = store.auth_configuration().unwrap().unwrap();
        selected.remote_api_origin = Some("https://remote.example".to_owned().try_into().unwrap());
        store.configure_auth(&selected).unwrap();
        let document =
            lomi_host_store::PublicDocument::encode(&lomi_platform::public_config::Configuration {
                version: 1,
                revision: 1,
                authentication: Some(selected),
            })
            .unwrap();
        let intent = store.public_prepare(None, &document).unwrap();
        store.public_finish(intent.operation_id, &document).unwrap();
        let generation = store.authorization_state().unwrap().generation;
        store.enable_authorization(generation).unwrap();
        store
    }
    #[test]
    #[cfg(any(unix, windows))]
    fn cloud_mutation_clock_preserves_actual_ready_and_original_scope_without_verification_scope() {
        let root = tempfile::tempdir().unwrap();
        let mut store = cloud_domain_store(&root.path().join("clock.sqlite"));
        let generation = store.authorization_state().unwrap().generation;
        let owner = OwnerDomain::new(generation);
        grant(&owner, generation);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut writer = owner
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        let scope = writer
            .try_enter()
            .unwrap()
            .prepare_cloud_mutation_scope(&store)
            .unwrap();
        let captured = (
            scope.ticket,
            scope.authority_revision,
            scope.generation,
            scope.deny_epoch,
        );
        let mut guard = writer.try_enter().unwrap();
        let revision = guard.state.revision;
        assert_eq!(
            guard.checkpoint_cloud_clock(&scope, &mut store, 1004),
            Ok(1004)
        );
        assert_eq!(
            guard.checkpoint_cloud_clock(&scope, &mut store, 1005),
            Ok(1005)
        );
        assert_eq!(guard.state.revision, revision + 2);
        assert_eq!(guard.state.authority_revision, captured.1);
        assert!(guard.state.ready.is_some());
        assert!(!guard.writer.committed);
        assert_eq!(
            captured,
            (
                scope.ticket,
                scope.authority_revision,
                scope.generation,
                scope.deny_epoch
            )
        );
        drop(guard);
        assert_eq!(writer.finish(), Err(Error::Unfinished));
    }
    #[test]
    #[cfg(any(unix, windows))]
    fn cloud_mutation_scope_rejects_missing_ready_foreign_context_and_changed_authority() {
        for change in 0..7 {
            let root = tempfile::tempdir().unwrap();
            let mut store = cloud_domain_store(&root.path().join("scope.sqlite"));
            let generation = store.authorization_state().unwrap().generation;
            let owner = OwnerDomain::new(generation);
            grant(&owner, generation);
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let other_cancel = AtomicBool::new(false);
            let other_operation = Operation::new(end(), &other_cancel);
            let mut writer = owner
                .announce(&operation, WriterClass::Remote, Intent::Mutation)
                .unwrap();
            let scope = writer
                .try_enter()
                .unwrap()
                .prepare_cloud_mutation_scope(&store)
                .unwrap();
            let mut guard = writer.try_enter().unwrap();
            match change {
                0 => guard.state.ready = None,
                1 => guard.writer.operation = &other_operation,
                2 => guard.writer.ticket += 1,
                3 => guard.state.authority_revision += 1,
                4 => guard.state.generation += 1,
                5 => owner.deny_epoch.store(scope.deny_epoch + 1, SeqCst),
                _ => {
                    owner.issued.store(scope.ticket + 1, SeqCst);
                }
            }
            assert!(matches!(
                guard.checkpoint_cloud_clock(&scope, &mut store, 1004),
                Err(StepError::Domain(Error::Stale))
            ));
            assert_eq!(store.authorization_state().unwrap().clock_floor, 0);
        }
    }
    #[test]
    #[cfg(any(unix, windows))]
    fn cloud_mutation_original_cancel_deadline_and_clock_revision_overflow_fail_before_write() {
        for boundary in 0..3 {
            let root = tempfile::tempdir().unwrap();
            let mut store = cloud_domain_store(&root.path().join("boundary.sqlite"));
            let generation = store.authorization_state().unwrap().generation;
            let owner = OwnerDomain::new(generation);
            grant(&owner, generation);
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let mut writer = owner
                .announce(&operation, WriterClass::Remote, Intent::Mutation)
                .unwrap();
            let scope = writer
                .try_enter()
                .unwrap()
                .prepare_cloud_mutation_scope(&store)
                .unwrap();
            let mut guard = writer.try_enter().unwrap();
            let error = match boundary {
                0 => {
                    cancel.store(true, SeqCst);
                    Error::Cancelled
                }
                1 => {
                    operation.expire_for_test();
                    Error::Deadline
                }
                _ => {
                    guard.state.revision = u64::MAX;
                    Error::Exhausted
                }
            };
            assert_eq!(
                guard.checkpoint_cloud_clock(&scope, &mut store, 1004),
                Err(StepError::Domain(error))
            );
            assert_eq!(store.authorization_state().unwrap().clock_floor, 0);
        }
    }
    #[test]
    #[cfg(any(unix, windows))]
    fn cloud_get_each_fixed_action_classifies_expected_vs_uncertain_and_preserves_primary_error() {
        for kind in [
            super::super::shared_owner::CloudGetStoreAction::Invalidate,
            super::super::shared_owner::CloudGetStoreAction::RecoveredAck,
            super::super::shared_owner::CloudGetStoreAction::Install,
        ] {
            for error in [
                lomi_host_store::StoreError::Fenced,
                lomi_host_store::StoreError::RevisionConflict,
                lomi_host_store::StoreError::Busy,
                lomi_host_store::StoreError::Invalid,
                lomi_host_store::StoreError::Storage,
                lomi_host_store::StoreError::ResourceExhausted,
            ] {
                for secondary in 0..4 {
                    let root = tempfile::tempdir().unwrap();
                    let store = cloud_domain_store(&root.path().join("outcome.sqlite"));
                    let generation = store.authorization_state().unwrap().generation;
                    let owner = OwnerDomain::new(generation);
                    grant(&owner, generation);
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let mut writer = owner
                        .announce(&operation, WriterClass::Remote, Intent::Mutation)
                        .unwrap();
                    let scope = writer
                        .try_enter()
                        .unwrap()
                        .prepare_cloud_mutation_scope(&store)
                        .unwrap();
                    let plan = super::super::shared_owner::CloudGetPlan::synthetic_for_domain_test(
                        &store, None,
                    );
                    let mut guard = writer.try_enter().unwrap();
                    guard.advance().unwrap();
                    let post = match secondary {
                        1 => Err(lomi_host_store::StoreError::Storage),
                        2 => {
                            guard.state.generation += 1;
                            StoreView::read(&store)
                        }
                        3 => {
                            cancel.store(true, SeqCst);
                            StoreView::read(&store)
                        }
                        _ => StoreView::read(&store),
                    };
                    // Synthetic owned-result fixture, NOT actual SQL error induction.
                    let result = guard.observe_cloud_get_action(
                        &scope,
                        &plan,
                        1004,
                        kind,
                        &store,
                        Err::<(), _>(error),
                        post,
                    );
                    match result {
                        Err(StepError::Source(
                            super::super::shared_owner::CloudGetError::Store(primary)
                            | super::super::shared_owner::CloudGetError::UncertainStore(primary),
                        )) => assert_eq!(primary, error),
                        _ => panic!("a secondary error masked the original Store action error"),
                    }
                    let healthy_expected = kind.expected(error) && secondary == 0;
                    assert_eq!(guard.writer.committed, healthy_expected);
                    assert_eq!(owner.failed_remote.load(SeqCst), !healthy_expected);
                    drop(guard);
                    let finished = writer.finish();
                    assert_eq!(finished.is_ok(), healthy_expected);
                }
            }
        }
    }
    #[test]
    #[cfg(any(unix, windows))]
    fn cloud_get_success_with_postview_failure_or_poststore_expiry_is_terminal() {
        for expired in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let store = cloud_domain_store(&root.path().join("post.sqlite"));
            let generation = store.authorization_state().unwrap().generation;
            let owner = OwnerDomain::new(generation);
            grant(&owner, generation);
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let mut writer = owner
                .announce(&operation, WriterClass::Remote, Intent::Mutation)
                .unwrap();
            let scope = writer
                .try_enter()
                .unwrap()
                .prepare_cloud_mutation_scope(&store)
                .unwrap();
            let plan = super::super::shared_owner::CloudGetPlan::synthetic_for_domain_test(
                &store,
                if expired { Some(1302) } else { None },
            );
            let mut guard = writer.try_enter().unwrap();
            guard.advance().unwrap();
            let post = if expired {
                StoreView::read(&store)
            } else {
                Err(lomi_host_store::StoreError::Storage)
            };
            let result = guard.observe_cloud_get_action(
                &scope,
                &plan,
                1004,
                super::super::shared_owner::CloudGetStoreAction::RecoveredAck,
                &store,
                Ok(()),
                post,
            );
            if expired {
                assert_eq!(
                    result,
                    Err(StepError::Source(
                        super::super::shared_owner::CloudGetError::Provider(
                            lomi_host_auth::Error::Expired
                        )
                    ))
                );
            } else {
                assert_eq!(
                    result,
                    Err(StepError::Source(
                        super::super::shared_owner::CloudGetError::UncertainStore(
                            lomi_host_store::StoreError::Storage
                        )
                    ))
                );
            }
            assert!(owner.failed_remote.load(SeqCst));
            assert!(!guard.writer.committed);
        }
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn cloud_read_clock_preserves_ready_and_authority_and_cancel_does_not_poison_fresh_read() {
        for cancelled in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let mut store = cloud_domain_store(&root.path().join("read.sqlite"));
            let generation = store.authorization_state().unwrap().generation;
            let owner = OwnerDomain::new(generation);
            grant(&owner, generation);
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let mut guard = owner.try_read(&operation).unwrap();
            let scope = guard.prepare_cloud_read(&store).unwrap();
            let captured = (
                scope.authority_revision,
                scope.generation,
                scope.deny_epoch,
                scope.issued,
            );
            let revision = guard.state.revision;
            assert_eq!(
                guard.checkpoint_cloud_read_clock(&scope, &mut store, 1004),
                Ok(1004)
            );
            assert_eq!(guard.state.revision, revision + 1);
            assert_eq!(guard.state.authority_revision, captured.0);
            assert_eq!(owner.pending.load(SeqCst), 0);
            assert!(guard.state.ready.is_some());
            if cancelled {
                cancel.store(true, SeqCst);
            } else {
                operation.expire_for_test();
            }
            assert_eq!(
                guard.checkpoint_cloud_read_clock(&scope, &mut store, 1005),
                Err(StepError::Domain(if cancelled {
                    Error::Cancelled
                } else {
                    Error::Deadline
                }))
            );
            assert!(!owner.failed_remote.load(SeqCst));
            drop(guard);
            let fresh_cancel = AtomicBool::new(false);
            let fresh = Operation::new(end(), &fresh_cancel);
            assert!(
                owner
                    .try_read(&fresh)
                    .unwrap()
                    .prepare_cloud_read(&store)
                    .is_ok()
            );
        }
    }
    #[test]
    #[cfg(any(unix, windows))]
    fn cloud_read_scope_rejects_changed_authority_announcement_deny_generation_and_wrong_identity()
    {
        for change in 0..7 {
            let root = tempfile::tempdir().unwrap();
            let mut store = cloud_domain_store(&root.path().join("read-scope.sqlite"));
            let generation = store.authorization_state().unwrap().generation;
            let owner = OwnerDomain::new(generation);
            grant(&owner, generation);
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let other_cancel = AtomicBool::new(false);
            let other = Operation::new(end(), &other_cancel);
            let foreign = OwnerDomain::new(generation);
            let mut guard = owner.try_read(&operation).unwrap();
            let mut scope = guard.prepare_cloud_read(&store).unwrap();
            match change {
                0 => guard.state.authority_revision += 1,
                1 => {
                    owner.issued.fetch_add(1, SeqCst);
                }
                2 => {
                    owner.deny_epoch.fetch_add(1, SeqCst);
                }
                3 => guard.state.generation += 1,
                4 => guard.state.ready = None,
                5 => scope.operation = &other,
                _ => scope.domain = &foreign,
            }
            assert_eq!(
                guard.checkpoint_cloud_read_clock(&scope, &mut store, 1004),
                Err(StepError::Domain(Error::Stale))
            );
            assert_eq!(store.authorization_state().unwrap().clock_floor, 0);
            assert!(!owner.failed_remote.load(SeqCst));
        }
    }
}

#[cfg(test)]
mod cloud_observed_failure_tests {
    use super::*;
    #[test]
    fn uncertain_observed_unlocked_view_permanently_denies_remote_and_preserves_action_error() {
        let owner = OwnerDomain::new(0);
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + std::time::Duration::from_secs(5), &cancel);
        let mut pending = owner
            .announce(&operation, WriterClass::Remote, Intent::Mutation)
            .unwrap();
        assert!(!owner.failed_remote.load(SeqCst));
        let view = StoreView {
            generation: 7,
            verified: Some(7),
            locked: false,
            pending_revoke: false,
        };
        let result = pending.try_enter().unwrap().commit_classified(|| {
            Err::<((), StoreView), _>(StoreFailure::UncertainObserved(
                "original-action-error",
                view,
            ))
        });
        assert_eq!(result, Err(StepError::Source("original-action-error")));
        assert!(owner.failed_remote.load(SeqCst));
        assert_eq!(owner.generation.load(SeqCst), 7);
        assert!(pending.finish().is_err());
        let guard = owner.try_read(&operation).unwrap();
        assert!(matches!(
            guard.capture_remote(|| Ok::<_, ()>(view)),
            Err(StepError::Domain(Error::Denied))
        ));
    }
}

#[cfg(any(unix, windows))]
pub(super) struct CloudGetSettlement {
    pub(super) decision: super::shared_owner::CloudGetDecision,
    pub(super) claim: Option<ClaimContinuation>,
}
// Dedicated Cloud Claim authority; never a normal-publication continuation.
// Owned private identities prevent operation/domain pointer ABA without copying
// cancellation state or admitting a replacement deadline.
#[cfg(any(unix, windows))]
pub(super) struct ClaimContinuation {
    domain_identity: std::sync::Arc<()>,
    operation_identity: OperationIdentity,
    authority_revision: u64,
    generation: u64,
    deny_epoch: u64,
    settled_get_ticket: u64,
    get_started: Instant,
}
#[cfg(any(unix, windows))]
impl ClaimContinuation {
    pub(super) fn get_started(&self) -> Instant {
        self.get_started
    }
}
#[cfg(any(unix, windows))]
impl OwnerDomain {
    fn check_claim(
        &self,
        state: &State,
        cap: &ClaimContinuation,
        operation: &Operation<'_>,
    ) -> Result<(), Error> {
        operation.check()?;
        if !std::sync::Arc::ptr_eq(&self.owner_identity, &cap.domain_identity)
            || !operation.is_same_admission(&cap.operation_identity)
            || self.failed_remote.load(SeqCst)
            || self.pending.load(SeqCst) != 0
            || self.issued.load(SeqCst) != cap.settled_get_ticket
            || state.authority_revision != cap.authority_revision
            || state.generation != cap.generation
            || self.deny_epoch.load(SeqCst) != cap.deny_epoch
            || self.generation_denied(cap.generation)
            || !state.ready.is_some_and(|ready| {
                ready.generation == cap.generation && ready.deny_epoch == cap.deny_epoch
            })
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
}
#[cfg(any(unix, windows))]
impl OwnerGuard<'_, '_> {
    pub(super) fn check_claim_send(
        &self,
        cap: &ClaimContinuation,
        store: &lomi_host_store::HostStore,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.domain
            .check_claim(&self.state, cap, self.operation)
            .map_err(StepError::Domain)?;
        let view = StoreView::read(store).map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        let floor = store
            .authorization_state()
            .map_err(|error| {
                self.domain.fail_remote();
                StepError::Source(error)
            })?
            .clock_floor;
        self.domain
            .check_claim(&self.state, cap, self.operation)
            .map_err(StepError::Domain)?;
        if view.generation != cap.generation
            || view.verified != Some(cap.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(StepError::Domain(Error::Stale));
        }
        Ok(floor)
    }
    pub(super) fn checkpoint_claim_clock(
        &mut self,
        cap: &ClaimContinuation,
        store: &mut lomi_host_store::HostStore,
        now: u64,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.check_claim_send(cap, store)?;
        self.state.revision = self.state.revision.checked_add(1).ok_or_else(|| {
            self.domain.fail_remote();
            StepError::Domain(Error::Exhausted)
        })?;
        let result = store.observe_authorization_clock(now);
        if result.is_err() {
            self.domain.fail_remote();
        }
        let post = self.check_claim_send(cap, store);
        match result {
            Err(error) => Err(StepError::Source(error)),
            Ok(floor) => {
                post?;
                Ok(floor)
            }
        }
    }
}

/// Locked/pending-revoke recovery only. This scope cannot verify, restore Ready,
/// install a runtime, acknowledge publication or authorize a Claim/PUT.
#[cfg(any(unix, windows))]
pub(super) struct LogoutRecoveryScope<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    authority_revision: u64,
    generation: u64,
    deny_epoch: u64,
    issued: u64,
}
#[cfg(any(unix, windows))]
impl OwnerDomain {
    fn check_logout_recovery(
        &self,
        state: &State,
        cap: &LogoutRecoveryScope<'_, '_>,
    ) -> Result<(), Error> {
        cap.operation.check()?;
        if !std::ptr::eq(self, cap.domain)
            || self.pending.load(SeqCst) != 0
            || self.issued.load(SeqCst) != cap.issued
            || state.authority_revision != cap.authority_revision
            || state.generation != cap.generation
            || self.deny_epoch.load(SeqCst) != cap.deny_epoch
            || state.ready.is_some()
        {
            return Err(Error::Stale);
        }
        // failed_remote is deliberately not cleared or treated as Ready.
        Ok(())
    }
}
#[cfg(any(unix, windows))]
impl<'d, 'o> OwnerGuard<'d, 'o> {
    pub(super) fn prepare_logout_recovery(
        &self,
        store: &lomi_host_store::HostStore,
    ) -> Result<LogoutRecoveryScope<'d, 'o>, StepError<lomi_host_store::StoreError>> {
        let cap = LogoutRecoveryScope {
            domain: self.domain,
            operation: self.operation,
            authority_revision: self.state.authority_revision,
            generation: self.state.generation,
            deny_epoch: self.domain.deny_epoch.load(SeqCst),
            issued: self.domain.issued.load(SeqCst),
        };
        self.check_logout_recovery_send(&cap, store)?;
        Ok(cap)
    }
    pub(super) fn check_logout_recovery_send(
        &self,
        cap: &LogoutRecoveryScope<'d, 'o>,
        store: &lomi_host_store::HostStore,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        if !std::ptr::eq(self.operation, cap.operation) {
            return Err(StepError::Domain(Error::Stale));
        }
        self.domain
            .check_logout_recovery(&self.state, cap)
            .map_err(StepError::Domain)?;
        let state = store.authorization_state().map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        self.domain
            .check_logout_recovery(&self.state, cap)
            .map_err(StepError::Domain)?;
        if state.generation != cap.generation || !state.locked || !state.pending_cloud_revoke {
            return Err(StepError::Domain(Error::Stale));
        }
        Ok(state.clock_floor)
    }
    pub(super) fn checkpoint_logout_recovery_clock(
        &mut self,
        cap: &LogoutRecoveryScope<'d, 'o>,
        store: &mut lomi_host_store::HostStore,
        now: u64,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.check_logout_recovery_send(cap, store)?;
        self.state.revision = self.state.revision.checked_add(1).ok_or_else(|| {
            self.domain.fail_remote();
            StepError::Domain(Error::Exhausted)
        })?;
        let result = store.observe_authorization_clock(now);
        if result.is_err() {
            self.domain.fail_remote();
        }
        let post = self.check_logout_recovery_send(cap, store);
        match result {
            Err(error) => Err(StepError::Source(error)),
            Ok(floor) => {
                post?;
                Ok(floor)
            }
        }
    }
}

// Dedicated Peer/Channel authority. Sealed original operation identity; neither
// eligibility nor a historical journal row can construct or renew this token.
pub(super) struct PeerContinuation {
    owner_identity: std::sync::Arc<()>,
    operation_identity: OperationIdentity,
    authority_revision: AtomicU64,
    generation: u64,
    deny_epoch: u64,
    issued: AtomicU64,
}
impl OwnerDomain {
    fn check_peer(
        &self,
        state: &State,
        cap: &PeerContinuation,
        operation: &Operation<'_>,
        ticket: Option<u64>,
    ) -> Result<(), Error> {
        cap.check_boundary(self, operation, ticket)?;
        if !std::sync::Arc::ptr_eq(&self.owner_identity, &cap.owner_identity)
            || state.authority_revision != cap.authority_revision.load(SeqCst)
            || state.generation != cap.generation
            || !state.ready.is_some_and(|ready| {
                ready.generation == cap.generation && ready.deny_epoch == cap.deny_epoch
            })
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
}
impl PeerContinuation {
    fn check_boundary(
        &self,
        domain: &OwnerDomain,
        operation: &Operation<'_>,
        ticket: Option<u64>,
    ) -> Result<(), Error> {
        operation.check()?;
        if !operation.is_same_admission(&self.operation_identity)
            || !std::sync::Arc::ptr_eq(&domain.owner_identity, &self.owner_identity)
        {
            return Err(Error::Stale);
        }
        let issued = match ticket {
            Some(ticket) if self.issued.load(SeqCst).checked_add(1) == Some(ticket) => ticket,
            Some(_) => return Err(Error::Stale),
            None => self.issued.load(SeqCst),
        };
        if domain.failed_remote.load(SeqCst)
            || domain.pending.load(SeqCst) != if ticket.is_some() { 1 } else { 0 }
            || domain.issued.load(SeqCst) != issued
            || domain.generation.load(SeqCst) != self.generation
            || domain.deny_epoch.load(SeqCst) != self.deny_epoch
            || domain.generation_denied(self.generation)
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub(super) fn check_effect_boundary(
        &self,
        domain: &OwnerDomain,
        operation: &Operation<'_>,
    ) -> Result<(), Error> {
        self.check_boundary(domain, operation, None)
    }
}
impl<'d, 'o> OwnerGuard<'d, 'o> {
    pub(super) fn prepare_peer_continuation(
        &self,
        store: &lomi_host_store::HostStore,
    ) -> Result<std::sync::Arc<PeerContinuation>, StepError<lomi_host_store::StoreError>> {
        let cap = std::sync::Arc::new(PeerContinuation {
            owner_identity: self.domain.owner_identity.clone(),
            operation_identity: self.operation.retained_identity(),
            authority_revision: AtomicU64::new(self.state.authority_revision),
            generation: self.state.generation,
            deny_epoch: self.domain.deny_epoch.load(SeqCst),
            issued: AtomicU64::new(self.domain.issued.load(SeqCst)),
        });
        self.check_peer_effect(&cap, store)?;
        Ok(cap)
    }
    pub(super) fn check_peer_effect(
        &self,
        cap: &PeerContinuation,
        store: &lomi_host_store::HostStore,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.domain
            .check_peer(&self.state, cap, self.operation, None)
            .map_err(StepError::Domain)?;
        let view = StoreView::read(store).map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        let floor = store
            .authorization_state()
            .map_err(|error| {
                self.domain.fail_remote();
                StepError::Source(error)
            })?
            .clock_floor;
        if view.generation != cap.generation
            || view.verified != Some(cap.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(StepError::Domain(Error::Stale));
        }
        self.domain
            .check_peer(&self.state, cap, self.operation, None)
            .map_err(StepError::Domain)?;
        Ok(floor)
    }
}
impl<'d, 'o> WriterGuard<'_, 'd, 'o> {
    pub(super) fn check_peer_journal(&self, cap: &PeerContinuation) -> Result<(), Error> {
        if !self
            .writer
            .operation
            .is_same_admission(&cap.operation_identity)
            || self.writer.class != WriterClass::Remote
        {
            return Err(Error::Stale);
        }
        self.writer.domain.check_peer(
            &self.state,
            cap,
            self.writer.operation,
            Some(self.writer.ticket),
        )
    }
    pub(super) fn settle_peer_journal(&self, cap: &PeerContinuation) -> Result<(), Error> {
        if !self.writer.committed {
            return Err(Error::Stale);
        }
        let expected = cap
            .authority_revision
            .load(SeqCst)
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        if self.state.authority_revision != expected
            || cap.issued.load(SeqCst).checked_add(1) != Some(self.writer.ticket)
        {
            return Err(Error::Stale);
        }
        // Only the named action's classified completion advances this original
        // token. No observation, provider response, Ready or new operation does.
        cap.authority_revision.store(expected, SeqCst);
        cap.issued.store(self.writer.ticket, SeqCst);
        Ok(())
    }
}

impl OwnerGuard<'_, '_> {
    pub(super) fn checkpoint_peer_clock(
        &mut self,
        cap: &PeerContinuation,
        store: &mut lomi_host_store::HostStore,
        now: u64,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.check_peer_effect(cap, store)?;
        self.state.revision = self
            .state
            .revision
            .checked_add(1)
            .ok_or(StepError::Domain(Error::Exhausted))?;
        let result = store.observe_authorization_clock(now);
        if result.is_err() {
            self.domain.fail_remote();
        }
        let checked = self.check_peer_effect(cap, store);
        match result {
            Err(error) => Err(StepError::Source(error)),
            Ok(floor) => {
                checked?;
                Ok(floor)
            }
        }
    }
}

// Fixed Shared rename transition. This does not renew generic PeerContinuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RemoteRenamePhase {
    StoreNotCalled,
    KnownNoEffect,
    /// Effect operations only: the operation is durably Running and this exact
    /// announcement still owns the single permit. Domain/Store are released so
    /// the OS effect can run; it never becomes abandonable or committed here.
    Started,
    Committed,
    Uncertain,
}
struct RemoteRenameScope<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    identity: OperationIdentity,
    owner_identity: std::sync::Arc<()>,
    ticket: u64,
    authority_revision: u64,
    generation: u64,
    deny_epoch: u64,
    absolute_expiry: Instant,
}
pub(super) struct RemoteRenameWrite<'d, 'o> {
    pending: Option<PendingWriter<'d, 'o>>,
    scope: RemoteRenameScope<'d, 'o>,
    phase: RemoteRenamePhase,
}
pub(super) struct RemoteRenameGuard<'w, 'd, 'o> {
    guard: WriterGuard<'w, 'd, 'o>,
    scope: &'w mut RemoteRenameScope<'d, 'o>,
    phase: &'w mut RemoteRenamePhase,
}
pub(super) struct RemoteRenameReceiptStamp<'d, 'o> {
    scope: RemoteRenameScope<'d, 'o>,
}
pub(super) struct RemoteRenameReceiptWatcher<'d, 'o> {
    stamp: RemoteRenameReceiptStamp<'d, 'o>,
}

/// One exact remote operation-cancellation writer. The actual Shared
/// announcement is registered while the verified remote OwnerGuard is still
/// held, then retained across pre-Store contention retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RemoteOperationCancelPhase {
    StoreNotCalled,
    KnownNoEffect,
    Committed,
    Uncertain,
}
struct RemoteOperationCancelScope<'d, 'o> {
    domain: &'d OwnerDomain,
    operation: &'o Operation<'o>,
    identity: OperationIdentity,
    owner_identity: std::sync::Arc<()>,
    ticket: u64,
    authority_revision: u64,
    generation: u64,
    deny_epoch: u64,
    absolute_expiry: Instant,
}
pub(super) struct RemoteOperationCancelWrite<'d, 'o> {
    pending: Option<PendingWriter<'d, 'o>>,
    scope: RemoteOperationCancelScope<'d, 'o>,
    phase: RemoteOperationCancelPhase,
}
pub(super) struct RemoteOperationCancelGuard<'w, 'd, 'o> {
    guard: WriterGuard<'w, 'd, 'o>,
    scope: &'w mut RemoteOperationCancelScope<'d, 'o>,
    phase: &'w mut RemoteOperationCancelPhase,
}

impl RemoteOperationCancelScope<'_, '_> {
    fn check_time(&self) -> Result<(), Error> {
        self.operation.check()?;
        if Instant::now() >= self.absolute_expiry {
            return Err(Error::Deadline);
        }
        Ok(())
    }

    fn common(&self) -> Result<(), Error> {
        self.check_time()?;
        if !std::sync::Arc::ptr_eq(&self.owner_identity, &self.domain.owner_identity)
            || !self.operation.is_same_admission(&self.identity)
            || self.domain.failed_remote.load(SeqCst)
            || self.domain.generation.load(SeqCst) != self.generation
            || self.domain.deny_epoch.load(SeqCst) != self.deny_epoch
            || self.domain.generation_denied(self.generation)
            || self.domain.issued.load(SeqCst) != self.ticket
        {
            return Err(Error::Stale);
        }
        Ok(())
    }

    fn check_writer(&self, state: &State) -> Result<(), Error> {
        if self.domain.pending.load(SeqCst) != 1
            || self.domain.shared_pending.load(SeqCst) != 1
            || state.generation != self.generation
            || state.authority_revision != self.authority_revision
            || !state.ready.is_some_and(|ready| {
                ready.generation == self.generation && ready.deny_epoch == self.deny_epoch
            })
        {
            return Err(Error::Stale);
        }
        // Read the exact issued ticket after the counters. A completed later
        // announcement cannot pass this check even if it releases quickly.
        self.common()
    }

    fn check_after_commit(&self, state: &State) -> Result<(), Error> {
        self.common()?;
        if self.domain.pending.load(SeqCst) != 1
            || self.domain.shared_pending.load(SeqCst) != 1
            || state.generation != self.generation
            || state.authority_revision
                != self
                    .authority_revision
                    .checked_add(1)
                    .ok_or(Error::Exhausted)?
            || !state.ready.is_some_and(|ready| {
                ready.generation == self.generation && ready.deny_epoch == self.deny_epoch
            })
        {
            return Err(Error::Stale);
        }
        self.common()
    }
}

impl<'d, 'o> OwnerGuard<'d, 'o> {
    /// Register this narrow Shared cancellation writer before dropping the
    /// exact current remote guard. The resulting ticket can only be used for
    /// one operation-cancel Store call under a re-entered writer guard.
    pub(super) fn begin_remote_operation_cancel(
        self,
        snapshot: Snapshot<'d, 'o>,
        peer: &PeerContinuation,
        absolute_expiry: Instant,
    ) -> Result<RemoteOperationCancelWrite<'d, 'o>, Error> {
        if snapshot.policy != Policy::Remote {
            return Err(Error::Denied);
        }
        self.operation.check()?;
        if Instant::now() >= absolute_expiry {
            return Err(Error::Deadline);
        }
        self.check(&snapshot)?;
        self.domain
            .check_peer(&self.state, peer, self.operation, None)?;
        let expected_ticket = peer
            .issued
            .load(SeqCst)
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let pending =
            self.domain
                .register_writer(self.operation, WriterClass::Shared, Intent::Mutation)?;
        if pending.ticket != expected_ticket {
            let mut pending = pending;
            pending.release();
            return Err(Error::Stale);
        }
        let write = RemoteOperationCancelWrite {
            scope: RemoteOperationCancelScope {
                domain: self.domain,
                operation: self.operation,
                identity: self.operation.retained_identity(),
                owner_identity: self.domain.owner_identity.clone(),
                ticket: pending.ticket,
                authority_revision: self.state.authority_revision,
                generation: self.state.generation,
                deny_epoch: self.domain.deny_epoch.load(SeqCst),
                absolute_expiry: absolute_expiry.min(self.operation.deadline()),
            },
            pending: Some(pending),
            phase: RemoteOperationCancelPhase::StoreNotCalled,
        };
        if let Err(error) = write.scope.check_writer(&self.state) {
            write.abandon()?;
            return Err(error);
        }
        Ok(write)
    }
}
impl<'d, 'o> OwnerGuard<'d, 'o> {
    /// Register the actual Shared writer before releasing this current reader.
    /// The caller supplied expiry is already sealed from original crypto proof;
    /// this layer additionally prevents exceeding the original Operation budget.
    pub(super) fn begin_remote_rename(
        self,
        snapshot: Snapshot<'d, 'o>,
        peer: &PeerContinuation,
        absolute_expiry: Instant,
    ) -> Result<RemoteRenameWrite<'d, 'o>, Error> {
        if snapshot.policy != Policy::Remote {
            return Err(Error::Denied);
        }
        self.operation.check()?;
        if Instant::now() >= absolute_expiry {
            return Err(Error::Deadline);
        }
        self.check(&snapshot)?;
        self.domain
            .check_peer(&self.state, peer, self.operation, None)?;
        let previous_issued = peer.issued.load(SeqCst);
        let expected_ticket = previous_issued.checked_add(1).ok_or(Error::Exhausted)?;
        let pending =
            self.domain
                .register_writer(self.operation, WriterClass::Shared, Intent::Mutation)?;
        let write = RemoteRenameWrite {
            scope: RemoteRenameScope {
                domain: self.domain,
                operation: self.operation,
                identity: self.operation.retained_identity(),
                owner_identity: self.domain.owner_identity.clone(),
                ticket: pending.ticket,
                authority_revision: self.state.authority_revision,
                generation: self.state.generation,
                deny_epoch: self.domain.deny_epoch.load(SeqCst),
                absolute_expiry: absolute_expiry.min(self.operation.deadline()),
            },
            pending: Some(pending),
            phase: RemoteRenamePhase::StoreNotCalled,
        };
        let checked = if write.scope.ticket != expected_ticket {
            Err(Error::Stale)
        } else {
            write.scope.check_writer(&self.state)
        };
        if let Err(error) = checked {
            // No Store call occurred. Release only this actual owned announcement.
            write.abandon()?;
            return Err(error);
        }
        Ok(write)
    }

    /// Register one Shared mutation announcement that may outlive this owner
    /// turn. The returned ticket is only Git-specific; it retains the original
    /// admission identity/deadline/cancellation and the exact Shared writer
    /// counters. The caller must persist its intent before using its gate.
    pub(super) fn begin_remote_git_writer(
        self,
        snapshot: Snapshot<'_, '_>,
        peer: &PeerContinuation,
        hard_expiry: Instant,
        heartbeat_expiry: Instant,
        peer_expiry: Instant,
        cancellation: &AtomicBool,
        domain_owner: std::sync::Arc<OwnerDomain>,
    ) -> Result<RemoteGitWriterLease, Error> {
        if !std::ptr::eq(self.domain, domain_owner.as_ref()) {
            return Err(Error::Stale);
        }
        if snapshot.policy != Policy::Remote {
            return Err(Error::Denied);
        }
        self.operation.check()?;
        let monotonic_origin = Instant::now();
        if monotonic_origin >= hard_expiry
            || monotonic_origin >= heartbeat_expiry
            || monotonic_origin >= peer_expiry
            || !std::ptr::eq(self.operation.cancellation_latch(), cancellation)
        {
            return Err(Error::Deadline);
        }
        let hard_expiry_ticks = monotonic_ticks(monotonic_origin, hard_expiry)?.min(
            monotonic_ticks(monotonic_origin, self.operation.deadline())?,
        );
        let heartbeat_expiry_ticks =
            monotonic_ticks(monotonic_origin, heartbeat_expiry)?.min(hard_expiry_ticks);
        let peer_expiry_ticks = monotonic_ticks(monotonic_origin, peer_expiry)?
            .min(heartbeat_expiry_ticks)
            .min(hard_expiry_ticks);
        self.check(&snapshot)?;
        self.domain
            .check_peer(&self.state, peer, self.operation, None)?;
        let previous_issued = peer.issued.load(SeqCst);
        let expected_ticket = previous_issued.checked_add(1).ok_or(Error::Exhausted)?;
        let pending =
            self.domain
                .register_writer(self.operation, WriterClass::Shared, Intent::Mutation)?;
        if pending.ticket != expected_ticket {
            let mut pending = pending;
            pending.release();
            return Err(Error::Stale);
        }
        let generation = self.state.generation;
        let authority_revision = self.state.authority_revision;
        let deny_epoch = self.domain.deny_epoch.load(SeqCst);
        let ticket = pending.ticket;
        let identity = self.operation.retained_identity();
        let sticky_cancel = self.operation.sticky_cancellation();
        let owner_identity = self.domain.owner_identity.clone();
        // Transfer the already-counted announcement into a move-only lease.
        // Its Drop releases these counters and fences if Started was not
        // durably completed.
        let mut pending = pending;
        pending.active = false;
        let core = std::sync::Arc::new(RemoteGitWriterCore {
            identity,
            owner_identity,
            ticket,
            generation,
            deny_epoch,
            pending: self.domain.pending.clone(),
            shared_pending: self.domain.shared_pending.clone(),
            issued: self.domain.issued.clone(),
            current_generation: self.domain.generation.clone(),
            current_deny_epoch: self.domain.deny_epoch.clone(),
            deny_floor: self.domain.deny_floor.clone(),
            revoked_through: self.domain.revoked_through.clone(),
            failed_remote: self.domain.failed_remote.clone(),
            authority_revision: AtomicU64::new(authority_revision),
            monotonic_origin,
            hard_expiry_ticks,
            heartbeat_expiry_ticks: AtomicU64::new(heartbeat_expiry_ticks),
            heartbeat_started_ticks: AtomicU64::new(0),
            peer_expiry_ticks: AtomicU64::new(peer_expiry_ticks),
            peer_started_ticks: AtomicU64::new(0),
            deadline: self.operation.deadline(),
            sticky_cancel: sticky_cancel.clone(),
            phase: AtomicU64::new(RemoteGitWriterPhase::Prepared as u64),
            active: AtomicBool::new(true),
            released: AtomicBool::new(false),
        });
        Ok(RemoteGitWriterLease {
            domain: domain_owner,
            sticky_cancellation: sticky_cancel,
            core,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum RemoteGitWriterPhase {
    Prepared = 1,
    Started = 2,
    Uncertain = 3,
    Committed = 4,
    Abandoned = 5,
}

struct RemoteGitWriterCore {
    identity: OperationIdentity,
    owner_identity: std::sync::Arc<()>,
    ticket: u64,
    generation: u64,
    deny_epoch: u64,
    pending: std::sync::Arc<AtomicU64>,
    shared_pending: std::sync::Arc<AtomicU64>,
    issued: std::sync::Arc<AtomicU64>,
    current_generation: std::sync::Arc<AtomicU64>,
    current_deny_epoch: std::sync::Arc<AtomicU64>,
    deny_floor: std::sync::Arc<AtomicU64>,
    revoked_through: std::sync::Arc<AtomicU64>,
    failed_remote: std::sync::Arc<AtomicBool>,
    authority_revision: AtomicU64,
    monotonic_origin: Instant,
    hard_expiry_ticks: u64,
    heartbeat_expiry_ticks: AtomicU64,
    heartbeat_started_ticks: AtomicU64,
    peer_expiry_ticks: AtomicU64,
    peer_started_ticks: AtomicU64,
    deadline: Instant,
    sticky_cancel: std::sync::Arc<AtomicBool>,
    phase: AtomicU64,
    active: AtomicBool,
    released: AtomicBool,
}
impl RemoteGitWriterCore {
    fn phase(&self) -> RemoteGitWriterPhase {
        match self.phase.load(SeqCst) {
            1 => RemoteGitWriterPhase::Prepared,
            2 => RemoteGitWriterPhase::Started,
            3 => RemoteGitWriterPhase::Uncertain,
            4 => RemoteGitWriterPhase::Committed,
            _ => RemoteGitWriterPhase::Abandoned,
        }
    }
    fn check_time(&self) -> Result<(), Error> {
        if self.sticky_cancel.load(SeqCst) {
            return Err(Error::Cancelled);
        }
        let now = Instant::now();
        if now >= self.deadline {
            return Err(Error::Deadline);
        }
        let elapsed = now
            .checked_duration_since(self.monotonic_origin)
            .ok_or(Error::Deadline)?
            .as_nanos();
        if elapsed >= u128::from(self.hard_expiry_ticks)
            || elapsed >= u128::from(self.heartbeat_expiry_ticks.load(SeqCst))
            || elapsed >= u128::from(self.peer_expiry_ticks.load(SeqCst))
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn heartbeat_deadline(&self) -> Instant {
        self.monotonic_origin
            + std::time::Duration::from_nanos(self.heartbeat_expiry_ticks.load(SeqCst))
    }
    fn hard_deadline(&self) -> Instant {
        self.monotonic_origin + std::time::Duration::from_nanos(self.hard_expiry_ticks)
    }
    fn peer_deadline(&self) -> Instant {
        self.monotonic_origin + std::time::Duration::from_nanos(self.peer_expiry_ticks.load(SeqCst))
    }
    fn renew_heartbeat(
        &self,
        request_started: Instant,
        lease_ms: u64,
        freshness_ms: u64,
    ) -> Result<(), Error> {
        self.common()?;
        if lease_ms == 0
            || lease_ms > 30_000
            || freshness_ms == 0
            || freshness_ms > 5_000
            || freshness_ms > lease_ms
        {
            return Err(Error::Denied);
        }
        let started_ticks = monotonic_ticks(self.monotonic_origin, request_started)?;
        let prior_started = self.heartbeat_started_ticks.load(SeqCst);
        if started_ticks <= prior_started || request_started >= self.heartbeat_deadline() {
            return Err(Error::Stale);
        }
        let refreshed = request_started
            .checked_add(std::time::Duration::from_millis(freshness_ms))
            .ok_or(Error::Deadline)?;
        let expiry_ticks =
            monotonic_ticks(self.monotonic_origin, refreshed)?.min(self.hard_expiry_ticks);
        if Instant::now() >= refreshed || expiry_ticks <= started_ticks {
            return Err(Error::Deadline);
        }
        self.heartbeat_started_ticks
            .compare_exchange(prior_started, started_ticks, SeqCst, SeqCst)
            .map_err(|_| Error::Stale)?;
        self.heartbeat_expiry_ticks.store(expiry_ticks, SeqCst);
        self.common()
    }
    fn renew_peer_observation(
        &self,
        request_started: Instant,
        peer_expiry: Instant,
    ) -> Result<(), Error> {
        self.common()?;
        let started_ticks = monotonic_ticks(self.monotonic_origin, request_started)?;
        let prior_started = self.peer_started_ticks.load(SeqCst);
        if started_ticks <= prior_started || request_started >= self.peer_deadline() {
            return Err(Error::Stale);
        }
        let expiry_ticks = monotonic_ticks(self.monotonic_origin, peer_expiry)?
            .min(self.heartbeat_expiry_ticks.load(SeqCst))
            .min(self.hard_expiry_ticks);
        if Instant::now() >= peer_expiry || expiry_ticks <= started_ticks {
            return Err(Error::Deadline);
        }
        self.peer_started_ticks
            .compare_exchange(prior_started, started_ticks, SeqCst, SeqCst)
            .map_err(|_| Error::Stale)?;
        self.peer_expiry_ticks.store(expiry_ticks, SeqCst);
        self.common()
    }
    fn common(&self) -> Result<(), Error> {
        self.check_time()?;
        if !self.active.load(SeqCst)
            || self.failed_remote.load(SeqCst)
            || self.current_generation.load(SeqCst) != self.generation
            || self.current_deny_epoch.load(SeqCst) != self.deny_epoch
            || (self.current_deny_epoch.load(SeqCst) != 0
                && (self.generation < self.deny_floor.load(SeqCst)
                    || self.generation <= self.revoked_through.load(SeqCst)))
            || self.issued.load(SeqCst) != self.ticket
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn common_after_release(&self) -> Result<(), Error> {
        self.check_time()?;
        if self.active.load(SeqCst)
            || !self.released.load(SeqCst)
            || self.failed_remote.load(SeqCst)
            || self.current_generation.load(SeqCst) != self.generation
            || self.current_deny_epoch.load(SeqCst) != self.deny_epoch
            || (self.current_deny_epoch.load(SeqCst) != 0
                && (self.generation < self.deny_floor.load(SeqCst)
                    || self.generation <= self.revoked_through.load(SeqCst)))
            || self.issued.load(SeqCst) != self.ticket
        {
            return Err(Error::Stale);
        }
        if self.pending.load(SeqCst) != 0 || self.shared_pending.load(SeqCst) != 0 {
            return Err(Error::Stale);
        }
        // A writer can announce, commit and release between the ticket read
        // above and the zero-pending reads. Recheck the authority epochs and
        // ticket after observing the drained counters so a completed later
        // writer cannot leave this receipt watcher looking current.
        self.check_time()?;
        if self.active.load(SeqCst)
            || !self.released.load(SeqCst)
            || self.failed_remote.load(SeqCst)
            || self.current_generation.load(SeqCst) != self.generation
            || self.current_deny_epoch.load(SeqCst) != self.deny_epoch
            || (self.current_deny_epoch.load(SeqCst) != 0
                && (self.generation < self.deny_floor.load(SeqCst)
                    || self.generation <= self.revoked_through.load(SeqCst)))
            || self.issued.load(SeqCst) != self.ticket
        {
            return Err(Error::Stale);
        }
        self.check_time()?;
        Ok(())
    }
    fn check_lock_free(&self) -> Result<(), Error> {
        self.common()?;
        if self.pending.load(SeqCst) != 1 || self.shared_pending.load(SeqCst) != 1 {
            return Err(Error::Stale);
        }
        self.common()
    }
    fn check_writer(&self, state: &State) -> Result<(), Error> {
        self.check_writer_revision(state, self.authority_revision.load(SeqCst))
    }
    fn check_writer_revision(&self, state: &State, revision: u64) -> Result<(), Error> {
        self.common()?;
        if self.pending.load(SeqCst) != 1
            || self.shared_pending.load(SeqCst) != 1
            || state.generation != self.generation
            || state.authority_revision != revision
            || !state
                .ready
                .is_some_and(|r| r.generation == self.generation && r.deny_epoch == self.deny_epoch)
        {
            return Err(Error::Stale);
        }
        self.common()
    }
    fn release(&self, fail_started: bool) {
        if self.released.swap(true, SeqCst) {
            return;
        }
        if fail_started
            && matches!(
                self.phase(),
                RemoteGitWriterPhase::Started | RemoteGitWriterPhase::Uncertain
            )
        {
            self.failed_remote.store(true, SeqCst);
        }
        self.active.store(false, SeqCst);
        if self
            .shared_pending
            .fetch_update(SeqCst, SeqCst, |old| old.checked_sub(1))
            .is_err()
            || self
                .pending
                .fetch_update(SeqCst, SeqCst, |old| old.checked_sub(1))
                .is_err()
        {
            self.failed_remote.store(true, SeqCst);
        }
    }
}

/// Cloneable, lock-free publication gate. A worker holding only this gate
/// cannot release the actual owner announcement; only the retained lease can.
#[derive(Clone)]
pub(super) struct RemoteGitWriterGate {
    core: std::sync::Arc<RemoteGitWriterCore>,
}
impl RemoteGitWriterGate {
    pub(super) fn current(&self) -> bool {
        self.core.phase() == RemoteGitWriterPhase::Started && self.core.check_lock_free().is_ok()
    }
}

/// Actual auth-worker latches carried into a Started-only terminal turn. This
/// value is constructed from Runtime, never from remote or local IPC input.
#[derive(Clone, Copy)]
pub(super) struct StartedGitTerminalLatches<'a> {
    gate_denied: &'a AtomicBool,
    paused: &'a AtomicBool,
    stopping: &'a AtomicBool,
    public_pending: &'a AtomicBool,
}
impl<'a> StartedGitTerminalLatches<'a> {
    pub(super) fn from_runtime(
        gate_denied: &'a AtomicBool,
        paused: &'a AtomicBool,
        stopping: &'a AtomicBool,
        public_pending: &'a AtomicBool,
    ) -> StartedGitTerminalLatches<'a> {
        StartedGitTerminalLatches {
            gate_denied,
            paused,
            stopping,
            public_pending,
        }
    }
    pub(super) fn gate_denied(&self) -> &'a AtomicBool {
        self.gate_denied
    }
    pub(super) fn paused(&self) -> &'a AtomicBool {
        self.paused
    }
    pub(super) fn stopping(&self) -> &'a AtomicBool {
        self.stopping
    }
    pub(super) fn current(&self) -> bool {
        !self.gate_denied.load(std::sync::atomic::Ordering::Acquire)
            && !self.paused.load(std::sync::atomic::Ordering::Acquire)
            && !self.stopping.load(std::sync::atomic::Ordering::Acquire)
            && !self
                .public_pending
                .load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Move-only owner continuation retained by the encrypted Git request.
#[must_use]
pub(super) struct RemoteGitWriterLease {
    domain: std::sync::Arc<OwnerDomain>,
    sticky_cancellation: std::sync::Arc<AtomicBool>,
    core: std::sync::Arc<RemoteGitWriterCore>,
}
impl RemoteGitWriterLease {
    pub(super) fn gate(&self) -> RemoteGitWriterGate {
        RemoteGitWriterGate {
            core: self.core.clone(),
        }
    }
    pub(super) fn control(&self) -> RemoteGitWriterControl {
        RemoteGitWriterControl {
            domain: self.domain.clone(),
            core: self.core.clone(),
        }
    }
    pub(super) fn current(&self) -> bool {
        self.core.phase() == RemoteGitWriterPhase::Started && self.core.check_lock_free().is_ok()
    }
    pub(super) fn is_started(&self) -> bool {
        self.core.phase() == RemoteGitWriterPhase::Started
    }
    pub(super) fn try_enter<'w, 'o>(
        &'w mut self,
        operation: &'o Operation<'o>,
    ) -> Result<RemoteGitWriterGuard<'w, 'o>, Error> {
        self.core.check_time()?;
        if !operation.is_same_admission(&self.core.identity)
            || !std::sync::Arc::ptr_eq(&operation.sticky_cancellation(), &self.sticky_cancellation)
            || !std::sync::Arc::ptr_eq(&self.domain.owner_identity, &self.core.owner_identity)
        {
            return Err(Error::Stale);
        }
        operation.check()?;
        let state = self.domain.lock(operation)?;
        self.core.check_writer(&state)?;
        Ok(RemoteGitWriterGuard {
            core: &self.core,
            domain: &self.domain,
            operation,
            state,
        })
    }
    pub(super) fn finish(self) -> Result<(), Error> {
        if self.core.phase() != RemoteGitWriterPhase::Committed {
            return Err(Error::Unfinished);
        }
        self.core.common()?;
        self.core.release(false);
        if self.core.pending.load(SeqCst) != 0 || self.core.shared_pending.load(SeqCst) != 0 {
            self.core.failed_remote.store(true, SeqCst);
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Release a completed Git writer while retaining an attenuated witness
    /// for its one exact durable receipt. The witness cannot start or extend a
    /// writer and becomes stale on any later owner/policy revision.
    pub(super) fn finish_receipt(self) -> Result<RemoteGitWriterReceiptWatcher, Error> {
        if self.core.phase() != RemoteGitWriterPhase::Committed {
            return Err(Error::Unfinished);
        }
        self.core.common()?;
        let authority_revision = self.core.authority_revision.load(SeqCst);
        self.core.release(false);
        self.core.common_after_release()?;
        Ok(RemoteGitWriterReceiptWatcher {
            domain: self.domain.clone(),
            core: self.core.clone(),
            authority_revision,
        })
    }
}

/// Exact Started Git control-plane continuation. It can validate and renew
/// only the lease that created it; it cannot release the writer or admit work.
#[derive(Clone)]
pub(super) struct RemoteGitWriterControl {
    domain: std::sync::Arc<OwnerDomain>,
    core: std::sync::Arc<RemoteGitWriterCore>,
}
impl RemoteGitWriterControl {
    pub(super) fn same_writer(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.domain, &other.domain)
            && std::sync::Arc::ptr_eq(&self.core, &other.core)
    }
    pub(super) fn current(&self) -> bool {
        self.core.phase() == RemoteGitWriterPhase::Started && self.core.check_lock_free().is_ok()
    }
    pub(super) fn authority_revision(&self) -> u64 {
        self.core.authority_revision.load(SeqCst)
    }
    pub(super) fn current_at_revision(&self, revision: u64) -> bool {
        self.authority_revision() == revision && self.current()
    }
    fn check_state(
        &self,
        domain: &OwnerDomain,
        operation: &Operation<'_>,
        state: &State,
    ) -> Result<(), Error> {
        if !self.matches_operation(operation) {
            return Err(Error::Stale);
        }
        self.check_state_current(domain, state)
    }
    fn check_state_current(&self, domain: &OwnerDomain, state: &State) -> Result<(), Error> {
        if !self.belongs_to(domain) || !self.current() {
            return Err(Error::Stale);
        }
        self.core
            .check_writer_revision(state, self.core.authority_revision.load(SeqCst))
    }
    pub(super) fn matches_operation(&self, operation: &Operation<'_>) -> bool {
        operation.is_same_admission(&self.core.identity)
            && std::ptr::eq(
                self.domain.owner_identity.as_ref(),
                self.core.owner_identity.as_ref(),
            )
    }
    pub(super) fn belongs_to(&self, domain: &OwnerDomain) -> bool {
        std::ptr::eq(
            domain.owner_identity.as_ref(),
            self.core.owner_identity.as_ref(),
        )
    }
    pub(super) fn hard_deadline(&self) -> Instant {
        self.core.hard_deadline()
    }
    pub(super) fn heartbeat_deadline(&self) -> Instant {
        self.core.heartbeat_deadline()
    }
    pub(super) fn peer_deadline(&self) -> Instant {
        self.core.peer_deadline()
    }
    pub(super) fn renew_heartbeat(
        &self,
        operation: &Operation<'_>,
        request_started: Instant,
        lease_ms: u64,
        freshness_ms: u64,
    ) -> Result<(), Error> {
        if !self.matches_operation(operation) || !self.current() {
            return Err(Error::Stale);
        }
        self.core
            .renew_heartbeat(request_started, lease_ms, freshness_ms)
    }
    pub(super) fn renew_peer_observation(
        &self,
        operation: &Operation<'_>,
        request_started: Instant,
        peer_expiry: Instant,
    ) -> Result<(), Error> {
        if !self.matches_operation(operation) || !self.current() {
            return Err(Error::Stale);
        }
        self.core
            .renew_peer_observation(request_started, peer_expiry)
    }
    pub(super) fn invalidate(&self) {
        self.core.sticky_cancel.store(true, SeqCst);
    }
}
pub(super) struct RemoteGitWriterReceiptWatcher {
    domain: std::sync::Arc<OwnerDomain>,
    core: std::sync::Arc<RemoteGitWriterCore>,
    authority_revision: u64,
}
impl RemoteGitWriterReceiptWatcher {
    pub(super) fn check(&self) -> Result<(), Error> {
        self.core.common_after_release()?;
        if self.core.phase() != RemoteGitWriterPhase::Committed
            || self.core.authority_revision.load(SeqCst) != self.authority_revision
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub(super) fn deadline(&self) -> Instant {
        self.core
            .heartbeat_deadline()
            .min(self.core.hard_deadline())
            .min(self.core.deadline)
    }
    pub(super) fn validate(
        &self,
        guard: &OwnerGuard<'_, '_>,
        store: &lomi_host_store::HostStore,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.check().map_err(StepError::Domain)?;
        if !std::ptr::eq(self.domain.as_ref(), guard.domain)
            || !guard.operation.is_same_admission(&self.core.identity)
            || guard.state.generation != self.core.generation
            || guard.state.authority_revision != self.authority_revision
            || !guard.state.ready.is_some_and(|ready| {
                ready.generation == self.core.generation && ready.deny_epoch == self.core.deny_epoch
            })
        {
            return Err(StepError::Domain(Error::Stale));
        }
        let view = StoreView::read(store).map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        if view.generation != self.core.generation
            || view.verified != Some(view.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(StepError::Domain(Error::Stale));
        }
        let floor = store
            .authorization_state()
            .map(|state| state.clock_floor)
            .map_err(|error| {
                self.domain.fail_remote();
                StepError::Source(error)
            })?;
        self.check().map_err(StepError::Domain)?;
        Ok(floor)
    }
}
impl Drop for RemoteGitWriterLease {
    fn drop(&mut self) {
        self.core.release(true);
    }
}

pub(super) struct RemoteGitWriterGuard<'w, 'o> {
    core: &'w RemoteGitWriterCore,
    domain: &'w OwnerDomain,
    operation: &'o Operation<'o>,
    state: MutexGuard<'w, State>,
}
impl RemoteGitWriterGuard<'_, '_> {
    fn advance(&mut self) -> Result<(), Error> {
        self.core.check_writer(&self.state)?;
        let revision = self.state.revision.checked_add(1).ok_or(Error::Exhausted)?;
        let authority = self
            .state
            .authority_revision
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.state.revision = revision;
        self.state.authority_revision = authority;
        Ok(())
    }
    fn observe(&mut self, view: StoreView) -> Result<(), Error> {
        if view.generation < self.state.generation {
            self.domain.fail_remote();
            return Err(Error::Stale);
        }
        self.state.generation = view.generation;
        self.domain.generation.store(view.generation, SeqCst);
        if self
            .state
            .ready
            .is_some_and(|ready| ready.generation != view.generation)
            || view.locked
            || view.pending_revoke
        {
            self.state.ready = None;
        }
        Ok(())
    }
    fn postview(
        &mut self,
        store: &lomi_host_store::HostStore,
    ) -> Result<(), StepError<lomi_host_store::StoreError>> {
        let view = StoreView::read(store).map_err(|error| {
            self.domain.fail_remote();
            StepError::Source(error)
        })?;
        let valid = view.generation == self.core.generation
            && view.verified == Some(view.generation)
            && !view.locked
            && !view.pending_revoke;
        self.observe(view).map_err(StepError::Domain)?;
        if !valid {
            self.domain.fail_remote();
            return Err(StepError::Domain(Error::Stale));
        }
        Ok(())
    }
    pub(super) fn start_external(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        binding: &lomi_host_store::OperationBinding,
        expected_revision: lomi_remote_protocol::DecimalU64,
        permit: &mut Option<lomi_host_store::ExternalPermit>,
    ) -> Result<lomi_host_store::Admission, StepError<lomi_host_store::StoreError>> {
        use lomi_host_store::StoreError;
        self.operation.check().map_err(StepError::Domain)?;
        self.core
            .check_writer(&self.state)
            .map_err(StepError::Domain)?;
        if self.core.phase() != RemoteGitWriterPhase::Prepared {
            return Err(StepError::Domain(Error::Stale));
        }
        self.advance().map_err(StepError::Domain)?;
        self.core
            .phase
            .store(RemoteGitWriterPhase::Uncertain as u64, SeqCst);
        let outcome = store.admit_start_external(binding, expected_revision);
        let outcome = match outcome {
            Ok((admission, started)) => {
                *permit = started;
                Ok(admission)
            }
            Err(error) => Err(error),
        };
        match &outcome {
            Ok(admission)
                if admission.newly_admitted
                    && permit.is_some()
                    && admission.receipt.state()
                        == lomi_remote_protocol::OperationState::Running
                    && admission.receipt.effect() == lomi_remote_protocol::Effect::None => {}
            Err(
                StoreError::RevisionConflict
                | StoreError::IdempotencyConflict
                | StoreError::NotFound
                | StoreError::ResourceExhausted
                | StoreError::Invalid
                | StoreError::Fenced,
            ) => {
                self.core
                    .phase
                    .store(RemoteGitWriterPhase::Prepared as u64, SeqCst);
            }
            _ => self.domain.fail_remote(),
        }
        let post = self.postview(store);
        let admission = outcome.map_err(StepError::Source)?;
        post?;
        if !admission.newly_admitted || permit.is_none() {
            return Err(StepError::Source(StoreError::AlreadyStarted));
        }
        self.operation.check().map_err(StepError::Domain)?;
        let revision = self
            .core
            .authority_revision
            .load(SeqCst)
            .checked_add(1)
            .ok_or(StepError::Domain(Error::Exhausted))?;
        if self
            .core
            .check_writer_revision(&self.state, revision)
            .is_err()
        {
            self.domain.fail_remote();
            return Err(StepError::Domain(Error::Stale));
        }
        self.core.authority_revision.store(revision, SeqCst);
        self.core
            .phase
            .store(RemoteGitWriterPhase::Started as u64, SeqCst);
        Ok(admission)
    }
    pub(super) fn complete_external(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        permit: &lomi_host_store::ExternalPermit,
        state: lomi_remote_protocol::OperationState,
        effect: lomi_remote_protocol::Effect,
        result: Option<lomi_remote_protocol::OperationResult>,
    ) -> Result<lomi_remote_protocol::OperationReceipt, StepError<lomi_host_store::StoreError>>
    {
        self.operation.check().map_err(StepError::Domain)?;
        self.core
            .check_writer(&self.state)
            .map_err(StepError::Domain)?;
        if self.core.phase() != RemoteGitWriterPhase::Started {
            return Err(StepError::Domain(Error::Stale));
        }
        self.advance().map_err(StepError::Domain)?;
        self.core
            .phase
            .store(RemoteGitWriterPhase::Uncertain as u64, SeqCst);
        let outcome = store.complete_external(permit, state, effect, result, None);
        if outcome.is_err() {
            self.domain.fail_remote();
        }
        let post = self.postview(store);
        let receipt = outcome.map_err(StepError::Source)?;
        post?;
        if receipt.state() != state || receipt.effect() != effect {
            self.domain.fail_remote();
            return Err(StepError::Domain(Error::Denied));
        }
        self.operation.check().map_err(StepError::Domain)?;
        let revision = self
            .core
            .authority_revision
            .load(SeqCst)
            .checked_add(1)
            .ok_or(StepError::Domain(Error::Exhausted))?;
        if self.state.authority_revision != revision
            || self.core.pending.load(SeqCst) != 1
            || self.core.shared_pending.load(SeqCst) != 1
            || self.state.generation != self.core.generation
            || !self.state.ready.is_some_and(|ready| {
                ready.generation == self.core.generation && ready.deny_epoch == self.core.deny_epoch
            })
        {
            self.domain.fail_remote();
            return Err(StepError::Domain(Error::Stale));
        }
        self.core.authority_revision.store(revision, SeqCst);
        self.core
            .phase
            .store(RemoteGitWriterPhase::Committed as u64, SeqCst);
        Ok(receipt)
    }
}
impl RemoteRenameScope<'_, '_> {
    fn check_time(&self) -> Result<(), Error> {
        self.operation.check()?;
        if Instant::now() >= self.absolute_expiry {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn common(&self) -> Result<(), Error> {
        self.check_time()?;
        if !std::sync::Arc::ptr_eq(&self.owner_identity, &self.domain.owner_identity)
            || !self.operation.is_same_admission(&self.identity)
            || self.domain.failed_remote.load(SeqCst)
            || self.domain.generation.load(SeqCst) != self.generation
            || self.domain.deny_epoch.load(SeqCst) != self.deny_epoch
            || self.domain.generation_denied(self.generation)
            || self.domain.issued.load(SeqCst) != self.ticket
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn check_lock_free(&self) -> Result<(), Error> {
        self.common()?;
        if self.domain.pending.load(SeqCst) != 1 || self.domain.shared_pending.load(SeqCst) != 1 {
            return Err(Error::Stale);
        }
        self.common()
    }
    fn check_writer(&self, state: &State) -> Result<(), Error> {
        if self.domain.pending.load(SeqCst) != 1
            || self.domain.shared_pending.load(SeqCst) != 1
            || state.generation != self.generation
            || state.authority_revision != self.authority_revision
            || !state
                .ready
                .is_some_and(|r| r.generation == self.generation && r.deny_epoch == self.deny_epoch)
        {
            return Err(Error::Stale);
        }
        // Sample issued after pending: a completed competing announcement also denies.
        self.common()
    }
}
impl<'d, 'o> RemoteOperationCancelWrite<'d, 'o> {
    pub(super) fn phase(&self) -> RemoteOperationCancelPhase {
        self.phase
    }

    /// Retry only contention before the fixed Store call. The same writer,
    /// operation, ticket and deadline remain owned by this value.
    pub(super) fn try_enter(&mut self) -> Result<RemoteOperationCancelGuard<'_, 'd, 'o>, Error> {
        if self.phase != RemoteOperationCancelPhase::StoreNotCalled {
            return Err(Error::Stale);
        }
        let pending = self.pending.as_mut().ok_or(Error::Stale)?;
        self.scope.check_time()?;
        if !pending.active
            || pending.committed
            || pending.terminal.is_some()
            || pending.class != WriterClass::Shared
            || pending.intent != Intent::Mutation
            || pending.ticket != self.scope.ticket
            || !std::ptr::eq(pending.domain, self.scope.domain)
            || !pending.operation.is_same_admission(&self.scope.identity)
        {
            return Err(Error::Stale);
        }
        let state = pending.domain.lock(pending.operation)?;
        self.scope.check_writer(&state)?;
        Ok(RemoteOperationCancelGuard {
            guard: WriterGuard {
                writer: pending,
                state,
            },
            scope: &mut self.scope,
            phase: &mut self.phase,
        })
    }

    /// Release a cancellation that provably never called Store. A busy
    /// pre-Store attempt may be abandoned at the original deadline without
    /// turning it into a failed/uncertain mutation.
    pub(super) fn abandon(mut self) -> Result<(), Error> {
        if self.phase != RemoteOperationCancelPhase::StoreNotCalled {
            return Err(Error::Denied);
        }
        if let Some(mut pending) = self.pending.take()
            && pending.active
        {
            pending.release();
        }
        Ok(())
    }

    /// Release only after one known Store result and its exact post-view have
    /// been checked under the same writer.
    pub(super) fn finish(mut self) -> Result<(), Error> {
        if !matches!(
            self.phase,
            RemoteOperationCancelPhase::KnownNoEffect | RemoteOperationCancelPhase::Committed
        ) {
            return Err(Error::Denied);
        }
        self.scope
            .common()
            .inspect_err(|_| self.scope.domain.fail_remote())?;
        let pending = self.pending.take().ok_or(Error::Stale)?;
        pending.finish()
    }
}

impl RemoteOperationCancelGuard<'_, '_, '_> {
    pub(super) fn phase(&self) -> RemoteOperationCancelPhase {
        *self.phase
    }

    pub(super) fn check_current(&self) -> Result<(), Error> {
        if *self.phase != RemoteOperationCancelPhase::StoreNotCalled {
            return Err(Error::Stale);
        }
        self.scope.check_writer(&self.guard.state)
    }

    /// The sole fixed Store call for the previously authorized operation.
    /// Domain and Store remain held across current-row validation and this
    /// transaction. Busy/Fenced are observed as known no effect; other Store
    /// failures fence before any post-view can hide uncertainty.
    pub(super) fn commit_cancel(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        expected: &lomi_remote_protocol::StoredOperationRights,
        current: &lomi_remote_protocol::CapabilitySet,
    ) -> Result<
        Option<lomi_remote_protocol::OperationReceipt>,
        StepError<lomi_host_store::StoreError>,
    > {
        use lomi_host_store::StoreError;

        self.check_current().map_err(StepError::Domain)?;
        if current
            .authorize_operation(
                lomi_remote_protocol::Method::OperationCancel,
                expected.operation_id(),
                expected.actor(),
                expected.workspace(),
                Some(expected),
            )
            .is_err()
        {
            return Err(StepError::Domain(Error::Denied));
        }
        self.guard.advance().map_err(StepError::Domain)?;
        *self.phase = RemoteOperationCancelPhase::Uncertain;

        let result = store.cancel_operation(
            expected.actor(),
            expected.workspace(),
            expected.operation_id(),
            current,
        );
        if let Err(error) = &result
            && !matches!(error, StoreError::Busy | StoreError::Fenced)
        {
            self.scope.domain.fail_remote();
            return Err(StepError::Source(*error));
        }

        let view = match StoreView::read(store) {
            Ok(view) => view,
            Err(error) => {
                self.scope.domain.fail_remote();
                return Err(StepError::Source(error));
            }
        };
        let view_valid = view.generation == self.scope.generation
            && view.verified == Some(view.generation)
            && !view.locked
            && !view.pending_revoke;
        if let Err(error) = self.guard.observe(view) {
            *self.phase = RemoteOperationCancelPhase::Uncertain;
            self.scope.domain.fail_remote();
            return Err(StepError::Domain(error));
        }
        if !view_valid {
            *self.phase = RemoteOperationCancelPhase::Uncertain;
            self.scope.domain.fail_remote();
            return Err(StepError::Domain(Error::Stale));
        }

        let receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                self.scope
                    .check_after_commit(&self.guard.state)
                    .map_err(|domain_error| {
                        self.scope.domain.fail_remote();
                        StepError::Domain(domain_error)
                    })?;
                self.guard.writer.committed = true;
                *self.phase = RemoteOperationCancelPhase::KnownNoEffect;
                return Err(StepError::Source(error));
            }
        };

        if receipt.as_ref().is_some_and(|receipt| {
            !same_stored_operation_rights(&receipt.stored_rights(), expected)
        }) {
            self.scope.domain.fail_remote();
            return Err(StepError::Domain(Error::Denied));
        }
        self.scope
            .check_after_commit(&self.guard.state)
            .map_err(|domain_error| {
                self.scope.domain.fail_remote();
                StepError::Domain(domain_error)
            })?;
        self.guard.writer.committed = true;
        *self.phase = if receipt.is_some() {
            RemoteOperationCancelPhase::Committed
        } else {
            RemoteOperationCancelPhase::KnownNoEffect
        };
        Ok(receipt)
    }
}

fn same_stored_operation_rights(
    a: &lomi_remote_protocol::StoredOperationRights,
    b: &lomi_remote_protocol::StoredOperationRights,
) -> bool {
    a.operation_id() == b.operation_id()
        && a.actor() == b.actor()
        && a.workspace() == b.workspace()
        && a.original_method() == b.original_method()
        && a.actual_rights() == b.actual_rights()
        && a.repository_execution() == b.repository_execution()
}

impl<'d, 'o> RemoteRenameWrite<'d, 'o> {
    pub(super) fn phase(&self) -> RemoteRenamePhase {
        self.phase
    }
    pub(super) fn try_enter(&mut self) -> Result<RemoteRenameGuard<'_, 'd, 'o>, Error> {
        if !matches!(
            self.phase,
            RemoteRenamePhase::StoreNotCalled | RemoteRenamePhase::Started
        ) {
            return Err(Error::Stale);
        }
        let pending = self.pending.as_mut().ok_or(Error::Stale)?;
        self.scope.check_time()?;
        if !pending.active
            || pending.committed
            || pending.terminal.is_some()
            || pending.class != WriterClass::Shared
            || pending.intent != Intent::Mutation
            || pending.ticket != self.scope.ticket
            || !std::ptr::eq(pending.domain, self.scope.domain)
            || !pending.operation.is_same_admission(&self.scope.identity)
        {
            return Err(Error::Stale);
        }
        let state = pending.domain.lock(pending.operation)?;
        self.scope.check_writer(&state)?;
        Ok(RemoteRenameGuard {
            guard: WriterGuard {
                writer: pending,
                state,
            },
            scope: &mut self.scope,
            phase: &mut self.phase,
        })
    }
    /// Lock-free predicate for the OS-effect boundary. It never acquires Domain,
    /// Store or a provider and is true only while this exact sole Shared
    /// announcement still owns the Started operation. Any competing writer,
    /// cancellation, deadline, fence or revoke makes it false before the effect.
    pub(super) fn effect_current(&self) -> bool {
        self.phase == RemoteRenamePhase::Started
            && self.pending.as_ref().is_some_and(|p| {
                p.active
                    && !p.committed
                    && p.terminal.is_none()
                    && p.class == WriterClass::Shared
                    && p.intent == Intent::Mutation
                    && p.ticket == self.scope.ticket
                    && std::ptr::eq(p.domain, self.scope.domain)
            })
            && self.scope.check_lock_free().is_ok()
    }
    /// Known-no-effect cleanup never marks committed or rewinds any stamp.
    pub(super) fn abandon(mut self) -> Result<(), Error> {
        if !matches!(
            self.phase,
            RemoteRenamePhase::StoreNotCalled | RemoteRenamePhase::KnownNoEffect
        ) {
            return Err(Error::Denied);
        }
        if let Some(mut pending) = self.pending.take()
            && pending.active
        {
            pending.release();
        }
        Ok(())
    }
    pub(super) fn finish(mut self) -> Result<RemoteRenameReceiptStamp<'d, 'o>, Error> {
        if self.phase != RemoteRenamePhase::Committed {
            return Err(Error::Denied);
        }
        self.scope.common()?;
        let pending = self.pending.take().ok_or(Error::Stale)?;
        pending.finish()?;
        // The actual announcement is released. Its Drop can no longer fence a
        // failed final check, so fence every error before minting the stamp.
        let settled = (|| {
            #[cfg(test)]
            remote_rename_tests::after_release(&self.scope);
            self.scope.common()?;
            if self.scope.domain.pending.load(SeqCst) != 0
                || self.scope.domain.shared_pending.load(SeqCst) != 0
            {
                return Err(Error::Stale);
            }
            self.scope.common()?;
            self.scope
                .authority_revision
                .checked_add(1)
                .ok_or(Error::Exhausted)
        })();
        let authority_revision = settled.inspect_err(|_| self.scope.domain.fail_remote())?;
        let mut scope = self.scope;
        scope.authority_revision = authority_revision;
        Ok(RemoteRenameReceiptStamp { scope })
    }
}
impl RemoteRenameGuard<'_, '_, '_> {
    pub(super) fn check_current(&self) -> Result<(), Error> {
        if *self.phase != RemoteRenamePhase::StoreNotCalled {
            return Err(Error::Stale);
        }
        self.scope.check_writer(&self.guard.state)
    }
    pub(super) fn commit(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        binding: &lomi_host_store::OperationBinding,
        original: &lomi_remote_protocol::rpc::RpcCall,
    ) -> Result<lomi_host_store::Admission, StepError<lomi_host_store::StoreError>> {
        if !matches!(
            original,
            lomi_remote_protocol::rpc::RpcCall::TerminalRename(_)
        ) {
            return Err(StepError::Domain(Error::Denied));
        }
        self.commit_original(store, binding, original)
    }
    /// Fixed move commit boundary; no projection, callback or local dispatch.
    pub(super) fn commit_move(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        binding: &lomi_host_store::OperationBinding,
        original: &lomi_remote_protocol::rpc::RpcCall,
    ) -> Result<lomi_host_store::Admission, StepError<lomi_host_store::StoreError>> {
        if !matches!(
            original,
            lomi_remote_protocol::rpc::RpcCall::TerminalMove(_)
        ) {
            return Err(StepError::Domain(Error::Denied));
        }
        self.commit_original(store, binding, original)
    }
    /// Exactly one fixed Store call and one postview. An unexpected duplicate
    /// never mints a receipt stamp. Busy AFTER call entry is terminal/uncertain.
    fn commit_original(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        binding: &lomi_host_store::OperationBinding,
        original: &lomi_remote_protocol::rpc::RpcCall,
    ) -> Result<lomi_host_store::Admission, StepError<lomi_host_store::StoreError>> {
        use super::remote_terminal_rename::RemoteTerminalEdit;
        use lomi_host_store::StoreError;
        let edit = RemoteTerminalEdit::from_call(original)
            .map_err(|_| StepError::Domain(Error::Denied))?;
        if edit.is_effect() {
            return Err(StepError::Domain(Error::Denied));
        }
        self.check_current().map_err(StepError::Domain)?;
        if *self.phase != RemoteRenamePhase::StoreNotCalled {
            return Err(StepError::Domain(Error::Stale));
        }
        self.guard.advance().map_err(StepError::Domain)?;
        *self.phase = RemoteRenamePhase::Uncertain;
        let outcome = match edit {
            RemoteTerminalEdit::Rename(params) => store.rename_tab(
                binding,
                params.mutation.expected_revision,
                params.tab_id,
                params.name.clone(),
            ),
            RemoteTerminalEdit::Move(params) => store.move_pane(
                binding,
                params.mutation.expected_revision,
                &lomi_host_store::TerminalMoveLayout::from(params),
            ),
            RemoteTerminalEdit::Create(_)
            | RemoteTerminalEdit::Split(_)
            | RemoteTerminalEdit::Close(_)
            | RemoteTerminalEdit::Restart(_) => unreachable!("rejected before any Store call"),
        };
        match &outcome {
            Ok(admission)
                if admission.newly_admitted
                    && admission.receipt.state()
                        == lomi_remote_protocol::OperationState::Succeeded
                    && admission.receipt.effect() == lomi_remote_protocol::Effect::Committed => {} // Retain Uncertain until the postview and original boundaries pass.
            Ok(admission) if !admission.newly_admitted => {
                *self.phase = RemoteRenamePhase::KnownNoEffect
            }
            Ok(_) => self.scope.domain.fail_remote(),
            Err(
                StoreError::RevisionConflict
                | StoreError::IdempotencyConflict
                | StoreError::NotFound
                | StoreError::ResourceExhausted
                | StoreError::Invalid
                | StoreError::Fenced,
            ) => *self.phase = RemoteRenamePhase::KnownNoEffect,
            Err(_) => self.scope.domain.fail_remote(), // fence BEFORE postview
        }
        // Exactly once after either actual outcome; never return before this.
        let post = StoreView::read(store);
        #[cfg(test)]
        let post = remote_rename_tests::postview(post);
        let observed = match post {
            Ok(view) => {
                let valid = view.generation == self.scope.generation
                    && view.verified == Some(view.generation)
                    && !view.locked
                    && !view.pending_revoke;
                let observed = self.guard.observe(view).map_err(StepError::Domain);
                if !valid || observed.is_err() {
                    *self.phase = RemoteRenamePhase::Uncertain;
                    self.scope.domain.fail_remote();
                }
                observed.and({
                    if valid {
                        Ok(())
                    } else {
                        Err(StepError::Domain(Error::Stale))
                    }
                })
            }
            Err(error) => {
                *self.phase = RemoteRenamePhase::Uncertain;
                self.scope.domain.fail_remote();
                Err(StepError::Source(error))
            }
        };
        // Primary Store error wins over all secondary observation/time failures.
        let admission = match outcome {
            Ok(value) => value,
            Err(error) => return Err(StepError::Source(error)),
        };
        observed?;
        if !admission.newly_admitted {
            return Err(StepError::Source(StoreError::AlreadyStarted));
        }
        if admission.receipt.state() != lomi_remote_protocol::OperationState::Succeeded
            || admission.receipt.effect() != lomi_remote_protocol::Effect::Committed
        {
            self.scope.domain.fail_remote();
            return Err(StepError::Domain(Error::Denied));
        }
        self.scope.common().map_err(StepError::Domain)?;
        if self.scope.domain.pending.load(SeqCst) != 1
            || self.scope.domain.shared_pending.load(SeqCst) != 1
            || self.guard.state.generation != self.scope.generation
            || self.guard.state.authority_revision
                != self
                    .scope
                    .authority_revision
                    .checked_add(1)
                    .ok_or(StepError::Domain(Error::Exhausted))?
            || !self.guard.state.ready.is_some_and(|r| {
                r.generation == self.scope.generation && r.deny_epoch == self.scope.deny_epoch
            })
        {
            return Err(StepError::Domain(Error::Stale));
        }
        self.scope.common().map_err(StepError::Domain)?;
        self.guard.writer.committed = true; // actual NEW committed outcome only
        *self.phase = RemoteRenamePhase::Committed;
        Ok(admission)
    }
}
// Closed OS-effect lifecycle (create/split/close/restart). Two Store turns share
// ONE retained Shared announcement: start (admit+run, single permit) and
// completion. The physical effect runs between them with Domain/Store released,
// gated only by the lock-free `effect_current` predicate. No other writer can be
// registered in that window without making the effect (and this write) stale.
impl RemoteRenameGuard<'_, '_, '_> {
    /// Post-Store observation shared by both effect turns. Any inconsistency
    /// leaves the phase Uncertain and fences the remote owner.
    fn effect_postview(
        &mut self,
        store: &lomi_host_store::HostStore,
    ) -> Result<(), StepError<lomi_host_store::StoreError>> {
        let post = StoreView::read(store);
        #[cfg(test)]
        let post = remote_rename_tests::postview(post);
        match post {
            Ok(view) => {
                let valid = view.generation == self.scope.generation
                    && view.verified == Some(view.generation)
                    && !view.locked
                    && !view.pending_revoke;
                let observed = self.guard.observe(view).map_err(StepError::Domain);
                if !valid || observed.is_err() {
                    *self.phase = RemoteRenamePhase::Uncertain;
                    self.scope.domain.fail_remote();
                }
                observed?;
                if valid {
                    Ok(())
                } else {
                    Err(StepError::Domain(Error::Stale))
                }
            }
            Err(error) => {
                *self.phase = RemoteRenamePhase::Uncertain;
                self.scope.domain.fail_remote();
                Err(StepError::Source(error))
            }
        }
    }

    /// The new authority revision must be exactly one past the scope's, with the
    /// same sole announcement and readiness; anything else is stale.
    fn effect_authority_advanced(&self) -> Result<(), StepError<lomi_host_store::StoreError>> {
        self.scope.common().map_err(StepError::Domain)?;
        if self.scope.domain.pending.load(SeqCst) != 1
            || self.scope.domain.shared_pending.load(SeqCst) != 1
            || self.guard.state.generation != self.scope.generation
            || self.guard.state.authority_revision
                != self
                    .scope
                    .authority_revision
                    .checked_add(1)
                    .ok_or(StepError::Domain(Error::Exhausted))?
            || !self.guard.state.ready.is_some_and(|r| {
                r.generation == self.scope.generation && r.deny_epoch == self.scope.deny_epoch
            })
        {
            return Err(StepError::Domain(Error::Stale));
        }
        self.scope.common().map_err(StepError::Domain)
    }

    /// Exactly one atomic admit+start Store call. The real permit is moved into
    /// `permit` before any fallible postcheck, so a later error can only hand it
    /// to persistence-only reconciliation, never to a new OS effect.
    pub(super) fn start_effect(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        binding: &lomi_host_store::OperationBinding,
        expected_revision: Option<lomi_remote_protocol::DecimalU64>,
        permit: &mut Option<lomi_host_store::ExternalPermit>,
    ) -> Result<lomi_host_store::Admission, StepError<lomi_host_store::StoreError>> {
        use lomi_host_store::StoreError;
        self.check_current().map_err(StepError::Domain)?;
        if *self.phase != RemoteRenamePhase::StoreNotCalled || permit.is_some() {
            return Err(StepError::Domain(Error::Stale));
        }
        self.guard.advance().map_err(StepError::Domain)?;
        *self.phase = RemoteRenamePhase::Uncertain;
        let outcome = match expected_revision {
            Some(expected) => store.admit_start_external(binding, expected),
            // File operations carry their own file-revision preconditions.
            None => store.admit_start_external_unversioned(binding),
        };
        let outcome = match outcome {
            Ok((admission, started)) => {
                *permit = started;
                Ok(admission)
            }
            Err(error) => Err(error),
        };
        match &outcome {
            Ok(admission)
                if admission.newly_admitted
                    && permit.is_some()
                    && admission.receipt.state()
                        == lomi_remote_protocol::OperationState::Running => {}
            Ok(admission) if !admission.newly_admitted && permit.is_none() => {
                *self.phase = RemoteRenamePhase::KnownNoEffect
            }
            Ok(_) => self.scope.domain.fail_remote(),
            Err(
                StoreError::RevisionConflict
                | StoreError::IdempotencyConflict
                | StoreError::NotFound
                | StoreError::ResourceExhausted
                | StoreError::Invalid
                | StoreError::Fenced,
            ) => *self.phase = RemoteRenamePhase::KnownNoEffect,
            Err(_) => self.scope.domain.fail_remote(),
        }
        let observed = self.effect_postview(store);
        let admission = match outcome {
            Ok(value) => value,
            Err(error) => return Err(StepError::Source(error)),
        };
        observed?;
        if !admission.newly_admitted {
            return Err(StepError::Source(StoreError::AlreadyStarted));
        }
        if permit.is_none()
            || admission.receipt.state() != lomi_remote_protocol::OperationState::Running
            || admission.receipt.effect() != lomi_remote_protocol::Effect::None
        {
            self.scope.domain.fail_remote();
            return Err(StepError::Domain(Error::Denied));
        }
        self.effect_authority_advanced()?;
        // The operation is durably Running. The announcement stays registered
        // (not committed) and the scope now tracks the advanced authority.
        self.scope.authority_revision = self
            .scope
            .authority_revision
            .checked_add(1)
            .ok_or(StepError::Domain(Error::Exhausted))?;
        *self.phase = RemoteRenamePhase::Started;
        Ok(admission)
    }

    pub(super) fn effect_namespace_plan(
        &self,
        store: &lomi_host_store::HostStore,
        permit: &lomi_host_store::ExternalPermit,
        effect: lomi_host_store::DesktopNamespaceEffect,
    ) -> Result<lomi_host_store::RemoteDesktopNamespacePlan, StepError<lomi_host_store::StoreError>>
    {
        if *self.phase != RemoteRenamePhase::Started {
            return Err(StepError::Domain(Error::Stale));
        }
        self.scope
            .check_writer(&self.guard.state)
            .map_err(StepError::Domain)?;
        let plan = store
            .plan_desktop_namespace_remote(permit, effect)
            .map_err(StepError::Source)?;
        self.scope
            .check_writer(&self.guard.state)
            .map_err(StepError::Domain)?;
        Ok(plan)
    }

    /// Bind namespace preparation to the same sole announcement that admitted
    /// the actual remote operation. No second writer or native job is created.
    pub(super) fn prepare_effect_namespace(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        permit: &lomi_host_store::ExternalPermit,
        plan: &lomi_host_store::RemoteDesktopNamespacePlan,
        proof: &lomi_host_store::DesktopNamespacePhysicalProof,
    ) -> Result<(), StepError<lomi_host_store::StoreError>> {
        if *self.phase != RemoteRenamePhase::Started {
            return Err(StepError::Domain(Error::Stale));
        }
        self.scope
            .check_writer(&self.guard.state)
            .map_err(StepError::Domain)?;
        self.guard.advance().map_err(StepError::Domain)?;
        *self.phase = RemoteRenamePhase::Uncertain;
        let result = store.prepare_desktop_namespace_remote(permit, plan, proof);
        if result.is_err() {
            self.scope.domain.fail_remote();
        }
        let observed = self.effect_postview(store);
        result.map_err(StepError::Source)?;
        observed?;
        self.effect_authority_advanced()?;
        self.scope.authority_revision = self
            .scope
            .authority_revision
            .checked_add(1)
            .ok_or(StepError::Domain(Error::Exhausted))?;
        *self.phase = RemoteRenamePhase::Started;
        Ok(())
    }

    /// Exactly one completion Store call for the retained permit, followed by one
    /// postview. Success of the call (any final state) commits this announcement;
    /// every failure keeps the permit with the caller for persistence-only
    /// reconciliation and fences the remote owner.
    pub(super) fn complete_effect(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        permit: &lomi_host_store::ExternalPermit,
        state: lomi_remote_protocol::OperationState,
        effect: lomi_remote_protocol::Effect,
        result: Option<lomi_remote_protocol::OperationResult>,
        projection: Option<lomi_remote_protocol::rpc::WorkspaceState>,
    ) -> Result<lomi_remote_protocol::OperationReceipt, StepError<lomi_host_store::StoreError>>
    {
        if *self.phase != RemoteRenamePhase::Started {
            return Err(StepError::Domain(Error::Stale));
        }
        self.scope
            .check_writer(&self.guard.state)
            .map_err(StepError::Domain)?;
        self.guard.advance().map_err(StepError::Domain)?;
        *self.phase = RemoteRenamePhase::Uncertain;
        let outcome = store.complete_external(permit, state, effect, result, projection);
        if outcome.is_err() {
            self.scope.domain.fail_remote();
        }
        let observed = self.effect_postview(store);
        let receipt = match outcome {
            Ok(receipt) => receipt,
            Err(error) => return Err(StepError::Source(error)),
        };
        observed?;
        if receipt.state() != state || receipt.effect() != effect {
            self.scope.domain.fail_remote();
            return Err(StepError::Domain(Error::Denied));
        }
        self.effect_authority_advanced()?;
        self.guard.writer.committed = true;
        *self.phase = RemoteRenamePhase::Committed;
        Ok(receipt)
    }

    /// The closed namespace counterpart commits root/alias changes and the
    /// genuine remote receipt in one Store transaction. It cannot accept a
    /// native completion proof or a caller-selected Store callback.
    pub(super) fn complete_namespace_effect(
        &mut self,
        store: &mut lomi_host_store::HostStore,
        permit: &lomi_host_store::ExternalPermit,
        state: lomi_remote_protocol::OperationState,
        effect: lomi_remote_protocol::Effect,
        result: Option<lomi_remote_protocol::OperationResult>,
        evidence: &lomi_host_store::DesktopNamespaceAppliedProof,
    ) -> Result<lomi_remote_protocol::OperationReceipt, StepError<lomi_host_store::StoreError>>
    {
        if *self.phase != RemoteRenamePhase::Started {
            return Err(StepError::Domain(Error::Stale));
        }
        self.scope
            .check_writer(&self.guard.state)
            .map_err(StepError::Domain)?;
        self.guard.advance().map_err(StepError::Domain)?;
        *self.phase = RemoteRenamePhase::Uncertain;
        let outcome = store.complete_remote_namespace(permit, state, effect, result, evidence);
        if outcome.is_err() {
            self.scope.domain.fail_remote();
        }
        let observed = self.effect_postview(store);
        let receipt = outcome.map_err(StepError::Source)?;
        observed?;
        if receipt.state() != state || receipt.effect() != effect {
            self.scope.domain.fail_remote();
            return Err(StepError::Domain(Error::Denied));
        }
        self.effect_authority_advanced()?;
        self.guard.writer.committed = true;
        *self.phase = RemoteRenamePhase::Committed;
        Ok(receipt)
    }
}
impl<'d, 'o> RemoteRenameReceiptStamp<'d, 'o> {
    pub(super) fn validate(
        &self,
        guard: &OwnerGuard<'_, '_>,
        store: &lomi_host_store::HostStore,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.check().map_err(StepError::Domain)?;
        if !std::ptr::eq(self.scope.domain, guard.domain)
            || !guard.operation.is_same_admission(&self.scope.identity)
            || guard.state.generation != self.scope.generation
            || guard.state.authority_revision != self.scope.authority_revision
            || !guard.state.ready.is_some_and(|r| {
                r.generation == self.scope.generation && r.deny_epoch == self.scope.deny_epoch
            })
        {
            return Err(StepError::Domain(Error::Stale));
        }
        let view = StoreView::read(store).map_err(|error| {
            self.scope.domain.fail_remote();
            StepError::Source(error)
        })?;
        if view.generation != self.scope.generation
            || view.verified != Some(view.generation)
            || view.locked
            || view.pending_revoke
        {
            return Err(StepError::Domain(Error::Stale));
        }
        let floor = store
            .authorization_state()
            .map(|a| a.clock_floor)
            .map_err(|error| {
                self.scope.domain.fail_remote();
                StepError::Source(error)
            })?;
        self.check().map_err(StepError::Domain)?;
        Ok(floor)
    }
    fn check(&self) -> Result<(), Error> {
        if self.scope.domain.pending.load(SeqCst) != 0
            || self.scope.domain.shared_pending.load(SeqCst) != 0
        {
            return Err(Error::Stale);
        }
        self.scope.common()
    }
    pub(super) fn into_io_watcher(self) -> RemoteRenameReceiptWatcher<'d, 'o> {
        RemoteRenameReceiptWatcher { stamp: self }
    }
}
impl RemoteRenameReceiptWatcher<'_, '_> {
    pub(super) fn deadline(&self) -> Instant {
        self.stamp.scope.absolute_expiry
    }
    /// Lock-free physical IO predicate; no generic peer continuation is renewed.
    pub(super) fn check(&self) -> Result<(), Error> {
        self.stamp.check()
    }
    pub(super) fn validate(
        &self,
        guard: &OwnerGuard<'_, '_>,
        store: &lomi_host_store::HostStore,
    ) -> Result<u64, StepError<lomi_host_store::StoreError>> {
        self.stamp.validate(guard, store)
    }
}

#[cfg(test)]
mod remote_rename_tests {
    use super::*;
    use lomi_host_store::{
        HostStore, Limits, OperationBinding, ProjectRecord, StoreError, parameter_hash,
    };
    use lomi_remote_protocol::{rpc::*, *};
    use std::cell::Cell;
    use std::time::Duration;

    thread_local! {
        static POST_READS: Cell<u32> = const { Cell::new(0) };
        static FAIL_POST: Cell<bool> = const { Cell::new(false) };
        static AFTER_RELEASE: Cell<u8> = const { Cell::new(0) };
    }
    // The production StoreView read has already happened once. This private,
    // thread-local seam counts it and can model its reported failure.
    pub(super) fn postview(value: Result<StoreView, StoreError>) -> Result<StoreView, StoreError> {
        POST_READS.with(|count| count.set(count.get() + 1));
        if FAIL_POST.with(|fault| fault.replace(false)) {
            Err(StoreError::Storage)
        } else {
            value
        }
    }
    fn post_reads() -> u32 {
        POST_READS.with(Cell::get)
    }
    // Deterministic scheduling seam after the real committed ticket release.
    // These are the original cancellation latch and Operation expiry marker;
    // the stale case registers and releases an actual later Shared ticket.
    pub(super) fn after_release(scope: &RemoteRenameScope<'_, '_>) {
        match AFTER_RELEASE.with(|action| action.replace(0)) {
            0 => {}
            1 => scope.operation.cancelled.store(true, SeqCst),
            2 => scope.operation.expire_for_test(),
            3 => {
                let mut later = scope
                    .domain
                    .register_writer(scope.operation, WriterClass::Shared, Intent::Mutation)
                    .unwrap();
                later.release();
            }
            _ => panic!("unknown post-release test action"),
        }
    }
    fn actor() -> ConsumerAuthorizationId {
        ConsumerAuthorizationId::from_bytes([71; 16]).unwrap()
    }
    fn required() -> CapabilitySet {
        vec![
            Capability::WorkspaceRead,
            Capability::TerminalObserve,
            Capability::TerminalManage,
        ]
        .try_into()
        .unwrap()
    }
    fn binding(call: &RpcCall, consumer: ConsumerAuthorizationId) -> OperationBinding {
        let edit =
            super::super::remote_terminal_rename::RemoteTerminalEdit::from_call(call).unwrap();
        let mutation = edit.mutation();
        OperationBinding {
            rights: StoredOperationRights::new(
                mutation.operation_id,
                consumer,
                mutation.context.workspace_id,
                edit.method(),
                required(),
                false,
            )
            .unwrap(),
            // Preserve original remote wire tuple; no hash of translated local DTO.
            parameter_hash: parameter_hash(call).unwrap(),
        }
    }
    fn store_fixture_layout(
        move_layout: Option<bool>,
    ) -> (tempfile::TempDir, HostStore, ProjectRecord) {
        let root = tempfile::tempdir().unwrap();
        let mut store =
            HostStore::open(&root.path().join("host.sqlite"), Limits::default()).unwrap();
        let project = store
            .add_project(root.path(), "rename fixture".to_owned().try_into().unwrap())
            .unwrap();
        store
            .share(project.state.context.workspace_id, project.fence)
            .unwrap();
        let project = store.workspace(project.state.context.workspace_id).unwrap();
        let create = OperationBinding {
            rights: StoredOperationRights::new(
                OperationId::from_bytes([72; 16]).unwrap(),
                actor(),
                project.state.context.workspace_id,
                Method::TerminalCreate,
                required(),
                false,
            )
            .unwrap(),
            parameter_hash: parameter_hash(&"source-only fixture setup; no PTY process").unwrap(),
        };
        store
            .admit_external(&create, project.state.domain_revision)
            .unwrap();
        let permit = store.start_external(&create).unwrap();
        let mut next = project.state.clone();
        next.domain_revision.0 += 1;
        let pane_id = PaneId::from_bytes([73; 16]).unwrap();
        let session_id = TerminalSessionId::from_bytes([74; 16]).unwrap();
        let session_epoch = SessionEpoch::from_bytes([75; 16]).unwrap();
        next.tabs = BoundedList(vec![TerminalTab {
            tab_id: TabId::from_bytes([76; 16]).unwrap(),
            name: "before".to_owned().try_into().unwrap(),
            layout: TerminalLayout::Pane {
                pane: TerminalPane {
                    pane_id,
                    state: PaneState::Running,
                    session: Some(TerminalContext {
                        workspace: next.context.clone(),
                        pane_id,
                        session_id,
                        session_epoch,
                        profile: TerminalProfile::ExperimentalRustGridV1,
                    }),
                },
            },
        }]);
        if let Some(cross_tab) = move_layout {
            let target = TerminalLayout::Pane {
                pane: TerminalPane {
                    pane_id: PaneId::from_bytes([77; 16]).unwrap(),
                    state: PaneState::Stopped,
                    session: None,
                },
            };
            if cross_tab {
                next.tabs.0.push(TerminalTab {
                    tab_id: TabId::from_bytes([78; 16]).unwrap(),
                    name: "target".to_owned().try_into().unwrap(),
                    layout: target,
                });
            } else {
                next.tabs.0[0].layout = TerminalLayout::Split {
                    axis: SplitAxis::Vertical,
                    first: Box::new(next.tabs.0[0].layout.clone()),
                    second: Box::new(target),
                };
            }
        }
        store
            .complete_external(
                &permit,
                OperationState::Succeeded,
                Effect::Committed,
                Some(OperationResult::Terminal {
                    domain_revision: next.domain_revision,
                    pane_id,
                    session_id,
                    session_epoch,
                }),
                Some(next),
            )
            .unwrap();
        for publication in store.pending_publications().unwrap() {
            assert!(store.acknowledge_publication(&publication).unwrap());
        }
        let current = store.workspace(project.state.context.workspace_id).unwrap();
        (root, store, current)
    }
    fn call(project: &ProjectRecord, operation: u8, name: &str) -> RpcCall {
        // Owner runtime generation is local. The grant tuple uses independent
        // server generation/access/grant revision. Workspace ID/epoch stay exact.
        let mut wire = project.state.context.clone();
        wire.runtime_generation = DecimalU64(wire.runtime_generation.0 + 11);
        wire.host_access_epoch = DecimalU64(wire.host_access_epoch.0 + 12);
        wire.grant_revision = DecimalU64(wire.grant_revision.0 + 13);
        RpcCall::TerminalRename(TerminalRenameParams {
            mutation: MutationContext {
                operation_id: OperationId::from_bytes([operation; 16]).unwrap(),
                context: wire,
                expected_revision: project.state.domain_revision,
            },
            tab_id: project.state.tabs.0[0].tab_id,
            name: name.to_owned().try_into().unwrap(),
        })
    }
    fn rename(
        store: &mut HostStore,
        call: &RpcCall,
        consumer: ConsumerAuthorizationId,
    ) -> lomi_host_store::Admission {
        let RpcCall::TerminalRename(params) = call else {
            panic!("rename fixture");
        };
        store
            .rename_tab(
                &binding(call, consumer),
                params.mutation.expected_revision,
                params.tab_id,
                params.name.clone(),
            )
            .unwrap()
    }

    fn configured_fixture() -> (tempfile::TempDir, HostStore, ProjectRecord) {
        configured_fixture_layout(None)
    }
    fn configured_fixture_layout(
        move_layout: Option<bool>,
    ) -> (tempfile::TempDir, HostStore, ProjectRecord) {
        use lomi_remote_protocol::ipc::*;
        let (root, mut store, project) = store_fixture_layout(move_layout);
        store
            .configure_auth(&LocalAuthConfiguration {
                version: 1,
                origin: "https://identity.example".to_owned().try_into().unwrap(),
                remote_api_origin: None,
                relay_endpoint: None,
                client_id: "lomi-remote-host".to_owned().try_into().unwrap(),
                provider: crate::testsupport::provider(),
                keychain_path: None,
                protected_file_acknowledgement: crate::testsupport::file_acknowledgement(),
            })
            .unwrap();
        (root, store, project)
    }
    fn login(domain: &OwnerDomain, store: &mut HostStore, operation: &Operation<'_>) {
        let generation = store.authorization_state().unwrap().generation;
        let mut writer = domain
            .announce(operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let intent = writer
            .try_enter()
            .unwrap()
            .commit(|| {
                let intent = store.begin_login(OperationId::from_bytes([90; 16]).unwrap())?;
                Ok::<_, StoreError>((intent, StoreView::read(store)?))
            })
            .unwrap();
        let scope = writer
            .try_enter()
            .unwrap()
            .prepare_verification(generation, || StoreView::read(store))
            .unwrap();
        writer
            .try_enter()
            .unwrap()
            .commit_verified(scope, || {
                store.complete_login(intent)?;
                Ok::<_, StoreError>(((), StoreView::read(store)?))
            })
            .unwrap();
        writer.finish().unwrap();
    }
    fn begin<'d, 'o>(
        domain: &'d OwnerDomain,
        operation: &'o Operation<'o>,
        store: &HostStore,
        peer: &PeerContinuation,
    ) -> RemoteRenameWrite<'d, 'o> {
        let guard = domain.try_read(operation).unwrap();
        let snapshot = guard.capture_remote(|| StoreView::read(store)).unwrap();
        guard
            .begin_remote_rename(snapshot, peer, operation.deadline())
            .unwrap_or_else(|_| panic!("current rename admission"))
    }
    fn commit(
        write: &mut RemoteRenameWrite<'_, '_>,
        store: &mut HostStore,
        request: &RpcCall,
    ) -> Result<lomi_host_store::Admission, StepError<StoreError>> {
        let mut guard = write.try_enter().map_err(StepError::Domain)?;
        match request {
            RpcCall::TerminalRename(_) => guard.commit(store, &binding(request, actor()), request),
            RpcCall::TerminalMove(_) => {
                guard.commit_move(store, &binding(request, actor()), request)
            }
            _ => panic!("closed edit fixture"),
        }
    }
    macro_rules! setup {
        ($root:ident, $store:ident, $project:ident, $domain:ident, $cancel:ident, $operation:ident, $peer:ident) => {
            setup!(
                $root,
                $store,
                $project,
                $domain,
                $cancel,
                $operation,
                $peer,
                configured_fixture()
            );
        };
        ($root:ident, $store:ident, $project:ident, $domain:ident, $cancel:ident, $operation:ident, $peer:ident, $fixture:expr) => {
            let ($root, mut $store, $project) = $fixture;
            let $domain = OwnerDomain::new($store.authorization_state().unwrap().generation);
            let $cancel = AtomicBool::new(false);
            let $operation = Operation::new(Instant::now() + Duration::from_secs(30), &$cancel);
            login(&$domain, &mut $store, &$operation);
            let $peer = $domain
                .try_read(&$operation)
                .unwrap()
                .prepare_peer_continuation(&$store)
                .unwrap();
        };
    }
    #[test]
    fn new_commit_has_one_postview_exact_delta_and_move_only_socket_cap() {
        setup!(_root, store, project, domain, cancel, operation, peer);
        let request = call(&project, 91, "renamed");
        let issued = domain.issued.load(SeqCst);
        let authority = domain.state.lock().unwrap().authority_revision;
        let mut write = begin(&domain, &operation, &store, &peer);
        assert_eq!(write.phase(), RemoteRenamePhase::StoreNotCalled);
        assert_eq!(domain.issued.load(SeqCst), issued + 1);
        assert_eq!(domain.pending.load(SeqCst), 1);
        assert_eq!(domain.shared_pending.load(SeqCst), 1);
        let before_reads = post_reads();
        let admitted = commit(&mut write, &mut store, &request).unwrap();
        assert!(admitted.newly_admitted);
        assert_eq!(post_reads(), before_reads + 1);
        assert_eq!(write.phase(), RemoteRenamePhase::Committed);
        assert!(write.try_enter().is_err()); // No second Store call on this ticket.
        assert_eq!(post_reads(), before_reads + 1);
        let stamp = write
            .finish()
            .unwrap_or_else(|_| panic!("new committed stamp"));
        assert_eq!(
            domain.state.lock().unwrap().authority_revision,
            authority + 1
        );
        assert_eq!(domain.pending.load(SeqCst), 0);
        assert!(peer.check_effect_boundary(&domain, &operation).is_err());
        let guard = domain.try_read(&operation).unwrap();
        stamp.validate(&guard, &store).unwrap();
        drop(guard);
        let watcher = stamp.into_io_watcher();
        assert_eq!(watcher.deadline(), operation.deadline());
        assert_eq!(watcher.check(), Ok(()));
        let mut expected = project.state.clone();
        expected.domain_revision.0 += 1;
        expected.tabs.0[0].name = "renamed".to_owned().try_into().unwrap();
        assert_eq!(
            store
                .workspace(project.state.context.workspace_id)
                .unwrap()
                .state,
            expected
        );
        let pending = store.pending_publications().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].domain_revision, expected.domain_revision);
    }
    #[test]
    fn cas_rejection_advances_once_and_abandon_releases_only_own_ticket() {
        setup!(_root, store, project, domain, cancel, operation, peer);
        let mut request = call(&project, 92, "not committed");
        let RpcCall::TerminalRename(params) = &mut request else {
            unreachable!();
        };
        params.mutation.expected_revision.0 += 1;
        let authority = domain.state.lock().unwrap().authority_revision;
        let mut write = begin(&domain, &operation, &store, &peer);
        let before_reads = post_reads();
        assert!(matches!(
            commit(&mut write, &mut store, &request),
            Err(StepError::Source(StoreError::RevisionConflict))
        ));
        assert_eq!(post_reads(), before_reads + 1);
        assert_eq!(write.phase(), RemoteRenamePhase::KnownNoEffect);
        assert_eq!(
            domain.state.lock().unwrap().authority_revision,
            authority + 1
        );
        let mut competitor = domain
            .register_writer(&operation, WriterClass::Shared, Intent::Mutation)
            .unwrap();
        let issued = domain.issued.load(SeqCst);
        write.abandon().unwrap();
        assert_eq!(domain.pending.load(SeqCst), 1);
        assert_eq!(domain.shared_pending.load(SeqCst), 1);
        assert_eq!(domain.issued.load(SeqCst), issued);
        assert!(!domain.failed_remote.load(SeqCst));
        competitor.release(); // Actual competing ticket, no Store call occurred.
        assert!(peer.check_effect_boundary(&domain, &operation).is_err());
        assert_eq!(
            store
                .workspace(project.state.context.workspace_id)
                .unwrap()
                .state,
            project.state
        );
        assert!(store.pending_publications().unwrap().is_empty());
    }
    #[test]
    fn unexpected_duplicate_withholds_stamp_without_second_effect() {
        setup!(_root, store, project, domain, cancel, operation, peer);
        let request = call(&project, 93, "once");
        let first = rename(&mut store, &request, actor()); // Actual pre-existing journal row.
        let publication = store.pending_publications().unwrap();
        let mut write = begin(&domain, &operation, &store, &peer);
        let before_reads = post_reads();
        assert!(matches!(
            commit(&mut write, &mut store, &request),
            Err(StepError::Source(StoreError::AlreadyStarted))
        ));
        assert_eq!(post_reads(), before_reads + 1);
        assert_eq!(write.phase(), RemoteRenamePhase::KnownNoEffect);
        write.abandon().unwrap();
        assert!(!domain.failed_remote.load(SeqCst));
        assert_eq!(store.pending_publications().unwrap(), publication);
        assert_eq!(
            store
                .lookup(&binding(&request, actor()), &required())
                .unwrap(),
            Some(first.receipt)
        );
    }
    #[test]
    fn secondary_postview_failure_fences_but_preserves_primary_store_error() {
        setup!(_root, store, project, domain, cancel, operation, peer);
        let mut request = call(&project, 94, "bad CAS");
        let RpcCall::TerminalRename(params) = &mut request else {
            unreachable!();
        };
        params.mutation.expected_revision.0 += 1;
        let mut write = begin(&domain, &operation, &store, &peer);
        FAIL_POST.with(|fault| fault.set(true));
        let before_reads = post_reads();
        assert!(matches!(
            commit(&mut write, &mut store, &request),
            Err(StepError::Source(StoreError::RevisionConflict))
        ));
        assert_eq!(post_reads(), before_reads + 1);
        assert_eq!(write.phase(), RemoteRenamePhase::Uncertain);
        assert!(domain.failed_remote.load(SeqCst));
        assert!(write.abandon().is_err());
        assert_eq!(domain.pending.load(SeqCst), 0);
    }
    #[test]
    fn postcommit_observation_failure_keeps_durable_receipt_but_no_stamp() {
        setup!(_root, store, project, domain, cancel, operation, peer);
        let request = call(&project, 95, "durable");
        let mut write = begin(&domain, &operation, &store, &peer);
        FAIL_POST.with(|fault| fault.set(true));
        assert!(matches!(
            commit(&mut write, &mut store, &request),
            Err(StepError::Source(StoreError::Storage))
        ));
        assert_eq!(write.phase(), RemoteRenamePhase::Uncertain);
        assert!(write.finish().is_err());
        assert!(domain.failed_remote.load(SeqCst));
        assert!(
            store
                .lookup(&binding(&request, actor()), &required())
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn pre_store_expiry_is_known_no_effect_and_uses_original_operation() {
        setup!(_root, store, project, domain, cancel, operation, peer);
        let mut write = begin(&domain, &operation, &store, &peer);
        operation.expire_for_test();
        let before_reads = post_reads();
        assert!(matches!(
            commit(&mut write, &mut store, &call(&project, 96, "late")),
            Err(StepError::Domain(Error::Deadline))
        ));
        assert_eq!(post_reads(), before_reads);
        assert_eq!(write.phase(), RemoteRenamePhase::StoreNotCalled);
        write.abandon().unwrap();
        assert_eq!(domain.pending.load(SeqCst), 0);
        assert!(!domain.failed_remote.load(SeqCst));
        assert_eq!(
            store
                .workspace(project.state.context.workspace_id)
                .unwrap()
                .state,
            project.state
        );
    }
    #[test]
    fn local_snapshot_foreign_owner_and_replacement_operation_cannot_enter() {
        setup!(_root, store, _project, domain, cancel, operation, peer);
        let guard = domain.try_read(&operation).unwrap();
        let snapshot = guard.capture_local(|| Ok::<_, StoreError>(())).unwrap();
        assert!(matches!(
            guard.begin_remote_rename(snapshot, &peer, operation.deadline()),
            Err(Error::Denied)
        ));
        let replacement = Operation::new(operation.deadline(), &cancel);
        let guard = domain.try_read(&replacement).unwrap();
        let snapshot = guard.capture_remote(|| StoreView::read(&store)).unwrap();
        assert!(
            guard
                .begin_remote_rename(snapshot, &peer, operation.deadline())
                .is_err()
        );
        let foreign = OwnerDomain::new(store.authorization_state().unwrap().generation);
        login(&foreign, &mut store, &operation);
        let guard = foreign.try_read(&operation).unwrap();
        let snapshot = guard.capture_remote(|| StoreView::read(&store)).unwrap();
        assert!(
            guard
                .begin_remote_rename(snapshot, &peer, operation.deadline())
                .is_err()
        );
        assert_eq!(foreign.pending.load(SeqCst), 0);
        assert_eq!(domain.pending.load(SeqCst), 0);
    }
    #[test]
    fn later_abandoned_announcement_and_actual_own_ack_each_invalidate_socket_cap() {
        for (movement, acknowledge) in [(false, false), (false, true), (true, false), (true, true)]
        {
            setup!(
                _root,
                store,
                project,
                domain,
                cancel,
                operation,
                peer,
                configured_fixture_layout(movement.then_some(true))
            );
            let mut write = begin(&domain, &operation, &store, &peer);
            let request = if movement {
                move_call(&project, 97, MovePlacement::Before)
            } else {
                call(&project, 97, "sent once")
            };
            commit(&mut write, &mut store, &request).unwrap();
            let watcher = write
                .finish()
                .unwrap_or_else(|_| panic!("committed stamp"))
                .into_io_watcher();
            assert_eq!(watcher.check(), Ok(()));
            let mut later = domain
                .register_writer(&operation, WriterClass::Shared, Intent::Mutation)
                .unwrap();
            assert!(watcher.check().is_err());
            if acknowledge {
                let publication = store.pending_publications().unwrap().remove(0);
                later
                    .try_enter()
                    .unwrap()
                    .commit(|| {
                        assert!(store.acknowledge_publication(&publication)?);
                        Ok::<_, StoreError>(((), StoreView::read(&store)?))
                    })
                    .unwrap();
                later.finish().unwrap();
            } else {
                later.release();
            }
            assert!(watcher.check().is_err());
            assert!(!domain.failed_remote.load(SeqCst));
        }
    }
    #[test]
    fn original_cancellation_and_retained_absolute_expiry_withhold_output() {
        setup!(_root, store, project, domain, cancel, operation, peer);
        let guard = domain.try_read(&operation).unwrap();
        let snapshot = guard.capture_remote(|| StoreView::read(&store)).unwrap();
        let cap_expiry = Instant::now() + Duration::from_secs(10);
        let mut write = guard
            .begin_remote_rename(snapshot, &peer, cap_expiry)
            .unwrap_or_else(|_| panic!("current cap"));
        commit(
            &mut write,
            &mut store,
            &call(&project, 98, "cancelled output"),
        )
        .unwrap();
        let watcher = write
            .finish()
            .unwrap_or_else(|_| panic!("committed stamp"))
            .into_io_watcher();
        assert_eq!(watcher.deadline(), cap_expiry);
        cancel.store(true, SeqCst);
        assert_eq!(watcher.check(), Err(Error::Cancelled));
        cancel.store(false, SeqCst);
        assert_eq!(watcher.check(), Err(Error::Cancelled)); // Original sticky latch, no replacement budget.
    }

    #[test]
    fn expired_original_cap_and_intervening_abandoned_writer_never_register_rename() {
        setup!(_root, store, _project, domain, cancel, operation, peer);
        let issued = domain.issued.load(SeqCst);
        let guard = domain.try_read(&operation).unwrap();
        let snapshot = guard.capture_remote(|| StoreView::read(&store)).unwrap();
        assert!(matches!(
            guard.begin_remote_rename(snapshot, &peer, Instant::now()),
            Err(Error::Deadline)
        ));
        assert_eq!(domain.issued.load(SeqCst), issued);
        let mut announced = domain
            .register_writer(&operation, WriterClass::Shared, Intent::Mutation)
            .unwrap();
        announced.release();
        let guard = domain.try_read(&operation).unwrap();
        let snapshot = guard.capture_remote(|| StoreView::read(&store)).unwrap();
        assert!(
            guard
                .begin_remote_rename(snapshot, &peer, operation.deadline())
                .is_err()
        );
        assert_eq!(domain.issued.load(SeqCst), issued + 1);
        assert_eq!(domain.pending.load(SeqCst), 0);
        assert!(!domain.failed_remote.load(SeqCst));
    }
    #[test]
    fn fresh_stamp_read_rejects_replacement_operation_and_foreign_owner() {
        setup!(_root, store, project, domain, cancel, operation, peer);
        let mut write = begin(&domain, &operation, &store, &peer);
        commit(&mut write, &mut store, &call(&project, 99, "scoped result")).unwrap();
        let stamp = write.finish().unwrap_or_else(|_| panic!("committed stamp"));
        let replacement = Operation::new(operation.deadline(), &cancel);
        let guard = domain.try_read(&replacement).unwrap();
        assert!(matches!(
            stamp.validate(&guard, &store),
            Err(StepError::Domain(Error::Stale))
        ));
        drop(guard);
        let foreign = OwnerDomain::new(store.authorization_state().unwrap().generation);
        login(&foreign, &mut store, &operation);
        let guard = foreign.try_read(&operation).unwrap();
        assert!(matches!(
            stamp.validate(&guard, &store),
            Err(StepError::Domain(Error::Stale))
        ));
        drop(guard);
        let guard = domain.try_read(&operation).unwrap();
        stamp.validate(&guard, &store).unwrap();
    }
    #[test]
    fn actual_logout_fence_and_failed_owner_each_withhold_socket_output() {
        for failed in [false, true] {
            setup!(_root, store, project, domain, cancel, operation, peer);
            let mut write = begin(&domain, &operation, &store, &peer);
            commit(
                &mut write,
                &mut store,
                &call(&project, 100, "before logout"),
            )
            .unwrap();
            let watcher = write
                .finish()
                .unwrap_or_else(|_| panic!("committed stamp"))
                .into_io_watcher();
            if failed {
                domain.fail_remote();
            } else {
                let mut revoke = domain
                    .announce(&operation, WriterClass::Shared, Intent::FenceRemote)
                    .unwrap();
                revoke
                    .try_enter()
                    .unwrap()
                    .commit(|| {
                        store.fence_authorization(
                            lomi_host_store::AuthorizationFenceReason::LocalLogout,
                        )?;
                        Ok::<_, StoreError>(((), StoreView::read(&store)?))
                    })
                    .unwrap();
                revoke.finish().unwrap();
                assert!(store.authorization_state().unwrap().pending_cloud_revoke);
            }
            assert!(watcher.check().is_err());
        }
    }

    #[test]
    fn postcommit_original_cancellation_fences_without_losing_durable_receipt() {
        setup!(_root, store, project, domain, cancel, operation, peer);
        let request = call(&project, 101, "committed before cancellation");
        let mut write = begin(&domain, &operation, &store, &peer);
        commit(&mut write, &mut store, &request).unwrap();
        assert_eq!(write.phase(), RemoteRenamePhase::Committed);
        cancel.store(true, SeqCst);
        assert!(matches!(write.finish(), Err(Error::Cancelled)));
        assert!(domain.failed_remote.load(SeqCst));
        assert_eq!(domain.pending.load(SeqCst), 0);
        let receipt = store
            .lookup(&binding(&request, actor()), &required())
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state(), OperationState::Succeeded);
        assert_eq!(receipt.effect(), Effect::Committed);
        assert_eq!(store.pending_publications().unwrap().len(), 1);
    }
    #[test]
    fn socket_watcher_contains_only_sync_sealed_state() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<RemoteRenameReceiptWatcher<'static, 'static>>();
    }

    fn assert_post_release_failure(action: u8, expected: Error) {
        assert_post_release_edit_failure(action, expected, false);
    }
    fn assert_post_release_edit_failure(action: u8, expected: Error, movement: bool) {
        setup!(
            _root,
            store,
            project,
            domain,
            cancel,
            operation,
            peer,
            configured_fixture_layout(movement.then_some(true))
        );
        let request = if movement {
            move_call(&project, 102, MovePlacement::Before)
        } else {
            call(&project, 102, "committed before release gap")
        };
        let mut write = begin(&domain, &operation, &store, &peer);
        let admitted = commit(&mut write, &mut store, &request).unwrap();
        assert!(admitted.newly_admitted);
        assert_eq!(admitted.receipt.state(), OperationState::Succeeded);
        assert_eq!(admitted.receipt.effect(), Effect::Committed);
        let issued = domain.issued.load(SeqCst);
        AFTER_RELEASE.with(|seam| seam.set(action));
        match write.finish() {
            Err(error) => assert_eq!(error, expected),
            Ok(_) => panic!("post-release failure must not mint a receipt stamp"),
        }
        assert_eq!(AFTER_RELEASE.with(Cell::get), 0);
        assert_eq!(domain.pending.load(SeqCst), 0);
        assert_eq!(domain.shared_pending.load(SeqCst), 0);
        assert!(domain.failed_remote.load(SeqCst));
        assert_eq!(domain.issued.load(SeqCst), issued + u64::from(action == 3));
        let receipt = store
            .lookup(&binding(&request, actor()), &required())
            .unwrap()
            .unwrap();
        assert_eq!(receipt, admitted.receipt);
        assert_eq!(receipt.state(), OperationState::Succeeded);
        assert_eq!(receipt.effect(), Effect::Committed);
        assert_eq!(store.pending_publications().unwrap().len(), 1);
    }
    #[test]
    fn post_release_original_cancellation_fences_without_minting_stamp() {
        assert_post_release_failure(1, Error::Cancelled);
    }
    #[test]
    fn post_release_original_expiry_fences_without_minting_stamp() {
        assert_post_release_failure(2, Error::Deadline);
    }
    #[test]
    fn post_release_later_abandoned_announcement_fences_without_minting_stamp() {
        assert_post_release_failure(3, Error::Stale);
    }

    fn move_call(project: &ProjectRecord, operation: u8, placement: MovePlacement) -> RpcCall {
        let RpcCall::TerminalRename(rename) = call(project, operation, "unused") else {
            unreachable!()
        };
        RpcCall::TerminalMove(TerminalMoveParams {
            mutation: rename.mutation,
            pane_id: PaneId::from_bytes([73; 16]).unwrap(),
            source_tab_id: project.state.tabs.0[0].tab_id,
            target_tab_id: project.state.tabs.0.last().unwrap().tab_id,
            target_pane_id: PaneId::from_bytes([77; 16]).unwrap(),
            placement,
        })
    }
    #[test]
    fn move_same_and_cross_tab_before_after_preserves_exact_local_tuple_and_one_settlement() {
        for cross_tab in [false, true] {
            for placement in [MovePlacement::Before, MovePlacement::After] {
                setup!(
                    _root,
                    store,
                    project,
                    domain,
                    cancel,
                    operation,
                    peer,
                    configured_fixture_layout(Some(cross_tab))
                );
                let request = move_call(&project, 110, placement);
                let edit =
                    super::super::remote_terminal_rename::RemoteTerminalEdit::from_call(&request)
                        .unwrap();
                let expected = edit.expected_state(&project.state).unwrap();
                assert_ne!(edit.mutation().context, expected.context);
                let descriptors = store
                    .terminal_descriptors(project.state.context.workspace_id)
                    .unwrap();
                let events = store.events_after(0).unwrap();
                let authority = domain.state.lock().unwrap().authority_revision;
                let mut write = begin(&domain, &operation, &store, &peer);
                let reads = post_reads();
                let admission = commit(&mut write, &mut store, &request).unwrap();
                assert_eq!(post_reads(), reads + 1);
                assert!(admission.newly_admitted);
                assert_eq!(
                    admission.receipt.stored_rights().original_method(),
                    Method::TerminalMove
                );
                assert_eq!(admission.receipt.stored_rights().actor(), actor());
                assert_eq!(
                    admission.receipt.stored_rights().actual_rights(),
                    &required()
                );
                assert_eq!(
                    store
                        .lookup(&binding(&request, actor()), &required())
                        .unwrap(),
                    Some(admission.receipt)
                );
                let after = store.workspace(project.state.context.workspace_id).unwrap();
                assert_eq!(after.state, expected);
                assert_eq!(after.local_root, project.local_root);
                assert_eq!(after.fence, project.fence);
                assert_eq!(after.consent, project.consent);
                let after_descriptors = store
                    .terminal_descriptors(project.state.context.workspace_id)
                    .unwrap();
                assert_eq!(format!("{descriptors:?}"), format!("{after_descriptors:?}"));
                let after_events = store.events_after(0).unwrap();
                assert_eq!(after_events.events.len(), events.events.len() + 1);
                assert_eq!(
                    after_events.events.last().unwrap().operation_id,
                    Some(edit.mutation().operation_id)
                );
                assert_eq!(store.pending_publications().unwrap().len(), 1);
                assert_eq!(
                    domain.state.lock().unwrap().authority_revision,
                    authority + 1
                );
                let watcher = write
                    .finish()
                    .unwrap_or_else(|_| panic!("committed move stamp"))
                    .into_io_watcher();
                assert_eq!(watcher.deadline(), operation.deadline());
                assert_eq!(watcher.check(), Ok(()));
                let mut later = domain
                    .register_writer(&operation, WriterClass::Shared, Intent::Mutation)
                    .unwrap();
                later.release();
                assert_eq!(watcher.check(), Err(Error::Stale));
            }
        }
    }
    #[test]
    fn move_invalid_membership_and_stale_cas_are_known_no_effect_with_one_postview() {
        for scenario in 0..4 {
            setup!(
                _root,
                store,
                project,
                domain,
                cancel,
                operation,
                peer,
                configured_fixture_layout(Some(true))
            );
            let mut request = move_call(&project, 111, MovePlacement::After);
            let RpcCall::TerminalMove(params) = &mut request else {
                unreachable!()
            };
            let expected_error = match scenario {
                0 => {
                    params.mutation.expected_revision.0 += 1;
                    StoreError::RevisionConflict
                }
                1 => {
                    params.pane_id = params.target_pane_id;
                    StoreError::Invalid
                }
                2 => {
                    params.source_tab_id = TabId::from_bytes([109; 16]).unwrap();
                    StoreError::NotFound
                }
                _ => {
                    params.target_pane_id = PaneId::from_bytes([109; 16]).unwrap();
                    StoreError::NotFound
                }
            };
            let mut write = begin(&domain, &operation, &store, &peer);
            let reads = post_reads();
            assert!(
                matches!(commit(&mut write, &mut store, &request), Err(StepError::Source(error)) if error == expected_error)
            );
            assert_eq!(post_reads(), reads + 1);
            assert_eq!(write.phase(), RemoteRenamePhase::KnownNoEffect);
            write.abandon().unwrap();
            assert_eq!(
                store
                    .workspace(project.state.context.workspace_id)
                    .unwrap()
                    .state,
                project.state
            );
            assert!(store.pending_publications().unwrap().is_empty());
            assert!(
                store
                    .lookup(&binding(&request, actor()), &required())
                    .unwrap()
                    .is_none()
            );
        }
    }
    #[test]
    fn move_original_expiry_cancellation_and_later_announcement_block_store_entry() {
        for scenario in 0..3 {
            setup!(
                _root,
                store,
                project,
                domain,
                cancel,
                operation,
                peer,
                configured_fixture_layout(Some(true))
            );
            let request = move_call(&project, 112, MovePlacement::Before);
            let mut write = begin(&domain, &operation, &store, &peer);
            match scenario {
                0 => cancel.store(true, SeqCst),
                1 => operation.expire_for_test(),
                _ => {
                    let mut later = domain
                        .register_writer(&operation, WriterClass::Shared, Intent::Mutation)
                        .unwrap();
                    later.release();
                }
            }
            let reads = post_reads();
            assert!(commit(&mut write, &mut store, &request).is_err());
            assert_eq!(post_reads(), reads);
            assert_eq!(write.phase(), RemoteRenamePhase::StoreNotCalled);
            let _ = write.abandon();
            assert_eq!(
                store
                    .workspace(project.state.context.workspace_id)
                    .unwrap()
                    .state,
                project.state
            );
            assert!(store.pending_publications().unwrap().is_empty());
        }
    }
    #[test]
    fn move_committed_receipt_survives_failed_postview_without_delivery_stamp() {
        setup!(
            _root,
            store,
            project,
            domain,
            cancel,
            operation,
            peer,
            configured_fixture_layout(Some(true))
        );
        let request = move_call(&project, 113, MovePlacement::After);
        let mut write = begin(&domain, &operation, &store, &peer);
        FAIL_POST.with(|fault| fault.set(true));
        assert!(commit(&mut write, &mut store, &request).is_err());
        assert_eq!(write.phase(), RemoteRenamePhase::Uncertain);
        drop(write);
        assert!(domain.failed_remote.load(SeqCst));
        assert_eq!(
            store
                .lookup(&binding(&request, actor()), &required())
                .unwrap()
                .unwrap()
                .effect(),
            Effect::Committed
        );
        assert_eq!(store.pending_publications().unwrap().len(), 1);
    }

    #[test]
    fn move_post_release_cancellation_expiry_and_competing_ticket_withhold_stamp() {
        assert_post_release_edit_failure(1, Error::Cancelled, true);
        assert_post_release_edit_failure(2, Error::Deadline, true);
        assert_post_release_edit_failure(3, Error::Stale, true);
    }
}
