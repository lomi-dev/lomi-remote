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
        if Instant::now() >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
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

        let outcome = store.prepare_host_publication(plan.binding());
        let known_no_effect = outcome
            .as_ref()
            .err()
            .is_some_and(|error| PublicationAction::Prepare.expected(*error));
        if outcome.is_err() && !known_no_effect {
            store.seal_authorization();
            guard.writer.fail(Error::Denied);
        }
        let post = StoreView::read(&store); // Exactly once after either action outcome.

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

        let outcome = store.acknowledge_host_publication(&intent, response.result());
        let known_no_effect = outcome
            .as_ref()
            .err()
            .is_some_and(|error| PublicationAction::Ack.expected(*error));
        if outcome.is_err() && !known_no_effect {
            store.seal_authorization();
            guard.writer.fail(Error::Denied);
        }
        let post = StoreView::read(&store); // Exactly once after either action outcome.

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
}
impl Drop for OwnerGuard<'_, '_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.domain.fail_remote();
        }
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
