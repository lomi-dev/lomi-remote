//! Runtime/publication steps run on the same credential owner and operation.
use super::super::shared_owner::{
    CloudClaimAdmission, CloudGetDecision, CloudGetError, ConfiguredCloudAttempt,
    ConfiguredNormalPublication, PublicationError,
};
use super::*;
use lomi_host_http::{DataTransport, RemoteApiOrigin};
use lomi_host_store::{CloudRuntimeScope, CloudRuntimeState, HostAcknowledgedPublication};

use lomi_remote_protocol::{HostAccessCredential, http::*};
use sha2::{Digest, Sha256};

pub(super) enum StepOutcome {
    Network,
    Deferred,
    PeerEligible(Box<PeerEligibility>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct HeartbeatObservation {
    pub(in super::super) scope: CloudRuntimeScope,
    pub(in super::super) runtime: RuntimeBinding,
    pub(in super::super) request_started: Instant,
    pub(in super::super) wall_at_request_start: u64,
    pub(in super::super) lease_ms: u64,
    pub(in super::super) freshness_ms: u64,
}
/// Observation only. Each consumer must obtain its own typed effect admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct PeerEligibility {
    pub(in super::super) identity: lomi_host_auth::PublicHostIdentity,
    pub(in super::super) binding: CloudRuntimeState,
    pub(in super::super) publication: HostAcknowledgedPublication,
    pub(in super::super) heartbeat: HeartbeatObservation,
}
#[derive(Default)]
enum Action {
    #[default]
    Get,
    Claim(DecimalU64),
    Online,
    Blocked,
}
#[derive(Default)]
pub(super) struct Worker {
    transport: Option<DataTransport>,
    scope: Option<CloudRuntimeScope>,
    action: Action,
    claim: Option<CloudClaimAdmission>,
    awaiting_claim_get: bool,
    unit_pending: bool,
    lease_until: Option<Instant>,
    fresh_until: Option<Instant>,
    heartbeat_at: Option<Instant>,
    publication_turn: bool,
    heartbeat_observation: Option<HeartbeatObservation>,
    logout_epoch_attempt: Option<(u64, [u8; 32])>,
    normal_publication_origin: Option<NormalConfiguredOrigin>,
    normal_worker_identity: std::sync::Arc<()>,
    pending_publication: Option<super::super::shared_owner::OwnedConfiguredHeartbeat>,
    eligibility: Option<Box<PeerEligibility>>,
}
fn cloud_error(error: CloudGetError) -> StepError {
    match error {
        CloudGetError::Provider(error) => error.into(),
        CloudGetError::Http(error) => error.into(),
        CloudGetError::Domain(
            DomainError::Busy | DomainError::Cancelled | DomainError::Deadline | DomainError::Stale,
        )
        | CloudGetError::Stale
        | CloudGetError::Store(StoreError::Fenced) => StepError::Stale,
        _ => lomi_host_auth::Error::Sealed.into(),
    }
}
fn publication_error(error: PublicationError) -> StepError {
    match error {
        PublicationError::Auth(error) => error.into(),
        PublicationError::Http(error) => error.into(),
        PublicationError::Domain(
            DomainError::Busy | DomainError::Cancelled | DomainError::Deadline | DomainError::Stale,
        )
        | PublicationError::Stale => StepError::Stale,
        _ => lomi_host_auth::Error::Sealed.into(),
    }
}
pub(super) fn guard(runtime: Runtime<'_>, generation: u64) -> Result<(), StepError> {
    runtime.check()?;
    if runtime.gate.load(Ordering::Acquire) {
        return Err(StepError::Stale);
    }
    let state = match runtime.owner.remote_authorization(runtime.operation) {
        Ok(state) => state,
        Err(error) => return Err(error.into()),
    };
    if state.generation != generation || state.locked || state.pending_cloud_revoke {
        return Err(StepError::Stale);
    }
    Ok(())
}
impl Worker {
    pub(super) fn cached_eligibility(&self) -> Option<&PeerEligibility> {
        self.eligibility.as_deref()
    }
    pub(super) fn has_retained_operation(&self) -> bool {
        self.claim.is_some()
            || self.awaiting_claim_get
            || self.unit_pending
            || self.pending_publication.is_some()
    }
    /// Called only after every class has settled/discarded its original unit.
    /// No heartbeat/GET observation survives into a successor admission.
    pub(super) fn finish_operation(&mut self) {
        self.claim = None;
        self.awaiting_claim_get = false;
        self.unit_pending = false;
        self.pending_publication = None;
        self.normal_publication_origin = None;
        self.heartbeat_observation = None;
        self.eligibility = None;
        self.lease_until = None;
        self.fresh_until = None;
        self.heartbeat_at = None;
        self.publication_turn = false;
        if !matches!(self.action, Action::Blocked) {
            self.action = Action::Get;
        }
    }
    fn clear_observations(&mut self) {
        self.pending_publication = None;
        self.normal_publication_origin = None;
        self.heartbeat_observation = None;
        self.eligibility = None;
        self.lease_until = None;
        self.fresh_until = None;
        self.heartbeat_at = None;
        self.publication_turn = false;
    }
    pub(super) fn logout_epoch_step(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        _config: &Config,
        runtime: Runtime<'_>,
        generation: u64,
    ) -> Result<bool, StepError> {
        self.finish_operation();
        runtime.check()?;
        if auth.status() != Status::Ready {
            self.logout_epoch_attempt = None;
            return Ok(false);
        }
        let now = runtime
            .base
            .saturating_add(runtime.anchor.elapsed().as_secs());
        if !fresh_access(auth, now) {
            return Ok(false);
        }
        let access = auth.access_credential(now)?;
        let access_identity: [u8; 32] = Sha256::digest(access.expose_wire().as_bytes()).into();
        if self.logout_epoch_attempt.as_ref().is_some_and(
            |(attempt_generation, attempted_identity)| {
                *attempt_generation == generation && attempted_identity == &access_identity
            },
        ) {
            return Ok(false);
        }
        let selection = runtime.owner.auth_selection(runtime.operation)?;
        if selection
            .configuration
            .as_ref()
            .and_then(|c| c.remote_api_origin.as_ref())
            .is_none()
        {
            return Ok(false);
        }
        let mut turn = runtime.owner.begin_logout_epoch(
            runtime.operation,
            auth,
            runtime.public_io,
            runtime.gate,
            runtime.paused,
            runtime.stopping,
            runtime.base,
            runtime.anchor,
            generation,
        );
        let outcome = loop {
            runtime.check()?;
            match turn.try_step() {
                Ok(true) => break Ok(true),
                Ok(false) => {}
                Err(CloudGetError::Domain(DomainError::Busy)) => runtime.busy()?,
                Err(error) => break Err(cloud_error(error)),
            }
        };
        if turn.allows_identity_revoke() {
            self.logout_epoch_attempt = Some((generation, access_identity));
        }
        outcome
    }
    pub(super) fn step(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        generation: u64,
    ) -> Result<StepOutcome, StepError> {
        self.run_step(auth, config, runtime, generation)
    }
    fn run_step(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        generation: u64,
    ) -> Result<StepOutcome, StepError> {
        guard(runtime, generation)?;

        let Some(snapshot) = runtime
            .owner
            .cloud_worker_snapshot(runtime.operation, generation)?
        else {
            self.finish_operation();
            return Ok(StepOutcome::Deferred);
        };

        if self.scope.as_ref() != Some(&snapshot.scope) {
            self.finish_operation();
            self.scope = Some(snapshot.scope.clone());
            self.action = Action::Get;
        }
        if self.transport.is_none() {
            // TLS/client construction is outside Domain/Store. The cached client
            // is diagnostic/owned IO only, never an authority or injected permit.
            let origin = RemoteApiOrigin::new(config, snapshot.scope.remote_api_origin.clone())?;
            self.transport = Some(runtime.public_io.data_transport(origin)?);
        }
        match self.action {
            Action::Blocked => {
                self.clear_observations();
                Ok(StepOutcome::Deferred)
            }
            Action::Get => {
                self.clear_observations();
                let mut attempt = ConfiguredCloudAttempt::from_existing_worker(
                    auth,
                    runtime.public_io,
                    runtime.gate,
                    runtime.paused,
                    runtime.stopping,
                    runtime.base,
                    runtime.anchor,
                );
                let mut turn = attempt
                    .begin_get(runtime.owner, runtime.operation)
                    .map_err(cloud_error)?;
                loop {
                    runtime.check()?;
                    match turn.try_step() {
                        Ok(true) => break,
                        Ok(false) => {}
                        Err(CloudGetError::Domain(DomainError::Busy)) => runtime.busy()?,
                        Err(error) => {
                            if matches!(turn.take_decision(), Some(CloudGetDecision::Blocked)) {
                                return self.block();
                            }
                            return Err(cloud_error(error));
                        }
                    }
                }
                self.awaiting_claim_get = false;
                match turn.take_decision().ok_or(StepError::Stale)? {
                    CloudGetDecision::Blocked => self.block(),
                    CloudGetDecision::Claim(expected_generation) => {
                        self.claim = turn.take_claim_admission();
                        if self.claim.is_some() {
                            self.action = Action::Claim(expected_generation);
                            self.unit_pending = true;
                        } else {
                            self.action = Action::Get;
                            self.unit_pending = false;
                        }
                        Ok(StepOutcome::Network)
                    }
                    CloudGetDecision::Online {
                        binding,
                        lease_until,
                    } => {
                        if binding
                            .as_ref()
                            .is_none_or(|binding| binding.scope != snapshot.scope)
                        {
                            return Err(StepError::Stale);
                        }
                        self.action = Action::Online;
                        self.lease_until = lease_until;
                        self.unit_pending = true;
                        Ok(StepOutcome::Network)
                    }
                }
            }
            Action::Claim(expected_generation) => {
                self.clear_observations();
                // Pre-arm reconciliation before any possible POST. A response,
                // timeout, cancellation or malformed response can never retry it.
                self.action = Action::Get;
                let mut admission = self.claim.take().ok_or(StepError::Stale)?;
                if admission.expected_generation() != expected_generation {
                    return Err(StepError::Stale);
                }
                let mut turn = admission
                    .begin(
                        runtime.owner,
                        runtime.operation,
                        auth,
                        runtime.public_io,
                        runtime.gate,
                        runtime.paused,
                        runtime.stopping,
                        runtime.base,
                        runtime.anchor,
                    )
                    .map_err(cloud_error)?;
                let result = loop {
                    runtime.check()?;
                    match turn.try_step() {
                        Ok(true) => break Ok(StepOutcome::Network),
                        Ok(false) => {}
                        Err(CloudGetError::Domain(DomainError::Busy)) => runtime.busy()?,
                        Err(error) => break Err(cloud_error(error)),
                    }
                };
                drop(turn);
                self.awaiting_claim_get = admission.was_sent();
                self.unit_pending = self.awaiting_claim_get;
                result
            }
            Action::Online => {
                let now = Instant::now();
                if self.lease_until.is_none_or(|until| now >= until) {
                    self.clear_observations();
                    self.action = Action::Get;
                    self.unit_pending = false;
                    return Ok(StepOutcome::Deferred);
                }
                if snapshot.binding.as_ref().is_none_or(|binding| {
                    self.heartbeat_observation
                        .as_ref()
                        .is_some_and(|heartbeat| {
                            heartbeat.scope != binding.scope
                                || heartbeat.runtime != binding.server_runtime
                        })
                }) {
                    self.clear_observations();
                    self.action = Action::Get;
                    self.unit_pending = false;
                    return Ok(StepOutcome::Deferred);
                }
                let heartbeat_due = self.fresh_until.is_none_or(|until| now >= until)
                    || self.heartbeat_at.is_none_or(|until| now >= until);
                if let Some(receipt) = self.pending_publication.take() {
                    let driver = self.normal_publication_driver().ok_or(StepError::Stale)?;
                    let mut attempt = ConfiguredNormalPublication::from_retained_heartbeat(
                        auth,
                        driver,
                        runtime.operation,
                        runtime.public_io,
                        runtime.gate,
                        runtime.paused,
                        runtime.stopping,
                        receipt,
                    )
                    .map_err(publication_error)?;
                    let outcome = (|| -> Result<(), StepError> {
                        let mut publication =
                            attempt.begin(runtime.owner).map_err(publication_error)?;
                        loop {
                            runtime.check()?;
                            match publication.try_step() {
                                Ok(true) => break,
                                Ok(false) => {}
                                Err(PublicationError::Domain(DomainError::Busy)) => {
                                    runtime.busy()?
                                }
                                Err(error) => return Err(publication_error(error)),
                            }
                        }
                        Ok(())
                    })();
                    drop(attempt);
                    match outcome {
                        Err(StepError::Http(lomi_host_http::Error::InvalidResponse)) => {
                            return self.block();
                        }
                        Err(
                            error @ StepError::Http(lomi_host_http::Error::DataRemote(
                                lomi_host_http::DataFailure::OutcomeUnknown,
                            )),
                        ) => {
                            // The server may have committed the publication. Do
                            // not retry it from the current observation; reconcile
                            // the committed cursor and state with a fresh GET.
                            self.action = Action::Get;
                            return Err(error);
                        }
                        Err(error) => return Err(error),
                        Ok(()) => {}
                    }
                    Ok(StepOutcome::Network)
                } else if heartbeat_due || snapshot.needs_publication {
                    let driver = self.normal_publication_driver().ok_or(StepError::Stale)?;

                    let mut attempt = ConfiguredNormalPublication::from_existing_worker(
                        auth,
                        driver,
                        runtime.operation,
                        runtime.public_io,
                        runtime.gate,
                        runtime.paused,
                        runtime.stopping,
                        runtime.base,
                        runtime.anchor,
                    );
                    let outcome = (|| -> Result<(), StepError> {
                        let mut heartbeat = attempt
                            .begin_configured_heartbeat(runtime.owner)
                            .map_err(publication_error)?;
                        loop {
                            runtime.check()?;
                            match heartbeat.try_step() {
                                Ok(true) => break,
                                Ok(false) => {}
                                Err(PublicationError::Domain(DomainError::Busy)) => {
                                    runtime.busy()?
                                }
                                Err(error) => return Err(publication_error(error)),
                            }
                        }
                        Ok(())
                    })();
                    match outcome {
                        Err(StepError::Http(lomi_host_http::Error::InvalidResponse)) => {
                            drop(attempt);
                            return self.block();
                        }
                        Err(error) => return Err(error),
                        Ok(()) => {}
                    }
                    let receipt = if snapshot.needs_publication {
                        Some(
                            attempt
                                .retain_configured_heartbeat()
                                .map_err(publication_error)?,
                        )
                    } else {
                        attempt.finish_heartbeat_only().map_err(publication_error)?;
                        drop(attempt);
                        None
                    };
                    self.pending_publication = receipt;
                    self.unit_pending = true;
                    Ok(StepOutcome::Network)
                } else {
                    let outcome = self.peer_eligibility(auth, runtime, generation)?;
                    self.unit_pending = false;
                    Ok(outcome)
                }
            }
        }
    }
    fn peer_eligibility(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        generation: u64,
    ) -> Result<StepOutcome, StepError> {
        guard(runtime, generation)?;
        let Some(heartbeat) = self.heartbeat_observation.clone() else {
            return Ok(StepOutcome::Deferred);
        };
        let floor = runtime
            .owner
            .authorization_state(runtime.operation)?
            .clock_floor;
        let now = runtime
            .base
            .saturating_add(runtime.anchor.elapsed().as_secs())
            .max(floor);
        let identity = auth.public_host_identity(now)?;
        let epoch = auth.verified_host_access_epoch()?;
        let deadlines = auth.credential_deadlines()?;
        if !fresh_access(auth, now) || now >= deadlines.refresh_at {
            return Err(StepError::Stale);
        }
        // Fixed owner read after the last provider operation. This DTO grants no
        // effect permission; the consumer captures its own original admission.
        let Some(snapshot) = runtime
            .owner
            .cloud_worker_snapshot(runtime.operation, generation)?
        else {
            return Ok(StepOutcome::Deferred);
        };
        let Some(binding) = snapshot.binding else {
            return Ok(StepOutcome::Deferred);
        };
        let Some(publication) = snapshot.acknowledged else {
            return Ok(StepOutcome::Deferred);
        };
        let checked = Instant::now();
        if snapshot.needs_publication
            || publication.state != binding
            || heartbeat.scope != binding.scope
            || heartbeat.runtime != binding.server_runtime
            || identity.host_id != binding.scope.host_id
            || identity.access_epoch != epoch.0
            || epoch != binding.server_runtime.host_access_epoch
            || heartbeat.wall_at_request_start > now
            || self.lease_until
                != heartbeat
                    .request_started
                    .checked_add(Duration::from_millis(heartbeat.lease_ms))
            || self.fresh_until
                != heartbeat
                    .request_started
                    .checked_add(Duration::from_millis(heartbeat.freshness_ms))
            || self.lease_until.is_none_or(|until| checked >= until)
            || self.fresh_until.is_none_or(|until| checked >= until)
        {
            self.heartbeat_observation = None;
            return Ok(StepOutcome::Deferred);
        }
        runtime.check()?;
        let eligibility = Box::new(PeerEligibility {
            identity,
            binding,
            publication,
            heartbeat,
        });
        self.eligibility = Some(eligibility.clone());
        Ok(StepOutcome::PeerEligible(eligibility))
    }
    fn block<T>(&mut self) -> Result<T, StepError> {
        self.action = Action::Blocked;
        self.claim = None;
        self.awaiting_claim_get = false;
        self.unit_pending = false;
        self.clear_observations();
        Err(lomi_host_http::Error::InvalidResponse.into())
    }
}

/// Maintain only the already-bound runtime lease for one Started Git writer.
/// This path never reads Cloud eligibility or calls claim/publication APIs.
pub(super) fn maintain_started_git_control_plane(
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    runtime: RuntimeWithOperation<'_, '_>,
    continuation: &super::shared_owner::StartedGitContinuation,
) -> Result<bool, StepError> {
    use std::sync::atomic::Ordering::Acquire;

    let operation = runtime.operation;
    if auth.status() != Status::Ready
        || runtime.check().is_err()
        || !continuation.is_current(operation)
    {
        return Err(StepError::Stale);
    }
    if !started_git_publication_clear(runtime, continuation)? {
        return Ok(false);
    }
    let now_mono = Instant::now();
    let heartbeat_deadline = continuation.heartbeat_deadline();
    if now_mono >= heartbeat_deadline {
        return Err(StepError::Stale);
    }
    let peer_deadline = continuation.peer_deadline();
    if now_mono >= peer_deadline {
        return Err(StepError::Stale);
    }
    let heartbeat_due =
        heartbeat_deadline.saturating_duration_since(now_mono) <= Duration::from_millis(2_500);
    let peer_due =
        peer_deadline.saturating_duration_since(now_mono) <= Duration::from_millis(2_500);
    if !heartbeat_due && !peer_due {
        return Ok(false);
    }

    let mut refreshed = false;
    let mut peer_attempted = false;
    if peer_due && (!heartbeat_due || peer_deadline < heartbeat_deadline) {
        if !started_git_publication_clear(runtime, continuation)? {
            return Ok(false);
        }
        peer_attempted = true;
        refreshed = super::peer::refresh_started_git_pairing(auth, runtime, continuation)?;
        if !started_git_publication_clear(runtime, continuation)? {
            return Ok(refreshed);
        }
    }

    let validate_local = |auth: &HostAuth<'_, dyn SecretStorage + '_>,
                          runtime: RuntimeWithOperation<'_, '_>|
     -> Result<
        (
            u64,
            lomi_host_auth::CredentialDeadlines,
            HostAccessCredential,
        ),
        StepError,
    > {
        runtime.check()?;
        if auth.status() != Status::Ready || !continuation.is_current(runtime.operation) {
            return Err(StepError::Stale);
        }
        let now = runtime.projected_time();
        let status = runtime
            .owner
            .auth_status_started_git(runtime.operation, continuation)
            .map_err(|_| StepError::Stale)?;
        let selection = runtime
            .owner
            .auth_selection_started_git(runtime.operation, continuation)
            .map_err(|_| StepError::Stale)?;
        if status.authorization.generation != continuation.runtime().scope.authorization_generation
            || status.authorization.locked
            || status.authorization.pending_cloud_revoke
            || selection.verified_generation != Some(status.authorization.generation)
            || selection.configuration.as_ref() != Some(continuation.credential_configuration())
            || selection.identity != *continuation.store_identity()
        {
            return Err(StepError::Stale);
        }
        let identity = auth
            .public_host_identity(now)
            .map_err(|_| StepError::Stale)?;
        let epoch = auth
            .verified_host_access_epoch()
            .map_err(|_| StepError::Stale)?;
        let deadlines = auth.credential_deadlines().map_err(|_| StepError::Stale)?;
        if identity != *continuation.identity()
            || epoch.0 != continuation.runtime().server_runtime.host_access_epoch.0
            || now >= deadlines.access_expires_at
            || now >= deadlines.refresh_at
        {
            return Err(StepError::Stale);
        }
        let access = auth.access_credential(now).map_err(|_| StepError::Stale)?;
        if !continuation.is_current(runtime.operation) {
            return Err(StepError::Stale);
        }
        Ok((now, deadlines, access))
    };

    if heartbeat_due {
        let (_wall_now, _deadlines, access) = validate_local(auth, runtime)?;
        let expected = continuation.runtime();
        let origin = RemoteApiOrigin::new(
            auth.trusted_configuration(),
            expected.scope.remote_api_origin.clone(),
        )?;
        let transport = runtime.public_io.data_transport(origin)?;
        let hard_deadline = continuation.hard_deadline().min(operation.deadline());
        let gate = runtime.gate;
        let paused = runtime.paused;
        let stopping = runtime.stopping;
        let public_pending = &runtime.public_io.setup().pending;
        let check = || {
            operation.check().map_err(|error| match error {
                DomainError::Deadline => lomi_host_http::BudgetStop::Deadline,
                _ => lomi_host_http::BudgetStop::Cancelled,
            })?;
            if gate.load(Acquire)
                || paused.load(Acquire)
                || stopping.load(Acquire)
                || public_pending.load(Acquire)
                || !continuation.is_current(operation)
            {
                return Err(lomi_host_http::BudgetStop::Cancelled);
            }
            Ok(())
        };
        check().map_err(|_| StepError::Stale)?;
        let budget = transport.with_budget(hard_deadline, &check);
        let get = budget
            .runtime_get(expected.scope.host_id, &access)
            .map_err(StepError::Http)?;
        check().map_err(|_| StepError::Stale)?;
        if !started_git_publication_clear(runtime, continuation)? {
            return Ok(false);
        }
        let (wall_now, deadlines, access) = validate_local(auth, runtime)?;
        if get.host_id != expected.scope.host_id
            || get.host_access_epoch != expected.server_runtime.host_access_epoch
            || get.runtime_generation != expected.server_runtime.runtime_generation
            || get.runtime.as_ref() != Some(&expected.server_runtime)
            || get.publication_seq != expected.acknowledged_publication_seq
            || get.lease_ms.0 == 0
            || get.lease_ms.0 > 30_000
            || get.freshness_ms.0 == 0
            || get.freshness_ms.0 > 5_000
            || get.freshness_ms.0 > get.lease_ms.0
            || wall_now >= deadlines.access_expires_at
            || wall_now >= deadlines.refresh_at
        {
            return Err(StepError::Stale);
        }

        // Start time is captured immediately before the only mutating control-plane
        // request. A slow response cannot manufacture a freshness window after the
        // original operation's hard deadline or signed/auth credential ceilings.
        let heartbeat_wall_at_start = wall_now;
        if !started_git_publication_clear(runtime, continuation)? {
            return Ok(false);
        }
        let request_started = Instant::now();
        if request_started >= continuation.heartbeat_deadline()
            || request_started >= hard_deadline
            || !continuation.is_current(operation)
        {
            return Err(StepError::Stale);
        }
        let response = budget
            .heartbeat(
                expected.scope.host_id,
                &HeartbeatParams {
                    runtime: expected.server_runtime.clone(),
                },
                &access,
            )
            .map_err(StepError::Http)?;
        check().map_err(|_| StepError::Stale)?;
        if !started_git_publication_clear(runtime, continuation)? {
            return Ok(false);
        }
        let (wall_now, deadlines, _) = validate_local(auth, runtime)?;
        if response.runtime != expected.server_runtime
            || response.lease_ms.0 == 0
            || response.lease_ms.0 > 30_000
            || response.freshness_ms.0 == 0
            || response.freshness_ms.0 > 5_000
            || response.freshness_ms.0 > response.lease_ms.0
            || wall_now >= deadlines.access_expires_at
            || wall_now >= deadlines.refresh_at
        {
            return Err(StepError::Stale);
        }
        continuation
            .renew_heartbeat(
                operation,
                HeartbeatObservation {
                    scope: expected.scope.clone(),
                    runtime: response.runtime,
                    request_started,
                    wall_at_request_start: heartbeat_wall_at_start,
                    lease_ms: response.lease_ms.0,
                    freshness_ms: response.freshness_ms.0,
                },
            )
            .map_err(|_| StepError::Stale)?;
        refreshed = true;
    }
    if peer_due && !peer_attempted {
        if !started_git_publication_clear(runtime, continuation)? {
            return Ok(refreshed);
        }
        let observed = super::peer::refresh_started_git_pairing(auth, runtime, continuation)?;
        if !started_git_publication_clear(runtime, continuation)? {
            return Ok(refreshed);
        }
        refreshed |= observed;
    }
    Ok(refreshed)
}

/// Negative-only check around control-plane callbacks. Store contention defers
/// the next callback without sealing authorization; a proven pending or changed
/// publication invalidates the Started lane.
fn started_git_publication_clear(
    runtime: RuntimeWithOperation<'_, '_>,
    continuation: &super::shared_owner::StartedGitContinuation,
) -> Result<bool, StepError> {
    use super::shared_owner::CloudPublicationFenceObservation as Observation;
    match runtime
        .owner
        .cloud_publication_fence_observation_started_git(
            runtime.operation,
            continuation,
            continuation.runtime().scope.authorization_generation,
            Some(&continuation.runtime().scope),
        )
        .map_err(|_| StepError::Stale)?
    {
        Observation::Clear => Ok(true),
        Observation::Defer => Ok(false),
        Observation::CloseIngress => Err(StepError::Stale),
    }
}

// Normal publication originates in the actual configured heartbeat driver.
// Test HTTP scripts are installed after that real constructor and admission.
#[cfg(any(unix, windows))]
struct NormalConfiguredOrigin {
    trusted: Config,
    provider: usize,
    epoch: DecimalU64,
    deadlines: lomi_host_auth::CredentialDeadlines,
    access: HostAccessCredential,
}
#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::unix) enum NormalPublicationOriginError {
    Auth(lomi_host_auth::Error),
    Http(lomi_host_http::Error),
    Stopped(crate::unix::owner_domain::Error),
    Stale,
}
#[cfg(any(unix, windows))]
pub(in crate::unix) struct NormalPublicationDriver<'w> {
    worker: &'w mut Worker,
    prepared: Option<ConfiguredHeartbeatPrepared>,
    original_lease_until: Option<Instant>,
    lease_now_test: Option<Instant>,
}
#[cfg(any(unix, windows))]
struct ConfiguredHeartbeatPrepared {
    trusted: Config,
    provider: usize,
    binding: CloudRuntimeState,
    epoch: DecimalU64,
    deadlines: lomi_host_auth::CredentialDeadlines,
    access: lomi_remote_protocol::HostAccessCredential,
    transport: DataTransport,
    response: Option<lomi_remote_protocol::http::HeartbeatResult>,
    request_started: Option<Instant>,
    wall_started: Option<u64>,
}
#[cfg(any(unix, windows))]
pub(in crate::unix) struct NormalPublicationObservation<'w, 'o> {
    worker: &'w mut Worker,
    operation: &'o crate::unix::owner_domain::Operation<'o>,
    binding: CloudRuntimeState,
    heartbeat: HeartbeatObservation,
    pre_heartbeat_lease_until: Option<Instant>,
    armed: bool,
    completed: bool,
    detached: bool,
    local_now_test: Option<Instant>,
}
#[cfg(any(unix, windows))]
impl Worker {
    pub(super) fn normal_publication_driver(&mut self) -> Option<NormalPublicationDriver<'_>> {
        if !matches!(self.action, Action::Online) {
            return None;
        }
        let original_lease_until = self.lease_until;
        Some(NormalPublicationDriver {
            worker: self,
            prepared: None,

            original_lease_until,
            lease_now_test: None,
        })
    }
}
#[cfg(any(unix, windows))]
impl<'w> NormalPublicationDriver<'w> {
    /// Original lease only: provider work, mutex retries and a new response
    /// cannot replace or extend this prerequisite for the actual send.
    fn check_original_heartbeat_lease(&self) -> Result<(), NormalPublicationOriginError> {
        let until = self
            .original_lease_until
            .ok_or(NormalPublicationOriginError::Stale)?;
        let now = self.lease_now_test.unwrap_or_else(Instant::now);
        if self.worker.lease_until != Some(until) || now >= until {
            return Err(NormalPublicationOriginError::Stale);
        }
        Ok(())
    }

    pub(in crate::unix) fn invalidate_heartbeat(&mut self) {
        self.worker.normal_publication_origin = None;
        self.worker.heartbeat_observation = None;
        self.worker.action = Action::Get;
    }
    /// Provider work only. The caller next checks the original Domain/Store
    /// scope and full captured tuple, with both locks dropped before send.
    pub(in crate::unix) fn prepare_configured_heartbeat<'p, S: SecretStorage + ?Sized>(
        &mut self,
        auth: &mut HostAuth<'p, S>,
        public_io: &super::super::public_configuration::WorkerPublicIo<'_>,
        binding: &CloudRuntimeState,
        now: u64,
    ) -> Result<(), NormalPublicationOriginError> {
        self.invalidate_heartbeat();
        self.check_original_heartbeat_lease()?;
        if self.prepared.is_some() || self.worker.scope.as_ref() != Some(&binding.scope) {
            return Err(NormalPublicationOriginError::Stale);
        }
        let trusted = auth.trusted_configuration().clone();
        let identity = auth
            .public_host_identity(now)
            .map_err(NormalPublicationOriginError::Auth)?;
        let deadlines = auth
            .credential_deadlines()
            .map_err(NormalPublicationOriginError::Auth)?;
        let epoch = auth
            .verified_host_access_epoch()
            .map_err(NormalPublicationOriginError::Auth)?;
        let access = auth
            .access_credential(now)
            .map_err(NormalPublicationOriginError::Auth)?;
        if identity.host_id != binding.scope.host_id
            || identity.access_epoch != binding.server_runtime.host_access_epoch.0
            || epoch != binding.server_runtime.host_access_epoch
            || now >= deadlines.refresh_at
        {
            return Err(NormalPublicationOriginError::Stale);
        }
        let origin = RemoteApiOrigin::new(&trusted, binding.scope.remote_api_origin.clone())
            .map_err(NormalPublicationOriginError::Http)?;
        let transport = public_io
            .data_transport(origin)
            .map_err(NormalPublicationOriginError::Http)?;
        self.prepared = Some(ConfiguredHeartbeatPrepared {
            trusted,
            provider: auth as *const _ as usize,
            binding: binding.clone(),
            epoch,
            deadlines,
            access,
            transport,
            response: None,
            request_started: None,
            wall_started: None,
        });
        Ok(())
    }
    /// Fixed configured TLS only; retained request start is written before IO.
    pub(in crate::unix) fn send_configured_heartbeat(
        &mut self,
        operation: &crate::unix::owner_domain::Operation<'_>,
        now: u64,
    ) -> Result<(), NormalPublicationOriginError> {
        self.check_original_heartbeat_lease()?;
        let prepared = self
            .prepared
            .as_mut()
            .ok_or(NormalPublicationOriginError::Stale)?;
        if prepared.request_started.is_some() || now >= prepared.deadlines.refresh_at {
            return Err(NormalPublicationOriginError::Stale);
        }
        operation
            .check()
            .map_err(NormalPublicationOriginError::Stopped)?;
        let check = || {
            operation.check().map_err(|error| match error {
                crate::unix::owner_domain::Error::Deadline => lomi_host_http::BudgetStop::Deadline,
                _ => lomi_host_http::BudgetStop::Cancelled,
            })
        };
        prepared.request_started = Some(Instant::now());
        prepared.wall_started = Some(now);
        prepared.response = Some(
            prepared
                .transport
                .with_budget(operation.deadline(), &check)
                .heartbeat(
                    prepared.binding.scope.host_id,
                    &HeartbeatParams {
                        runtime: prepared.binding.server_runtime.clone(),
                    },
                    &prepared.access,
                )
                .map_err(NormalPublicationOriginError::Http)?,
        );
        Ok(())
    }
    pub(in crate::unix) fn validate_configured_heartbeat<'p, S: SecretStorage + ?Sized>(
        &self,
        auth: &HostAuth<'p, S>,
        now: u64,
    ) -> Result<(), NormalPublicationOriginError> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(NormalPublicationOriginError::Stale)?;
        if prepared.provider != auth as *const _ as usize
            || &prepared.trusted != auth.trusted_configuration()
        {
            return Err(NormalPublicationOriginError::Stale);
        }
        let identity = auth
            .public_host_identity(now)
            .map_err(NormalPublicationOriginError::Auth)?;
        let access = auth
            .access_credential(now)
            .map_err(NormalPublicationOriginError::Auth)?;
        if identity.host_id != prepared.binding.scope.host_id
            || identity.access_epoch != prepared.epoch.0
            || auth
                .verified_host_access_epoch()
                .map_err(NormalPublicationOriginError::Auth)?
                != prepared.epoch
            || auth
                .credential_deadlines()
                .map_err(NormalPublicationOriginError::Auth)?
                != prepared.deadlines
            || access != prepared.access
            || now >= prepared.deadlines.refresh_at
        {
            return Err(NormalPublicationOriginError::Stale);
        }
        Ok(())
    }
    /// Only after the fixed post-response clock and original-scope check.
    pub(in crate::unix) fn install_configured_heartbeat<'o>(
        mut self,
        operation: &'o crate::unix::owner_domain::Operation<'o>,
        now: u64,
    ) -> Result<NormalPublicationObservation<'w, 'o>, NormalPublicationOriginError> {
        operation
            .check()
            .map_err(NormalPublicationOriginError::Stopped)?;
        let prepared = self
            .prepared
            .take()
            .ok_or(NormalPublicationOriginError::Stale)?;
        let response = prepared
            .response
            .ok_or(NormalPublicationOriginError::Stale)?;
        let request_started = prepared
            .request_started
            .ok_or(NormalPublicationOriginError::Stale)?;
        let wall_at_request_start = prepared
            .wall_started
            .ok_or(NormalPublicationOriginError::Stale)?;
        if response.runtime != prepared.binding.server_runtime
            || response.lease_ms.0 == 0
            || response.lease_ms.0 > 30_000
            || response.freshness_ms.0 == 0
            || response.freshness_ms.0 > 5_000
            || response.freshness_ms > response.lease_ms
        {
            return Err(NormalPublicationOriginError::Http(
                lomi_host_http::Error::InvalidResponse,
            ));
        }
        if wall_at_request_start > now
            || now >= prepared.deadlines.refresh_at
            || request_started
                .checked_add(Duration::from_millis(response.freshness_ms.0))
                .is_none_or(|end| Instant::now() >= end)
            || self.worker.scope.as_ref() != Some(&prepared.binding.scope)
        {
            return Err(NormalPublicationOriginError::Stale);
        }
        let heartbeat = HeartbeatObservation {
            scope: prepared.binding.scope.clone(),
            runtime: response.runtime,
            request_started,
            wall_at_request_start,
            lease_ms: response.lease_ms.0,
            freshness_ms: response.freshness_ms.0,
        };
        self.worker.lease_until =
            request_started.checked_add(Duration::from_millis(heartbeat.lease_ms));
        self.worker.fresh_until =
            request_started.checked_add(Duration::from_millis(heartbeat.freshness_ms));
        self.worker.heartbeat_at = request_started.checked_add(Duration::from_secs(1));
        self.worker.heartbeat_observation = Some(heartbeat.clone());
        self.worker.publication_turn = true;
        self.worker.normal_publication_origin = Some(NormalConfiguredOrigin {
            trusted: prepared.trusted,
            provider: prepared.provider,
            epoch: prepared.epoch,
            deadlines: prepared.deadlines,
            access: prepared.access,
        });
        self.worker.action = Action::Online;
        let observation = NormalPublicationObservation {
            worker: self.worker,
            operation,
            binding: prepared.binding,
            heartbeat,
            pre_heartbeat_lease_until: self.original_lease_until,
            armed: false,
            completed: false,
            detached: false,
            local_now_test: None,
        };
        observation.check_local(now)?;
        Ok(observation)
    }
}

#[cfg(any(unix, windows))]
pub(in crate::unix) struct OwnedNormalPublicationObservation {
    worker_identity: std::sync::Arc<()>,
    operation_identity: crate::unix::owner_domain::OperationIdentity,
    binding: CloudRuntimeState,
    heartbeat: HeartbeatObservation,
    pre_heartbeat_lease_until: Option<Instant>,
    local_now_test: Option<Instant>,
}
#[cfg(any(unix, windows))]
impl NormalPublicationObservation<'_, '_> {
    pub(in crate::unix) fn retain_owned(
        mut self,
        now: u64,
    ) -> Result<OwnedNormalPublicationObservation, NormalPublicationOriginError> {
        self.check_local(now)?;
        if self.armed || self.completed {
            return Err(NormalPublicationOriginError::Stale);
        }
        let receipt = OwnedNormalPublicationObservation {
            worker_identity: self.worker.normal_worker_identity.clone(),
            operation_identity: self.operation.retained_identity(),
            binding: self.binding.clone(),
            heartbeat: self.heartbeat.clone(),
            pre_heartbeat_lease_until: self.pre_heartbeat_lease_until,
            local_now_test: self.local_now_test,
        };
        self.detached = true;
        Ok(receipt)
    }
}
#[cfg(any(unix, windows))]
impl<'w> NormalPublicationDriver<'w> {
    pub(in crate::unix) fn resume_owned<'o>(
        self,
        receipt: OwnedNormalPublicationObservation,
        operation: &'o crate::unix::owner_domain::Operation<'o>,
        now: u64,
    ) -> Result<NormalPublicationObservation<'w, 'o>, NormalPublicationOriginError> {
        operation
            .check()
            .map_err(NormalPublicationOriginError::Stopped)?;
        if !std::sync::Arc::ptr_eq(
            &receipt.worker_identity,
            &self.worker.normal_worker_identity,
        ) || !operation.is_same_admission(&receipt.operation_identity)
        {
            return Err(NormalPublicationOriginError::Stale);
        }
        let observation = NormalPublicationObservation {
            worker: self.worker,
            operation,
            binding: receipt.binding,
            heartbeat: receipt.heartbeat,
            pre_heartbeat_lease_until: receipt.pre_heartbeat_lease_until,
            armed: false,
            completed: false,
            detached: false,
            local_now_test: receipt.local_now_test,
        };
        observation.check_local(now)?;
        Ok(observation)
    }
}
#[cfg(any(unix, windows))]
impl NormalPublicationObservation<'_, '_> {
    pub(in crate::unix) fn operation(&self) -> &crate::unix::owner_domain::Operation<'_> {
        self.operation
    }

    pub(in crate::unix) fn check_local(
        &self,
        now: u64,
    ) -> Result<(), NormalPublicationOriginError> {
        self.operation
            .check()
            .map_err(NormalPublicationOriginError::Stopped)?;
        let current = self.local_now_test.unwrap_or_else(Instant::now);
        if self.worker.normal_publication_origin.is_none()
            || self.heartbeat.wall_at_request_start > now
            || self.worker.scope.as_ref() != Some(&self.binding.scope)
            || self.worker.heartbeat_observation.as_ref() != Some(&self.heartbeat)
            || self.worker.lease_until
                != self
                    .heartbeat
                    .request_started
                    .checked_add(Duration::from_millis(self.heartbeat.lease_ms))
            || self.worker.fresh_until
                != self
                    .heartbeat
                    .request_started
                    .checked_add(Duration::from_millis(self.heartbeat.freshness_ms))
            || self.worker.lease_until.is_none_or(|until| current >= until)
            || self.worker.fresh_until.is_none_or(|until| current >= until)
            || (!self.armed && !matches!(self.worker.action, Action::Online))
            || (self.armed && !matches!(self.worker.action, Action::Get))
        {
            return Err(NormalPublicationOriginError::Stale);
        }
        Ok(())
    }
    /// Pure attenuation from the SAME accepted heartbeat and original operation.
    /// The copied absolute deadline can cross the Sync transport boundary; the
    /// Worker/observation borrow never enters the watcher. No PUT-start renewal.
    pub(in crate::unix) fn publication_http_deadline(
        &self,
        now: u64,
    ) -> Result<Instant, NormalPublicationOriginError> {
        self.check_local(now)?;
        let fresh = self
            .heartbeat
            .request_started
            .checked_add(Duration::from_millis(self.heartbeat.freshness_ms))
            .ok_or(NormalPublicationOriginError::Stale)?;
        let lease = self
            .heartbeat
            .request_started
            .checked_add(Duration::from_millis(self.heartbeat.lease_ms))
            .ok_or(NormalPublicationOriginError::Stale)?;
        let deadline = self.operation.deadline().min(fresh).min(lease);
        if self.local_now_test.unwrap_or_else(Instant::now) >= deadline {
            return Err(NormalPublicationOriginError::Stale);
        }
        Ok(deadline)
    }

    pub(in crate::unix) fn validate_provider<'p, S: SecretStorage + ?Sized>(
        &self,
        auth: &HostAuth<'p, S>,
        now: u64,
    ) -> Result<(), NormalPublicationOriginError> {
        let origin = self
            .worker
            .normal_publication_origin
            .as_ref()
            .ok_or(NormalPublicationOriginError::Stale)?;
        if origin.provider != auth as *const _ as usize
            || &origin.trusted != auth.trusted_configuration()
        {
            return Err(NormalPublicationOriginError::Stale);
        }
        let identity = auth
            .public_host_identity(now)
            .map_err(NormalPublicationOriginError::Auth)?;
        let access = auth
            .access_credential(now)
            .map_err(NormalPublicationOriginError::Auth)?;
        if identity.host_id != self.binding.scope.host_id
            || identity.access_epoch != self.binding.server_runtime.host_access_epoch.0
            || auth
                .verified_host_access_epoch()
                .map_err(NormalPublicationOriginError::Auth)?
                != origin.epoch
            || auth
                .credential_deadlines()
                .map_err(NormalPublicationOriginError::Auth)?
                != origin.deadlines
            || access != origin.access
            || now >= origin.deadlines.refresh_at
        {
            return Err(NormalPublicationOriginError::Stale);
        }
        self.check_local(now)
    }
    pub(in crate::unix) fn arm_get(
        &mut self,
        now: u64,
    ) -> Result<(), NormalPublicationOriginError> {
        self.check_local(now)?;
        self.worker.action = Action::Get;
        self.worker.publication_turn = false;
        self.armed = true;
        Ok(())
    }
    /// Flow only. No eligibility or authority escapes this completion.
    pub(in crate::unix) fn complete_ack(
        mut self,
        now: u64,
    ) -> Result<(), NormalPublicationOriginError> {
        self.check_local(now)?;
        self.worker.action = Action::Online;
        self.completed = true;
        Ok(())
    }
}
#[cfg(any(unix, windows))]
impl Drop for NormalPublicationObservation<'_, '_> {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        self.worker.normal_publication_origin = None;
        if !self.completed {
            self.worker.action = Action::Get;
            self.worker.heartbeat_observation = None;
        }
    }
}
// END INACTIVE NORMAL PUBLICATION WORKER ORIGIN

#[cfg(any(unix, windows))]
impl NormalPublicationObservation<'_, '_> {
    pub(in crate::unix) fn complete_heartbeat_only(
        mut self,
        now: u64,
    ) -> Result<(), NormalPublicationOriginError> {
        self.check_local(now)?;
        self.worker.action = Action::Online;
        self.completed = true;
        Ok(())
    }
}
