//! Runtime/publication steps run on the same credential owner and operation.
use super::super::shared_owner::{
    CloudClaimAdmission, CloudGetDecision, CloudGetError, ConfiguredCloudAttempt,
    ConfiguredNormalPublication, PublicationError,
};
use super::*;
use lomi_host_http::{DataTransport, RemoteApiOrigin};
use lomi_host_store::{CloudRuntimeScope, CloudRuntimeState, HostAcknowledgedPublication};
#[cfg(test)]
use lomi_remote_protocol::HostId;
#[cfg(test)]
use lomi_remote_protocol::RuntimeId;
use lomi_remote_protocol::{HostAccessCredential, http::*};
use sha2::{Digest, Sha256};

#[cfg(test)]
static CLOUD_RESTART_DIAGNOSTIC_STAGE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);
#[cfg(test)]
static CLOUD_RESTART_CLOUD_GET_ERROR: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);
#[cfg(test)]
static CLOUD_RESTART_WORKER_PATH: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
#[cfg(test)]
static CLOUD_RESTART_GUARD_OWNER_ERROR: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0);
#[cfg(test)]
fn cloud_restart_after_phase() -> bool {
    std::env::var("LOMI_E2_CLOUD_FIXTURE_RESTART_PHASE")
        .is_ok_and(|phase| phase == "after" || phase == "after-valid-lease")
}
#[cfg(test)]
fn set_cloud_restart_diagnostic_stage(stage: u8) {
    CLOUD_RESTART_DIAGNOSTIC_STAGE.store(stage, Ordering::Release);
}
#[cfg(test)]
fn set_cloud_restart_worker_path(path: u8) {
    if cloud_restart_after_phase() {
        CLOUD_RESTART_WORKER_PATH.store(path, Ordering::Release);
    }
}

pub(in super::super) trait DataApi {
    #[cfg(test)]
    fn get(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<HostRuntimeGetResult, lomi_host_http::Error>;
    #[cfg(test)]
    fn claim(
        &self,
        host: HostId,
        params: &RuntimeClaimParams,
        access: &HostAccessCredential,
    ) -> Result<RuntimeClaimResult, lomi_host_http::Error>;
    #[cfg(test)]
    fn heartbeat(
        &self,
        host: HostId,
        params: &HeartbeatParams,
        access: &HostAccessCredential,
    ) -> Result<HeartbeatResult, lomi_host_http::Error>;
    #[cfg(test)]
    fn publish(
        &self,
        host: HostId,
        params: &PublicationParams,
        access: &HostAccessCredential,
    ) -> Result<PublicationResult, lomi_host_http::Error>;
}
impl DataApi for DataTransport {
    #[cfg(test)]
    fn get(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<HostRuntimeGetResult, lomi_host_http::Error> {
        self.runtime_get(host, access)
    }
    #[cfg(test)]
    fn claim(
        &self,
        host: HostId,
        params: &RuntimeClaimParams,
        access: &HostAccessCredential,
    ) -> Result<RuntimeClaimResult, lomi_host_http::Error> {
        self.runtime_claim(host, params, access)
    }
    #[cfg(test)]
    fn heartbeat(
        &self,
        host: HostId,
        params: &HeartbeatParams,
        access: &HostAccessCredential,
    ) -> Result<HeartbeatResult, lomi_host_http::Error> {
        DataTransport::heartbeat(self, host, params, access)
    }
    #[cfg(test)]
    fn publish(
        &self,
        host: HostId,
        params: &PublicationParams,
        access: &HostAccessCredential,
    ) -> Result<PublicationResult, lomi_host_http::Error> {
        self.publication(host, params, access)
    }
}
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
    #[cfg(test)]
    if cloud_restart_after_phase() {
        CLOUD_RESTART_CLOUD_GET_ERROR.store(
            match error {
                CloudGetError::Domain(_) => 1,
                CloudGetError::Store(_) => 2,
                CloudGetError::UncertainStore(_) => 3,
                CloudGetError::Provider(_) => 4,
                CloudGetError::Http(_) => 5,
                CloudGetError::Stale => 6,
            },
            Ordering::Release,
        );
    }
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
        Err(error) => {
            #[cfg(test)]
            if cloud_restart_after_phase() {
                let class = match error {
                    super::shared_owner::Error::Domain(super::owner_domain::Error::Poisoned) => 1,
                    super::shared_owner::Error::Domain(_) => 2,
                    super::shared_owner::Error::Store(lomi_host_store::StoreError::Storage) => 3,
                    super::shared_owner::Error::Store(lomi_host_store::StoreError::Fenced) => 4,
                    super::shared_owner::Error::Store(_) => 5,
                    super::shared_owner::Error::UncertainStore(_) => 6,
                };
                CLOUD_RESTART_GUARD_OWNER_ERROR.store(class, Ordering::Release);
            }
            return Err(error.into());
        }
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
        injected: Option<&dyn DataApi>,
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
        #[cfg(test)]
        if let Some(api) = injected {
            turn.install_cloud_api_for_test(api);
        }
        #[cfg(not(test))]
        let _ = injected;
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
        self.run_step(auth, config, runtime, generation, None)
    }
    pub(super) fn step_using(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        api: &dyn DataApi,
        config: &Config,
        runtime: Runtime<'_>,
        generation: u64,
    ) -> Result<StepOutcome, StepError> {
        #[cfg(test)]
        {
            self.run_step(auth, config, runtime, generation, Some(api))
        }
        #[cfg(not(test))]
        {
            let _ = api;
            self.step(auth, config, runtime, generation)
        }
    }
    fn run_step(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        generation: u64,
        injected: Option<&dyn DataApi>,
    ) -> Result<StepOutcome, StepError> {
        #[cfg(not(test))]
        let _ = injected;
        #[cfg(test)]
        set_cloud_restart_worker_path(1);
        guard(runtime, generation)?;
        #[cfg(test)]
        set_cloud_restart_worker_path(2);
        #[cfg(test)]
        set_cloud_restart_worker_path(3);
        let Some(snapshot) = runtime
            .owner
            .cloud_worker_snapshot(runtime.operation, generation)?
        else {
            self.finish_operation();
            return Ok(StepOutcome::Deferred);
        };
        #[cfg(test)]
        set_cloud_restart_worker_path(4);
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
                #[cfg(test)]
                set_cloud_restart_worker_path(5);
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
                #[cfg(test)]
                if let Some(api) = injected {
                    attempt.install_cloud_api_for_test(api);
                }
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
                        #[cfg(all(test, feature = "cloud-fixture"))]
                        if cloud_restart_after_phase() {
                            println!(
                                "LOMI_CLOUD_RESTART_STAGE=claim_admission_{}",
                                if self.claim.is_some() {
                                    "present"
                                } else {
                                    "missing"
                                }
                            );
                        }
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
                #[cfg(test)]
                if let Some(api) = injected {
                    turn.install_cloud_api_for_test(api);
                }
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
                    #[cfg(test)]
                    if let Some(api) = injected {
                        attempt.install_cloud_api_for_test(api);
                    }
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
                    #[cfg(test)]
                    let mut driver = driver;
                    #[cfg(test)]
                    if let Some(api) = injected {
                        driver.install_cloud_api_for_test(api);
                    }
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

#[cfg(test)]
pub(in crate::unix) mod tests {
    use super::super::tests::{MemoryStorage, unconfirmed_storage};
    use super::*;
    use crate::testsupport::BuilderExt as _;
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
    };
    #[cfg(feature = "cloud-fixture")]
    use std::{
        io::Write as _,
        os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    };
    #[cfg(feature = "cloud-fixture")]
    static CLOUD_RESTART_PRE_GET_FLAGS: std::sync::atomic::AtomicU8 =
        std::sync::atomic::AtomicU8::new(0);
    #[cfg(feature = "cloud-fixture")]
    fn cloud_fixture_private_tempdir(prefix: &str) -> tempfile::TempDir {
        #[cfg(target_os = "macos")]
        const TEMP_ROOT: &str = "/private/tmp";
        #[cfg(not(target_os = "macos"))]
        const TEMP_ROOT: &str = "/tmp";

        tempfile::Builder::new()
            .prefix(prefix)
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(TEMP_ROOT)
            .unwrap()
    }
    enum Reply {
        Get(HostRuntimeGetResult),
        Claim(RuntimeClaimResult),
        Heartbeat(HeartbeatResult),
        Publication(PublicationResult),
        Error(lomi_host_http::Error),
    }
    struct FixedApi<'a> {
        replies: RefCell<VecDeque<Reply>>,
        requests: RefCell<Vec<&'static str>>,
        publications: RefCell<Vec<PublicationParams>>,
        claims: RefCell<Vec<RuntimeClaimParams>>,
        hook: RefCell<Option<Box<dyn FnOnce() + 'a>>>,
        hook_name: Cell<Option<&'static str>>,
    }
    impl<'a> FixedApi<'a> {
        fn new(replies: Vec<Reply>) -> Self {
            Self {
                replies: RefCell::new(replies.into()),
                requests: RefCell::new(Vec::new()),
                publications: RefCell::new(Vec::new()),
                claims: RefCell::new(Vec::new()),
                hook: RefCell::new(None),
                hook_name: Cell::new(None),
            }
        }
        fn hook(&self, hook: impl FnOnce() + 'a) {
            *self.hook.borrow_mut() = Some(Box::new(hook));
        }
        fn hook_on(&self, name: &'static str, hook: impl FnOnce() + 'a) {
            self.hook_name.set(Some(name));
            self.hook(hook);
        }
        fn reply(&self, name: &'static str) -> Result<Reply, lomi_host_http::Error> {
            self.requests.borrow_mut().push(name);
            // This callback models a network rendezvous OUTSIDE both guards.
            if self.hook_name.get().is_none_or(|expected| expected == name)
                && let Some(hook) = self.hook.borrow_mut().take()
            {
                hook();
            }
            match self
                .replies
                .borrow_mut()
                .pop_front()
                .expect("exact bounded HTTP script")
            {
                Reply::Error(error) => Err(error),
                other => Ok(other),
            }
        }
    }
    impl DataApi for FixedApi<'_> {
        fn get(
            &self,
            _: HostId,
            _: &HostAccessCredential,
        ) -> Result<HostRuntimeGetResult, lomi_host_http::Error> {
            match self.reply("GET")? {
                Reply::Get(reply) => Ok(reply),
                _ => panic!("expected Get"),
            }
        }
        fn claim(
            &self,
            _: HostId,
            request: &RuntimeClaimParams,
            _: &HostAccessCredential,
        ) -> Result<RuntimeClaimResult, lomi_host_http::Error> {
            self.claims.borrow_mut().push(request.clone());
            match self.reply("CLAIM")? {
                Reply::Claim(reply) => Ok(reply),
                _ => panic!("expected Claim"),
            }
        }
        fn heartbeat(
            &self,
            _: HostId,
            _: &HeartbeatParams,
            _: &HostAccessCredential,
        ) -> Result<HeartbeatResult, lomi_host_http::Error> {
            match self.reply("HB")? {
                Reply::Heartbeat(reply) => Ok(reply),
                _ => panic!("expected Heartbeat"),
            }
        }
        fn publish(
            &self,
            _: HostId,
            request: &PublicationParams,
            _: &HostAccessCredential,
        ) -> Result<PublicationResult, lomi_host_http::Error> {
            self.publications.borrow_mut().push(request.clone());
            match self.reply("PUT")? {
                Reply::Publication(reply) => Ok(reply),
                _ => panic!("expected Publication"),
            }
        }
    }
    #[derive(Clone, Copy)]
    enum Seed {
        Normal,
        NoPin,
        LegacySequence,
        Pending,
        ReopenedPending,
        ReopenedLogout,
        #[cfg(feature = "cloud-fixture")]
        ExternalActive,
        #[cfg(feature = "cloud-fixture")]
        ExternalUnbound,
        #[cfg(feature = "cloud-fixture")]
        ExternalRestarted,
    }
    pub(in crate::unix) struct Fixture<'a> {
        directory: &'a std::path::Path,
        #[cfg(feature = "cloud-fixture")]
        ipc_profile: std::path::PathBuf,
        #[cfg(feature = "cloud-fixture")]
        ipc_discovery: LocalDiscovery,
        owner: &'a Arc<SharedOwner>,
        setup: &'a Arc<super::super::super::public_configuration::PublicSetup>,
        config: Config,
        runtime_id: lomi_remote_protocol::RuntimeId,
        operation: &'a OwnerOperation<'a>,
        state: &'a Arc<Mutex<View>>,
        stopping: &'a Arc<AtomicBool>,
        gate: &'a Arc<AtomicBool>,
        paused: &'a Arc<AtomicBool>,
        retry: &'a Arc<AtomicBool>,
        receiver: &'a mpsc::Receiver<Command>,
        io: Option<super::super::super::public_configuration::WorkerPublicIo<'a>>,
        aborted: Cell<bool>,
        anchor: Instant,
        fault: &'a Cell<u8>,
        probe_arm: &'a Cell<bool>,
        probes: &'a Cell<usize>,
    }
    impl Fixture<'_> {
        fn enter(&mut self) {
            if self.io.is_none() {
                self.io = Some(self.setup.enter_owned(self.paused).unwrap().unwrap());
            }
        }
        pub(in crate::unix::auth) fn runtime(&self) -> Runtime<'_> {
            Runtime {
                owner: self.owner,
                operation: self.operation,
                public_io: self.io.as_ref().expect("entered actual IO"),
                state: self.state,
                stopping: self.stopping,
                receiver: self.receiver,
                retry_requested: self.retry,
                gate: self.gate,
                paused: self.paused,
                base: 1005,
                anchor: self.anchor,
                aborted: &self.aborted,
            }
        }
        fn binding(&self) -> RuntimeBinding {
            RuntimeBinding {
                runtime_id: self.runtime_id,
                runtime_generation: DecimalU64(18),
                host_access_epoch: DecimalU64(13),
            }
        }
        fn snapshot(&self, runtime: Option<RuntimeBinding>, sequence: u64) -> HostRuntimeGetResult {
            HostRuntimeGetResult {
                host_id: self.owner.identity(self.operation).unwrap().host_id,
                host_access_epoch: DecimalU64(if runtime.is_some() { 13 } else { 12 }),
                runtime_generation: DecimalU64(if runtime.is_some() { 18 } else { 17 }),
                runtime: runtime.clone(),
                publication_seq: DecimalU64(sequence),
                lease_ms: DecimalU64(if runtime.is_some() { 30_000 } else { 0 }),
                freshness_ms: DecimalU64(if runtime.is_some() { 5_000 } else { 0 }),
            }
        }
        fn authorization(&self) -> lomi_host_store::AuthorizationState {
            let cancelled = AtomicBool::new(false);
            let operation =
                OwnerOperation::new(Instant::now() + Duration::from_secs(3), &cancelled);
            self.owner.authorization_state(&operation).unwrap()
        }
        fn records(&self) -> super::super::super::shared_owner::CloudTestRecords {
            // Independent read admission remains available after the worker's
            // original cancellation became sticky. It carries no effect cap.
            let cancelled = AtomicBool::new(false);
            let operation =
                OwnerOperation::new(Instant::now() + Duration::from_secs(3), &cancelled);
            #[cfg(feature = "cloud-fixture")]
            let restart_diagnostic = cloud_restart_after_phase();
            #[cfg(feature = "cloud-fixture")]
            if restart_diagnostic {
                println!("LOMI_CLOUD_RESTART_STAGE=records_auth_status_started");
            }
            let status = self.owner.auth_status(&operation).unwrap();
            #[cfg(feature = "cloud-fixture")]
            if restart_diagnostic {
                let locked = if status.authorization.locked {
                    "locked"
                } else {
                    "unlocked"
                };
                let revoke = if status.authorization.pending_cloud_revoke {
                    "revoke_pending"
                } else {
                    "no_revoke"
                };
                println!("LOMI_CLOUD_RESTART_STAGE=records_auth_{locked}_{revoke}");
            }
            let scope = if status.authorization.locked || status.authorization.pending_cloud_revoke
            {
                #[cfg(feature = "cloud-fixture")]
                if restart_diagnostic {
                    println!("LOMI_CLOUD_RESTART_STAGE=records_scope_skipped_by_auth");
                }
                None
            } else {
                let snapshot = self
                    .owner
                    .cloud_worker_snapshot(&operation, status.authorization.generation);
                #[cfg(feature = "cloud-fixture")]
                if restart_diagnostic {
                    let class = match &snapshot {
                        Ok(Some(_)) => "some",
                        Ok(None) => "none",
                        Err(super::super::shared_owner::Error::Domain(_)) => "domain_error",
                        Err(super::super::shared_owner::Error::Store(_)) => "store_error",
                        Err(super::super::shared_owner::Error::UncertainStore(_)) => {
                            "uncertain_store_error"
                        }
                    };
                    println!("LOMI_CLOUD_RESTART_STAGE=records_snapshot_{class}");
                }
                snapshot.ok().flatten().map(|s| s.scope)
            };
            let records = self
                .owner
                .cloud_records_for_test(&operation, scope.as_ref())
                .unwrap();
            #[cfg(feature = "cloud-fixture")]
            if restart_diagnostic {
                println!("LOMI_CLOUD_RESTART_STAGE=records_read_completed");
            }
            records
        }
        fn step(
            &mut self,
            worker: &mut Worker,
            auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
            api: &dyn DataApi,
        ) -> Result<StepOutcome, StepError> {
            #[cfg(feature = "cloud-fixture")]
            let restart_diagnostic = cloud_restart_after_phase();
            #[cfg(feature = "cloud-fixture")]
            if restart_diagnostic {
                set_cloud_restart_diagnostic_stage(70);
            }
            self.enter();
            #[cfg(feature = "cloud-fixture")]
            if restart_diagnostic {
                set_cloud_restart_diagnostic_stage(71);
            }
            #[cfg(feature = "cloud-fixture")]
            if restart_diagnostic {
                set_cloud_restart_diagnostic_stage(72);
            }
            let result = worker.step_using(auth, api, &self.config, self.runtime(), 0);
            #[cfg(feature = "cloud-fixture")]
            if restart_diagnostic {
                set_cloud_restart_diagnostic_stage(73);
            }
            if !worker.has_retained_operation() {
                self.io = None;
            }
            #[cfg(feature = "cloud-fixture")]
            if restart_diagnostic {
                set_cloud_restart_diagnostic_stage(74);
            }
            result
        }
        fn logout(
            &mut self,
            worker: &mut Worker,
            auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
            api: &dyn DataApi,
            generation: u64,
        ) -> Result<bool, StepError> {
            // Refusal to enter real PublicIo is itself a disabled-network
            // boundary; no forged IO capability is supplied to the worker.
            if self.io.is_none()
                && (self.paused.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire))
            {
                return Err(StepError::Stale);
            }
            self.enter();
            let result =
                worker.logout_epoch_step(auth, &self.config, self.runtime(), generation, Some(api));
            self.io = None;
            result
        }
        fn fence(&self) -> lomi_host_store::AuthorizationState {
            self.gate.store(true, Ordering::Release);
            self.owner
                .begin_local_logout(self.operation)
                .unwrap()
                .try_commit()
                .unwrap()
        }
        fn project(&self) -> lomi_remote_protocol::WorkspaceId {
            let project = self
                .owner
                .begin_add_project(
                    self.operation,
                    self.directory,
                    "Project".to_owned().try_into().unwrap(),
                )
                .unwrap()
                .try_commit()
                .unwrap();
            self.owner
                .begin_share(self.operation, project.state.context.workspace_id, 0)
                .unwrap()
                .try_commit()
                .unwrap();
            project.state.context.workspace_id
        }
        fn pin(&mut self, auth: &mut HostAuth<'_, dyn SecretStorage + '_>) {
            assert!(
                self.io.is_none(),
                "configuration follows settled IO disposal"
            );
            let mut configuration = self
                .owner
                .auth_selection(self.operation)
                .unwrap()
                .configuration
                .unwrap();
            configuration.remote_api_origin =
                Some("https://remote.example".to_owned().try_into().unwrap());
            let (wake, _) = mpsc::sync_channel(1);
            let handle = Handle {
                owner: self.owner.clone(),
                wake,
                state: self.state.clone(),
                retry_requested: self.retry.clone(),
                gate: self.gate.clone(),
                paused: self.paused.clone(),
                public_setup: Some(self.setup.clone()),
            };
            handle
                .dispatch(
                    self.operation,
                    LocalCall::AuthConfigure(LocalAuthConfigure {
                        configuration,
                        operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
                    }),
                )
                .unwrap();
            real_ready(
                self.owner,
                self.setup,
                self.operation,
                auth,
                self.gate,
                self.paused,
            )
            .unwrap_or_else(|_| panic!("LOMI_CLOUD_WORKER_FAILURE=ready_fixture"));
        }
    }
    fn configuration(pin: bool) -> LocalAuthConfiguration {
        LocalAuthConfiguration {
            version: 1,
            origin: "https://identity.example".to_owned().try_into().unwrap(),
            remote_api_origin: pin.then(|| {
                std::env::var("LOMI_E2_CLOUD_FIXTURE_ORIGIN")
                    .unwrap_or_else(|_| "https://remote.example".to_owned())
                    .try_into()
                    .unwrap()
            }),
            relay_endpoint: None,
            client_id: "lomi-remote-host".to_owned().try_into().unwrap(),
            provider: crate::testsupport::provider(),
            keychain_path: None,
            protected_file_acknowledgement: crate::testsupport::file_acknowledgement(),
        }
    }
    fn real_ready(
        owner: &SharedOwner,
        setup: &super::super::super::public_configuration::PublicSetup,
        operation: &OwnerOperation<'_>,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        gate: &AtomicBool,
        paused: &AtomicBool,
    ) -> Result<(), u8> {
        let io = setup.enter_owned(paused).map_err(|_| 1)?.ok_or(2)?;
        let mut attempt =
            super::super::super::shared_owner::ConfiguredWorkerAttempt::from_existing_worker(
                auth,
                &io,
                gate,
                paused,
                1005,
                Instant::now(),
            )
            .map_err(ready_error_diagnostic_class)?;
        attempt.install_ready_http_script_for_test(
            std::rc::Rc::new(Cell::new(0)),
            std::rc::Rc::new(RefCell::new(None)),
            1005,
        );
        let mut turn = attempt
            .begin_ready(owner, operation)
            .map_err(ready_error_diagnostic_class)?;
        loop {
            match turn.try_step() {
                Ok(true) => return Ok(()),
                Ok(false) => (),
                Err(error) => return Err(ready_error_diagnostic_class(error)),
            }
        }
    }
    fn ready_error_diagnostic_class(error: super::super::shared_owner::WorkerReadyError) -> u8 {
        use super::super::owner_domain::Error as DomainError;
        use super::super::shared_owner::WorkerReadyError;
        use lomi_host_store::StoreError;
        match error {
            WorkerReadyError::Domain(DomainError::Busy) => 10,
            WorkerReadyError::Domain(DomainError::Cancelled) => 11,
            WorkerReadyError::Domain(DomainError::Deadline) => 12,
            WorkerReadyError::Domain(DomainError::Denied) => 13,
            WorkerReadyError::Domain(DomainError::Poisoned) => 14,
            WorkerReadyError::Domain(DomainError::Exhausted) => 15,
            WorkerReadyError::Domain(DomainError::Stale) => 16,
            WorkerReadyError::Domain(DomainError::Unfinished) => 17,
            WorkerReadyError::Store(StoreError::Storage) => 20,
            WorkerReadyError::Store(StoreError::Busy) => 21,
            WorkerReadyError::Store(StoreError::Invalid) => 22,
            WorkerReadyError::Store(StoreError::NotFound) => 23,
            WorkerReadyError::Store(StoreError::RevisionConflict) => 24,
            WorkerReadyError::Store(StoreError::IdempotencyConflict) => 25,
            WorkerReadyError::Store(StoreError::ResourceExhausted) => 26,
            WorkerReadyError::Store(StoreError::Fenced) => 27,
            WorkerReadyError::Store(StoreError::AlreadyStarted) => 28,
            WorkerReadyError::Store(StoreError::SchemaVersion) => 29,
            WorkerReadyError::Store(StoreError::Backup) => 30,
            WorkerReadyError::Provider(lomi_host_auth::Error::Storage(_)) => 40,
            WorkerReadyError::Provider(lomi_host_auth::Error::InvalidConfig) => 41,
            WorkerReadyError::Provider(lomi_host_auth::Error::InvalidState) => 42,
            WorkerReadyError::Provider(lomi_host_auth::Error::InvalidBundle) => 43,
            WorkerReadyError::Provider(lomi_host_auth::Error::InvalidResponse) => 44,
            WorkerReadyError::Provider(lomi_host_auth::Error::Expired) => 45,
            WorkerReadyError::Provider(lomi_host_auth::Error::Sealed) => 46,
            WorkerReadyError::Provider(lomi_host_auth::Error::ClockRollback) => 47,
            WorkerReadyError::Provider(lomi_host_auth::Error::PollTooEarly) => 48,
            WorkerReadyError::Http(_) => 50,
            WorkerReadyError::Stale => 51,
        }
    }
    struct ProbeStorage<'a> {
        inner: MemoryStorage,
        owner: &'a SharedOwner,
        operation: &'a OwnerOperation<'a>,
        gate: &'a AtomicBool,
        paused: &'a AtomicBool,
        pending: &'a AtomicBool,
        fault: &'a Cell<u8>,
        arm: &'a Cell<bool>,
        probes: &'a Cell<usize>,
    }
    impl SecretStorage for ProbeStorage<'_> {
        fn status(&self) -> secrets::ProviderStatus {
            self.inner.status()
        }
        fn load(&self) -> Result<Option<secrets::SecretBundle>, secrets::Error> {
            self.inner.load()
        }
        fn replace(&mut self, bundle: &secrets::SecretBundle) -> Result<(), secrets::Error> {
            let armed = self.arm.replace(false);
            let fault = if armed { self.fault.replace(0) } else { 0 };
            if fault < 4 {
                self.inner.replace(bundle)?;
            }
            if armed {
                self.owner
                    .probe_both_locks_for_test(self.operation)
                    .unwrap();
                self.probes.set(self.probes.get() + 1);
                match fault {
                    1 => {
                        self.gate.store(true, Ordering::Release);
                        self.owner
                            .begin_local_logout(self.operation)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                    2 => {
                        self.gate.store(true, Ordering::Release);
                        self.owner
                            .begin_local_logout(self.operation)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                        return Err(secrets::Error::CommitUncertain);
                    }
                    3 => {
                        self.paused.store(true, Ordering::Release);
                        self.pending.store(true, Ordering::Release);
                        return Err(secrets::Error::CommitUncertain);
                    }
                    4 => {
                        self.gate.store(true, Ordering::Release);
                        self.owner
                            .begin_local_logout(self.operation)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                        return Err(secrets::Error::Unavailable);
                    }
                    5 => {
                        self.paused.store(true, Ordering::Release);
                        self.pending.store(true, Ordering::Release);
                        return Err(secrets::Error::Unavailable);
                    }
                    _ => (),
                }
            }
            Ok(())
        }
    }
    pub(in crate::unix) fn with_fixture(
        test: impl FnOnce(&mut Fixture<'_>, &mut HostAuth<'_, dyn SecretStorage + '_>),
    ) {
        fixture(Seed::Normal, test)
    }
    fn fixture(
        seed: Seed,
        test: impl FnOnce(&mut Fixture<'_>, &mut HostAuth<'_, dyn SecretStorage + '_>),
    ) {
        fixture_with_profile_override(seed, None, test)
    }
    fn fixture_with_profile_override(
        seed: Seed,
        profile_override: Option<std::path::PathBuf>,
        test: impl FnOnce(&mut Fixture<'_>, &mut HostAuth<'_, dyn SecretStorage + '_>),
    ) {
        #[cfg(feature = "cloud-fixture")]
        let external_restart = matches!(seed, Seed::ExternalRestarted);
        #[cfg(not(feature = "cloud-fixture"))]
        let external_restart = false;
        // An explicit test profile also disables ambient fixture credentials
        // and identities, keeping this path-local regression self-contained.
        #[cfg(feature = "cloud-fixture")]
        let suppress_fixture_environment = profile_override.is_some();
        #[cfg(feature = "cloud-fixture")]
        let selected_profile = profile_override.or_else(|| {
            std::env::var_os("LOMI_E2_CLOUD_FIXTURE_STORE_PATH")
                .filter(|_| matches!(seed, Seed::ExternalActive) || external_restart)
                .map(std::path::PathBuf::from)
        });
        #[cfg(not(feature = "cloud-fixture"))]
        drop(profile_override);
        #[cfg(feature = "cloud-fixture")]
        let persistent_profile = selected_profile.is_some();
        #[cfg(feature = "cloud-fixture")]
        let private_directory = if selected_profile.is_none() {
            Some(tempfile::Builder::new().private_tempdir().unwrap())
        } else {
            None
        };
        #[cfg(not(feature = "cloud-fixture"))]
        let private_directory = Some(tempfile::Builder::new().private_tempdir().unwrap());
        #[cfg(feature = "cloud-fixture")]
        let directory_path = if let Some(path) = selected_profile {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => panic!("restart fixture directory: {error}"),
            }
            path
        } else {
            private_directory.as_ref().unwrap().path().to_path_buf()
        };
        #[cfg(not(feature = "cloud-fixture"))]
        let directory_path = private_directory.as_ref().unwrap().path().to_path_buf();
        let profile = directory_path.canonicalize().unwrap();
        if external_restart {
            set_cloud_restart_diagnostic_stage(1);
        }
        let durable_lock = OwnerLock::acquire(&profile).unwrap();
        if external_restart {
            set_cloud_restart_diagnostic_stage(2);
        }
        let mut store =
            HostStore::open(&durable_lock.prepare_database().unwrap(), Limits::default()).unwrap();
        if external_restart {
            set_cloud_restart_diagnostic_stage(3);
        }
        #[cfg(all(test, feature = "cloud-fixture"))]
        if !external_restart && !suppress_fixture_environment {
            if let Ok(host) = std::env::var("LOMI_E2_CLOUD_FIXTURE_HOST_ID") {
                let host = HostId::try_from(host).expect("fixture host id");
                let runtime = RuntimeId::try_from(
                    std::env::var("LOMI_E2_CLOUD_FIXTURE_RUNTIME_ID").expect("fixture runtime id"),
                )
                .expect("fixture runtime id");
                store
                    .rebind_identity_for_fixture(host, runtime)
                    .expect("fresh fixture identity");
            }
        }
        let configuration = configuration(!matches!(seed, Seed::NoPin));
        #[cfg(feature = "cloud-fixture")]
        if !external_restart {
            store.configure_auth(&configuration).unwrap();
        }
        #[cfg(not(feature = "cloud-fixture"))]
        store.configure_auth(&configuration).unwrap();
        let config = super::super::configuration(store.identity(), &configuration).unwrap();
        let host = store.identity().host_id;
        let mut memory = if external_restart {
            let bytes = std::fs::read(directory_path.join("fixture-secret-state"))
                .expect("persisted fixture credential state");
            MemoryStorage::from_fixture_bytes(bytes)
        } else {
            unconfirmed_storage(&config, host)
        };
        #[cfg(feature = "cloud-fixture")]
        let intent = if external_restart {
            None
        } else {
            Some(
                store
                    .begin_login(
                        OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).unwrap(),
                    )
                    .unwrap(),
            )
        };
        #[cfg(not(feature = "cloud-fixture"))]
        let intent = store
            .begin_login(OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).unwrap())
            .unwrap();
        #[cfg(feature = "cloud-fixture")]
        let external = matches!(seed, Seed::ExternalActive);
        #[cfg(feature = "cloud-fixture")]
        let external_fixture = matches!(seed, Seed::ExternalActive | Seed::ExternalUnbound);
        #[cfg(feature = "cloud-fixture")]
        let external_unbound = matches!(seed, Seed::ExternalUnbound);
        #[cfg(not(feature = "cloud-fixture"))]
        let (external, external_fixture, external_unbound) = (false, false, false);
        if external_restart {
            // This phase opens the database left by a different owner process;
            // it must not seed, reset, or rebind any durable state.
        } else if matches!(
            seed,
            Seed::LegacySequence | Seed::Pending | Seed::ReopenedPending
        ) || external_fixture
        {
            // Exclusive pre-owner restart/legacy preparation only. Domain Ready
            // is still closed below until the ACTUAL Ready constructor succeeds.
            #[cfg(feature = "cloud-fixture")]
            if let Some(intent) = intent {
                store.complete_login(intent).unwrap();
            }
            #[cfg(not(feature = "cloud-fixture"))]
            store.complete_login(intent).unwrap();
            let remote_origin = std::env::var("LOMI_E2_CLOUD_FIXTURE_ORIGIN")
                .unwrap_or_else(|_| "https://remote.example".to_owned());
            let scope = store.cloud_runtime_scope(0, remote_origin).unwrap();
            if external_unbound {
                let mut auth = HostAuth::open(&mut memory, config.clone(), 1005).unwrap();
                auth.confirm_registration(lomi_remote_protocol::HostRegisterResult {
                    host_id: host,
                    host_access_epoch: DecimalU64(1),
                })
                .unwrap();
                drop(auth);
            } else {
                let binding = RuntimeBinding {
                    runtime_id: if external {
                        RuntimeId::try_from(
                            std::env::var("LOMI_E2_CLOUD_FIXTURE_RUNTIME_ID")
                                .expect("fixture runtime id"),
                        )
                        .expect("fixture runtime id")
                    } else {
                        store.runtime_id()
                    },
                    runtime_generation: DecimalU64(if external {
                        std::env::var("LOMI_E2_CLOUD_FIXTURE_GENERATION")
                            .expect("fixture generation")
                            .parse()
                            .expect("fixture generation")
                    } else {
                        18
                    }),
                    host_access_epoch: DecimalU64(if external {
                        std::env::var("LOMI_E2_CLOUD_FIXTURE_EPOCH")
                            .expect("fixture epoch")
                            .parse()
                            .expect("fixture epoch")
                    } else {
                        13
                    }),
                };
                let registered_epoch = if external { 1 } else { 12 };
                let mut auth = HostAuth::open(&mut memory, config.clone(), 1005).unwrap();
                auth.confirm_registration(lomi_remote_protocol::HostRegisterResult {
                    host_id: host,
                    host_access_epoch: DecimalU64(registered_epoch),
                })
                .unwrap();
                auth.accept_runtime_observation(
                    DecimalU64(registered_epoch),
                    HostRuntimeGetResult {
                        host_id: host,
                        host_access_epoch: binding.host_access_epoch,
                        runtime_generation: binding.runtime_generation,
                        runtime: Some(binding.clone()),
                        publication_seq: DecimalU64(if external {
                            std::env::var("LOMI_E2_CLOUD_FIXTURE_PUBLICATION_SEQ")
                                .expect("fixture publication sequence")
                                .parse()
                                .expect("fixture publication sequence")
                        } else {
                            0
                        }),
                        lease_ms: DecimalU64(30_000),
                        freshness_ms: DecimalU64(5_000),
                    },
                    1005,
                )
                .unwrap();
                drop(auth);
                let state = store
                    .compare_and_set_cloud_runtime(
                        &scope,
                        None,
                        binding,
                        DecimalU64(if external {
                            std::env::var("LOMI_E2_CLOUD_FIXTURE_PUBLICATION_SEQ")
                                .expect("fixture publication sequence")
                                .parse()
                                .expect("fixture publication sequence")
                        } else if matches!(seed, Seed::LegacySequence) {
                            7
                        } else {
                            0
                        }),
                    )
                    .unwrap();
                if matches!(seed, Seed::Pending | Seed::ReopenedPending) {
                    let project = store
                        .add_project(&directory_path, "Project".to_owned().try_into().unwrap())
                        .unwrap();
                    store.share(project.state.context.workspace_id, 0).unwrap();
                    store.prepare_host_publication(&state).unwrap();
                }
                if matches!(seed, Seed::ReopenedPending) {
                    let backup = directory_path.join("restart.sqlite");
                    store.checked_backup(&backup).unwrap();
                    drop(store);
                    store = HostStore::open(&backup, Limits::default()).unwrap();
                }
            }
        } else if matches!(seed, Seed::ReopenedLogout) {
            #[cfg(feature = "cloud-fixture")]
            if let Some(intent) = intent {
                store.complete_login(intent).unwrap();
            }
            #[cfg(not(feature = "cloud-fixture"))]
            store.complete_login(intent).unwrap();
            let mut auth = HostAuth::open(&mut memory, config.clone(), 1005).unwrap();
            auth.confirm_registration(lomi_remote_protocol::HostRegisterResult {
                host_id: host,
                host_access_epoch: DecimalU64(12),
            })
            .unwrap();
            drop(auth);
            store.mark_cloud_authorization_possible(0).unwrap();
            store
                .fence_authorization(lomi_host_store::AuthorizationFenceReason::LocalLogout)
                .unwrap();
            let backup = directory_path.join("logout-restart.sqlite");
            store.checked_backup(&backup).unwrap();
            drop(store);
            store = HostStore::open(&backup, Limits::default()).unwrap();
        }
        super::super::super::public_configuration::startup(&mut store, durable_lock.profile())
            .unwrap();
        if external_restart {
            // Startup deliberately seals authorization. For this synthetic
            // CloudWorker fixture, verify the exact saved provider bundle is
            // Ready. The normal test-only auth worker below performs the
            // volatile and durable verification checkpoint before Cloud GET.
            let auth = HostAuth::open(&mut memory, config.clone(), 1005)
                .expect("reopen persisted fixture auth");
            if !matches!(auth.status(), lomi_host_auth::Status::Ready) {
                panic!("LOMI_CLOUD_RESTART_FAILURE=restart_auth_not_ready");
            }
        }
        if external_restart {
            set_cloud_restart_diagnostic_stage(4);
        }
        let discovery = LocalDiscovery {
            version: lomi_remote_protocol::LocalIpcVersion::CURRENT,
            profile_id: store.identity().profile_id,
            host_id: host,
            runtime_id: store.runtime_id(),
            build_id: "cloud-owner-fixture".to_owned(),
        };
        // Persistent Cloud profiles sit below the canonical cloud-artifacts
        // child, where host.sock exceeds macOS's Unix-domain path limit. Keep
        // their durable lock and store at the requested profile, but put only
        // the fixture's ephemeral local IPC endpoint in a short private dir.
        // This fixture never calls PublicSetup::configure_owned; startup and
        // all durable/public-configuration state remain on durable_lock.
        #[cfg(feature = "cloud-fixture")]
        let ipc_directory = if persistent_profile {
            Some(cloud_fixture_private_tempdir("lomi-cloud-ipc-"))
        } else {
            None
        };
        #[cfg(not(feature = "cloud-fixture"))]
        let ipc_directory: Option<tempfile::TempDir> = None;
        let endpoint = Arc::new(if let Some(directory) = ipc_directory.as_ref() {
            OwnerEndpoint::bind(OwnerLock::acquire(directory.path()).unwrap(), discovery).unwrap()
        } else {
            OwnerEndpoint::bind(durable_lock, discovery).unwrap()
        });
        #[cfg(feature = "cloud-fixture")]
        let ipc_profile = endpoint.profile().path().to_path_buf();
        #[cfg(feature = "cloud-fixture")]
        let ipc_discovery = endpoint.discovery().clone();
        let runtime_id = store.runtime_id();
        let owner = SharedOwner::new(store).unwrap();
        if external_restart {
            set_cloud_restart_diagnostic_stage(5);
        }
        let setup = Arc::new(super::super::super::public_configuration::PublicSetup::new(
            endpoint,
        ));
        let stopping = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(AtomicBool::new(true));
        let paused = Arc::new(AtomicBool::new(false));
        let retry = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(initial()));
        let (_wake, receiver) = mpsc::sync_channel(8);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(30), &stopping);
        let fault = Cell::new(0);
        let arm = Cell::new(false);
        let probes = Cell::new(0);
        let mut provider = ProbeStorage {
            inner: memory,
            owner: &owner,
            operation: &operation,
            gate: &gate,
            paused: &paused,
            pending: &setup.pending,
            fault: &fault,
            arm: &arm,
            probes: &probes,
        };
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1005,
        )
        .unwrap();
        if external_restart {
            set_cloud_restart_diagnostic_stage(51);
        }
        if !matches!(seed, Seed::ReopenedLogout)
            && let Err(class) = real_ready(&owner, &setup, &operation, &mut auth, &gate, &paused)
        {
            if external_restart {
                set_cloud_restart_diagnostic_stage(100 + class);
                panic!("LOMI_CLOUD_RESTART_FAILURE=restart_ready_failed");
            }
            panic!("LOMI_CLOUD_WORKER_FAILURE=ready_fixture");
        }
        #[cfg(all(test, feature = "cloud-fixture"))]
        if !suppress_fixture_environment
            && let Ok(access) = std::env::var("LOMI_E2_CLOUD_FIXTURE_ACCESS")
        {
            let access = HostAccessCredential::try_from(access).expect("fixture access credential");
            let epoch = std::env::var("LOMI_E2_CLOUD_FIXTURE_EPOCH")
                .expect("fixture epoch")
                .parse::<u64>()
                .expect("fixture epoch decimal");
            // Fixture auth time is 1005; the bundle enforces a 300-second
            // maximum future window even though the remote bearer is live.
            auth.replace_ready_access_for_fixture(access, DecimalU64(epoch), 1305)
                .unwrap_or_else(|error| {
                    panic!("LOMI_CLOUD_WORKER_FAILURE=fixture_access_{error}");
                });
        }
        #[cfg(all(test, feature = "cloud-fixture"))]
        if matches!(seed, Seed::ExternalActive)
            && std::env::var_os("LOMI_E2_CLOUD_FIXTURE_STORE_PATH").is_some()
        {
            // The restart proof runs in separate OS processes. Carry the exact
            // synthetic secret bundle across that boundary just as the durable
            // HostStore is carried, so process two opens the same Ready auth.
            drop(auth);
            set_cloud_restart_diagnostic_stage(54);
            let bytes = provider
                .inner
                .fixture_bytes()
                .expect("fixture credential bundle")
                .to_vec();
            let path = directory_path.join("fixture-secret-state");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .expect("create fixture credential handoff");
            file.write_all(&bytes)
                .expect("write fixture credential handoff");
            file.sync_all().expect("sync fixture credential handoff");
            auth = HostAuth::open(
                &mut provider as &mut dyn SecretStorage,
                config.clone(),
                1005,
            )
            .expect("reopen fixture auth after handoff");
        }
        let mut context = Fixture {
            directory: &directory_path,
            #[cfg(feature = "cloud-fixture")]
            ipc_profile,
            #[cfg(feature = "cloud-fixture")]
            ipc_discovery,
            owner: &owner,
            setup: &setup,
            config,
            runtime_id,
            operation: &operation,
            state: &state,
            stopping: &stopping,
            gate: &gate,
            paused: &paused,
            retry: &retry,
            receiver: &receiver,
            io: None,
            aborted: Cell::new(false),
            anchor: Instant::now(),
            fault: &fault,
            probe_arm: &arm,
            probes: &probes,
        };
        test(&mut context, &mut auth);
    }
    fn heartbeat(binding: &RuntimeBinding) -> Reply {
        Reply::Heartbeat(HeartbeatResult {
            runtime: binding.clone(),
            lease_ms: DecimalU64(30_000),
            freshness_ms: DecimalU64(5_000),
        })
    }
    fn ack(binding: &RuntimeBinding, sequence: u64) -> Reply {
        Reply::Publication(PublicationResult {
            runtime: binding.clone(),
            publication_seq: DecimalU64(sequence),
        })
    }
    fn claim(binding: &RuntimeBinding) -> Reply {
        Reply::Claim(RuntimeClaimResult {
            runtime: binding.clone(),
            lease_ms: DecimalU64(30_000),
        })
    }
    fn successful<T>(result: Result<T, StepError>) {
        assert!(result.is_ok(), "actual typed step must succeed");
    }
    /// Bounded CloudWorker publication and permission refresh against auth-app.
    /// The ignored test is launched only by the private Bun/PostgreSQL fixture.
    #[cfg(feature = "cloud-fixture")]
    #[test]
    #[ignore = "requires the private auth-app TLS handler and live fixture token"]
    fn cloud_worker_uses_actual_handler_for_publication_and_permission_refresh() {
        fn fail_worker_step(error: StepError) -> ! {
            match error {
                StepError::Http(error) => {
                    panic!("LOMI_CLOUD_WORKER_FAILURE=http_{error}");
                }
                StepError::Auth(_) => panic!("LOMI_CLOUD_WORKER_FAILURE=auth"),
                StepError::Rejected => panic!("LOMI_CLOUD_WORKER_FAILURE=rejected"),
                StepError::Stale => panic!("LOMI_CLOUD_WORKER_FAILURE=stale"),
                StepError::ExpiredEnrollment => {
                    panic!("LOMI_CLOUD_WORKER_FAILURE=expired_enrollment")
                }
                StepError::ExpiredRotation => {
                    panic!("LOMI_CLOUD_WORKER_FAILURE=expired_rotation")
                }
            }
        }
        let origin = std::env::var("LOMI_E2_CLOUD_FIXTURE_ORIGIN").expect("fixture origin");
        let root = std::fs::read(
            std::env::var("LOMI_E2_CLOUD_FIXTURE_ROOT_DER").expect("fixture TLS root"),
        )
        .expect("fixture TLS root file");
        fixture(Seed::ExternalActive, |f, auth| {
            let workspace = f.project();
            let transport = DataTransport::with_test_root(
                RemoteApiOrigin::new(&f.config, origin).expect("pinned fixture origin"),
                root,
            )
            .expect("fixture TLS transport");
            let mut worker = Worker::default();
            println!("LOMI_CLOUD_WORKER_STAGE=fixture_ready");
            for index in 0..3 {
                match f.step(&mut worker, auth, &transport) {
                    Ok(StepOutcome::Network) => {
                        println!("LOMI_CLOUD_WORKER_STAGE=network_{index}");
                    }
                    Ok(StepOutcome::Deferred) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=deferred");
                    }
                    Ok(StepOutcome::PeerEligible(_)) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=unexpected_peer_eligibility");
                    }
                    Err(StepError::Http(error)) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=http_{}", error);
                    }
                    Err(StepError::Auth(_)) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=auth");
                    }
                    Err(StepError::Rejected) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=rejected");
                    }
                    Err(StepError::Stale) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=stale");
                    }
                    Err(StepError::ExpiredEnrollment) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=expired_enrollment");
                    }
                    Err(StepError::ExpiredRotation) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=expired_rotation");
                    }
                }
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::PeerEligible(_)) => {}
                Ok(StepOutcome::Network) => {
                    panic!("LOMI_CLOUD_WORKER_FAILURE=unexpected_settlement_network");
                }
                Ok(StepOutcome::Deferred) => {
                    panic!("LOMI_CLOUD_WORKER_FAILURE=settlement_deferred");
                }
                Err(error) => fail_worker_step(error),
            }
            if worker.heartbeat_observation.is_none() {
                panic!("LOMI_CLOUD_WORKER_FAILURE=heartbeat_missing");
            }
            if worker.has_retained_operation() {
                panic!("LOMI_CLOUD_WORKER_FAILURE=operation_retained");
            }

            let initial = f.records();
            if initial.pending.is_some() || !initial.outbox.is_empty() {
                panic!("LOMI_CLOUD_WORKER_FAILURE=initial_ack_retained");
            }
            let Some(initial_ack) = initial.acknowledged else {
                panic!("LOMI_CLOUD_WORKER_FAILURE=initial_ack_missing");
            };
            if initial_ack.state.acknowledged_publication_seq != DecimalU64(5)
                || initial_ack.workspaces.as_slice().len() != 1
            {
                panic!("LOMI_CLOUD_WORKER_FAILURE=initial_membership_mismatch");
            }

            // Revoke local workspace sharing only after the first Cloud ACK.
            // The next real Worker turn must publish the reduced membership.
            f.owner
                .begin_unshare(f.operation, workspace)
                .unwrap()
                .try_commit()
                .unwrap();
            for index in 3..5 {
                match f.step(&mut worker, auth, &transport) {
                    Ok(StepOutcome::Network) => {
                        println!("LOMI_CLOUD_WORKER_STAGE=network_{index}");
                    }
                    Ok(StepOutcome::Deferred) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_deferred");
                    }
                    Ok(StepOutcome::PeerEligible(_)) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_not_published");
                    }
                    Err(StepError::Http(error)) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=http_{}", error);
                    }
                    Err(StepError::Auth(_)) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_auth");
                    }
                    Err(StepError::Rejected) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_rejected");
                    }
                    Err(StepError::Stale) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_stale");
                    }
                    Err(StepError::ExpiredEnrollment) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_expired_enrollment");
                    }
                    Err(StepError::ExpiredRotation) => {
                        panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_expired_rotation");
                    }
                }
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::PeerEligible(_)) => {}
                Ok(StepOutcome::Network) => {
                    panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_unsettled");
                }
                Ok(StepOutcome::Deferred) => {
                    panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_settlement_deferred");
                }
                Err(error) => fail_worker_step(error),
            }
            let refreshed = f.records();
            if refreshed.pending.is_some() || !refreshed.outbox.is_empty() {
                panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_ack_retained");
            }
            let Some(refreshed_ack) = refreshed.acknowledged else {
                panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_ack_missing");
            };
            if refreshed_ack.state.acknowledged_publication_seq != DecimalU64(6)
                || !refreshed_ack.workspaces.as_slice().is_empty()
            {
                panic!("LOMI_CLOUD_WORKER_FAILURE=permission_refresh_membership_mismatch");
            }
            println!("LOMI_CLOUD_WORKER_STAGE=complete");
        });
    }
    /// A committed publication whose TLS acknowledgement is lost is reconciled
    /// by the next runtime GET; the retained local intent must not be retried.
    #[cfg(feature = "cloud-fixture")]
    fn run_actual_handler_lost_publication_ack(recreate_worker: bool) {
        let stage_prefix = if recreate_worker {
            "LOMI_CLOUD_LOST_ACK_RECREATE_STAGE"
        } else {
            "LOMI_CLOUD_LOST_ACK_STAGE"
        };
        let origin = std::env::var("LOMI_E2_CLOUD_FIXTURE_ORIGIN").expect("fixture origin");
        let root = std::fs::read(
            std::env::var("LOMI_E2_CLOUD_FIXTURE_ROOT_DER").expect("fixture TLS root"),
        )
        .expect("fixture TLS root");
        let expected_sequence = std::env::var("LOMI_E2_CLOUD_FIXTURE_PUBLICATION_SEQ")
            .expect("fixture publication sequence")
            .parse::<u64>()
            .expect("fixture publication sequence");
        let expected_generation = std::env::var("LOMI_E2_CLOUD_FIXTURE_GENERATION")
            .expect("fixture generation")
            .parse::<u64>()
            .expect("fixture generation");
        let expected_epoch = std::env::var("LOMI_E2_CLOUD_FIXTURE_EPOCH")
            .expect("fixture epoch")
            .parse::<u64>()
            .expect("fixture epoch");
        fixture(Seed::ExternalActive, |f, auth| {
            let workspace = f.project();
            let expected_runtime = RuntimeBinding {
                runtime_id: f.runtime_id,
                runtime_generation: DecimalU64(expected_generation),
                host_access_epoch: DecimalU64(expected_epoch),
            };
            let transport = DataTransport::with_test_root(
                RemoteApiOrigin::new(&f.config, origin).expect("pinned fixture origin"),
                root,
            )
            .expect("fixture TLS transport");
            let mut worker = Worker::default();
            for index in 0..2 {
                match f.step(&mut worker, auth, &transport) {
                    Ok(StepOutcome::Network) => {
                        println!("{stage_prefix}=network_{index}");
                    }
                    Ok(StepOutcome::Deferred) => {
                        panic!("LOMI_CLOUD_LOST_ACK_FAILURE=deferred_{index}");
                    }
                    Ok(StepOutcome::PeerEligible(_)) => {
                        panic!("LOMI_CLOUD_LOST_ACK_FAILURE=early_peer_{index}");
                    }
                    Err(StepError::Http(error)) => {
                        panic!("LOMI_CLOUD_LOST_ACK_FAILURE=http_{error}");
                    }
                    Err(StepError::Auth(_)) => {
                        panic!("LOMI_CLOUD_LOST_ACK_FAILURE=auth_{index}");
                    }
                    Err(StepError::Rejected) => {
                        panic!("LOMI_CLOUD_LOST_ACK_FAILURE=rejected_{index}");
                    }
                    Err(StepError::Stale) => {
                        panic!("LOMI_CLOUD_LOST_ACK_FAILURE=stale_{index}");
                    }
                    Err(StepError::ExpiredEnrollment) => {
                        panic!("LOMI_CLOUD_LOST_ACK_FAILURE=expired_enrollment");
                    }
                    Err(StepError::ExpiredRotation) => {
                        panic!("LOMI_CLOUD_LOST_ACK_FAILURE=expired_rotation");
                    }
                }
            }

            match f.step(&mut worker, auth, &transport) {
                Err(StepError::Http(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::OutcomeUnknown,
                ))) => {
                    println!("{stage_prefix}=publication_outcome_unknown");
                }
                Ok(_) => panic!("LOMI_CLOUD_LOST_ACK_FAILURE=publication_ack_not_lost"),
                Err(StepError::Http(error)) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=unexpected_http_{error}")
                }
                Err(StepError::Auth(_)) => panic!("LOMI_CLOUD_LOST_ACK_FAILURE=auth_publish"),
                Err(StepError::Rejected) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=rejected_publish")
                }
                Err(StepError::Stale) => panic!("LOMI_CLOUD_LOST_ACK_FAILURE=stale_publish"),
                Err(StepError::ExpiredEnrollment) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=expired_enrollment_publish")
                }
                Err(StepError::ExpiredRotation) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=expired_rotation_publish")
                }
            }
            if !worker.has_retained_operation() {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=recovery_continuation_lost");
            }
            let uncertain = f.records();
            if uncertain.pending.is_none() || uncertain.outbox.is_empty() {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=local_intent_not_retained");
            }
            let Some(binding_before_get) = uncertain.binding.as_ref() else {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=local_binding_missing");
            };
            if binding_before_get.acknowledged_publication_seq != DecimalU64(expected_sequence) {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=local_binding_cursor_advanced");
            }
            let binding_before_get = binding_before_get.clone();
            if let Some(before_ack) = uncertain.acknowledged.as_ref() {
                if before_ack.state.acknowledged_publication_seq != DecimalU64(expected_sequence)
                    || before_ack.workspaces.as_slice().len() > 1
                {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=local_ack_advanced");
                }
            }
            let Some(pending_before_get) = uncertain.pending.clone() else {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=local_intent_missing");
            };
            let outbox_before_get = uncertain.outbox.clone();
            let acknowledged_before_get = uncertain.acknowledged.clone();
            if binding_before_get.server_runtime != expected_runtime
                || binding_before_get.scope.authorization_generation != f.authorization().generation
                || binding_before_get.scope.owner_runtime_id != f.runtime_id
                || pending_before_get.params.expected_publication_seq
                    != DecimalU64(expected_sequence)
                || pending_before_get.params.runtime != binding_before_get.server_runtime
            {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=local_runtime_or_generation_changed");
            }
            println!("{stage_prefix}=not_acknowledged");
            println!("{stage_prefix}=intent_retained");

            if recreate_worker {
                // Recreate only the volatile worker. HostAuth, SharedOwner,
                // HostStore and PublicIo stay in place; the next GET must
                // confirm that the remote runtime lease is still live.
                drop(worker);
                let replacement_worker = Worker::default();
                if !matches!(&replacement_worker.action, Action::Get)
                    || replacement_worker.has_retained_operation()
                    || replacement_worker.transport.is_some()
                    || replacement_worker.scope.is_some()
                    || replacement_worker.lease_until.is_some()
                    || replacement_worker.fresh_until.is_some()
                    || replacement_worker.heartbeat_observation.is_some()
                    || replacement_worker.cached_eligibility().is_some()
                {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=replacement_worker_not_fresh");
                }
                let still_retained = f.records();
                if still_retained.pending.as_ref() != Some(&pending_before_get)
                    || still_retained.outbox != outbox_before_get
                    || still_retained.binding.as_ref() != Some(&binding_before_get)
                    || still_retained.acknowledged != acknowledged_before_get
                    || !matches!(auth.status(), lomi_host_auth::Status::Ready)
                    || f.authorization().generation
                        != binding_before_get.scope.authorization_generation
                {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=state_changed_during_worker_recreation");
                }
                worker = replacement_worker;
                println!("{stage_prefix}=fresh_worker_ready");
            }

            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::Network) => {
                    println!("{stage_prefix}=reconciled_by_get");
                }
                Ok(StepOutcome::Deferred) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=recovery_deferred");
                }
                Ok(StepOutcome::PeerEligible(_)) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=recovery_not_get");
                }
                Err(StepError::Http(error)) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=recovery_http_{error}");
                }
                Err(StepError::Auth(_)) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=recovery_auth");
                }
                Err(StepError::Rejected) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=recovery_rejected");
                }
                Err(StepError::Stale) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=recovery_stale");
                }
                Err(StepError::ExpiredEnrollment) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=recovery_expired_enrollment");
                }
                Err(StepError::ExpiredRotation) => {
                    panic!("LOMI_CLOUD_LOST_ACK_FAILURE=recovery_expired_rotation");
                }
            }
            let reconciled = f.records();
            if reconciled.pending.is_some() || !reconciled.outbox.is_empty() {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=reconciled_pending_work");
            }
            let Some(ack) = reconciled.acknowledged else {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=reconciled_ack_missing");
            };
            let Some(binding_after_get) = reconciled.binding.as_ref() else {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=reconciled_binding_missing");
            };
            if ack.state.acknowledged_publication_seq != DecimalU64(expected_sequence + 1)
                || ack.workspaces.as_slice().len() != 1
                || ack.workspaces.as_slice()[0].workspace_id != workspace
                || ack.workspaces != pending_before_get.params.workspaces
                || binding_after_get.acknowledged_publication_seq
                    != DecimalU64(expected_sequence + 1)
                || binding_after_get.server_runtime != binding_before_get.server_runtime
                || binding_after_get.scope != binding_before_get.scope
            {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=reconciled_state_mismatch");
            }
            if recreate_worker
                && (!matches!(&worker.action, Action::Online)
                    || worker.scope.as_ref() != Some(&binding_before_get.scope)
                    || worker
                        .lease_until
                        .is_none_or(|until| until <= Instant::now())
                    || worker.heartbeat_observation.is_some())
            {
                panic!("LOMI_CLOUD_LOST_ACK_FAILURE=reconciled_runtime_or_lease_missing");
            }
            println!("{stage_prefix}=complete");
        });
    }
    #[cfg(feature = "cloud-fixture")]
    #[test]
    #[ignore = "requires the private auth-app TLS handler and live fixture token"]
    fn cloud_worker_reconciles_lost_publication_ack_from_actual_handler() {
        run_actual_handler_lost_publication_ack(false);
    }
    /// The same real committed PUT with lost ACK recovers in a fresh Worker
    /// using only the HostStore records and a new runtime GET.
    #[cfg(feature = "cloud-fixture")]
    #[test]
    #[ignore = "requires the private auth-app TLS handler and live fixture token"]
    fn cloud_worker_reconciles_lost_publication_ack_after_worker_recreation() {
        run_actual_handler_lost_publication_ack(true);
    }
    /// A new owner process reconciles an ambiguous commit from the exact
    /// HostStore left behind by the process that lost its HTTP acknowledgement.
    #[cfg(feature = "cloud-fixture")]
    #[test]
    #[ignore = "requires the private auth-app TLS handler and live fixture token"]
    fn cloud_worker_reconciles_lost_ack_after_owner_process_restart() {
        CLOUD_RESTART_DIAGNOSTIC_STAGE.store(0, Ordering::Release);
        CLOUD_RESTART_CLOUD_GET_ERROR.store(0, Ordering::Release);
        CLOUD_RESTART_WORKER_PATH.store(0, Ordering::Release);
        CLOUD_RESTART_GUARD_OWNER_ERROR.store(0, Ordering::Release);
        CLOUD_RESTART_PRE_GET_FLAGS.store(0, Ordering::Release);
        std::panic::set_hook(Box::new(|info| {
            let stage = CLOUD_RESTART_DIAGNOSTIC_STAGE.load(Ordering::Acquire);
            let flags = CLOUD_RESTART_PRE_GET_FLAGS.load(Ordering::Acquire);
            let cloud_get_error = CLOUD_RESTART_CLOUD_GET_ERROR.load(Ordering::Acquire);
            let worker_path = CLOUD_RESTART_WORKER_PATH.load(Ordering::Acquire);
            let owner_error = CLOUD_RESTART_GUARD_OWNER_ERROR.load(Ordering::Acquire);
            let failure = match owner_error {
                1 => "recovery_guard_owner_domain_poisoned",
                2 => "recovery_guard_owner_domain_other",
                3 => "recovery_guard_owner_store_storage",
                4 => "recovery_guard_owner_store_fenced",
                5 => "recovery_guard_owner_store_other",
                6 => "recovery_guard_owner_uncertain_store",
                _ => match cloud_get_error {
                    1 => "recovery_cloud_get_domain",
                    2 => "recovery_cloud_get_store",
                    3 => "recovery_cloud_get_uncertain_store",
                    4 => "recovery_cloud_get_provider",
                    5 => "recovery_cloud_get_http",
                    6 => "recovery_cloud_get_stale",
                    _ => match worker_path {
                        1 => "recovery_auth_sealed_in_guard",
                        3 => "recovery_auth_sealed_in_snapshot",
                        _ => match stage {
                            1 => "profile_path_ready",
                            2 => "owner_lock_acquired",
                            3 => "store_opened",
                            4 => "fixture_state_prepared",
                            5 => "shared_owner_created",
                            6 => "auth_ready",
                            51 => "host_auth_opened",
                            54 => "fixture_secret_handoff",
                            7 => "recovery_records_read",
                            8 => "pending_intent_found",
                            9 => "binding_found",
                            10 => "pre_recovery_state_validated",
                            11 => "recovery_get_started",
                            12 => "recovery_get_returned",
                            13 => "post_recovery_records_read",
                            14 => "first_get_scope_not_invalidated",
                            15 => "second_get_claim_admitted",
                            16 => "second_get_claim_missing",
                            17 => "claim_post_completed",
                            18 => "claim_post_failed",
                            19 => "final_get_reconciled",
                            20 => "final_get_failed",
                            70 => "recovery_io_enter_started",
                            71 => "recovery_io_entered",
                            72 => "recovery_worker_step_started",
                            73 => "recovery_worker_step_returned",
                            74 => "recovery_worker_step_cleaned",
                            75 => "recovery_result_network",
                            76 => "recovery_result_deferred",
                            77 => "recovery_result_peer_eligible",
                            78 => "recovery_result_auth_error",
                            79 => "recovery_result_http_error",
                            80 => "recovery_result_rejected",
                            81 => "recovery_result_stale",
                            82 => "recovery_auth_storage",
                            83 => "recovery_auth_invalid_config",
                            84 => "recovery_auth_invalid_state",
                            85 => "recovery_auth_invalid_bundle",
                            86 => "recovery_auth_invalid_response",
                            87 => "recovery_auth_expired",
                            88 => "recovery_auth_sealed",
                            89 => "recovery_auth_clock_rollback",
                            90 => "recovery_auth_poll_too_early",
                            101 => "restart_ready_io_error",
                            102 => "restart_ready_io_unavailable",
                            110 => "restart_ready_domain_busy",
                            111 => "restart_ready_domain_cancelled",
                            112 => "restart_ready_domain_deadline",
                            113 => "restart_ready_domain_denied",
                            114 => "restart_ready_domain_poisoned",
                            115 => "restart_ready_domain_exhausted",
                            116 => "restart_ready_domain_stale",
                            117 => "restart_ready_domain_unfinished",
                            120 => "restart_ready_store_storage",
                            121 => "restart_ready_store_busy",
                            122 => "restart_ready_store_invalid",
                            123 => "restart_ready_store_not_found",
                            124 => "restart_ready_store_revision_conflict",
                            125 => "restart_ready_store_idempotency_conflict",
                            126 => "restart_ready_store_resource_exhausted",
                            127 => "restart_ready_store_fenced",
                            128 => "restart_ready_store_already_started",
                            129 => "restart_ready_store_schema_version",
                            130 => "restart_ready_store_backup",
                            140 => "restart_ready_provider_storage",
                            141 => "restart_ready_provider_invalid_config",
                            142 => "restart_ready_provider_invalid_state",
                            143 => "restart_ready_provider_invalid_bundle",
                            144 => "restart_ready_provider_invalid_response",
                            145 => "restart_ready_provider_expired",
                            146 => "restart_ready_provider_sealed",
                            147 => "restart_ready_provider_clock_rollback",
                            148 => "restart_ready_provider_poll_too_early",
                            150 => "restart_ready_http",
                            151 => "restart_ready_stale",
                            _ => "restart_test_setup",
                        },
                    },
                },
            };
            eprintln!(
                "LOMI_CLOUD_RESTART_PRE_GET=action_get:{}:retained_operation:{}:pending_intent:{}:outbox_nonempty:{}",
                flags & 1 != 0,
                flags & 2 != 0,
                flags & 4 != 0,
                flags & 8 != 0,
            );
            eprintln!("LOMI_CLOUD_RESTART_FAILURE={failure}");
            if failure == "restart_test_setup"
                && let Some(location) = info.location()
            {
                eprintln!(
                    "LOMI_CLOUD_RESTART_PANIC_LOCATION={}:{}",
                    location.file(),
                    location.line()
                );
            }
        }));
        let phase = std::env::var("LOMI_E2_CLOUD_FIXTURE_RESTART_PHASE").expect("restart phase");
        let origin = std::env::var("LOMI_E2_CLOUD_FIXTURE_ORIGIN").expect("fixture origin");
        let root = std::fs::read(
            std::env::var("LOMI_E2_CLOUD_FIXTURE_ROOT_DER").expect("fixture TLS root"),
        )
        .expect("fixture TLS root");
        let expected_sequence = std::env::var("LOMI_E2_CLOUD_FIXTURE_PUBLICATION_SEQ")
            .expect("fixture publication sequence")
            .parse::<u64>()
            .expect("fixture publication sequence");
        let seed = if phase == "before" {
            Seed::ExternalActive
        } else {
            assert!(
                phase == "after" || phase == "after-valid-lease",
                "unexpected restart phase"
            );
            Seed::ExternalRestarted
        };
        fixture(seed, |f, auth| {
            let transport = DataTransport::with_test_root(
                RemoteApiOrigin::new(&f.config, origin).expect("pinned fixture origin"),
                root,
            )
            .expect("fixture TLS transport");
            let mut worker = Worker::default();
            if phase == "before" {
                let workspace = f.project();
                for index in 0..2 {
                    match f.step(&mut worker, auth, &transport) {
                        Ok(StepOutcome::Network) => {
                            println!("LOMI_CLOUD_RESTART_STAGE=before_network_{index}")
                        }
                        _ => panic!("LOMI_CLOUD_RESTART_FAILURE=before_get_or_heartbeat"),
                    }
                }
                match f.step(&mut worker, auth, &transport) {
                    Err(StepError::Http(lomi_host_http::Error::DataRemote(
                        lomi_host_http::DataFailure::OutcomeUnknown,
                    ))) => println!("LOMI_CLOUD_RESTART_STAGE=outcome_unknown"),
                    _ => panic!("LOMI_CLOUD_RESTART_FAILURE=publication_not_ambiguous"),
                }
                let uncertain = f.records();
                let pending = uncertain.pending.expect("retained publication intent");
                let binding = uncertain.binding.expect("retained local binding");
                if uncertain.outbox.is_empty()
                    || binding.acknowledged_publication_seq != DecimalU64(expected_sequence)
                    || uncertain.acknowledged.is_some()
                    || pending.params.workspaces.as_slice().len() != 1
                    || pending.params.workspaces.as_slice()[0].workspace_id != workspace
                {
                    panic!("LOMI_CLOUD_RESTART_FAILURE=pre_restart_store_mismatch");
                }
                println!("LOMI_CLOUD_RESTART_STAGE=durable_intent_retained");
                println!("LOMI_CLOUD_RESTART_STAGE=owner_process_exiting");
                return;
            }

            set_cloud_restart_diagnostic_stage(7);
            let before = f.records();
            set_cloud_restart_diagnostic_stage(8);
            let old_intent = before
                .pending
                .as_ref()
                .expect("intent survives owner restart");
            let workspace = old_intent.params.workspaces.as_slice()[0].workspace_id;
            let old_binding = before
                .binding
                .as_ref()
                .expect("binding survives owner restart");
            set_cloud_restart_diagnostic_stage(9);
            if before.outbox.is_empty() {
                panic!("LOMI_CLOUD_RESTART_FAILURE=pre_recovery_outbox_missing");
            }
            set_cloud_restart_diagnostic_stage(10);
            println!(
                "LOMI_CLOUD_RESTART_PRE_GET=action_get:{}:retained_operation:{}:pending_intent:{}:outbox_nonempty:{}",
                matches!(&worker.action, Action::Get),
                worker.has_retained_operation(),
                before.pending.is_some(),
                !before.outbox.is_empty(),
            );
            CLOUD_RESTART_PRE_GET_FLAGS.store(
                (u8::from(matches!(&worker.action, Action::Get)))
                    | (u8::from(!worker.has_retained_operation()) << 1)
                    | (u8::from(before.pending.is_some()) << 2)
                    | (u8::from(!before.outbox.is_empty()) << 3),
                Ordering::Release,
            );
            println!("LOMI_CLOUD_RESTART_STAGE=new_owner_opened");
            set_cloud_restart_diagnostic_stage(11);
            if phase == "after-valid-lease" {
                match f.step(&mut worker, auth, &transport) {
                    Ok(StepOutcome::Network)
                        if matches!(worker.action, Action::Get) && worker.claim.is_none() =>
                    {
                        // A live predecessor lease is evidence about the old
                        // runtime, not authority for this newly opened owner.
                        // The GET invalidates its intent/binding and preserves
                        // the outbox; without current-owner claim admission the
                        // worker remains fail-closed and cannot publish again.
                    }
                    _ => panic!("LOMI_CLOUD_RESTART_FAILURE=valid_lease_predecessor_not_fenced"),
                }
                let fenced = f.records();
                if fenced.binding.is_some()
                    || fenced.pending.is_some()
                    || fenced.acknowledged.is_some()
                    || fenced.outbox != before.outbox
                    || fenced.outbox.is_empty()
                {
                    panic!(
                        "LOMI_CLOUD_RESTART_FAILURE=valid_lease_predecessor_fencing_state_mismatch"
                    );
                }
                println!(
                    "LOMI_CLOUD_RESTART_STAGE=valid_lease_predecessor_invalidated_outbox_preserved"
                );
                println!("LOMI_CLOUD_RESTART_STAGE=complete");
                return;
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::Network)
                    if matches!(worker.action, Action::Get) && worker.claim.is_none() =>
                {
                    // The lease expired while the owner was stopped. The GET
                    // therefore invalidates the old binding and ambiguous
                    // intent instead of acknowledging a publication against a
                    // runtime that is no longer live. Invalidation preserves
                    // the workspace outbox and cannot admit Claim in this turn.
                    let invalidated = f.records();
                    if invalidated.binding.is_some()
                        || invalidated.pending.is_some()
                        || invalidated.acknowledged.is_some()
                        || invalidated.outbox.is_empty()
                    {
                        set_cloud_restart_diagnostic_stage(14);
                        panic!("LOMI_CLOUD_RESTART_FAILURE=expired_lease_invalidation_mismatch");
                    }
                    println!("LOMI_CLOUD_RESTART_STAGE=expired_lease_invalidated_after_restart");
                }
                _ => {
                    set_cloud_restart_diagnostic_stage(14);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=lost_ack_reconciliation_did_not_complete");
                }
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::Network) => {
                    if !matches!(worker.action, Action::Claim(_)) || worker.claim.is_none() {
                        set_cloud_restart_diagnostic_stage(14);
                        panic!("LOMI_CLOUD_RESTART_FAILURE=expired_lease_claim_not_admitted");
                    }
                    set_cloud_restart_diagnostic_stage(15);
                    println!("LOMI_CLOUD_RESTART_STAGE=expired_lease_claim_admitted");
                }
                Ok(StepOutcome::Deferred) => {
                    set_cloud_restart_diagnostic_stage(76);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=recovery_deferred")
                }
                Ok(StepOutcome::PeerEligible(_)) => {
                    set_cloud_restart_diagnostic_stage(77);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=recovery_unexpected_peer")
                }
                Err(StepError::Auth(error)) => {
                    set_cloud_restart_diagnostic_stage(match error {
                        lomi_host_auth::Error::Storage(_) => 82,
                        lomi_host_auth::Error::InvalidConfig => 83,
                        lomi_host_auth::Error::InvalidState => 84,
                        lomi_host_auth::Error::InvalidBundle => 85,
                        lomi_host_auth::Error::InvalidResponse => 86,
                        lomi_host_auth::Error::Expired => 87,
                        lomi_host_auth::Error::Sealed => 88,
                        lomi_host_auth::Error::ClockRollback => 89,
                        lomi_host_auth::Error::PollTooEarly => 90,
                    });
                    panic!("LOMI_CLOUD_RESTART_FAILURE=recovery_auth_error")
                }
                Err(StepError::Http(_)) => {
                    set_cloud_restart_diagnostic_stage(79);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=recovery_http_error")
                }
                Err(StepError::Rejected) => {
                    set_cloud_restart_diagnostic_stage(80);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=recovery_rejected")
                }
                Err(StepError::Stale) => {
                    set_cloud_restart_diagnostic_stage(81);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=recovery_stale")
                }
                Err(StepError::ExpiredEnrollment) => {
                    panic!("LOMI_CLOUD_RESTART_FAILURE=recovery_expired_enrollment")
                }
                Err(StepError::ExpiredRotation) => {
                    panic!("LOMI_CLOUD_RESTART_FAILURE=recovery_expired_rotation")
                }
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::Network) if matches!(worker.action, Action::Get) => {
                    set_cloud_restart_diagnostic_stage(17);
                    println!("LOMI_CLOUD_RESTART_STAGE=expired_lease_claim_completed");
                }
                Ok(StepOutcome::Network) => {
                    set_cloud_restart_diagnostic_stage(18);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=claim_did_not_arm_reconciliation_get");
                }
                Ok(StepOutcome::Deferred) => {
                    set_cloud_restart_diagnostic_stage(76);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=claim_deferred");
                }
                Ok(StepOutcome::PeerEligible(_)) => {
                    set_cloud_restart_diagnostic_stage(77);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=claim_unexpected_peer");
                }
                Err(StepError::Auth(_)) => {
                    set_cloud_restart_diagnostic_stage(82);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=claim_auth_error");
                }
                Err(StepError::Http(_)) => {
                    set_cloud_restart_diagnostic_stage(79);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=claim_http_error");
                }
                Err(StepError::Rejected) => {
                    set_cloud_restart_diagnostic_stage(80);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=claim_rejected");
                }
                Err(StepError::Stale) => {
                    set_cloud_restart_diagnostic_stage(81);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=claim_stale");
                }
                Err(StepError::ExpiredEnrollment) => {
                    panic!("LOMI_CLOUD_RESTART_FAILURE=claim_expired_enrollment");
                }
                Err(StepError::ExpiredRotation) => {
                    panic!("LOMI_CLOUD_RESTART_FAILURE=claim_expired_rotation");
                }
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::Network) if matches!(worker.action, Action::Online) => {
                    set_cloud_restart_diagnostic_stage(19);
                    println!("LOMI_CLOUD_RESTART_STAGE=reconciled_by_get");
                }
                Ok(StepOutcome::Network) if matches!(worker.action, Action::Claim(_)) => {
                    set_cloud_restart_diagnostic_stage(16);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=unexpected_claim_after_restart");
                }
                _ => {
                    set_cloud_restart_diagnostic_stage(20);
                    panic!("LOMI_CLOUD_RESTART_FAILURE=final_get_failed");
                }
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::Network) if matches!(worker.action, Action::Online) => {
                    println!("LOMI_CLOUD_RESTART_STAGE=new_generation_heartbeat");
                }
                _ => panic!("LOMI_CLOUD_RESTART_FAILURE=new_generation_heartbeat_failed"),
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::Network) if matches!(worker.action, Action::Online) => {
                    println!("LOMI_CLOUD_RESTART_STAGE=new_generation_publication");
                }
                _ => panic!("LOMI_CLOUD_RESTART_FAILURE=new_generation_publication_failed"),
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::PeerEligible(_)) => {}
                _ => panic!("LOMI_CLOUD_RESTART_FAILURE=new_generation_settlement_failed"),
            }
            set_cloud_restart_diagnostic_stage(12);
            set_cloud_restart_diagnostic_stage(13);
            let after = f.records();
            let action = match worker.action {
                Action::Get => "get",
                Action::Claim(_) => "claim",
                Action::Online => "online",
                Action::Blocked => "blocked",
            };
            let ack_sequence = after
                .acknowledged
                .as_ref()
                .map(|ack| ack.state.acknowledged_publication_seq.0);
            let binding_sequence = after
                .binding
                .as_ref()
                .map(|binding| binding.acknowledged_publication_seq.0);
            let pending = if after.pending.is_some() {
                "present"
            } else {
                "absent"
            };
            let outbox = if after.outbox.is_empty() {
                "empty"
            } else {
                "nonempty"
            };
            let ack = match ack_sequence {
                None => "missing",
                Some(1) => "new_generation",
                Some(_) => "other",
            };
            let binding = match binding_sequence {
                None => "missing",
                Some(1) => "new_generation",
                Some(_) => "other",
            };
            println!(
                "LOMI_CLOUD_RESTART_STAGE=post_step_action_{action}_{pending}_outbox_{outbox}_ack_{ack}_binding_{binding}"
            );
            let ack = after
                .acknowledged
                .as_ref()
                .expect("new-generation publication acknowledgement persisted");
            if after.pending.is_some()
                || !after.outbox.is_empty()
                || ack.state.acknowledged_publication_seq != DecimalU64(1)
                || ack.workspaces.as_slice().len() != 1
                || ack.workspaces.as_slice()[0].workspace_id != workspace
                || after.binding.as_ref().is_none_or(|binding| {
                    binding.acknowledged_publication_seq != DecimalU64(1)
                        || binding.server_runtime.runtime_generation
                            != DecimalU64(old_binding.server_runtime.runtime_generation.0 + 1)
                })
            {
                panic!("LOMI_CLOUD_RESTART_FAILURE=post_recovery_store_mismatch");
            }
            println!("LOMI_CLOUD_RESTART_STAGE=complete");
        });
    }
    #[cfg(feature = "cloud-fixture")]
    #[test]
    fn persistent_cloud_profile_keeps_durable_lock_separate_from_short_ipc_profile() {
        fn long_profile(prefix: &str) -> (tempfile::TempDir, std::path::PathBuf) {
            let root = cloud_fixture_private_tempdir(prefix);
            let profile = root.path().join("cloud-artifacts/cloud-valid");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(profile.parent().unwrap())
                .unwrap();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&profile)
                .unwrap();
            assert!(
                profile
                    .join("host.sock")
                    .as_os_str()
                    .as_encoded_bytes()
                    .len()
                    > 100
            );
            (root, profile)
        }

        let (durable_root, durable_profile) =
            long_profile("lomi-cloud-fixture-deliberately-long-durable-profile-");
        assert!(durable_profile.starts_with(durable_root.path()));

        let mut observed_host = None;
        let mut observed_profile_id = None;
        let mut observed_runtime = None;
        let mut observed_public_doc = None;
        let mut ipc_profile = None;
        fixture_with_profile_override(
            Seed::Normal,
            Some(durable_profile.clone()),
            |fixture, auth| {
                assert_eq!(fixture.directory, durable_profile.as_path());
                assert!(matches!(auth.status(), lomi_host_auth::Status::Ready));
                assert_ne!(fixture.ipc_profile, durable_profile);
                assert!(
                    fixture
                        .ipc_profile
                        .join("host.sock")
                        .as_os_str()
                        .as_encoded_bytes()
                        .len()
                        <= 100
                );
                assert_eq!(
                    std::fs::symlink_metadata(&fixture.ipc_profile)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
                assert!(fixture.directory.join("host-public.toml").is_file());
                assert!(!fixture.ipc_profile.join("host-public.toml").exists());
                assert!(fixture.directory.join("host.sqlite3").is_file());
                assert!(
                    OwnerLock::acquire(fixture.directory)
                        .is_err_and(|error| matches!(error, super::super::platform::Error::Busy))
                );
                let identity = fixture.owner.identity(fixture.operation).unwrap();
                assert_eq!(fixture.ipc_discovery.host_id, identity.host_id);
                assert_eq!(fixture.ipc_discovery.profile_id, identity.profile_id);
                assert_eq!(fixture.ipc_discovery.runtime_id, fixture.runtime_id);
                observed_host = Some(identity.host_id);
                observed_profile_id = Some(identity.profile_id);
                observed_runtime = Some(fixture.runtime_id);
                observed_public_doc =
                    Some(std::fs::read(fixture.directory.join("host-public.toml")).unwrap());
                ipc_profile = Some(fixture.ipc_profile.clone());
            },
        );

        let ipc_profile = ipc_profile.unwrap();
        assert!(!ipc_profile.exists());
        let lock = OwnerLock::acquire(&durable_profile).unwrap();
        let store = HostStore::open(&lock.prepare_database().unwrap(), Limits::default()).unwrap();
        assert_eq!(store.identity().host_id, observed_host.unwrap());
        assert_eq!(store.identity().profile_id, observed_profile_id.unwrap());
        assert_ne!(store.runtime_id(), observed_runtime.unwrap());
        assert!(durable_profile.join("host-public.toml").is_file());
        assert_eq!(
            std::fs::read(durable_profile.join("host-public.toml")).unwrap(),
            observed_public_doc.unwrap()
        );

        let (unwind_root, unwind_profile) =
            long_profile("lomi-cloud-fixture-deliberately-long-unwind-profile-");
        assert!(unwind_profile.starts_with(unwind_root.path()));
        let mut unwind_ipc_profile = None;
        let mut unwind_host = None;
        let mut unwind_profile_id = None;
        let mut unwind_runtime = None;
        let mut unwind_public_doc = None;
        let unwind =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                fixture_with_profile_override(
                    Seed::Normal,
                    Some(unwind_profile.clone()),
                    |fixture, auth| {
                        assert!(matches!(auth.status(), lomi_host_auth::Status::Ready));
                        assert!(OwnerLock::acquire(fixture.directory).is_err_and(
                            |error| matches!(error, super::super::platform::Error::Busy)
                        ));
                        assert!(
                            fixture
                                .ipc_profile
                                .join("host.sock")
                                .as_os_str()
                                .as_encoded_bytes()
                                .len()
                                <= 100
                        );
                        assert!(fixture.directory.join("host-public.toml").is_file());
                        let identity = fixture.owner.identity(fixture.operation).unwrap();
                        assert_eq!(fixture.ipc_discovery.host_id, identity.host_id);
                        assert_eq!(fixture.ipc_discovery.profile_id, identity.profile_id);
                        assert_eq!(fixture.ipc_discovery.runtime_id, fixture.runtime_id);
                        unwind_ipc_profile = Some(fixture.ipc_profile.clone());
                        unwind_host = Some(identity.host_id);
                        unwind_profile_id = Some(identity.profile_id);
                        unwind_runtime = Some(fixture.runtime_id);
                        unwind_public_doc = Some(
                            std::fs::read(fixture.directory.join("host-public.toml")).unwrap(),
                        );
                        panic!("exercise persistent Cloud fixture unwind cleanup");
                    },
                );
            }));
        assert!(unwind.is_err());
        assert!(!unwind_ipc_profile.unwrap().exists());
        let lock = OwnerLock::acquire(&unwind_profile).unwrap();
        let store = HostStore::open(&lock.prepare_database().unwrap(), Limits::default()).unwrap();
        assert_eq!(store.identity().host_id, unwind_host.unwrap());
        assert_eq!(store.identity().profile_id, unwind_profile_id.unwrap());
        assert_ne!(store.runtime_id(), unwind_runtime.unwrap());
        assert!(unwind_profile.join("host-public.toml").is_file());
        assert_eq!(
            std::fs::read(unwind_profile.join("host-public.toml")).unwrap(),
            unwind_public_doc.unwrap()
        );
    }
    /// An account manager's actual host revoke denies the next Worker GET and
    /// the product loop durably closes the local authority before any write.
    #[cfg(feature = "cloud-fixture")]
    #[test]
    #[ignore = "requires the private auth-app TLS handler and live fixture token"]
    fn cloud_worker_fences_after_central_revoke_from_actual_handler() {
        let origin = std::env::var("LOMI_E2_CLOUD_FIXTURE_ORIGIN").expect("fixture origin");
        let root = std::fs::read(
            std::env::var("LOMI_E2_CLOUD_FIXTURE_ROOT_DER").expect("fixture TLS root"),
        )
        .expect("fixture TLS root");
        fixture(Seed::ExternalActive, |f, auth| {
            let transport = DataTransport::with_test_root(
                RemoteApiOrigin::new(&f.config, origin).expect("pinned fixture origin"),
                root,
            )
            .expect("fixture TLS transport");
            let identity = IdentityApi {
                host: f.owner.identity(f.operation).unwrap().host_id,
                stopping: f.stopping,
                refreshes: Cell::new(0),
                revokes: Cell::new(0),
                revoke_ok: false,
            };
            println!("LOMI_CLOUD_REVOKE_STAGE=fixture_ready");
            run_until_fence(f, auth, &identity, &transport, false);
            let fence = f.authorization();
            if !fence.locked
                || fence.pending_cloud_revoke
                || fence.generation != 1
                || !f.gate.load(Ordering::Acquire)
                || identity.refreshes.get() != 0
                || identity.revokes.get() != 0
                || f.io.is_some()
            {
                panic!("LOMI_CLOUD_REVOKE_FAILURE=local_fence_mismatch");
            }
            println!("LOMI_CLOUD_REVOKE_STAGE=complete");
        });
    }
    /// The first owner turn claims the server runtime, then proceeds through
    /// the normal GET, heartbeat and publication handlers over pinned TLS.
    #[cfg(feature = "cloud-fixture")]
    #[test]
    #[ignore = "requires the private auth-app TLS handler and live fixture token"]
    fn cloud_worker_claims_and_publishes_through_actual_handler() {
        let origin = std::env::var("LOMI_E2_CLOUD_FIXTURE_ORIGIN").expect("fixture origin");
        let root = std::fs::read(
            std::env::var("LOMI_E2_CLOUD_FIXTURE_ROOT_DER").expect("fixture TLS root"),
        )
        .expect("fixture TLS root");
        fixture(Seed::ExternalUnbound, |f, auth| {
            let transport = DataTransport::with_test_root(
                RemoteApiOrigin::new(&f.config, origin).expect("pinned fixture origin"),
                root,
            )
            .expect("fixture TLS transport");
            let mut worker = Worker::default();
            for index in 0..5 {
                match f.step(&mut worker, auth, &transport) {
                    Ok(StepOutcome::Network) => println!("LOMI_CLOUD_CLAIM_STAGE=network_{index}"),
                    Ok(StepOutcome::Deferred) => {
                        panic!("LOMI_CLOUD_CLAIM_FAILURE=deferred_{index}")
                    }
                    Ok(StepOutcome::PeerEligible(_)) => {
                        panic!("LOMI_CLOUD_CLAIM_FAILURE=early_peer_{index}")
                    }
                    Err(StepError::Http(error)) => panic!("LOMI_CLOUD_CLAIM_FAILURE=http_{error}"),
                    Err(StepError::Auth(_)) => panic!("LOMI_CLOUD_CLAIM_FAILURE=auth_{index}"),
                    Err(StepError::Rejected) => panic!("LOMI_CLOUD_CLAIM_FAILURE=rejected_{index}"),
                    Err(StepError::Stale) => panic!("LOMI_CLOUD_CLAIM_FAILURE=stale_{index}"),
                    Err(StepError::ExpiredEnrollment) => {
                        panic!("LOMI_CLOUD_CLAIM_FAILURE=expired_enrollment");
                    }
                    Err(StepError::ExpiredRotation) => {
                        panic!("LOMI_CLOUD_CLAIM_FAILURE=expired_rotation");
                    }
                }
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::PeerEligible(_)) => (),
                _ => panic!("LOMI_CLOUD_CLAIM_FAILURE=settlement"),
            }
            let records = f.records();
            let Some(binding) = records.binding else {
                panic!("LOMI_CLOUD_CLAIM_FAILURE=binding_missing")
            };
            let expected_generation = DecimalU64(
                std::env::var("LOMI_E2_CLOUD_FIXTURE_GENERATION")
                    .expect("fixture generation")
                    .parse::<u64>()
                    .expect("fixture generation")
                    .checked_add(1)
                    .expect("fixture generation increment"),
            );
            let expected_epoch = DecimalU64(
                std::env::var("LOMI_E2_CLOUD_FIXTURE_EPOCH")
                    .expect("fixture epoch")
                    .parse::<u64>()
                    .expect("fixture epoch")
                    .checked_add(1)
                    .expect("fixture epoch increment"),
            );
            if binding.server_runtime.runtime_generation != expected_generation
                || binding.server_runtime.host_access_epoch != expected_epoch
                || binding.server_runtime.runtime_id
                    != RuntimeId::try_from(
                        std::env::var("LOMI_E2_CLOUD_FIXTURE_RUNTIME_ID")
                            .expect("fixture runtime id"),
                    )
                    .expect("fixture runtime id")
                || records
                    .acknowledged
                    .as_ref()
                    .map(|ack| ack.state.acknowledged_publication_seq)
                    != Some(DecimalU64(1))
                || records.pending.is_some()
                || !records.outbox.is_empty()
                || auth.verified_host_access_epoch().ok() != Some(expected_epoch)
                || worker.has_retained_operation()
            {
                panic!("LOMI_CLOUD_CLAIM_FAILURE=state_mismatch");
            }
            println!("LOMI_CLOUD_CLAIM_STAGE=complete");
        });
    }
    /// A newly registered host with no server runtime row claims generation one
    /// and publishes its already-shared workspace through the real handlers.
    #[cfg(feature = "cloud-fixture")]
    #[test]
    #[ignore = "requires the private auth-app TLS handler and live fixture token"]
    fn cloud_worker_initial_claims_without_existing_server_binding() {
        let origin = std::env::var("LOMI_E2_CLOUD_FIXTURE_ORIGIN").expect("fixture origin");
        let root = std::fs::read(
            std::env::var("LOMI_E2_CLOUD_FIXTURE_ROOT_DER").expect("fixture TLS root"),
        )
        .expect("fixture TLS root");
        let expected_epoch = std::env::var("LOMI_E2_CLOUD_FIXTURE_EXPECTED_EPOCH")
            .map(|value| value.parse::<u64>().expect("expected claim epoch"))
            .unwrap_or(5);
        fixture(Seed::ExternalUnbound, |f, auth| {
            let workspace = f.project();
            let transport = DataTransport::with_test_root(
                RemoteApiOrigin::new(&f.config, origin).expect("pinned fixture origin"),
                root,
            )
            .expect("fixture TLS transport");
            let mut worker = Worker::default();
            for index in 0..5 {
                match f.step(&mut worker, auth, &transport) {
                    Ok(StepOutcome::Network) => {
                        println!("LOMI_CLOUD_INITIAL_CLAIM_STAGE=network_{index}")
                    }
                    Ok(StepOutcome::Deferred) => {
                        panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=deferred_{index}")
                    }
                    Ok(StepOutcome::PeerEligible(_)) => {
                        panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=early_peer_{index}")
                    }
                    Err(StepError::Http(error)) => {
                        panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=http_{error}")
                    }
                    Err(StepError::Auth(_)) => {
                        panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=auth_{index}")
                    }
                    Err(StepError::Rejected) => {
                        panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=rejected_{index}")
                    }
                    Err(StepError::Stale) => {
                        panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=stale_{index}")
                    }
                    Err(StepError::ExpiredEnrollment) => {
                        panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=expired_enrollment")
                    }
                    Err(StepError::ExpiredRotation) => {
                        panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=expired_rotation")
                    }
                }
            }
            match f.step(&mut worker, auth, &transport) {
                Ok(StepOutcome::PeerEligible(_)) => (),
                _ => panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=settlement"),
            }
            let records = f.records();
            let Some(binding) = records.binding else {
                panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=binding_missing")
            };
            let expected_epoch = DecimalU64(expected_epoch);
            let Some(ack) = records.acknowledged else {
                panic!("LOMI_CLOUD_INITIAL_CLAIM_FAILURE=ack_missing")
            };
            if binding.server_runtime.runtime_generation != DecimalU64(1)
                || binding.server_runtime.host_access_epoch != expected_epoch
                || binding.server_runtime.runtime_id
                    != RuntimeId::try_from(
                        std::env::var("LOMI_E2_CLOUD_FIXTURE_RUNTIME_ID")
                            .expect("fixture runtime id"),
                    )
                    .expect("fixture runtime id")
                || ack.state.acknowledged_publication_seq != DecimalU64(1)
                || ack.workspaces.as_slice().len() != 1
                || ack.workspaces.as_slice()[0].workspace_id != workspace
                || records.pending.is_some()
                || !records.outbox.is_empty()
                || auth.verified_host_access_epoch().ok() != Some(expected_epoch)
                || worker.has_retained_operation()
            {
                panic!(
                    "LOMI_CLOUD_INITIAL_CLAIM_FAILURE=state_mismatch_gen{}_epoch{}_runtime{}_seq{}_workspaces{}_membership{}_pending{}_outbox{}_auth{}_retained{}",
                    binding.server_runtime.runtime_generation.0,
                    binding.server_runtime.host_access_epoch.0,
                    binding.server_runtime.runtime_id
                        == RuntimeId::try_from(
                            std::env::var("LOMI_E2_CLOUD_FIXTURE_RUNTIME_ID")
                                .expect("fixture runtime id")
                        )
                        .expect("fixture runtime id"),
                    ack.state.acknowledged_publication_seq.0,
                    ack.workspaces.as_slice().len(),
                    ack.workspaces
                        .as_slice()
                        .first()
                        .is_some_and(|w| w.workspace_id == workspace),
                    records.pending.is_some(),
                    records.outbox.len(),
                    auth.verified_host_access_epoch().map(|e| e.0).unwrap_or(0),
                    worker.has_retained_operation(),
                );
            }
            println!("LOMI_CLOUD_INITIAL_CLAIM_STAGE=complete");
        });
    }
    // Preserve a distinct worker call for every configured HTTP request.
    fn online(f: &mut Fixture<'_>, auth: &mut HostAuth<'_, dyn SecretStorage + '_>) -> Worker {
        let binding = f.binding();
        let api = FixedApi::new(vec![
            Reply::Get(f.snapshot(Some(binding.clone()), 0)),
            heartbeat(&binding),
            ack(&binding, 1),
        ]);
        let mut worker = Worker::default();
        successful(f.step(&mut worker, auth, &api));
        successful(f.step(&mut worker, auth, &api));
        successful(f.step(&mut worker, auth, &api));
        assert_eq!(*api.requests.borrow(), ["GET", "HB", "PUT"]);
        worker
    }
    fn eligibility(
        f: &mut Fixture<'_>,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        worker: &mut Worker,
    ) -> PeerEligibility {
        worker.heartbeat_at = Instant::now().checked_add(Duration::from_secs(60));
        let api = FixedApi::new(vec![]);
        match f.step(worker, auth, &api).unwrap() {
            StepOutcome::PeerEligible(value) => *value,
            _ => panic!("expected exact idle observation"),
        }
    }
    struct IdentityApi<'a> {
        host: HostId,
        stopping: &'a AtomicBool,
        refreshes: Cell<usize>,
        revokes: Cell<usize>,
        revoke_ok: bool,
    }
    impl AuthTransport for IdentityApi<'_> {
        fn initiate(
            &self,
            _: &lomi_remote_protocol::EnrollmentInitiateParams,
        ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn poll(
            &self,
            _: &lomi_remote_protocol::DeviceCode,
        ) -> Result<lomi_host_http::PollOutcome, lomi_host_http::Error> {
            unreachable!()
        }
        fn exchange(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationExchangeParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn register(
            &self,
            _: &lomi_remote_protocol::HostRegisterParams,
            _: &HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn refresh(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationRefreshParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            self.refreshes.set(self.refreshes.get() + 1);
            self.stopping.store(true, Ordering::Release);
            Err(lomi_host_http::Error::Timeout)
        }
        fn revoke(
            &self,
            host: HostId,
            request: &lomi_remote_protocol::HostRevokeParams,
            _: &HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            assert_eq!(host, self.host);
            self.revokes.set(self.revokes.get() + 1);
            if self.revoke_ok {
                Ok(lomi_remote_protocol::HostRevokeResult {
                    host_id: host,
                    host_access_epoch: DecimalU64(request.expected_host_access_epoch.0 + 1),
                })
            } else {
                self.stopping.store(true, Ordering::Release);
                Err(lomi_host_http::Error::Timeout)
            }
        }
    }

    fn running_terminal(
        f: &Fixture<'_>,
        workspace: lomi_remote_protocol::WorkspaceId,
    ) -> lomi_remote_protocol::TerminalContext {
        use lomi_host_store::{OperationBinding, parameter_hash};
        use lomi_remote_protocol::{rpc::*, *};
        let binding = OperationBinding {
            rights: StoredOperationRights::new(
                OperationId::from_bytes([1; 16]).unwrap(),
                ConsumerAuthorizationId::from_bytes([2; 16]).unwrap(),
                workspace,
                Method::TerminalCreate,
                CapabilitySet::control_with_workspace_tools(),
                false,
            )
            .unwrap(),
            parameter_hash: parameter_hash(&(Method::TerminalCreate, workspace)).unwrap(),
        };
        let mut state = f.owner.workspace(f.operation, workspace).unwrap().state;
        f.owner
            .begin_admit_external(f.operation, &binding, state.domain_revision)
            .unwrap()
            .try_commit()
            .unwrap();
        let permit = f
            .owner
            .begin_start_external(f.operation, &binding)
            .unwrap()
            .try_commit()
            .unwrap();
        state.domain_revision = DecimalU64(state.domain_revision.0 + 1);
        let terminal = TerminalContext {
            workspace: state.context.clone(),
            pane_id: PaneId::from_bytes([3; 16]).unwrap(),
            session_id: TerminalSessionId::from_bytes([4; 16]).unwrap(),
            session_epoch: SessionEpoch::from_bytes([5; 16]).unwrap(),
            profile: TerminalProfile::ExperimentalRustGridV1,
        };
        state.tabs = BoundedList(vec![TerminalTab {
            tab_id: TabId::from_bytes([6; 16]).unwrap(),
            name: "private-title".to_owned().try_into().unwrap(),
            layout: TerminalLayout::Pane {
                pane: TerminalPane {
                    pane_id: terminal.pane_id,
                    session: Some(terminal.clone()),
                    state: PaneState::Running,
                },
            },
        }]);
        f.owner
            .begin_complete_external(
                f.operation,
                &permit,
                OperationState::Succeeded,
                Effect::Committed,
                Some(OperationResult::Terminal {
                    domain_revision: state.domain_revision,
                    pane_id: terminal.pane_id,
                    session_id: terminal.session_id,
                    session_epoch: terminal.session_epoch,
                }),
                Some(state),
            )
            .unwrap()
            .try_commit()
            .unwrap();
        terminal
    }

    #[test]
    fn absent_pin_creates_no_agent_and_running_worker_sees_installed_pin() {
        fixture(Seed::NoPin, |f, auth| {
            let mut worker = Worker::default();
            let api = FixedApi::new(vec![Reply::Get(f.snapshot(None, 0))]);
            successful(f.step(&mut worker, auth, &api));
            assert!(worker.transport.is_none());
            assert!(api.requests.borrow().is_empty());
            f.pin(auth);
            successful(f.step(&mut worker, auth, &api));
            assert_eq!(*api.requests.borrow(), ["GET"]);
            assert!(matches!(worker.action, Action::Claim(DecimalU64(17))));
        });
    }
    #[test]
    fn initial_get_claim_get_persists_epoch_then_heartbeat_and_complete_publication() {
        with_fixture(|f, auth| {
            f.project();
            let binding = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(None, 0)),
                claim(&binding),
                Reply::Get(f.snapshot(Some(binding.clone()), 0)),
                heartbeat(&binding),
                ack(&binding, 1),
            ]);
            let mut worker = Worker::default();
            successful(f.step(&mut worker, auth, &api));
            successful(f.step(&mut worker, auth, &api));
            assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(12));
            successful(f.step(&mut worker, auth, &api));
            successful(f.step(&mut worker, auth, &api));
            successful(f.step(&mut worker, auth, &api));
            assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(13));
            assert_eq!(*api.requests.borrow(), ["GET", "CLAIM", "GET", "HB", "PUT"]);
            assert_eq!(api.claims.borrow()[0].expected_generation, DecimalU64(17));
            assert_eq!(api.claims.borrow()[0].runtime_id, binding.runtime_id);
            assert_eq!(api.publications.borrow()[0].workspaces.as_slice().len(), 1);
            assert!(
                api.publications.borrow()[0].workspaces.as_slice()[0]
                    .terminals
                    .as_slice()
                    .is_empty()
            );
            assert!(f.records().pending.is_none());
            assert!(f.records().outbox.is_empty());
        });
    }
    #[test]
    fn legacy_sequence_without_acknowledged_membership_publishes_once() {
        fixture(Seed::LegacySequence, |f, auth| {
            assert!(f.records().acknowledged.is_none());
            let binding = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(binding.clone()), 7)),
                heartbeat(&binding),
                ack(&binding, 8),
            ]);
            let mut worker = Worker::default();
            successful(f.step(&mut worker, auth, &api));
            successful(f.step(&mut worker, auth, &api));
            successful(f.step(&mut worker, auth, &api));
            let _ = eligibility(f, auth, &mut worker);
            assert_eq!(*api.requests.borrow(), ["GET", "HB", "PUT"]);
            assert_eq!(api.publications.borrow()[0].publication_seq, DecimalU64(8));
            let records = f.records();
            assert!(records.pending.is_none());
            let acknowledged = records.acknowledged.unwrap();
            assert_eq!(
                acknowledged.state.acknowledged_publication_seq,
                DecimalU64(8)
            );
            assert!(acknowledged.workspaces.as_slice().is_empty());
        });
    }
    #[test]
    fn lost_claim_and_lost_put_reconcile_exact_get_without_blind_retry() {
        with_fixture(|f, auth| {
            let b = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(None, 0)),
                Reply::Error(lomi_host_http::Error::Timeout),
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                heartbeat(&b),
                Reply::Error(lomi_host_http::Error::Timeout),
                Reply::Get(f.snapshot(Some(b), 1)),
            ]);
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            assert!(f.step(&mut w, auth, &api).is_err());
            successful(f.step(&mut w, auth, &api));
            successful(f.step(&mut w, auth, &api));
            assert!(f.step(&mut w, auth, &api).is_err());
            assert!(f.records().pending.is_some());
            successful(f.step(&mut w, auth, &api));
            assert!(f.records().pending.is_none());
            assert_eq!(
                *api.requests.borrow(),
                ["GET", "CLAIM", "GET", "HB", "PUT", "GET"]
            );
        });
    }
    #[test]
    fn uncertain_put_retains_exact_intent_across_unshare_and_retries_only_after_get() {
        with_fixture(|f, auth| {
            let workspace = f.project();
            let b = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                heartbeat(&b),
                Reply::Error(lomi_host_http::Error::Timeout),
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                heartbeat(&b),
                ack(&b, 1),
                heartbeat(&b),
                ack(&b, 2),
            ]);
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            successful(f.step(&mut w, auth, &api));
            assert!(f.step(&mut w, auth, &api).is_err());
            let frozen = f.records().pending.unwrap();
            f.owner
                .begin_unshare(f.operation, workspace)
                .unwrap()
                .try_commit()
                .unwrap();
            assert_eq!(f.records().pending, Some(frozen));
            for _ in 0..5 {
                successful(f.step(&mut w, auth, &api));
            }
            let publications = api.publications.borrow();
            assert_eq!(publications[0], publications[1]);
            assert_eq!(publications[0].workspaces.as_slice().len(), 1);
            assert!(publications[2].workspaces.as_slice().is_empty());
            assert!(f.records().outbox.is_empty());
        });
    }
    #[test]
    fn unknown_publication_outcome_prearms_get_instead_of_retrying_put() {
        with_fixture(|f, auth| {
            let workspace = f.project();
            let binding = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(binding.clone()), 0)),
                heartbeat(&binding),
                Reply::Error(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::OutcomeUnknown,
                )),
                Reply::Get(f.snapshot(Some(binding), 1)),
            ]);
            let mut worker = Worker::default();
            successful(f.step(&mut worker, auth, &api));
            successful(f.step(&mut worker, auth, &api));
            assert!(matches!(
                f.step(&mut worker, auth, &api),
                Err(StepError::Http(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::OutcomeUnknown
                )))
            ));
            assert!(matches!(worker.action, Action::Get));
            let pending = f.records();
            assert!(pending.pending.is_some());
            assert_eq!(pending.outbox.len(), 1);
            successful(f.step(&mut worker, auth, &api));
            assert_eq!(&*api.requests.borrow(), &["GET", "HB", "PUT", "GET"]);
            assert_eq!(api.publications.borrow().len(), 1);
            let reconciled = f.records();
            assert!(reconciled.pending.is_none());
            assert!(reconciled.outbox.is_empty());
            let ack = reconciled
                .acknowledged
                .expect("GET reconciles committed cursor");
            assert_eq!(ack.workspaces.as_slice().len(), 1);
            assert_eq!(ack.workspaces.as_slice()[0].workspace_id, workspace);
        });
    }
    #[test]
    fn foreign_owner_is_not_adopted_and_server_generation_drives_claim() {
        with_fixture(|f, auth| {
            let mut foreign = f.binding();
            foreign.runtime_id = lomi_remote_protocol::RuntimeId::from_bytes([77; 16]).unwrap();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(foreign), 9)),
                Reply::Error(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::HostBusy,
                )),
            ]);
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            assert!(f.records().binding.is_none());
            assert!(f.step(&mut w, auth, &api).is_err());
            assert_eq!(api.claims.borrow()[0].expected_generation, DecimalU64(18));
            assert_eq!(api.claims.borrow()[0].runtime_id, f.binding().runtime_id);
        });
    }
    #[test]
    fn volatile_logout_gate_drops_publication_response_without_ack_or_durable_logout() {
        with_fixture(|f, auth| {
            let b = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                heartbeat(&b),
                ack(&b, 1),
            ]);
            let gate = f.gate;
            api.hook_on("PUT", move || gate.store(true, Ordering::Release));
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            successful(f.step(&mut w, auth, &api));
            assert!(matches!(f.step(&mut w, auth, &api), Err(StepError::Stale)));
            assert!(f.records().pending.is_some());
            assert!(!f.authorization().locked);
            assert!(matches!(f.step(&mut w, auth, &api), Err(StepError::Stale)));
            assert_eq!(api.publications.borrow().len(), 1);
        });
    }
    #[test]
    fn advanced_sequence_and_malformed_heartbeat_park_cloud_without_ack() {
        with_fixture(|f, auth| {
            let b = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                heartbeat(&b),
                Reply::Error(lomi_host_http::Error::Timeout),
                Reply::Get(f.snapshot(Some(b.clone()), 2)),
            ]);
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            successful(f.step(&mut w, auth, &api));
            assert!(f.step(&mut w, auth, &api).is_err());
            assert!(f.step(&mut w, auth, &api).is_err());
            assert!(matches!(w.action, Action::Blocked));
            successful(f.step(&mut w, auth, &api));
            assert_eq!(api.requests.borrow().len(), 4);
            assert!(f.records().pending.is_some());
        });
        with_fixture(|f, auth| {
            let b = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                Reply::Heartbeat(HeartbeatResult {
                    runtime: b,
                    lease_ms: DecimalU64(100),
                    freshness_ms: DecimalU64(101),
                }),
            ]);
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            assert!(f.step(&mut w, auth, &api).is_err());
            assert!(w.heartbeat_observation.is_none());
            assert!(api.publications.borrow().is_empty());
        });
    }
    #[test]
    fn terminal_exit_during_lost_put_preserves_intent_then_publishes_current_membership() {
        with_fixture(|f, auth| {
            let workspace = f.project();
            let terminal = running_terminal(f, workspace);
            let b = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                heartbeat(&b),
                Reply::Error(lomi_host_http::Error::Timeout),
                Reply::Get(f.snapshot(Some(b.clone()), 1)),
                heartbeat(&b),
                ack(&b, 2),
            ]);
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            successful(f.step(&mut w, auth, &api));
            assert!(f.step(&mut w, auth, &api).is_err());
            let frozen = f.records().pending.unwrap();
            assert!(
                f.owner
                    .begin_terminal_exit(f.operation, &terminal)
                    .unwrap()
                    .try_commit()
                    .unwrap()
            );
            let outbox = f.records().outbox;
            assert_eq!(f.records().pending, Some(frozen));
            successful(f.step(&mut w, auth, &api));
            assert_eq!(f.records().outbox, outbox);
            successful(f.step(&mut w, auth, &api));
            successful(f.step(&mut w, auth, &api));
            let publications = api.publications.borrow();
            assert_eq!(
                publications[0].workspaces.as_slice()[0]
                    .terminals
                    .as_slice()[0]
                    .session_id,
                terminal.session_id
            );
            assert!(
                publications[1].workspaces.as_slice()[0]
                    .terminals
                    .as_slice()
                    .is_empty()
            );
            assert!(
                !serde_json::to_string(&publications[0])
                    .unwrap()
                    .contains("private-title")
            );
        });
    }
    #[test]
    fn predecessor_runtime_intent_is_explicitly_invalidated_without_acknowledging_outbox() {
        fixture(Seed::ReopenedPending, |f, auth| {
            let before = f.records();
            assert!(before.pending.is_some());
            assert!(!before.outbox.is_empty());
            let predecessor = before.pending.as_ref().unwrap().params.runtime.clone();
            assert_ne!(predecessor.runtime_id, f.binding().runtime_id);
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(predecessor.clone()), 1)),
                // Invalidation is an effectful settlement. A fresh GET must
                // produce the no-effect continuation before Claim can send.
                Reply::Get(f.snapshot(Some(predecessor), 1)),
                Reply::Error(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::HostBusy,
                )),
            ]);
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            assert!(f.records().pending.is_none());
            assert!(f.records().binding.is_none());
            assert_eq!(f.records().outbox, before.outbox);
            successful(f.step(&mut w, auth, &api));
            assert!(f.step(&mut w, auth, &api).is_err());
            assert_eq!(*api.requests.borrow(), ["GET", "GET", "CLAIM"]);
            assert_eq!(api.claims.borrow()[0].runtime_id, f.binding().runtime_id);
            assert!(api.publications.borrow().is_empty());
        });
    }
    #[test]
    fn durable_logout_or_stop_during_get_drops_higher_epoch() {
        for stop in [false, true] {
            with_fixture(|f, auth| {
                let api = FixedApi::new(vec![Reply::Get(f.snapshot(Some(f.binding()), 0))]);
                let stopping = f.stopping;
                let gate = f.gate;
                let owner = f.owner;
                let operation = f.operation;
                api.hook(move || {
                    if stop {
                        stopping.store(true, Ordering::Release);
                    } else {
                        gate.store(true, Ordering::Release);
                        owner
                            .begin_local_logout(operation)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                });
                let mut w = Worker::default();
                assert!(matches!(f.step(&mut w, auth, &api), Err(StepError::Stale)));
                assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(12));
                assert!(w.heartbeat_observation.is_none());
                stopping.store(false, Ordering::Release);
                assert!(f.records().pending.is_none());
            });
        }
    }
    // Observer owns its own bounded operation; it never receives a guard.
    fn run_until_fence(
        f: &mut Fixture<'_>,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        transport: &dyn AuthTransport,
        api: &dyn DataApi,
        pending: bool,
    ) {
        f.enter();
        let owner = f.owner;
        let stopping = f.stopping;
        thread::scope(|threads| {
            threads.spawn(move || {
                let observer_stop = AtomicBool::new(false);
                let operation =
                    OwnerOperation::new(Instant::now() + Duration::from_secs(3), &observer_stop);
                for _ in 0..200 {
                    if let Ok(status) = owner.auth_status(&operation) {
                        let fence = status.authorization;
                        if fence.locked && fence.pending_cloud_revoke == pending {
                            stopping.store(true, Ordering::Release);
                            return;
                        }
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                stopping.store(true, Ordering::Release);
                panic!("bounded typed observer did not see fence");
            });
            run_with_data(auth, transport, &f.config, f.runtime(), Some(api));
        });
        f.io = None;
        stopping.store(false, Ordering::Release);
    }
    #[test]
    fn refresh_and_revoke_take_priority_over_runtime_publication_in_actual_worker_loop() {
        for logout in [false, true] {
            with_fixture(|f, auth| {
                if logout {
                    f.fence();
                }
                let stopping = f.stopping;
                let host = f.owner.identity(f.operation).unwrap().host_id;
                let transport = IdentityApi {
                    host,
                    stopping,
                    refreshes: Cell::new(0),
                    revokes: Cell::new(0),
                    revoke_ok: false,
                };
                let api = FixedApi::new(if logout {
                    vec![Reply::Get(f.snapshot(None, 0))]
                } else {
                    vec![]
                });
                f.enter();
                let mut runtime = f.runtime();
                if !logout {
                    runtime.base = 1243;
                }
                run_with_data(auth, &transport, &f.config, runtime, Some(&api));
                assert_eq!(transport.refreshes.get(), usize::from(!logout));
                assert_eq!(transport.revokes.get(), usize::from(logout));
                assert_eq!(
                    *api.requests.borrow(),
                    if logout { vec!["GET"] } else { vec![] }
                );
            });
        }
    }
    #[test]
    fn authorization_rejections_fence_durable_and_volatile_authority_in_actual_loop() {
        for failure in [
            lomi_host_http::DataFailure::AuthRequired,
            lomi_host_http::DataFailure::ScopeDenied,
        ] {
            with_fixture(|f, auth| {
                let transport = IdentityApi {
                    host: f.owner.identity(f.operation).unwrap().host_id,
                    stopping: f.stopping,
                    refreshes: Cell::new(0),
                    revokes: Cell::new(0),
                    revoke_ok: false,
                };
                let api = FixedApi::new(vec![Reply::Error(lomi_host_http::Error::DataRemote(
                    failure,
                ))]);
                run_until_fence(f, auth, &transport, &api, false);
                let fence = f.authorization();
                assert!(fence.locked);
                assert_eq!(fence.generation, 1);
                assert!(!fence.pending_cloud_revoke);
                assert!(f.gate.load(Ordering::Acquire));
                assert_eq!(*api.requests.borrow(), ["GET"]);
                assert_eq!(transport.revokes.get(), 0);
                assert_eq!(transport.refreshes.get(), 0);
            });
        }
    }
    #[test]
    fn malformed_get_binding_never_updates_provider_epoch_or_installs_runtime() {
        for malformed in 0..4 {
            with_fixture(|f, auth| {
                let mut response = f.snapshot(Some(f.binding()), 0);
                match malformed {
                    0 => response.runtime.as_mut().unwrap().host_access_epoch = DecimalU64(14),
                    1 => response.runtime.as_mut().unwrap().runtime_generation = DecimalU64(19),
                    2 => response.host_id = HostId::from_bytes([99; 16]).unwrap(),
                    _ => response.freshness_ms = DecimalU64(5_001),
                }
                let api = FixedApi::new(vec![Reply::Get(response)]);
                let mut w = Worker::default();
                assert!(f.step(&mut w, auth, &api).is_err());
                assert!(matches!(w.action, Action::Blocked));
                assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(12));
                assert!(f.records().binding.is_none());
                successful(f.step(&mut w, auth, &api));
                assert_eq!(*api.requests.borrow(), ["GET"]);
            });
        }
    }
    #[test]
    fn heartbeat_freshness_starts_before_network_and_expired_lease_forces_get() {
        with_fixture(|f, auth| {
            let b = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                Reply::Heartbeat(HeartbeatResult {
                    runtime: b,
                    lease_ms: DecimalU64(30_000),
                    freshness_ms: DecimalU64(1),
                }),
            ]);
            api.hook_on("HB", || thread::sleep(Duration::from_millis(10)));
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            assert!(matches!(f.step(&mut w, auth, &api), Err(StepError::Stale)));
            assert!(api.publications.borrow().is_empty());
            assert!(w.heartbeat_observation.is_none());
        });
        with_fixture(|f, auth| {
            let mut w = online(f, auth);
            w.lease_until = Some(Instant::now());
            let api = FixedApi::new(vec![]);
            assert!(matches!(
                f.step(&mut w, auth, &api),
                Ok(StepOutcome::Deferred)
            ));
            assert!(matches!(w.action, Action::Get));
            assert!(api.requests.borrow().is_empty());
        });
    }
    #[test]
    fn slow_heartbeats_and_continuous_newer_outbox_each_receive_a_bounded_turn() {
        with_fixture(|f, auth| {
            let workspace = f.project();
            let mut w = online(f, auth);
            let b = f.binding();
            for sequence in 2..=4 {
                f.owner
                    .begin_unshare(f.operation, workspace)
                    .unwrap()
                    .try_commit()
                    .unwrap();
                let api = FixedApi::new(vec![
                    heartbeat(&b),
                    ack(&b, sequence),
                    Reply::Get(f.snapshot(Some(b.clone()), sequence)),
                ]);
                let owner = f.owner;
                let operation = f.operation;
                api.hook_on("PUT", move || {
                    owner.probe_both_locks_for_test(operation).unwrap();
                    owner
                        .begin_share(
                            operation,
                            workspace,
                            owner.workspace(operation, workspace).unwrap().fence,
                        )
                        .unwrap()
                        .try_commit()
                        .unwrap();
                });
                assert!(matches!(
                    f.step(&mut w, auth, &api),
                    Ok(StepOutcome::Network)
                ));
                assert_eq!(*api.requests.borrow(), ["HB"]);
                // New consent during PUT invalidates the original continuation.
                // It cannot acknowledge using that superseded authority revision.
                assert!(matches!(f.step(&mut w, auth, &api), Err(StepError::Stale)));
                assert_eq!(*api.requests.borrow(), ["HB", "PUT"]);
                let retained = f.records();
                assert_eq!(
                    retained.pending.as_ref().unwrap().params.publication_seq,
                    DecimalU64(sequence)
                );
                assert!(matches!(w.action, Action::Get));
                assert!(w.heartbeat_observation.is_none());
                // One bounded GET reconciles the sent intent; newer outbox work
                // remains queued for the next heartbeat/publication pair.
                assert!(matches!(
                    f.step(&mut w, auth, &api),
                    Ok(StepOutcome::Network)
                ));
                assert_eq!(*api.requests.borrow(), ["HB", "PUT", "GET"]);
                let reconciled = f.records();
                assert!(reconciled.pending.is_none());
                assert_eq!(
                    reconciled.binding.unwrap().acknowledged_publication_seq,
                    DecimalU64(sequence)
                );
                assert!(reconciled.acknowledged.is_some());
                assert!(!reconciled.outbox.is_empty());
            }
        });
    }
    #[test]
    fn logout_after_successful_or_lost_claim_reconciles_epoch_then_finishes_revoke() {
        for lost in [false, true] {
            with_fixture(|f, auth| {
                let b = f.binding();
                let api = FixedApi::new(vec![
                    Reply::Get(f.snapshot(None, 0)),
                    if lost {
                        Reply::Error(lomi_host_http::Error::Timeout)
                    } else {
                        claim(&b)
                    },
                    Reply::Get(f.snapshot(Some(b), 0)),
                ]);
                let mut w = Worker::default();
                successful(f.step(&mut w, auth, &api));
                assert_eq!(f.step(&mut w, auth, &api).is_err(), lost);
                assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(12));
                let generation = f.fence().generation;
                let before = f.records().outbox;
                assert!(f.logout(&mut w, auth, &api, generation).unwrap());
                assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(13));
                assert_eq!(f.records().outbox, before);
                assert!(!f.logout(&mut w, auth, &api, generation).unwrap());
                assert!(w.lease_until.is_none());
                let transport = IdentityApi {
                    host: f.owner.identity(f.operation).unwrap().host_id,
                    stopping: f.stopping,
                    refreshes: Cell::new(0),
                    revokes: Cell::new(0),
                    revoke_ok: true,
                };
                f.enter();
                successful(revoke_step(
                    auth,
                    &transport,
                    &f.config,
                    f.runtime(),
                    generation,
                ));
                successful(revoke_step(
                    auth,
                    &transport,
                    &f.config,
                    f.runtime(),
                    generation,
                ));
                f.io = None;
                assert_eq!(auth.status(), Status::Revoked);
                assert!(!f.authorization().pending_cloud_revoke);
                assert_eq!(transport.revokes.get(), 1);
                assert_eq!(*api.requests.borrow(), ["GET", "CLAIM", "GET"]);
            });
        }
    }
    #[test]
    fn pending_logout_epoch_response_is_exact_generation_and_volatile_gate_fenced() {
        for race in 0..4 {
            with_fixture(|f, auth| {
                let response = f.snapshot(Some(f.binding()), 0);
                let generation = f.fence().generation;
                let api = FixedApi::new(vec![Reply::Get(response)]);
                let owner = f.owner;
                let operation = f.operation;
                let gate = f.gate;
                let paused = f.paused;
                let stopping = f.stopping;
                api.hook(move || match race {
                    0 => {
                        owner
                            .begin_local_logout(operation)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                    1 => gate.store(false, Ordering::Release),
                    2 => paused.store(true, Ordering::Release),
                    _ => stopping.store(true, Ordering::Release),
                });
                let mut w = Worker::default();
                assert!(matches!(
                    f.logout(&mut w, auth, &api, generation),
                    Err(StepError::Stale)
                ));
                assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(12));
                assert_eq!(w.logout_epoch_attempt, None);
                stopping.store(false, Ordering::Release);
                assert!(f.authorization().pending_cloud_revoke);
            });
        }
    }
    fn rotate(auth: &mut HostAuth<'_, dyn SecretStorage + '_>, host: HostId) {
        auth.prepare_rotation(1005).unwrap();
        let request = auth.rotation_request(1005).unwrap();
        auth.accept_rotation(
            lomi_remote_protocol::HostAuthorizationResult {
                account_id: lomi_remote_protocol::AccountId::from_bytes([4; 16]).unwrap(),
                host_id: host,
                host_authorization_id: lomi_remote_protocol::HostAuthorizationId::from_bytes(
                    [8; 16],
                )
                .unwrap(),
                access: "rotated_access".to_owned().try_into().unwrap(),
                refresh: "rotated_refresh".to_owned().try_into().unwrap(),
                rotation_id: request.rotation_id,
                expires_in_seconds: DecimalU64(300),
            },
            1005,
        )
        .unwrap();
    }
    #[test]
    fn pending_logout_retries_epoch_get_after_access_rotation_and_avoids_disabled_network() {
        with_fixture(|f, auth| {
            let response = f.snapshot(Some(f.binding()), 0);
            let host = response.host_id;
            let generation = f.fence().generation;
            let api = FixedApi::new(vec![
                Reply::Error(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::AuthRequired,
                )),
                Reply::Get(response),
            ]);
            let mut w = Worker::default();
            assert!(f.logout(&mut w, auth, &api, generation).is_err());
            assert!(!f.logout(&mut w, auth, &api, generation).unwrap());
            rotate(auth, host);
            f.paused.store(true, Ordering::Release);
            assert!(f.logout(&mut w, auth, &api, generation).is_err());
            f.paused.store(false, Ordering::Release);
            f.stopping.store(true, Ordering::Release);
            assert!(f.logout(&mut w, auth, &api, generation).is_err());
            f.stopping.store(false, Ordering::Release);
            assert_eq!(api.requests.borrow().len(), 1);
            assert!(f.logout(&mut w, auth, &api, generation).unwrap());
            assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(13));
            assert_eq!(*api.requests.borrow(), ["GET", "GET"]);
        });
    }
    #[test]
    fn claim_logout_restart_durably_recovers_epoch_and_actual_worker_completes_revoke() {
        fixture(Seed::ReopenedLogout, |f, auth| {
            assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(12));
            let generation = f.authorization().generation;
            assert!(f.authorization().pending_cloud_revoke);
            let response = f.snapshot(Some(f.binding()), 0);
            let api = FixedApi::new(vec![Reply::Get(response)]);
            let transport = IdentityApi {
                host: f.owner.identity(f.operation).unwrap().host_id,
                stopping: f.stopping,
                refreshes: Cell::new(0),
                revokes: Cell::new(0),
                revoke_ok: true,
            };
            run_until_fence(f, auth, &transport, &api, false);
            assert_eq!(auth.status(), Status::Revoked);
            assert_eq!(transport.revokes.get(), 1);
            assert_eq!(
                auth.revocation_acknowledgement().unwrap().host_access_epoch,
                DecimalU64(14)
            );
            assert_eq!(f.authorization().generation, generation);
            assert_eq!(*api.requests.borrow(), ["GET"]);
        });
    }
    #[test]
    fn pending_logout_remote_api_outage_still_permits_identity_revoke() {
        with_fixture(|f, auth| {
            f.fence();
            let api = FixedApi::new(vec![Reply::Error(lomi_host_http::Error::Timeout)]);
            let transport = IdentityApi {
                host: f.owner.identity(f.operation).unwrap().host_id,
                stopping: f.stopping,
                refreshes: Cell::new(0),
                revokes: Cell::new(0),
                revoke_ok: true,
            };
            run_until_fence(f, auth, &transport, &api, false);
            assert_eq!(auth.status(), Status::Revoked);
            assert_eq!(transport.revokes.get(), 1);
            assert_eq!(*api.requests.borrow(), ["GET"]);
            assert!(f.gate.load(Ordering::Acquire));
        });
    }
    #[test]
    fn pending_logout_epoch_get_never_acknowledges_intent_or_changes_outbox() {
        fixture(Seed::Pending, |f, auth| {
            let response = f.snapshot(Some(f.binding()), 1);
            let pending = f.records().pending;
            let generation = f.fence().generation;
            // Logout itself supersedes enabled outbox rows. The recovery GET
            // must preserve the already-fenced intent and outbox exactly.
            let before = f.records();
            assert_eq!(before.pending, pending);
            assert!(before.pending.is_some());
            assert!(!before.outbox.is_empty());
            let mut w = Worker::default();
            let api = FixedApi::new(vec![Reply::Get(response)]);
            assert!(f.logout(&mut w, auth, &api, generation).unwrap());
            assert_eq!(f.records().pending, before.pending);
            assert_eq!(f.records().outbox, before.outbox);
            assert!(w.lease_until.is_none() && w.fresh_until.is_none());
            assert!(f.gate.load(Ordering::Acquire));
        });
    }
    #[test]
    fn pending_logout_without_pin_or_with_expired_access_creates_no_data_agent() {
        for expired in [false, true] {
            fixture(
                if expired { Seed::Normal } else { Seed::NoPin },
                |f, auth| {
                    let generation = f.fence().generation;
                    f.enter();
                    let mut runtime = f.runtime();
                    if expired {
                        runtime.base = 1304;
                    }
                    let api = FixedApi::new(vec![]);
                    let mut w = Worker::default();
                    assert!(
                        !w.logout_epoch_step(auth, &f.config, runtime, generation, Some(&api))
                            .unwrap()
                    );
                    assert!(w.transport.is_none());
                    assert!(api.requests.borrow().is_empty());
                    assert!(f.authorization().pending_cloud_revoke);
                },
            );
        }
    }
    #[test]
    fn explicit_outcomes_keep_get_claim_heartbeat_and_publication_turns_exclusive() {
        fixture(Seed::NoPin, |f, auth| {
            let mut w = Worker::default();
            let none = FixedApi::new(vec![]);
            assert!(matches!(
                f.step(&mut w, auth, &none),
                Ok(StepOutcome::Deferred)
            ));
            assert!(none.requests.borrow().is_empty());
            f.pin(auth);
            let b = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(None, 0)),
                claim(&b),
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                heartbeat(&b),
                ack(&b, 1),
            ]);
            // Every HTTP effect retains the same original unit and consumes
            // exactly one worker turn, including the HB-to-PUT continuation.
            for count in 1..=5 {
                assert!(matches!(
                    f.step(&mut w, auth, &api),
                    Ok(StepOutcome::Network)
                ));
                assert_eq!(api.requests.borrow().len(), count);
            }
            let _ = eligibility(f, auth, &mut w);
            assert!(!w.has_retained_operation());
            assert_eq!(*api.requests.borrow(), ["GET", "CLAIM", "GET", "HB", "PUT"]);
        });
    }
    #[test]
    fn retained_configured_heartbeat_keeps_original_anchors_and_one_http_per_step() {
        with_fixture(|f, auth| {
            let b = f.binding();
            let api = FixedApi::new(vec![
                Reply::Get(f.snapshot(Some(b.clone()), 0)),
                heartbeat(&b),
                ack(&b, 1),
            ]);
            let mut w = Worker::default();
            successful(f.step(&mut w, auth, &api));
            successful(f.step(&mut w, auth, &api));
            assert_eq!(*api.requests.borrow(), ["GET", "HB"]);
            assert!(w.pending_publication.is_some());
            assert!(w.has_retained_operation());
            let accepted = w.heartbeat_observation.clone().unwrap();
            let anchors = (w.lease_until, w.fresh_until, w.heartbeat_at);
            successful(f.step(&mut w, auth, &api));
            assert_eq!(*api.requests.borrow(), ["GET", "HB", "PUT"]);
            assert!(w.pending_publication.is_none());
            assert_eq!(w.heartbeat_observation.as_ref(), Some(&accepted));
            assert_eq!((w.lease_until, w.fresh_until, w.heartbeat_at), anchors);
        });
    }
    #[test]
    fn retained_configured_heartbeat_rejects_cancel_revoke_pause_and_changed_anchors_before_put() {
        for change in 0..6 {
            with_fixture(|f, auth| {
                let b = f.binding();
                let api = FixedApi::new(vec![
                    Reply::Get(f.snapshot(Some(b.clone()), 0)),
                    heartbeat(&b),
                ]);
                let mut w = Worker::default();
                successful(f.step(&mut w, auth, &api));
                successful(f.step(&mut w, auth, &api));
                assert!(w.pending_publication.is_some());
                match change {
                    0 => f.stopping.store(true, Ordering::Release),
                    1 => {
                        f.owner
                            .begin_local_logout(f.operation)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                    2 => f.paused.store(true, Ordering::Release),
                    3 => w.fresh_until = Instant::now().checked_add(Duration::from_secs(5)),
                    4 => {
                        f.owner
                            .begin_authority_rejection(f.operation, 0)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                    _ => auth.prepare_rotation(1005).unwrap(),
                }
                let result = f.step(&mut w, auth, &api);
                assert!(!matches!(
                    result,
                    Ok(StepOutcome::Network | StepOutcome::PeerEligible(_))
                ));
                assert_eq!(*api.requests.borrow(), ["GET", "HB"]);
                assert!(api.publications.borrow().is_empty());
                assert!(f.records().acknowledged.is_none());
            });
        }
    }
    #[test]
    fn retained_configured_heartbeat_cannot_move_to_new_operation_worker_or_io_lease() {
        for replacement in 0..3 {
            with_fixture(|f, auth| {
                let b = f.binding();
                let api = FixedApi::new(vec![
                    Reply::Get(f.snapshot(Some(b.clone()), 0)),
                    heartbeat(&b),
                ]);
                let mut w = Worker::default();
                successful(f.step(&mut w, auth, &api));
                successful(f.step(&mut w, auth, &api));
                let receipt = w.pending_publication.take().unwrap();
                let cancel = AtomicBool::new(false);
                let successor =
                    OwnerOperation::new(Instant::now() + Duration::from_secs(60), &cancel);
                // Matching observational data cannot replace original worker origin.
                let mut replacement_worker = Worker {
                    action: Action::Online,
                    scope: w.scope.clone(),
                    heartbeat_observation: w.heartbeat_observation.clone(),
                    lease_until: w.lease_until,
                    fresh_until: w.fresh_until,
                    ..Worker::default()
                };
                if replacement == 2 {
                    f.io = None;
                    f.enter();
                }
                let driver = if replacement == 1 {
                    replacement_worker.normal_publication_driver().unwrap()
                } else {
                    w.normal_publication_driver().unwrap()
                };
                let operation = if replacement == 0 {
                    &successor
                } else {
                    f.operation
                };
                let result = ConfiguredNormalPublication::from_retained_heartbeat(
                    auth,
                    driver,
                    operation,
                    f.io.as_ref().unwrap(),
                    f.gate,
                    f.paused,
                    f.stopping,
                    receipt,
                );
                assert!(result.is_err(), "replacement {replacement}");
                assert_eq!(*api.requests.borrow(), ["GET", "HB"]);
                assert!(api.publications.borrow().is_empty());
            });
        }
    }
    #[test]
    fn retained_configured_heartbeat_busy_before_put_keeps_receipt_and_sends_once() {
        for boundary in [3, 4] {
            with_fixture(|f, auth| {
                let b = f.binding();
                let api = FixedApi::new(vec![
                    Reply::Get(f.snapshot(Some(b.clone()), 0)),
                    heartbeat(&b),
                    ack(&b, 1),
                ]);
                let mut w = Worker::default();
                successful(f.step(&mut w, auth, &api));
                successful(f.step(&mut w, auth, &api));
                let accepted = w.heartbeat_observation.clone().unwrap();
                super::super::super::shared_owner::set_publication_final_send_boundary_for_test(
                    boundary,
                );
                successful(f.step(&mut w, auth, &api));
                assert_eq!(*api.requests.borrow(), ["GET", "HB", "PUT"]);
                assert_eq!(w.heartbeat_observation.as_ref(), Some(&accepted));
                assert_eq!(api.publications.borrow().len(), 1);
                assert!(f.records().pending.is_none());
                assert!(f.records().acknowledged.is_some());
            });
        }
    }
    #[test]
    fn peer_eligibility_contains_exact_current_identity_ack_and_original_heartbeat_anchor() {
        with_fixture(|f, auth| {
            let workspace = f.project();
            let before = Instant::now();
            let mut w = online(f, auth);
            let retained = w.heartbeat_observation.clone().unwrap();
            assert!(retained.request_started >= before);
            let first = eligibility(f, auth, &mut w);
            assert_eq!(
                first.identity,
                auth.public_host_identity(1005 + f.anchor.elapsed().as_secs())
                    .unwrap()
            );
            assert_eq!(first.heartbeat, retained);
            assert_eq!(first.binding.scope, retained.scope);
            assert_eq!(first.binding.server_runtime, retained.runtime);
            assert_eq!(first.publication.state, first.binding);
            assert_eq!(
                first.publication.workspaces.as_slice()[0].workspace_id,
                workspace
            );
            assert_eq!(
                w.lease_until,
                retained
                    .request_started
                    .checked_add(Duration::from_millis(retained.lease_ms))
            );
            assert_eq!(
                w.fresh_until,
                retained
                    .request_started
                    .checked_add(Duration::from_millis(retained.freshness_ms))
            );
            assert_eq!(eligibility(f, auth, &mut w), first);
        });
    }
    #[test]
    fn pending_intent_outbox_and_missing_ack_each_take_publication_turn_without_handoff() {
        // Pending intent and missing acknowledged membership are seeded before
        // owner startup; the outbox case is changed through typed local consent.
        for seed in [Seed::Pending, Seed::LegacySequence] {
            fixture(seed, |f, auth| {
                let sequence = if matches!(seed, Seed::LegacySequence) {
                    7
                } else {
                    0
                };
                let b = f.binding();
                let api = FixedApi::new(vec![
                    Reply::Get(f.snapshot(Some(b.clone()), sequence)),
                    heartbeat(&b),
                    ack(&b, sequence + 1),
                ]);
                let mut w = Worker::default();
                successful(f.step(&mut w, auth, &api));
                assert!(matches!(
                    f.step(&mut w, auth, &api),
                    Ok(StepOutcome::Network)
                ));
                assert_eq!(*api.requests.borrow(), ["GET", "HB"]);
                assert!(matches!(
                    f.step(&mut w, auth, &api),
                    Ok(StepOutcome::Network)
                ));
                assert_eq!(*api.requests.borrow(), ["GET", "HB", "PUT"]);
                assert!(f.records().acknowledged.is_some());
            });
        }
        with_fixture(|f, auth| {
            let workspace = f.project();
            let mut w = online(f, auth);
            f.owner
                .begin_unshare(f.operation, workspace)
                .unwrap()
                .try_commit()
                .unwrap();
            let b = f.binding();
            let api = FixedApi::new(vec![heartbeat(&b), ack(&b, 2)]);
            assert!(matches!(
                f.step(&mut w, auth, &api),
                Ok(StepOutcome::Network)
            ));
            assert_eq!(*api.requests.borrow(), ["HB"]);
            assert!(matches!(
                f.step(&mut w, auth, &api),
                Ok(StepOutcome::Network)
            ));
            assert_eq!(*api.requests.borrow(), ["HB", "PUT"]);
            assert!(f.records().outbox.is_empty());
        });
    }
    #[test]
    fn expired_or_mismatched_heartbeat_evidence_never_yields_peer_eligibility() {
        for change in 0..6 {
            with_fixture(|f, auth| {
                let mut w = online(f, auth);
                w.heartbeat_at = Instant::now().checked_add(Duration::from_secs(60));
                let mut replies = vec![];
                match change {
                    0 => w.lease_until = Some(Instant::now()),
                    1 => {
                        w.fresh_until = Some(Instant::now());
                        replies.push(heartbeat(&f.binding()));
                    }
                    2 => {
                        w.heartbeat_observation
                            .as_mut()
                            .unwrap()
                            .scope
                            .remote_api_origin = "https://different.example".into()
                    }
                    3 => {
                        w.heartbeat_observation
                            .as_mut()
                            .unwrap()
                            .runtime
                            .runtime_generation
                            .0 += 1
                    }
                    4 => {
                        let previous = f.records().binding.unwrap();
                        f.owner
                            .begin_invalidate_cloud_runtime(
                                f.operation,
                                previous.scope.clone(),
                                previous,
                                None,
                            )
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                    _ => {
                        w.scope.as_mut().unwrap().remote_api_origin =
                            "https://predecessor.example".into();
                        replies.push(Reply::Get(f.snapshot(Some(f.binding()), 1)));
                    }
                }
                let api = FixedApi::new(replies);
                let result = f.step(&mut w, auth, &api);
                assert!(
                    !matches!(result, Ok(StepOutcome::PeerEligible(_))),
                    "mutation {change}"
                );
                if change != 1 {
                    assert!(w.heartbeat_observation.is_none(), "mutation {change}");
                }
                assert!(api.requests.borrow().len() <= 1);
            });
        }
    }
    #[test]
    fn auth_refresh_pause_logout_revoke_and_stop_gates_drop_idle_handoff_without_http() {
        for change in 0..9 {
            with_fixture(|f, auth| {
                let mut w = online(f, auth);
                w.heartbeat_at = Instant::now().checked_add(Duration::from_secs(60));
                let response = f.snapshot(Some(f.binding()), 1);
                f.enter();
                match change {
                    0 => f.gate.store(true, Ordering::Release),
                    1 => f.paused.store(true, Ordering::Release),
                    2 => f.stopping.store(true, Ordering::Release),
                    3 => {
                        f.owner
                            .begin_local_logout(f.operation)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                    4 => {
                        f.owner
                            .begin_authority_rejection(f.operation, 0)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                    5 => {
                        f.owner
                            .begin_seal_authorization(f.operation)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                    6 => auth.prepare_rotation(1005).unwrap(),
                    7 => (),
                    _ => {
                        let mut response = response;
                        response.host_access_epoch.0 += 1;
                        response.runtime.as_mut().unwrap().host_access_epoch =
                            response.host_access_epoch;
                        auth.accept_runtime_observation(DecimalU64(13), response, 1005)
                            .unwrap();
                    }
                }
                let mut runtime = f.runtime();
                if change == 7 {
                    runtime.base = auth.credential_deadlines().unwrap().refresh_at;
                }
                let api = FixedApi::new(vec![]);
                let result = w.step_using(auth, &api, &f.config, runtime, 0);
                if change == 8 {
                    // A provider epoch newer than the retained runtime drops the
                    // observation as a local deferred turn, without peer handoff.
                    assert!(matches!(result, Ok(StepOutcome::Deferred)));
                    assert!(w.heartbeat_observation.is_none());
                    assert!(w.cached_eligibility().is_none());
                } else {
                    assert!(result.is_err(), "mutation {change}");
                }
                assert!(api.requests.borrow().is_empty());
            });
        }
    }
    fn provider_race(recovery: bool, fault: u8, actual_loop: bool) {
        with_fixture(|f, auth| {
            let response = f.snapshot(Some(f.binding()), 0);
            let generation = if recovery { f.fence().generation } else { 0 };
            f.fault.set(fault);
            f.probe_arm.set(true);
            let api = FixedApi::new(vec![Reply::Get(response)]);
            let mut w = Worker::default();
            if actual_loop {
                let transport = IdentityApi {
                    host: f.owner.identity(f.operation).unwrap().host_id,
                    stopping: f.stopping,
                    refreshes: Cell::new(0),
                    revokes: Cell::new(0),
                    revoke_ok: false,
                };
                f.enter();
                run_with_data(auth, &transport, &f.config, f.runtime(), Some(&api));
                let view = f.state.lock().unwrap();
                assert_eq!(view.status.storage, LocalAuthStorage::Unavailable);
                assert!(f.gate.load(Ordering::Acquire));
            } else {
                let result = if recovery {
                    f.logout(&mut w, auth, &api, generation).map(|_| ())
                } else {
                    f.step(&mut w, auth, &api).map(|_| ())
                };
                if fault == 0 {
                    assert!(result.is_ok());
                } else if fault == 1 {
                    assert!(matches!(result, Err(StepError::Stale)));
                } else {
                    match result {
                        Err(StepError::Auth(lomi_host_auth::Error::Storage(error))) => assert_eq!(
                            error,
                            if fault < 4 {
                                secrets::Error::CommitUncertain
                            } else {
                                secrets::Error::Unavailable
                            }
                        ),
                        _ => panic!("provider error must survive all post-IO fences"),
                    }
                }
                if fault != 0 {
                    assert!(w.heartbeat_observation.is_none());
                    assert!(w.lease_until.is_none());
                }
            }
            assert_eq!(
                f.probes.get(),
                1,
                "provider callback obtains both actual locks"
            );
            assert_eq!(*api.requests.borrow(), ["GET"]);
            // A successful replace is durable even if its local acceptance was
            // fenced. CommitUncertain must reach the real storage-error branch.
            if fault <= 1 {
                assert_eq!(auth.verified_host_access_epoch().unwrap(), DecimalU64(13));
            }
        });
    }
    #[test]
    fn epoch_provider_replace_releases_store_and_fences_stale_get_publication() {
        for fault in [0, 1] {
            provider_race(false, fault, false);
        }
    }
    #[test]
    fn logout_epoch_provider_replace_releases_store_and_rechecks_recovery_authority() {
        for fault in [0, 1] {
            provider_race(true, fault, false);
        }
    }
    #[test]
    fn provider_storage_errors_survive_configuration_and_generation_races() {
        for recovery in [false, true] {
            for fault in [2, 3, 4, 5] {
                provider_race(recovery, fault, false);
            }
        }
    }
    #[test]
    fn raced_provider_storage_errors_reach_actual_owner_failure_handling() {
        for recovery in [false, true] {
            for fault in [2, 3, 4, 5] {
                provider_race(recovery, fault, true);
            }
        }
    }
    #[test]
    fn injected_step_clears_configured_publication_origin_even_on_http_error() {
        with_fixture(|f, auth| {
            let mut w = online(f, auth);
            assert!(w.heartbeat_observation.is_some());
            // A successor starts at GET and must drop every previous origin.
            w.finish_operation();
            let api = FixedApi::new(vec![Reply::Error(lomi_host_http::Error::Network)]);
            assert!(f.step(&mut w, auth, &api).is_err());
            assert!(w.normal_publication_origin.is_none());
            assert!(w.heartbeat_observation.is_none());
            assert_eq!(*api.requests.borrow(), ["GET"]);
        });
    }
    #[test]
    fn retained_claim_uses_settled_get_revision_and_rejects_interposed_writer() {
        for interposed in [false, true] {
            with_fixture(|f, auth| {
                let get = FixedApi::new(vec![Reply::Get(f.snapshot(None, 0))]);
                let mut worker = Worker::default();
                successful(f.step(&mut worker, auth, &get));
                assert!(worker.claim.is_some());
                if interposed {
                    // An unrelated committed writer invalidates the exact GET
                    // continuation even though its original Operation is live.
                    f.project();
                }
                let api = FixedApi::new(if interposed {
                    vec![]
                } else {
                    vec![claim(&f.binding())]
                });
                let result = f.step(&mut worker, auth, &api);
                if interposed {
                    assert!(result.is_err());
                    assert!(api.requests.borrow().is_empty());
                } else {
                    assert!(matches!(result, Ok(StepOutcome::Network)));
                    assert_eq!(*api.requests.borrow(), ["CLAIM"]);
                    assert!(worker.awaiting_claim_get);
                }
                assert_eq!(*get.requests.borrow(), ["GET"]);
                assert!(api.publications.borrow().is_empty());
            });
        }
    }
    #[test]
    fn retained_claim_requires_original_live_operation_and_never_sends_on_replacement() {
        for expired in [false, true] {
            with_fixture(|f, auth| {
                let get = FixedApi::new(vec![Reply::Get(f.snapshot(None, 0))]);
                let mut worker = Worker::default();
                successful(f.step(&mut worker, auth, &get));
                assert!(worker.has_retained_operation());
                assert!(worker.claim.is_some());
                let cancelled = AtomicBool::new(false);
                let no_http = FixedApi::new(vec![]);
                if expired {
                    f.operation.expire_for_test();
                    assert!(f.step(&mut worker, auth, &no_http).is_err());
                    assert!(
                        worker.claim.is_some(),
                        "deadline cannot consume or renew retained capability"
                    );
                }
                let replacement =
                    OwnerOperation::new(Instant::now() + Duration::from_secs(30), &cancelled);
                let mut runtime = f.runtime();
                runtime.operation = &replacement;
                assert!(
                    worker
                        .step_using(auth, &no_http, &f.config, runtime, 0)
                        .is_err()
                );
                assert!(no_http.requests.borrow().is_empty());
                assert_eq!(*get.requests.borrow(), ["GET"]);
                worker.finish_operation();
                f.io = None;
                assert!(!worker.has_retained_operation());
                assert!(worker.claim.is_none());
            });
        }
    }
}

#[cfg(test)]
type HeartbeatTestScript = (
    Result<HeartbeatResult, lomi_host_http::Error>,
    std::rc::Rc<std::cell::Cell<usize>>,
    Duration,
);
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
    #[cfg(test)]
    script: Option<HeartbeatTestScript>,
    #[cfg(test)]
    api: Option<&'w dyn DataApi>,
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
            #[cfg(test)]
            script: None,
            #[cfg(test)]
            api: None,
            original_lease_until,
            lease_now_test: None,
        })
    }
}
#[cfg(any(unix, windows))]
impl<'w> NormalPublicationDriver<'w> {
    #[cfg(test)]
    pub(in crate::unix) fn set_original_heartbeat_lease_test(&mut self, lease: Option<Instant>) {
        self.worker.lease_until = lease;
        self.original_lease_until = lease;
    }
    #[cfg(test)]
    pub(in crate::unix) fn original_heartbeat_lease_test(&self) -> Option<Instant> {
        self.original_lease_until
    }
    #[cfg(test)]
    pub(in crate::unix) fn advance_heartbeat_lease_clock_test(&mut self, now: Instant) {
        self.lease_now_test = Some(now);
    }
    #[cfg(test)]
    pub(in crate::unix) fn change_current_heartbeat_lease_test(&mut self) {
        self.worker.lease_until = None;
    }
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
    #[cfg(test)]
    pub(in crate::unix) fn corrupt_heartbeat_provider_test(&mut self, fault: u8) {
        let prepared = self.prepared.as_mut().unwrap();
        match fault {
            0 => prepared.provider ^= 1,
            1 => prepared.binding.scope.host_id = HostId::from_bytes([91; 16]).unwrap(),
            2 => prepared.epoch.0 += 1,
            3 => prepared.deadlines.access_expires_at += 1,
            _ => prepared.access = "different-access".to_owned().try_into().unwrap(),
        }
    }
    #[cfg(test)]
    pub(in crate::unix) fn retained_heartbeat_test(
        &self,
    ) -> Option<(Option<Instant>, Option<HeartbeatResult>, usize)> {
        self.prepared.as_ref().map(|prepared| {
            (
                prepared.request_started,
                prepared.response.clone(),
                prepared.provider,
            )
        })
    }
    /// Synthetic response seam only: changes request data, never origin/Ready.
    #[cfg(test)]
    pub(in crate::unix) fn script_heartbeat_test(
        &mut self,
        binding: &CloudRuntimeState,
        reply: Result<lomi_remote_protocol::http::HeartbeatResult, lomi_host_http::Error>,
        sends: std::rc::Rc<std::cell::Cell<usize>>,
        elapsed: Duration,
    ) {
        self.worker.scope = Some(binding.scope.clone());
        self.set_original_heartbeat_lease_test(Instant::now().checked_add(Duration::from_secs(30)));
        self.script = Some((reply, sends, elapsed));
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
        #[cfg(test)]
        if let Some(api) = self.api {
            prepared.response = Some(
                api.heartbeat(
                    prepared.binding.scope.host_id,
                    &HeartbeatParams {
                        runtime: prepared.binding.server_runtime.clone(),
                    },
                    &prepared.access,
                )
                .map_err(NormalPublicationOriginError::Http)?,
            );
            return Ok(());
        }
        #[cfg(test)]
        if let Some((reply, sends, elapsed)) = self.script.take() {
            operation
                .check()
                .map_err(NormalPublicationOriginError::Stopped)?;
            sends.set(sends.get() + 1);
            prepared.request_started = Instant::now().checked_sub(elapsed);
            prepared.response = Some(reply.map_err(NormalPublicationOriginError::Http)?);
            return Ok(());
        }
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
    #[cfg(test)]
    pub(in crate::unix) fn binding(&self) -> &CloudRuntimeState {
        &self.binding
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
    #[cfg(test)]
    pub(in crate::unix) fn publication_anchors_test(&self) -> (Instant, u64, u64) {
        (
            self.heartbeat.request_started,
            self.heartbeat.freshness_ms,
            self.heartbeat.lease_ms,
        )
    }
    #[cfg(test)]
    pub(in crate::unix) fn advance_publication_clock_test(&mut self, now: Instant) {
        self.local_now_test = Some(now);
    }
    #[cfg(test)]
    pub(in crate::unix) fn invalidate_publication_anchor_test(&mut self, fault: u8) {
        match fault {
            0 => self.worker.lease_until = None,
            1 => self.worker.fresh_until = None,
            _ => {
                self.worker.fresh_until = self
                    .worker
                    .fresh_until
                    .and_then(|until| until.checked_add(Duration::from_millis(1)))
            }
        }
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

#[cfg(test)]
pub(in crate::unix) fn with_normal_publication_test_worker(
    run: impl FnOnce(NormalPublicationDriver<'_>),
) -> bool {
    let mut worker = Worker {
        action: Action::Online,
        ..Worker::default()
    };
    run(worker.normal_publication_driver().unwrap());
    matches!(worker.action, Action::Get)
}

#[cfg(test)]
impl<'w> NormalPublicationDriver<'w> {
    fn install_cloud_api_for_test(&mut self, api: &'w dyn DataApi) {
        self.api = Some(api);
    }
}
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
