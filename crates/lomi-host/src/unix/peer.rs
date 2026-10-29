//! Owner-account workspace pairing only. Public journal bytes are never authority.
//! Every peer observation retains its original TLS GET and heartbeat start. Peer
//! HTTP failures are resource-local; they never reach the global auth-error path.
use super::*;
use cloud::{HeartbeatObservation, PeerEligibility};
use lomi_host_auth::peer_policy::{
    ApprovedGrant, GrantNarrowing, LocalWorkspace, OwnerScope, PeerObservation, PolicyClock,
    PolicySnapshot, RemoteOrigin, SnapshotInput,
};
use lomi_host_http::{DataTransport, RemoteApiOrigin};
use lomi_host_store::{
    CloudPairingScope, CloudRuntimeScope, PairingDecisionIntent, PairingDecisionPreparation,
};
use lomi_remote_crypto::{
    ChannelContextV3, CurrentAuthorityV3, GrantV3, SignedBundle, SignedGrantV3,
    verify_consumer_window_identity,
};
use lomi_remote_protocol::{http::*, *};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(super) trait PeerApi {
    fn pending(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<PairingPendingResult, lomi_host_http::Error>;
    fn get(
        &self,
        pairing: PairingId,
        access: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error>;
    fn decide(
        &self,
        pairing: PairingId,
        params: &PairingDecisionParams,
        access: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error>;
}
impl PeerApi for lomi_host_http::BudgetDataTransport<'_> {
    fn pending(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<PairingPendingResult, lomi_host_http::Error> {
        self.pairing_pending(host, access)
    }
    fn get(
        &self,
        pairing: PairingId,
        access: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        self.pairing_get(pairing, access)
    }
    fn decide(
        &self,
        pairing: PairingId,
        params: &PairingDecisionParams,
        access: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        self.pairing_decision(pairing, params, access)
    }
}
pub(in super::super) struct Observation {
    pub(in super::super) continuation: Arc<owner_domain::PeerContinuation>,
    host: lomi_host_auth::PublicHostIdentity,
    heartbeat: HeartbeatObservation,
    started: Instant,
}
impl Observation {
    pub(super) fn new(
        eligibility: &PeerEligibility,
        started: Instant,
        continuation: Arc<owner_domain::PeerContinuation>,
    ) -> Self {
        Self {
            continuation,
            host: eligibility.identity.clone(),
            heartbeat: eligibility.heartbeat.clone(),
            started,
        }
    }
    pub(super) fn current_operation(&self, runtime: Runtime<'_>) -> bool {
        runtime
            .owner
            .peer_original_boundary(runtime.operation, &self.continuation)
            .is_ok()
    }
    pub(in super::super) fn current(&self, eligibility: &PeerEligibility) -> bool {
        let now = Instant::now();
        self.host == eligibility.identity
            && self.heartbeat.scope == eligibility.binding.scope
            && self.heartbeat.runtime == eligibility.binding.server_runtime
            && now < self.started + Duration::from_secs(5)
            && now
                < self.heartbeat.request_started
                    + Duration::from_millis(self.heartbeat.freshness_ms)
            && now < self.heartbeat.request_started + Duration::from_millis(self.heartbeat.lease_ms)
    }
}
/// Complete provider evidence captured before acquiring Store. This value is
/// bounded by the original credential deadlines; it cannot establish Domain Ready.
/// HostAuth remains exclusively borrowed by the worker during the transaction.
pub(in super::super) struct ProviderCapture {
    identity: lomi_host_auth::PublicHostIdentity,
    epoch: DecimalU64,
    deadlines: lomi_host_auth::CredentialDeadlines,
}
impl ProviderCapture {
    pub(super) fn read(
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
    ) -> ResultPeer<Self> {
        let now = owner_turn(runtime, || {
            runtime
                .owner
                .peer_time(runtime.operation, eligibility, runtime.base, runtime.anchor)
        })?;
        if auth.status() != Status::Ready {
            return Err(StepError::Stale.into());
        }
        let captured = Self {
            identity: managed(auth.public_host_identity(now))?,
            epoch: managed(auth.verified_host_access_epoch())?,
            deadlines: managed(auth.credential_deadlines())?,
        };
        captured.validate(now, eligibility)?;
        Ok(captured)
    }
    pub(in super::super) fn captured_deadlines(&self) -> lomi_host_auth::CredentialDeadlines {
        self.deadlines
    }
    pub(in super::super) fn valid_for_owner(
        &self,
        now: u64,
        eligibility: &PeerEligibility,
    ) -> bool {
        self.validate(now, eligibility).is_ok()
    }
    pub(super) fn validate(&self, now: u64, eligibility: &PeerEligibility) -> ResultPeer<()> {
        if now >= self.deadlines.access_expires_at
            || now >= self.deadlines.refresh_at
            || self.identity != eligibility.identity
            || self.epoch != eligibility.binding.server_runtime.host_access_epoch
        {
            return Err(StepError::Stale.into());
        }
        Ok(())
    }
}
pub(super) struct Work {
    pub(super) pairing: PairingId,
    pub(super) proposal: PairingProposal,
    pub(super) observation: std::sync::Arc<Observation>,
    pub(super) intent: Option<PairingDecisionIntent>,
}

#[derive(Default)]
pub(super) struct Worker {
    transport: Option<DataTransport>,
    scope: Option<CloudRuntimeScope>,
    cache: VecDeque<Work>,
    active: Option<Work>,
    poll_at: Option<Instant>,
    failures: u32,
    parked: BTreeMap<String, Instant>,
    cursor: Option<String>,
    clock: Option<PolicyClock>,
    capacity_blocked: bool,
    cleanup_cursor: usize,
    retire_cursor: usize,
    turns_since_poll: u32,
    proposal_cursor: Option<PairingId>,
    prefer_recovery: bool,
}
pub(super) enum PeerError {
    Invalid,
    Fatal(StepError),
}
impl From<StepError> for PeerError {
    fn from(value: StepError) -> Self {
        Self::Fatal(value)
    }
}
pub(super) type ResultPeer<T> = Result<T, PeerError>;
pub(super) fn crypt<T>(value: lomi_remote_crypto::Result<T>) -> ResultPeer<T> {
    value.map_err(|_| PeerError::Invalid)
}
pub(super) fn policy<T>(
    value: Result<T, lomi_host_auth::peer_policy::PolicyError>,
) -> ResultPeer<T> {
    value.map_err(|_| PeerError::Invalid)
}

macro_rules! policy_instant {
    ($stage:literal, $wall:expr, $runtime:expr, $heartbeat:expr) => {
        Instant::now()
    };
}
pub(super) fn managed<T>(value: Result<T, lomi_host_auth::Error>) -> ResultPeer<T> {
    value.map_err(|error| match error {
        lomi_host_auth::Error::Storage(_) | lomi_host_auth::Error::Sealed => {
            PeerError::Fatal(StepError::Auth(error))
        }
        _ => PeerError::Invalid,
    })
}
pub(super) fn durable<T>(value: Result<T, StoreError>) -> ResultPeer<T> {
    value.map_err(|error| match error {
        StoreError::Fenced
        | StoreError::RevisionConflict
        | StoreError::IdempotencyConflict
        | StoreError::ResourceExhausted
        | StoreError::NotFound
        | StoreError::Invalid => PeerError::Invalid,
        _ => PeerError::Fatal(StepError::Auth(lomi_host_auth::Error::Sealed)),
    })
}
pub(super) fn check_peer_runtime(runtime: Runtime<'_>) -> Result<(), StepError> {
    runtime.check()?;
    if runtime.gate.load(Ordering::Acquire) {
        runtime.aborted.set(true);
        return Err(StepError::Stale);
    }
    Ok(())
}
pub(super) fn owner_error(error: shared_owner::Error) -> PeerError {
    match error {
        shared_owner::Error::Store(error) => durable::<()>(Err(error)).err().unwrap(),
        shared_owner::Error::UncertainStore(_) => {
            StepError::Auth(lomi_host_auth::Error::Sealed).into()
        }
        shared_owner::Error::Domain(_) => StepError::Stale.into(),
    }
}
/// Retry only the retained owner turn. The closure never receives Store, guards,
/// provider or transport; all retries use the original operation and values.
pub(super) fn owner_turn<T>(
    runtime: Runtime<'_>,
    mut step: impl FnMut() -> Result<T, shared_owner::Error>,
) -> ResultPeer<T> {
    loop {
        check_peer_runtime(runtime)?;
        match step() {
            Ok(value) => return Ok(value),
            Err(shared_owner::Error::Domain(owner_domain::Error::Busy))
            | Err(shared_owner::Error::Store(StoreError::Busy)) => runtime.busy()?,
            Err(shared_owner::Error::Store(error)) => return durable(Err(error)),
            Err(shared_owner::Error::Domain(_)) => return Err(StepError::Stale.into()),
            Err(shared_owner::Error::UncertainStore(_)) => {
                return Err(StepError::Auth(lomi_host_auth::Error::Sealed).into());
            }
        }
    }
}
// Only the bounded hex carrier is decoded here; canonical CBOR and every
// signature are decoded/verified by the existing crypto APIs.
pub(super) fn hex_bytes(value: &str) -> ResultPeer<Vec<u8>> {
    if value.len() > 16384 || !value.len().is_multiple_of(2) {
        return Err(PeerError::Invalid);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| PeerError::Invalid)?;
            u8::from_str_radix(text, 16).map_err(|_| PeerError::Invalid)
        })
        .collect()
}
pub(super) fn pin(value: &IdentityFingerprintHex) -> ResultPeer<[u8; 32]> {
    hex_bytes(value.expose_wire())?
        .try_into()
        .map_err(|_| PeerError::Invalid)
}
impl Worker {
    pub(super) fn discard_retained_operation(&mut self) {
        self.active = None;
        self.cache.clear();
    }
    pub(super) fn has_retained_operation(&self) -> bool {
        self.active.is_some() || !self.cache.is_empty()
    }

    pub(super) fn step(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        injected: Option<&dyn PeerApi>,
    ) -> Result<(), StepError> {
        if let Some(api) = injected {
            return self.step_using(auth, config, runtime, eligibility, api);
        }
        if self.scope.as_ref() != Some(&eligibility.binding.scope) {
            self.transport = None;
        }
        if self.transport.is_none() {
            // This independent pin was already authenticated by cloud handoff;
            // validate again before allocating the peer-only HTTP adapter.
            let origin =
                RemoteApiOrigin::new(config, eligibility.binding.scope.remote_api_origin.clone())
                    .map_err(|_| StepError::Stale)?;
            self.transport = Some(
                runtime
                    .public_io
                    .data_transport(origin)
                    .map_err(|_| StepError::Stale)?,
            );
        }
        let transport = self.transport.take().expect("initialized peer adapter");
        let operation = runtime.operation;
        let stopping = runtime.stopping;
        let paused = runtime.paused;
        let gate = runtime.gate;
        #[cfg(unix)]
        let public_pending = &runtime.public_io.setup().pending;
        let check = || {
            operation.check().map_err(|error| match error {
                owner_domain::Error::Deadline => lomi_host_http::BudgetStop::Deadline,
                _ => lomi_host_http::BudgetStop::Cancelled,
            })?;
            if stopping.load(Ordering::Acquire)
                || paused.load(Ordering::Acquire)
                || gate.load(Ordering::Acquire)
            {
                return Err(lomi_host_http::BudgetStop::Cancelled);
            }
            #[cfg(unix)]
            if public_pending.load(Ordering::Acquire) {
                return Err(lomi_host_http::BudgetStop::Cancelled);
            }
            Ok(())
        };
        let budget = transport.with_budget(operation.deadline(), &check);
        let result = self.step_using(auth, config, runtime, eligibility, &budget);
        self.transport = Some(transport);
        result
    }
    fn step_using(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn PeerApi,
    ) -> Result<(), StepError> {
        if self.scope.as_ref() != Some(&eligibility.binding.scope) {
            self.scope = Some(eligibility.binding.scope.clone());
            self.cache.clear();
            self.active = None;
            self.poll_at = None;
            self.parked.clear();
            self.cursor = None;
            self.proposal_cursor = None;
            self.prefer_recovery = false;
            self.failures = 0;
        }
        let result = self.turn(auth, config, runtime, eligibility, api);
        match result {
            Ok(()) => Ok(()),
            Err(PeerError::Fatal(error)) => {
                self.active = None;
                self.cache.clear();
                Err(error)
            }
            Err(PeerError::Invalid) => {
                // A policy/peer-local denial must be consumed only after the
                // same current live guards used for successful responses.
                self.live(auth, runtime, eligibility)
                    .map_err(|error| match error {
                        PeerError::Fatal(error) => error,
                        PeerError::Invalid => StepError::Stale,
                    })?;
                self.active = None;
                self.backoff();
                Ok(())
            }
        }
    }
    pub(super) fn live(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
    ) -> ResultPeer<u64> {
        let now = owner_turn(runtime, || {
            runtime
                .owner
                .peer_time(runtime.operation, eligibility, runtime.base, runtime.anchor)
        })?;
        if !fresh_access(auth, now) || managed(auth.credential_deadlines())?.refresh_at <= now {
            return Err(StepError::Stale.into());
        }
        let identity = managed(auth.public_host_identity(now))?;
        if identity != eligibility.identity
            || identity.access_epoch != eligibility.binding.server_runtime.host_access_epoch.0
        {
            return Err(StepError::Stale.into());
        }
        owner_turn(runtime, || {
            runtime
                .owner
                .validate_peer_eligibility(runtime.operation, eligibility)
        })?;
        check_peer_runtime(runtime)?;
        Ok(now)
    }
    fn backoff(&mut self) {
        self.failures = self.failures.saturating_add(1).min(5);
        self.poll_at = Some(Instant::now() + Duration::from_secs((1u64 << self.failures).min(30)));
    }
    fn park(&mut self, intent: &PairingDecisionIntent) {
        self.parked.insert(
            intent.token.clone(),
            Instant::now() + Duration::from_secs(1),
        );
    }
    fn turn(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn PeerApi,
    ) -> ResultPeer<()> {
        self.live(auth, runtime, eligibility)?;
        if self.clock.is_none() {
            self.clock = Some(policy(PolicyClock::new(runtime.base, runtime.anchor))?);
        }
        let pending = owner_turn(runtime, || {
            runtime
                .owner
                .peer_pending_pairings(runtime.operation, eligibility)
        })?;
        self.parked
            .retain(|token, _| pending.iter().any(|intent| &intent.token == token));
        self.turns_since_poll = self.turns_since_poll.saturating_add(1);
        // Resource-local unknowns must not monopolize every idle turn. Honor
        // outage backoff, then reserve every fourth eligible turn for a due poll.
        if self.turns_since_poll >= 4 && self.poll_at.is_none_or(|at| Instant::now() >= at) {
            return self.poll(auth, runtime, eligibility, api, &pending);
        }
        if let Some(work) = self.active.take() {
            if !work.observation.current(eligibility)
                || !work.observation.current_operation(runtime)
            {
                return Ok(());
            }
            return if work.intent.is_some() {
                self.send(auth, config, runtime, eligibility, api, work)
            } else {
                self.prepare(auth, config, runtime, eligibility, work)
            };
        }
        // Polls do not reset this class. Replenished valid caches and durable
        // unknown outcomes each receive a bounded share of non-poll idle turns.
        if self.prefer_recovery
            && self.recover_one(auth, config, runtime, eligibility, api, &pending)?
        {
            self.prefer_recovery = false;
            return Ok(());
        }
        if let Some(work) = self.cache.pop_front() {
            self.prefer_recovery = true;
            self.proposal_cursor = Some(work.pairing);
            if work.observation.current(eligibility) && work.observation.current_operation(runtime)
            {
                return self.prepare(auth, config, runtime, eligibility, work);
            }
            return Ok(());
        }
        if self.recover_one(auth, config, runtime, eligibility, api, &pending)? {
            self.prefer_recovery = false;
            return Ok(());
        }
        if self.poll_at.is_some_and(|until| Instant::now() < until) {
            return Ok(());
        }
        self.poll(auth, runtime, eligibility, api, &pending)
    }
    fn recover_one(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn PeerApi,
        pending: &[PairingDecisionIntent],
    ) -> ResultPeer<bool> {
        let now = self.live(auth, runtime, eligibility)?;
        if self.retire_expired_intent(auth, runtime, eligibility, pending, now)? {
            return Ok(true);
        }
        if self.capacity_blocked && self.cleanup_expired(auth, runtime, eligibility, now)? {
            return Ok(true);
        }
        let start = self
            .cursor
            .as_ref()
            .and_then(|token| pending.iter().position(|p| &p.token == token))
            .map_or(0, |i| (i + 1) % pending.len().max(1));
        for offset in 0..pending.len() {
            let intent = &pending[(start + offset) % pending.len()];
            if self
                .parked
                .get(&intent.token)
                .is_none_or(|until| Instant::now() >= *until)
            {
                self.cursor = Some(intent.token.clone());
                // Selection advances the class even if the resource returns an
                // invalid proposal/policy result after this actual GET.
                self.prefer_recovery = false;
                self.reconcile(auth, config, runtime, eligibility, api, intent.clone())?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn poll(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn PeerApi,
        pending: &[PairingDecisionIntent],
    ) -> ResultPeer<()> {
        let now = self.live(auth, runtime, eligibility)?;
        let mut effect = owner_turn(runtime, || {
            runtime.owner.capture_peer_effect(
                runtime.operation,
                eligibility,
                shared_owner::PeerEffect::PairingPending(eligibility.identity.host_id),
                None,
                runtime.base,
                runtime.anchor,
            )
        })?;
        let access = managed(auth.access_credential(now))?;
        let started = Instant::now();
        self.poll_at = Some(started + Duration::from_secs(1));
        self.turns_since_poll = 0;
        let provider = ProviderCapture::read(auth, runtime, eligibility)?;
        owner_turn(runtime, || effect.try_validate(&provider))?;
        check_peer_runtime(runtime)?;
        effect.check_boundary(&provider).map_err(owner_error)?;
        let response = api.pending(eligibility.identity.host_id, &access);
        self.live(auth, runtime, eligibility)?;
        let Ok(response) = response else {
            self.backoff();
            return Ok(());
        };
        let observation = std::sync::Arc::new(Observation::new(
            eligibility,
            started,
            effect.continuation(),
        ));
        if !observation.current(eligibility) {
            return Ok(());
        }
        if response.pairings.as_slice().len() > 64 {
            return Err(PeerError::Invalid);
        }
        let mut seen = BTreeSet::new();
        self.cache.clear();
        let pairings = response.pairings.as_slice();
        if pairings
            .iter()
            .any(|pairing| !seen.insert(pairing.pairing_id))
        {
            return Err(PeerError::Invalid);
        }
        // A stable server ordering must not starve its tail when metadata expires
        // before all64 proposals can be prepared on separate idle turns.
        let start = self
            .proposal_cursor
            .and_then(|cursor| {
                pairings
                    .iter()
                    .position(|pairing| pairing.pairing_id == cursor)
            })
            .map_or(0, |i| (i + 1) % pairings.len().max(1));
        for offset in 0..pairings.len() {
            let pairing = &pairings[(start + offset) % pairings.len()];
            if pending
                .iter()
                .any(|p| p.preparation.pairing_id == pairing.pairing_id)
            {
                continue;
            }
            self.cache.push_back(Work {
                pairing: pairing.pairing_id,
                proposal: pairing.proposal.clone(),
                observation: observation.clone(),
                intent: None,
            });
        }
        self.failures = 0;
        Ok(())
    }
    fn snapshot(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        work: &Work,
    ) -> ResultPeer<(PolicySnapshot, GrantV3, CloudPairingScope, u64)> {
        self.snapshot_with_ceiling(auth, config, runtime, eligibility, work, None)
    }
    pub(super) fn snapshot_with_ceiling(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        work: &Work,
        authority_expires_at: Option<u64>,
    ) -> ResultPeer<(PolicySnapshot, GrantV3, CloudPairingScope, u64)> {
        let now = self.live(auth, runtime, eligibility)?;
        if !work.observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        let host = managed(auth.public_host_identity(now))?;
        let proposal = &work.proposal;
        if proposal.identities.host != host.identity
            || pin(&proposal.identities.host_fingerprint)? != host.fingerprint
        {
            return Err(PeerError::Invalid);
        }
        let consumer = crypt(SignedBundle::from_wire(&proposal.identities.consumer))?;
        let window = WindowIdentityId::from_bytes(consumer.bundle.subject_id)
            .map_err(|_| PeerError::Invalid)?;
        crypt(verify_consumer_window_identity(
            &proposal.identities.consumer,
            host.account_id.to_bytes(),
            window.to_bytes(),
        ))?;
        let consumer_pin = pin(&proposal.identities.consumer_fingerprint)?;
        crypt(consumer.verify(&consumer_pin))?;
        // The ceiling is server-generated under authenticated TLS. Its expiry is
        // bounded by the recipient/session at that server observation, not copied
        // from a consumer-signed proposal or a mutable retry deadline.
        let maximum = crypt(GrantV3::from_canonical(&hex_bytes(
            proposal.maximum_grant.expose_wire(),
        )?))?;
        if authority_expires_at.is_some_and(|expiry| expiry > maximum.expires_at) {
            return Err(PeerError::Invalid);
        }
        let workspace =
            WorkspaceId::from_bytes(maximum.workspace_id).map_err(|_| PeerError::Invalid)?;
        let evidence = owner_turn(runtime, || {
            runtime
                .owner
                .peer_workspace(runtime.operation, eligibility, workspace)
        })?;
        let local = evidence.workspace;
        let mut terminals = Vec::new();
        let mut layouts: Vec<_> = local.state.tabs.0.iter().map(|tab| &tab.layout).collect();
        let descriptors = evidence.descriptors;
        while let Some(layout) = layouts.pop() {
            match layout {
                lomi_remote_protocol::rpc::TerminalLayout::Split { first, second, .. } => {
                    layouts.push(first);
                    layouts.push(second);
                }
                lomi_remote_protocol::rpc::TerminalLayout::Pane { pane }
                    if pane.state == lomi_remote_protocol::rpc::PaneState::Running =>
                {
                    let session = pane.session.as_ref().ok_or(PeerError::Invalid)?;
                    if session.workspace != local.state.context
                        || session.pane_id != pane.pane_id
                        || !descriptors.iter().any(|d| {
                            d.pane_id == pane.pane_id
                                && d.status == lomi_host_store::TerminalStatus::Running
                        })
                    {
                        return Err(PeerError::Invalid);
                    }
                    terminals.push(PublishedTerminal {
                        pane_id: pane.pane_id,
                        session_id: session.session_id,
                        session_epoch: session.session_epoch,
                    });
                }
                lomi_remote_protocol::rpc::TerminalLayout::Pane { .. } => (),
            }
        }
        let scope = CloudPairingScope {
            runtime_scope: eligibility.binding.scope.clone(),
            runtime: eligibility.binding.server_runtime.clone(),
            workspace_id: workspace,
            workspace_epoch: local.state.context.workspace_epoch,
            workspace_fence: local.fence,
        };
        if local.state.context.runtime_id != scope.runtime_scope.owner_runtime_id
            || local.state.context.runtime_generation.0 != scope.runtime_scope.owner_generation
        {
            return Err(PeerError::Invalid);
        }
        let snapshot = policy(PolicySnapshot::new(SnapshotInput {
            protected_host: host.clone(),
            remote_origin: policy(RemoteOrigin::new(
                config,
                scope.runtime_scope.remote_api_origin.clone(),
            ))?,
            owner: OwnerScope {
                authorization_generation: scope.runtime_scope.authorization_generation,
                owner_runtime_id: scope.runtime_scope.owner_runtime_id,
                owner_generation: scope.runtime_scope.owner_generation,
                runtime: scope.runtime.clone(),
            },
            acknowledged_runtime: eligibility.publication.state.server_runtime.clone(),
            acknowledged_workspaces: eligibility.publication.workspaces.clone(),
            local: LocalWorkspace {
                workspace_id: workspace,
                workspace_epoch: scope.workspace_epoch,
                fence: scope.workspace_fence,
                consent: local.consent,
                running_terminals: PublicationTerminals::try_from(terminals)
                    .map_err(|_| PeerError::Invalid)?,
                capability_ceiling: None,
            },
            peer: PeerObservation {
                account_id: host.account_id,
                window_id: window,
                identity: proposal.identities.consumer.clone(),
                fingerprint: consumer_pin,
                authority: proposal.authority.clone(),
                authority_expires_at: authority_expires_at.unwrap_or(maximum.expires_at),
            },
            request_started: work.observation.heartbeat.request_started,
            wall_at_request_start: work.observation.heartbeat.wall_at_request_start,
            lease_ms: work.observation.heartbeat.lease_ms,
            freshness_ms: work.observation.heartbeat.freshness_ms,
        }))?;
        Ok((snapshot, maximum, scope, now))
    }
    fn verify_retained(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        work: &Work,
        intent: &PairingDecisionIntent,
    ) -> ResultPeer<ApprovedGrant> {
        let (snapshot, maximum, scope, _snapshot_now) =
            self.snapshot(auth, config, runtime, eligibility, work)?;
        let p = &intent.preparation;
        let PairingDecisionParams::Approve { grant, .. } = &p.params else {
            return Err(PeerError::Invalid);
        };
        let signed = crypt(SignedGrantV3::from_wire(grant))?;
        if p.scope != scope
            || p.proposal != work.proposal
            || p.pairing_id != work.pairing
            || p.original_expires_at != signed.grant.expires_at
            || p.grant_id.to_bytes() != signed.grant.grant_id
            || p.account_id != eligibility.identity.account_id
            || p.window_identity_id.to_bytes() != signed.grant.consumer_id
            || signed.grant.expires_at > maximum.expires_at
        {
            return Err(PeerError::Invalid);
        }
        let now = self.live(auth, runtime, eligibility)?;
        let prepared = policy(snapshot.prepare_grant(
            &hex_bytes(p.proposal.maximum_grant.expose_wire())?,
            GrantNarrowing {
                capabilities: signed.grant.capabilities.clone(),
                expires_at: signed.grant.expires_at,
            },
            self.clock.as_mut().expect("initialized policy clock"),
            now,
            policy_instant!(
                "verify_retained.prepare_grant",
                now,
                runtime,
                &work.observation.heartbeat
            ),
        ))?;
        if prepared.canonical() != hex_bytes(grant.canonical_cbor.expose_wire())?
            || prepared.grant() != &signed.grant
            || crypt(signed.to_wire())? != *grant
        {
            return Err(PeerError::Invalid);
        }
        let now = self.live(auth, runtime, eligibility)?;
        let approved = policy(snapshot.retain_approved_grant(
            &prepared,
            signed,
            self.clock.as_mut().expect("initialized policy clock"),
            now,
            policy_instant!(
                "verify_retained.retain_approved_grant",
                now,
                runtime,
                &work.observation.heartbeat
            ),
        ))?;
        self.live(auth, runtime, eligibility)?;
        Ok(approved)
    }
    fn prepare(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        mut work: Work,
    ) -> ResultPeer<()> {
        let (snapshot, maximum, scope, _snapshot_now) =
            self.snapshot(auth, config, runtime, eligibility, &work)?;
        let now = self.live(auth, runtime, eligibility)?;
        let prepared = policy(snapshot.prepare_grant(
            &hex_bytes(work.proposal.maximum_grant.expose_wire())?,
            GrantNarrowing {
                capabilities: CapabilitySet::control_with_workspace_tools(),
                expires_at: maximum.expires_at,
            },
            self.clock.as_mut().expect("initialized policy clock"),
            now,
            policy_instant!(
                "prepare.prepare_grant",
                now,
                runtime,
                &work.observation.heartbeat
            ),
        ))?;
        let now = self.live(auth, runtime, eligibility)?;
        let signed = managed(auth.sign_grant_v3(prepared.grant(), now))?;
        if crypt(signed.grant.canonical())? != prepared.canonical() {
            return Err(PeerError::Invalid);
        }
        let now = self.live(auth, runtime, eligibility)?;
        let _approved = policy(snapshot.retain_approved_grant(
            &prepared,
            signed.clone(),
            self.clock.as_mut().expect("policy clock"),
            now,
            policy_instant!(
                "prepare.retain_approved_grant",
                now,
                runtime,
                &work.observation.heartbeat
            ),
        ))?;
        self.live(auth, runtime, eligibility)?;
        if !work.observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        let params = PairingDecisionParams::Approve {
            grant: crypt(signed.to_wire())?,
            runtime: scope.runtime.clone(),
        };
        let request = PairingDecisionPreparation {
            scope,
            pairing_id: work.pairing,
            grant_id: GrantId::from_bytes(signed.grant.grant_id).map_err(|_| PeerError::Invalid)?,
            account_id: eligibility.identity.account_id,
            window_identity_id: WindowIdentityId::from_bytes(signed.grant.consumer_id)
                .map_err(|_| PeerError::Invalid)?,
            proposal: work.proposal.clone(),
            original_expires_at: signed.grant.expires_at,
            params,
        };
        let provider = ProviderCapture::read(auth, runtime, eligibility)?;
        let capture = owner_turn(runtime, || {
            runtime.owner.capture_peer_journal(
                runtime.operation,
                eligibility,
                &provider,
                Some(&work.observation),
                request.scope.workspace_id,
                runtime.base,
                runtime.anchor,
            )
        })?;
        let mut turn = capture
            .begin_prepare_pairing_decision(request)
            .map_err(owner_error)?;
        let intent = owner_turn(runtime, || {
            let result = turn.try_commit();
            if matches!(
                result,
                Err(shared_owner::Error::Store(StoreError::ResourceExhausted))
            ) {
                self.capacity_blocked = true;
            }
            result
        })?;
        drop(turn);
        self.live(auth, runtime, eligibility)?;
        work.intent = Some(intent);
        self.active = Some(work);
        Ok(())
    }
    fn reconcile(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn PeerApi,
        intent: PairingDecisionIntent,
    ) -> ResultPeer<()> {
        let now = self.live(auth, runtime, eligibility)?;
        let mut effect = owner_turn(runtime, || {
            runtime.owner.capture_peer_effect(
                runtime.operation,
                eligibility,
                shared_owner::PeerEffect::PairingGet(intent.preparation.pairing_id),
                None,
                runtime.base,
                runtime.anchor,
            )
        })?;
        let access = managed(auth.access_credential(now))?;
        let started = Instant::now();
        let provider = ProviderCapture::read(auth, runtime, eligibility)?;
        owner_turn(runtime, || effect.try_validate(&provider))?;
        check_peer_runtime(runtime)?;
        effect.check_boundary(&provider).map_err(owner_error)?;
        let response = api.get(intent.preparation.pairing_id, &access);
        self.live(auth, runtime, eligibility)?;
        self.park(&intent);
        let Ok(response) = response else {
            return Ok(());
        };
        let observation = std::sync::Arc::new(Observation::new(
            eligibility,
            started,
            effect.continuation(),
        ));
        let mut work = Work {
            pairing: intent.preparation.pairing_id,
            proposal: intent.preparation.proposal.clone(),
            observation,
            intent: Some(intent.clone()),
        };
        if !work.observation.current(eligibility) {
            return Ok(());
        }
        match &response {
            PairingResult::Pending {
                pairing_id,
                proposal,
            } if *pairing_id == work.pairing && proposal == &work.proposal => {
                self.verify_retained(auth, config, runtime, eligibility, &work, &intent)?;
                work.proposal = proposal.clone();
                self.active = Some(work);
            }
            PairingResult::Approved { .. } => {
                self.ack(auth, config, runtime, eligibility, &work, &response)?
            }
            PairingResult::Expired { pairing_id } | PairingResult::Denied { pairing_id }
                if *pairing_id == work.pairing =>
            {
                self.live(auth, runtime, eligibility)?;
                let provider = ProviderCapture::read(auth, runtime, eligibility)?;
                let capture = owner_turn(runtime, || {
                    runtime.owner.capture_peer_journal(
                        runtime.operation,
                        eligibility,
                        &provider,
                        Some(&work.observation),
                        intent.preparation.scope.workspace_id,
                        runtime.base,
                        runtime.anchor,
                    )
                })?;
                let mut turn = capture
                    .begin_retire_pairing_decision(intent.clone())
                    .map_err(owner_error)?;
                owner_turn(runtime, || turn.try_commit())?;
            }
            _ => (),
        }
        Ok(())
    }
    fn send(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn PeerApi,
        work: Work,
    ) -> ResultPeer<()> {
        let intent = work.intent.as_ref().expect("frozen intent");
        self.verify_retained(auth, config, runtime, eligibility, &work, intent)?;
        self.live(auth, runtime, eligibility)?;
        {
            let provider = ProviderCapture::read(auth, runtime, eligibility)?;
            let capture = owner_turn(runtime, || {
                runtime.owner.capture_peer_journal(
                    runtime.operation,
                    eligibility,
                    &provider,
                    Some(&work.observation),
                    intent.preparation.scope.workspace_id,
                    runtime.base,
                    runtime.anchor,
                )
            })?;
            let mut turn = capture
                .begin_check_pairing_decision_send(intent.clone())
                .map_err(owner_error)?;
            owner_turn(runtime, || turn.try_commit())?;
        }
        let now = self.live(auth, runtime, eligibility)?;
        let mut effect = owner_turn(runtime, || {
            runtime.owner.capture_peer_effect(
                runtime.operation,
                eligibility,
                shared_owner::PeerEffect::PairingSend(intent.clone()),
                Some(&work.observation),
                runtime.base,
                runtime.anchor,
            )
        })?;
        let access = managed(auth.access_credential(now))?;
        self.live(auth, runtime, eligibility)?;
        if !work.observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        let provider = ProviderCapture::read(auth, runtime, eligibility)?;
        owner_turn(runtime, || effect.try_validate(&provider))?;
        check_peer_runtime(runtime)?;
        effect.check_boundary(&provider).map_err(owner_error)?;
        let response = api.decide(work.pairing, &intent.preparation.params, &access);
        self.live(auth, runtime, eligibility)?;
        // Even a transport failure may have committed. The active work is taken
        // before sending: every subsequent attempt therefore starts with GET.
        let Ok(response) = response else {
            return Ok(());
        };
        if !work.observation.current(eligibility) {
            return Ok(());
        }
        self.ack(auth, config, runtime, eligibility, &work, &response)
    }
    fn ack(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        work: &Work,
        response: &PairingResult,
    ) -> ResultPeer<()> {
        let intent = work.intent.as_ref().ok_or(PeerError::Invalid)?;
        let p = &intent.preparation;
        let PairingDecisionParams::Approve { grant, .. } = &p.params else {
            return Err(PeerError::Invalid);
        };
        if !matches!(response,PairingResult::Approved {pairing_id,proposal,grant:actual,identities,authority} if *pairing_id==p.pairing_id && proposal==&p.proposal && actual==grant && identities==&p.proposal.identities && authority==&p.proposal.authority)
        {
            return Err(PeerError::Invalid);
        }
        let _approved = self.verify_retained(auth, config, runtime, eligibility, work, intent)?;
        self.live(auth, runtime, eligibility)?;
        if !work.observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        let provider = ProviderCapture::read(auth, runtime, eligibility)?;
        let capture = owner_turn(runtime, || {
            runtime.owner.capture_peer_journal(
                runtime.operation,
                eligibility,
                &provider,
                Some(&work.observation),
                intent.preparation.scope.workspace_id,
                runtime.base,
                runtime.anchor,
            )
        })?;
        let mut turn = capture
            .begin_acknowledge_pairing(intent.clone(), response.clone())
            .map_err(owner_error)?;
        owner_turn(runtime, || turn.try_commit())?;
        Ok(())
    }
    fn retire_expired_intent(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        pending: &[PairingDecisionIntent],
        now: u64,
    ) -> ResultPeer<bool> {
        for offset in 0..pending.len() {
            let index = (self.retire_cursor + offset) % pending.len();
            let intent = &pending[index];
            if intent.preparation.original_expires_at > now
                || !matches!(
                    intent.preparation.params,
                    PairingDecisionParams::Approve { .. }
                )
            {
                continue;
            }
            self.retire_cursor = (index + 1) % pending.len();
            if verify_expired_intent(intent, &eligibility.identity, now).is_err() {
                return Ok(false);
            }
            self.live(auth, runtime, eligibility)?;
            let provider = ProviderCapture::read(auth, runtime, eligibility)?;
            let capture = owner_turn(runtime, || {
                runtime.owner.capture_peer_journal(
                    runtime.operation,
                    eligibility,
                    &provider,
                    None,
                    intent.preparation.scope.workspace_id,
                    runtime.base,
                    runtime.anchor,
                )
            })?;
            let mut turn = capture
                .begin_retire_pairing_decision(intent.clone())
                .map_err(owner_error)?;
            owner_turn(runtime, || turn.try_commit())?;
            return Ok(true);
        }
        Ok(false)
    }
    fn cleanup_expired(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        now: u64,
    ) -> ResultPeer<bool> {
        let grants = owner_turn(runtime, || {
            runtime
                .owner
                .peer_workspace_grants(runtime.operation, eligibility)
        })?;
        let count = grants.len();
        for offset in 0..count {
            let index = (self.cleanup_cursor + offset) % count;
            let grant = &grants[index];
            if grant.intent.preparation.original_expires_at > now {
                continue;
            }
            self.cleanup_cursor = (index + 1) % count;
            // One bounded candidate per turn. Invalid evidence remains retained;
            // it must not permanently prevent checking a different expired row.
            if verify_expired_intent(&grant.intent, &eligibility.identity, now).is_err() {
                return Ok(false);
            }
            self.live(auth, runtime, eligibility)?;
            let provider = ProviderCapture::read(auth, runtime, eligibility)?;
            let capture = owner_turn(runtime, || {
                runtime.owner.capture_peer_journal(
                    runtime.operation,
                    eligibility,
                    &provider,
                    None,
                    grant.intent.preparation.scope.workspace_id,
                    runtime.base,
                    runtime.anchor,
                )
            })?;
            let mut turn = capture
                .begin_retire_acknowledged_workspace_grant(grant.clone())
                .map_err(owner_error)?;
            owner_turn(runtime, || turn.try_commit())?;
            self.capacity_blocked = false;
            return Ok(true);
        }
        Ok(false)
    }
}
fn verify_expired_intent(
    intent: &PairingDecisionIntent,
    host: &lomi_host_auth::PublicHostIdentity,
    now: u64,
) -> ResultPeer<()> {
    let p = &intent.preparation;
    let PairingDecisionParams::Approve { grant, .. } = &p.params else {
        return Err(PeerError::Invalid);
    };
    let signed = crypt(SignedGrantV3::from_wire(grant))?;
    let mut maximum = crypt(GrantV3::from_canonical(&hex_bytes(
        p.proposal.maximum_grant.expose_wire(),
    )?))?;
    let ids = &p.proposal.identities;
    if ids.host != host.identity
        || pin(&ids.host_fingerprint)? != host.fingerprint
        || p.account_id != host.account_id
        || p.scope.runtime_scope.host_id != host.host_id
        || p.original_expires_at != signed.grant.expires_at
        || now < signed.grant.expires_at
        || signed.grant.expires_at > maximum.expires_at
        || signed.grant.grant_id != p.grant_id.to_bytes()
        || signed.grant.consumer_id != p.window_identity_id.to_bytes()
        || Vec::<Capability>::from(signed.grant.capabilities.clone())
            .iter()
            .any(|cap| !maximum.capabilities.contains(*cap))
    {
        return Err(PeerError::Invalid);
    }
    maximum.capabilities = signed.grant.capabilities.clone();
    maximum.expires_at = signed.grant.expires_at;
    if maximum != signed.grant || crypt(signed.to_wire())? != *grant {
        return Err(PeerError::Invalid);
    }
    let consumer = crypt(verify_consumer_window_identity(
        &ids.consumer,
        host.account_id.to_bytes(),
        p.window_identity_id.to_bytes(),
    ))?;
    let a = &p.proposal.authority;
    if p.scope.runtime
        != match &p.params {
            PairingDecisionParams::Approve { runtime, .. }
            | PairingDecisionParams::Deny { runtime } => runtime.clone(),
        }
        || signed.grant.workspace_id != p.scope.workspace_id.to_bytes()
        || signed.grant.workspace_epoch != p.scope.workspace_epoch.to_bytes()
    {
        return Err(PeerError::Invalid);
    }
    let authority = CurrentAuthorityV3 {
        host_authorization_id: a.host_authorization_id.to_bytes(),
        consumer_authorization_id: a.consumer_authorization_id.to_bytes(),
        account_session_id: a.account_session_id.as_str().to_owned(),
        access_epoch: a.access_epoch.0,
        grant_revision: a.grant_revision.0,
        workspace_epoch: a.workspace_epoch.to_bytes(),
        runtime_id: a.runtime_id.to_bytes(),
        runtime_generation: a.runtime_generation.0,
        terminal_membership: None,
    };
    if a.terminal_membership.is_some() {
        return Err(PeerError::Invalid);
    }
    // Historical signature proof only. The current nondecreasing durable clock
    // is already >= the exact signed expiry, so this cannot create live authority
    // or a PolicyClock/ApprovedGrant token at an earlier time.
    crypt(signed.verify(
        &signed.grant,
        &crypt(SignedBundle::from_wire(&host.identity))?,
        &host.fingerprint,
        &consumer,
        &pin(&ids.consumer_fingerprint)?,
        &authority,
        signed.grant.expires_at.saturating_sub(1),
    ))?;
    Ok(())
}

// Approved journal bytes authorize only the TARGET of this fresh authenticated
// read. They never supply the current authority or freshness in this token.
pub(in super::super) struct VerifiedCurrentPeer {
    operation: owner_domain::OperationIdentity,
    source: lomi_host_store::AcknowledgedWorkspaceGrant,
    observation: Observation,
    origin: RemoteOrigin,
    consumer: EnrollmentProof,
    consumer_pin: [u8; 32],
    signed: SignedGrantV3,
    authority: CurrentAuthorityV3,
    wall_at_start: u64,
}

/// Exact cached channel tuple from an established RemoteConnectionState.
/// It selects a pairing GET target but contains no authority of its own.
#[derive(Clone)]
pub(in crate::unix) struct StartedGitPairingTarget {
    pub(in crate::unix) connection: uuid::Uuid,
    pub(in crate::unix) context: ChannelContextV3,
    pub(in crate::unix) signed_grant: SignedGrantV3,
    pub(in crate::unix) consumer_window_id: [u8; 16],
    pub(in crate::unix) consumer_identity: lomi_remote_protocol::EnrollmentProof,
    pub(in crate::unix) authority: CurrentAuthorityV3,
    pub(in crate::unix) origin: RemoteOrigin,
    pub(in crate::unix) scope: lomi_host_store::CloudRuntimeScope,
}

/// Fresh proof that one already established channel's original pairing is
/// still current during this exact Started Git writer.
#[derive(Clone)]
pub(in crate::unix) struct StartedGitPeerObservation {
    pub(in crate::unix) active: shared_owner::StartedGitContinuation,
    pub(in crate::unix) target: StartedGitPairingTarget,
    pub(in crate::unix) source: lomi_host_store::AcknowledgedWorkspaceGrant,
    pub(in crate::unix) fresh_until: Instant,
}
impl StartedGitPeerObservation {
    pub(in crate::unix) fn fresh_until(&self) -> Instant {
        self.fresh_until
    }
    pub(in crate::unix) fn source(&self) -> &lomi_host_store::AcknowledgedWorkspaceGrant {
        &self.source
    }
    pub(in crate::unix) fn target(&self) -> &StartedGitPairingTarget {
        &self.target
    }
    pub(in crate::unix) fn current_for(
        &self,
        active: &shared_owner::StartedGitContinuation,
        operation: &owner_domain::Operation<'_>,
        connection: uuid::Uuid,
    ) -> bool {
        self.target.connection == connection
            && self.active.same_writer(active)
            && self.active.is_current(operation)
            && Instant::now() < self.fresh_until
    }
}

impl VerifiedCurrentPeer {
    pub(in crate::unix) fn io_deadline(
        &self,
        worker: &super::RemoteWorkerEvidence<'_, '_, '_, '_>,
    ) -> Option<Instant> {
        if !self.current(worker) {
            return None;
        }
        let now = worker.now()?;
        let credentials = worker.provider().captured_deadlines();
        let wall_limit = self
            .signed
            .grant
            .expires_at
            .min(credentials.access_expires_at)
            .min(credentials.refresh_at);
        let remaining = Duration::from_secs(wall_limit).checked_sub(now.wall)?;
        Some(
            self.fresh_until()
                .min(now.monotonic.checked_add(remaining)?)
                .min(worker.operation().deadline()),
        )
    }
    pub(super) fn observed_at(&self) -> Instant {
        self.observation.started
    }
    pub(in crate::unix) fn fresh_until(&self) -> Instant {
        (self.observation.started + Duration::from_secs(5))
            .min(
                self.observation.heartbeat.request_started
                    + Duration::from_millis(self.observation.heartbeat.freshness_ms),
            )
            .min(
                self.observation.heartbeat.request_started
                    + Duration::from_millis(self.observation.heartbeat.lease_ms),
            )
    }
    pub(in super::super) fn source(&self) -> &lomi_host_store::AcknowledgedWorkspaceGrant {
        &self.source
    }
    pub(in super::super) fn continuation(&self) -> &owner_domain::PeerContinuation {
        &self.observation.continuation
    }
    pub(in super::super) fn grant(&self) -> &GrantV3 {
        &self.signed.grant
    }
    pub(in crate::unix) fn current_authority(&self) -> &CurrentAuthorityV3 {
        &self.authority
    }
    pub(in super::super) fn current(
        &self,
        worker: &super::RemoteWorkerEvidence<'_, '_, '_, '_>,
    ) -> bool {
        worker.current()
            && worker.operation().is_same_admission(&self.operation)
            && self.observation.current(worker.eligibility())
            && worker
                .owner()
                .peer_original_boundary(worker.operation(), self.continuation())
                .is_ok()
            && worker
                .now()
                .is_some_and(|now| now.wall.as_secs() < self.signed.grant.expires_at)
    }
    /// Workspace authority is preserved exactly as returned by pairing GET.
    /// A terminal-purpose membership projection requires separate owner review.
    pub(in super::super) fn read(&self) -> super::remote_connection::PeerRead<'_> {
        super::remote_connection::PeerRead {
            origin: &self.origin,
            request_started: self.observation.started,
            wall_at_request_start: self.wall_at_start,
            original_heartbeat: &self.observation.heartbeat,
            consumer_window: WindowIdentityId::from_bytes(self.signed.grant.consumer_id)
                .expect("verified window"),
            consumer_identity: &self.consumer,
            consumer_pin: self.consumer_pin,
            signed_grant: &self.signed,
            authority: &self.authority,
            authority_expires_at: self.signed.grant.expires_at,
        }
    }
}
impl Worker {
    /// No injected PeerApi: only the actual independently pinned TLS transport
    /// can create the production-shaped current-peer token. Still no ingress driver.
    pub(super) fn read_current_pairing<'r>(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'r>,
        eligibility: &PeerEligibility,
        source: lomi_host_store::AcknowledgedWorkspaceGrant,
    ) -> ResultPeer<VerifiedCurrentPeer> {
        self.read_current_pairing_bounded(
            auth,
            runtime,
            eligibility,
            source,
            runtime.operation.deadline(),
        )
    }
    pub(super) fn read_current_pairing_bounded<'r>(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'r>,
        eligibility: &PeerEligibility,
        source: lomi_host_store::AcknowledgedWorkspaceGrant,
        cutoff: Instant,
    ) -> ResultPeer<VerifiedCurrentPeer> {
        check_peer_runtime(runtime)?;
        let trusted = auth.trusted_configuration();
        let origin = policy(RemoteOrigin::new(
            trusted,
            eligibility.binding.scope.remote_api_origin.clone(),
        ))?;
        let transport = runtime
            .public_io
            .data_transport(
                RemoteApiOrigin::new(trusted, origin.as_str().to_owned())
                    .map_err(|_| PeerError::Invalid)?,
            )
            .map_err(|_| PeerError::Invalid)?;

        let mut effect = owner_turn(runtime, || {
            runtime.owner.capture_peer_effect(
                runtime.operation,
                eligibility,
                shared_owner::PeerEffect::ApprovedPairingGet(Box::new(source.clone())),
                None,
                runtime.base,
                runtime.anchor,
            )
        })?;
        let provider = ProviderCapture::read(auth, runtime, eligibility)?;
        owner_turn(runtime, || effect.try_validate(&provider))?;
        let now = runtime
            .base
            .checked_add(runtime.anchor.elapsed().as_secs())
            .ok_or(PeerError::Invalid)?;
        let access = managed(auth.access_credential(now))?;
        check_peer_runtime(runtime)?;
        effect.check_boundary(&provider).map_err(owner_error)?;
        let operation = runtime.operation;
        let gate = runtime.gate;
        let paused = runtime.paused;
        let stopping = runtime.stopping;
        let pending = &runtime.public_io.setup().pending;
        let check = || {
            if Instant::now() >= cutoff {
                return Err(lomi_host_http::BudgetStop::Deadline);
            }
            operation.check().map_err(|error| match error {
                owner_domain::Error::Deadline => lomi_host_http::BudgetStop::Deadline,
                _ => lomi_host_http::BudgetStop::Cancelled,
            })?;
            if gate.load(Ordering::Acquire)
                || paused.load(Ordering::Acquire)
                || stopping.load(Ordering::Acquire)
                || pending.load(Ordering::Acquire)
            {
                return Err(lomi_host_http::BudgetStop::Cancelled);
            }
            Ok(())
        };
        let wall_at_start = runtime
            .base
            .checked_add(runtime.anchor.elapsed().as_secs())
            .ok_or(PeerError::Invalid)?;
        let started = Instant::now();
        let response = transport
            .with_budget(operation.deadline().min(cutoff), &check)
            .pairing_get(source.intent.preparation.pairing_id, &access)
            .map_err(|_| PeerError::Invalid)?;

        check_peer_runtime(runtime)?;
        let provider = ProviderCapture::read(auth, runtime, eligibility)?;
        owner_turn(runtime, || effect.try_validate(&provider))?;
        let observation = Observation::new(eligibility, started, effect.continuation());
        // Endpoint inference, not a wire field: pairing-peer.readResult invokes
        // verifiedApproval; migration009 host_read invokes migration008
        // pairing_retained under the global authorization lock. It rejects a
        // returned grant deadline > current maximumExpiresAt. Thus the freshly
        // returned VERIFIED grant expiry is a conservative current ceiling.
        // Never substitute the ACK grant, context expiry, or ChannelGET here.
        verify_current_pairing(
            auth,
            runtime,
            eligibility,
            source,
            response,
            observation,
            origin,
            wall_at_start,
        )
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "keep actual response, original owner operation and request observation distinct from journal target"
)]
fn verify_current_pairing<'r>(
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    runtime: Runtime<'r>,
    eligibility: &PeerEligibility,
    source: lomi_host_store::AcknowledgedWorkspaceGrant,
    response: PairingResult,
    observation: Observation,
    origin: RemoteOrigin,
    wall_at_start: u64,
) -> ResultPeer<VerifiedCurrentPeer> {
    check_peer_runtime(runtime)?;
    if !observation.current(eligibility) || !observation.current_operation(runtime) {
        return Err(PeerError::Invalid);
    }
    let PairingResult::Approved {
        pairing_id,
        proposal,
        grant,
        identities,
        authority: current,
    } = response
    else {
        return Err(PeerError::Invalid);
    };
    let preparation = &source.intent.preparation;
    let PairingDecisionParams::Approve {
        grant: original, ..
    } = &preparation.params
    else {
        return Err(PeerError::Invalid);
    };
    let now = runtime
        .base
        .checked_add(runtime.anchor.elapsed().as_secs())
        .ok_or(PeerError::Invalid)?;
    let host = managed(auth.public_host_identity(now))?;
    if pairing_id != preparation.pairing_id
        || proposal != preparation.proposal
        || grant != *original
        || identities != preparation.proposal.identities
        || identities.host != host.identity
        || pin(&identities.host_fingerprint)? != host.fingerprint
        || preparation.scope.runtime_scope != eligibility.binding.scope
        || preparation.scope.runtime != eligibility.binding.server_runtime
        || current.terminal_membership.is_some()
    {
        return Err(PeerError::Invalid);
    }
    let signed = crypt(SignedGrantV3::from_wire(&grant))?;
    let consumer = crypt(verify_consumer_window_identity(
        &identities.consumer,
        host.account_id.to_bytes(),
        preparation.window_identity_id.to_bytes(),
    ))?;
    let consumer_pin = pin(&identities.consumer_fingerprint)?;
    let authority = CurrentAuthorityV3 {
        host_authorization_id: current.host_authorization_id.to_bytes(),
        consumer_authorization_id: current.consumer_authorization_id.to_bytes(),
        account_session_id: current.account_session_id.as_str().to_owned(),
        access_epoch: current.access_epoch.0,
        grant_revision: current.grant_revision.0,
        workspace_epoch: current.workspace_epoch.to_bytes(),
        runtime_id: current.runtime_id.to_bytes(),
        runtime_generation: current.runtime_generation.0,
        terminal_membership: None,
    };
    if signed.grant.grant_id != preparation.grant_id.to_bytes()
        || signed.grant.workspace_id != preparation.scope.workspace_id.to_bytes()
        || signed.grant.workspace_epoch != preparation.scope.workspace_epoch.to_bytes()
        || signed.grant.expires_at != preparation.original_expires_at
    {
        return Err(PeerError::Invalid);
    }
    crypt(signed.verify(
        &signed.grant,
        &crypt(SignedBundle::from_wire(&host.identity))?,
        &host.fingerprint,
        &consumer,
        &consumer_pin,
        &authority,
        now,
    ))?;
    if !observation.current(eligibility) || !observation.current_operation(runtime) {
        return Err(PeerError::Invalid);
    }
    Ok(VerifiedCurrentPeer {
        operation: runtime.operation.retained_identity(),
        source,
        observation,
        origin,
        consumer: identities.consumer,
        consumer_pin,
        signed,
        authority,
        wall_at_start,
    })
}

/// Refresh only the exact source pairing for a retained Started Git writer.
/// The result updates a bounded freshness expiry; it never returns peer or
/// grant authority to another RPC path.
pub(super) fn refresh_started_git_pairing(
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    runtime: RuntimeWithOperation<'_, '_>,
    continuation: &shared_owner::StartedGitContinuation,
) -> Result<bool, StepError> {
    let operation = runtime.operation;
    if auth.status() != Status::Ready
        || runtime.check().is_err()
        || !continuation.is_current(operation)
    {
        return Err(StepError::Stale);
    }
    let peer_deadline = continuation.peer_deadline();
    if peer_deadline.saturating_duration_since(Instant::now()) > Duration::from_millis(2_500) {
        return Ok(false);
    }
    match runtime
        .owner
        .started_git_pairing_source_current(operation, continuation)
        .map_err(|_| StepError::Stale)?
    {
        None => return Ok(false),
        Some(true) => {}
        Some(false) => return Err(StepError::Stale),
    }

    let trusted = auth.trusted_configuration();
    let origin = RemoteApiOrigin::new(trusted, continuation.origin().as_str().to_owned())?;
    let transport = runtime.public_io.data_transport(origin)?;
    let expected = continuation.runtime();
    let now_wall = runtime
        .base
        .checked_add(runtime.anchor.elapsed().as_secs())
        .ok_or(StepError::Stale)?;
    started_git_auth_snapshot(auth, runtime, continuation, now_wall)?;
    let access = auth
        .access_credential(now_wall)
        .map_err(|_| StepError::Stale)?;
    let heartbeat = continuation.heartbeat().ok_or(StepError::Stale)?;
    if heartbeat.scope != expected.scope || heartbeat.runtime != expected.server_runtime {
        return Err(StepError::Stale);
    }
    let deadline = operation
        .deadline()
        .min(continuation.hard_deadline())
        .min(continuation.heartbeat_deadline())
        .min(peer_deadline);
    let gate = runtime.gate;
    let paused = runtime.paused;
    let stopping = runtime.stopping;
    let public_pending = &runtime.public_io.setup().pending;
    let check = || {
        operation.check().map_err(|error| match error {
            owner_domain::Error::Deadline => lomi_host_http::BudgetStop::Deadline,
            _ => lomi_host_http::BudgetStop::Cancelled,
        })?;
        if gate.load(Ordering::Acquire)
            || paused.load(Ordering::Acquire)
            || stopping.load(Ordering::Acquire)
            || public_pending.load(Ordering::Acquire)
            || !continuation.is_current(operation)
        {
            return Err(lomi_host_http::BudgetStop::Cancelled);
        }
        Ok(())
    };
    check().map_err(|_| StepError::Stale)?;
    let wall_at_start = runtime
        .base
        .checked_add(runtime.anchor.elapsed().as_secs())
        .ok_or(StepError::Stale)?;
    let request_started = Instant::now();
    if request_started >= deadline {
        return Err(StepError::Stale);
    }
    let response = transport
        .with_budget(deadline, &check)
        .pairing_get(continuation.source().intent.preparation.pairing_id, &access)
        .map_err(|_| StepError::Stale)?;
    check().map_err(|_| StepError::Stale)?;
    let now_wall = runtime
        .base
        .checked_add(runtime.anchor.elapsed().as_secs())
        .ok_or(StepError::Stale)?;
    started_git_auth_snapshot(auth, runtime, continuation, now_wall)?;
    match runtime
        .owner
        .started_git_pairing_source_current(operation, continuation)
        .map_err(|_| StepError::Stale)?
    {
        Some(true) => {}
        None => return Ok(false),
        Some(false) => return Err(StepError::Stale),
    }

    let PairingResult::Approved {
        pairing_id,
        proposal,
        grant,
        identities,
        authority: current,
    } = response
    else {
        return Err(StepError::Stale);
    };
    let source = continuation.source();
    let preparation = &source.intent.preparation;
    let PairingDecisionParams::Approve {
        grant: original, ..
    } = &preparation.params
    else {
        return Err(StepError::Stale);
    };
    let host = auth
        .public_host_identity(wall_at_start)
        .map_err(|_| StepError::Stale)?;
    if pairing_id != preparation.pairing_id
        || proposal != preparation.proposal
        || grant != *original
        || identities != preparation.proposal.identities
        || identities.host != host.identity
        || pin(&identities.host_fingerprint).map_err(|_| StepError::Stale)? != host.fingerprint
        || preparation.scope.runtime_scope != expected.scope
        || preparation.scope.runtime != expected.server_runtime
        || current.terminal_membership.is_some()
    {
        return Err(StepError::Stale);
    }
    let signed = SignedGrantV3::from_wire(&grant).map_err(|_| StepError::Stale)?;
    let consumer = verify_consumer_window_identity(
        &identities.consumer,
        host.account_id.to_bytes(),
        preparation.window_identity_id.to_bytes(),
    )
    .map_err(|_| StepError::Stale)?;
    let consumer_pin = pin(&identities.consumer_fingerprint).map_err(|_| StepError::Stale)?;
    let authority = CurrentAuthorityV3 {
        host_authorization_id: current.host_authorization_id.to_bytes(),
        consumer_authorization_id: current.consumer_authorization_id.to_bytes(),
        account_session_id: current.account_session_id.as_str().to_owned(),
        access_epoch: current.access_epoch.0,
        grant_revision: current.grant_revision.0,
        workspace_epoch: current.workspace_epoch.to_bytes(),
        runtime_id: current.runtime_id.to_bytes(),
        runtime_generation: current.runtime_generation.0,
        terminal_membership: None,
    };
    if authority != *continuation.authority()
        || signed.grant.grant_id != preparation.grant_id.to_bytes()
        || signed.grant.workspace_id != preparation.scope.workspace_id.to_bytes()
        || signed.grant.workspace_epoch != preparation.scope.workspace_epoch.to_bytes()
        || signed.grant.expires_at != preparation.original_expires_at
    {
        return Err(StepError::Stale);
    }
    signed
        .verify(
            &signed.grant,
            &SignedBundle::from_wire(&host.identity).map_err(|_| StepError::Stale)?,
            &host.fingerprint,
            &consumer,
            &consumer_pin,
            &authority,
            wall_at_start,
        )
        .map_err(|_| StepError::Stale)?;
    check().map_err(|_| StepError::Stale)?;

    let heartbeat_deadline = heartbeat
        .request_started
        .checked_add(Duration::from_millis(heartbeat.freshness_ms))
        .ok_or(StepError::Stale)?
        .min(
            heartbeat
                .request_started
                .checked_add(Duration::from_millis(heartbeat.lease_ms))
                .ok_or(StepError::Stale)?,
        );
    let wall_limit = preparation
        .original_expires_at
        .min(continuation.credential_deadlines().access_expires_at)
        .min(continuation.credential_deadlines().refresh_at);
    let wall_remaining = wall_limit
        .checked_sub(wall_at_start)
        .ok_or(StepError::Stale)?;
    let peer_expiry = request_started
        .checked_add(Duration::from_secs(5))
        .ok_or(StepError::Stale)?
        .min(heartbeat_deadline)
        .min(
            request_started
                .checked_add(Duration::from_secs(wall_remaining))
                .ok_or(StepError::Stale)?,
        )
        .min(continuation.hard_deadline())
        .min(operation.deadline());
    if Instant::now() >= peer_expiry {
        return Err(StepError::Stale);
    }
    continuation
        .renew_peer_observation(operation, request_started, peer_expiry)
        .map_err(|_| StepError::Stale)?;
    Ok(true)
}

/// Revalidate a different, already established channel during the exact
/// Started Git writer. This returns a channel-bound observation only; callers
/// must not use it to admit or refresh a channel.
pub(super) fn refresh_established_started_git_pairing(
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    runtime: RuntimeWithOperation<'_, '_>,
    active: &shared_owner::StartedGitContinuation,
    target: StartedGitPairingTarget,
) -> Result<Option<StartedGitPeerObservation>, StepError> {
    let operation = runtime.operation;
    if auth.status() != Status::Ready
        || runtime.check().is_err()
        || !active.is_current(operation)
        || target.scope != active.runtime().scope
        || target.context.grant.runtime_id != active.runtime().server_runtime.runtime_id.to_bytes()
        || target.context.grant.runtime_generation
            != active.runtime().server_runtime.runtime_generation.0
        || target.context.grant.access_epoch != active.runtime().server_runtime.host_access_epoch.0
        || target.signed_grant.grant != target.context.grant
    {
        return Err(StepError::Stale);
    }
    match runtime
        .owner
        .cloud_publication_fence_observation_started_git(
            operation,
            active,
            active.runtime().scope.authorization_generation,
            Some(&active.runtime().scope),
        )
        .map_err(|_| StepError::Stale)?
    {
        shared_owner::CloudPublicationFenceObservation::Clear => {}
        shared_owner::CloudPublicationFenceObservation::Defer => return Ok(None),
        shared_owner::CloudPublicationFenceObservation::CloseIngress => {
            return Err(StepError::Stale);
        }
    }
    let source = match runtime
        .owner
        .started_git_pairing_source_for_target(operation, active, &target)
    {
        Ok(source) => source,
        Err(shared_owner::Error::Domain(owner_domain::Error::Busy))
        | Err(shared_owner::Error::Store(StoreError::Busy)) => return Ok(None),
        Err(_) => return Err(StepError::Stale),
    };
    let trusted = auth.trusted_configuration();
    let origin = RemoteApiOrigin::new(trusted, target.origin.as_str().to_owned())?;
    let transport = runtime.public_io.data_transport(origin)?;
    let now_wall = runtime
        .base
        .checked_add(runtime.anchor.elapsed().as_secs())
        .ok_or(StepError::Stale)?;
    started_git_auth_snapshot(auth, runtime, active, now_wall)?;
    let access = auth
        .access_credential(now_wall)
        .map_err(|_| StepError::Stale)?;
    let heartbeat = active.heartbeat().ok_or(StepError::Stale)?;
    if heartbeat.scope != active.runtime().scope
        || heartbeat.runtime != active.runtime().server_runtime
    {
        return Err(StepError::Stale);
    }
    let deadline = operation
        .deadline()
        .min(active.hard_deadline())
        .min(active.heartbeat_deadline())
        .min(active.peer_deadline());
    let gate = runtime.gate;
    let paused = runtime.paused;
    let stopping = runtime.stopping;
    let public_pending = &runtime.public_io.setup().pending;
    let check = || {
        operation.check().map_err(|error| match error {
            owner_domain::Error::Deadline => lomi_host_http::BudgetStop::Deadline,
            _ => lomi_host_http::BudgetStop::Cancelled,
        })?;
        if gate.load(Ordering::Acquire)
            || paused.load(Ordering::Acquire)
            || stopping.load(Ordering::Acquire)
            || public_pending.load(Ordering::Acquire)
            || !active.is_current(operation)
        {
            return Err(lomi_host_http::BudgetStop::Cancelled);
        }
        Ok(())
    };
    check().map_err(|_| StepError::Stale)?;
    let wall_at_start = runtime
        .base
        .checked_add(runtime.anchor.elapsed().as_secs())
        .ok_or(StepError::Stale)?;
    let request_started = Instant::now();
    if request_started >= deadline {
        return Err(StepError::Stale);
    }
    let response = transport
        .with_budget(deadline, &check)
        .pairing_get(source.intent.preparation.pairing_id, &access)
        .map_err(|_| StepError::Stale)?;
    check().map_err(|_| StepError::Stale)?;
    started_git_auth_snapshot(
        auth,
        runtime,
        active,
        runtime
            .base
            .checked_add(runtime.anchor.elapsed().as_secs())
            .ok_or(StepError::Stale)?,
    )?;
    match runtime
        .owner
        .cloud_publication_fence_observation_started_git(
            operation,
            active,
            active.runtime().scope.authorization_generation,
            Some(&active.runtime().scope),
        )
        .map_err(|_| StepError::Stale)?
    {
        shared_owner::CloudPublicationFenceObservation::Clear => {}
        shared_owner::CloudPublicationFenceObservation::Defer => return Ok(None),
        shared_owner::CloudPublicationFenceObservation::CloseIngress => {
            return Err(StepError::Stale);
        }
    }
    let source_after = match runtime
        .owner
        .started_git_pairing_source_for_target(operation, active, &target)
    {
        Ok(source) => source,
        Err(shared_owner::Error::Domain(owner_domain::Error::Busy))
        | Err(shared_owner::Error::Store(StoreError::Busy)) => return Ok(None),
        Err(_) => return Err(StepError::Stale),
    };
    if source_after != source {
        return Err(StepError::Stale);
    }
    let PairingResult::Approved {
        pairing_id,
        proposal,
        grant,
        identities,
        authority: current,
    } = response
    else {
        return Err(StepError::Stale);
    };
    let preparation = &source.intent.preparation;
    let PairingDecisionParams::Approve {
        grant: original, ..
    } = &preparation.params
    else {
        return Err(StepError::Stale);
    };
    if pairing_id != preparation.pairing_id
        || proposal != preparation.proposal
        || grant != *original
        || identities != preparation.proposal.identities
        || preparation.scope.runtime_scope != target.scope
        || preparation.scope.runtime != active.runtime().server_runtime
        || preparation.scope.workspace_id.to_bytes() != target.context.grant.workspace_id
        || current.terminal_membership.is_some()
    {
        return Err(StepError::Stale);
    }
    let host = auth
        .public_host_identity(wall_at_start)
        .map_err(|_| StepError::Stale)?;
    if identities.host != host.identity
        || pin(&identities.host_fingerprint).map_err(|_| StepError::Stale)? != host.fingerprint
    {
        return Err(StepError::Stale);
    }
    let signed = SignedGrantV3::from_wire(&grant).map_err(|_| StepError::Stale)?;
    if signed != target.signed_grant {
        return Err(StepError::Stale);
    }
    let consumer = verify_consumer_window_identity(
        &identities.consumer,
        host.account_id.to_bytes(),
        preparation.window_identity_id.to_bytes(),
    )
    .map_err(|_| StepError::Stale)?;
    let consumer_pin = pin(&identities.consumer_fingerprint).map_err(|_| StepError::Stale)?;
    let authority = CurrentAuthorityV3 {
        host_authorization_id: current.host_authorization_id.to_bytes(),
        consumer_authorization_id: current.consumer_authorization_id.to_bytes(),
        account_session_id: current.account_session_id.as_str().to_owned(),
        access_epoch: current.access_epoch.0,
        grant_revision: current.grant_revision.0,
        workspace_epoch: current.workspace_epoch.to_bytes(),
        runtime_id: current.runtime_id.to_bytes(),
        runtime_generation: current.runtime_generation.0,
        terminal_membership: None,
    };
    let mut expected_authority = target.authority.clone();
    expected_authority.terminal_membership = None;
    if authority != expected_authority
        || signed.grant.grant_id != preparation.grant_id.to_bytes()
        || signed.grant.workspace_id != preparation.scope.workspace_id.to_bytes()
        || signed.grant.workspace_epoch != preparation.scope.workspace_epoch.to_bytes()
        || signed.grant.expires_at != preparation.original_expires_at
    {
        return Err(StepError::Stale);
    }
    signed
        .verify(
            &signed.grant,
            &SignedBundle::from_wire(&host.identity).map_err(|_| StepError::Stale)?,
            &host.fingerprint,
            &consumer,
            &consumer_pin,
            &authority,
            wall_at_start,
        )
        .map_err(|_| StepError::Stale)?;
    check().map_err(|_| StepError::Stale)?;
    let heartbeat_deadline = heartbeat
        .request_started
        .checked_add(Duration::from_millis(heartbeat.freshness_ms))
        .ok_or(StepError::Stale)?
        .min(
            heartbeat
                .request_started
                .checked_add(Duration::from_millis(heartbeat.lease_ms))
                .ok_or(StepError::Stale)?,
        );
    let wall_limit = preparation
        .original_expires_at
        .min(active.credential_deadlines().access_expires_at)
        .min(active.credential_deadlines().refresh_at);
    let wall_remaining = wall_limit
        .checked_sub(wall_at_start)
        .ok_or(StepError::Stale)?;
    let fresh_until = request_started
        .checked_add(Duration::from_secs(5))
        .ok_or(StepError::Stale)?
        .min(heartbeat_deadline)
        .min(
            request_started
                .checked_add(Duration::from_secs(wall_remaining))
                .ok_or(StepError::Stale)?,
        )
        .min(active.hard_deadline())
        .min(operation.deadline());
    if Instant::now() >= fresh_until || !active.is_current(operation) {
        return Err(StepError::Stale);
    }
    Ok(Some(StartedGitPeerObservation {
        active: active.clone(),
        target,
        source,
        fresh_until,
    }))
}

fn started_git_auth_snapshot(
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    runtime: RuntimeWithOperation<'_, '_>,
    continuation: &shared_owner::StartedGitContinuation,
    now: u64,
) -> Result<
    (
        shared_owner::AuthStatusSnapshot,
        shared_owner::AuthSelectionSnapshot,
    ),
    StepError,
> {
    if auth.status() != Status::Ready || !continuation.is_current(runtime.operation) {
        return Err(StepError::Stale);
    }
    let status = runtime
        .owner
        .auth_status_started_git(runtime.operation, continuation)
        .map_err(|_| StepError::Stale)?;
    let selection = runtime
        .owner
        .auth_selection_started_git(runtime.operation, continuation)
        .map_err(|_| StepError::Stale)?;
    let identity = auth
        .public_host_identity(now)
        .map_err(|_| StepError::Stale)?;
    let epoch = auth
        .verified_host_access_epoch()
        .map_err(|_| StepError::Stale)?;
    let deadlines = auth.credential_deadlines().map_err(|_| StepError::Stale)?;
    if status.authorization.generation != continuation.runtime().scope.authorization_generation
        || status.authorization.locked
        || status.authorization.pending_cloud_revoke
        || selection.verified_generation != Some(status.authorization.generation)
        || selection.configuration.as_ref() != Some(continuation.credential_configuration())
        || selection.identity != *continuation.store_identity()
        || identity != *continuation.identity()
        || epoch.0 != continuation.runtime().server_runtime.host_access_epoch.0
        || deadlines != continuation.credential_deadlines()
        || now >= deadlines.access_expires_at
        || now >= deadlines.refresh_at
    {
        return Err(StepError::Stale);
    }
    Ok((status, selection))
}
