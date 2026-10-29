//! Owner channel admission only; historical journal ACKs never authorize a live
//! channel. Established-channel lifetime belongs to the future data-plane gate.
use super::*;
use cloud::PeerEligibility;
use lomi_host_auth::peer_policy::{GrantNarrowing, PolicyClock, PreparedChannel};
use lomi_host_http::{DataTransport, RemoteApiOrigin};
use lomi_host_store::{
    AcknowledgedWorkspaceGrant, ChannelAdmissionIntent, ChannelAdmissionPreparation,
    CloudPairingScope, CloudRuntimeScope,
};
use lomi_remote_crypto::{
    ChannelContextV3, ChannelPurposeV3, CurrentAuthorityV3, SignedBundle, SignedChannelAdmissionV3,
    SignedGrantV3, TerminalTargetV3,
};
use lomi_remote_protocol::{http::*, *};
use peer::{
    Observation, PeerError, ProviderCapture, ResultPeer, check_peer_runtime, crypt, hex_bytes,
    managed, owner_error, owner_turn, pin, policy,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(super) trait ChannelApi {
    fn pending(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<ChannelPendingResult, lomi_host_http::Error>;
    fn get(
        &self,
        id: ChannelId,
        access: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error>;
    fn admit(
        &self,
        id: ChannelId,
        params: &ChannelAdmissionParams,
        access: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error>;
}
impl ChannelApi for lomi_host_http::BudgetDataTransport<'_> {
    fn pending(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<ChannelPendingResult, lomi_host_http::Error> {
        self.channel_pending(host, access)
    }
    fn get(
        &self,
        id: ChannelId,
        access: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error> {
        self.channel_get(id, access)
    }
    fn admit(
        &self,
        id: ChannelId,
        params: &ChannelAdmissionParams,
        access: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error> {
        self.channel_admission(id, params, access)
    }
}
/// Move-only provenance from this worker's successful live ACK. A durable ACK
/// enumeration cannot construct it, and possession never grants ongoing access.
/// The original observation's sealed continuation also pins the actual owner.
pub(in super::super) struct AdmittedChannelHandoff {
    prepared: PreparedChannel,
    scope: CloudPairingScope,
    source: AcknowledgedWorkspaceGrant,
    target: ChannelTarget,
    acknowledgement: lomi_host_store::AcknowledgedChannelAdmission,
    trusted: Config,
    signed_grant: SignedGrantV3,
    admission: SignedChannelAdmissionV3,
    observation: Arc<Observation>,
    operation: owner_domain::OperationIdentity,
    deadline: Instant,
}
impl AdmittedChannelHandoff {
    pub(in super::super) fn acknowledgement(
        &self,
    ) -> &lomi_host_store::AcknowledgedChannelAdmission {
        &self.acknowledgement
    }
    pub(in super::super) fn source(&self) -> &AcknowledgedWorkspaceGrant {
        &self.source
    }
    pub(in super::super) fn observation(&self) -> &Arc<Observation> {
        &self.observation
    }
    pub(super) fn canonical_context(&self) -> &[u8] {
        self.prepared.canonical()
    }
    pub(super) fn signed_grant(&self) -> &SignedGrantV3 {
        &self.signed_grant
    }
    pub(super) fn signed_admission(&self) -> &SignedChannelAdmissionV3 {
        &self.admission
    }
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(super) fn channel_id(&self) -> ChannelId {
        self.acknowledgement.intent.preparation.channel_id
    }
    pub(super) fn ticket_params(&self) -> ChannelTicketParams {
        ChannelTicketParams {
            runtime: self.scope.runtime.clone(),
            window_identity_id: None,
        }
    }
    // Only an actual live ACK handoff can mint this private-field named binding.
    // Shared independently checks its original owner's continuation and Store.
    pub(in super::super) fn ticket_binding(
        &self,
        operation: &owner_domain::Operation<'_>,
        eligibility: &PeerEligibility,
    ) -> Option<ChannelTicketBinding> {
        if operation.check().is_err()
            || !operation.is_same_admission(&self.operation)
            || Instant::now() >= self.deadline
            || !self.observation.current(eligibility)
            || self.scope.runtime_scope != eligibility.binding.scope
            || self.scope.runtime != eligibility.binding.server_runtime
        {
            return None;
        }
        Some(ChannelTicketBinding {
            acknowledgement: self.acknowledgement().clone(),
            source: self.source().clone(),
            scope: self.scope.clone(),
            trusted: self.trusted.clone(),
            deadline: self.deadline,
        })
    }
    pub(super) fn check_current(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
    ) -> ResultPeer<()> {
        check_peer_runtime(runtime)?;
        if !runtime.operation.is_same_admission(&self.operation)
            || Instant::now() >= self.deadline
            || !self.observation.current(eligibility)
            || !self.observation.current_operation(runtime)
            || self.scope.runtime_scope != eligibility.binding.scope
            || self.scope.runtime != eligibility.binding.server_runtime
            || self.source.intent.preparation.scope != self.scope
            || auth.trusted_configuration() != &self.trusted
        {
            return Err(PeerError::Invalid);
        }
        let now = peer::Worker::default().live(auth, runtime, eligibility)?;
        let context = self.prepared.context();
        let ChannelResult::Admitted {
            channel_id,
            inputs,
            admission,
        } = &self.acknowledgement.response
        else {
            return Err(PeerError::Invalid);
        };
        if channel_id.to_bytes() != context.channel_id
            || context.grant != self.signed_grant.grant
            || now >= context.expires_at
            || self.prepared.canonical() != hex_bytes(inputs.expected_context.expose_wire())?
            || crypt(self.signed_grant.to_wire())? != inputs.grant
            || crypt(self.admission.to_wire())? != *admission
            || target(context)? != self.target
            || self.scope.workspace_id.to_bytes() != context.grant.workspace_id
            || self.scope.workspace_epoch.to_bytes() != context.grant.workspace_epoch
            || self.source.intent.preparation.grant_id.to_bytes() != context.grant.grant_id
            || !matches!(&self.source.response, PairingResult::Approved { grant, .. } if *grant == inputs.grant)
        {
            return Err(PeerError::Invalid);
        }
        verify_wire(inputs, admission, &eligibility.identity, now)?;
        check_peer_runtime(runtime)?;
        if !self.observation.current(eligibility)
            || !self.observation.current_operation(runtime)
            || Instant::now() >= self.deadline
        {
            return Err(PeerError::Invalid);
        }
        Ok(())
    }
}

/// Sealed named ticket read/effect binding; neither ACK enumeration nor a public
/// snapshot can construct it. Public immutable rows are retained for exact joins.
pub(in super::super) struct ChannelTicketBinding {
    acknowledgement: lomi_host_store::AcknowledgedChannelAdmission,
    source: AcknowledgedWorkspaceGrant,
    scope: CloudPairingScope,
    trusted: Config,
    deadline: Instant,
}
impl ChannelTicketBinding {
    pub(in super::super) fn acknowledgement(
        &self,
    ) -> &lomi_host_store::AcknowledgedChannelAdmission {
        &self.acknowledgement
    }
    pub(in super::super) fn source(&self) -> &AcknowledgedWorkspaceGrant {
        &self.source
    }
    pub(in super::super) fn scope(&self) -> &CloudPairingScope {
        &self.scope
    }
    pub(in super::super) fn trusted(&self) -> &Config {
        &self.trusted
    }
    pub(in super::super) fn deadline(&self) -> Instant {
        self.deadline
    }
}

struct Work {
    id: ChannelId,
    inputs: ChannelAdmissionInputs,
    observation: Arc<Observation>,
    intent: Option<ChannelAdmissionIntent>,
}
#[cfg(test)]
type SnapshotHook = Box<dyn FnOnce(u64, Runtime<'_>)>;

#[derive(Default)]
pub(super) struct Worker {
    trust: peer::Worker,
    transport: Option<DataTransport>,
    scope: Option<CloudRuntimeScope>,
    clock: Option<PolicyClock>,
    cache: VecDeque<Work>,
    active: Option<Work>,
    // This sole worker is the reservation owner; never overwrite a live output.
    pending_handoff: Option<AdmittedChannelHandoff>,
    poll_at: Option<Instant>,
    failures: u32,
    parked: BTreeMap<String, Instant>,
    cursor: Option<String>,
    proposal_cursor: Option<ChannelId>,
    retire_cursor: usize,
    cleanup_cursor: usize,
    turns_since_poll: u32,
    prefer_recovery: bool,
    capacity_blocked: bool,
    #[cfg(test)]
    after_snapshot: Option<SnapshotHook>,
    #[cfg(test)]
    after_sign: Option<Box<dyn FnOnce()>>,
    #[cfg(test)]
    before_prepare_lock: Option<Box<dyn FnOnce()>>,
    #[cfg(test)]
    before_ack_lock: Option<Box<dyn FnOnce()>>,
}
impl Worker {
    pub(super) fn discard_retained_operation(&mut self) {
        self.active = None;
        self.cache.clear();
        self.pending_handoff = None;
    }
    pub(super) fn take_admitted(&mut self) -> Option<AdmittedChannelHandoff> {
        self.pending_handoff.take()
    }
    pub(super) fn has_retained_operation(&self) -> bool {
        self.active.is_some() || !self.cache.is_empty() || self.pending_handoff.is_some()
    }

    pub(super) fn step(
        &mut self,
        auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        injected: Option<&dyn ChannelApi>,
    ) -> Result<(), StepError> {
        if let Some(api) = injected {
            return self.step_using(auth, config, runtime, eligibility, api);
        }
        if self.scope.as_ref() != Some(&eligibility.binding.scope) {
            self.transport = None;
        }
        if self.transport.is_none() {
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
        let transport = self.transport.take().expect("channel adapter");
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
        api: &dyn ChannelApi,
    ) -> Result<(), StepError> {
        if self.scope.as_ref() != Some(&eligibility.binding.scope) {
            self.scope = Some(eligibility.binding.scope.clone());
            self.cache.clear();
            self.active = None;
            self.pending_handoff = None;
            self.poll_at = None;
            self.parked.clear();
            self.cursor = None;
            self.proposal_cursor = None;
            self.prefer_recovery = false;
            self.failures = 0;
            // Preserve the nondecreasing policy clock across scope changes.
        }
        if let Some(handoff) = &self.pending_handoff {
            if handoff.check_current(auth, runtime, eligibility).is_ok() {
                return Ok(());
            }
            self.pending_handoff = None;
        }
        match self.turn(auth, config, runtime, eligibility, api) {
            Ok(()) => Ok(()),
            Err(PeerError::Fatal(error)) => {
                self.active = None;
                self.cache.clear();
                self.pending_handoff = None;
                Err(error)
            }
            Err(PeerError::Invalid) => {
                self.trust
                    .live(auth, runtime, eligibility)
                    .map_err(|error| match error {
                        PeerError::Fatal(e) => e,
                        PeerError::Invalid => StepError::Stale,
                    })?;
                self.active = None;
                self.backoff();
                Ok(())
            }
        }
    }
    fn backoff(&mut self) {
        self.failures = self.failures.saturating_add(1).min(5);
        self.poll_at = Some(Instant::now() + Duration::from_secs((1u64 << self.failures).min(30)));
    }
    fn turn(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn ChannelApi,
    ) -> ResultPeer<()> {
        // The clock must use Runtime's original wall/monotonic pair. Sampling
        // `live()` (whole seconds) against a fresh `Instant::now()` drops the
        // fractional second and fails closed with a false ClockRollback once
        // the authenticated heartbeat crosses that boundary.
        self.trust.live(auth, runtime, eligibility)?;
        if self.clock.is_none() {
            self.clock = Some(policy(PolicyClock::new(runtime.base, runtime.anchor))?);
        }
        let pending = owner_turn(runtime, || {
            runtime
                .owner
                .peer_pending_channels(runtime.operation, eligibility)
        })?;
        self.parked
            .retain(|token, _| pending.iter().any(|p| &p.token == token));
        self.turns_since_poll = self.turns_since_poll.saturating_add(1);
        if self.turns_since_poll >= 4 && self.poll_at.is_none_or(|at| Instant::now() >= at) {
            return self.poll(auth, runtime, eligibility, api, &pending);
        }
        if let Some(work) = self.active.take() {
            if !work.observation.current(eligibility)
                || !work.observation.current_operation(runtime)
            {
                return Ok(());
            }
            return self.send(auth, config, runtime, eligibility, api, work);
        }
        if self.prefer_recovery
            && self.recover_one(auth, config, runtime, eligibility, api, &pending)?
        {
            self.prefer_recovery = false;
            return Ok(());
        }
        if let Some(work) = self.cache.pop_front() {
            self.prefer_recovery = true;
            self.proposal_cursor = Some(work.id);
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
        if self.poll_at.is_some_and(|at| Instant::now() < at) {
            return Ok(());
        }
        self.poll(auth, runtime, eligibility, api, &pending)
    }
    fn poll(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn ChannelApi,
        pending: &[ChannelAdmissionIntent],
    ) -> ResultPeer<()> {
        let now = self.trust.live(auth, runtime, eligibility)?;
        let mut effect = owner_turn(runtime, || {
            runtime.owner.capture_peer_effect(
                runtime.operation,
                eligibility,
                shared_owner::PeerEffect::ChannelPending(eligibility.identity.host_id),
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
        self.trust.live(auth, runtime, eligibility)?;
        let Ok(response) = response else {
            self.backoff();
            return Ok(());
        };
        let observation = Arc::new(Observation::new(
            eligibility,
            started,
            effect.continuation(),
        ));
        if !observation.current(eligibility) {
            return Ok(());
        }
        let proposals = response.channels.as_slice();
        let mut seen = BTreeSet::new();
        if proposals.len() > 64 || proposals.iter().any(|p| !seen.insert(p.channel_id)) {
            return Err(PeerError::Invalid);
        }
        self.cache.clear();
        let start = self
            .proposal_cursor
            .and_then(|id| proposals.iter().position(|p| p.channel_id == id))
            .map_or(0, |i| (i + 1) % proposals.len().max(1));
        for offset in 0..proposals.len() {
            let p = &proposals[(start + offset) % proposals.len()];
            if pending
                .iter()
                .any(|i| i.preparation.channel_id == p.channel_id)
            {
                continue;
            }
            self.cache.push_back(Work {
                id: p.channel_id,
                inputs: p.inputs.clone(),
                observation: observation.clone(),
                intent: None,
            });
        }
        self.failures = 0;
        Ok(())
    }
    // Fresh authenticated TLS inputs independently supply current identities,
    // pins and authority. The journal contributes ONLY original maximum/wire.
    fn reconstruct(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        work: &Work,
    ) -> ResultPeer<(
        PreparedChannel,
        CloudPairingScope,
        AcknowledgedWorkspaceGrant,
        ChannelTarget,
    )> {
        self.trust.live(auth, runtime, eligibility)?;
        if !work.observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        let signed = crypt(SignedGrantV3::from_wire(&work.inputs.grant))?;
        let context = crypt(ChannelContextV3::from_canonical(&hex_bytes(
            work.inputs.expected_context.expose_wire(),
        )?))?;
        if context.grant != signed.grant || context.channel_id != work.id.to_bytes() {
            return Err(PeerError::Invalid);
        }
        let grants = owner_turn(runtime, || {
            runtime
                .owner
                .peer_workspace_grants(runtime.operation, eligibility)
        })?;
        let mut matching = grants.into_iter().filter(|g| {
            g.intent.preparation.grant_id.to_bytes() == signed.grant.grant_id
                && work
                    .intent
                    .as_ref()
                    .is_none_or(|i| i.preparation.source_grant_token == g.intent.token)
        });
        let source = matching.next().ok_or(PeerError::Invalid)?;
        if matching.next().is_some() {
            return Err(PeerError::Invalid);
        }
        let original = &source.intent.preparation;
        let PairingResult::Approved {
            pairing_id,
            proposal,
            grant,
            identities,
            authority,
        } = &source.response
        else {
            return Err(PeerError::Invalid);
        };
        let mut current_workspace = work.inputs.authority.clone();
        current_workspace.terminal_membership = None;
        if *pairing_id != original.pairing_id
            || *proposal != original.proposal
            || *grant != work.inputs.grant
            || *identities != work.inputs.identities
            || *authority != current_workspace
            || original.scope.runtime_scope != eligibility.binding.scope
            || original.scope.runtime != eligibility.binding.server_runtime
            || original.original_expires_at != signed.grant.expires_at
        {
            return Err(PeerError::Invalid);
        }
        if let Some(intent) = &work.intent
            && (intent.preparation.source_grant_token != source.intent.token
                || intent.preparation.source_grant_id != original.grant_id
                || intent.preparation.inputs != work.inputs
                || intent.preparation.channel_id != work.id)
        {
            return Err(PeerError::Invalid);
        }
        let pairing_work = peer::Work {
            pairing: original.pairing_id,
            proposal: PairingProposal {
                maximum_grant: original.proposal.maximum_grant.clone(),
                identities: work.inputs.identities.clone(),
                authority: current_workspace,
            },
            observation: work.observation.clone(),
            intent: None,
        };
        let (snapshot, _, scope, _snapshot_now) = self.trust.snapshot_with_ceiling(
            auth,
            config,
            runtime,
            eligibility,
            &pairing_work,
            Some(signed.grant.expires_at),
        )?;
        #[cfg(test)]
        if let Some(hook) = self.after_snapshot.take() {
            hook(_snapshot_now, runtime);
        }
        if scope != original.scope {
            return Err(PeerError::Invalid);
        }
        let maximum = hex_bytes(original.proposal.maximum_grant.expose_wire())?;
        let now = self.trust.live(auth, runtime, eligibility)?;
        let prepared = policy(snapshot.prepare_grant(
            &maximum,
            GrantNarrowing {
                capabilities: signed.grant.capabilities.clone(),
                expires_at: signed.grant.expires_at,
            },
            self.clock.as_mut().expect("channel clock"),
            now,
            Instant::now(),
        ))?;
        if prepared.grant() != &signed.grant
            || prepared.canonical() != hex_bytes(grant.canonical_cbor.expose_wire())?
        {
            return Err(PeerError::Invalid);
        }
        let now = self.trust.live(auth, runtime, eligibility)?;
        let approved = policy(snapshot.retain_approved_grant(
            &prepared,
            signed,
            self.clock.as_mut().expect("channel clock"),
            now,
            Instant::now(),
        ))?;
        let mut full_work = pairing_work;
        full_work.proposal.authority = work.inputs.authority.clone();
        let (snapshot, _, full_scope, _) = self.trust.snapshot_with_ceiling(
            auth,
            config,
            runtime,
            eligibility,
            &full_work,
            Some(context.grant.expires_at),
        )?;
        if full_scope != scope {
            return Err(PeerError::Invalid);
        }
        let now = self.trust.live(auth, runtime, eligibility)?;
        let prepared = policy(snapshot.prepare_channel(
            &approved,
            &hex_bytes(work.inputs.expected_context.expose_wire())?,
            self.clock.as_mut().expect("channel clock"),
            now,
            Instant::now(),
        ))?;
        let target = target(&context)?;
        // Validate profile/session before signing as well as in the final Store
        // transaction. Policy matches ACK+local IDs; Store also binds profiles.
        if let ChannelTarget::Terminal {
            pane_id,
            session_id,
            session_epoch,
            ..
        } = target
        {
            let local = owner_turn(runtime, || {
                runtime
                    .owner
                    .peer_workspace(runtime.operation, eligibility, scope.workspace_id)
            })?
            .workspace;
            context.terminal.as_ref().ok_or(PeerError::Invalid)?;
            let mut layouts: Vec<_> = local.state.tabs.0.iter().map(|t| &t.layout).collect();
            let mut found = false;
            while let Some(layout) = layouts.pop() {
                match layout {
                    lomi_remote_protocol::rpc::TerminalLayout::Split { first, second, .. } => {
                        layouts.push(first);
                        layouts.push(second);
                    }
                    lomi_remote_protocol::rpc::TerminalLayout::Pane { pane } => {
                        if pane.pane_id == pane_id
                            && pane.state == lomi_remote_protocol::rpc::PaneState::Running
                        {
                            found = pane.session.as_ref().is_some_and(|s| {
                                s.session_id == session_id
                                    && s.session_epoch == session_epoch
                                    && work
                                        .inputs
                                        .authority
                                        .terminal_membership
                                        .as_ref()
                                        .is_some_and(|m| m.terminal_profile == s.profile)
                                    && s.workspace == local.state.context
                            });
                        }
                    }
                }
            }
            if !found {
                return Err(PeerError::Invalid);
            }
        }
        Ok((prepared, scope, source, target))
    }
    fn prepare(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        mut work: Work,
    ) -> ResultPeer<()> {
        let (prepared, scope, source, target) =
            self.reconstruct(auth, config, runtime, eligibility, &work)?;
        let now = self.trust.live(auth, runtime, eligibility)?;
        let admission = managed(auth.sign_channel_admission_v3(prepared.context(), now))?;
        #[cfg(test)]
        if let Some(hook) = self.after_sign.take() {
            hook();
        }
        let wire = crypt(admission.to_wire())?;
        self.verify_admission(auth, runtime, eligibility, &work, &wire)?;
        let p = ChannelAdmissionPreparation {
            scope,
            channel_id: work.id,
            source_grant_id: source.intent.preparation.grant_id,
            source_grant_token: source.intent.token,
            target,
            inputs: work.inputs.clone(),
            issued_at: prepared.context().issued_at,
            expires_at: prepared.context().expires_at,
            params: ChannelAdmissionParams {
                runtime: eligibility.binding.server_runtime.clone(),
                admission: wire,
            },
        };
        #[cfg(test)]
        if let Some(hook) = self.before_prepare_lock.take() {
            hook();
        }
        let provider = ProviderCapture::read(auth, runtime, eligibility)?;
        let capture = owner_turn(runtime, || {
            runtime.owner.capture_peer_journal(
                runtime.operation,
                eligibility,
                &provider,
                Some(&work.observation),
                p.scope.workspace_id,
                runtime.base,
                runtime.anchor,
            )
        })?;
        let mut turn = capture
            .begin_prepare_channel_admission(p)
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
        self.trust.live(auth, runtime, eligibility)?;
        work.intent = Some(intent);
        self.active = Some(work);
        Ok(())
    }
    fn verify_admission(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        work: &Work,
        wire: &SignedChannelAdmissionWire,
    ) -> ResultPeer<()> {
        let now = self.trust.live(auth, runtime, eligibility)?;
        if !work.observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        verify_wire(&work.inputs, wire, &eligibility.identity, now)?;
        self.trust.live(auth, runtime, eligibility)?;
        if !work.observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        Ok(())
    }
    fn send(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn ChannelApi,
        work: Work,
    ) -> ResultPeer<()> {
        self.reconstruct(auth, config, runtime, eligibility, &work)?;
        let intent = work.intent.as_ref().ok_or(PeerError::Invalid)?;
        self.verify_admission(
            auth,
            runtime,
            eligibility,
            &work,
            &intent.preparation.params.admission,
        )?;
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
            .begin_check_channel_admission_send(intent.clone())
            .map_err(owner_error)?;
        owner_turn(runtime, || turn.try_commit())?;
        let now = self.trust.live(auth, runtime, eligibility)?;
        if !work.observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        let mut effect = owner_turn(runtime, || {
            runtime.owner.capture_peer_effect(
                runtime.operation,
                eligibility,
                shared_owner::PeerEffect::ChannelSend(intent.clone()),
                Some(&work.observation),
                runtime.base,
                runtime.anchor,
            )
        })?;
        let access = managed(auth.access_credential(now))?;
        let provider = ProviderCapture::read(auth, runtime, eligibility)?;
        owner_turn(runtime, || effect.try_validate(&provider))?;
        check_peer_runtime(runtime)?;
        effect.check_boundary(&provider).map_err(owner_error)?;
        let response = api.admit(work.id, &intent.preparation.params, &access);
        self.trust.live(auth, runtime, eligibility)?;
        if !work.observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        if let Ok(response) = response {
            let reconstructed = self.reconstruct(auth, config, runtime, eligibility, &work)?;
            self.ack(auth, runtime, eligibility, &work, response, reconstructed)?;
        } else {
            self.parked.insert(
                intent.token.clone(),
                Instant::now() + Duration::from_secs(1),
            );
        }
        // A lost POST can only return through fresh GET, never active resend.
        Ok(())
    }
    fn ack(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        work: &Work,
        response: ChannelResult,
        reconstructed: (
            PreparedChannel,
            CloudPairingScope,
            AcknowledgedWorkspaceGrant,
            ChannelTarget,
        ),
    ) -> ResultPeer<()> {
        // Reserve the single output slot before any ACK persistence. No callback
        // or competing thread can fill this private slot while &mut self is held.
        if self.pending_handoff.is_some() {
            return Err(PeerError::Invalid);
        }
        let intent = work.intent.as_ref().ok_or(PeerError::Invalid)?;
        let ChannelResult::Admitted {
            channel_id,
            inputs,
            admission,
        } = &response
        else {
            return Err(PeerError::Invalid);
        };
        if *channel_id != work.id
            || *inputs != work.inputs
            || *admission != intent.preparation.params.admission
        {
            return Err(PeerError::Invalid);
        }
        self.verify_admission(auth, runtime, eligibility, work, admission)?;
        let (prepared, scope, source, target) = reconstructed;
        if scope != intent.preparation.scope
            || target != intent.preparation.target
            || source.intent.token != intent.preparation.source_grant_token
            || prepared.canonical() != hex_bytes(work.inputs.expected_context.expose_wire())?
            || !work.observation.current_operation(runtime)
        {
            return Err(PeerError::Invalid);
        }
        // All parsing/allocation and the absolute expiry conversion precede the
        // write. Never create a new budget from the post-ACK completion time.
        let channel_deadline = runtime
            .anchor
            .checked_add(Duration::from_secs(
                prepared
                    .context()
                    .expires_at
                    .checked_sub(runtime.base)
                    .ok_or(PeerError::Invalid)?,
            ))
            .ok_or(PeerError::Invalid)?;
        let handoff = AdmittedChannelHandoff {
            signed_grant: crypt(SignedGrantV3::from_wire(&work.inputs.grant))?,
            admission: crypt(SignedChannelAdmissionV3::from_wire(admission))?,
            prepared,
            scope,
            source,
            target,
            acknowledgement: lomi_host_store::AcknowledgedChannelAdmission {
                intent: intent.clone(),
                response: response.clone(),
            },
            trusted: auth.trusted_configuration().clone(),
            observation: work.observation.clone(),
            operation: runtime.operation.retained_identity(),
            deadline: runtime.operation.deadline().min(channel_deadline),
        };
        #[cfg(test)]
        if let Some(hook) = self.before_ack_lock.take() {
            hook();
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
            .begin_acknowledge_channel(intent.clone(), response.clone())
            .map_err(owner_error)?;
        owner_turn(runtime, || turn.try_commit())?;
        // The named writer has settled this exact original continuation under
        // the same Domain unit. All guard-owning state drops before provider IO.
        drop(turn);
        self.trust.live(auth, runtime, eligibility)?;
        handoff.check_current(auth, runtime, eligibility)?;
        self.pending_handoff = Some(handoff);
        Ok(())
    }
    fn recover_one(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn ChannelApi,
        pending: &[ChannelAdmissionIntent],
    ) -> ResultPeer<bool> {
        let now = self.trust.live(auth, runtime, eligibility)?;
        if self.retire_expired(auth, runtime, eligibility, pending, now)? {
            return Ok(true);
        }
        if self.capacity_blocked && self.cleanup_expired(auth, runtime, eligibility, now)? {
            return Ok(true);
        }
        let start = self
            .cursor
            .as_ref()
            .and_then(|t| pending.iter().position(|p| &p.token == t))
            .map_or(0, |i| (i + 1) % pending.len().max(1));
        for offset in 0..pending.len() {
            let intent = &pending[(start + offset) % pending.len()];
            if self
                .parked
                .get(&intent.token)
                .is_some_and(|at| Instant::now() < *at)
            {
                continue;
            }
            self.cursor = Some(intent.token.clone());
            self.prefer_recovery = false;
            self.reconcile(auth, config, runtime, eligibility, api, intent.clone())?;
            return Ok(true);
        }
        Ok(false)
    }
    fn reconcile(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        config: &Config,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        api: &dyn ChannelApi,
        intent: ChannelAdmissionIntent,
    ) -> ResultPeer<()> {
        let now = self.trust.live(auth, runtime, eligibility)?;
        let mut effect = owner_turn(runtime, || {
            runtime.owner.capture_peer_effect(
                runtime.operation,
                eligibility,
                shared_owner::PeerEffect::ChannelGet(intent.preparation.channel_id),
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
        let response = api.get(intent.preparation.channel_id, &access);
        self.trust.live(auth, runtime, eligibility)?;
        let observation = Arc::new(Observation::new(
            eligibility,
            started,
            effect.continuation(),
        ));
        if !observation.current(eligibility) {
            return Err(PeerError::Invalid);
        }
        self.parked.insert(
            intent.token.clone(),
            Instant::now() + Duration::from_secs(1),
        );
        match response {
            Ok(ChannelResult::Pending { channel_id, inputs })
                if channel_id == intent.preparation.channel_id
                    && inputs == intent.preparation.inputs =>
            {
                let work = Work {
                    id: channel_id,
                    inputs,
                    observation,
                    intent: Some(intent),
                };
                self.reconstruct(auth, config, runtime, eligibility, &work)?;
                self.verify_admission(
                    auth,
                    runtime,
                    eligibility,
                    &work,
                    &work.intent.as_ref().unwrap().preparation.params.admission,
                )?;
                self.active = Some(work);
            }
            Ok(response @ ChannelResult::Admitted { .. }) => {
                let work = Work {
                    id: intent.preparation.channel_id,
                    inputs: intent.preparation.inputs.clone(),
                    observation,
                    intent: Some(intent),
                };
                if !matches!(&response, ChannelResult::Admitted { channel_id, inputs, .. } if *channel_id == work.id && *inputs == work.inputs)
                {
                    return Err(PeerError::Invalid);
                }
                let reconstructed = self.reconstruct(auth, config, runtime, eligibility, &work)?;
                self.ack(auth, runtime, eligibility, &work, response, reconstructed)?;
            }
            Ok(ChannelResult::Expired { channel_id } | ChannelResult::Closed { channel_id })
                if channel_id == intent.preparation.channel_id =>
            {
                let provider = ProviderCapture::read(auth, runtime, eligibility)?;
                let capture = owner_turn(runtime, || {
                    runtime.owner.capture_peer_journal(
                        runtime.operation,
                        eligibility,
                        &provider,
                        Some(&observation),
                        intent.preparation.scope.workspace_id,
                        runtime.base,
                        runtime.anchor,
                    )
                })?;
                let mut turn = capture
                    .begin_retire_channel_admission(intent.clone())
                    .map_err(owner_error)?;
                owner_turn(runtime, || turn.try_commit())?;
            }
            _ => (), // Resource-local unknowns never become global credential errors.
        }
        Ok(())
    }
    fn retire_expired(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'_>,
        eligibility: &PeerEligibility,
        pending: &[ChannelAdmissionIntent],
        now: u64,
    ) -> ResultPeer<bool> {
        for offset in 0..pending.len() {
            let index = (self.retire_cursor + offset) % pending.len();
            let intent = &pending[index];
            if intent.preparation.expires_at > now {
                continue;
            }
            self.retire_cursor = (index + 1) % pending.len();
            if verify_expired(intent, &eligibility.identity, now).is_err() {
                return Ok(false);
            }
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
                .begin_retire_channel_admission(intent.clone())
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
        let acks = owner_turn(runtime, || {
            runtime
                .owner
                .peer_channel_acks(runtime.operation, eligibility)
        })?;
        for offset in 0..acks.len() {
            let index = (self.cleanup_cursor + offset) % acks.len();
            let ack = &acks[index];
            if ack.intent.preparation.expires_at > now {
                continue;
            }
            self.cleanup_cursor = (index + 1) % acks.len();
            if verify_expired(&ack.intent, &eligibility.identity, now).is_err() {
                return Ok(false);
            }
            let provider = ProviderCapture::read(auth, runtime, eligibility)?;
            let capture = owner_turn(runtime, || {
                runtime.owner.capture_peer_journal(
                    runtime.operation,
                    eligibility,
                    &provider,
                    None,
                    ack.intent.preparation.scope.workspace_id,
                    runtime.base,
                    runtime.anchor,
                )
            })?;
            let mut turn = capture
                .begin_retire_acknowledged_channel_admission(ack.clone())
                .map_err(owner_error)?;
            owner_turn(runtime, || turn.try_commit())?;
            self.capacity_blocked = false;
            return Ok(true);
        }
        // Nonexpired old-owner/unknown records remain bounded until signed expiry
        // or fresh terminal proof. Retirement is not remote close/revoke or ACK.
        Ok(false)
    }
}
fn target(c: &ChannelContextV3) -> ResultPeer<ChannelTarget> {
    let workspace_id =
        WorkspaceId::from_bytes(c.grant.workspace_id).map_err(|_| PeerError::Invalid)?;
    let workspace_epoch =
        WorkspaceEpoch::from_bytes(c.grant.workspace_epoch).map_err(|_| PeerError::Invalid)?;
    match (&c.purpose, &c.terminal) {
        (ChannelPurposeV3::Workspace, None) => Ok(ChannelTarget::Workspace {
            workspace_id,
            workspace_epoch,
        }),
        (ChannelPurposeV3::Terminal, Some(t)) => Ok(ChannelTarget::Terminal {
            workspace_id,
            workspace_epoch,
            pane_id: PaneId::from_bytes(t.pane_id).map_err(|_| PeerError::Invalid)?,
            session_id: TerminalSessionId::from_bytes(t.session_id)
                .map_err(|_| PeerError::Invalid)?,
            session_epoch: SessionEpoch::from_bytes(t.session_epoch)
                .map_err(|_| PeerError::Invalid)?,
        }),
        _ => Err(PeerError::Invalid),
    }
}
fn authority(a: &CurrentAuthorityBinding) -> CurrentAuthorityV3 {
    CurrentAuthorityV3 {
        host_authorization_id: a.host_authorization_id.to_bytes(),
        consumer_authorization_id: a.consumer_authorization_id.to_bytes(),
        account_session_id: a.account_session_id.as_str().to_owned(),
        access_epoch: a.access_epoch.0,
        grant_revision: a.grant_revision.0,
        workspace_epoch: a.workspace_epoch.to_bytes(),
        runtime_id: a.runtime_id.to_bytes(),
        runtime_generation: a.runtime_generation.0,
        terminal_membership: a.terminal_membership.as_ref().map(|t| TerminalTargetV3 {
            pane_id: t.pane_id.to_bytes(),
            session_id: t.session_id.to_bytes(),
            session_epoch: t.session_epoch.to_bytes(),
            terminal_profile: match t.terminal_profile {
                TerminalProfile::ExperimentalRustGridV1 => {
                    "lomi-rust-grid-v1-experimental".to_owned()
                }
            },
        }),
    }
}
fn verify_wire(
    inputs: &ChannelAdmissionInputs,
    wire: &SignedChannelAdmissionWire,
    host: &lomi_host_auth::PublicHostIdentity,
    now: u64,
) -> ResultPeer<()> {
    if inputs.identities.host != host.identity
        || pin(&inputs.identities.host_fingerprint)? != host.fingerprint
    {
        return Err(PeerError::Invalid);
    }
    let signed = crypt(SignedGrantV3::from_wire(&inputs.grant))?;
    crypt(lomi_remote_crypto::verify_consumer_window_identity(
        &inputs.identities.consumer,
        host.account_id.to_bytes(),
        signed.grant.consumer_id,
    ))?;
    let expected = crypt(ChannelContextV3::from_canonical(&hex_bytes(
        inputs.expected_context.expose_wire(),
    )?))?;
    if expected.grant != signed.grant {
        return Err(PeerError::Invalid);
    }
    let admission = crypt(SignedChannelAdmissionV3::from_wire(wire))?;
    if crypt(admission.to_wire())? != *wire {
        return Err(PeerError::Invalid);
    }
    crypt(admission.verify(
        &signed,
        &expected,
        &crypt(SignedBundle::from_wire(&host.identity))?,
        &host.fingerprint,
        &crypt(SignedBundle::from_wire(&inputs.identities.consumer))?,
        &pin(&inputs.identities.consumer_fingerprint)?,
        &authority(&inputs.authority),
        now,
    ))?;
    Ok(())
}
fn verify_expired(
    intent: &ChannelAdmissionIntent,
    host: &lomi_host_auth::PublicHostIdentity,
    now: u64,
) -> ResultPeer<()> {
    let p = &intent.preparation;
    let context = crypt(ChannelContextV3::from_canonical(&hex_bytes(
        p.inputs.expected_context.expose_wire(),
    )?))?;
    if now < context.expires_at
        || p.expires_at != context.expires_at
        || p.issued_at != context.issued_at
        || p.channel_id.to_bytes() != context.channel_id
        || p.target != target(&context)?
        || context.grant.account_id != host.account_id.to_bytes()
        || context.grant.host_id != host.host_id.to_bytes()
        || p.scope.workspace_id.to_bytes() != context.grant.workspace_id
        || p.scope.workspace_epoch.to_bytes() != context.grant.workspace_epoch
        || p.source_grant_id.to_bytes() != context.grant.grant_id
        || p.scope.runtime_scope.host_id != host.host_id
        || p.scope.runtime.runtime_id.to_bytes() != context.grant.runtime_id
        || p.scope.runtime.runtime_generation.0 != context.grant.runtime_generation
        || p.scope.runtime.host_access_epoch.0 != context.grant.access_epoch
        || p.params.runtime != p.scope.runtime
    {
        return Err(PeerError::Invalid);
    }
    // Signature proof at the immutable context's historical final second ONLY
    // after durable expiry; no live policy token/clock/source adoption is created.
    verify_wire(
        &p.inputs,
        &p.params.admission,
        host,
        context.expires_at.saturating_sub(1),
    )
}
#[cfg(test)]
#[path = "channel_tests.rs"]
mod tests;
