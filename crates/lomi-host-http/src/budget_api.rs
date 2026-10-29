//! Typed original-operation entry points. Legacy callers are not qualified by
//! this addition. The authoritative callback borrows the actual owner Operation;
//! its only job is mapping Operation::check() into the closed BudgetStop result.
use super::*;
use std::time::Instant;

/// One borrowed binding to the caller's original operation. Cancellation stops
/// local waiting; a failed mutating request can still have a remote effect.
pub struct BudgetTransport<'a> {
    inner: &'a Transport,
    deadline: Instant,
    check: &'a budget::Check<'a>,
}
impl Transport {
    pub fn with_budget<'a>(
        &'a self,
        original_deadline: Instant,
        authoritative_check: &'a (dyn Fn() -> std::result::Result<(), BudgetStop> + Sync),
    ) -> BudgetTransport<'a> {
        BudgetTransport {
            inner: self,
            deadline: original_deadline,
            check: authoritative_check,
        }
    }
}
impl BudgetTransport<'_> {
    pub fn initiate(&self, request: &EnrollmentInitiateParams) -> Result<EnrollmentInitiateResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = Transport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: self.inner.origin.clone(),
                client: self.inner.client.clone(),
            };
            bound.initiate(request)
        })
    }
    pub fn exchange(
        &self,
        request: &HostAuthorizationExchangeParams,
    ) -> Result<HostAuthorizationResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = Transport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: self.inner.origin.clone(),
                client: self.inner.client.clone(),
            };
            bound.exchange(request)
        })
    }
    pub fn refresh(
        &self,
        request: &HostAuthorizationRefreshParams,
    ) -> Result<HostAuthorizationResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = Transport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: self.inner.origin.clone(),
                client: self.inner.client.clone(),
            };
            bound.refresh(request)
        })
    }
    pub fn register(
        &self,
        request: &HostRegisterParams,
        unconfirmed_access: &HostAccessCredential,
    ) -> Result<HostRegisterResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = Transport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: self.inner.origin.clone(),
                client: self.inner.client.clone(),
            };
            bound.register(request, unconfirmed_access)
        })
    }
    pub fn revoke(
        &self,
        host_id: HostId,
        request: &HostRevokeParams,
        access: &HostAccessCredential,
    ) -> Result<HostRevokeResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = Transport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: self.inner.origin.clone(),
                client: self.inner.client.clone(),
            };
            bound.revoke(host_id, request, access)
        })
    }
    pub fn poll(&self, device: &DeviceCode) -> Result<PollOutcome> {
        budget::run(self.deadline, self.check, |state| {
            let bound = Transport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: self.inner.origin.clone(),
                client: self.inner.client.clone(),
            };
            bound.poll(device)
        })
    }
}

/// One borrowed binding to the caller's original operation. Cancellation stops
/// local waiting; a failed mutating request can still have a remote effect.
pub struct BudgetDataTransport<'a> {
    inner: &'a DataTransport,
    deadline: Instant,
    check: &'a budget::Check<'a>,
}
impl DataTransport {
    pub fn with_budget<'a>(
        &'a self,
        original_deadline: Instant,
        authoritative_check: &'a (dyn Fn() -> std::result::Result<(), BudgetStop> + Sync),
    ) -> BudgetDataTransport<'a> {
        BudgetDataTransport {
            inner: self,
            deadline: original_deadline,
            check: authoritative_check,
        }
    }
}
impl BudgetDataTransport<'_> {
    pub fn runtime_get(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<HostRuntimeGetResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.runtime_get(host, access)
        })
    }
    pub fn runtime_claim(
        &self,
        host: HostId,
        request: &RuntimeClaimParams,
        access: &HostAccessCredential,
    ) -> Result<RuntimeClaimResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.runtime_claim(host, request, access)
        })
    }
    pub fn heartbeat(
        &self,
        host: HostId,
        request: &HeartbeatParams,
        access: &HostAccessCredential,
    ) -> Result<HeartbeatResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.heartbeat(host, request, access)
        })
    }
    pub fn publication(
        &self,
        host: HostId,
        request: &PublicationParams,
        access: &HostAccessCredential,
    ) -> Result<PublicationResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.publication(host, request, access)
        })
    }
    pub fn pairing_pending(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<PairingPendingResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.pairing_pending(host, access)
        })
    }
    pub fn pairing_get(
        &self,
        pairing: PairingId,
        access: &HostAccessCredential,
    ) -> Result<PairingResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.pairing_get(pairing, access)
        })
    }
    pub fn pairing_decision(
        &self,
        pairing: PairingId,
        request: &PairingDecisionParams,
        access: &HostAccessCredential,
    ) -> Result<PairingResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.pairing_decision(pairing, request, access)
        })
    }
    pub fn channel_pending(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<ChannelPendingResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.channel_pending(host, access)
        })
    }
    pub fn channel_get(
        &self,
        channel: ChannelId,
        access: &HostAccessCredential,
    ) -> Result<ChannelResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.channel_get(channel, access)
        })
    }
    pub fn channel_admission(
        &self,
        channel: ChannelId,
        request: &ChannelAdmissionParams,
        access: &HostAccessCredential,
    ) -> Result<ChannelResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.channel_admission(channel, request, access)
        })
    }
    pub fn channel_ticket(
        &self,
        channel: ChannelId,
        request: &ChannelTicketParams,
        access: &HostAccessCredential,
    ) -> Result<ChannelTicketResult> {
        budget::run(self.deadline, self.check, |state| {
            let bound = DataTransport {
                agent: budget::agent(self.inner.agent.config().clone(), state.clone())?,
                budget: Some(state),
                origin: RemoteApiOrigin(self.inner.origin.0.clone()),
            };
            bound.channel_ticket(channel, request, access)
        })
    }
}
