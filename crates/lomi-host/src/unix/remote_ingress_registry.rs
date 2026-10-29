//! Bounded channel-keyed ingress owners for the auth worker.
use super::super::Coordinator;
use super::super::cloud::PeerEligibility;
use super::{Driver, HostAuth, RuntimeWithOperation, SecretStorage, channel};
use lomi_remote_protocol::ChannelId;
#[cfg(test)]
use lomi_remote_protocol::http::ChannelTicketResult;
#[cfg(test)]
use std::cell::Cell;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Weak, atomic::AtomicBool},
    time::{Duration, Instant},
};

// A full browser/desktop view consumes one workspace and one terminal
// channel. Allow eight views plus one overlapping reconnect pair, while
// remaining below the protocol and Store admission limits.
const MAX_CHANNELS: usize = 32;

#[cfg(test)]
struct ScriptedDriverSetup {
    ticket: Option<super::TicketScript>,
    relay: Option<lomi_host_http::RelayTransport>,
}

/// Owns one independent ingress Driver per admitted channel, all sharing the
/// auth worker's Coordinator and stop signal.
pub(in crate::unix::auth) struct Registry<'cancel> {
    cancelled: &'cancel AtomicBool,
    coordinator: Weak<Coordinator>,
    entries: BTreeMap<ChannelId, Driver<'cancel>>,
    round_robin: VecDeque<ChannelId>,
    #[cfg(all(test, feature = "cloud-fixture"))]
    cloud_fixture_transport_roots: Option<(Vec<u8>, Vec<u8>)>,
    #[cfg(test)]
    scripted_setups: BTreeMap<ChannelId, ScriptedDriverSetup>,
    #[cfg(test)]
    driver_factory_calls: Cell<usize>,
}

impl<'cancel> Registry<'cancel> {
    fn publish_client_observation(&self) {
        let Some(coordinator) = self.coordinator.upgrade() else {
            return;
        };
        let now = Instant::now();
        let mut windows = std::collections::BTreeSet::new();
        // Bound the observation independently of the grant so a stalled auth
        // worker cannot make an old count look current indefinitely.
        let mut until = now + Duration::from_secs(2);
        for driver in self.entries.values() {
            if let Some((window, cutoff)) = driver.observed_window(now) {
                windows.insert(window);
                until = until.min(cutoff);
            }
        }
        coordinator.observe_clients(windows.len() as u32, until);
    }
    pub(in crate::unix::auth) fn with_coordinator(
        cancelled: &'cancel AtomicBool,
        coordinator: Weak<Coordinator>,
    ) -> Self {
        Self {
            cancelled,
            coordinator,
            entries: BTreeMap::new(),
            round_robin: VecDeque::new(),
            #[cfg(all(test, feature = "cloud-fixture"))]
            cloud_fixture_transport_roots: None,
            #[cfg(test)]
            scripted_setups: BTreeMap::new(),
            #[cfg(test)]
            driver_factory_calls: Cell::new(0),
        }
    }

    pub(in crate::unix::auth) fn has_retained_operation(&self) -> bool {
        self.entries.values().any(Driver::has_retained_operation)
    }

    pub(in crate::unix::auth) fn has_active_git_writer(&self) -> bool {
        self.entries.values().any(Driver::has_active_git_writer)
    }

    pub(in crate::unix::auth) fn started_git_continuation(
        &self,
    ) -> Option<super::super::shared_owner::StartedGitContinuation> {
        let mut active = self
            .entries
            .values()
            .filter(|driver| driver.has_active_git_writer());
        let first = active.next()?.started_git_continuation()?;
        if active.next().is_some() {
            return None;
        }
        Some(first)
    }

    fn sync_started_git_terminal_continuation(&self) {
        if let Some(coordinator) = self.coordinator.upgrade() {
            let _ =
                coordinator.set_started_git_terminal_continuation(self.started_git_continuation());
        }
    }

    pub(in crate::unix::auth) fn started_git_auth_status(
        &self,
        owner: &super::super::shared_owner::SharedOwner,
    ) -> Result<
        Option<super::super::shared_owner::AuthStatusSnapshot>,
        super::super::shared_owner::Error,
    > {
        let mut active = self
            .entries
            .values()
            .filter(|driver| driver.has_active_git_writer());
        let Some(driver) = active.next() else {
            return Ok(None);
        };
        if active.next().is_some() {
            return Err(super::super::shared_owner::Error::Domain(
                super::super::owner_domain::Error::Stale,
            ));
        }
        driver.started_git_auth_status(owner)
    }

    pub(in crate::unix::auth) fn advance_started_git(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
    ) -> bool {
        let Some(channel_id) = self
            .entries
            .iter()
            .find(|(_, driver)| driver.has_active_git_writer())
            .map(|(channel_id, _)| *channel_id)
        else {
            return false;
        };
        if self
            .entries
            .values()
            .filter(|driver| driver.has_active_git_writer())
            .count()
            != 1
        {
            self.discard();
            return false;
        }
        let observation = self.entries.get(&channel_id).ok_or(()).and_then(|driver| {
            driver
                .started_git_publication_observation(runtime.owner)
                .map_err(|_| ())
        });
        match observation {
            Ok(super::super::shared_owner::CloudPublicationFenceObservation::Clear) => {}
            Ok(super::super::shared_owner::CloudPublicationFenceObservation::Defer) => {
                return false;
            }
            Ok(super::super::shared_owner::CloudPublicationFenceObservation::CloseIngress)
            | Err(()) => {
                self.discard_other_ingress_for_started_git();
                self.cancel_started_git();
            }
        }
        let Some(mut active_driver) = self.entries.remove(&channel_id) else {
            self.publish_client_observation();
            return false;
        };
        // The Git writer gets first service on every actor pass. Only after
        // its control-plane step may one established sibling advance, which
        // keeps heartbeat/revoke work ahead of terminal output.
        let mut immediate = active_driver.advance_started_git(auth, runtime);
        if active_driver.has_active_git_writer()
            && let Some(sibling_id) = self.next_started_git_sibling(channel_id)
            && let Some(sibling) = self.entries.get_mut(&sibling_id)
        {
            immediate |=
                active_driver.advance_started_git_terminal_from_active(sibling, auth, runtime);
            self.prune_empty(sibling_id);
        }
        if active_driver.is_empty() {
            self.round_robin
                .retain(|candidate| *candidate != channel_id);
        } else {
            self.entries.insert(channel_id, active_driver);
        }
        self.sync_started_git_terminal_continuation();
        self.publish_client_observation();
        immediate
    }

    fn next_started_git_sibling(&mut self, active: ChannelId) -> Option<ChannelId> {
        let selected = self.round_robin.iter().copied().find(|channel_id| {
            *channel_id != active
                && self
                    .entries
                    .get(channel_id)
                    .is_some_and(Driver::has_established_connection)
        })?;
        let index = self
            .round_robin
            .iter()
            .position(|channel_id| *channel_id == selected)?;
        self.round_robin.remove(index);
        self.round_robin.push_back(selected);
        Some(selected)
    }

    pub(in crate::unix::auth) fn cancel_started_git(&mut self) {
        for driver in self.entries.values_mut() {
            if driver.has_active_git_writer() {
                driver.cancel_started_git();
            }
        }
        if let Some(coordinator) = self.coordinator.upgrade() {
            let _ = coordinator.set_started_git_terminal_continuation(None);
        }
    }

    pub(in crate::unix::auth) fn discard_other_ingress_for_started_git(&mut self) {
        let active = self
            .entries
            .iter()
            .find(|(_, driver)| driver.has_active_git_writer())
            .map(|(id, _)| *id);
        let Some(active) = active else {
            return;
        };
        self.entries.retain(|id, driver| {
            if *id == active {
                true
            } else {
                driver.discard();
                false
            }
        });
        self.round_robin.retain(|id| *id == active);
        self.sync_started_git_terminal_continuation();
        self.publish_client_observation();
    }

    pub(in crate::unix::auth) fn has_immediate_output(
        &self,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) -> bool {
        let Some(eligibility) = eligibility else {
            return false;
        };
        let now = Instant::now();
        let heartbeat = &eligibility.heartbeat;
        let fresh_until = heartbeat
            .request_started
            .checked_add(Duration::from_millis(heartbeat.freshness_ms));
        let lease_until = heartbeat
            .request_started
            .checked_add(Duration::from_millis(heartbeat.lease_ms));
        runtime.ingress_can_advance()
            && fresh_until.is_some_and(|until| now < until)
            && lease_until.is_some_and(|until| now < until)
            && self.entries.values().any(Driver::has_immediate_output)
    }

    pub(in crate::unix::auth) fn poll(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) {
        let channel_ids: Vec<_> = self.round_robin.iter().copied().collect();
        for channel_id in channel_ids {
            if let Some(driver) = self.entries.get_mut(&channel_id) {
                let _ = driver.poll(auth, runtime, eligibility);
            }
            self.prune_empty(channel_id);
        }
        self.sync_started_git_terminal_continuation();
        self.publish_client_observation();
    }

    /// Consumes at most one admitted handoff and queues its candidate behind
    /// existing channels. Duplicate/full arrivals are dropped before Driver
    /// creation or ticket HTTP.
    pub(in crate::unix::auth) fn after_channel_step(
        &mut self,
        worker: &mut channel::Worker,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
    ) {
        let Some(handoff) = worker.take_admitted() else {
            return;
        };
        let channel_id = handoff.channel_id();
        if !self.can_admit(channel_id) {
            drop(handoff);
            #[cfg(test)]
            self.scripted_setups.remove(&channel_id);
            return;
        }

        let Ok(mut driver) = self.new_driver() else {
            drop(handoff);
            return;
        };
        #[cfg(test)]
        if let Some(mut setup) = self.scripted_setups.remove(&channel_id) {
            #[cfg(all(test, feature = "cloud-fixture"))]
            let scripted_allowed = driver.cloud_fixture_transport_roots.is_none();
            #[cfg(all(test, not(feature = "cloud-fixture")))]
            let scripted_allowed = true;
            if scripted_allowed {
                driver.script = setup.ticket.take();
                driver.relay_script = setup.relay.take();
            }
        }
        if !driver.accept(handoff, auth, runtime, eligibility) {
            return;
        }
        self.insert_admitted(channel_id, driver);
        // `accept` performed the handoff's current-owner, operation, expiry,
        // and authorization checks. The ticket request remains queued until
        // this channel wins the shared round-robin advance.
    }

    /// Advances one round-robin entry. Eligible queued output in any entry
    /// keeps the next actor pass immediate, including output on a sibling.
    pub(in crate::unix::auth) fn advance(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) -> bool {
        self.prune_all_empty();
        let now = Instant::now();
        let due = eligibility
            .is_some()
            .then(|| self.next_peer_refresh(now))
            .flatten();
        let Some(channel_id) = due.or_else(|| self.next_round_robin()) else {
            return false;
        };
        if let Some(driver) = self.entries.get_mut(&channel_id) {
            let _ = driver.advance_registry_stage(auth, runtime, eligibility);
        }
        self.prune_empty(channel_id);
        self.sync_started_git_terminal_continuation();
        self.publish_client_observation();
        self.has_immediate_output(runtime, eligibility)
    }

    /// Global authorization loss closes and removes every channel entry.
    pub(in crate::unix::auth) fn discard(&mut self) {
        for driver in self.entries.values_mut() {
            driver.discard();
        }
        self.entries.clear();
        self.round_robin.clear();
        if let Some(coordinator) = self.coordinator.upgrade() {
            let _ = coordinator.set_started_git_terminal_continuation(None);
        }
        self.publish_client_observation();
        #[cfg(test)]
        self.scripted_setups.clear();
    }

    fn can_admit(&self, channel_id: ChannelId) -> bool {
        self.entries.len() < MAX_CHANNELS && !self.entries.contains_key(&channel_id)
    }

    fn new_driver(&self) -> Result<Driver<'cancel>, &'static str> {
        #[cfg(test)]
        self.driver_factory_calls
            .set(self.driver_factory_calls.get().saturating_add(1));
        let driver = Driver::with_coordinator(self.cancelled, self.coordinator.clone());
        #[cfg(all(test, feature = "cloud-fixture"))]
        let driver = {
            let mut driver = driver;
            if let Some((remote_api_root, relay_root)) = self.cloud_fixture_transport_roots.as_ref()
            {
                driver.use_cloud_fixture_transport_for_test(
                    remote_api_root.clone(),
                    relay_root.clone(),
                )?;
            }
            driver
        };
        Ok(driver)
    }

    fn insert_admitted(&mut self, channel_id: ChannelId, driver: Driver<'cancel>) {
        debug_assert!(self.can_admit(channel_id));
        let previous = self.entries.insert(channel_id, driver);
        debug_assert!(previous.is_none());
        self.round_robin.push_back(channel_id);
    }

    fn next_round_robin(&mut self) -> Option<ChannelId> {
        for _ in 0..MAX_CHANNELS {
            let channel_id = self.round_robin.pop_front()?;
            if self.entries.contains_key(&channel_id) {
                self.round_robin.push_back(channel_id);
                return Some(channel_id);
            }
        }
        None
    }

    /// Refresh the established connection with the earliest impending peer
    /// cutoff before ordinary round-robin work. Each successful refresh leaves
    /// this window; a failed or expired refresh closes and prunes that channel.
    fn next_peer_refresh(&mut self, now: Instant) -> Option<ChannelId> {
        let round_robin = &self.round_robin;
        let entries = &self.entries;
        let selected = earliest_peer_refresh(round_robin, |channel_id| {
            entries
                .get(&channel_id)
                .and_then(|driver| driver.peer_refresh_deadline(now))
        })?;
        let index = self
            .round_robin
            .iter()
            .position(|channel_id| *channel_id == selected)?;
        self.round_robin.remove(index);
        self.round_robin.push_back(selected);
        Some(selected)
    }

    fn prune_empty(&mut self, channel_id: ChannelId) {
        if self.entries.get(&channel_id).is_some_and(Driver::is_empty) {
            self.entries.remove(&channel_id);
            self.round_robin
                .retain(|candidate| *candidate != channel_id);
        }
    }

    fn prune_all_empty(&mut self) {
        let empty: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(channel_id, driver)| driver.is_empty().then_some(*channel_id))
            .collect();
        for channel_id in empty {
            self.prune_empty(channel_id);
        }
    }

    #[cfg(all(test, feature = "cloud-fixture"))]
    pub(in crate::unix::auth) fn use_cloud_fixture_transport_for_test(
        &mut self,
        remote_api_root_der: Vec<u8>,
        relay_root_der: Vec<u8>,
    ) -> Result<(), &'static str> {
        if !self.entries.is_empty()
            || !self.scripted_setups.is_empty()
            || self.cloud_fixture_transport_roots.is_some()
        {
            return Err("cloud fixture transport must be selected before ingress work");
        }
        if remote_api_root_der.is_empty()
            || remote_api_root_der.len() > super::CLOUD_FIXTURE_ROOT_DER_MAX_BYTES
            || relay_root_der.is_empty()
            || relay_root_der.len() > super::CLOUD_FIXTURE_ROOT_DER_MAX_BYTES
        {
            return Err("cloud fixture TLS root is outside its byte bound");
        }
        self.cloud_fixture_transport_roots = Some((remote_api_root_der, relay_root_der));
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn script_ticket_for_channel_test(
        &mut self,
        channel_id: ChannelId,
        response: Result<ChannelTicketResult, lomi_host_http::Error>,
        hook: Option<super::TicketTestHook>,
        minimum_elapsed: Duration,
    ) -> Result<std::rc::Rc<std::cell::Cell<usize>>, &'static str> {
        if !self.can_admit(channel_id)
            || (self.scripted_setups.len() >= MAX_CHANNELS
                && !self.scripted_setups.contains_key(&channel_id))
        {
            return Err("duplicate or full ingress registry");
        }
        #[cfg(feature = "cloud-fixture")]
        if self.cloud_fixture_transport_roots.is_some() {
            return Err("scripted ticket cannot replace explicitly selected Cloud transport");
        }
        let setup = self
            .scripted_setups
            .entry(channel_id)
            .or_insert_with(|| ScriptedDriverSetup {
                ticket: None,
                relay: None,
            });
        if setup.ticket.is_some() {
            return Err("ticket script already configured for channel");
        }
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        setup.ticket = Some(super::TicketScript {
            response,
            hook,
            calls: calls.clone(),
            minimum_elapsed,
        });
        Ok(calls)
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn script_relay_for_channel_test(
        &mut self,
        channel_id: ChannelId,
        relay: lomi_host_http::RelayTransport,
    ) -> Result<(), &'static str> {
        if !self.can_admit(channel_id)
            || (self.scripted_setups.len() >= MAX_CHANNELS
                && !self.scripted_setups.contains_key(&channel_id))
        {
            return Err("duplicate or full ingress registry");
        }
        #[cfg(feature = "cloud-fixture")]
        if self.cloud_fixture_transport_roots.is_some() {
            return Err("scripted relay cannot replace explicitly selected Cloud transport");
        }
        let setup = self
            .scripted_setups
            .entry(channel_id)
            .or_insert_with(|| ScriptedDriverSetup {
                ticket: None,
                relay: None,
            });
        if setup.relay.is_some() {
            return Err("relay script already configured for channel");
        }
        setup.relay = Some(relay);
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn connected_for_test(&self, channel_id: ChannelId) -> bool {
        self.entries
            .get(&channel_id)
            .is_some_and(Driver::connected_for_test)
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn stream_pending_for_test(&self, channel_id: ChannelId) -> bool {
        self.entries
            .get(&channel_id)
            .is_some_and(Driver::diagnostic_stream_pending_for_test)
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn settle_maintenance_for_test(&mut self, channel_id: ChannelId) {
        self.entries
            .get_mut(&channel_id)
            .expect("registered ingress channel")
            .settle_maintenance_for_test();
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn shorten_peer_cutoff_for_test(
        &mut self,
        channel_id: ChannelId,
        cutoff: Instant,
    ) {
        self.entries
            .get_mut(&channel_id)
            .expect("registered ingress channel")
            .set_peer_cutoff_for_test(cutoff);
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn failure_observation_for_test(
        &self,
        channel_id: ChannelId,
    ) -> Option<super::IngressFailureSnapshot> {
        self.entries
            .get(&channel_id)
            .map(Driver::failure_observation_for_test)
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn channel_step_observation_for_test(
        &self,
        channel_id: ChannelId,
    ) -> Option<(&'static str, Option<&'static str>)> {
        self.entries
            .get(&channel_id)
            .map(Driver::channel_step_observation_for_test)
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn registered_channels_for_test(&self) -> Vec<ChannelId> {
        self.round_robin.iter().copied().collect()
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn driver_factory_calls_for_test(&self) -> usize {
        self.driver_factory_calls.get()
    }

    #[cfg(test)]
    pub(in crate::unix::auth) fn reserve_test_key_for_duplicate(&mut self, channel_id: ChannelId) {
        assert!(self.can_admit(channel_id));
        self.insert_admitted(channel_id, Driver::default());
    }
}

fn earliest_peer_refresh(
    round_robin: &VecDeque<ChannelId>,
    mut cutoff: impl FnMut(ChannelId) -> Option<Instant>,
) -> Option<ChannelId> {
    round_robin
        .iter()
        .filter_map(|channel_id| cutoff(*channel_id).map(|deadline| (*channel_id, deadline)))
        .min_by_key(|(_, deadline)| *deadline)
        .map(|(channel_id, _)| channel_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel_id(index: u8) -> ChannelId {
        ChannelId::from_bytes([index; 16]).unwrap()
    }

    fn registry<'a>(cancelled: &'a AtomicBool) -> Registry<'a> {
        Registry::with_coordinator(cancelled, Weak::new())
    }

    #[test]
    fn admission_is_bounded_and_duplicate_or_ninth_never_replaces_an_incumbent() {
        let cancelled = AtomicBool::new(false);
        let mut registry = registry(&cancelled);
        for index in 1..=MAX_CHANNELS as u8 {
            let channel_id = channel_id(index);
            assert!(registry.can_admit(channel_id));
            registry.insert_admitted(channel_id, Driver::default());
        }
        let original: Vec<_> = registry.entries.keys().copied().collect();
        assert_eq!(registry.entries.len(), MAX_CHANNELS);
        assert!(!registry.can_admit(channel_id(1)));
        assert!(!registry.can_admit(channel_id(9)));
        assert_eq!(
            registry.entries.keys().copied().collect::<Vec<_>>(),
            original
        );
        assert_eq!(registry.round_robin.len(), MAX_CHANNELS);
    }

    #[test]
    fn round_robin_advances_each_registered_channel_without_starvation() {
        let cancelled = AtomicBool::new(false);
        let mut registry = registry(&cancelled);
        let channels: Vec<_> = (1..=3).map(channel_id).collect();
        for id in &channels {
            registry.insert_admitted(*id, Driver::default());
        }
        for expected in channels.iter().cycle().take(9) {
            assert_eq!(registry.next_round_robin(), Some(*expected));
        }
    }

    #[test]
    fn peer_refresh_deadlines_rotate_earliest_first_across_eight_channels() {
        let now = Instant::now();
        let mut round_robin: VecDeque<_> = (1..=8).map(channel_id).collect();
        let mut deadlines: BTreeMap<_, _> = round_robin
            .iter()
            .enumerate()
            .map(|(index, channel_id)| {
                (*channel_id, now + Duration::from_millis((8 - index) as u64))
            })
            .collect();

        for expected_byte in (1..=8).rev() {
            let selected = earliest_peer_refresh(&round_robin, |channel_id| {
                deadlines.get(&channel_id).copied()
            })
            .expect("a due channel remains");
            assert_eq!(selected, channel_id(expected_byte));
            let index = round_robin
                .iter()
                .position(|candidate| *candidate == selected)
                .expect("selected channel is registered");
            round_robin.remove(index);
            round_robin.push_back(selected);
            deadlines.remove(&selected);
        }
        assert!(earliest_peer_refresh(&round_robin, |_| None).is_none());
    }

    #[test]
    fn local_empty_prune_preserves_siblings_and_global_discard_clears_every_entry() {
        let cancelled = AtomicBool::new(false);
        let mut registry = registry(&cancelled);
        for index in 1..=3 {
            let id = channel_id(index);
            registry.insert_admitted(id, Driver::default());
        }
        registry.prune_empty(channel_id(2));
        assert!(!registry.entries.contains_key(&channel_id(2)));
        assert!(registry.entries.contains_key(&channel_id(1)));
        assert!(registry.entries.contains_key(&channel_id(3)));
        registry.discard();
        assert!(registry.entries.is_empty());
        assert!(registry.round_robin.is_empty());
    }

    #[test]
    fn arrivals_stay_behind_the_round_robin_cursor_when_an_entry_is_pruned() {
        let cancelled = AtomicBool::new(false);
        let mut registry = registry(&cancelled);
        registry.insert_admitted(channel_id(1), Driver::default());
        registry.insert_admitted(channel_id(2), Driver::default());
        assert_eq!(registry.next_round_robin(), Some(channel_id(1)));

        registry.insert_admitted(channel_id(3), Driver::default());
        assert_eq!(
            registry.round_robin.iter().copied().collect::<Vec<_>>(),
            [channel_id(2), channel_id(1), channel_id(3)]
        );
        assert_eq!(registry.next_round_robin(), Some(channel_id(2)));
        registry.prune_empty(channel_id(2));
        assert_eq!(registry.next_round_robin(), Some(channel_id(1)));
        assert_eq!(registry.next_round_robin(), Some(channel_id(3)));
    }

    #[cfg(all(test, feature = "cloud-fixture"))]
    #[test]
    fn fixture_tls_roots_are_closed_by_default_and_inherited_only_after_explicit_selection() {
        let cancelled = AtomicBool::new(false);
        let mut registry = registry(&cancelled);
        let default_driver = registry.new_driver().unwrap();
        assert!(default_driver.cloud_fixture_transport_roots.is_none());
        assert!(default_driver.script.is_none());
        assert!(default_driver.relay_script.is_none());

        registry
            .use_cloud_fixture_transport_for_test(vec![1], vec![2])
            .unwrap();
        let opted_in_driver = registry.new_driver().unwrap();
        assert_eq!(
            opted_in_driver
                .cloud_fixture_transport_roots
                .as_ref()
                .map(|roots| (roots.remote_api.as_slice(), roots.relay.as_slice())),
            Some((&[1][..], &[2][..]))
        );
        assert!(opted_in_driver.script.is_none());
        assert!(opted_in_driver.relay_script.is_none());
    }
}
