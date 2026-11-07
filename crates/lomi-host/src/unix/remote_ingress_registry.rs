//! Bounded channel-keyed ingress owners for the auth worker.
use super::super::Coordinator;
use super::super::cloud::PeerEligibility;
use super::{Driver, HostAuth, RuntimeWithOperation, SecretStorage, channel};
use lomi_remote_protocol::{ChannelId, message_framing::MAX_FRAGMENTS_PER_MESSAGE};

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Weak, atomic::AtomicBool},
    time::{Duration, Instant},
};

// A full browser/desktop view consumes one workspace and one terminal
// channel. Allow eight views plus one overlapping reconnect pair, while
// remaining below the protocol and Store admission limits.
const MAX_CHANNELS: usize = 32;
const STAGED_MESSAGE_BATCH_QUANTUM: Duration = Duration::from_millis(10);

fn staged_batch_initial_allowed(
    ordinary_yield_pending: bool,
    due_peer_selected: bool,
    staged_output_live: bool,
    remaining: Option<usize>,
    active_git_writer: bool,
    output_eligibility_live: bool,
) -> bool {
    !ordinary_yield_pending
        && !due_peer_selected
        && staged_output_live
        && remaining.is_some_and(|remaining| remaining > 0)
        && !active_git_writer
        && output_eligibility_live
}

fn staged_batch_made_progress(advanced: bool, before: Option<usize>, after: Option<usize>) -> bool {
    advanced
        && matches!((before, after), (Some(before), Some(after)) if before > 0 && after > 0 && after < before)
}

fn staged_batch_can_continue(
    progressed: bool,
    remaining: Option<usize>,
    elapsed: Duration,
    iterations: usize,
    staged_output_live: bool,
    due_peer_refresh: bool,
    active_git_writer: bool,
    output_eligibility_live: bool,
) -> bool {
    progressed
        && remaining.is_some_and(|remaining| remaining > 0)
        && elapsed < STAGED_MESSAGE_BATCH_QUANTUM
        && iterations < MAX_FRAGMENTS_PER_MESSAGE
        && staged_output_live
        && !due_peer_refresh
        && !active_git_writer
        && output_eligibility_live
}

fn staged_batch_fence_is_clear(
    observation: Result<
        super::super::shared_owner::CloudPublicationFenceObservation,
        super::super::shared_owner::Error,
    >,
) -> bool {
    matches!(
        observation,
        Ok(super::super::shared_owner::CloudPublicationFenceObservation::Clear)
    )
}

fn output_eligibility_is_live(
    runtime: RuntimeWithOperation<'_, '_>,
    eligibility: &PeerEligibility,
    now: Instant,
) -> bool {
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
}

/// Owns one independent ingress Driver per admitted channel, all sharing the
/// auth worker's Coordinator and stop signal.
pub(in crate::unix::auth) struct Registry<'cancel> {
    cancelled: &'cancel AtomicBool,
    coordinator: Weak<Coordinator>,
    entries: BTreeMap<ChannelId, Driver<'cancel>>,
    round_robin: VecDeque<ChannelId>,
    idle_yield_pending: bool,
    ordinary_yield_pending: bool,
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
            idle_yield_pending: false,
            ordinary_yield_pending: false,
        }
    }

    fn note_staged_message_transition(&mut self, was_staged: bool, is_staged: bool) {
        if was_staged && !is_staged {
            self.idle_yield_pending = true;
            self.ordinary_yield_pending = true;
        }
    }

    /// Preserve setup priority; otherwise consume one global idle opportunity
    /// recorded when any channel's finite staged message settled.
    pub(in crate::unix::auth) fn idle_priority_pending(
        &mut self,
        setup_pending: bool,
        staged_output_pending: bool,
        due_peer_refresh: bool,
    ) -> bool {
        if setup_pending || due_peer_refresh {
            return true;
        }
        let idle_yield = std::mem::take(&mut self.idle_yield_pending);
        staged_output_pending && !idle_yield
    }

    pub(in crate::unix::auth) fn has_due_peer_refresh(&self, now: Instant) -> bool {
        self.entries
            .values()
            .any(|driver| driver.peer_refresh_deadline(now).is_some())
    }

    pub(in crate::unix::auth) fn has_retained_operation(&self) -> bool {
        self.entries.values().any(Driver::has_retained_operation)
    }

    pub(in crate::unix::auth) fn has_pending_setup(&self) -> bool {
        self.entries.values().any(Driver::has_pending_setup)
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
            | Ok(super::super::shared_owner::CloudPublicationFenceObservation::PauseIngress(_))
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
        output_eligibility_is_live(runtime, eligibility, now)
            && self.entries.values().any(Driver::has_immediate_output)
    }

    pub(in crate::unix::auth) fn has_staged_output(
        &self,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) -> bool {
        let Some(eligibility) = eligibility else {
            return false;
        };
        let now = Instant::now();
        output_eligibility_is_live(runtime, eligibility, now)
            && self.entries.values().any(Driver::has_staged_output)
    }

    fn staged_batch_ready(
        &self,
        channel_id: ChannelId,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
        batch_started_at: Instant,
        iterations: usize,
        remaining: Option<usize>,
    ) -> bool {
        let now = Instant::now();
        let current_remaining = self
            .entries
            .get(&channel_id)
            .and_then(Driver::staged_message_remaining);
        staged_batch_can_continue(
            true,
            remaining,
            now.checked_duration_since(batch_started_at)
                .unwrap_or_default(),
            iterations,
            self.entries
                .get(&channel_id)
                .is_some_and(Driver::has_staged_output),
            self.has_due_peer_refresh(now),
            self.has_active_git_writer(),
            output_eligibility_is_live(runtime, eligibility, now),
        ) && current_remaining == remaining
    }

    pub(in crate::unix::auth) fn poll(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) {
        let channel_ids: Vec<_> = self.round_robin.iter().copied().collect();
        for channel_id in channel_ids {
            let staged_settled = if let Some(driver) = self.entries.get_mut(&channel_id) {
                let staged_before = driver.has_staged_message();
                let _ = driver.poll(auth, runtime, eligibility);
                staged_before && !driver.has_staged_message()
            } else {
                false
            };
            if staged_settled {
                self.note_staged_message_transition(true, false);
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

            return;
        }

        let Ok(mut driver) = self.new_driver() else {
            drop(handoff);
            return;
        };
        if !driver.accept(handoff, auth, runtime, eligibility) {
            return;
        }
        self.insert_admitted(channel_id, driver);
        // `accept` performed the handoff's current-owner, operation, expiry,
        // and authorization checks. The ticket request remains queued until
        // this channel wins the shared round-robin advance.
    }

    /// Advances due peer refreshes first, then staged finite output fairly.
    pub(in crate::unix::auth) fn advance(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) -> bool {
        self.prune_all_empty();
        let now = Instant::now();
        let ordinary_yield_pending_before_selection = self.ordinary_yield_pending;
        let due = eligibility
            .is_some()
            .then(|| self.next_peer_refresh(now))
            .flatten();
        let Some(channel_id) = self.next_registry_channel(due) else {
            return false;
        };

        let output_eligibility_live = eligibility.is_some_and(|eligibility| {
            output_eligibility_is_live(runtime, eligibility, Instant::now())
        });
        let active_git_writer = self.has_active_git_writer();
        let staged_output_live = self
            .entries
            .get(&channel_id)
            .is_some_and(Driver::has_staged_output);
        let staged_remaining_before = self
            .entries
            .get(&channel_id)
            .and_then(Driver::staged_message_remaining);
        let batch_allowed = staged_batch_initial_allowed(
            ordinary_yield_pending_before_selection,
            due.is_some(),
            staged_output_live,
            staged_remaining_before,
            active_git_writer,
            output_eligibility_live,
        );

        let staged_before = self
            .entries
            .get(&channel_id)
            .is_some_and(Driver::has_staged_message);
        // The quantum begins immediately before the original registry stage;
        // that stage itself remains unchanged and is included in the hard cap.
        let batch_started_at = Instant::now();
        let first_advanced = self
            .entries
            .get_mut(&channel_id)
            .is_some_and(|driver| driver.advance_registry_stage(auth, runtime, eligibility));
        let mut staged_remaining_after = if batch_allowed {
            self.entries
                .get(&channel_id)
                .and_then(Driver::staged_message_remaining)
        } else {
            None
        };
        let mut iterations = 1;
        let mut progressed = batch_allowed
            && staged_batch_made_progress(
                first_advanced,
                staged_remaining_before,
                staged_remaining_after,
            );

        while progressed {
            let Some(eligibility) = eligibility else {
                break;
            };
            if !self.staged_batch_ready(
                channel_id,
                runtime,
                eligibility,
                batch_started_at,
                iterations,
                staged_remaining_after,
            ) {
                break;
            }
            if !staged_batch_fence_is_clear(runtime.owner.cloud_publication_fence_observation(
                runtime.operation,
                eligibility.binding.scope.authorization_generation,
                Some(&eligibility.binding.scope),
            )) {
                break;
            }

            // The negative-only cloud observation can take time. Recheck the
            // quantum and all live scheduler gates before one more same-message
            // fragment; a changed gate merely ends batching.
            if !self.staged_batch_ready(
                channel_id,
                runtime,
                eligibility,
                batch_started_at,
                iterations,
                staged_remaining_after,
            ) {
                break;
            }

            let Some(before_remaining) = staged_remaining_after else {
                break;
            };
            let advanced = self.entries.get_mut(&channel_id).is_some_and(|driver| {
                driver.advance_registry_stage(auth, runtime, Some(eligibility))
            });
            let after_remaining = self
                .entries
                .get(&channel_id)
                .and_then(Driver::staged_message_remaining);
            iterations += 1;
            progressed =
                staged_batch_made_progress(advanced, Some(before_remaining), after_remaining);
            staged_remaining_after = after_remaining;
        }

        let staged_settled = staged_before
            && !self
                .entries
                .get(&channel_id)
                .is_some_and(Driver::has_staged_message);
        if staged_settled {
            self.note_staged_message_transition(true, false);
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
        self.idle_yield_pending = false;
        self.ordinary_yield_pending = false;
        if let Some(coordinator) = self.coordinator.upgrade() {
            let _ = coordinator.set_started_git_terminal_continuation(None);
        }
        self.publish_client_observation();
    }

    fn can_admit(&self, channel_id: ChannelId) -> bool {
        self.entries.len() < MAX_CHANNELS && !self.entries.contains_key(&channel_id)
    }

    fn new_driver(&self) -> Result<Driver<'cancel>, &'static str> {
        let driver = Driver::with_coordinator(self.cancelled, self.coordinator.clone());

        Ok(driver)
    }

    fn insert_admitted(&mut self, channel_id: ChannelId, driver: Driver<'cancel>) {
        debug_assert!(self.can_admit(channel_id));
        let previous = self.entries.insert(channel_id, driver);
        debug_assert!(previous.is_none());
        self.round_robin.push_back(channel_id);
    }

    fn next_registry_channel(&mut self, due: Option<ChannelId>) -> Option<ChannelId> {
        let entries = &self.entries;
        select_registry_channel(
            due,
            &mut self.ordinary_yield_pending,
            &mut self.round_robin,
            |channel_id| entries.get(&channel_id).map(Driver::has_staged_output),
        )
    }

    /// Refresh the pending or established connection with the earliest
    /// impending peer cutoff before ordinary round-robin work. Each successful
    /// refresh leaves this window; a failed or expired refresh closes and
    /// prunes that channel.
    fn next_peer_refresh(&mut self, now: Instant) -> Option<ChannelId> {
        let round_robin = &self.round_robin;
        let entries = &self.entries;
        let selected = earliest_peer_refresh(
            round_robin,
            |channel_id| {
                entries
                    .get(&channel_id)
                    .and_then(|driver| driver.peer_refresh_deadline(now))
            },
            |channel_id| {
                entries
                    .get(&channel_id)
                    .is_some_and(Driver::has_established_connection)
            },
        )?;
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
}

fn next_matching_round_robin(
    round_robin: &mut VecDeque<ChannelId>,
    mut matches: impl FnMut(ChannelId) -> Option<bool>,
) -> Option<ChannelId> {
    round_robin.retain(|channel_id| matches(*channel_id).is_some());
    let index = round_robin
        .iter()
        .position(|channel_id| matches(*channel_id) == Some(true))?;
    let channel_id = round_robin.remove(index)?;
    round_robin.push_back(channel_id);
    Some(channel_id)
}

fn select_registry_channel(
    due: Option<ChannelId>,
    ordinary_yield_pending: &mut bool,
    round_robin: &mut VecDeque<ChannelId>,
    mut has_staged_output: impl FnMut(ChannelId) -> Option<bool>,
) -> Option<ChannelId> {
    if due.is_some() {
        return due;
    }
    if *ordinary_yield_pending {
        if let Some(channel_id) = next_matching_round_robin(round_robin, |channel_id| {
            has_staged_output(channel_id).map(|_| true)
        }) {
            *ordinary_yield_pending = false;
            return Some(channel_id);
        }
    }
    next_matching_round_robin(round_robin, &mut has_staged_output).or_else(|| {
        next_matching_round_robin(round_robin, |channel_id| {
            has_staged_output(channel_id).map(|_| true)
        })
    })
}

fn earliest_peer_refresh(
    round_robin: &VecDeque<ChannelId>,
    mut cutoff: impl FnMut(ChannelId) -> Option<Instant>,
    mut established: impl FnMut(ChannelId) -> bool,
) -> Option<ChannelId> {
    round_robin
        .iter()
        .filter_map(|channel_id| {
            cutoff(*channel_id).map(|deadline| (*channel_id, deadline, established(*channel_id)))
        })
        .min_by_key(|(_, deadline, is_established)| (*deadline, !*is_established))
        .map(|(channel_id, _, _)| channel_id)
}

#[cfg(test)]
mod tests {
    use super::super::super::{IdleScheduler, WorkClass};
    use super::*;

    #[test]
    fn staged_batch_requires_no_owed_turn_due_refresh_writer_or_dead_output() {
        assert!(staged_batch_initial_allowed(
            false,
            false,
            true,
            Some(4),
            false,
            true,
        ));
        for (ordinary_yield, due, staged, remaining, writer, live) in [
            (true, false, true, Some(4), false, true),
            (false, true, true, Some(4), false, true),
            (false, false, false, Some(4), false, true),
            (false, false, true, None, false, true),
            (false, false, true, Some(4), true, true),
            (false, false, true, Some(4), false, false),
        ] {
            assert!(!staged_batch_initial_allowed(
                ordinary_yield,
                due,
                staged,
                remaining,
                writer,
                live,
            ));
        }
    }

    #[test]
    fn staged_batch_requires_strict_same_message_progress_and_all_live_gates() {
        assert!(staged_batch_made_progress(true, Some(5), Some(4)));
        assert!(!staged_batch_made_progress(false, Some(5), Some(4)));
        assert!(!staged_batch_made_progress(true, Some(5), Some(5)));
        assert!(!staged_batch_made_progress(true, Some(5), None));
        assert!(!staged_batch_made_progress(true, Some(1), Some(0)));

        let can_continue = |elapsed, iterations, staged, due, writer, live| {
            staged_batch_can_continue(
                true,
                Some(4),
                elapsed,
                iterations,
                staged,
                due,
                writer,
                live,
            )
        };
        assert!(can_continue(
            Duration::from_millis(9),
            1,
            true,
            false,
            false,
            true
        ));
        assert!(!can_continue(
            Duration::from_millis(10),
            1,
            true,
            false,
            false,
            true
        ));
        assert!(!can_continue(
            Duration::from_millis(1),
            MAX_FRAGMENTS_PER_MESSAGE,
            true,
            false,
            false,
            true,
        ));
        assert!(!can_continue(Duration::ZERO, 1, false, false, false, true));
        assert!(!can_continue(Duration::ZERO, 1, true, true, false, true));
        assert!(!can_continue(Duration::ZERO, 1, true, false, true, true));
        assert!(!can_continue(Duration::ZERO, 1, true, false, false, false));
    }

    #[test]
    fn staged_batch_stops_on_every_nonclear_cloud_observation() {
        use super::super::super::shared_owner::CloudPublicationFenceObservation;

        assert!(staged_batch_fence_is_clear(Ok(
            CloudPublicationFenceObservation::Clear
        )));
        assert!(!staged_batch_fence_is_clear(Ok(
            CloudPublicationFenceObservation::CloseIngress
        )));
        assert!(!staged_batch_fence_is_clear(Ok(
            CloudPublicationFenceObservation::Defer
        )));
        assert!(!staged_batch_fence_is_clear(Err(
            super::super::super::shared_owner::Error::Domain(
                super::super::super::owner_domain::Error::Stale
            )
        )));
    }

    #[test]
    fn staged_batch_finishes_only_the_current_fragment_sequence_within_bounds() {
        let mut remaining = Some(33);
        let mut iterations = 1;
        let mut fragment_calls = 1;
        let mut progressed = staged_batch_made_progress(true, Some(34), remaining);
        while staged_batch_can_continue(
            progressed,
            remaining,
            Duration::from_millis(1),
            iterations,
            true,
            false,
            false,
            true,
        ) {
            let before = remaining;
            remaining = before
                .and_then(|count| count.checked_sub(1))
                .filter(|count| *count > 0);
            fragment_calls += 1;
            iterations += 1;
            progressed = staged_batch_made_progress(true, before, remaining);
        }
        assert_eq!(fragment_calls, 34);
        assert_eq!(
            remaining, None,
            "completion ends the batch before a next message"
        );
        assert!(iterations <= MAX_FRAGMENTS_PER_MESSAGE);
    }

    #[test]
    fn earlier_pending_handshake_refresh_precedes_later_established_refresh() {
        let pending = ChannelId::from_bytes([1; 16]).unwrap();
        let established = ChannelId::from_bytes([2; 16]).unwrap();
        let pending_cutoff = Instant::now() + Duration::from_secs(1);
        let established_cutoff = pending_cutoff + Duration::from_secs(1);
        let round_robin = VecDeque::from([established, pending]);

        let selected = earliest_peer_refresh(
            &round_robin,
            |channel_id| match channel_id {
                id if id == pending => Some(pending_cutoff),
                id if id == established => Some(established_cutoff),
                _ => None,
            },
            |channel_id| channel_id == established,
        );

        assert_eq!(selected, Some(pending));
    }

    #[test]
    fn candidate_and_ticket_deadlines_precede_later_parent_refreshes() {
        let parent = ChannelId::from_bytes([3; 16]).unwrap();
        let ticketed = ChannelId::from_bytes([4; 16]).unwrap();
        let candidate = ChannelId::from_bytes([5; 16]).unwrap();
        let now = Instant::now();
        let parent_cutoff = now + Duration::from_millis(2_500);
        let ticket_cutoff = now + Duration::from_millis(1_500);
        let candidate_cutoff = now + Duration::from_millis(500);
        let round_robin = VecDeque::from([parent, ticketed, candidate]);

        let selected = earliest_peer_refresh(
            &round_robin,
            |channel_id| match channel_id {
                id if id == parent => Some(parent_cutoff),
                id if id == ticketed => Some(ticket_cutoff),
                id if id == candidate => Some(candidate_cutoff),
                _ => None,
            },
            |_| false,
        );

        assert_eq!(selected, Some(candidate));
    }

    #[test]
    fn earlier_parent_cutoff_still_precedes_candidate_and_ticket() {
        let parent = ChannelId::from_bytes([6; 16]).unwrap();
        let candidate = ChannelId::from_bytes([7; 16]).unwrap();
        let ticketed = ChannelId::from_bytes([8; 16]).unwrap();
        let now = Instant::now();
        let parent_cutoff = now + Duration::from_millis(250);
        let candidate_cutoff = now + Duration::from_millis(500);
        let ticket_cutoff = now + Duration::from_millis(750);
        let round_robin = VecDeque::from([candidate, ticketed, parent]);

        let selected = earliest_peer_refresh(
            &round_robin,
            |channel_id| match channel_id {
                id if id == parent => Some(parent_cutoff),
                id if id == candidate => Some(candidate_cutoff),
                id if id == ticketed => Some(ticket_cutoff),
                _ => None,
            },
            |_| false,
        );

        assert_eq!(selected, Some(parent));
    }

    #[test]
    fn equal_cutoffs_keep_round_robin_order_and_empty_cutoffs_select_none() {
        let first = ChannelId::from_bytes([9; 16]).unwrap();
        let second = ChannelId::from_bytes([10; 16]).unwrap();
        let pending = ChannelId::from_bytes([21; 16]).unwrap();
        let established = ChannelId::from_bytes([22; 16]).unwrap();
        let cutoff = Instant::now() + Duration::from_millis(500);
        let round_robin = VecDeque::from([first, second]);

        assert_eq!(
            earliest_peer_refresh(&round_robin, |_| Some(cutoff), |_| true),
            Some(first)
        );
        assert_eq!(
            earliest_peer_refresh(&round_robin, |_| None, |_| false),
            None
        );
        assert_eq!(
            earliest_peer_refresh(
                &VecDeque::from([pending, established]),
                |_| Some(cutoff),
                |channel_id| channel_id == established,
            ),
            Some(established),
            "established state breaks equal-cutoff ties only",
        );
    }

    #[test]
    fn earliest_deadline_wins_across_established_and_pending_channels() {
        let first_established = ChannelId::from_bytes([11; 16]).unwrap();
        let second_established = ChannelId::from_bytes([12; 16]).unwrap();
        let pending = ChannelId::from_bytes([13; 16]).unwrap();
        let now = Instant::now();
        let first_cutoff = now + Duration::from_millis(2_500);
        let second_cutoff = now + Duration::from_millis(2_000);
        let pending_cutoff = now + Duration::from_millis(500);
        let round_robin = VecDeque::from([first_established, second_established, pending]);
        assert_eq!(
            earliest_peer_refresh(
                &round_robin,
                |channel_id| match channel_id {
                    id if id == first_established => Some(first_cutoff),
                    id if id == second_established => Some(second_cutoff),
                    id if id == pending => Some(pending_cutoff),
                    _ => None,
                },
                |channel_id| {
                    channel_id == first_established || channel_id == second_established
                },
            ),
            Some(pending)
        );
    }

    #[test]
    fn fresh_established_observation_leaves_pending_refresh_next() {
        let established = ChannelId::from_bytes([14; 16]).unwrap();
        let pending = ChannelId::from_bytes([15; 16]).unwrap();
        let now = Instant::now();
        let established_cutoff = now + Duration::from_millis(1_500);
        let pending_cutoff = now + Duration::from_millis(2_000);
        let refreshed_cutoff = now + super::super::PEER_REFRESH_MARGIN + Duration::from_nanos(1);
        let round_robin = VecDeque::from([established, pending]);
        assert_eq!(
            earliest_peer_refresh(
                &round_robin,
                |channel_id| {
                    if channel_id == established {
                        Some(established_cutoff)
                    } else {
                        Some(pending_cutoff)
                    }
                },
                |channel_id| channel_id == established,
            ),
            Some(established)
        );

        // A fresh observation moves the first established channel outside the
        // due window, leaving pending work eligible on the next registry pass.
        assert_eq!(
            super::super::peer_refresh_deadline_for(true, refreshed_cutoff, now),
            None
        );
        assert_eq!(
            earliest_peer_refresh(
                &round_robin,
                |channel_id| {
                    if channel_id == established {
                        super::super::peer_refresh_deadline_for(true, refreshed_cutoff, now)
                    } else {
                        super::super::peer_refresh_deadline_for(true, pending_cutoff, now)
                    }
                },
                |channel_id| channel_id == established,
            ),
            Some(pending)
        );
    }

    #[test]
    fn child_deadline_first_leaves_time_for_parent_refresh_after_heartbeat() {
        let child = ChannelId::from_bytes([23; 16]).unwrap();
        let parent = ChannelId::from_bytes([24; 16]).unwrap();
        let start = Instant::now();
        let child_cutoff = start + Duration::from_millis(866);
        let parent_cutoff = start + Duration::from_millis(2_565);
        let child_connect = Duration::from_millis(844);
        let cloud_heartbeat = Duration::from_millis(190);
        let parent_refresh = Duration::from_millis(592);
        let round_robin = VecDeque::from([parent, child]);

        let selected = earliest_peer_refresh(
            &round_robin,
            |channel_id| match channel_id {
                id if id == child => {
                    super::super::peer_refresh_deadline_for(true, child_cutoff, start)
                }
                id if id == parent => {
                    super::super::peer_refresh_deadline_for(true, parent_cutoff, start)
                }
                _ => None,
            },
            |channel_id| channel_id == parent,
        );
        assert_eq!(selected, Some(child));

        let child_completed = start + child_connect;
        assert!(child_completed < child_cutoff);
        let after_heartbeat = child_completed + cloud_heartbeat;
        let refreshed_child_cutoff = child_completed + Duration::from_secs(5);
        let selected = earliest_peer_refresh(
            &round_robin,
            |channel_id| match channel_id {
                id if id == child => super::super::peer_refresh_deadline_for(
                    true,
                    refreshed_child_cutoff,
                    after_heartbeat,
                ),
                id if id == parent => {
                    super::super::peer_refresh_deadline_for(true, parent_cutoff, after_heartbeat)
                }
                _ => None,
            },
            |channel_id| channel_id == parent,
        );
        assert_eq!(selected, Some(parent));
        assert!(after_heartbeat < parent_cutoff);
        assert!(after_heartbeat + parent_refresh < parent_cutoff);
    }

    #[test]
    fn expired_or_unknown_cutoffs_are_skipped() {
        let expired = ChannelId::from_bytes([25; 16]).unwrap();
        let live = ChannelId::from_bytes([26; 16]).unwrap();
        let cutoff = Instant::now() + Duration::from_millis(500);

        assert_eq!(
            earliest_peer_refresh(
                &VecDeque::from([expired, live]),
                |channel_id| (channel_id == live).then_some(cutoff),
                |_| false,
            ),
            Some(live)
        );
    }

    #[test]
    fn sibling_message_completions_grant_global_idle_yields() {
        let cancelled = AtomicBool::new(false);
        let mut registry = Registry::with_coordinator(&cancelled, Weak::new());
        let mut idle = IdleScheduler::default();
        let reserved_class = idle
            .select_class_for_ready_turn(false, false, false, false, true, false, true)
            .expect("cached Channel reservation");
        assert_eq!(reserved_class, WorkClass::Channel);
        assert!(!idle.after_step(reserved_class, false, true, false));
        let retained_reservation = idle.reservation;
        let mut staged = [true, false, true];
        let events = [
            (0, false), // Flush A
            (1, true),  // Stage B
            (2, false), // Flush C
            (0, true),  // Stage A
            (1, false), // Flush B
            (2, true),  // Stage C
            (0, false), // Flush A
            (1, true),  // Stage B
            (2, false), // Flush C
            (0, true),  // Stage A
            (1, false), // Flush B
            (2, true),  // Stage C
        ];
        let mut idle_turns = 0;

        for (channel, is_staged_after) in events {
            let any_staged = staged.iter().any(|is_staged| *is_staged);
            let priority_ingress_pending = registry.idle_priority_pending(false, any_staged, false);
            let reservation_before = idle.reservation;
            let selected = idle.select_class_for_ready_turn(
                priority_ingress_pending,
                false,
                false,
                false,
                true,
                false,
                true,
            );
            if priority_ingress_pending {
                assert_eq!(selected, None);
                assert_eq!(idle.reservation, retained_reservation);
                assert_eq!(idle.reservation, reservation_before);
            } else {
                let class = selected.expect("one idle opportunity after message completion");
                assert_eq!(class, reserved_class);
                idle_turns += 1;
                assert!(!idle.after_step(class, false, true, false));
                assert_eq!(idle.reservation, retained_reservation);
            }

            let was_staged = staged[channel];
            assert_ne!(was_staged, is_staged_after);
            staged[channel] = is_staged_after;
            registry.note_staged_message_transition(was_staged, is_staged_after);
        }

        assert_eq!(idle_turns, 6);
        assert_eq!(staged, [true, false, true]);
        assert_eq!(idle.reservation, retained_reservation);
    }

    #[test]
    fn setup_keeps_global_idle_yield_pending_until_setup_finishes() {
        let cancelled = AtomicBool::new(false);
        let mut registry = Registry::with_coordinator(&cancelled, Weak::new());
        registry.note_staged_message_transition(true, false);

        assert!(registry.idle_priority_pending(true, true, false));
        assert!(!registry.idle_priority_pending(false, true, false));
        assert!(registry.idle_priority_pending(false, true, false));
    }

    #[test]
    fn due_peer_refresh_preserves_cached_idle_reservations_and_owed_yield() {
        let due_peer_refresh = true;
        let refreshed_peer_refresh = false;

        for (class, peer_cached, channel_cached) in [
            (WorkClass::Peer, true, false),
            (WorkClass::Channel, false, true),
        ] {
            let cancelled = AtomicBool::new(false);
            let mut registry = Registry::with_coordinator(&cancelled, Weak::new());
            registry.note_staged_message_transition(true, false);

            let mut idle = IdleScheduler::default();
            assert_eq!(
                idle.select_class_for_ready_turn(
                    false,
                    false,
                    peer_cached,
                    false,
                    channel_cached,
                    false,
                    true,
                ),
                Some(class)
            );
            assert!(!idle.after_step(class, false, true, false));
            let cached_reservation = idle.reservation;

            // A due peer refresh suppresses cached idle work without consuming
            // the owed turn or dropping either scheduler reservation.
            assert!(registry.idle_priority_pending(false, true, due_peer_refresh));
            assert!(registry.idle_yield_pending);
            assert_eq!(
                idle.select_class_for_ready_turn(
                    true,
                    false,
                    peer_cached,
                    false,
                    channel_cached,
                    false,
                    true,
                ),
                None
            );
            assert_eq!(idle.reservation, cached_reservation);

            // Once the peer cutoff is refreshed outside the due window, the
            // owed idle turn runs even though sibling ingress remains staged.
            assert!(!registry.idle_priority_pending(false, true, refreshed_peer_refresh));
            assert!(!registry.idle_yield_pending);
            assert_eq!(
                idle.select_class_for_ready_turn(
                    false,
                    false,
                    peer_cached,
                    false,
                    channel_cached,
                    false,
                    true,
                ),
                Some(class)
            );
            assert_eq!(idle.reservation, cached_reservation);
        }
    }

    #[test]
    fn due_peer_refresh_keeps_registry_yield_for_the_next_turn() {
        let due = ChannelId::from_bytes([16; 16]).unwrap();
        let staged = ChannelId::from_bytes([17; 16]).unwrap();
        let mut round_robin = VecDeque::from([staged]);
        let mut ordinary_yield_pending = true;

        assert_eq!(
            select_registry_channel(
                Some(due),
                &mut ordinary_yield_pending,
                &mut round_robin,
                |_| { panic!("a due refresh must win before staged output") }
            ),
            Some(due)
        );
        assert!(ordinary_yield_pending);
        assert_eq!(round_robin, VecDeque::from([staged]));
    }

    #[test]
    fn registry_yield_services_round_robin_before_remaining_staged_output() {
        let idle = ChannelId::from_bytes([18; 16]).unwrap();
        let first_staged = ChannelId::from_bytes([19; 16]).unwrap();
        let second_staged = ChannelId::from_bytes([20; 16]).unwrap();
        let mut round_robin = VecDeque::from([idle, first_staged, second_staged]);
        let mut ordinary_yield_pending = true;
        let staged = |channel_id| Some(channel_id != idle);

        assert_eq!(
            select_registry_channel(None, &mut ordinary_yield_pending, &mut round_robin, staged),
            Some(idle)
        );
        assert!(!ordinary_yield_pending);
        assert_eq!(
            select_registry_channel(None, &mut ordinary_yield_pending, &mut round_robin, staged),
            Some(first_staged)
        );
        assert_eq!(
            select_registry_channel(None, &mut ordinary_yield_pending, &mut round_robin, staged),
            Some(second_staged)
        );
        assert_eq!(round_robin.len(), 3);
    }

    #[test]
    fn completed_staged_message_yields_to_idle_channel_before_sibling_output() {
        let idle = ChannelId::from_bytes([25; 16]).unwrap();
        let completed = ChannelId::from_bytes([26; 16]).unwrap();
        let sibling = ChannelId::from_bytes([27; 16]).unwrap();
        let mut round_robin = VecDeque::from([idle, completed, sibling]);
        let staged = |channel_id| Some(channel_id != idle);
        let mut ordinary_yield_pending = false;

        assert_eq!(
            select_registry_channel(None, &mut ordinary_yield_pending, &mut round_robin, staged),
            Some(completed)
        );
        assert_eq!(round_robin, VecDeque::from([idle, sibling, completed]));

        let cancelled = AtomicBool::new(false);
        let mut registry = Registry::with_coordinator(&cancelled, Weak::new());
        registry.note_staged_message_transition(true, false);
        assert!(registry.ordinary_yield_pending);

        assert_eq!(
            select_registry_channel(
                None,
                &mut registry.ordinary_yield_pending,
                &mut round_robin,
                staged
            ),
            Some(idle)
        );
        assert!(!registry.ordinary_yield_pending);
        assert_eq!(round_robin, VecDeque::from([sibling, completed, idle]));
    }

    #[test]
    fn staged_output_round_robins_and_skips_unknown_or_unstaged_channels() {
        let unknown = ChannelId::from_bytes([21; 16]).unwrap();
        let producer_only = ChannelId::from_bytes([22; 16]).unwrap();
        let first_staged = ChannelId::from_bytes([23; 16]).unwrap();
        let second_staged = ChannelId::from_bytes([24; 16]).unwrap();
        let mut round_robin = VecDeque::from([unknown, producer_only, first_staged, second_staged]);
        let mut ordinary_yield_pending = false;
        let has_staged = |channel_id| match channel_id {
            id if id == unknown => None,
            id if id == producer_only => Some(false),
            _ => Some(true),
        };

        assert_eq!(
            select_registry_channel(
                None,
                &mut ordinary_yield_pending,
                &mut round_robin,
                has_staged
            ),
            Some(first_staged)
        );
        assert_eq!(
            select_registry_channel(
                None,
                &mut ordinary_yield_pending,
                &mut round_robin,
                has_staged
            ),
            Some(second_staged)
        );
        assert_eq!(round_robin.len(), 3);
        assert!(!round_robin.contains(&unknown));

        let mut unstaged = VecDeque::from([producer_only, first_staged]);
        let only_unstaged = |channel_id| (channel_id == producer_only).then_some(false);
        assert_eq!(
            select_registry_channel(
                None,
                &mut ordinary_yield_pending,
                &mut unstaged,
                only_unstaged
            ),
            Some(producer_only)
        );
        assert_eq!(unstaged.len(), 1);
        assert_eq!(unstaged.front(), Some(&producer_only));
    }
}
