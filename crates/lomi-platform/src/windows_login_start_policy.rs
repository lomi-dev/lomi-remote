//! Readiness after one successful Scheduler Run, using one caller-owned deadline.
//! Scheduler state alone cannot prove either host readiness or launch failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Observation {
    SchedulerOnly,
    PreviousGeneration,
    NewGenerationPending,
    NewGenerationReady,
    NewGenerationFinished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    Wait,
    Ready,
    NotReady,
    Deadline,
}

pub(crate) fn decide(observation: Observation, deadline_expired: bool) -> Decision {
    if deadline_expired {
        return Decision::Deadline;
    }
    match observation {
        Observation::NewGenerationReady => Decision::Ready,
        Observation::NewGenerationFinished => Decision::NotReady,
        Observation::SchedulerOnly
        | Observation::PreviousGeneration
        | Observation::NewGenerationPending => Decision::Wait,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_admission_waits_until_fresh_authenticated_ipc() {
        // READY, then QUEUED, then RUNNING: none is an authenticated host.
        for observation in [
            Observation::SchedulerOnly,
            Observation::SchedulerOnly,
            Observation::NewGenerationPending,
        ] {
            assert_eq!(decide(observation, false), Decision::Wait);
        }
        assert_eq!(
            decide(Observation::NewGenerationReady, false),
            Decision::Ready
        );
    }

    #[test]
    fn previous_clean_running_or_failed_marker_never_authorizes_readiness() {
        assert_eq!(
            decide(Observation::PreviousGeneration, false),
            Decision::Wait
        );
    }

    #[test]
    fn fresh_completion_rejects_the_new_instance() {
        assert_eq!(
            decide(Observation::NewGenerationFinished, false),
            Decision::NotReady
        );
    }

    #[test]
    fn all_observations_obey_the_original_deadline() {
        for observation in [
            Observation::SchedulerOnly,
            Observation::PreviousGeneration,
            Observation::NewGenerationPending,
            Observation::NewGenerationReady,
            Observation::NewGenerationFinished,
        ] {
            assert_eq!(decide(observation, true), Decision::Deadline);
        }
    }

    #[test]
    fn immediate_restart_requires_another_fresh_bound_generation() {
        assert_eq!(
            decide(Observation::NewGenerationReady, false),
            Decision::Ready
        );
        // The next operation's pre-Run snapshot makes that same run previous.
        assert_eq!(
            decide(Observation::PreviousGeneration, false),
            Decision::Wait
        );
        assert_eq!(
            decide(Observation::NewGenerationReady, false),
            Decision::Ready
        );
    }
}
