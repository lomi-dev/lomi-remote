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
