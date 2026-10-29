//! Capture the original operation before decoding any local request frame.
use super::owner_domain::{Error, Operation};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

pub(super) struct IpcAdmission<'a> {
    started: Instant,
    operation: Operation<'a>,
}
impl<'a> IpcAdmission<'a> {
    /// Capture once BEFORE read_request, and set the connection to deadline().
    pub(super) fn capture(budget: Duration, cancelled: &'a AtomicBool) -> Result<Self, Error> {
        Self::at(Instant::now(), budget, cancelled)
    }
    fn at(started: Instant, budget: Duration, cancelled: &'a AtomicBool) -> Result<Self, Error> {
        let deadline = started.checked_add(budget).ok_or(Error::Exhausted)?;
        Ok(Self {
            started,
            operation: Operation::new(deadline, cancelled),
        })
    }
    pub(super) fn deadline(&self) -> Instant {
        self.operation.deadline()
    }
    /// Bound frame decoding separately while retaining the original start for
    /// a longer typed operation budget. A slow frame never receives a new
    /// operation clock after its contents are decoded.
    pub(super) fn frame_deadline(&self, budget: Duration) -> Instant {
        self.started
            .checked_add(budget)
            .unwrap_or(self.deadline())
            .min(self.deadline())
    }

    /// Consume this admission after decoding. Frame time counts toward BOTH
    /// budgets. Moving this existing Operation preserves its observed cancel
    /// latch; no provider scope or pending writer exists before this handoff.
    pub(super) fn into_operation(
        mut self,
        decoded_timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        self.operation.check()?;
        let cap = self
            .started
            .checked_add(decoded_timeout)
            .unwrap_or(self.deadline());
        self.operation.cap_deadline(cap);
        self.operation.check()?;
        Ok(self.operation)
    }
}
