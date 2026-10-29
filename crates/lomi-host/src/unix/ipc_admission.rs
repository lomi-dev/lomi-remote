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
    #[cfg(test)]
    pub(super) fn check(&self) -> Result<(), Error> {
        self.operation.check()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering::SeqCst;

    #[test]
    fn decoded_timeout_counts_time_spent_reading_frame() {
        let cancel = AtomicBool::new(false);
        let started = Instant::now() - Duration::from_secs(10);
        let admission = IpcAdmission::at(started, Duration::from_secs(60), &cancel).unwrap();
        assert!(matches!(
            admission.into_operation(Duration::from_secs(5)),
            Err(Error::Deadline)
        ));
    }
    #[test]
    fn larger_decoded_timeout_never_extends_original_frame_budget() {
        let cancel = AtomicBool::new(false);
        let admission = IpcAdmission::capture(Duration::from_secs(60), &cancel).unwrap();
        let original = admission.deadline();
        admission.check().unwrap();
        let operation = admission.into_operation(Duration::from_secs(120)).unwrap();
        assert_eq!(operation.deadline(), original);
    }
    #[test]
    fn shorter_decoded_timeout_uses_original_start() {
        let cancel = AtomicBool::new(false);
        let started = Instant::now() - Duration::from_secs(10);
        let admission = IpcAdmission::at(started, Duration::from_secs(120), &cancel).unwrap();
        let operation = admission.into_operation(Duration::from_secs(60)).unwrap();
        assert_eq!(operation.deadline(), started + Duration::from_secs(60));
    }
    #[test]
    fn cancellation_observed_during_frame_survives_latch_reset() {
        let cancel = AtomicBool::new(false);
        let admission = IpcAdmission::capture(Duration::from_secs(60), &cancel).unwrap();
        cancel.store(true, SeqCst);
        assert_eq!(admission.check(), Err(Error::Cancelled));
        cancel.store(false, SeqCst);
        assert!(matches!(
            admission.into_operation(Duration::from_secs(60)),
            Err(Error::Cancelled)
        ));
    }
    #[test]
    fn expired_frame_cannot_receive_fresh_decoded_budget() {
        let cancel = AtomicBool::new(false);
        let started = Instant::now() - Duration::from_secs(20);
        let admission = IpcAdmission::at(started, Duration::from_secs(10), &cancel).unwrap();
        assert!(matches!(
            admission.into_operation(Duration::from_secs(600)),
            Err(Error::Deadline)
        ));
    }
    #[test]
    fn cancellation_arriving_after_decode_uses_same_external_latch() {
        let cancel = AtomicBool::new(false);
        let operation = IpcAdmission::capture(Duration::from_secs(60), &cancel)
            .unwrap()
            .into_operation(Duration::from_secs(30))
            .unwrap();
        cancel.store(true, SeqCst);
        assert_eq!(operation.check(), Err(Error::Cancelled));
        cancel.store(false, SeqCst);
        assert_eq!(operation.check(), Err(Error::Cancelled));
    }
}
