//! Focused owned current-peer and request-budget source regressions.
//! Authored only. These tests do not claim the full TLS/Noise ingress matrix.
use super::*;

#[test]
fn owned_current_peer_rejects_wrong_owner_with_original_source_and_operation() {
    tests::fixture(|f, auth| {
        let source = retained_terminal_tests::source(f, auth);
        let proof = retained_terminal_tests::verified(f, auth, source);
        let worker = f
            .runtime()
            .remote_worker_evidence(auth, &f.eligibility)
            .unwrap_or_else(|_| panic!("actual worker evidence"));
        assert!(proof.current(&worker));
        tests::fixture(|other, _| {
            // Keep exact original operation/provider/source; replace only the
            // owner. Sealed continuation must reject this independently of ptrs.
            let foreign = Runtime {
                owner: &other.owner,
                ..f.runtime()
            };
            assert!(
                foreign
                    .remote_worker_evidence(auth, &f.eligibility)
                    .is_err(),
                "foreign owner must be rejected before current-peer evidence exists",
            );
        });
        assert!(proof.current(&worker));
    });
}

#[test]
fn fresh_current_peer_read_without_script_is_closed() {
    tests::fixture(|f, auth| {
        let source = retained_terminal_tests::source(f, auth);
        let result =
            Worker::default().read_current_pairing(auth, f.runtime(), &f.eligibility, source);
        assert!(
            result.is_err(),
            "unscripted GET must never fall back to account network"
        );
    });
}

#[test]
fn moved_request_operation_retains_deadline_identity_and_actual_cancellation() {
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(3);
    let operation = owner_domain::Operation::new(deadline, &cancelled);
    let identity = operation.retained_identity();
    fn transfer<'a>(operation: owner_domain::Operation<'a>) -> owner_domain::Operation<'a> {
        operation
    }
    let operation = transfer(operation);
    assert_eq!(operation.deadline(), deadline);
    assert!(operation.is_same_admission(&identity));
    cancelled.store(true, Ordering::Release);
    assert!(matches!(
        operation.check(),
        Err(owner_domain::Error::Cancelled)
    ));
    cancelled.store(false, Ordering::Release);
    assert!(matches!(
        operation.check(),
        Err(owner_domain::Error::Cancelled)
    ));
}

#[test]
fn expired_remote_operation_marks_its_own_abort_cell_only() {
    tests::fixture(|f, _| {
        let outer = f.runtime();
        assert!(!outer.aborted.get());
        let operation =
            owner_domain::Operation::new(Instant::now() - Duration::from_millis(1), &f.stopping);
        let aborted = std::cell::Cell::new(false);
        let remote = Runtime {
            operation: &operation,
            aborted: &aborted,
            ..outer
        };
        assert!(check_peer_runtime(remote).is_err());
        assert!(aborted.get());
        assert!(
            !outer.aborted.get(),
            "remote expiry poisoned the auth worker unit"
        );
        assert!(outer.check().is_ok(), "normal Cloud work cannot continue");
    });
}

#[test]
fn current_peer_io_deadline_never_outlives_retained_proof_or_worker() {
    tests::fixture(|f, auth| {
        let source = retained_terminal_tests::source(f, auth);
        let proof = retained_terminal_tests::verified(f, auth, source);
        let evidence = f
            .runtime()
            .remote_worker_evidence(auth, &f.eligibility)
            .unwrap_or_else(|_| panic!("actual worker evidence"));
        let deadline = proof.io_deadline(&evidence).expect("live IO deadline");
        assert!(deadline <= proof.fresh_until());
        assert!(deadline <= f.runtime().operation.deadline());
        assert!(deadline > Instant::now());
    });
}

#[test]
fn current_peer_refresh_after_the_original_cutoff_remains_closed() {
    peer::current_pairing_script::clear();
    tests::fixture(|f, auth| {
        let source = retained_terminal_tests::source(f, auth);
        peer::current_pairing_script::enqueue(
            source.intent.preparation.pairing_id,
            source.response.clone(),
        );
        let result = peer::Worker::default().read_current_pairing_bounded(
            auth,
            f.runtime(),
            &f.eligibility,
            source,
            Instant::now() - Duration::from_millis(1),
        );
        assert!(
            result.is_err(),
            "a fresh pairing GET cannot revive a connection after its old proof cutoff"
        );
    });
    peer::current_pairing_script::clear();
}
