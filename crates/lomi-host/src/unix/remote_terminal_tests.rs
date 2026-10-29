//! Pure state and allowlist regressions. No PTY/process/provider/network runs.
use super::*;
fn context() -> TerminalContext {
    TerminalContext {
        workspace: WorkspaceContext {
            workspace_id: WorkspaceId::from_bytes([1; 16]).unwrap(),
            workspace_epoch: WorkspaceEpoch::from_bytes([2; 16]).unwrap(),
            runtime_id: RuntimeId::from_bytes([3; 16]).unwrap(),
            runtime_generation: DecimalU64(4),
            host_access_epoch: DecimalU64(5),
            grant_revision: DecimalU64(6),
        },
        pane_id: PaneId::from_bytes([7; 16]).unwrap(),
        session_id: TerminalSessionId::from_bytes([8; 16]).unwrap(),
        session_epoch: SessionEpoch::from_bytes([9; 16]).unwrap(),
        profile: TerminalProfile::ExperimentalRustGridV1,
    }
}
fn state() -> RemoteTerminalState {
    RemoteTerminalState {
        coordinator: Weak::new(),
        principal: AuthenticatedConnection::new(
            ConsumerAuthorizationId::from_bytes([10; 16]).unwrap(),
        ),
        channel: Uuid::new_v4(),
        subscriptions: HashMap::new(),
        leases: HashMap::new(),
        schedule: VecDeque::new(),
        pending: None,
        disconnected: false,
    }
}
fn prepare(state: &mut RemoteTerminalState) -> RemoteTerminalStreamFrame {
    let terminal = context();
    let frame = TerminalStreamFrame::ResyncRequired(TerminalResync {
        terminal: terminal.clone(),
        subscription_id: "stream".to_owned().try_into().unwrap(),
        reason: ResyncReason::SubscriberOverflow,
    });
    state.prepare("stream", terminal, frame, None, true)
}
#[test]
fn foreign_delivery_cannot_consume_outstanding_frame() {
    let mut active = state();
    let original = prepare(&mut active);
    let pending = active.pending.as_ref().unwrap().id;
    let foreign = prepare(&mut state());
    assert!(active.commit_delivery(foreign).is_err());
    assert_eq!(active.pending.as_ref().unwrap().id, pending);
    active.commit_delivery(original).unwrap();
    assert!(active.pending.is_none());
}
#[test]
fn disconnect_abandons_pending_delivery_and_cannot_resume_it() {
    let mut state = state();
    let frame = prepare(&mut state);
    state.disconnect();
    assert!(state.disconnected);
    assert!(state.pending.is_none());
    assert!(state.commit_delivery(frame).is_err());
}
#[test]
fn target_allowlist_preserves_complete_tuple_and_rejects_workspace_calls() {
    let terminal = context();
    for call in [
        RpcCall::TerminalAttach(TerminalReadParams {
            terminal: terminal.clone(),
        }),
        RpcCall::TerminalSnapshot(TerminalReadParams {
            terminal: terminal.clone(),
        }),
    ] {
        assert_eq!(target(&call), Some(&terminal));
    }
    assert!(
        target(&RpcCall::WorkspaceGet(WorkspaceReadParams {
            context: terminal.workspace.clone()
        }))
        .is_none()
    );
}

// This test starts a controlled raw-mode PTY which deliberately never reads
// stdin, so kernel PTY backpressure must produce a real partial/no-progress
// receipt within the cap.
#[cfg(unix)]
#[test]
fn real_pty_backpressure_preserves_partial_receipt_and_never_replays_duplicate() {
    use lomi_terminal::{InputOutcome, SpawnProfile, TerminalService};
    use std::time::{Duration, Instant};
    let temp = tempfile::tempdir().unwrap();
    let service = TerminalService::new(); // Drop shuts down its owned child.
    let context = context();
    service
        .spawn(
            context.session_id,
            context.session_epoch,
            &SpawnProfile {
                executable: "/bin/sh".into(),
                args: vec![
                    "-c".into(),
                    "stty raw -echo; printf 'BACKPRESSURE_READY\\r\\n'; sleep 30".into(),
                ],
                cwd: temp.path().canonicalize().unwrap(),
                environment: vec![("PATH".into(), "/usr/bin:/bin".into())],
                shell_integration: None,
                rows: 8,
                cols: 40,
                history: 0,
            },
        )
        .unwrap();
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = service
            .snapshot(context.session_id, context.session_epoch)
            .unwrap();
        let visible: String = snapshot
            .normal
            .lines
            .iter()
            .flat_map(|row| row.cells.iter().map(|cell| cell.text.as_str()))
            .collect();
        if visible.contains("BACKPRESSURE_READY") {
            break;
        }
        assert!(
            Instant::now() < ready_deadline,
            "controlled raw PTY did not become ready; visible={visible:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let principal =
        AuthenticatedConnection::new(ConsumerAuthorizationId::from_bytes([44; 16]).unwrap());
    let attachment = service
        .attach(context.session_id, context.session_epoch, &principal)
        .unwrap();
    attachment
        .acknowledge(&principal, attachment.snapshot.sequence.0)
        .unwrap();
    let mut lease = service
        .claim(context.session_id, context.session_epoch, &principal)
        .unwrap();
    let bytes = vec![b'X'; lomi_terminal::INPUT_LIMIT];
    let mut accepted_total = 0;
    let mut partial = None;
    for sequence in 1..=64 {
        lease = service
            .renew(
                context.session_id,
                context.session_epoch,
                &principal,
                &lease,
            )
            .unwrap();
        let receipt = service
            .input(
                context.session_id,
                context.session_epoch,
                &principal,
                &lease,
                sequence,
                sequence,
                &bytes,
                || true,
            )
            .unwrap();
        accepted_total += receipt.accepted_bytes;
        if receipt.outcome == InputOutcome::Unknown {
            partial = Some((sequence, receipt));
            break;
        }
    }
    let (sequence, receipt) =
        partial.expect("non-reading PTY must exhaust its bounded kernel input queue");
    assert!(
        accepted_total > 0,
        "exercise real accepted PTY bytes before backpressure"
    );
    assert!(receipt.accepted_bytes < receipt.submitted_bytes);
    let duplicate = service
        .input(
            context.session_id,
            context.session_epoch,
            &principal,
            &lease,
            sequence,
            sequence,
            &bytes,
            || {
                panic!(
                    "duplicate input must return cached counts without retrying the write or suffix"
                )
            },
        )
        .unwrap();
    assert_eq!(duplicate, receipt);
    let params = TerminalInputParams {
        terminal: context.clone(),
        lease: lease.wire_binding(),
        input_id: DecimalU64(sequence),
        input_seq: InputSeq(DecimalU64(sequence)),
        bytes: BoundedList(bytes),
    };
    // This is the same canonical byte-count DTO returned by the executor. The
    // real service receipt remains intact; partial acceptance is not replay.
    let wire = InputReceipt::new(
        context.session_id,
        context.session_epoch,
        params.input_id,
        params.input_seq.0,
        InputBytes::new(receipt.submitted_bytes as u64).unwrap(),
        InputBytes::new(receipt.accepted_bytes as u64).unwrap(),
    )
    .unwrap();
    assert_eq!(wire.accepted_bytes().get(), receipt.accepted_bytes as u64);
    wire.validate_binding(
        context.session_id,
        context.session_epoch,
        params.input_id,
        params.input_seq.0,
        InputBytes::new(receipt.submitted_bytes as u64).unwrap(),
    )
    .unwrap();
    service.disconnect(&principal);
    assert!(
        service
            .snapshot(context.session_id, context.session_epoch)
            .is_ok(),
        "remote disconnect must leave host PTY alive"
    );
    let reconnected = AuthenticatedConnection::new(principal.actor());
    assert!(matches!(
        service.input(
            context.session_id,
            context.session_epoch,
            &reconnected,
            &lease,
            sequence + 1,
            sequence + 1,
            b"X",
            || true
        ),
        Err(lomi_terminal::Error::ControlRequired | lomi_terminal::Error::LeaseExpired)
    ));
    service.stop(context.session_id).unwrap();
}
