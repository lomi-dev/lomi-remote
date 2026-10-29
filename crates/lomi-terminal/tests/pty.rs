#![cfg(unix)]
use lomi_remote_protocol::{ConsumerAuthorizationId, SessionEpoch, TerminalSessionId};
use lomi_terminal::*;
use lomi_terminal_state::Snapshot;
use std::{
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
const SCRIPT: &str = r#"
import os,sys,tty,select,time
fd=0
tty.setraw(fd)
os.write(1,b'READY\r\n\x1b[6n')
count=0
while True:
    data=os.read(fd,16384)
    if not data: break
    for c in data:
        if c==65:
            count+=1
            os.write(1,('A_COUNT_%d\r\n'%count).encode())
        elif c==66:
            for i in range(160):
                os.write(1,('BURST_%d\r\n'%i).encode())
                time.sleep(.004)
        elif c==68:
            for i in range(20):
                os.write(1,('DETACHED_%d\r\n'%i).encode())
                time.sleep(.01)
        elif c==88:
            os.write(1,b'FINAL_OUTPUT\r\n')
            sys.exit(0)
"#;
fn ids() -> (TerminalSessionId, SessionEpoch) {
    (
        TerminalSessionId::from_bytes([1; 16]).unwrap(),
        SessionEpoch::from_bytes([2; 16]).unwrap(),
    )
}
fn connection(n: u8) -> AuthenticatedConnection {
    AuthenticatedConnection::new(ConsumerAuthorizationId::from_bytes([n; 16]).unwrap())
}
fn visible(s: &Snapshot) -> String {
    s.normal
        .lines
        .iter()
        .flat_map(|r| r.cells.iter().map(|c| c.text.as_str()))
        .collect()
}
fn wait(
    service: &TerminalService,
    id: TerminalSessionId,
    epoch: SessionEpoch,
    condition: impl Fn(&Snapshot) -> bool,
) {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = service.snapshot(id, epoch).unwrap();
        if condition(&snapshot) {
            return;
        }
        assert!(
            Instant::now() < end,
            "synthetic terminal milestone timed out"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
fn fixture() -> (
    tempfile::TempDir,
    TerminalService,
    TerminalSessionId,
    SessionEpoch,
) {
    let temp = tempfile::tempdir().unwrap();
    let service = TerminalService::new();
    let (id, epoch) = ids();
    service
        .spawn(
            id,
            epoch,
            &SpawnProfile {
                executable: PathBuf::from("/usr/bin/python3"),
                args: vec!["-I".into(), "-u".into(), "-c".into(), SCRIPT.into()],
                cwd: temp.path().canonicalize().unwrap(),
                environment: vec![("TERM".into(), "xterm-256color".into())],
                shell_integration: None,
                rows: 8,
                cols: 40,
                history: 16,
            },
        )
        .unwrap();
    wait(&service, id, epoch, |s| visible(s).contains("READY"));
    (temp, service, id, epoch)
}
fn attach_control(
    service: &TerminalService,
    id: TerminalSessionId,
    epoch: SessionEpoch,
    owner: &AuthenticatedConnection,
) -> (Attachment, ControlLease) {
    let attachment = service.attach(id, epoch, owner).unwrap();
    attachment
        .acknowledge(owner, attachment.snapshot.sequence.0)
        .unwrap();
    let lease = service.claim(id, epoch, owner).unwrap();
    (attachment, lease)
}
// One acknowledged synthetic echo at a time guarantees distinct PTY reads.
// A timed burst can coalesce and correctly remain below the 128-event bound.
fn overflow_slow_queue(
    service: &TerminalService,
    id: TerminalSessionId,
    epoch: SessionEpoch,
    owner: &AuthenticatedConnection,
    lease: &ControlLease,
    slow: &Attachment,
    fast: Option<&Attachment>,
) -> (u64, usize) {
    let mut events = 0;
    for seq in 1..=160 {
        service
            .input(id, epoch, owner, lease, seq, seq, b"A", || true)
            .unwrap();
        let marker = format!("A_COUNT_{seq}");
        wait(service, id, epoch, |s| visible(s).contains(&marker));
        if let Some(fast) = fast {
            while let Some(event) = fast.try_next() {
                assert!(!matches!(*event, TerminalEvent::ResyncRequired));
                events += 1;
            }
        }
        if slow.resync_required() {
            return (seq, events);
        }
    }
    panic!("more than 128 distinct updates did not overflow slow subscriber");
}
#[test]
fn two_observers_one_writer_duplicate_input_and_detach_keep_model_alive() {
    let (_temp, service, id, epoch) = fixture();
    let first = connection(3);
    let second = connection(4);
    let (a, lease) = attach_control(&service, id, epoch, &first);
    let b = service.attach(id, epoch, &second).unwrap();
    b.acknowledge(&second, b.snapshot.sequence.0).unwrap();
    assert_eq!(a.snapshot.session_epoch.as_bytes(), &epoch.to_bytes());
    assert_eq!(
        service.claim(id, epoch, &second),
        Err(Error::ControlRequired)
    );
    assert_eq!(
        service.input(id, epoch, &second, &lease, 1, 1, b"A", || true),
        Err(Error::ControlRequired)
    );
    let receipt = service
        .input(id, epoch, &first, &lease, 1, 1, b"A", || true)
        .unwrap();
    assert_eq!(receipt.outcome, InputOutcome::Accepted);
    assert_eq!(
        service
            .input(id, epoch, &first, &lease, 1, 1, b"A", || panic!(
                "duplicate reached syscall fence"
            ))
            .unwrap(),
        receipt
    );
    wait(&service, id, epoch, |s| visible(s).contains("A_COUNT_1"));
    thread::sleep(Duration::from_millis(30));
    assert!(!visible(&service.snapshot(id, epoch).unwrap()).contains("A_COUNT_2"));
    assert_eq!(service.stats(id).unwrap().host_replies, 1);
    let wrong = SessionEpoch::from_bytes([9; 16]).unwrap();
    assert_eq!(
        service.input(id, wrong, &first, &lease, 2, 2, b"A", || true),
        Err(Error::StaleEpoch)
    );
    service
        .input(id, epoch, &first, &lease, 2, 2, b"D", || true)
        .unwrap();
    drop(a);
    drop(b);
    wait(&service, id, epoch, |s| visible(s).contains("DETACHED_19"));
    let reconnected = connection(3);
    let fresh = service.attach(id, epoch, &reconnected).unwrap();
    assert!(visible(&fresh.snapshot).contains("DETACHED_19"));
    assert_eq!(
        service.input(id, epoch, &reconnected, &lease, 3, 3, b"A", || true),
        Err(Error::ControlRequired)
    );
    service.stop(id).unwrap();
    assert!(matches!(
        service.attach(id, epoch, &first),
        Err(Error::SessionMissing)
    ));
}
#[test]
fn overflow_resyncs_only_slow_subscriber_while_pty_and_fast_observer_continue() {
    let (_temp, service, id, epoch) = fixture();
    let first = connection(3);
    let second = connection(4);
    let (fast, lease) = attach_control(&service, id, epoch, &first);
    let slow = service.attach(id, epoch, &second).unwrap();
    let (writes, events) =
        overflow_slow_queue(&service, id, epoch, &first, &lease, &slow, Some(&fast));
    assert!(events > 20);
    assert!(slow.resync_required());
    assert!(matches!(
        *slow.try_next().unwrap(),
        TerminalEvent::ResyncRequired
    ));
    assert!(slow.try_next().is_none());
    service
        .input(
            id,
            epoch,
            &first,
            &lease,
            writes + 1,
            writes + 1,
            b"A",
            || true,
        )
        .unwrap();
    let marker = format!("A_COUNT_{}", writes + 1);
    wait(&service, id, epoch, |s| visible(s).contains(&marker));
    assert!(service.stats(id).unwrap().subscriber_overflows >= 1);
    service.stop(id).unwrap();
}
#[test]
fn ack_resize_sequences_disconnect_and_real_monotonic_expiry() {
    let (_temp, service, id, epoch) = fixture();
    let first = connection(3);
    let a = service.attach(id, epoch, &first).unwrap();
    assert_eq!(
        service.claim(id, epoch, &first),
        Err(Error::RenderAckRequired)
    );
    a.acknowledge(&first, a.snapshot.sequence.0).unwrap();
    let lease = service.claim(id, epoch, &first).unwrap();
    let receipt = service
        .resize(id, epoch, &first, &lease, 1, 10, 50, || true)
        .unwrap();
    assert_eq!(
        service
            .resize(id, epoch, &first, &lease, 1, 10, 50, || panic!(
                "duplicate resize syscall"
            ))
            .unwrap(),
        receipt
    );
    assert_eq!(
        service.resize(id, epoch, &first, &lease, 1, 11, 50, || true),
        Err(Error::SequenceConflict)
    );
    assert_eq!(service.snapshot(id, epoch).unwrap().rows, 10);
    service.disconnect(&first);
    assert_eq!(
        service.renew(id, epoch, &first, &lease),
        Err(Error::ControlRequired)
    );
    let second = connection(3);
    let (_b, fresh) = attach_control(&service, id, epoch, &second);
    thread::sleep(LEASE_TTL + Duration::from_millis(30));
    assert!(matches!(
        service.input(id, epoch, &second, &fresh, 1, 1, b"A", || true),
        Err(Error::ControlRequired | Error::LeaseExpired)
    ));
    service.stop(id).unwrap();
}
#[test]
fn fence_refusal_retains_unknown_receipt_and_never_replays() {
    let (_temp, service, id, epoch) = fixture();
    let first = connection(3);
    let (_a, lease) = attach_control(&service, id, epoch, &first);
    let receipt = service
        .input(id, epoch, &first, &lease, 1, 1, b"A", || false)
        .unwrap();
    assert_eq!(receipt.accepted_bytes, 0);
    assert_eq!(receipt.outcome, InputOutcome::Unknown);
    assert_eq!(
        service
            .input(id, epoch, &first, &lease, 1, 1, b"A", || panic!(
                "unknown input was replayed"
            ))
            .unwrap(),
        receipt
    );
    thread::sleep(Duration::from_millis(30));
    assert!(!visible(&service.snapshot(id, epoch).unwrap()).contains("A_COUNT_1"));
    service.stop(id).unwrap();
}
#[test]
fn explicit_restart_uses_new_epoch_and_never_adopts_missing_session() {
    let (temp, service, id, epoch) = fixture();
    service.stop(id).unwrap();
    let fresh = SessionEpoch::from_bytes([8; 16]).unwrap();
    assert_eq!(service.snapshot(id, fresh), Err(Error::SessionMissing));
    service
        .spawn(
            id,
            fresh,
            &SpawnProfile {
                executable: "/bin/sleep".into(),
                args: vec!["30".into()],
                cwd: temp.path().canonicalize().unwrap(),
                environment: vec![],
                shell_integration: None,
                rows: 8,
                cols: 40,
                history: 0,
            },
        )
        .unwrap();
    assert_eq!(service.snapshot(id, epoch), Err(Error::StaleEpoch));
    assert_eq!(
        service
            .snapshot(id, fresh)
            .unwrap()
            .session_epoch
            .as_bytes(),
        &fresh.to_bytes()
    );
    service.stop(id).unwrap();
}
#[test]
fn final_output_precedes_ordered_exit() {
    let (_temp, service, id, epoch) = fixture();
    let connection = connection(3);
    let (attachment, lease) = attach_control(&service, id, epoch, &connection);
    service
        .input(id, epoch, &connection, &lease, 1, 1, b"X", || true)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut final_sequence = None;
    let mut model = attachment.snapshot.clone();
    loop {
        if let Some(event) = attachment.try_next() {
            match &*event {
                TerminalEvent::State(delta) => {
                    model = delta.apply(&model).unwrap();
                    if visible(&model).contains("FINAL_OUTPUT") {
                        final_sequence = Some(model.sequence.0);
                    }
                }
                TerminalEvent::ControlChanged { sequence, .. } => {
                    model.sequence = lomi_remote_protocol::DecimalU64(*sequence);
                }
                TerminalEvent::Exited { sequence } => {
                    assert!(final_sequence.is_some_and(|last| last < *sequence));
                    break;
                }
                TerminalEvent::ResyncRequired => panic!("small exit stream overflowed"),
            }
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    let readonly = service.attach(id, epoch, &connection).unwrap();
    let latest = service.snapshot(id, epoch).unwrap();
    assert_eq!(readonly.snapshot.sequence.0 + 1, latest.sequence.0);
    assert_eq!(visible(&readonly.snapshot), visible(&latest));
    assert!(
        matches!(&*readonly.try_next().unwrap(), TerminalEvent::Exited { sequence } if *sequence == latest.sequence.0)
    );
    assert!(visible(&readonly.snapshot).contains("FINAL_OUTPUT"));
    assert_eq!(
        service.claim(id, epoch, &connection),
        Err(Error::SessionExited)
    );
    assert_eq!(
        service.input(id, epoch, &connection, &lease, 2, 2, b"A", || true),
        Err(Error::SessionExited)
    );
    assert_eq!(
        service.resize(id, epoch, &connection, &lease, 1, 9, 41, || true),
        Err(Error::SessionExited)
    );
    service.stop(id).unwrap();
}

#[test]
fn concurrent_output_has_no_gap_between_atomic_snapshot_and_subscription() {
    let (_temp, service, id, epoch) = fixture();
    let owner = connection(3);
    let (owner_attachment, lease) = attach_control(&service, id, epoch, &owner);
    service
        .input(id, epoch, &owner, &lease, 1, 1, b"B", || true)
        .unwrap();
    thread::sleep(Duration::from_millis(20));
    let observer = service.attach(id, epoch, &connection(4)).unwrap();
    let mut model = observer.snapshot.clone();
    let mut through = model.sequence.0;
    let mut updates = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        // Drain the writer's independent queue so it remains a live controller.
        while owner_attachment.try_next().is_some() {}
        while let Some(event) = observer.try_next() {
            match &*event {
                TerminalEvent::State(delta) => {
                    assert_eq!(delta.previous_sequence().0, through);
                    model = delta.apply(&model).unwrap();
                    through = model.sequence.0;
                    updates += 1;
                    if visible(&model).contains("BURST_159") {
                        assert!(updates > 10);
                        service.stop(id).unwrap();
                        return;
                    }
                }
                TerminalEvent::ResyncRequired => panic!("actively draining observer overflowed"),
                TerminalEvent::ControlChanged { sequence, .. } => {
                    assert_eq!(*sequence, through + 1);
                    through = *sequence;
                    model.sequence = lomi_remote_protocol::DecimalU64(*sequence);
                }
                TerminalEvent::Exited { .. } => panic!("synthetic process exited early"),
            }
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn overflow_revokes_old_control_before_same_connection_reattaches() {
    let (_temp, service, id, epoch) = fixture();
    let owner = connection(3);
    let (slow, lease) = attach_control(&service, id, epoch, &owner);
    overflow_slow_queue(&service, id, epoch, &owner, &lease, &slow, None);
    assert!(slow.resync_required());
    let fresh = service.attach(id, epoch, &owner).unwrap();
    assert_eq!(
        service.input(id, epoch, &owner, &lease, 2, 2, b"A", || true),
        Err(Error::ControlRequired)
    );
    fresh
        .acknowledge(&owner, fresh.snapshot.sequence.0)
        .unwrap();
    let replacement = service.claim(id, epoch, &owner).unwrap();
    assert!(replacement.version > lease.version);
    service.stop(id).unwrap();
}

#[test]
fn interactive_spawn_thread_can_end_before_another_thread_stops_session() {
    let temp = tempfile::tempdir().unwrap();
    let service = std::sync::Arc::new(TerminalService::new());
    let (id, epoch) = ids();
    let profile = SpawnProfile {
        executable: "/bin/sh".into(),
        args: vec![],
        cwd: temp.path().canonicalize().unwrap(),
        environment: vec![
            ("HOME".into(), temp.path().to_str().unwrap().into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
        ],
        shell_integration: None,
        rows: 8,
        cols: 40,
        history: 0,
    };
    let creator = service.clone();
    thread::spawn(move || creator.spawn(id, epoch, &profile).unwrap())
        .join()
        .unwrap();
    let before = Instant::now();
    service.stop(id).unwrap();
    assert!(before.elapsed() < Duration::from_secs(2));
}

#[test]
fn query_reply_batch_observes_shutdown_without_per_reply_deadline_reset() {
    let temp = tempfile::tempdir().unwrap();
    let service = TerminalService::new();
    let (id, epoch) = ids();
    let script = r#"
import os,tty,time,sys
tty.setraw(0)
os.write(1,b'READY\r\n')
os.read(0,1)
os.write(1,b'\x1b[6n'*64)
open(sys.argv[1],'w').close()
while True:
    time.sleep(.08)
    os.read(0,6)
"#;
    let marker = temp.path().join("synthetic-query-ready");
    service
        .spawn(
            id,
            epoch,
            &SpawnProfile {
                executable: "/usr/bin/python3".into(),
                args: vec![
                    "-I".into(),
                    "-u".into(),
                    "-c".into(),
                    script.into(),
                    marker.to_str().unwrap().into(),
                ],
                cwd: temp.path().canonicalize().unwrap(),
                environment: vec![],
                shell_integration: None,
                rows: 8,
                cols: 40,
                history: 0,
            },
        )
        .unwrap();
    wait(&service, id, epoch, |s| visible(s).contains("READY"));
    let owner = connection(3);
    let (_attachment, lease) = attach_control(&service, id, epoch, &owner);
    let mut input = vec![b'A'; 16384];
    input[0] = b'G';
    let receipt = service
        .input(id, epoch, &owner, &lease, 1, 1, &input, || true)
        .unwrap();
    assert!(receipt.accepted_bytes > 0);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !marker.exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    thread::sleep(Duration::from_millis(20));
    let before = Instant::now();
    service.stop(id).unwrap();
    assert!(
        before.elapsed() < Duration::from_secs(1),
        "reply flood delayed owned shutdown"
    );
}

#[test]
fn unacknowledged_sibling_cannot_preserve_overflowed_controller_lease() {
    let (_temp, service, id, epoch) = fixture();
    let owner = connection(3);
    let (controller, lease) = attach_control(&service, id, epoch, &owner);
    let sibling = service.attach(id, epoch, &owner).unwrap();
    overflow_slow_queue(
        &service,
        id,
        epoch,
        &owner,
        &lease,
        &controller,
        Some(&sibling),
    );
    assert!(controller.resync_required());
    assert!(!sibling.resync_required());
    assert_eq!(
        service.renew(id, epoch, &owner, &lease),
        Err(Error::ControlRequired)
    );
    assert_eq!(
        service.input(id, epoch, &owner, &lease, 2, 2, b"A", || true),
        Err(Error::ControlRequired)
    );
    assert_eq!(
        service.claim(id, epoch, &owner),
        Err(Error::RenderAckRequired)
    );
    let snapshot = service.snapshot(id, epoch).unwrap();
    sibling.acknowledge(&owner, snapshot.sequence.0).unwrap();
    let fresh = service.claim(id, epoch, &owner).unwrap();
    assert!(fresh.version > lease.version);
    service.stop(id).unwrap();
}

#[test]
fn pre_exec_fence_runs_after_allocation_and_prevents_startup_effects() {
    let temp = tempfile::tempdir().unwrap();
    let service = TerminalService::new();
    let (id, epoch) = ids();
    let profile = SpawnProfile {
        executable: "/bin/sh".into(),
        args: vec!["-c".into(), "printf ran > should-not-exist".into()],
        cwd: temp.path().into(),
        environment: vec![],
        shell_integration: None,
        rows: 24,
        cols: 80,
        history: 16,
    };
    let mut checked = false;
    let result = service.spawn_with_checks(
        id,
        epoch,
        &profile,
        || {
            checked = true;
            false
        },
        || panic!("post-exec check must not run"),
    );
    assert_eq!(result, Err(Error::SpawnFailed));
    assert!(checked);
    assert!(!temp.path().join("should-not-exist").exists());
    assert!(matches!(
        service.snapshot(id, epoch),
        Err(Error::SessionMissing)
    ));
    service.shutdown().unwrap();
}

#[test]
fn hundred_ordinary_lines_keep_undrained_control_queue_within_budget() {
    let temp = tempfile::tempdir().unwrap();
    let service = TerminalService::new();
    let (id, epoch) = ids();
    let script = r#"
import os,tty,time
tty.setraw(0)
os.write(1,b'READY\r\n')
os.read(0,1)
for i in range(100):
    os.write(1,('LINE_%03d ordinary output\r\n'%i).encode())
    time.sleep(.005)
os.read(0,1)
"#;
    service
        .spawn(
            id,
            epoch,
            &SpawnProfile {
                executable: PathBuf::from("/usr/bin/python3"),
                args: vec!["-I".into(), "-u".into(), "-c".into(), script.into()],
                cwd: temp.path().canonicalize().unwrap(),
                environment: vec![],
                shell_integration: None,
                rows: 24,
                cols: 80,
                history: 256,
            },
        )
        .unwrap();
    wait(&service, id, epoch, |s| visible(s).contains("READY"));
    let owner = connection(3);
    let (attachment, lease) = attach_control(&service, id, epoch, &owner);
    service
        .input(id, epoch, &owner, &lease, 1, 1, b"B", || true)
        .unwrap();
    wait(&service, id, epoch, |s| visible(s).contains("LINE_099"));
    assert!(service.lease_is_current(id, epoch, &owner, &lease));
    let expected = service.snapshot(id, epoch).unwrap();
    let mut model = attachment.snapshot.clone();
    let mut updates = 0;
    let mut bytes = 0;
    while let Some(event) = attachment.try_next() {
        match &*event {
            TerminalEvent::State(patch) => {
                bytes += serde_json::to_vec(patch).unwrap().len();
                model = patch.apply(&model).unwrap();
                updates += 1;
            }
            TerminalEvent::ControlChanged { sequence, .. } => {
                model.sequence = lomi_remote_protocol::DecimalU64(*sequence)
            }
            TerminalEvent::ResyncRequired => panic!("100 ordinary updates overflowed"),
            TerminalEvent::Exited { .. } => panic!("synthetic process exited early"),
        }
    }
    assert!(updates > 1);
    assert!(bytes < 1024 * 1024);
    assert_eq!(model, expected);
    service.stop(id).unwrap();
}

#[test]
fn exited_final_snapshot_is_readonly_and_retirement_excludes_racing_attach() {
    use std::sync::{Arc, Barrier};
    let temp = tempfile::tempdir().unwrap();
    let service = Arc::new(TerminalService::new());
    let (id, epoch) = ids();
    service
        .spawn(
            id,
            epoch,
            &SpawnProfile {
                executable: "/bin/sh".into(),
                args: vec!["-c".into(), "printf RETAINED; exit 0".into()],
                cwd: temp.path().into(),
                environment: vec![],
                shell_integration: None,
                rows: 8,
                cols: 40,
                history: 0,
            },
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while service.exited_sessions().unwrap().is_empty() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    let observer = connection(5);
    let attachment = service.attach(id, epoch, &observer).unwrap();
    assert!(visible(&attachment.snapshot).contains("RETAINED"));
    assert!(matches!(
        service.claim(id, epoch, &observer),
        Err(Error::SessionExited)
    ));
    assert!(
        !service
            .retire_exited(id, epoch, || panic!(
                "unacknowledged attachment must prevent retirement"
            ))
            .unwrap()
    );
    drop(attachment);
    assert!(!service.retire_exited(id, epoch, || false).unwrap());
    assert!(
        service.snapshot(id, epoch).is_ok(),
        "failed durable CAS must retain RAM"
    );
    let entered = Arc::new(Barrier::new(2));
    let retiring = service.clone();
    let gate = entered.clone();
    let retire = thread::spawn(move || {
        retiring
            .retire_exited(id, epoch, || {
                gate.wait();
                thread::sleep(Duration::from_millis(30));
                true
            })
            .unwrap()
    });
    entered.wait();
    assert!(matches!(
        service.attach(id, epoch, &observer),
        Err(Error::SessionMissing)
    ));
    assert!(retire.join().unwrap());
    assert!(matches!(
        service.snapshot(id, epoch),
        Err(Error::SessionMissing)
    ));
    service.shutdown().unwrap();
}

fn exited_retirement_fixture() -> (
    tempfile::TempDir,
    std::sync::Arc<TerminalService>,
    TerminalSessionId,
    SessionEpoch,
) {
    let temp = tempfile::tempdir().unwrap();
    let service = std::sync::Arc::new(TerminalService::new());
    let (id, epoch) = ids();
    service
        .spawn(
            id,
            epoch,
            &SpawnProfile {
                executable: "/bin/sh".into(),
                args: vec!["-c".into(), "printf RESERVED; exit 0".into()],
                cwd: temp.path().into(),
                environment: vec![],
                shell_integration: None,
                rows: 8,
                cols: 40,
                history: 0,
            },
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while service.exited_sessions().unwrap().is_empty() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    (temp, service, id, epoch)
}

#[test]
fn retirement_persist_releases_map_and_core_and_failed_reservation_restores_attach() {
    use std::sync::mpsc;
    let (_temp, service, id, epoch) = exited_retirement_fixture();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let retiring = service.clone();
    let retire = thread::spawn(move || {
        retiring.retire_exited(id, epoch, || {
            // Both methods acquire locks that the persistence callback used to hold.
            assert!(!retiring.at_capacity().unwrap());
            assert!(retiring.stats(id).is_ok());
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            false
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let attaching = service.clone();
    let (attach_tx, attach_rx) = mpsc::channel();
    let attach = thread::spawn(move || {
        attach_tx
            .send(attaching.attach(id, epoch, &connection(7)))
            .unwrap()
    });
    let early = attach_rx.recv_timeout(Duration::from_millis(30));
    release_tx.send(()).unwrap();
    assert!(!retire.join().unwrap().unwrap());
    assert!(early.is_err(), "attach must wait for reservation outcome");
    let attachment = attach_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    attach.join().unwrap();
    assert!(visible(&attachment.snapshot).contains("RESERVED"));
    drop(attachment);
    assert!(service.retire_exited(id, epoch, || true).unwrap());
}

#[test]
fn retirement_panic_cancels_reservation_and_does_not_poison_model() {
    let (_temp, service, id, epoch) = exited_retirement_fixture();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = service.retire_exited(id, epoch, || panic!("synthetic persistence unwind"));
        }))
        .is_err()
    );
    let attachment = service.attach(id, epoch, &connection(8)).unwrap();
    assert!(visible(&attachment.snapshot).contains("RESERVED"));
    drop(attachment);
    assert!(service.retire_exited(id, epoch, || true).unwrap());
}

#[test]
fn retirement_excludes_claim_and_stop_until_persistence_finishes() {
    use std::sync::mpsc;
    let (_temp, service, id, epoch) = exited_retirement_fixture();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let retiring = service.clone();
    let retire = thread::spawn(move || {
        retiring.retire_exited(id, epoch, || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            true
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let claiming = service.clone();
    let (claim_tx, claim_rx) = mpsc::channel();
    let claim = thread::spawn(move || {
        claim_tx
            .send(claiming.claim(id, epoch, &connection(9)))
            .unwrap()
    });
    let stopping = service.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let stop = thread::spawn(move || stop_tx.send(stopping.stop(id)).unwrap());
    let claim_early = claim_rx.recv_timeout(Duration::from_millis(30));
    let stop_early = stop_rx.recv_timeout(Duration::from_millis(30));
    release_tx.send(()).unwrap();
    assert!(retire.join().unwrap().unwrap());
    assert!(claim_early.is_err());
    assert!(stop_early.is_err());
    assert!(matches!(
        claim_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        Err(Error::SessionMissing)
    ));
    assert!(matches!(
        stop_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        Err(Error::SessionMissing)
    ));
    claim.join().unwrap();
    stop.join().unwrap();
}

#[test]
fn stale_retirement_epoch_never_calls_persistence_or_removes_session() {
    let (_temp, service, id, epoch) = exited_retirement_fixture();
    let stale = SessionEpoch::from_bytes([99; 16]).unwrap();
    assert!(matches!(
        service.retire_exited(id, stale, || panic!("stale reservation persisted")),
        Err(Error::StaleEpoch)
    ));
    assert!(service.snapshot(id, epoch).is_ok());
    assert!(service.retire_exited(id, epoch, || true).unwrap());
}

#[test]
fn retirement_failure_unblocks_shutdown_without_retiring_a_replacement() {
    use std::sync::mpsc;
    let (temp, service, id, epoch) = exited_retirement_fixture();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let retiring = service.clone();
    let retire = thread::spawn(move || {
        retiring.retire_exited(id, epoch, || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            false
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let shutting_down = service.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let shutdown = thread::spawn(move || done_tx.send(shutting_down.shutdown()).unwrap());
    let early = done_rx.recv_timeout(Duration::from_millis(30));
    release_tx.send(()).unwrap();
    assert!(!retire.join().unwrap().unwrap());
    assert!(early.is_err());
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    shutdown.join().unwrap();
    assert!(matches!(
        service.snapshot(id, epoch),
        Err(Error::SessionMissing)
    ));
    let replacement_epoch = SessionEpoch::from_bytes([77; 16]).unwrap();
    service
        .spawn(
            id,
            replacement_epoch,
            &SpawnProfile {
                executable: "/bin/sh".into(),
                args: vec!["-c".into(), "exit 0".into()],
                cwd: temp.path().into(),
                environment: vec![],
                shell_integration: None,
                rows: 8,
                cols: 40,
                history: 0,
            },
        )
        .unwrap();
    assert!(matches!(
        service.retire_exited(id, epoch, || panic!("old generation persisted")),
        Err(Error::StaleEpoch)
    ));
    assert!(service.snapshot(id, replacement_epoch).is_ok());
    service.shutdown().unwrap();
}
