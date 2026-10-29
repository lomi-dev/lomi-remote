use lomi_remote_protocol::{ipc::LocalStreamEvent, rpc::*, streams::*, *};
use lomi_terminal_state::TerminalState;
use lomiremote::attach::{View, draw};
use ratatui::{Terminal, backend::TestBackend, style::Color};
const ID: &str = "11111111-1111-4111-8111-111111111111";
fn context() -> TerminalContext {
    serde_json::from_value(serde_json::json!({"workspace":{"workspaceId":ID,"workspaceEpoch":ID,"runtimeId":ID,"runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"},"paneId":ID,"sessionId":ID,"sessionEpoch":ID,"profile":"lomi-rust-grid-v1-experimental"})).unwrap()
}
fn sub() -> SubscriptionId {
    "synthetic-subscription".to_owned().try_into().unwrap()
}
fn event(frame: TerminalStreamFrame) -> LocalStreamEvent {
    LocalStreamEvent::Terminal(frame)
}
fn begin(view: &mut View, model: &lomi_terminal_state::Snapshot) -> Vec<u8> {
    let bytes = serde_json::to_vec(model).unwrap();
    view.begin(TerminalSnapshotMetadata {
        terminal: view.context.clone(),
        subscription_id: sub(),
        through_seq: TerminalSeq(model.sequence),
        output_offset: model.output_offset,
        columns: TerminalDimension(model.cols as u32),
        rows: TerminalDimension(model.rows as u32),
        chunk_count: ChunkCount(bytes.len().div_ceil(16384) as u32),
        total_bytes: DecimalU64(bytes.len() as u64),
    })
    .unwrap();
    bytes
}
fn initial(view: &mut View, model: &lomi_terminal_state::Snapshot) {
    let bytes = begin(view, model);
    for (i, chunk) in bytes.chunks(16384).enumerate() {
        view.apply(event(TerminalStreamFrame::SnapshotChunk(
            TerminalSnapshotChunk {
                terminal: view.context.clone(),
                subscription_id: sub(),
                index: ChunkIndex(i as u32),
                bytes: BoundedList(chunk.to_vec()),
            },
        )))
        .unwrap();
        assert!(view.model.is_none());
    }
    view.apply(event(TerminalStreamFrame::SnapshotComplete(
        TerminalSnapshotComplete {
            terminal: view.context.clone(),
            subscription_id: sub(),
            through_seq: TerminalSeq(model.sequence),
            output_offset: model.output_offset,
        },
    )))
    .unwrap();
}
fn engine() -> TerminalState {
    TerminalState::new_with_epoch(50, 80, 0, context().session_epoch).unwrap()
}
#[test]
fn complete_structured_snapshot_and_chunked_delta_are_rendered_without_ansi_reparse() {
    let mut engine = engine();
    engine
        .feed("\x1b[31;1m界é\x1b[0m\r\nplain".as_bytes())
        .unwrap();
    let model = engine.snapshot().unwrap();
    let mut view = View::new(context());
    initial(&mut view, &model);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| draw(f, &view, "Observer")).unwrap();
    let cells = terminal.backend().buffer();
    assert_eq!(cells[(0, 1)].symbol(), "界");
    assert_eq!(cells[(2, 1)].symbol(), "é");
    assert_eq!(cells[(0, 1)].fg, Color::Indexed(1));
    assert_eq!(cells[(0, 2)].symbol(), "p");
    engine
        .feed(
            format!(
                "\x1b[?1049h\x1b[H{}",
                (0..3999)
                    .map(|i| char::from(b'A' + (i % 26) as u8))
                    .collect::<String>()
            )
            .as_bytes(),
        )
        .unwrap();
    let next = engine.snapshot().unwrap();
    let delta = lomi_terminal_state::GridPatch::between(&model, &next).unwrap();
    let bytes = serde_json::to_vec(&delta).unwrap();
    assert!(bytes.len() > 200000);
    let through = TerminalSeq(delta.sequence());
    view.apply(event(TerminalStreamFrame::DeltaMetadata(
        TerminalDeltaMetadata {
            terminal: context(),
            subscription_id: sub(),
            previous_seq: TerminalSeq(model.sequence),
            through_seq: through,
            chunk_count: ChunkCount(bytes.len().div_ceil(16384) as u32),
            total_bytes: DecimalU64(bytes.len() as u64),
        },
    )))
    .unwrap();
    for (i, chunk) in bytes.chunks(16384).enumerate() {
        view.apply(event(TerminalStreamFrame::DeltaChunk(TerminalDeltaChunk {
            terminal: context(),
            subscription_id: sub(),
            index: ChunkIndex(i as u32),
            bytes: BoundedList(chunk.to_vec()),
        })))
        .unwrap();
        assert_eq!(view.through, Some(TerminalSeq(model.sequence)));
    }
    view.apply(event(TerminalStreamFrame::DeltaComplete(
        TerminalDeltaComplete {
            terminal: context(),
            subscription_id: sub(),
            through_seq: through,
        },
    )))
    .unwrap();
    assert_eq!(view.through, Some(through));
    terminal.draw(|f| draw(f, &view, "Control")).unwrap();
    assert_eq!(terminal.backend().buffer()[(0, 1)].symbol(), "A");
    assert!(
        view.apply(event(TerminalStreamFrame::DeltaComplete(
            TerminalDeltaComplete {
                terminal: context(),
                subscription_id: sub(),
                through_seq: through
            }
        )))
        .is_err()
    );
}
#[test]
fn incomplete_wrong_order_wrong_epoch_and_oversized_models_never_become_renderable() {
    let model = engine().snapshot().unwrap();
    let mut view = View::new(context());
    let bytes = begin(&mut view, &model);
    assert!(
        view.apply(event(TerminalStreamFrame::SnapshotChunk(
            TerminalSnapshotChunk {
                terminal: context(),
                subscription_id: sub(),
                index: ChunkIndex(1),
                bytes: BoundedList(bytes[..16384].to_vec())
            }
        )))
        .is_err()
    );
    assert!(view.model.is_none());
    let mut view = View::new(context());
    begin(&mut view, &model);
    assert!(
        view.apply(event(TerminalStreamFrame::SnapshotComplete(
            TerminalSnapshotComplete {
                terminal: context(),
                subscription_id: sub(),
                through_seq: TerminalSeq(model.sequence),
                output_offset: model.output_offset
            }
        )))
        .is_err()
    );
    assert!(view.model.is_none());
    let mut view = View::new(context());
    let bytes = begin(&mut view, &model);
    assert!(
        view.apply(event(TerminalStreamFrame::SnapshotChunk(
            TerminalSnapshotChunk {
                terminal: context(),
                subscription_id: "other-subscription".to_owned().try_into().unwrap(),
                index: ChunkIndex(0),
                bytes: BoundedList(bytes[..16384].to_vec()),
            }
        )))
        .is_err()
    );
    assert!(view.model.is_none());
    let mut view = View::new(context());
    let bytes = begin(&mut view, &model);
    let mut wrong_context = context();
    wrong_context.session_epoch =
        SessionEpoch::from_bytes(*uuid::Uuid::new_v4().as_bytes()).unwrap();
    assert!(
        view.apply(event(TerminalStreamFrame::SnapshotChunk(
            TerminalSnapshotChunk {
                terminal: wrong_context,
                subscription_id: sub(),
                index: ChunkIndex(0),
                bytes: BoundedList(bytes[..16384].to_vec()),
            }
        )))
        .is_err()
    );
    assert!(view.model.is_none());
    let mut view = View::new(context());
    let mut wrong = model.clone();
    wrong.session_epoch = uuid::Uuid::new_v4();
    let bytes = begin(&mut view, &wrong);
    for (i, c) in bytes.chunks(16384).enumerate() {
        view.apply(event(TerminalStreamFrame::SnapshotChunk(
            TerminalSnapshotChunk {
                terminal: context(),
                subscription_id: sub(),
                index: ChunkIndex(i as u32),
                bytes: BoundedList(c.to_vec()),
            },
        )))
        .unwrap();
    }
    assert!(
        view.apply(event(TerminalStreamFrame::SnapshotComplete(
            TerminalSnapshotComplete {
                terminal: context(),
                subscription_id: sub(),
                through_seq: TerminalSeq(model.sequence),
                output_offset: model.output_offset
            }
        )))
        .is_err()
    );
    assert!(view.model.is_none());
    let mut bad = View::new(context());
    assert!(
        bad.begin(TerminalSnapshotMetadata {
            terminal: context(),
            subscription_id: sub(),
            through_seq: TerminalSeq(model.sequence),
            output_offset: model.output_offset,
            columns: TerminalDimension(80),
            rows: TerminalDimension(24),
            chunk_count: ChunkCount(513),
            total_bytes: DecimalU64(8 * 1024 * 1024 + 1)
        })
        .is_err()
    );
}
