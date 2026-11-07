use lomi_remote_protocol::{
    DecimalU64, PaneId, RuntimeId, SessionEpoch, TerminalContext, TerminalProfile,
    TerminalSessionId, WorkspaceContext, WorkspaceEpoch, WorkspaceId,
    ipc::LocalStreamEvent,
    rpc::{BoundedList, ChunkCount, ChunkIndex, SubscriptionId, TerminalDimension},
    streams::{
        TerminalSeq, TerminalSnapshotChunk, TerminalSnapshotComplete, TerminalSnapshotMetadata,
        TerminalStreamFrame, WorkingDirectoryValue,
    },
};
use lomi_terminal_state::{Buffer, GridPatch, TerminalState};
use lomiremote::attach::View;

const SNAPSHOT_CHUNK_BYTES: usize = 16_384;

fn context_for(snapshot: &lomi_terminal_state::Snapshot) -> TerminalContext {
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
        session_epoch: SessionEpoch::from_bytes(*snapshot.session_epoch.as_bytes()).unwrap(),
        profile: TerminalProfile::ExperimentalRustGridV1,
    }
}

fn buffer_text(buffer: &Buffer) -> String {
    buffer
        .lines
        .iter()
        .flat_map(|line| line.cells.iter())
        .map(|cell| cell.text.as_str())
        .collect()
}

#[test]
fn cli_view_accepts_snapshot_serialized_from_terminal_state() {
    let mut terminal = TerminalState::new(24, 80, 0).expect("create 80x24 terminal model");
    terminal
        .feed(b"normal screen\r\n")
        .expect("write normal-screen fixture");
    terminal
        .feed(b"\x1b[?1049halternate screen")
        .expect("write alternate-screen fixture");
    let snapshot = terminal.snapshot().expect("capture terminal snapshot");
    assert_eq!(snapshot.rows, 24);
    assert_eq!(snapshot.cols, 80);
    assert_eq!(snapshot.active, "alternate");
    assert!(buffer_text(&snapshot.normal).contains("normal screen"));
    assert!(buffer_text(&snapshot.alternate).contains("alternate screen"));

    // Mirror ConnectionState::register_attachment: serialize the captured
    // snapshot once, and derive metadata and all stream frames from those bytes
    // and that same snapshot checkpoint.
    let bytes = serde_json::to_vec(&snapshot).expect("serialize terminal snapshot");
    let subscription_id =
        SubscriptionId::try_from("123e4567-e89b-42d3-a456-426614174000".to_owned())
            .expect("valid subscription id");
    let context = context_for(&snapshot);
    let metadata = TerminalSnapshotMetadata {
        terminal: context.clone(),
        subscription_id: subscription_id.clone(),
        through_seq: TerminalSeq(snapshot.sequence),
        output_offset: snapshot.output_offset,
        columns: TerminalDimension(snapshot.cols as u32),
        rows: TerminalDimension(snapshot.rows as u32),
        chunk_count: ChunkCount(bytes.len().div_ceil(SNAPSHOT_CHUNK_BYTES) as u32),
        total_bytes: DecimalU64(bytes.len() as u64),
        working_directory: WorkingDirectoryValue::from(None),
    };

    let mut view = View::new(context.clone());
    view.begin(metadata.clone())
        .expect("begin CLI snapshot assembly from attach metadata");
    for (index, chunk) in bytes.chunks(SNAPSHOT_CHUNK_BYTES).enumerate() {
        view.apply(LocalStreamEvent::Terminal(
            TerminalStreamFrame::SnapshotChunk(TerminalSnapshotChunk {
                terminal: context.clone(),
                subscription_id: subscription_id.clone(),
                index: ChunkIndex(index as u32),
                bytes: BoundedList(chunk.to_vec()),
            }),
        ))
        .expect("apply serialized snapshot chunk");
    }
    view.apply(LocalStreamEvent::Terminal(
        TerminalStreamFrame::SnapshotComplete(TerminalSnapshotComplete {
            terminal: context,
            subscription_id,
            through_seq: metadata.through_seq,
            output_offset: metadata.output_offset,
        }),
    ))
    .expect("complete CLI snapshot assembly");

    assert_eq!(view.model.as_ref(), Some(&snapshot));
    assert_eq!(view.subscription, Some(metadata.subscription_id));
    assert_eq!(view.through, Some(metadata.through_seq));
}

#[test]
fn resize_checkpoint_fits_terminal_attachment_queue_budget() {
    let mut terminal = TerminalState::new(24, 80, 0).expect("create initial 80x24 model");
    let before = terminal.snapshot().expect("capture initial model");
    terminal.resize(39, 120).expect("resize model to 120x39");
    let after = terminal.snapshot().expect("capture resized model");
    let patch = GridPatch::between(&before, &after).expect("build topology checkpoint");
    let encoded = serde_json::to_vec(&patch).expect("serialize resize checkpoint");
    let value: serde_json::Value =
        serde_json::from_slice(&encoded).expect("decode serialized checkpoint");

    assert_eq!(value["update"]["kind"], "checkpoint");
    assert_eq!(after.rows, 39);
    assert_eq!(after.cols, 120);
    assert!(terminal.working_directory().is_none());
    assert!(
        encoded.len() > 1024 * 1024,
        "checkpoint should reproduce the former 1 MiB overflow"
    );
    assert!(
        encoded.len() <= lomi_terminal::ATTACHMENT_BYTES,
        "serialized checkpoint is {} bytes, attachment queue budget is {} bytes",
        encoded.len(),
        lomi_terminal::ATTACHMENT_BYTES,
    );
}
