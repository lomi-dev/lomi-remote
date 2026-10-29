//! Pure framing prerequisites. These tests do not construct a receipt authority
//! stamp or bypass the actual owner/peer/connection pipeline.
use super::*;
use lomi_remote_protocol::*;
fn response() -> RpcResponse {
    let rights = StoredOperationRights::new(
        OperationId::from_bytes([101; 16]).unwrap(),
        ConsumerAuthorizationId::from_bytes([102; 16]).unwrap(),
        WorkspaceId::from_bytes([103; 16]).unwrap(),
        Method::TerminalRename,
        vec![
            Capability::WorkspaceRead,
            Capability::TerminalObserve,
            Capability::TerminalManage,
        ]
        .try_into()
        .unwrap(),
        false,
    )
    .unwrap();
    let receipt = OperationReceipt::new(
        &rights,
        "ab".repeat(32).try_into().unwrap(),
        OperationState::Succeeded,
        false,
        Effect::Committed,
        Some(OperationResult::Domain {
            domain_revision: DecimalU64(9),
        }),
    )
    .unwrap();
    RpcResponse::Result {
        v: ApplicationMajor,
        request_id: "the-original-request-id".to_owned().try_into().unwrap(),
        result: RpcResult::TerminalRename(receipt),
    }
}
#[test]
fn exact_receipt_response_uses_one_fragment_and_the_existing_encoder_sequence() {
    use lomi_remote_protocol::message_framing::MessageAssembler;
    let mut encoder = MessageEncoder::new();
    let mut decoder = MessageAssembler::new();
    assert_eq!(
        encoder
            .begin(MessageKind::WorkspaceFrame, b"{}".to_vec())
            .unwrap(),
        1
    );
    let prior = encoder.next_frame().unwrap().unwrap();
    assert_eq!(decoder.push(&prior, 0).unwrap().unwrap().id, 1);
    assert!(encoder.next_frame().unwrap().is_none());
    let expected = response();
    let fragment = encode_receipt_response(&expected, &mut encoder).unwrap();
    let complete = decoder.push(&fragment, 1).unwrap().unwrap();
    assert_eq!(complete.id, 2);
    assert_eq!(complete.kind, MessageKind::RpcResponse);
    assert_eq!(
        serde_json::from_slice::<RpcResponse>(&complete.bytes).unwrap(),
        expected
    );
    assert!(encoder.next_frame().unwrap().is_none());
}
#[test]
fn publication_exception_encoding_rejects_error_responses() {
    let response = RpcResponse::Error {
        v: ApplicationMajor,
        request_id: "not-a-receipt".to_owned().try_into().unwrap(),
        operation_id: None,
        error: RemoteError::new(
            ErrorCode::ScopeDenied,
            false,
            Effect::None,
            ErrorDetails::empty(),
            None,
        )
        .unwrap(),
    };
    assert!(matches!(
        encode_receipt_response(&response, &mut MessageEncoder::new()),
        Err(RemoteRenameError::Closed)
    ));
}
#[test]
fn receipt_io_atoms_are_sync_without_worker_runtime_or_hostauth_capture() {
    fn sync<T: Sync>() {}
    sync::<super::super::shared_owner::RemoteRenameIoAtoms<'static, 'static>>();
}

fn move_response() -> RpcResponse {
    let rights = StoredOperationRights::new(
        OperationId::from_bytes([101; 16]).unwrap(),
        ConsumerAuthorizationId::from_bytes([102; 16]).unwrap(),
        WorkspaceId::from_bytes([103; 16]).unwrap(),
        Method::TerminalMove,
        vec![
            Capability::WorkspaceRead,
            Capability::TerminalObserve,
            Capability::TerminalManage,
        ]
        .try_into()
        .unwrap(),
        false,
    )
    .unwrap();
    RpcResponse::Result {
        v: ApplicationMajor,
        request_id: "the-original-request-id".to_owned().try_into().unwrap(),
        result: RpcResult::TerminalMove(
            OperationReceipt::new(
                &rights,
                "ab".repeat(32).try_into().unwrap(),
                OperationState::Succeeded,
                false,
                Effect::Committed,
                Some(OperationResult::Domain {
                    domain_revision: DecimalU64(9),
                }),
            )
            .unwrap(),
        ),
    }
}
#[test]
fn move_receipt_uses_existing_sequence_one_fragment_and_exact_original_response() {
    use lomi_remote_protocol::message_framing::MessageAssembler;
    let mut encoder = MessageEncoder::new();
    let mut decoder = MessageAssembler::new();
    let first = encode_receipt_response(&response(), &mut encoder).unwrap();
    assert_eq!(decoder.push(&first, 0).unwrap().unwrap().id, 1);
    let expected = move_response();
    let second = encode_receipt_response(&expected, &mut encoder).unwrap();
    let decoded = decoder.push(&second, 1).unwrap().unwrap();
    assert_eq!(decoded.id, 2);
    assert_eq!(decoded.kind, MessageKind::RpcResponse);
    assert_eq!(
        serde_json::from_slice::<RpcResponse>(&decoded.bytes).unwrap(),
        expected
    );
    assert!(encoder.next_frame().unwrap().is_none());
}
#[test]
fn move_receipt_encoder_rejects_cross_method_receipt_laundering() {
    let RpcResponse::Result {
        result: RpcResult::TerminalRename(rename_receipt),
        ..
    } = response()
    else {
        unreachable!()
    };
    let RpcResponse::Result {
        result: RpcResult::TerminalMove(move_receipt),
        ..
    } = move_response()
    else {
        unreachable!()
    };
    for wrong in [
        RpcResult::TerminalRename(move_receipt),
        RpcResult::TerminalMove(rename_receipt),
    ] {
        let response = RpcResponse::Result {
            v: ApplicationMajor,
            request_id: "the-original-request-id".to_owned().try_into().unwrap(),
            result: wrong,
        };
        assert!(matches!(
            encode_receipt_response(&response, &mut MessageEncoder::new()),
            Err(RemoteRenameError::Closed)
        ));
    }
}
#[test]
fn closed_edit_view_rejects_reads_and_preserves_exact_mutation_identity() {
    let context = WorkspaceContext {
        workspace_id: WorkspaceId::from_bytes([103; 16]).unwrap(),
        workspace_epoch: WorkspaceEpoch::from_bytes([104; 16]).unwrap(),
        runtime_id: RuntimeId::from_bytes([105; 16]).unwrap(),
        runtime_generation: DecimalU64(11),
        host_access_epoch: DecimalU64(12),
        grant_revision: DecimalU64(13),
    };
    let read = RpcCall::WorkspaceGet(WorkspaceReadParams {
        context: context.clone(),
    });
    assert!(RemoteTerminalEdit::from_call(&read).is_err());
    let call = RpcCall::TerminalMove(TerminalMoveParams {
        mutation: MutationContext {
            context,
            operation_id: OperationId::from_bytes([101; 16]).unwrap(),
            expected_revision: DecimalU64(8),
        },
        pane_id: PaneId::from_bytes([106; 16]).unwrap(),
        source_tab_id: TabId::from_bytes([107; 16]).unwrap(),
        target_tab_id: TabId::from_bytes([108; 16]).unwrap(),
        target_pane_id: PaneId::from_bytes([109; 16]).unwrap(),
        placement: MovePlacement::After,
    });
    let edit = RemoteTerminalEdit::from_call(&call).unwrap();
    let RpcCall::TerminalMove(params) = &call else {
        unreachable!()
    };
    assert!(std::ptr::eq(edit.mutation(), &params.mutation));
    assert_eq!(edit.method(), Method::TerminalMove);
}
