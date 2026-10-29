use lomi_remote_protocol::{ipc::*, rpc::*, streams::*, *};
use serde_json::{Value, json};
const ID: &str = "11111111-1111-4111-8111-111111111111";
fn context() -> Value {
    json!({"workspaceId":ID,"workspaceEpoch":ID,"runtimeId":ID,"runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"})
}
fn terminal() -> TerminalContext {
    serde_json::from_value(json!({"workspace":context(),"paneId":ID,"sessionId":ID,"sessionEpoch":ID,"profile":"lomi-rust-grid-v1-experimental"})).unwrap()
}
fn seq(value: u64) -> TerminalSeq {
    TerminalSeq(DecimalU64(value))
}
fn metadata(total: usize, count: u32) -> TerminalDeltaMetadata {
    TerminalDeltaMetadata {
        terminal: terminal(),
        subscription_id: SubscriptionId::try_from("sub".to_owned()).unwrap(),
        previous_seq: seq(7),
        through_seq: seq(8),
        chunk_count: ChunkCount(count),
        total_bytes: DecimalU64(total as u64),
    }
}
fn chunk(index: u32, bytes: &[u8]) -> TerminalDeltaChunk {
    TerminalDeltaChunk {
        terminal: terminal(),
        subscription_id: SubscriptionId::try_from("sub".to_owned()).unwrap(),
        index: ChunkIndex(index),
        bytes: BoundedList(bytes.to_vec()),
    }
}
fn completion() -> TerminalDeltaComplete {
    TerminalDeltaComplete {
        terminal: terminal(),
        subscription_id: SubscriptionId::try_from("sub".to_owned()).unwrap(),
        through_seq: seq(8),
    }
}
fn wire(frame: TerminalStreamFrame) -> Vec<u8> {
    serde_json::to_vec(&frame).unwrap()
}

#[test]
fn descriptor_cas_targets_lost_or_stopped_panes_without_fabricated_sessions() {
    for method in ["terminal.close", "terminal.restart"] {
        for expected in [json!(null), serde_json::to_value(terminal()).unwrap()] {
            let mut params = json!({"mutation":{"operationId":ID,"context":context(),"expectedRevision":"9"},"paneId":ID,"expectedSession":expected});
            if method == "terminal.restart" {
                params["profileId"] = json!("default");
            }
            let mut request = json!({"v":2,"type":"request","requestId":"req","timeoutMs":1000,"call":{"method":method,"params":params}});
            assert!(decode_request(&serde_json::to_vec(&request).unwrap()).is_ok());
            if !request["call"]["params"]["expectedSession"].is_null() {
                request["call"]["params"]["expectedSession"]["paneId"] =
                    json!("22222222-2222-4222-8222-222222222222");
                assert!(decode_request(&serde_json::to_vec(&request).unwrap()).is_err());
            }
        }
    }
    for (state, value) in [(PaneState::Stopped, "stopped"), (PaneState::Lost, "lost")] {
        assert_eq!(serde_json::to_value(state).unwrap(), value);
        let pane: TerminalPane =
            serde_json::from_value(json!({"paneId":ID,"session":null,"state":value})).unwrap();
        assert!(pane.session.is_none());
    }
    let invalid_state:WorkspaceState=serde_json::from_value(json!({"context":context(),"domainRevision":"9","name":"Build","tabs":[{"tabId":ID,"name":"Build","layout":{"kind":"pane","pane":{"paneId":ID,"session":terminal(),"state":"lost"}}}]})).unwrap();
    assert!(invalid_state.validate().is_err());
    let old = json!({"v":2,"type":"request","requestId":"req","timeoutMs":1000,"call":{"method":"terminal.close","params":{"mutation":{"operationId":ID,"context":context(),"expectedRevision":"9"},"terminal":terminal()}}});
    assert!(decode_request(&serde_json::to_vec(&old).unwrap()).is_err());
}

#[test]
fn local_inspection_supplies_current_context_without_request_epoch_claims() {
    let mut request = json!({"version":{"major":1,"minor":0},"requestId":"local","call":{"method":"workspace.inspect","params":{"workspaceId":ID}}});
    assert!(matches!(
        decode_local_request(&encode_local_frame(&request).unwrap())
            .unwrap()
            .call,
        LocalCall::WorkspaceInspect(_)
    ));
    for key in [
        "workspaceEpoch",
        "expectedRevision",
        "operationId",
        "runtimeGeneration",
    ] {
        request["call"]["params"][key] = json!(ID);
        assert!(decode_local_request(&encode_local_frame(&request).unwrap()).is_err());
        request["call"]["params"]
            .as_object_mut()
            .unwrap()
            .remove(key);
    }
    let state = json!({"context":context(),"domainRevision":"9","name":"Build","tabs":[]});
    let mut response = json!({"version":{"major":1,"minor":0},"requestId":"local","result":{"Ok":{"type":"workspaceState","value":state}}});
    assert!(matches!(
        decode_local_response(&encode_local_frame(&response).unwrap())
            .unwrap()
            .result,
        Ok(LocalResult::WorkspaceState(_))
    ));
    response["result"]["Ok"]["value"]["tabs"] = json!([{"tabId":ID,"name":"Build","layout":{"kind":"pane","pane":{"paneId":"22222222-2222-4222-8222-222222222222","session":terminal(),"state":"running"}}}]);
    assert!(decode_local_response(&encode_local_frame(&response).unwrap()).is_err());
}

#[test]
fn local_stream_envelope_demultiplexes_and_checks_inner_semantics() {
    let terminal_event =
        LocalStreamEvent::Terminal(TerminalStreamFrame::DeltaMetadata(metadata(3, 1)));
    let frame = encode_local_frame(&terminal_event).unwrap();
    assert!(decode_local_stream_event(&frame).is_ok());
    assert!(decode_local_response(&frame).is_err());
    let workspace = json!({"stream":"workspace","frame":{"type":"event","data":{"context":context(),"subscriptionId":"sub","eventSeq":"1","cursor":"cur","data":{"kind":"cursor.advance","data":{}}}}});
    assert!(decode_local_stream_event(&encode_local_frame(&workspace).unwrap()).is_ok());
    let response = json!({"version":{"major":1,"minor":0},"requestId":"local","result":{"Ok":{"type":"stopping","value":{}}}});
    assert!(decode_local_response(&encode_local_frame(&response).unwrap()).is_ok());
    assert!(decode_local_stream_event(&encode_local_frame(&response).unwrap()).is_err());
    let invalid =
        LocalStreamEvent::Terminal(TerminalStreamFrame::DeltaComplete(TerminalDeltaComplete {
            through_seq: seq(0),
            ..completion()
        }));
    assert!(decode_local_stream_event(&encode_local_frame(&invalid).unwrap()).is_err());
    let mut bad = serde_json::to_value(terminal_event).unwrap();
    bad["version"] = json!({"major":1,"minor":0});
    assert!(decode_local_stream_event(&encode_local_frame(&bad).unwrap()).is_err());
}

#[test]
fn chunked_delta_reassembles_200_kib_without_advancing_through_early() {
    // Serialized synthetic model payload; actual TerminalState integration and
    // renderer application remain separate host/client responsibilities.
    let model =
        json!({"previousSeq":"7","throughSeq":"8","checkpoint":{"text":"x".repeat(200*1024)}});
    let bytes = serde_json::to_vec(&model).unwrap();
    assert!(bytes.len() > 200 * 1024);
    let count = bytes.len().div_ceil(16384) as u32;
    let metadata = metadata(bytes.len(), count);
    assert!(
        decode_terminal_frame(&wire(TerminalStreamFrame::DeltaMetadata(metadata.clone()))).is_ok()
    );
    let mut assembly = DeltaAssembly::new(metadata, seq(7)).unwrap();
    for (index, part) in bytes.chunks(16384).enumerate() {
        let frame = wire(TerminalStreamFrame::DeltaChunk(chunk(index as u32, part)));
        let TerminalStreamFrame::DeltaChunk(chunk) = decode_terminal_frame(&frame).unwrap() else {
            panic!("chunk")
        };
        assembly.push(&chunk).unwrap();
        assert_eq!(assembly.through_seq(), seq(7));
    }
    let complete = completion();
    let assembled = assembly.complete(&complete).unwrap();
    assert_eq!(assembled, bytes);
    assert_eq!(serde_json::from_slice::<Value>(&assembled).unwrap(), model);
    assert_eq!(assembly.through_seq(), seq(8));
    assert!(assembly.complete(&complete).is_err());
    assert!(assembly.push(&chunk(0, &[1])).is_err());
}

#[test]
fn delta_metadata_rejects_budget_gaps_overflow_and_stale_previous_sequence() {
    for invalid in [
        metadata(8 * 1024 * 1024 + 1, 513),
        metadata(16385, 1),
        metadata(0, 1),
        metadata(1, 2),
        metadata(1, 0),
        metadata(2048, 1025),
    ] {
        assert!(DeltaAssembly::new(invalid.clone(), seq(7)).is_err());
        assert!(decode_terminal_frame(&wire(TerminalStreamFrame::DeltaMetadata(invalid))).is_err());
    }
    for (previous, through) in [(7, 9), (7, 7), (u64::MAX, 0)] {
        let mut invalid = metadata(3, 1);
        invalid.previous_seq = seq(previous);
        invalid.through_seq = seq(through);
        assert!(DeltaAssembly::new(invalid.clone(), seq(previous)).is_err());
        assert!(decode_terminal_frame(&wire(TerminalStreamFrame::DeltaMetadata(invalid))).is_err());
    }
    assert!(DeltaAssembly::new(metadata(3, 1), seq(6)).is_err());
    for bytes in [vec![], vec![0; 16385]] {
        assert!(
            decode_terminal_frame(&wire(TerminalStreamFrame::DeltaChunk(chunk(0, &bytes))))
                .is_err()
        );
    }
}

#[test]
fn delta_binding_order_truncation_and_abort_fail_without_sequence_advance() {
    let mut invalid_chunks = vec![chunk(1, &[1]), chunk(0, &[1, 2, 3, 4])];
    let mut wrong = chunk(0, &[1]);
    wrong.subscription_id = SubscriptionId::try_from("other".to_owned()).unwrap();
    invalid_chunks.push(wrong);
    let mut wrong = chunk(0, &[1]);
    wrong.terminal.session_epoch = SessionEpoch::from_bytes([2; 16]).unwrap();
    invalid_chunks.push(wrong);
    let mut wrong = chunk(0, &[1]);
    wrong.terminal.workspace.runtime_generation = DecimalU64(2);
    invalid_chunks.push(wrong);
    for invalid in invalid_chunks {
        let mut assembly = DeltaAssembly::new(metadata(3, 2), seq(7)).unwrap();
        assert!(assembly.push(&invalid).is_err());
        assert_eq!(assembly.through_seq(), seq(7));
        assert!(
            assembly.push(&chunk(0, &[1])).is_err(),
            "failed assembly cannot resume"
        );
    }
    let mut assembly = DeltaAssembly::new(metadata(3, 2), seq(7)).unwrap();
    assembly.push(&chunk(0, &[1])).unwrap();
    assert!(assembly.push(&chunk(0, &[2])).is_err());
    assert_eq!(assembly.through_seq(), seq(7));
    let mut assembly = DeltaAssembly::new(metadata(3, 2), seq(7)).unwrap();
    assembly.push(&chunk(0, &[1])).unwrap();
    assert!(assembly.complete(&completion()).is_err());
    assert_eq!(assembly.through_seq(), seq(7));
    for wrong in [
        TerminalDeltaComplete {
            through_seq: seq(9),
            ..completion()
        },
        TerminalDeltaComplete {
            subscription_id: SubscriptionId::try_from("other".to_owned()).unwrap(),
            ..completion()
        },
        TerminalDeltaComplete {
            terminal: TerminalContext {
                session_epoch: SessionEpoch::from_bytes([2; 16]).unwrap(),
                ..terminal()
            },
            ..completion()
        },
    ] {
        let mut assembly = DeltaAssembly::new(metadata(3, 1), seq(7)).unwrap();
        assembly.push(&chunk(0, &[1, 2, 3])).unwrap();
        assert!(assembly.complete(&wrong).is_err());
        assert_eq!(assembly.through_seq(), seq(7));
    }
    let mut assembly = DeltaAssembly::new(metadata(3, 1), seq(7)).unwrap();
    assembly.abort();
    assert!(assembly.push(&chunk(0, &[1, 2, 3])).is_err());
    assert!(assembly.complete(&completion()).is_err());
}

#[test]
fn claim_and_renew_require_canonical_next_id_input_and_resize_watermarks() {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/rpc-streams/lease-watermarks.json"
    ))
    .unwrap();
    assert_eq!(fixtures.len(), 20);
    for fixture in fixtures {
        let request = decode_request(&serde_json::to_vec(&fixture["request"]).unwrap()).unwrap();
        let result = decode_response_for(&serde_json::to_vec(&fixture["value"]).unwrap(), &request);
        assert_eq!(
            result.is_ok(),
            fixture["accepted"].as_bool().unwrap(),
            "{}",
            fixture["name"]
        );
        if let Ok(RpcResponse::Result { result, .. }) = result {
            let lease = match result {
                RpcResult::TerminalClaim(lease) | RpcResult::TerminalRenew(lease) => lease,
                _ => panic!("lease result"),
            };
            assert_eq!(lease.next_input_id, DecimalU64(41));
            assert_eq!(lease.next_input_seq, InputSeq(DecimalU64(12)));
            assert_eq!(lease.next_resize_seq, ResizeSeq(DecimalU64(9)));
        }
    }
}

#[test]
fn shared_e1_wire_corpus_uses_checked_native_entrypoints_without_skips() {
    let fixtures: Vec<Value> =
        serde_json::from_str(include_str!("../../../contracts/fixtures/e1/wire.json")).unwrap();
    assert_eq!(fixtures.len(), 26);
    for fixture in fixtures {
        let value = &fixture["value"];
        let bytes = serde_json::to_vec(value).unwrap();
        let accepted = match fixture["schema"].as_str().unwrap() {
            "rpc-request" => decode_request(&bytes).is_ok(),
            "rpc-response" => {
                let request =
                    decode_request(&serde_json::to_vec(&fixture["request"]).unwrap()).unwrap();
                decode_response_for(&bytes, &request).is_ok()
            }
            "terminal-stream-frame" => decode_terminal_frame(&bytes).is_ok(),
            "local-request" => decode_local_request(&encode_local_frame(value).unwrap()).is_ok(),
            "local-response" => decode_local_response(&encode_local_frame(value).unwrap()).is_ok(),
            "local-stream-event" => {
                decode_local_stream_event(&encode_local_frame(value).unwrap()).is_ok()
            }
            other => panic!("unhandled E1 fixture kind: {other}"),
        };
        assert_eq!(
            Some(accepted),
            fixture["accepted"].as_bool(),
            "{}",
            fixture["name"]
        );
    }
}
