use lomi_remote_protocol::{rpc::*, streams::*, *};
use serde_json::{Value, json};
const ID: &str = "11111111-1111-4111-8111-111111111111";
fn context() -> Value {
    json!({"workspaceId":ID,"workspaceEpoch":ID,"runtimeId":ID,"runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"})
}
fn mutation() -> Value {
    json!({"operationId":ID,"context":context(),"expectedRevision":"1"})
}
fn file_mutation() -> Value {
    json!({"operationId":ID,"context":context()})
}
fn terminal() -> Value {
    json!({"workspace":context(),"paneId":ID,"sessionId":ID,"sessionEpoch":ID,"profile":"lomi-rust-grid-v1-experimental"})
}
fn lease() -> Value {
    json!({"token":"lease-token","version":"1"})
}
fn request(method: &str, params: Value) -> Value {
    json!({"v":2,"type":"request","requestId":"req-1","timeoutMs":10000,"call":{"method":method,"params":params}})
}
fn decode(value: &Value) -> Result<RpcRequest, String> {
    decode_request(&serde_json::to_vec(value).unwrap())
}
fn create() -> Value {
    json!({"mutation":file_mutation(),"parentEntryId":ID,"parentRevision":"revision","name":"new.txt","destination":"absent"})
}
fn network() -> Value {
    json!({"mutation":file_mutation(),"repositoryId":ID,"remoteId":"remote-main","refId":"ref-main","expectedRefs":"refs"})
}
#[test]
fn all_39_methods_have_typed_decodable_requests() {
    let expected = json!({"head":"head","index":"index"});
    let mut cases = vec![
        ("workspace.get", json!({"context":context()})),
        ("workspace.capabilities", json!({"context":context()})),
        (
            "workspace.subscribe",
            json!({"context":context(),"cursor":null}),
        ),
        (
            "terminal.create",
            json!({"mutation":mutation(),"tabName":"Build","profileId":"default"}),
        ),
        (
            "terminal.split",
            json!({"mutation":mutation(),"tabId":ID,"paneId":ID,"axis":"horizontal","profileId":"default"}),
        ),
        (
            "terminal.rename",
            json!({"mutation":mutation(),"tabId":ID,"name":"Build"}),
        ),
        (
            "terminal.move",
            json!({"mutation":mutation(),"paneId":ID,"sourceTabId":ID,"targetTabId":ID,"targetPaneId":ID,"placement":"after"}),
        ),
        (
            "terminal.close",
            json!({"mutation":mutation(),"paneId":ID,"expectedSession":terminal()}),
        ),
        (
            "terminal.restart",
            json!({"mutation":mutation(),"paneId":ID,"expectedSession":terminal(),"profileId":"default"}),
        ),
        ("terminal.attach", json!({"terminal":terminal()})),
        ("terminal.snapshot", json!({"terminal":terminal()})),
        (
            "terminal.ack",
            json!({"terminal":terminal(),"subscriptionId":"sub","throughSeq":"3"}),
        ),
        (
            "terminal.claim",
            json!({"terminal":terminal(),"subscriptionId":"sub","renderedThroughSeq":"3"}),
        ),
        (
            "terminal.renew",
            json!({"terminal":terminal(),"lease":lease()}),
        ),
        (
            "terminal.release",
            json!({"terminal":terminal(),"lease":lease()}),
        ),
        (
            "terminal.input",
            json!({"terminal":terminal(),"lease":lease(),"inputId":"1","inputSeq":"1","bytes":[65]}),
        ),
        (
            "terminal.resize",
            json!({"terminal":terminal(),"lease":lease(),"resizeSeq":"1","columns":80,"rows":24}),
        ),
        (
            "files.list",
            json!({"context":context(),"parentEntryId":ID,"cursor":null,"limit":200}),
        ),
        (
            "files.stat",
            json!({"context":context(),"entryId":ID,"fileRevision":null}),
        ),
        (
            "files.read",
            json!({"context":context(),"entryId":ID,"fileRevision":"rev","offset":"0","maxBytes":1048576}),
        ),
        (
            "files.searchNames",
            json!({"context":context(),"parentEntryId":ID,"query":"test","cursor":null,"limit":20}),
        ),
        (
            "files.watch",
            json!({"context":context(),"entryId":ID,"cursor":null}),
        ),
        ("files.create", create()),
        ("files.mkdir", create()),
        (
            "files.rename",
            json!({"mutation":file_mutation(),"entryId":ID,"fileRevision":"rev","sourceParentId":ID,"sourceParentRevision":"rev","targetParentId":ID,"targetParentRevision":"rev","name":"new","destination":"absent"}),
        ),
        (
            "files.remove",
            json!({"mutation":file_mutation(),"entryId":ID,"fileRevision":"rev","parentEntryId":ID,"parentRevision":"rev","confirmation":"confirmed"}),
        ),
        ("git.repositories", json!({"context":context()})),
        (
            "git.status",
            json!({"context":context(),"repositoryId":ID,"stateToken":null,"cursor":null,"limit":10}),
        ),
        (
            "git.diff",
            json!({"context":context(),"repositoryId":ID,"stateToken":"state","entryId":null,"view":"worktree","cursor":null,"limit":10}),
        ),
        (
            "git.log",
            json!({"context":context(),"repositoryId":ID,"stateToken":"state","cursor":null,"limit":10}),
        ),
        (
            "git.show",
            json!({"context":context(),"repositoryId":ID,"stateToken":"state","objectId":"object","cursor":null,"limit":10}),
        ),
        (
            "git.stage",
            json!({"mutation":file_mutation(),"repositoryId":ID,"expected":expected,"paths":[{"entryId":ID,"fileRevision":"rev"}]}),
        ),
        (
            "git.unstage",
            json!({"mutation":file_mutation(),"repositoryId":ID,"expected":expected,"paths":[ID]}),
        ),
        (
            "git.commit",
            json!({"mutation":file_mutation(),"repositoryId":ID,"expected":expected,"message":"Add feature"}),
        ),
        ("git.fetch", network()),
        ("git.push", network()),
        (
            "operation.status",
            json!({"context":context(),"operationId":ID}),
        ),
        (
            "operation.cancel",
            json!({"context":context(),"operationId":ID}),
        ),
    ];
    let mut pull = network();
    pull["expected"] = expected;
    pull["expectedWorktree"] = json!("worktree");
    pull["mode"] = json!("ff-only");
    cases.push(("git.pull", pull));
    assert_eq!(cases.len(), 39);
    for (method, params) in cases {
        let req = decode(&request(method, params)).unwrap_or_else(|e| panic!("{method}: {e}"));
        assert_eq!(req.call.method().as_str(), method);
    }
}
#[test]
fn mutation_fields_are_scoped_to_their_domain() {
    let mut read = request("workspace.get", json!({"context":context()}));
    assert!(decode(&read).is_ok());
    read["operationId"] = json!(ID);
    assert!(decode(&read).is_err());
    let mut domain = request(
        "terminal.create",
        json!({"mutation":mutation(),"tabName":"Build","profileId":"default"}),
    );
    domain["call"]["params"]["mutation"]
        .as_object_mut()
        .unwrap()
        .remove("operationId");
    assert!(decode(&domain).is_err());
    let mut file = create();
    file["mutation"]["expectedRevision"] = json!("1");
    assert!(decode(&request("files.create", file)).is_err());
    let mut status = json!({"context":context(),"operationId":ID});
    status["expectedRevision"] = json!("1");
    assert!(decode(&request("operation.status", status)).is_err());
    let mut bad = request(
        "terminal.close",
        json!({"mutation":mutation(),"paneId":ID,"expectedSession":terminal()}),
    );
    bad["call"]["params"]["expectedSession"]["workspace"]["runtimeGeneration"] = json!("2");
    assert!(decode(&bad).is_err());
}
#[test]
fn forbidden_remote_execution_and_file_write_shapes_fail_closed() {
    for (method, mut params, field, value) in [
        ("files.create", create(), "content", json!("secret")),
        ("files.create", create(), "mode", json!(493)),
        (
            "files.remove",
            json!({"mutation":file_mutation(),"entryId":ID,"fileRevision":"rev","parentEntryId":ID,"parentRevision":"rev","confirmation":"confirmed"}),
            "recursive",
            json!(true),
        ),
        (
            "terminal.create",
            json!({"mutation":mutation(),"tabName":"Build","profileId":"default"}),
            "command",
            json!("sh"),
        ),
        ("git.push", network(), "force", json!(true)),
        ("git.push", network(), "remoteUrl", json!("ssh://example")),
        (
            "git.stage",
            json!({"mutation":file_mutation(),"repositoryId":ID,"expected":{"head":"h","index":"i"},"paths":[{"entryId":ID,"fileRevision":"r"}]}),
            "patch",
            json!("diff"),
        ),
    ] {
        params[field] = value;
        assert!(
            decode(&request(method, params)).is_err(),
            "{method}/{field}"
        );
    }
    for name in ["../x", "/etc/passwd", ".", "..", "a\\b"] {
        let mut p = create();
        p["name"] = json!(name);
        assert!(decode(&request("files.create", p)).is_err());
    }
    let mut p = network();
    p["remoteId"] = json!("https://example.com");
    assert!(decode(&request("git.push", p)).is_err());
    let p = json!({"mutation":mutation(),"paneId":ID,"sourceTabId":ID,"targetTabId":ID,"targetPaneId":ID,"placement":"after","targetWorkspaceId":ID});
    assert!(decode(&request("terminal.move", p)).is_err());
}
#[test]
fn versions_unknown_methods_u64_and_budgets_are_strict() {
    assert!(decode(&request("system.exec", json!({}))).is_err());
    let mut r = request("workspace.get", json!({"context":context()}));
    r["v"] = json!(1);
    assert!(decode(&r).is_err());
    r["v"] = json!(2);
    r["call"]["params"]["context"]["grantRevision"] = json!(1);
    assert!(decode(&r).is_err());
    r["call"]["params"]["context"]["grantRevision"] = json!("18446744073709551616");
    assert!(decode(&r).is_err());
    let mut p = json!({"terminal":terminal(),"lease":lease(),"inputId":"1","inputSeq":"1","bytes":vec![0;16385]});
    assert!(decode(&request("terminal.input", p.clone())).is_err());
    p["bytes"] = json!([0]);
    p["terminal"]["profile"] = json!("xterm-raw");
    assert!(decode(&request("terminal.input", p)).is_err());
    let p = json!({"context":context(),"entryId":ID,"offset":"0","maxBytes":1048577});
    assert!(decode(&request("files.read", p)).is_err());
    let mut r = request("workspace.get", json!({"context":context()}));
    r["timeoutMs"] = json!(120001);
    assert!(decode(&r).is_err());
}
#[test]
fn streams_reject_bad_seq_chunks_and_watch_overflow() {
    let mut event = json!({"type":"event","data":{"context":context(),"subscriptionId":"sub","eventSeq":"1","cursor":"cursor","data":{"kind":"cursor.advance","data":{}}}});
    assert!(decode_workspace_frame(&serde_json::to_vec(&event).unwrap()).is_ok());
    for seq in [json!(0), json!("0"), json!("18446744073709551616")] {
        event["data"]["eventSeq"] = seq;
        assert!(decode_workspace_frame(&serde_json::to_vec(&event).unwrap()).is_err());
    }
    let chunk = json!({"type":"snapshotChunk","data":{"subscriptionId":"sub","index":0,"bytes":vec![0;16385]}});
    assert!(decode_workspace_frame(&serde_json::to_vec(&chunk).unwrap()).is_err());
    let watch = json!({"type":"invalidated","data":{"context":context(),"subscriptionId":"sub","watchSeq":"1","cursor":"cur","invalidation":{"entries":[],"overflow":true}}});
    assert!(decode_watch_frame(&serde_json::to_vec(&watch).unwrap()).is_err());
    let mut seq = OrderedSequence::new(DecimalU64(10));
    assert_eq!(seq.accept(DecimalU64(11)), Ok(true));
    assert_eq!(seq.accept(DecimalU64(11)), Ok(false));
    assert_eq!(seq.accept(DecimalU64(13)), Err(ResyncReason::Gap));
    assert!(seq.accept(DecimalU64(12)).is_err());
    let mut max = OrderedSequence::new(DecimalU64(u64::MAX));
    assert!(max.accept(DecimalU64(0)).is_err());
}
#[test]
fn snapshot_assembly_requires_exact_subscription_order_and_total() {
    let sub = SubscriptionId::try_from("sub".to_owned()).unwrap();
    let mut assembly =
        SnapshotAssembly::new(sub.clone(), ChunkCount::try_from(2).unwrap(), DecimalU64(3))
            .unwrap();
    assert!(assembly.complete(&sub).is_err());
    assert!(assembly.push(&sub, ChunkIndex(1), &[0]).is_err());
    assembly.push(&sub, ChunkIndex(0), &[0, 1]).unwrap();
    assert!(assembly.complete(&sub).is_err());
    assembly.push(&sub, ChunkIndex(1), &[2]).unwrap();
    assembly.complete(&sub).unwrap();
    assert!(assembly.push(&sub, ChunkIndex(2), &[3]).is_err());
    assert!(SnapshotAssembly::new(sub, ChunkCount(1), DecimalU64(8388609)).is_err());
}

#[test]
fn checked_responses_bind_method_file_revision_and_terminal_epoch() {
    let req = decode(&request(
        "files.read",
        json!({"context":context(),"entryId":ID,"fileRevision":"rev","offset":"0","maxBytes":1}),
    ))
    .unwrap();
    let metadata = json!({"entryId":ID,"pathId":"encoded-nonutf8-path","displayName":"safe display","kind":"file","fileRevision":"rev","size":"2"});
    let mut response = json!({"type":"result","v":2,"requestId":"req-1","result":{"method":"files.read","params":{"metadata":metadata,"encoding":"utf8","lineEndings":"lf","offset":"0","bytes":[65],"truncated":true}}});
    let check = |value: &Value| decode_response_for(&serde_json::to_vec(value).unwrap(), &req);
    assert!(check(&response).is_ok());
    response["requestId"] = json!("other");
    assert!(check(&response).is_err());
    response["requestId"] = json!("req-1");
    response["result"]["params"]["bytes"] = json!([65, 66]);
    assert!(check(&response).is_err());
    response["result"]["params"]["bytes"] = json!([65]);
    response["result"]["params"]["metadata"]["fileRevision"] = json!("other");
    assert!(check(&response).is_err());
    response["result"]["params"]["metadata"]["fileRevision"] = json!("rev");
    response["result"]["params"]["encoding"] = json!("binary");
    assert!(check(&response).is_err());
    response["result"]["params"]["bytes"] = json!(vec![0; 1048577]);
    assert!(decode_response(&serde_json::to_vec(&response).unwrap()).is_err());

    let req = decode(&request(
        "terminal.input",
        json!({"terminal":terminal(),"lease":lease(),"inputId":"1","inputSeq":"2","bytes":[65]}),
    ))
    .unwrap();
    let receipt = InputReceipt::new(
        TerminalSessionId::try_from(ID.to_owned()).unwrap(),
        SessionEpoch::try_from(ID.to_owned()).unwrap(),
        DecimalU64(1),
        DecimalU64(2),
        InputBytes::new(1).unwrap(),
        InputBytes::new(1).unwrap(),
    )
    .unwrap();
    let mut response = json!({"type":"result","v":2,"requestId":"req-1","result":{"method":"terminal.input","params":receipt}});
    assert!(decode_response_for(&serde_json::to_vec(&response).unwrap(), &req).is_ok());
    response["result"]["params"]["sessionEpoch"] = json!("22222222-2222-4222-8222-222222222222");
    assert!(decode_response_for(&serde_json::to_vec(&response).unwrap(), &req).is_err());
}

#[test]
fn shared_layout_is_a_terminal_only_tree_with_exact_session_bindings() {
    let state = json!({"context":context(),"domainRevision":"1","name":"Build","tabs":[{"tabId":ID,"name":"Main","layout":{"kind":"pane","pane":{"paneId":ID,"session":terminal(),"state":"running"}}}]});
    let mut state: WorkspaceState = serde_json::from_value(state).unwrap();
    state.validate().unwrap();
    if let TerminalLayout::Pane { pane } = &mut state.tabs.0[0].layout {
        pane.pane_id = PaneId::try_from("22222222-2222-4222-8222-222222222222".to_owned()).unwrap();
    }
    assert!(state.validate().is_err());
    let layout = json!({"kind":"editor","path":"secret-private-buffer"});
    assert!(serde_json::from_value::<TerminalLayout>(layout).is_err());
}

#[test]
fn ordinary_rpc_responses_use_control_limit_instead_of_snapshot_budget() {
    let req=decode(&request("git.diff",json!({"context":context(),"repositoryId":ID,"stateToken":"state","entryId":null,"view":"worktree","cursor":null,"limit":1}))).unwrap();
    let mut response = json!({"type":"result","v":2,"requestId":"req-1","result":{"method":"git.diff","params":{"stateToken":"state","files":[],"nextCursor":null,"truncated":false}}});
    let mut bytes = serde_json::to_vec(&response).unwrap();
    bytes.resize(CONTROL_MESSAGE_BYTES as usize, b' ');
    assert!(decode_response_for(&bytes, &req).is_ok());
    bytes.push(b' ');
    assert!(decode_response_for(&bytes, &req).is_err());
    assert!(decode_response(&bytes).is_err());

    let line = json!({"kind":"context","text":"x".repeat(4000)});
    let hunk = json!({"oldStart":"1","newStart":"1","lines":vec![line;200]});
    response["result"]["params"]["files"] = json!([{"entryId":ID,"displayName":"file.txt","binary":false,"hunks":[hunk.clone(),hunk],"truncated":false}]);
    let bytes = serde_json::to_vec(&response).unwrap();
    assert!(bytes.len() > CONTROL_MESSAGE_BYTES as usize);
    // The per-field bounds are valid; the complete control message is too large.
    assert!(serde_json::from_slice::<RpcResponse>(&bytes).is_ok());
    assert!(decode_response_for(&bytes, &req).is_err());
}

#[test]
fn lease_bearer_tokens_are_redacted_in_direct_and_nested_debug() {
    let secret = "synthetic-lease-bearer-secret";
    let token = LeaseToken::try_from(secret.to_owned()).unwrap();
    assert!(!format!("{token:?}").contains(secret));
    let req=decode(&request("terminal.input",json!({"terminal":terminal(),"lease":{"token":secret,"version":"1"},"inputId":"1","inputSeq":"1","bytes":[65]}))).unwrap();
    assert!(!format!("{req:?}").contains(secret));
    let RpcCall::TerminalInput(input) = &req.call else {
        panic!("expected terminal input")
    };
    assert!(!format!("{:?}", input.lease).contains(secret));
    // Debug redaction must preserve the authenticated wire token.
    assert_eq!(serde_json::to_value(&input.lease).unwrap()["token"], secret);
}

#[test]
fn git_diff_lines_preserve_blank_lines_and_enforce_text_bounds() {
    for kind in ["context", "added", "removed"] {
        let line: GitDiffLine = serde_json::from_value(json!({"kind":kind,"text":""})).unwrap();
        assert_eq!(serde_json::to_value(line).unwrap()["text"], "");
    }
    for text in ["x".repeat(4096), "\tindented".to_owned()] {
        assert!(
            serde_json::from_value::<GitDiffLine>(json!({"kind":"context","text":text})).is_ok()
        );
    }
    for text in [
        "x".repeat(4097),
        "line\nline".to_owned(),
        "nul\0".to_owned(),
        "escape\u{1b}".to_owned(),
    ] {
        assert!(
            serde_json::from_value::<GitDiffLine>(json!({"kind":"context","text":text})).is_err()
        );
    }
}

#[test]
fn text_schema_carries_byte_and_character_constraints() {
    fn schema<T: schemars::JsonSchema>() -> Value {
        serde_json::to_value(schemars::schema_for!(T)).unwrap()
    }
    let display = schema::<DisplayText>();
    assert_eq!(display["x-lomi-maxUtf8Bytes"], 4096);
    assert_eq!(
        display["not"]["pattern"],
        r"[\u0000-\u0008\u000B-\u001F\u007F-\u009F]"
    );
    let entry = schema::<EntryName>();
    assert_eq!(entry["x-lomi-maxUtf8Bytes"], 255);
    assert_eq!(
        entry["not"]["anyOf"][0]["pattern"],
        r"[/\\\u0000-\u001F\u007F-\u009F]"
    );
    let lease = schema::<LeaseToken>();
    assert_eq!(lease["x-lomi-maxUtf8Bytes"], 256);
    assert_eq!(lease["not"]["pattern"], "[^A-Za-z0-9_-]");
    let diff = schema::<DiffLineText>();
    assert_eq!(diff["x-lomi-maxUtf8Bytes"], 4096);
    assert_eq!(
        diff["not"]["pattern"],
        r"[\u0000-\u0008\u000A-\u001F\u007F-\u009F]"
    );
}

#[test]
fn rust_text_parity_corpus_covers_controls_and_multibyte_limits() {
    let corpus: Vec<Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/rpc-streams/text-parity.json"
    ))
    .unwrap();
    assert_eq!(corpus.len(), 20);
    let mut correlated_responses = 0;
    for case in corpus {
        let bytes = serde_json::to_vec(&case["value"]).unwrap();
        let accepted = match case["schema"].as_str().unwrap() {
            "rpc-request" => decode_request(&bytes).is_ok(),
            "rpc-response" => {
                let original = case
                    .get("request")
                    .expect("response fixture requires request binding");
                let request = decode_request(&serde_json::to_vec(original).unwrap())
                    .expect("response fixture request must be valid");
                correlated_responses += 1;
                decode_response_for(&bytes, &request).is_ok()
            }
            _ => panic!("unexpected schema"),
        };
        assert_eq!(
            accepted,
            case["accepted"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
    assert_eq!(
        correlated_responses, 8,
        "all response fixtures must exercise correlation"
    );
}
