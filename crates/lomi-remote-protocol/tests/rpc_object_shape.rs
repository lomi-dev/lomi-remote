use lomi_remote_protocol::{
    CONTROL_MESSAGE_BYTES, MutationContext, TerminalContext, WorkspaceContext, ipc::*,
    rpc::decode_request,
};
use serde_json::{Value, json};

const ID: &str = "11111111-1111-4111-8111-111111111111";

fn context() -> Value {
    json!({
        "workspaceId": ID,
        "workspaceEpoch": ID,
        "runtimeId": ID,
        "runtimeGeneration": "1",
        "hostAccessEpoch": "1",
        "grantRevision": "1"
    })
}

fn request(params: Value) -> Value {
    json!({
        "v": 2,
        "type": "request",
        "requestId": "req-1",
        "timeoutMs": 10000,
        "call": { "method": "workspace.get", "params": params }
    })
}

#[test]
fn native_rpc_requests_require_object_envelopes_and_params() {
    let canonical = request(json!({"context": context()}));
    assert!(decode_request(&serde_json::to_vec(&canonical).unwrap()).is_ok());

    let positional_root = json!([
        2,
        "request",
        "req-1",
        10000,
        {"method": "workspace.get", "params": {"context": context()}}
    ]);
    let positional_params = request(json!([context()]));

    let accepted = (
        decode_request(&serde_json::to_vec(&positional_root).unwrap()).is_ok(),
        decode_request(&serde_json::to_vec(&positional_params).unwrap()).is_ok(),
    );
    assert_eq!(
        accepted,
        (false, false),
        "positional requests were accepted"
    );
}

#[test]
fn native_rpc_requests_check_original_json_before_typed_decode() {
    let duplicate = br#"{"v":2,"v":2}"#;
    assert_eq!(decode_request(duplicate).unwrap_err(), "INVALID_ARGUMENT");

    let mut trailing = serde_json::to_vec(&request(json!({"context": context()}))).unwrap();
    trailing.extend_from_slice(b" {} ");
    assert_eq!(decode_request(&trailing).unwrap_err(), "INVALID_ARGUMENT");

    assert_eq!(decode_request(b"\xff").unwrap_err(), "INVALID_ARGUMENT");

    let oversized = vec![b' '; CONTROL_MESSAGE_BYTES as usize + 1];
    assert_eq!(
        decode_request(&oversized).unwrap_err(),
        "RESOURCE_EXHAUSTED"
    );
}

#[test]
fn nested_local_rpc_uses_the_same_object_only_dto_decode() {
    let valid = json!({
        "version": {"major": 1, "minor": 0},
        "requestId": "local-1",
        "call": {
            "method": "rpc",
            "params": request(json!({"context": context()}))
        }
    });
    assert!(decode_local_request(&encode_local_frame(&valid).unwrap()).is_ok());

    let positional_rpc = json!({
        "version": {"major": 1, "minor": 0},
        "requestId": "local-1",
        "call": {
            "method": "rpc",
            "params": [
                2,
                "request",
                "rpc-1",
                10000,
                {"method": "workspace.get", "params": {"context": context()}}
            ]
        }
    });
    assert!(decode_local_request(&encode_local_frame(&positional_rpc).unwrap()).is_err());
}

fn positional_workspace_context() -> Value {
    json!([ID, ID, ID, "1", "1", "1"])
}

fn positional_mutation_context() -> Value {
    json!([ID, context(), "1"])
}

fn positional_terminal_context() -> Value {
    json!([context(), ID, ID, ID, "lomi-rust-grid-v1-experimental"])
}

#[test]
fn rpc_calls_and_shared_contexts_require_objects() {
    let context_value = positional_workspace_context();
    let mutation_value = positional_mutation_context();
    let terminal_value = positional_terminal_context();

    let direct_contexts = [
        serde_json::from_value::<WorkspaceContext>(context_value.clone()).is_ok(),
        serde_json::from_value::<MutationContext>(mutation_value.clone()).is_ok(),
        serde_json::from_value::<TerminalContext>(terminal_value.clone()).is_ok(),
    ];

    let mut positional_workspace = request(json!({"context": context()}));
    positional_workspace["call"]["params"]["context"] = context_value;

    let positional_mutation = json!({
        "v": 2,
        "type": "request",
        "requestId": "req-1",
        "timeoutMs": 10000,
        "call": {
            "method": "terminal.create",
            "params": {
                "mutation": mutation_value,
                "tabName": "Build",
                "profileId": "default"
            }
        }
    });

    let positional_terminal = json!({
        "v": 2,
        "type": "request",
        "requestId": "req-1",
        "timeoutMs": 10000,
        "call": {
            "method": "terminal.attach",
            "params": {"terminal": terminal_value}
        }
    });

    let positional_call = json!({
        "v": 2,
        "type": "request",
        "requestId": "req-1",
        "timeoutMs": 10000,
        "call": ["workspace.get", {"context": context()}]
    });

    let reachable_rpc = [
        decode_request(&serde_json::to_vec(&positional_workspace).unwrap()).is_ok(),
        decode_request(&serde_json::to_vec(&positional_mutation).unwrap()).is_ok(),
        decode_request(&serde_json::to_vec(&positional_terminal).unwrap()).is_ok(),
        decode_request(&serde_json::to_vec(&positional_call).unwrap()).is_ok(),
    ];

    assert_eq!(
        (direct_contexts, reachable_rpc),
        ([false, false, false], [false, false, false, false])
    );
}

#[test]
fn nested_local_rpc_requires_object_call_and_contexts() {
    let mut rpc_request = request(json!({"context": context()}));
    rpc_request["call"] = json!(["workspace.get", {"context": context()}]);

    let local = json!({
        "version": {"major": 1, "minor": 0},
        "requestId": "local-1",
        "call": {"method": "rpc", "params": rpc_request}
    });

    let nested_call = decode_local_request(&encode_local_frame(&local).unwrap()).is_ok();

    let mut rpc_request = request(json!({"context": context()}));
    rpc_request["call"]["params"]["context"] = positional_workspace_context();
    let local = json!({
        "version": {"major": 1, "minor": 0},
        "requestId": "local-1",
        "call": {"method": "rpc", "params": rpc_request}
    });
    let nested_context = decode_local_request(&encode_local_frame(&local).unwrap()).is_ok();

    assert_eq!([nested_call, nested_context], [false, false]);
}
