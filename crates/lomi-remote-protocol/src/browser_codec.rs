//! Pure wire checks only. No principal, database, freshness or stream-assembly authority.
use crate::{ipc::*, *};
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;

fn invalid() -> JsValue {
    JsValue::from_str("INVALID_ARGUMENT")
}
fn check_raw(json: &str) -> Result<(), JsValue> {
    crate::json_wire::check_raw(json).map_err(JsValue::from_str)
}
fn typed<T: DeserializeOwned>(json: &str) -> Result<(), JsValue> {
    serde_json::from_str::<T>(json)
        .map(|_| ())
        .map_err(|_| invalid())
}
fn local_frame(json: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(json.len() + 4);
    frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
    frame.extend_from_slice(json.as_bytes());
    frame
}
#[wasm_bindgen]
pub fn protocol_validate_wire(kind: &str, json: &str) -> Result<(), JsValue> {
    check_raw(json)?;
    match kind {
        "rpc-request" | "RpcRequest" => decode_request(json.as_bytes())
            .map(|_| ())
            .map_err(|_| invalid()),
        // Correlation and method-specific semantics need the original request.
        "rpc-response" | "RpcResponse" => Err(invalid()),
        "workspace-stream-frame" | "WorkspaceStreamFrame" => {
            decode_workspace_frame(json.as_bytes())
                .map(|_| ())
                .map_err(|_| invalid())
        }
        "terminal-stream-frame" | "TerminalStreamFrame" => decode_terminal_frame(json.as_bytes())
            .map(|_| ())
            .map_err(|_| invalid()),
        "file-watch-frame" | "FileWatchFrame" => decode_watch_frame(json.as_bytes())
            .map(|_| ())
            .map_err(|_| invalid()),
        "local-request" | "LocalRequest" => decode_local_request(&local_frame(json))
            .map(|_| ())
            .map_err(|_| invalid()),
        "local-response" | "LocalResponse" => decode_local_response(&local_frame(json))
            .map(|_| ())
            .map_err(|_| invalid()),
        "local-stream-event" | "LocalStreamEvent" => decode_local_stream_event(&local_frame(json))
            .map(|_| ())
            .map_err(|_| invalid()),
        "draft-contract" | "DraftContract" => typed::<DraftContract>(json),
        "remote-error" | "RemoteError" => typed::<RemoteError>(json),
        "operation-receipt" | "OperationReceipt" => typed::<OperationReceipt>(json),
        "operation-tombstone" | "OperationTombstone" => typed::<OperationTombstone>(json),
        "input-receipt" | "InputReceipt" => typed::<InputReceipt>(json),
        "workspace-context" | "WorkspaceContext" => typed::<WorkspaceContext>(json),
        "terminal-context" | "TerminalContext" => typed::<TerminalContext>(json),
        "mutation-context" | "MutationContext" => typed::<MutationContext>(json),
        "wss-admission-frame" | "WssAdmissionFrame" => typed::<WssAdmissionFrame>(json),
        "local-client-hello" | "LocalClientHello" => typed::<LocalClientHello>(json),
        "local-server-hello" | "LocalServerHello" => typed::<LocalServerHello>(json),
        "native-lease" | "NativeLease" => typed::<NativeLease>(json),
        "native-intent-scope" | "NativeIntentScope" => typed::<NativeIntentScope>(json),
        _ => validate_http_wire(kind, json).map_err(JsValue::from_str),
    }
}
#[wasm_bindgen]
pub fn protocol_validate_response_for(
    request_json: &str,
    response_json: &str,
) -> Result<(), JsValue> {
    check_raw(request_json)?;
    check_raw(response_json)?;
    let request = decode_request(request_json.as_bytes()).map_err(|_| invalid())?;
    decode_response_for(response_json.as_bytes(), &request)
        .map(|_| ())
        .map_err(|_| invalid())
}
