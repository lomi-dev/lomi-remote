//! `directory.decodeMessage`: the Host's postcard directory stream message as JSON.

use lomi_remote_core::bridge;
use lomi_remote_protocol::{
    WorkspaceId,
    tunnel::{DirectoryChange, DirectoryMessage, DirectoryUpdate},
};
use serde_json::{Value, json};

const WS: &str = "11111111-1111-4111-8111-111111111111";

fn decode(payload: &[u8]) -> (u8, Value) {
    let out = bridge::call(0, "directory.decodeMessage", b"{}", payload);
    (out[0], serde_json::from_slice(&out[1..]).unwrap())
}

#[test]
fn decodes_a_change_and_refuses_garbage() {
    let message = DirectoryMessage::Change(DirectoryUpdate {
        seq: 3,
        change: DirectoryChange::Removed(WorkspaceId::try_from(WS.to_string()).unwrap()),
    });
    let (status, value) = decode(&message.encode().unwrap());
    assert_eq!(status, 0);
    assert_eq!(
        value,
        json!({"change": {"seq": 3, "change": {"removed": WS}}})
    );
    let (status, error) = decode(&[0xff, 0xff, 0xff]);
    assert_eq!(status, 1);
    assert_eq!(error["code"], "malformed");
}
