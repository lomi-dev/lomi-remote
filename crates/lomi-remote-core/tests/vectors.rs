//! Every shared vector (auth-app `relay-frames.v1.json`) through the Rust codec.

use lomi_remote_core::frame::*;
use serde_json::{Value, json};

const VECTORS: &str = include_str!("../test-vectors/relay-frames.v1.json");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn dir(v: &Value) -> Direction {
    match v["direction"].as_str().unwrap() {
        "client" => Direction::Client,
        "relay" => Direction::Relay,
        d => panic!("direction {d}"),
    }
}

fn role(r: Role) -> &'static str {
    if r == Role::Host { "host" } else { "device" }
}

/// The vectors' `frame` shape (the TypeScript `Frame` type).
fn to_value(f: &Frame) -> Value {
    match f {
        Frame::Auth {
            role: r,
            token,
            contract_hash,
            claim,
        } => {
            let mut v =
                json!({"type":"AUTH","role":role(*r),"token":token,"contractHash":contract_hash});
            if let Some(c) = claim {
                v["claim"] = json!({"hostId":c.host_id,"runtimeId":c.runtime_id,"expectedGeneration":c.expected_generation});
            }
            v
        }
        Frame::ReadyOk {
            role: r,
            expires_at,
            state,
        } => json!({"type":"READY","ok":true,"role":role(*r),"expiresAt":expires_at,"state":state}),
        Frame::ReadyErr { code, older } => {
            let code = match code {
                ReadyErrorCode::AuthFailed => "AUTH_FAILED",
                ReadyErrorCode::UpdateRequired => "UPDATE_REQUIRED",
                ReadyErrorCode::Unavailable => "UNAVAILABLE",
                ReadyErrorCode::Busy => "BUSY",
                ReadyErrorCode::HostBusy => "HOST_BUSY",
                ReadyErrorCode::StaleEpoch => "STALE_EPOCH",
            };
            let mut e = json!({ "code": code });
            if let Some(o) = older {
                e["older"] = json!(match o {
                    Older::Host => "host",
                    Older::Client => "client",
                    Older::Unknown => "unknown",
                });
            }
            json!({"type":"READY","ok":false,"error":e})
        }
        Frame::Event { name, data } => json!({"type":"EVENT","name":name,"data":data}),
        Frame::Call {
            call_id,
            name,
            args,
        } => json!({"type":"CALL","callId":call_id,"name":name,"args":args}),
        Frame::ReplyOk { call_id, data } => {
            json!({"type":"REPLY","callId":call_id,"ok":true,"data":data})
        }
        Frame::ReplyErr { call_id, code } => {
            json!({"type":"REPLY","callId":call_id,"ok":false,"error":{"code":code}})
        }
    }
}

#[test]
fn limits_and_types_match() {
    let d: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(d["limits"]["maxFrameBytes"], MAX_FRAME_BYTES);
    assert_eq!(d["limits"]["maxAuthFrameBytes"], MAX_AUTH_FRAME_BYTES);
    assert_eq!(d["limits"]["maxJsonDepth"], 8);
    assert_eq!(d["limits"]["callIdMax"], u32::MAX);
    let t = &d["types"];
    assert_eq!(
        [
            t["AUTH"].as_u64(),
            t["READY"].as_u64(),
            t["EVENT"].as_u64(),
            t["CALL"].as_u64(),
            t["REPLY"].as_u64()
        ],
        [TYPE_AUTH, TYPE_READY, TYPE_EVENT, TYPE_CALL, TYPE_REPLY].map(|n| Some(u64::from(n)))
    );
}

#[test]
fn valid_vectors_decode_and_canonical_ones_reencode() {
    let d: Value = serde_json::from_str(VECTORS).unwrap();
    let valid = d["valid"].as_array().unwrap();
    assert!(valid.len() >= 26);
    for v in valid {
        let name = v["name"].as_str().unwrap();
        let bytes = hex(v["hex"].as_str().unwrap());
        let frame = decode_frame(&bytes, dir(v), MAX_FRAME_BYTES)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(to_value(&frame), v["frame"], "{name}: decoded frame");
        if v["canonical"] == true {
            assert_eq!(
                encode_frame(&frame, MAX_FRAME_BYTES).unwrap(),
                bytes,
                "{name}: canonical re-encode"
            );
        } else {
            // Non-canonical input must still round-trip to a frame that decodes to the same value.
            let again = decode_frame(
                &encode_frame(&frame, MAX_FRAME_BYTES).unwrap(),
                dir(v),
                MAX_FRAME_BYTES,
            )
            .unwrap();
            assert_eq!(again, frame, "{name}: re-encode is stable");
        }
    }
}

fn class(e: FrameError) -> &'static str {
    match e {
        FrameError::EmptyFrame
        | FrameError::FrameTooLarge
        | FrameError::UnknownType
        | FrameError::WrongDirection => "framing",
        FrameError::BadUtf8 | FrameError::BadJson => "encoding",
        FrameError::BadShape => "shape",
    }
}

#[test]
fn invalid_vectors_are_rejected() {
    let d: Value = serde_json::from_str(VECTORS).unwrap();
    let invalid = d["invalid"].as_array().unwrap();
    assert!(invalid.len() >= 55);
    for v in invalid {
        let name = v["name"].as_str().unwrap();
        let err = decode_frame(&hex(v["hex"].as_str().unwrap()), dir(v), MAX_FRAME_BYTES)
            .expect_err(name);
        // Coarse class only; the TypeScript names are informative.
        let want = match v["error"].as_str().unwrap() {
            "EMPTY_FRAME" | "FRAME_TOO_LARGE" | "UNKNOWN_TYPE" | "WRONG_DIRECTION" => "framing",
            "BAD_UTF8" | "BAD_JSON" => "encoding",
            "BAD_SHAPE" => "shape",
            e => panic!("{e}"),
        };
        assert_eq!(class(err), want, "{name}: {err:?}");
    }
}

#[test]
fn encode_refuses_what_a_peer_would_reject() {
    let big = Frame::Event {
        name: "presence".into(),
        data: [("x".to_owned(), json!("a".repeat(70_000)))]
            .into_iter()
            .collect(),
    };
    assert_eq!(
        encode_frame(&big, MAX_FRAME_BYTES),
        Err(FrameError::FrameTooLarge)
    );
    let bad = Frame::Call {
        call_id: 1,
        name: "Bad".into(),
        args: Default::default(),
    };
    assert_eq!(
        encode_frame(&bad, MAX_FRAME_BYTES),
        Err(FrameError::BadShape)
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The vendored copy must equal the hash in PROVENANCE.md, and the auth-app original when
/// that checkout exists (`AUTH_APP_DIR`, default `../auth-app` of the repo root's parent).
#[test]
fn vendored_vectors_match_provenance_and_auth_app() {
    let prov = include_str!("../test-vectors/PROVENANCE.md");
    let want = prov
        .split("SHA-256: `")
        .nth(1)
        .and_then(|r| r.split('`').next())
        .expect("hash in PROVENANCE.md");
    assert_eq!(
        sha256_hex(VECTORS.as_bytes()),
        want,
        "vectors differ from PROVENANCE.md"
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = std::env::var_os("AUTH_APP_DIR").map_or_else(|| root.join("../auth-app"), Into::into);
    match std::fs::read(dir.join("test-vectors/relay-frames.v1.json")) {
        Ok(orig) => assert_eq!(
            orig,
            VECTORS.as_bytes(),
            "vectors differ from the auth-app original"
        ),
        Err(_) => eprintln!("auth-app checkout not found; compared with the recorded hash only"),
    }
}
