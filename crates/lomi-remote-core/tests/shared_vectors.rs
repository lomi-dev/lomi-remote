//! The shared vectors through the C ABI (`lomi_core_call`), the same entry the iOS and Android
//! libraries expose. The WASM package runs the same files (`packages/remote-core-wasm/test`).
//! `scripts/test-remote-core-targets.sh` also runs this binary on the iOS simulator and an
//! Android emulator.

use lomi_remote_core::ffi::{lomi_core_bytes_free, lomi_core_call, lomi_core_free};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Mutex;

/// The handle registry is process-global and capped, so tests that use it run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

const RELAY: &str = include_str!("../test-vectors/relay-frames.v1.json");
const SCENARIOS: &str = include_str!("../test-vectors/core-scenarios.v1.json");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `Ok(data)` or `Err(error json)`.
fn bridge(handle: u32, op: &str, args: &Value, payload: &[u8]) -> Result<Vec<u8>, Value> {
    let op = CString::new(op).unwrap();
    let args = if args.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(args).unwrap()
    };
    let mut len = 0usize;
    // SAFETY: pointers and lengths come from live slices; the result is freed once.
    let out = unsafe {
        let p = lomi_core_call(
            handle,
            op.as_ptr(),
            args.as_ptr(),
            args.len(),
            payload.as_ptr(),
            payload.len(),
            &mut len,
        );
        assert!(!p.is_null(), "bridge returned null");
        let v = std::slice::from_raw_parts(p, len).to_vec();
        lomi_core_bytes_free(p, len);
        v
    };
    match out[0] {
        0 => Ok(out[1..].to_vec()),
        1 => Err(serde_json::from_slice(&out[1..]).unwrap()),
        s => panic!("status {s}"),
    }
}

fn relay_vector(name: &str) -> Vec<u8> {
    let d: Value = serde_json::from_str(RELAY).unwrap();
    hex(d["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("no vector {name}"))["hex"]
        .as_str()
        .unwrap())
}

#[test]
fn relay_vectors() {
    let d: Value = serde_json::from_str(RELAY).unwrap();
    let args = |v: &Value| json!({ "fromRelay": v["direction"] == "relay" });
    for v in d["valid"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let bytes = hex(v["hex"].as_str().unwrap());
        let a = args(v);
        let frame = bridge(0, "frame.decode", &a, &bytes).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&frame).unwrap(),
            v["frame"],
            "{name}"
        );
        let canon = bridge(0, "frame.canonical", &a, &bytes).unwrap();
        if v["canonical"] == true {
            assert_eq!(canon, bytes, "{name}: canonical");
        }
        // Whatever the input form, the canonical form decodes to the same frame and is stable.
        assert_eq!(
            bridge(0, "frame.canonical", &a, &canon).unwrap(),
            canon,
            "{name}: stable"
        );
        let again = bridge(0, "frame.decode", &a, &canon).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&again).unwrap(),
            v["frame"],
            "{name}"
        );
    }
    for v in d["invalid"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let want = match v["error"].as_str().unwrap() {
            "EMPTY_FRAME" | "FRAME_TOO_LARGE" | "UNKNOWN_TYPE" | "WRONG_DIRECTION" => "framing",
            "BAD_UTF8" | "BAD_JSON" => "encoding",
            _ => "shape",
        };
        let e = bridge(
            0,
            "frame.decode",
            &args(v),
            &hex(v["hex"].as_str().unwrap()),
        )
        .unwrap_err();
        assert_eq!(e["code"], want, "{name}");
    }
}

fn payload(spec: Option<&str>, last_seal: &[u8]) -> Vec<u8> {
    let Some(s) = spec else { return Vec::new() };
    if let Some(h) = s.strip_prefix("hex:") {
        let (h, tail) = h
            .strip_suffix("@last")
            .map_or((h, &[][..]), |h| (h, last_seal));
        [hex(h), tail.to_vec()].concat()
    } else if let Some(t) = s.strip_prefix("utf8:") {
        t.as_bytes().to_vec()
    } else if let Some(n) = s.strip_prefix("vector:") {
        relay_vector(n)
    } else {
        panic!("payload {s}")
    }
}

fn records(data: &[u8]) -> Vec<Value> {
    let (mut i, mut out) = (0, Vec::new());
    while i < data.len() {
        let len = u32::from_be_bytes(data[i + 1..i + 5].try_into().unwrap()) as usize;
        let body = &data[i + 5..i + 5 + len];
        out.push(match data[i] {
            1 => json!({"t": "connect"}),
            2 => {
                let f = bridge(0, "frame.decode", &json!({"fromRelay": false}), body).unwrap();
                json!({"t": "send", "frame": serde_json::from_slice::<Value>(&f).unwrap()})
            }
            3 => json!({"t": "close"}),
            4 => json!({"t": "event", "event": serde_json::from_slice::<Value>(body).unwrap()}),
            t => panic!("record tag {t}"),
        });
        i += 5 + len;
    }
    out
}

#[test]
fn scenarios() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let d: Value = serde_json::from_str(SCENARIOS).unwrap();
    for sc in d["scenarios"].as_array().unwrap() {
        let name = sc["name"].as_str().unwrap();
        let mut handles = BTreeMap::new();
        let mut last_seal = Vec::new();
        for (n, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("{name} step {n} ({})", step["op"]);
            let on = step["on"].as_str().map_or(0, |h| handles[h]);
            let got = bridge(
                on,
                step["op"].as_str().unwrap(),
                &step["args"],
                &payload(step["payload"].as_str(), &last_seal),
            );
            let want = &step["expect"];
            if let Some(e) = want.get("error") {
                assert_eq!(got.as_ref().unwrap_err(), e, "{at}");
                continue;
            }
            let data = got.unwrap_or_else(|e| panic!("{at}: unexpected error {e}"));
            if let Some(h) = step["as"].as_str() {
                let v: Value = serde_json::from_slice(&data).unwrap();
                handles.insert(h.to_owned(), v["handle"].as_u64().unwrap() as u32);
            }
            if step["op"] == "directory.seal" {
                last_seal = data.clone();
            }
            if let Some(j) = want.get("json") {
                assert_eq!(&serde_json::from_slice::<Value>(&data).unwrap(), j, "{at}");
            } else if let Some(r) = want.get("records") {
                assert_eq!(&Value::Array(records(&data)), r, "{at}");
            } else if let Some(h) = want.get("hex") {
                assert_eq!(&Value::String(to_hex(&data)), h, "{at}");
            }
        }
        for h in handles.values() {
            lomi_core_free(*h);
            lomi_core_free(*h); // idempotent
        }
    }
}

#[test]
fn version_and_handle_limit() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        bridge(0, "version", &Value::Null, &[]).unwrap(),
        lomi_remote_core::version().as_bytes()
    );
    let a = json!({"accountId": "a", "deviceId": "d"});
    let hs: Vec<u32> = (0..64)
        .map(|_| {
            let v = bridge(0, "directory.new", &a, &[]).unwrap();
            serde_json::from_slice::<Value>(&v).unwrap()["handle"]
                .as_u64()
                .unwrap() as u32
        })
        .collect();
    assert_eq!(
        bridge(0, "directory.new", &a, &[]).unwrap_err()["code"],
        "handleLimit"
    );
    hs.into_iter().for_each(|h| lomi_core_free(h));
    bridge(0, "directory.new", &a, &[]).unwrap();
}

#[test]
fn c_abi_refuses_null_inputs() {
    let op = CString::new("version").unwrap();
    let mut len = 0usize;
    // SAFETY: every call below passes a null that the function must refuse, never dereference.
    unsafe {
        let call = |op: *const std::ffi::c_char, a: *const u8, n: usize, out: *mut usize| {
            lomi_core_call(0, op, a, n, std::ptr::null(), 0, out)
        };
        assert!(call(std::ptr::null(), std::ptr::null(), 0, &mut len).is_null());
        assert!(call(op.as_ptr(), std::ptr::null(), 0, std::ptr::null_mut()).is_null());
        assert!(call(op.as_ptr(), std::ptr::null(), 4, &mut len).is_null());
        let p = call(op.as_ptr(), std::ptr::null(), 0, &mut len);
        assert!(!p.is_null());
        lomi_core_bytes_free(p, len);
    }
}
