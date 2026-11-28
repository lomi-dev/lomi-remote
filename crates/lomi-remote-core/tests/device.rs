//! `device.*` bridge operations: create, re-derive, registration signature.

use ed25519_dalek::{Signature, VerifyingKey};
use lomi_remote_core::bridge;
use lomi_remote_crypto::{SignedBundle, device_registration_message};
use serde_json::{Value, json};

const ACC: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const DEV: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

fn call(op: &str, args: Value, payload: &[u8]) -> Result<Vec<u8>, Value> {
    let out = bridge::call(0, op, &serde_json::to_vec(&args).unwrap(), payload);
    match out[0] {
        0 => Ok(out[1..].to_vec()),
        _ => Err(serde_json::from_slice(&out[1..]).unwrap()),
    }
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    lomi_remote_core::tunnel::unhex(s).unwrap()
}

/// `(info json, seed blob)` from the record list of `device.create`.
fn create(random: &str) -> (Value, Vec<u8>) {
    let data = call(
        "device.create",
        json!({"accountId": ACC, "deviceId": DEV, "random": random}),
        &[],
    )
    .unwrap();
    assert_eq!(data[0], 1);
    let n = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
    let info = serde_json::from_slice(&data[5..5 + n]).unwrap();
    assert_eq!(data[5 + n], 2);
    assert_eq!(&data[6 + n..10 + n], 97u32.to_be_bytes());
    let seeds = data[10 + n..].to_vec();
    assert_eq!(seeds.len(), 97);
    (info, seeds)
}

#[test]
fn create_then_rederive_the_same_bundle_and_sign_the_registration() {
    let random = "5a".repeat(100); // more than needed: the first 96 bytes count
    let (info, seeds) = create(&random);
    assert_eq!(seeds[0], 1);
    assert_eq!(seeds[1..], [0x5a; 96]);

    let again = call(
        "device.bundle",
        json!({"accountId": ACC, "deviceId": DEV}),
        &seeds,
    )
    .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&again).unwrap(), info);

    let bundle: SignedBundle = serde_json::from_value(info["bundle"].clone()).unwrap();
    let fp = bundle.bundle.fingerprint().unwrap();
    assert_eq!(info["fingerprint"], lomi_remote_core::tunnel::hex(&fp));
    assert_eq!(bundle.bundle.account_id, unhex::<16>(ACC));
    assert_eq!(bundle.bundle.subject_id, unhex::<16>(DEV));
    bundle.verify(&fp).unwrap();

    // The check auth-app makes: Ed25519 over the CBOR registration message.
    let challenge = [9u8; 32];
    let sig = call(
        "device.signRegistration",
        json!({"accountId": ACC, "deviceId": DEV, "challenge": "09".repeat(32)}),
        &seeds,
    )
    .unwrap();
    let sig: Value = serde_json::from_slice(&sig).unwrap();
    let sig = Signature::from_bytes(&unhex::<64>(sig["signature"].as_str().unwrap()));
    VerifyingKey::from_bytes(&bundle.bundle.identity_key)
        .unwrap()
        .verify_strict(
            &device_registration_message(&challenge, &unhex(ACC), &fp),
            &sig,
        )
        .unwrap();
}

#[test]
fn different_random_gives_a_different_identity() {
    let (a, _) = create(&"01".repeat(96));
    let (b, _) = create(&"02".repeat(96));
    assert_ne!(a["fingerprint"], b["fingerprint"]);
}

#[test]
fn bad_input_is_rejected() {
    let args = |random: &str| json!({"accountId": ACC, "deviceId": DEV, "random": random});
    for bad in ["".to_owned(), "00".repeat(95), "zz".repeat(96)] {
        assert_eq!(
            call("device.create", args(&bad), &[]).unwrap_err()["code"],
            "badArgs"
        );
    }
    let ids = json!({"accountId": ACC, "deviceId": DEV});
    assert_eq!(
        call("device.bundle", ids.clone(), &[1; 96]).unwrap_err()["code"],
        "badIdentity"
    );
    let (_, seeds) = create(&"03".repeat(96));
    assert_eq!(
        call("device.signRegistration", ids, &seeds).unwrap_err()["code"],
        "badArgs"
    );
}
