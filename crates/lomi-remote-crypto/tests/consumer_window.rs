#![cfg(not(target_arch = "wasm32"))]
use lomi_remote_crypto::*;
use lomi_remote_protocol::{DecimalU64, EnrollmentProof};
use serde_json::json;
fn context() -> ConsumerWindowChallengeContext {
    ConsumerWindowChallengeContext {
        consumer_authorization_id: [3; 16],
        account_session_id: "opaque_Account-SESSION42".into(),
        window_identity_id: [2; 16],
        operation_id: [4; 16],
        nonce: [5; 32],
        audience: "https://example.test/consumer/windows".into(),
        expires_at: DecimalU64(100),
    }
}
fn setup() -> (Identity, EnrollmentProof, ConsumerWindowChallenge) {
    let id = Identity::generate([1; 16], [2; 16], Role::Device, 1).unwrap();
    let wire = id.public_bundle().to_wire().unwrap();
    let challenge = prepare_consumer_window_challenge(&wire, [1; 16], &context()).unwrap();
    (id, wire, challenge)
}
fn carrier(bytes: &[u8], signature: &[u8]) -> EnrollmentProof {
    let hex = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
    serde_json::from_value(json!({"canonicalCbor":hex(bytes),"signature":hex(signature)})).unwrap()
}
#[test]
fn native_prepare_sign_verify_and_roundtrip_bind_complete_account_identity() {
    let (id, wire, c) = setup();
    let proof = id.sign_consumer_window_proof(&c).unwrap();
    assert_eq!(
        c.window_key_fingerprint,
        id.public_bundle().bundle.fingerprint().unwrap()
    );
    assert_eq!(
        ConsumerWindowChallenge::from_canonical(&c.canonical().unwrap()).unwrap(),
        c
    );
    assert_eq!(serde_json::to_value(&c).unwrap()["expiresAt"], "100");
    verify_consumer_window_proof(&proof, &c, &wire, [1; 16], 99).unwrap();
    assert!(verify_consumer_window_proof(&proof, &c, &wire, [1; 16], 100).is_err());
    assert!(verify_consumer_window_proof(&proof, &c, &wire, [1; 16], u64::MAX).is_err());
    // Fresh challenge in the same window is a distinct statement.
    let mut next = context();
    next.operation_id = [8; 16];
    next.nonce = [9; 32];
    let next = prepare_consumer_window_challenge(&wire, [1; 16], &next).unwrap();
    assert!(verify_consumer_window_proof(&proof, &next, &wire, [1; 16], 1).is_err());
    verify_consumer_window_proof(
        &id.sign_consumer_window_proof(&next).unwrap(),
        &next,
        &wire,
        [1; 16],
        1,
    )
    .unwrap();
}
#[test]
fn every_expected_claim_and_all_three_public_keys_are_bound() {
    let (id, wire, c) = setup();
    let proof = id.sign_consumer_window_proof(&c).unwrap();
    for field in 0..11 {
        let mut v = c.clone();
        match field {
            0 => v.account_id = [9; 16],
            1 => v.consumer_authorization_id = [9; 16],
            2 => v.account_session_id.push('x'),
            3 => v.window_identity_id = [9; 16],
            4 => v.window_key_fingerprint[0] ^= 1,
            5 => v.operation_id = [9; 16],
            6 => v.nonce[0] ^= 1,
            7 => v.audience.push('x'),
            8 => v.expires_at.0 += 1,
            9 => v.version = 2,
            _ => v.expires_at.0 = 1,
        };
        assert!(
            verify_consumer_window_proof(&proof, &v, &wire, [1; 16], 1).is_err(),
            "field {field}"
        );
    }
    assert!(verify_consumer_window_proof(&proof, &c, &wire, [9; 16], 1).is_err());
    let other = Identity::generate([1; 16], [2; 16], Role::Device, 1)
        .unwrap()
        .public_bundle()
        .to_wire()
        .unwrap();
    assert!(verify_consumer_window_proof(&proof, &c, &other, [1; 16], 1).is_err());
    let signed = id.public_bundle();
    for key in 0..3 {
        let mut s = signed.clone();
        match key {
            0 => s.bundle.identity_key[0] ^= 1,
            1 => s.bundle.channel_key[0] ^= 1,
            _ => s.bundle.mailbox_key[0] ^= 1,
        };
        let w = carrier(&s.bundle.canonical().unwrap(), &s.signature);
        assert!(verify_consumer_window_proof(&proof, &c, &w, [1; 16], 1).is_err());
    }
    // A self-consistent replacement bundle still cannot match the retained hash.
    let mut wrong = c.clone();
    wrong.window_key_fingerprint = [9; 32];
    assert!(id.sign_consumer_window_proof(&wrong).is_err());
    wrong = c.clone();
    wrong.account_id = [9; 16];
    assert!(id.sign_consumer_window_proof(&wrong).is_err());
    wrong = c.clone();
    wrong.window_identity_id = [9; 16];
    assert!(id.sign_consumer_window_proof(&wrong).is_err());
}
#[test]
fn signer_rejects_host_disposed_and_cross_domain_enrollment_refresh_signatures() {
    let (mut id, wire, c) = setup();
    let pending = PendingHostIdentity::generate([2; 16], 1).unwrap();
    let committed = pending.signed_commitment().unwrap();
    let pin = committed.descriptor.commitment().unwrap();
    let host = pending.finalize([1; 16], &pin).unwrap();
    assert!(host.sign_consumer_window_proof(&c).is_err());
    assert!(prepare_consumer_window_challenge(
        &host.public_bundle().to_wire().unwrap(),
        [1; 16],
        &context()
    )
    .is_err());
    let enrollment = EnrollmentChallenge {
        version: 1,
        enrollment_id: [3; 16],
        host_id: [2; 16],
        host_key_fingerprint: host.public_bundle().bundle.fingerprint().unwrap(),
        bootstrap_session_id: [4; 16],
        audience: "enroll".into(),
        expires_at: 100,
        nonce: [5; 32],
        operation_id: [6; 16],
    };
    let ep = host.sign_enrollment_proof(&enrollment).unwrap();
    let refresh = host
        .sign_host_refresh_proof([3; 16], [4; 16], "public-test-opaque-value", "refresh")
        .unwrap();
    for p in [
        carrier(&enrollment.canonical().unwrap(), &ep.signature),
        refresh,
        host.public_bundle().to_wire().unwrap(),
    ] {
        assert!(verify_consumer_window_proof(&p, &c, &wire, [1; 16], 1).is_err());
    }
    // Same identity key's public-bundle signature cannot sign a window challenge.
    assert!(verify_consumer_window_proof(
        &carrier(&c.canonical().unwrap(), &id.public_bundle().signature),
        &c,
        &wire,
        [1; 16],
        1
    )
    .is_err());
    let proof = id.sign_consumer_window_proof(&c).unwrap();
    assert!(
        verify_host_enrollment_proof(&proof, &enrollment, &committed, &pin, [1; 16], 1,).is_err()
    );
    let refresh_statement = prepare_host_refresh_statement(
        &committed,
        &pin,
        [1; 16],
        &HostRefreshContext {
            host_authorization_id: [3; 16],
            rotation_id: [4; 16],
            refresh_hash: [5; 32],
            audience: "refresh".into(),
        },
    )
    .unwrap();
    assert!(
        verify_host_refresh_proof(&proof, &refresh_statement, &committed, &pin, [1; 16],).is_err()
    );
    let mut bad = proof.clone();
    bad.signature = "00".repeat(64).try_into().unwrap();
    assert!(verify_consumer_window_proof(&bad, &c, &wire, [1; 16], 1).is_err());
    id.dispose();
    assert!(id.sign_consumer_window_proof(&c).is_err());
}
#[test]
fn canonical_decoder_rejects_truncated_nonminimal_indefinite_trailing_and_oversized() {
    let (_, _, c) = setup();
    let b = c.canonical().unwrap();
    for end in 0..b.len() {
        assert!(ConsumerWindowChallenge::from_canonical(&b[..end]).is_err());
    }
    for bad in [
        vec![0; 1025],
        [&[0x98, 11][..], &b[1..]].concat(),
        [b.as_slice(), &[0]].concat(),
        [&[0x9f][..], &b[1..], &[0xff]].concat(),
        vec![0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
    ] {
        assert!(ConsumerWindowChallenge::from_canonical(&bad).is_err());
    }
    let mut d = minicbor::Decoder::new(&b);
    d.array().unwrap();
    d.str().unwrap();
    let p = d.position();
    assert!(
        ConsumerWindowChallenge::from_canonical(&[&b[..p], &[0x18, 1], &b[p + 1..]].concat())
            .is_err()
    );
    let mut huge = b[..p + 1 + 17 + 17].to_vec();
    huge.extend_from_slice(&[0x7b, 255, 255, 255, 255, 255, 255, 255, 255]);
    assert!(ConsumerWindowChallenge::from_canonical(&huge).is_err());
}
#[test]
fn zero_values_json_unknown_fields_and_text_bounds_are_rejected() {
    let (_, wire, c) = setup();
    for field in 0..8 {
        let mut v = c.clone();
        match field {
            0 => v.account_id = [0; 16],
            1 => v.consumer_authorization_id = [0; 16],
            2 => v.window_identity_id = [0; 16],
            3 => v.operation_id = [0; 16],
            4 => v.nonce = [0; 32],
            5 => v.window_key_fingerprint = [0; 32],
            6 => v.expires_at.0 = 0,
            _ => v.version = 0,
        };
        assert!(v.canonical().is_err());
    }
    let mut max = context();
    max.account_session_id = "a".repeat(128);
    max.audience = "a".repeat(256);
    max.expires_at = DecimalU64(u64::MAX);
    let max = prepare_consumer_window_challenge(&wire, [1; 16], &max).unwrap();
    assert_eq!(
        ConsumerWindowChallenge::from_canonical(&max.canonical().unwrap()).unwrap(),
        max
    );
    for (field, bads) in [
        (
            "accountSessionId",
            vec![
                "".into(),
                "a".repeat(129),
                "é".into(),
                "has space".into(),
                "a/b".into(),
                "a\n".into(),
            ],
        ),
        (
            "audience",
            vec![
                "".into(),
                "a".repeat(257),
                "é".into(),
                "has space".into(),
                "a\n".into(),
            ],
        ),
    ] {
        for bad in bads {
            let mut v = serde_json::to_value(context()).unwrap();
            v[field] = json!(bad);
            assert!(serde_json::from_value::<ConsumerWindowChallengeContext>(v).is_err());
            let mut v = serde_json::to_value(&c).unwrap();
            v[field] = json!(bad);
            assert!(serde_json::from_value::<ConsumerWindowChallenge>(v).is_err());
            let mut cx = context();
            if field == "audience" {
                cx.audience = bad;
            } else {
                cx.account_session_id = bad;
            }
            assert!(prepare_consumer_window_challenge(&wire, [1; 16], &cx).is_err());
        }
    }
    for field in ["accountId", "windowKeyFingerprint", "version", "unknown"] {
        let mut v = serde_json::to_value(context()).unwrap();
        v[field] = json!(1);
        assert!(serde_json::from_value::<ConsumerWindowChallengeContext>(v).is_err());
    }
    let mut v = serde_json::to_value(&c).unwrap();
    v["unknown"] = json!(true);
    assert!(serde_json::from_value::<ConsumerWindowChallenge>(v).is_err());
    for bad in [
        json!(1),
        json!("01"),
        json!("+1"),
        json!("18446744073709551616"),
    ] {
        let mut v = serde_json::to_value(context()).unwrap();
        v["expiresAt"] = bad;
        assert!(serde_json::from_value::<ConsumerWindowChallengeContext>(v).is_err());
    }
    let duplicate = serde_json::to_string(&c)
        .unwrap()
        .replacen("{", "{\"expiresAt\":\"1\",", 1);
    assert!(serde_json::from_str::<ConsumerWindowChallenge>(&duplicate).is_err());
}
