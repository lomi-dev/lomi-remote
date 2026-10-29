use lomi_remote_crypto::*;
use lomi_remote_protocol::{EnrollmentInitiateParams, EnrollmentProof};
use serde_json::{json, Value};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn wire_proof(bytes: &[u8], signature: &[u8]) -> EnrollmentProof {
    serde_json::from_value(json!({"canonicalCbor":hex(bytes), "signature":hex(signature)})).unwrap()
}
fn generated() -> Value {
    let pending = PendingHostIdentity::generate([2; 16], 1).unwrap();
    let committed = pending.signed_commitment().unwrap();
    let pin = committed.descriptor.commitment().unwrap();
    let account = [1; 16];
    let expected = EnrollmentChallenge {
        version: 1,
        enrollment_id: [3; 16],
        host_id: committed.descriptor.host_id,
        host_key_fingerprint: committed
            .descriptor
            .account_bound_bundle(account)
            .unwrap()
            .fingerprint()
            .unwrap(),
        bootstrap_session_id: [4; 16],
        audience: "lomi-remote-host-enrollment".into(),
        expires_at: 2_000_000_000,
        nonce: [5; 32],
        operation_id: [6; 16],
    };
    let host = pending.finalize(account, &pin).unwrap();
    let signed = host.sign_enrollment_proof(&expected).unwrap();
    json!({
        "init": {"clientId":"lomi-remote-host", "keyCommitment":hex(&pin),
            "proof":wire_proof(&committed.descriptor.canonical().unwrap(), &committed.signature)},
        "expected":expected, "committed":committed, "initialCommitment":pin,
        "approvedAccountId":account, "now":"100", "finalProof":wire_proof(&expected.canonical().unwrap(), &signed.signature)
    })
}
#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    init: EnrollmentInitiateParams,
    expected: EnrollmentChallenge,
    committed: SignedHostKeyCommitment,
    initial_commitment: [u8; 32],
    approved_account_id: [u8; 16],
    now: String,
    final_proof: EnrollmentProof,
}
fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/enrollment-wire-v1.json")).unwrap()
}
fn verify_final(f: &Fixture) -> Result<()> {
    verify_host_enrollment_proof(
        &f.final_proof,
        &f.expected,
        &f.committed,
        &f.initial_commitment,
        f.approved_account_id,
        f.now.parse().unwrap(),
    )
}
#[test]
fn shared_wire_fixture_and_generated_keys_verify_without_fixture_feature() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/enrollment/wire.json"
    ))
    .unwrap();
    for vector in vectors {
        let decoded = serde_json::from_value::<EnrollmentInitiateParams>(vector["value"].clone());
        if vector["accepted"] == true {
            let signed = verify_host_key_initiation(&decoded.unwrap()).unwrap();
            assert_eq!(signed.descriptor.host_id, [2; 16]);
        } else {
            assert!(decoded.is_err(), "{}", vector["name"]);
        }
    }
    for f in [
        fixture(),
        serde_json::from_value::<Fixture>(generated()).unwrap(),
    ] {
        assert_eq!(verify_host_key_initiation(&f.init).unwrap(), f.committed);
        verify_final(&f).unwrap();
    }
}
#[test]
fn public_client_id_never_changes_possession_verification_or_result() {
    let f = fixture();
    let mut request = f.init.clone();
    request.client_id = "untrusted_public_client".to_owned().try_into().unwrap();
    assert_eq!(verify_host_key_initiation(&request).unwrap(), f.committed);
}
#[test]
fn initiation_rejects_tampered_signature_pin_and_each_encryption_key() {
    let f = fixture();
    let mut changed = f.init.clone();
    changed.key_commitment = "00".repeat(32).try_into().unwrap();
    assert!(verify_host_key_initiation(&changed).is_err());
    let mut signature = f.committed.signature.clone();
    signature[0] ^= 1;
    changed = f.init.clone();
    changed.proof.signature = hex(&signature).try_into().unwrap();
    assert!(verify_host_key_initiation(&changed).is_err());
    for channel in [true, false] {
        let mut descriptor = f.committed.descriptor.clone();
        if channel {
            descriptor.channel_key[0] ^= 1;
        } else {
            descriptor.mailbox_key[0] ^= 1;
        }
        changed = f.init.clone();
        changed.proof = wire_proof(&descriptor.canonical().unwrap(), &f.committed.signature);
        assert!(verify_host_key_initiation(&changed).is_err());
        // A matching replacement digest still cannot repair the old signature.
        changed.key_commitment = hex(&descriptor.commitment().unwrap()).try_into().unwrap();
        assert!(verify_host_key_initiation(&changed).is_err());
    }
}
#[test]
fn wire_verification_rejects_noncanonical_cbor_and_wrong_signature_purpose() {
    let f = fixture();
    let canonical = f.committed.descriptor.canonical().unwrap();
    let mut wide = vec![0x98, 8];
    wide.extend_from_slice(&canonical[1..]);
    let mut init = f.init.clone();
    init.proof = wire_proof(&wide, &f.committed.signature);
    assert!(verify_host_key_initiation(&init).is_err());
    init.proof = f.final_proof.clone();
    assert!(verify_host_key_initiation(&init).is_err());
    let mut changed = f.clone();
    changed.final_proof = f.init.proof.clone();
    assert!(verify_final(&changed).is_err());
    // Correct final challenge with the same key's init-domain signature.
    changed.final_proof = wire_proof(&f.expected.canonical().unwrap(), &f.committed.signature);
    assert!(verify_final(&changed).is_err());
    let canonical = f.expected.canonical().unwrap();
    let mut wide = vec![0x98, 10];
    wide.extend_from_slice(&canonical[1..]);
    changed.final_proof = f.final_proof.clone();
    changed.final_proof.canonical_cbor = hex(&wide).try_into().unwrap();
    assert!(verify_final(&changed).is_err());
    changed.final_proof = f.final_proof.clone();
    changed.final_proof.signature = "00".repeat(64).try_into().unwrap();
    assert!(verify_final(&changed).is_err());
}
#[test]
fn final_verification_requires_independent_trusted_context_and_unexpired_time() {
    let f = fixture();
    let mut variants = Vec::new();
    let mut c = f.clone();
    c.expected.enrollment_id[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.expected.host_id[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.expected.host_key_fingerprint[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.expected.bootstrap_session_id[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.expected.audience.push('x');
    variants.push(c);
    let mut c = f.clone();
    c.expected.nonce[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.expected.operation_id[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.expected.expires_at += 1;
    variants.push(c);
    let mut c = f.clone();
    c.approved_account_id = [9; 16];
    variants.push(c);
    let mut c = f.clone();
    c.approved_account_id = [0; 16];
    variants.push(c);
    let mut c = f.clone();
    c.initial_commitment[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.committed.descriptor.mailbox_key[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.committed.signature[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.now = c.expected.expires_at.to_string();
    variants.push(c);
    let mut c = f.clone();
    c.now = u64::MAX.to_string();
    variants.push(c);
    for (i, changed) in variants.iter().enumerate() {
        assert!(verify_final(changed).is_err(), "trusted context case {i}");
    }
}
#[test]
fn wire_and_crypto_bounds_reject_oversized_truncated_and_invalid_encodings() {
    let f = fixture();
    let bytes = f.expected.canonical().unwrap();
    for end in 1..bytes.len() {
        let mut changed = f.clone();
        changed.final_proof.canonical_cbor = hex(&bytes[..end]).try_into().unwrap();
        assert!(verify_final(&changed).is_err());
    }
    for cbor in [
        "00".repeat(1025),
        "00".repeat(8192),
        hex(&[bytes.as_slice(), &[0]].concat()),
    ] {
        let mut changed = f.clone();
        changed.final_proof.canonical_cbor = cbor.clone().try_into().unwrap();
        assert!(verify_final(&changed).is_err());
        changed.init.proof.canonical_cbor = cbor.try_into().unwrap();
        assert!(verify_host_key_initiation(&changed.init).is_err());
    }
    let original = serde_json::to_value(&f.init).unwrap();
    for (field, bad) in [
        ("keyCommitment", "ab".repeat(31)),
        ("keyCommitment", "AB".repeat(32)),
        ("keyCommitment", "gg".repeat(32)),
    ] {
        let mut v = original.clone();
        v[field] = json!(bad);
        assert!(serde_json::from_value::<EnrollmentInitiateParams>(v).is_err());
    }
    for (field, bad) in [
        ("signature", "ab".repeat(63)),
        ("signature", "AB".repeat(64)),
        ("signature", "ab".repeat(65)),
        ("canonicalCbor", "a".into()),
        ("canonicalCbor", "AB".into()),
        ("canonicalCbor", "".into()),
        ("canonicalCbor", "00".repeat(8193)),
    ] {
        let mut v = original.clone();
        v["proof"][field] = json!(bad);
        assert!(serde_json::from_value::<EnrollmentInitiateParams>(v).is_err());
    }
}

fn context(expected: &EnrollmentChallenge) -> HostEnrollmentChallengeContext {
    HostEnrollmentChallengeContext {
        enrollment_id: expected.enrollment_id,
        bootstrap_session_id: expected.bootstrap_session_id,
        operation_id: expected.operation_id,
        nonce: expected.nonce,
        audience: expected.audience.clone(),
        expires_at: lomi_remote_protocol::DecimalU64(expected.expires_at),
    }
}
fn prepare(f: &Fixture, context: &HostEnrollmentChallengeContext) -> Result<EnrollmentChallenge> {
    prepare_host_enrollment_challenge(
        &f.committed,
        &f.initial_commitment,
        f.approved_account_id,
        context,
    )
}
#[test]
fn preparation_derives_exact_approved_challenge_and_canonical_proof_bytes() {
    for f in [
        fixture(),
        serde_json::from_value::<Fixture>(generated()).unwrap(),
    ] {
        let context = context(&f.expected);
        let json = serde_json::to_value(&context).unwrap();
        assert_eq!(json["expiresAt"], f.expected.expires_at.to_string());
        let decoded: HostEnrollmentChallengeContext = serde_json::from_value(json).unwrap();
        let prepared = prepare(&f, &decoded).unwrap();
        assert_eq!(prepared, f.expected);
        assert_eq!(
            hex(&prepared.canonical().unwrap()),
            f.final_proof.canonical_cbor.expose_wire()
        );
        verify_host_enrollment_proof(
            &f.final_proof,
            &prepared,
            &f.committed,
            &f.initial_commitment,
            f.approved_account_id,
            f.now.parse().unwrap(),
        )
        .unwrap();
        let mut other_account = f.clone();
        other_account.approved_account_id = [9; 16];
        let rebound = prepare(&other_account, &context).unwrap();
        assert_eq!(rebound.host_id, f.committed.descriptor.host_id);
        assert_ne!(rebound.host_key_fingerprint, prepared.host_key_fingerprint);
    }
}
#[test]
fn preparation_binds_each_server_context_field_and_rejects_replaced_init_state() {
    let f = fixture();
    let original = context(&f.expected);
    let mut variants = Vec::new();
    let mut c = original.clone();
    c.enrollment_id[0] ^= 1;
    variants.push(c);
    let mut c = original.clone();
    c.bootstrap_session_id[0] ^= 1;
    variants.push(c);
    let mut c = original.clone();
    c.operation_id[0] ^= 1;
    variants.push(c);
    let mut c = original.clone();
    c.nonce[0] ^= 1;
    variants.push(c);
    let mut c = original.clone();
    c.audience.push('x');
    variants.push(c);
    let mut c = original.clone();
    c.expires_at.0 += 1;
    variants.push(c);
    for c in variants {
        let prepared = prepare(&f, &c).unwrap();
        assert_ne!(prepared, f.expected);
        assert!(verify_host_enrollment_proof(
            &f.final_proof,
            &prepared,
            &f.committed,
            &f.initial_commitment,
            f.approved_account_id,
            100,
        )
        .is_err());
    }
    let mut variants = Vec::new();
    let mut c = f.clone();
    c.initial_commitment[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.committed.signature[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.committed.descriptor.channel_key[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.committed.descriptor.mailbox_key[0] ^= 1;
    variants.push(c);
    let mut c = f.clone();
    c.approved_account_id = [0; 16];
    variants.push(c);
    for c in variants {
        assert!(prepare(&c, &original).is_err());
    }
}
#[test]
fn preparation_rejects_invalid_context_bounds_and_duplicate_host_claims() {
    let f = fixture();
    let original = context(&f.expected);
    let mut maximum = original.clone();
    maximum.audience = "a".repeat(256);
    maximum.expires_at = lomi_remote_protocol::DecimalU64(u64::MAX);
    let prepared = prepare(&f, &maximum).unwrap();
    assert_eq!(prepared.audience.len(), 256);
    assert_eq!(prepared.expires_at, u64::MAX);
    assert_eq!(
        EnrollmentChallenge::from_canonical(&prepared.canonical().unwrap()).unwrap(),
        prepared
    );
    let mut variants = Vec::new();
    let mut c = original.clone();
    c.enrollment_id = [0; 16];
    variants.push(c);
    let mut c = original.clone();
    c.bootstrap_session_id = [0; 16];
    variants.push(c);
    let mut c = original.clone();
    c.operation_id = [0; 16];
    variants.push(c);
    let mut c = original.clone();
    c.nonce = [0; 32];
    variants.push(c);
    let mut c = original.clone();
    c.expires_at.0 = 0;
    variants.push(c);
    for audience in [
        "".into(),
        "a".repeat(257),
        "a".repeat(MAX_JSON + 1),
        "bad audience".into(),
        "é".into(),
        "bad\naudience".into(),
    ] {
        let mut c = original.clone();
        c.audience = audience;
        variants.push(c);
    }
    for c in variants {
        assert!(prepare(&f, &c).is_err());
    }
    let value = serde_json::to_value(&original).unwrap();
    for audience in [
        "".into(),
        "a".repeat(257),
        "a".repeat(MAX_JSON + 1),
        "bad audience".into(),
        "é".into(),
    ] {
        let mut v = value.clone();
        v["audience"] = json!(audience);
        assert!(serde_json::from_value::<HostEnrollmentChallengeContext>(v).is_err());
    }
    for bad in [
        json!(1),
        json!("01"),
        json!("+1"),
        json!("18446744073709551616"),
    ] {
        let mut v = value.clone();
        v["expiresAt"] = bad;
        assert!(serde_json::from_value::<HostEnrollmentChallengeContext>(v).is_err());
    }
    for field in ["hostId", "hostKeyFingerprint", "accountId", "version"] {
        let mut v = value.clone();
        v[field] = json!(1);
        assert!(serde_json::from_value::<HostEnrollmentChallengeContext>(v).is_err());
    }
    let duplicate =
        serde_json::to_string(&original)
            .unwrap()
            .replacen("{", "{\"expiresAt\":\"1\",", 1);
    assert!(serde_json::from_str::<HostEnrollmentChallengeContext>(&duplicate).is_err());
}
