use lomi_remote_crypto::{EnrollmentChallenge, Identity, Role, SignedEnrollmentProof};
use serde_json::json;

fn fixture() -> (Identity, EnrollmentChallenge) {
    let host = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
    let challenge = EnrollmentChallenge {
        version: 1,
        enrollment_id: [3; 16],
        host_id: [2; 16],
        host_key_fingerprint: host.public_bundle().bundle.fingerprint().unwrap(),
        bootstrap_session_id: [4; 16],
        audience: "lomi-remote-host-enrollment".into(),
        expires_at: 2_000_000_000,
        nonce: [5; 32],
        operation_id: [6; 16],
    };
    (host, challenge)
}
#[test]
fn native_roundtrip_and_seed_import_sign_identically() {
    let (host, expected) = fixture();
    let proof = host.sign_enrollment_proof(&expected).unwrap();
    let bundle = host.public_bundle();
    let pin = bundle.bundle.fingerprint().unwrap();
    proof.verify(&expected, &bundle, &pin, 100).unwrap();
    let restored =
        Identity::import_secret_seed_blob(&host.export_secret_seed_blob().unwrap(), &bundle)
            .unwrap();
    assert_eq!(restored.sign_enrollment_proof(&expected).unwrap(), proof);
    let decoded: SignedEnrollmentProof =
        serde_json::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap();
    assert_eq!(decoded, proof);
    decoded.verify(&expected, &bundle, &pin, 100).unwrap();
    let mut disposed = restored;
    disposed.dispose();
    assert!(disposed.sign_enrollment_proof(&expected).is_err());
}
#[test]
fn changing_every_bound_field_invalidates_signature_even_if_expected_changes() {
    let (host, expected) = fixture();
    let proof = host.sign_enrollment_proof(&expected).unwrap();
    let bundle = host.public_bundle();
    let pin = bundle.bundle.fingerprint().unwrap();
    let mut variants = Vec::new();
    let mut c = expected.clone();
    c.version = 2;
    variants.push(c);
    let mut c = expected.clone();
    c.enrollment_id[0] ^= 1;
    variants.push(c);
    let mut c = expected.clone();
    c.host_id[0] ^= 1;
    variants.push(c);
    let mut c = expected.clone();
    c.host_key_fingerprint[0] ^= 1;
    variants.push(c);
    let mut c = expected.clone();
    c.bootstrap_session_id[0] ^= 1;
    variants.push(c);
    let mut c = expected.clone();
    c.audience.push('x');
    variants.push(c);
    let mut c = expected.clone();
    c.expires_at += 1;
    variants.push(c);
    let mut c = expected.clone();
    c.nonce[0] ^= 1;
    variants.push(c);
    let mut c = expected.clone();
    c.operation_id[0] ^= 1;
    variants.push(c);
    for changed in variants {
        let tampered = SignedEnrollmentProof {
            challenge: changed.clone(),
            signature: proof.signature.clone(),
        };
        assert!(tampered.verify(&expected, &bundle, &pin, 100).is_err());
        assert!(tampered.verify(&changed, &bundle, &pin, 100).is_err());
    }
}
#[test]
fn rejects_wrong_pin_key_role_expiry_and_malformed_signature() {
    let (host, expected) = fixture();
    let proof = host.sign_enrollment_proof(&expected).unwrap();
    let bundle = host.public_bundle();
    let pin = bundle.bundle.fingerprint().unwrap();
    assert!(proof.verify(&expected, &bundle, &[9; 32], 100).is_err());
    assert!(proof
        .verify(&expected, &bundle, &pin, expected.expires_at)
        .is_err());
    assert!(proof
        .verify(&expected, &bundle, &pin, expected.expires_at + 1)
        .is_err());
    let other = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
    assert!(other.sign_enrollment_proof(&expected).is_err());
    assert!(proof
        .verify(&expected, &other.public_bundle(), &pin, 100)
        .is_err());
    let device = Identity::generate([1; 16], [2; 16], Role::Device, 1).unwrap();
    let mut c = expected.clone();
    c.host_key_fingerprint = device.public_bundle().bundle.fingerprint().unwrap();
    assert!(device.sign_enrollment_proof(&c).is_err());
    let mut bad = proof;
    bad.signature.pop();
    assert!(bad.verify(&expected, &bundle, &pin, 100).is_err());
}
#[test]
fn strict_json_and_canonical_expiry() {
    let (_, expected) = fixture();
    let value = serde_json::to_value(&expected).unwrap();
    assert!(value["expiresAt"].is_string());
    for bad in [
        json!(1),
        json!("01"),
        json!("+1"),
        json!("18446744073709551616"),
    ] {
        let mut v = value.clone();
        v["expiresAt"] = bad;
        assert!(serde_json::from_value::<EnrollmentChallenge>(v).is_err());
    }
    let mut extra = value.clone();
    extra["unknown"] = json!(true);
    assert!(serde_json::from_value::<EnrollmentChallenge>(extra).is_err());
    let mut invalid = expected.clone();
    invalid.nonce = [0; 32];
    assert!(invalid.canonical().is_err());
    invalid = expected;
    invalid.audience = "bad audience".into();
    assert!(invalid.canonical().is_err());
}
#[test]
fn canonical_bytes_have_independent_domain_and_stable_field_order() {
    let (_, mut challenge) = fixture();
    // Entirely public deterministic fixture: no identity seed or private key.
    challenge.host_key_fingerprint = [7; 32];
    let bytes = challenge.canonical().unwrap();
    let mut d = minicbor::Decoder::new(&bytes);
    assert_eq!(d.array().unwrap(), Some(10));
    assert_eq!(
        d.str().unwrap(),
        lomi_remote_crypto::ENROLLMENT_PROOF_DOMAIN
    );
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.bytes().unwrap(), challenge.enrollment_id);
    assert_eq!(d.bytes().unwrap(), challenge.host_id);
    assert_eq!(d.bytes().unwrap(), challenge.host_key_fingerprint);
    assert_eq!(d.bytes().unwrap(), challenge.bootstrap_session_id);
    assert_eq!(d.str().unwrap(), challenge.audience);
    assert_eq!(d.u64().unwrap(), challenge.expires_at);
    assert_eq!(d.bytes().unwrap(), challenge.nonce);
    assert_eq!(d.bytes().unwrap(), challenge.operation_id);
    assert_eq!(d.position(), bytes.len());
    assert!(!bytes
        .windows(b"lomi-remote-live-v1".len())
        .any(|b| b == b"lomi-remote-live-v1"));
}

fn replace_cbor_field(bytes: &[u8], field: usize, replacement: &[u8]) -> Vec<u8> {
    let mut d = minicbor::Decoder::new(bytes);
    d.array().unwrap();
    for _ in 0..field {
        d.skip().unwrap();
    }
    let start = d.position();
    d.skip().unwrap();
    let mut changed = bytes.to_vec();
    changed.splice(start..d.position(), replacement.iter().copied());
    changed
}
fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.bytes(bytes).unwrap();
    e.into_writer()
}

fn cbor_text(text: &str) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.str(text).unwrap();
    e.into_writer()
}
#[test]
fn canonical_decoder_preserves_signed_challenge_and_maximum_bounds() {
    let (host, expected) = fixture();
    let proof = host.sign_enrollment_proof(&expected).unwrap();
    let decoded = EnrollmentChallenge::from_canonical(&expected.canonical().unwrap()).unwrap();
    assert_eq!(decoded, expected);
    let bundle = host.public_bundle();
    let pin = bundle.bundle.fingerprint().unwrap();
    let mut decoded_proof = SignedEnrollmentProof {
        challenge: decoded,
        signature: proof.signature,
    };
    decoded_proof.verify(&expected, &bundle, &pin, 100).unwrap();
    decoded_proof.challenge.nonce[0] ^= 1;
    let changed = decoded_proof.challenge.canonical().unwrap();
    decoded_proof.challenge = EnrollmentChallenge::from_canonical(&changed).unwrap();
    assert!(decoded_proof
        .verify(&decoded_proof.challenge, &bundle, &pin, 100)
        .is_err());
    let mut maximum = expected;
    maximum.audience = "a".repeat(256);
    maximum.expires_at = u64::MAX;
    assert_eq!(
        EnrollmentChallenge::from_canonical(&maximum.canonical().unwrap()).unwrap(),
        maximum
    );
}
#[test]
fn canonical_decoder_rejects_malformed_challenges() {
    let (_, expected) = fixture();
    let bytes = expected.canonical().unwrap();
    for end in 0..bytes.len() {
        assert!(EnrollmentChallenge::from_canonical(&bytes[..end]).is_err());
    }
    let mut wrong_domain = bytes.clone();
    wrong_domain[3] ^= 1;
    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut indefinite = bytes.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    let mut wrong_array = bytes.clone();
    wrong_array[0] = 0x89;
    let mut wide_array = vec![0x98, 10];
    wide_array.extend_from_slice(&bytes[1..]);
    let mut cases = vec![
        wrong_domain,
        trailing,
        indefinite,
        wrong_array,
        wide_array,
        vec![0; 1024],
        replace_cbor_field(
            &bytes,
            0,
            &cbor_text(lomi_remote_crypto::HOST_KEY_COMMITMENT_DOMAIN),
        ),
        replace_cbor_field(&bytes, 1, &[2]),
        replace_cbor_field(&bytes, 1, &[0x18, 1]),
        replace_cbor_field(&bytes, 7, &[0]),
        replace_cbor_field(&bytes, 7, &[0x1b, 0, 0, 0, 0, 0x77, 0x35, 0x94, 0]),
        replace_cbor_field(&bytes, 7, &[0x20]),
        replace_cbor_field(&bytes, 6, &[0x7f, 0x61, b'a', 0xff]),
        replace_cbor_field(&bytes, 6, &[0x7b, 255, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for text in [
        "".into(),
        "bad audience".into(),
        "é".into(),
        "a".repeat(257),
    ] {
        cases.push(replace_cbor_field(&bytes, 6, &cbor_text(&text)));
    }
    for (field, len) in [(2, 16), (3, 16), (4, 32), (5, 16), (8, 32), (9, 16)] {
        cases.push(replace_cbor_field(
            &bytes,
            field,
            &cbor_bytes(&vec![0; len]),
        ));
        cases.push(replace_cbor_field(
            &bytes,
            field,
            &cbor_bytes(&vec![1; len - 1]),
        ));
    }
    let mut wide_audience = vec![0x79, 0, expected.audience.len() as u8];
    wide_audience.extend_from_slice(expected.audience.as_bytes());
    cases.push(replace_cbor_field(&bytes, 6, &wide_audience));
    for (i, bad) in cases.iter().enumerate() {
        assert!(
            EnrollmentChallenge::from_canonical(bad).is_err(),
            "case {i}"
        );
    }
}
