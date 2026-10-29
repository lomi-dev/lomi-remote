#![cfg(feature = "test-fixtures")]
use ed25519_dalek::{Signer, SigningKey};
use lomi_remote_crypto::*;
use serde_json::{json, Value};

fn challenge(descriptor: &AccountIndependentHostKey, account: [u8; 16]) -> EnrollmentChallenge {
    EnrollmentChallenge {
        version: 1,
        enrollment_id: [4; 16],
        host_id: descriptor.host_id,
        host_key_fingerprint: descriptor
            .account_bound_bundle(account)
            .unwrap()
            .fingerprint()
            .unwrap(),
        bootstrap_session_id: [5; 16],
        audience: "remote-enrollment".into(),
        expires_at: 1000,
        nonce: [6; 32],
        operation_id: [7; 16],
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn finalization_and_native_persistence_preserve_every_key_and_seed() {
    let pending = PendingHostIdentity::fixture(7).unwrap();
    let commitment = pending.signed_commitment().unwrap();
    let pin = commitment.descriptor.commitment().unwrap();
    commitment.verify(&pin).unwrap();
    let seeds = pending.export_secret_seed_blob().unwrap();
    assert_eq!(seeds.len(), 97);
    assert_eq!(seeds[0], 1);
    let restored = PendingHostIdentity::import_secret_seed_blob(&seeds, &commitment, &pin).unwrap();
    assert_eq!(restored.signed_commitment().unwrap(), commitment);
    assert_eq!(&*restored.export_secret_seed_blob().unwrap(), &*seeds);
    let bound = restored.finalize([1; 16], &pin).unwrap();
    let bundle = bound.public_bundle();
    assert_eq!(
        bundle.bundle,
        commitment.descriptor.account_bound_bundle([1; 16]).unwrap()
    );
    assert_eq!(
        bundle,
        Identity::fixture(Role::Host, 7).unwrap().public_bundle()
    );
    assert_eq!(
        bundle.bundle.identity_key,
        commitment.descriptor.identity_key
    );
    assert_eq!(bundle.bundle.channel_key, commitment.descriptor.channel_key);
    assert_eq!(bundle.bundle.mailbox_key, commitment.descriptor.mailbox_key);
    assert_eq!(&*bound.export_secret_seed_blob().unwrap(), &*seeds);
    let imported = Identity::import_secret_seed_blob(&seeds, &bundle).unwrap();
    assert_eq!(imported.public_bundle(), bundle);
    let other = pending.finalize([9; 16], &pin).unwrap().public_bundle();
    assert_ne!(
        other.bundle.fingerprint().unwrap(),
        bundle.bundle.fingerprint().unwrap()
    );
    assert_eq!(other.bundle.identity_key, bundle.bundle.identity_key);
    assert_eq!(other.bundle.channel_key, bundle.bundle.channel_key);
    assert_eq!(other.bundle.mailbox_key, bundle.bundle.mailbox_key);
}
#[test]
fn public_projection_verifies_final_enrollment_without_request_bundle() {
    let pending = PendingHostIdentity::fixture(7).unwrap();
    let committed = pending.signed_commitment().unwrap();
    let pin = committed.descriptor.commitment().unwrap();
    let expected = challenge(&committed.descriptor, [1; 16]);
    let bound = pending.finalize([1; 16], &pin).unwrap();
    let proof = bound.sign_enrollment_proof(&expected).unwrap();
    proof
        .verify_committed_host(&expected, &committed, &pin, [1; 16], 999)
        .unwrap();
    assert!(proof
        .verify_committed_host(&expected, &committed, &pin, [1; 16], 1000)
        .is_err());
    assert!(proof
        .verify_committed_host(&expected, &committed, &pin, [2; 16], 999)
        .is_err());
    assert!(proof
        .verify_committed_host(&expected, &committed, &pin, [0; 16], 999)
        .is_err());
    assert!(proof
        .verify_committed_host(&expected, &committed, &[9; 32], [1; 16], 999)
        .is_err());
    let mut other = expected.clone();
    other.bootstrap_session_id = [8; 16];
    assert!(proof
        .verify_committed_host(&other, &committed, &pin, [1; 16], 999)
        .is_err());
    let reused = SignedEnrollmentProof {
        challenge: expected.clone(),
        signature: committed.signature.clone(),
    };
    assert!(reused
        .verify_committed_host(&expected, &committed, &pin, [1; 16], 999)
        .is_err());
    let replacement = PendingHostIdentity::fixture(8)
        .unwrap()
        .signed_commitment()
        .unwrap();
    assert!(proof
        .verify_committed_host(&expected, &replacement, &pin, [1; 16], 999)
        .is_err());
    // Same Ed25519 key cannot replace another committed encryption key, even if
    // the attacker can create a new self-signature with that unchanged key.
    let mut replacement = committed.clone();
    replacement.descriptor.channel_key = [42; 32];
    replacement.signature = SigningKey::from_bytes(&[7; 32])
        .sign(&replacement.descriptor.canonical().unwrap())
        .to_bytes()
        .to_vec();
    assert!(proof
        .verify_committed_host(&expected, &replacement, &pin, [1; 16], 999)
        .is_err());
    assert!(proof
        .verify_committed_host(
            &expected,
            &replacement,
            &replacement.descriptor.commitment().unwrap(),
            [1; 16],
            999
        )
        .is_err());
}
#[test]
fn descriptor_mutations_and_projection_account_changes_are_bound() {
    let signed = PendingHostIdentity::fixture(7)
        .unwrap()
        .signed_commitment()
        .unwrap();
    let pin = signed.descriptor.commitment().unwrap();
    let original = serde_json::to_value(&signed.descriptor).unwrap();
    for (field, value) in original.as_object().unwrap() {
        let mut changed = original.clone();
        changed[field] = match value {
            Value::Array(a) => {
                let mut a = a.clone();
                a[0] = json!(a[0].as_u64().unwrap() ^ 1);
                Value::Array(a)
            }
            Value::Number(n) => json!(n.as_u64().unwrap() + 1),
            Value::String(_) => json!("device"),
            _ => panic!("unexpected"),
        };
        if let Ok(descriptor) = AccountIndependentHostKey::from_json(&changed.to_string()) {
            let altered = SignedHostKeyCommitment {
                descriptor,
                signature: signed.signature.clone(),
            };
            assert!(altered.verify(&pin).is_err(), "{field}");
            assert!(
                altered
                    .verify(&altered.descriptor.commitment().unwrap())
                    .is_err(),
                "self signature {field}"
            );
        }
    }
    let original_fp = signed
        .descriptor
        .account_bound_bundle([1; 16])
        .unwrap()
        .fingerprint()
        .unwrap();
    for i in 0..16 {
        let mut account = [1; 16];
        account[i] ^= 1;
        assert_ne!(
            signed
                .descriptor
                .account_bound_bundle(account)
                .unwrap()
                .fingerprint()
                .unwrap(),
            original_fp
        );
    }
}
#[test]
fn invalid_keys_json_disposal_and_seed_import_fail_closed() {
    assert!(PendingHostIdentity::generate([0; 16], 1).is_err());
    assert!(PendingHostIdentity::generate([1; 16], 0).is_err());
    let mut pending = PendingHostIdentity::fixture(7).unwrap();
    let signed = pending.signed_commitment().unwrap();
    let pin = signed.descriptor.commitment().unwrap();
    let seeds = pending.export_secret_seed_blob().unwrap();
    for seed in [vec![], vec![1; 96], vec![1; 98], vec![2; 97]] {
        assert!(PendingHostIdentity::import_secret_seed_blob(&seed, &signed, &pin).is_err());
    }
    for i in [1, 34, 65] {
        let mut changed = seeds.to_vec();
        changed[i] ^= 1;
        assert!(PendingHostIdentity::import_secret_seed_blob(&changed, &signed, &pin).is_err());
    }
    let other = PendingHostIdentity::fixture(8)
        .unwrap()
        .signed_commitment()
        .unwrap();
    assert!(PendingHostIdentity::import_secret_seed_blob(
        &seeds,
        &other,
        &other.descriptor.commitment().unwrap()
    )
    .is_err());
    for field in ["identityKey", "channelKey", "mailboxKey"] {
        let mut v = serde_json::to_value(&signed.descriptor).unwrap();
        v[field] = json!(vec![0; 32]);
        assert!(AccountIndependentHostKey::from_json(&v.to_string()).is_err());
    }
    let mut weak = signed.descriptor.clone();
    weak.identity_key = [0; 32];
    weak.identity_key[0] = 1;
    assert!(weak.canonical().is_err());
    let s = serde_json::to_string(&signed.descriptor).unwrap();
    assert!(AccountIndependentHostKey::from_json(&s.replacen("{", "{\"version\":1,", 1)).is_err());
    let mut v = serde_json::to_value(&signed).unwrap();
    v["unknown"] = json!(1);
    assert!(SignedHostKeyCommitment::from_json(&v.to_string()).is_err());
    let mut v = serde_json::to_value(&signed.descriptor).unwrap();
    v["keyVersion"] = json!(4294967296u64);
    assert!(AccountIndependentHostKey::from_json(&v.to_string()).is_err());
    assert!(AccountIndependentHostKey::from_json(&" ".repeat(MAX_JSON + 1)).is_err());
    assert!(signed.descriptor.account_bound_bundle([0; 16]).is_err());
    assert!(PendingHostIdentity::fixture(7)
        .unwrap()
        .finalize([0; 16], &pin)
        .is_err());
    assert!(PendingHostIdentity::fixture(7)
        .unwrap()
        .finalize([1; 16], &[9; 32])
        .is_err());
    pending.dispose();
    assert!(pending.signed_commitment().is_err());
    assert!(pending.export_secret_seed_blob().is_err());
    assert!(pending.finalize([1; 16], &pin).is_err());
}
#[test]
fn canonical_fixed_descriptor_signature_and_bound_projection_vectors() {
    let pending = PendingHostIdentity::fixture(7).unwrap();
    let signed = pending.signed_commitment().unwrap();
    let pin = signed.descriptor.commitment().unwrap();
    let bundle = signed.descriptor.account_bound_bundle([1; 16]).unwrap();
    let bytes = signed.descriptor.canonical().unwrap();
    assert_eq!(
        AccountIndependentHostKey::from_canonical(&bytes).unwrap(),
        signed.descriptor
    );
    let mut decoder = minicbor::Decoder::new(&bytes);
    assert_eq!(decoder.array().unwrap(), Some(8));
    for _ in 0..8 {
        decoder.skip().unwrap();
    }
    assert_eq!(decoder.position(), bytes.len());
    let actual = json!({"descriptor":signed.descriptor,"canonicalCbor":hex(&bytes),"commitment":hex(&pin),"signature":hex(&signed.signature),"approvedAccount":vec![1;16],"boundBundleCbor":hex(&bundle.canonical().unwrap()),"boundFingerprint":hex(&bundle.fingerprint().unwrap())});
    assert_eq!(
        actual,
        serde_json::from_str::<Value>(include_str!("fixtures/host-key-commitment-v1.json"))
            .unwrap()
    );
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

#[test]
fn canonical_decoder_preserves_generated_commitment_and_signature() {
    let pending = PendingHostIdentity::generate([2; 16], u32::MAX).unwrap();
    let signed = pending.signed_commitment().unwrap();
    let bytes = signed.descriptor.canonical().unwrap();
    let descriptor = AccountIndependentHostKey::from_canonical(&bytes).unwrap();
    assert_eq!(descriptor, signed.descriptor);
    let pin = descriptor.commitment().unwrap();
    let mut decoded = SignedHostKeyCommitment {
        descriptor,
        signature: signed.signature,
    };
    decoded.verify(&pin).unwrap();
    decoded.descriptor.channel_key[0] ^= 1;
    let changed = decoded.descriptor.canonical().unwrap();
    decoded.descriptor = AccountIndependentHostKey::from_canonical(&changed).unwrap();
    assert!(decoded.verify(&pin).is_err());
    assert!(decoded
        .verify(&decoded.descriptor.commitment().unwrap())
        .is_err());
}
#[test]
fn canonical_decoder_rejects_malformed_commitments() {
    let signed = PendingHostIdentity::generate([2; 16], 1)
        .unwrap()
        .signed_commitment()
        .unwrap();
    let bytes = signed.descriptor.canonical().unwrap();
    for end in 0..bytes.len() {
        assert!(AccountIndependentHostKey::from_canonical(&bytes[..end]).is_err());
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
    let mut wide_array = vec![0x98, 8];
    wide_array.extend_from_slice(&bytes[1..]);
    let mut weak_key = [0; 32];
    weak_key[0] = 1;
    let mut cases = vec![
        wrong_domain,
        trailing,
        indefinite,
        wrong_array,
        wide_array,
        vec![0; 1024],
        replace_cbor_field(&bytes, 1, &[2]),
        replace_cbor_field(&bytes, 1, &[0x18, 1]),
        replace_cbor_field(&bytes, 2, &cbor_bytes(&[0; 16])),
        replace_cbor_field(&bytes, 2, &cbor_bytes(&[2; 15])),
        replace_cbor_field(&bytes, 2, &[0x5f, 0x50, 2, 0xff]),
        replace_cbor_field(&bytes, 3, &[2]),
        replace_cbor_field(&bytes, 3, &[0x18, 1]),
        replace_cbor_field(&bytes, 4, &[0]),
        replace_cbor_field(&bytes, 4, &[0x18, 1]),
        replace_cbor_field(&bytes, 4, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        replace_cbor_field(&bytes, 5, &cbor_bytes(&weak_key)),
    ];
    for field in 5..8 {
        cases.push(replace_cbor_field(&bytes, field, &cbor_bytes(&[0; 32])));
        cases.push(replace_cbor_field(&bytes, field, &cbor_bytes(&[2; 31])));
    }
    // Non-shortest byte-string length and an impossible declared length.
    let mut wide_uuid = vec![0x58, 16];
    wide_uuid.extend_from_slice(&[2; 16]);
    cases.push(replace_cbor_field(&bytes, 2, &wide_uuid));
    cases.push(replace_cbor_field(
        &bytes,
        2,
        &[0x5b, 255, 255, 255, 255, 255, 255, 255, 255],
    ));
    for (i, bad) in cases.iter().enumerate() {
        assert!(
            AccountIndependentHostKey::from_canonical(bad).is_err(),
            "case {i}"
        );
    }
}
