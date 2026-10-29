#![cfg(not(target_arch = "wasm32"))]
use lomi_remote_crypto::*;
use lomi_remote_protocol::EnrollmentProof;
use serde_json::json;
fn carrier(bytes: &[u8], signature: &[u8]) -> EnrollmentProof {
    let hex = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
    serde_json::from_value(json!({"canonicalCbor":hex(bytes),"signature":hex(signature)})).unwrap()
}
#[test]
fn historical_bundle_bytes_and_signatures_roundtrip_without_reencoding_changes() {
    for role in [Role::Host, Role::Device] {
        let identity = Identity::generate([1; 16], [2; 16], role, u32::MAX).unwrap();
        let signed = identity.public_bundle();
        let before = signed.bundle.canonical().unwrap();
        assert_eq!(
            PublicBundle::from_canonical(&before).unwrap(),
            signed.bundle
        );
        assert_eq!(
            SignedBundle::from_wire(&signed.to_wire().unwrap()).unwrap(),
            signed
        );
        assert_eq!(signed.bundle.canonical().unwrap(), before);
        signed
            .verify(&signed.bundle.fingerprint().unwrap())
            .unwrap();
    }
    // Generic decoding retains the historical pending projection semantics.
    let pending = Identity::generate([0; 16], [2; 16], Role::Host, 1)
        .unwrap()
        .public_bundle();
    assert_eq!(
        PublicBundle::from_canonical(&pending.bundle.canonical().unwrap()).unwrap(),
        pending.bundle
    );
    assert!(
        verify_consumer_window_identity(&pending.to_wire().unwrap(), [0; 16], [2; 16]).is_err()
    );
}
#[test]
fn host_registration_requires_exact_finalized_account_bound_identity() {
    let pending = PendingHostIdentity::generate([2; 16], 3).unwrap();
    let committed = pending.signed_commitment().unwrap();
    let pin = committed.descriptor.commitment().unwrap();
    let host = pending.finalize([1; 16], &pin).unwrap();
    let signed = host.public_bundle();
    let wire = signed.to_wire().unwrap();
    assert_eq!(
        verify_registered_host_identity(&committed, &pin, [1; 16], &wire).unwrap(),
        signed
    );
    for account in [[0; 16], [9; 16]] {
        assert!(verify_registered_host_identity(&committed, &pin, account, &wire).is_err());
    }
    assert!(verify_registered_host_identity(&committed, &[9; 32], [1; 16], &wire).is_err());
    let mut altered = committed.clone();
    altered.signature[0] ^= 1;
    assert!(verify_registered_host_identity(&altered, &pin, [1; 16], &wire).is_err());
    for field in 0..8 {
        let mut replacement = signed.clone();
        match field {
            0 => replacement.bundle.account_id = [9; 16],
            1 => replacement.bundle.subject_id = [9; 16],
            2 => replacement.bundle.role = Role::Device,
            3 => replacement.bundle.key_version += 1,
            4 => replacement.bundle.identity_key[0] ^= 1,
            5 => replacement.bundle.channel_key[0] ^= 1,
            6 => replacement.bundle.mailbox_key[0] ^= 1,
            _ => replacement.signature[0] ^= 1,
        }
        let wire = carrier(
            &replacement.bundle.canonical().unwrap(),
            &replacement.signature,
        );
        assert!(
            verify_registered_host_identity(&committed, &pin, [1; 16], &wire).is_err(),
            "field {field}"
        );
    }
    let other = Identity::generate([1; 16], [2; 16], Role::Host, 3)
        .unwrap()
        .public_bundle()
        .to_wire()
        .unwrap();
    assert!(verify_registered_host_identity(&committed, &pin, [1; 16], &other).is_err());
    // Init signature is not the finalized bundle signature, even for the same key.
    assert!(verify_registered_host_identity(
        &committed,
        &pin,
        [1; 16],
        &carrier(&signed.bundle.canonical().unwrap(), &committed.signature)
    )
    .is_err());
}
#[test]
fn public_decoder_rejects_malleable_or_unbounded_encodings_and_wire_signatures() {
    let signed = Identity::generate([1; 16], [2; 16], Role::Device, 1)
        .unwrap()
        .public_bundle();
    let bytes = signed.bundle.canonical().unwrap();
    for end in 0..bytes.len() {
        assert!(PublicBundle::from_canonical(&bytes[..end]).is_err());
    }
    let mut cases = vec![
        vec![0; 257],
        vec![0x9f],
        vec![0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
    ];
    cases.push([&[0x98, 10][..], &bytes[1..]].concat());
    cases.push([bytes.as_slice(), &[0]].concat());
    let mut indefinite = bytes.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    cases.push(indefinite);
    for bad in cases {
        assert!(PublicBundle::from_canonical(&bad).is_err());
    }
    // Nonminimal version, unsupported versions, invalid roles and zero key version.
    for (field, bad) in [("version", 0), ("version", 2), ("key_version", 0)] {
        let mut b = signed.bundle.clone();
        if field == "version" {
            b.version = bad;
        } else {
            b.key_version = bad;
        }
        assert!(b.canonical().is_err());
    }
    let mut d = minicbor::Decoder::new(&bytes);
    d.array().unwrap();
    d.str().unwrap();
    d.str().unwrap();
    let p = d.position();
    assert!(
        PublicBundle::from_canonical(&[&bytes[..p], &[0x18, 1], &bytes[p + 1..]].concat()).is_err()
    );
    let original = serde_json::to_value(signed.to_wire().unwrap()).unwrap();
    for (field, bad) in [
        ("canonicalCbor", "AB".into()),
        ("canonicalCbor", "00".repeat(257)),
        ("signature", "AB".repeat(64)),
        ("signature", "00".repeat(63)),
        ("signature", "00".repeat(65)),
        ("signature", "00".repeat(64)),
    ] {
        let mut v = original.clone();
        v[field] = json!(bad);
        if let Ok(w) = serde_json::from_value::<EnrollmentProof>(v) {
            assert!(SignedBundle::from_wire(&w).is_err());
        }
    }
}
#[test]
fn consumer_identity_requires_account_window_device_and_complete_keys() {
    let signed = Identity::generate([1; 16], [2; 16], Role::Device, 1)
        .unwrap()
        .public_bundle();
    let wire = signed.to_wire().unwrap();
    verify_consumer_window_identity(&wire, [1; 16], [2; 16]).unwrap();
    for (a, w) in [
        ([0; 16], [2; 16]),
        ([9; 16], [2; 16]),
        ([1; 16], [0; 16]),
        ([1; 16], [9; 16]),
    ] {
        assert!(verify_consumer_window_identity(&wire, a, w).is_err());
    }
    let host = Identity::generate([1; 16], [2; 16], Role::Host, 1)
        .unwrap()
        .public_bundle()
        .to_wire()
        .unwrap();
    assert!(verify_consumer_window_identity(&host, [1; 16], [2; 16]).is_err());
    for key in 0..3 {
        let mut s = signed.clone();
        match key {
            0 => s.bundle.identity_key = [0; 32],
            1 => s.bundle.channel_key = [0; 32],
            _ => s.bundle.mailbox_key = [0; 32],
        };
        assert!(verify_consumer_window_identity(
            &carrier(&s.bundle.canonical().unwrap(), &s.signature),
            [1; 16],
            [2; 16]
        )
        .is_err());
    }
}
