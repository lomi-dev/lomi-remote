use lomi_remote_crypto::*;
use lomi_remote_protocol::EnrollmentProof;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

const AUDIENCE: &str = "https://authority.example/v2/remote/host-authorizations/refresh";
const SYNTHETIC: &str = "synthetic-only_REFRESH-credential";
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    committed: SignedHostKeyCommitment,
    initial_commitment: [u8; 32],
    approved_account_id: [u8; 16],
    context: HostRefreshContext,
    statement: HostRefreshStatement,
    proof: EnrollmentProof,
}
fn generated() -> (Identity, Fixture) {
    let pending = PendingHostIdentity::generate([2; 16], 1).unwrap();
    let committed = pending.signed_commitment().unwrap();
    let initial_commitment = committed.descriptor.commitment().unwrap();
    let approved_account_id = [1; 16];
    let host = pending
        .finalize(approved_account_id, &initial_commitment)
        .unwrap();
    let context = HostRefreshContext {
        host_authorization_id: [3; 16],
        rotation_id: [4; 16],
        refresh_hash: Sha256::digest(SYNTHETIC.as_bytes()).into(),
        audience: AUDIENCE.into(),
    };
    let statement = prepare_host_refresh_statement(
        &committed,
        &initial_commitment,
        approved_account_id,
        &context,
    )
    .unwrap();
    let proof = host
        .sign_host_refresh_proof(
            context.host_authorization_id,
            context.rotation_id,
            SYNTHETIC,
            AUDIENCE,
        )
        .unwrap();
    (
        host,
        Fixture {
            committed,
            initial_commitment,
            approved_account_id,
            context,
            statement,
            proof,
        },
    )
}
fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/host-refresh-v1.json")).unwrap()
}
fn verify(f: &Fixture) -> Result<()> {
    verify_host_refresh_proof(
        &f.proof,
        &f.statement,
        &f.committed,
        &f.initial_commitment,
        f.approved_account_id,
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn wire(bytes: &[u8], signature: &str) -> EnrollmentProof {
    serde_json::from_value(json!({"canonicalCbor":hex(bytes),"signature":signature})).unwrap()
}
#[test]
fn public_golden_and_fresh_keys_match_exact_canonical_statement() {
    for f in [fixture(), generated().1] {
        verify(&f).unwrap();
        assert_eq!(
            prepare_host_refresh_statement(
                &f.committed,
                &f.initial_commitment,
                f.approved_account_id,
                &f.context
            )
            .unwrap(),
            f.statement
        );
        let bytes = f.statement.canonical().unwrap();
        assert_eq!(hex(&bytes), f.proof.canonical_cbor.expose_wire());
        assert_eq!(
            HostRefreshStatement::from_canonical(&bytes).unwrap(),
            f.statement
        );
    }
}
#[test]
fn every_trusted_context_account_and_key_binding_rejects_substitution() {
    let f = fixture();
    let mut variants = vec![];
    macro_rules! change { ($($field:ident).+) => {{ let mut v=f.clone(); v.$($field).+[0] ^= 1; variants.push(v); }} }
    change!(statement.account_id);
    change!(statement.host_id);
    change!(statement.host_authorization_id);
    change!(statement.host_key_fingerprint);
    change!(statement.rotation_id);
    change!(statement.refresh_hash);
    change!(approved_account_id);
    change!(initial_commitment);
    change!(committed.signature);
    change!(committed.descriptor.identity_key);
    change!(committed.descriptor.channel_key);
    change!(committed.descriptor.mailbox_key);
    let mut v = f.clone();
    v.statement.audience.push('x');
    variants.push(v);
    let mut v = f.clone();
    v.statement.version = 2;
    variants.push(v);
    for (i, v) in variants.into_iter().enumerate() {
        assert!(verify(&v).is_err(), "substitution {i}");
    }
    for field in [
        "hostAuthorizationId",
        "rotationId",
        "refreshHash",
        "audience",
    ] {
        let mut value = serde_json::to_value(&f.context).unwrap();
        value[field] = if field == "audience" {
            json!("https://staging.example/v2/remote/host-authorizations/refresh")
        } else {
            let mut a = value[field].as_array().unwrap().clone();
            a[0] = json!(99);
            json!(a)
        };
        let context = serde_json::from_value(value).unwrap();
        let expected = prepare_host_refresh_statement(
            &f.committed,
            &f.initial_commitment,
            f.approved_account_id,
            &context,
        )
        .unwrap();
        assert!(verify_host_refresh_proof(
            &f.proof,
            &expected,
            &f.committed,
            &f.initial_commitment,
            f.approved_account_id
        )
        .is_err());
    }
}
#[test]
fn credentials_are_hashed_as_exact_wire_text_and_rotation_is_bound() {
    let (host, f) = generated();
    for text in [
        "synthetic-only_REFRESH-credentiaL",
        "U1lOVEhFVElD",
        "synthetic-only_REFRESH-credential_",
        "a",
        &"a".repeat(2048),
    ] {
        let proof = host
            .sign_host_refresh_proof([3; 16], [4; 16], text, AUDIENCE)
            .unwrap();
        let mut changed = f.clone();
        changed.proof = proof;
        assert!(verify(&changed).is_err());
        changed.context.refresh_hash = Sha256::digest(text.as_bytes()).into();
        changed.statement = prepare_host_refresh_statement(
            &changed.committed,
            &changed.initial_commitment,
            changed.approved_account_id,
            &changed.context,
        )
        .unwrap();
        verify(&changed).unwrap();
    }
    for text in ["", " space", "newline\n", "é", "a=b", &"a".repeat(2049)] {
        assert!(host
            .sign_host_refresh_proof([3; 16], [4; 16], text, AUDIENCE)
            .is_err());
    }
    let mut rotated = f.clone();
    rotated.proof = host
        .sign_host_refresh_proof([3; 16], [9; 16], SYNTHETIC, AUDIENCE)
        .unwrap();
    assert!(verify(&rotated).is_err());
}
#[test]
fn disposed_wrong_role_and_other_identity_cannot_authorize_refresh() {
    let (mut host, mut f) = generated();
    let other = generated().0;
    f.proof = other
        .sign_host_refresh_proof([3; 16], [4; 16], SYNTHETIC, AUDIENCE)
        .unwrap();
    assert!(verify(&f).is_err());
    host.dispose();
    assert!(host
        .sign_host_refresh_proof([3; 16], [4; 16], SYNTHETIC, AUDIENCE)
        .is_err());
    let consumer = Identity::generate([1; 16], [2; 16], Role::Device, 1).unwrap();
    assert!(consumer
        .sign_host_refresh_proof([3; 16], [4; 16], SYNTHETIC, AUDIENCE)
        .is_err());
}
#[test]
fn enrollment_and_refresh_domains_reject_replay_in_both_directions() {
    let (host, f) = generated();
    let challenge = EnrollmentChallenge {
        version: 1,
        enrollment_id: [7; 16],
        host_id: f.statement.host_id,
        host_key_fingerprint: f.statement.host_key_fingerprint,
        bootstrap_session_id: [8; 16],
        audience: AUDIENCE.into(),
        expires_at: 100,
        nonce: [9; 32],
        operation_id: [10; 16],
    };
    let enrollment = host.sign_enrollment_proof(&challenge).unwrap();
    let enrollment_wire = wire(&challenge.canonical().unwrap(), &hex(&enrollment.signature));
    assert!(verify_host_refresh_proof(
        &enrollment_wire,
        &f.statement,
        &f.committed,
        &f.initial_commitment,
        f.approved_account_id
    )
    .is_err());
    assert!(verify_host_enrollment_proof(
        &f.proof,
        &challenge,
        &f.committed,
        &f.initial_commitment,
        f.approved_account_id,
        1
    )
    .is_err());
    let substituted = wire(
        &f.statement.canonical().unwrap(),
        &hex(&enrollment.signature),
    );
    assert!(verify_host_refresh_proof(
        &substituted,
        &f.statement,
        &f.committed,
        &f.initial_commitment,
        f.approved_account_id
    )
    .is_err());
    let substituted = wire(
        &challenge.canonical().unwrap(),
        f.proof.signature.expose_wire(),
    );
    assert!(verify_host_enrollment_proof(
        &substituted,
        &challenge,
        &f.committed,
        &f.initial_commitment,
        f.approved_account_id,
        1
    )
    .is_err());
}
#[test]
fn strict_cbor_rejects_nonshortest_indefinite_trailing_truncated_and_lengths() {
    let f = fixture();
    let bytes = f.statement.canonical().unwrap();
    let mut wide = vec![0x98, 9];
    wide.extend_from_slice(&bytes[1..]);
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&bytes[1..]);
    indefinite.push(0xff);
    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut variants = vec![wide, indefinite, trailing, vec![0; 1025]];
    for end in 0..bytes.len() {
        variants.push(bytes[..end].to_vec());
    }
    // Domain uses a two-byte text header. Version must use the shortest form.
    let version_offset = 1 + 2 + HOST_REFRESH_PROOF_DOMAIN.len();
    let mut wide_version = bytes.clone();
    wide_version.splice(version_offset..version_offset + 1, [0x18, 1]);
    variants.push(wide_version);
    let mut wrong_domain = bytes.clone();
    wrong_domain[3] ^= 1;
    variants.push(wrong_domain);
    let uuid_offset = version_offset + 1;
    let mut short_uuid = bytes.clone();
    short_uuid[uuid_offset] = 0x4f;
    short_uuid.remove(uuid_offset + 16);
    variants.push(short_uuid);
    let mut wide_uuid = bytes.clone();
    wide_uuid.splice(uuid_offset..uuid_offset + 1, [0x58, 16]);
    variants.push(wide_uuid);
    for bytes in variants {
        assert!(HostRefreshStatement::from_canonical(&bytes).is_err());
        if !bytes.is_empty() {
            let proof = wire(&bytes, f.proof.signature.expose_wire());
            assert!(verify_host_refresh_proof(
                &proof,
                &f.statement,
                &f.committed,
                &f.initial_commitment,
                f.approved_account_id
            )
            .is_err());
        }
    }
}
#[test]
fn bounds_zero_identifiers_and_unknown_json_claims_are_rejected() {
    let f = fixture();
    let mut maximum = f.statement.clone();
    maximum.audience = "a".repeat(256);
    assert_eq!(
        HostRefreshStatement::from_canonical(&maximum.canonical().unwrap()).unwrap(),
        maximum
    );
    for audience in [
        "".into(),
        "a".repeat(257),
        "bad audience".into(),
        "é".into(),
        "\n".into(),
    ] {
        let mut value = f.statement.clone();
        value.audience = audience.clone();
        assert!(value.canonical().is_err());
        let mut context = serde_json::to_value(&f.context).unwrap();
        context["audience"] = json!(audience);
        assert!(serde_json::from_value::<HostRefreshContext>(context).is_err());
        let mut statement = serde_json::to_value(&f.statement).unwrap();
        statement["audience"] = json!(audience);
        assert!(serde_json::from_value::<HostRefreshStatement>(statement).is_err());
    }
    let mut value = serde_json::to_value(&f.statement).unwrap();
    for field in [
        "accountId",
        "hostId",
        "hostAuthorizationId",
        "hostKeyFingerprint",
        "rotationId",
        "refreshHash",
    ] {
        let saved = value[field].clone();
        value[field] = json!(vec![0; saved.as_array().unwrap().len()]);
        let statement: HostRefreshStatement = serde_json::from_value(value.clone()).unwrap();
        assert!(statement.canonical().is_err());
        value[field] = saved;
    }
    for field in [
        "accountId",
        "approvedAccountId",
        "hostId",
        "hostKeyFingerprint",
        "version",
        "role",
    ] {
        let mut value = serde_json::to_value(&f.context).unwrap();
        value[field] = json!(1);
        assert!(serde_json::from_value::<HostRefreshContext>(value).is_err());
    }
    let mut value = serde_json::to_value(&f.statement).unwrap();
    value["role"] = json!("consumer");
    assert!(serde_json::from_value::<HostRefreshStatement>(value).is_err());
    let duplicate =
        serde_json::to_string(&f.context)
            .unwrap()
            .replacen("{", "{\"audience\":\"duplicate\",", 1);
    assert!(serde_json::from_str::<HostRefreshContext>(&duplicate).is_err());
}

#[test]
fn signing_and_preparation_enforce_context_bounds_before_producing_a_proof() {
    let (host, f) = generated();
    let mut maximum = f.clone();
    maximum.context.audience = "a".repeat(256);
    maximum.statement = prepare_host_refresh_statement(
        &f.committed,
        &f.initial_commitment,
        f.approved_account_id,
        &maximum.context,
    )
    .unwrap();
    maximum.proof = host
        .sign_host_refresh_proof([3; 16], [4; 16], SYNTHETIC, &maximum.context.audience)
        .unwrap();
    verify(&maximum).unwrap();
    for audience in ["", &"a".repeat(257), "é", "space audience", "newline\n"] {
        assert!(host
            .sign_host_refresh_proof([3; 16], [4; 16], SYNTHETIC, audience)
            .is_err());
    }
    assert!(host
        .sign_host_refresh_proof([0; 16], [4; 16], SYNTHETIC, AUDIENCE)
        .is_err());
    assert!(host
        .sign_host_refresh_proof([3; 16], [0; 16], SYNTHETIC, AUDIENCE)
        .is_err());
    for field in ["hostAuthorizationId", "rotationId", "refreshHash"] {
        let mut value = serde_json::to_value(&f.context).unwrap();
        value[field] = json!(vec![0; value[field].as_array().unwrap().len()]);
        let context = serde_json::from_value(value).unwrap();
        assert!(prepare_host_refresh_statement(
            &f.committed,
            &f.initial_commitment,
            f.approved_account_id,
            &context
        )
        .is_err());
    }
    assert!(prepare_host_refresh_statement(
        &f.committed,
        &f.initial_commitment,
        [0; 16],
        &f.context
    )
    .is_err());
    let mut wrong_role = f.committed.clone();
    wrong_role.descriptor.role = Role::Device;
    assert!(prepare_host_refresh_statement(
        &wrong_role,
        &f.initial_commitment,
        f.approved_account_id,
        &f.context
    )
    .is_err());
    let mut forged = f.clone();
    forged.proof.signature = "00".repeat(64).try_into().unwrap();
    assert!(verify(&forged).is_err());
}
