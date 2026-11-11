//! Domain-separated refresh possession proof. Storage must enforce rotation,
//! recovery, idle expiry and current account/host epochs atomically. A captured
//! signed request can be replayed within the server's recovery window; this is
//! not DPoP and does not prove fresh key possession on replay.
//! Self-retirement reuses the strict refresh CBOR and WASM verifier, with a
//! narrow audience derived internally from trusted origin, path host, epoch and
//! immutable 300-second intent times.
use crate::{identity::verify_signature, Identity, Result, Role, SignedHostKeyCommitment};
use ed25519_dalek::Signer;
use lomi_remote_protocol::EnrollmentProof;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HOST_REFRESH_PROOF_DOMAIN: &str = "lomi-remote-host-refresh-proof-v1";
const HOST_SELF_RETIREMENT_CONTEXT: &[u8] =
    b"lomi-host-self-retirement-context-v1\0POST /v2/remote/hosts/{hostId}/retire\0";
const HOST_SELF_RETIREMENT_AUDIENCE: &str = "lomi-host-self-retirement-v1:";

/// Hash the exact bounded refresh wire credential without normalization.
pub fn host_refresh_credential_hash(refresh_credential: &str) -> Result<[u8; 32]> {
    if refresh_credential.is_empty()
        || refresh_credential.len() > 2048
        || !refresh_credential
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("invalid host refresh credential".into());
    }
    Ok(Sha256::digest(refresh_credential.as_bytes()).into())
}

/// Compute the purpose-separated audience for one exact host retirement.
/// `origin` is the independently trusted canonical HTTPS origin, and the route
/// template is deliberately literal: `{hostId}` is not UUID-substituted here.
pub fn host_self_retirement_audience(
    origin: &str,
    host_id: [u8; 16],
    expected_host_access_epoch: u64,
    prepared_at: u64,
    expires_at: u64,
) -> Result<String> {
    let context = host_self_retirement_context(
        origin,
        host_id,
        expected_host_access_epoch,
        prepared_at,
        expires_at,
    )?;
    let digest: [u8; 32] = Sha256::digest(context).into();
    let mut value = String::with_capacity(HOST_SELF_RETIREMENT_AUDIENCE.len() + 64);
    value.push_str(HOST_SELF_RETIREMENT_AUDIENCE);
    for byte in digest {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").expect("writing into String cannot fail");
    }
    Ok(value)
}

fn host_self_retirement_context(
    origin: &str,
    host_id: [u8; 16],
    expected_host_access_epoch: u64,
    prepared_at: u64,
    expires_at: u64,
) -> Result<Vec<u8>> {
    validate_canonical_origin(origin)?;
    if host_id == [0; 16]
        || expected_host_access_epoch == 0
        || expected_host_access_epoch > i64::MAX as u64
        || prepared_at == 0
        || expires_at == 0
        || prepared_at.checked_add(300) != Some(expires_at)
    {
        return Err("invalid self-retirement context".into());
    }
    let origin = origin.as_bytes();
    let origin_len: u32 = origin
        .len()
        .try_into()
        .map_err(|_| "self-retirement origin too long")?;
    let mut context =
        Vec::with_capacity(HOST_SELF_RETIREMENT_CONTEXT.len() + 4 + origin.len() + 40);
    context.extend_from_slice(HOST_SELF_RETIREMENT_CONTEXT);
    context.extend_from_slice(&origin_len.to_be_bytes());
    context.extend_from_slice(origin);
    context.extend_from_slice(&host_id);
    context.extend_from_slice(&expected_host_access_epoch.to_be_bytes());
    context.extend_from_slice(&prepared_at.to_be_bytes());
    context.extend_from_slice(&expires_at.to_be_bytes());
    Ok(context)
}

// Match Config's deliberately narrow canonical HTTPS DNS/IPv4 origin syntax.
fn validate_canonical_origin(origin: &str) -> Result<()> {
    let authority = origin
        .strip_prefix("https://")
        .ok_or("invalid self-retirement origin")?;
    let (hostname, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if origin.len() > 180
        || hostname.len() > 253
        || hostname.is_empty()
        || hostname.starts_with('.')
        || hostname.ends_with('.')
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || port.is_some_and(|port| {
            port.is_empty()
                || port.starts_with('0')
                || port == "443"
                || port.parse::<u16>().is_err()
                || !port.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("invalid self-retirement origin".into());
    }
    let last = hostname
        .rsplit('.')
        .next()
        .ok_or("invalid self-retirement origin")?;
    let numeric_ending = last.bytes().all(|byte| byte.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .or_else(|| last.strip_prefix("0X"))
            .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if numeric_ending
        && !hostname
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.to_string() == hostname)
    {
        return Err("invalid self-retirement origin".into());
    }
    Ok(())
}

pub(crate) fn validate_audience(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("invalid refresh audience".into());
    }
    Ok(())
}
fn bounded_audience<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<String, D::Error> {
    struct Audience;
    impl serde::de::Visitor<'_> for Audience {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded ASCII refresh audience")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<String, E> {
            validate_audience(value).map_err(E::custom)?;
            Ok(value.to_owned())
        }
    }
    d.deserialize_str(Audience)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRefreshStatement {
    pub version: u8,
    pub account_id: [u8; 16],
    pub host_id: [u8; 16],
    pub host_authorization_id: [u8; 16],
    pub host_key_fingerprint: [u8; 32],
    pub rotation_id: [u8; 16],
    pub refresh_hash: [u8; 32],
    #[serde(deserialize_with = "bounded_audience")]
    pub audience: String,
}
impl HostRefreshStatement {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        validate_audience(&self.audience)?;
        if self.version != 1
            || [
                self.account_id,
                self.host_id,
                self.host_authorization_id,
                self.rotation_id,
            ]
            .contains(&[0; 16])
            || [self.host_key_fingerprint, self.refresh_hash].contains(&[0; 32])
        {
            return Err("invalid host refresh statement".into());
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(9).unwrap();
        e.str(HOST_REFRESH_PROOF_DOMAIN).unwrap();
        e.u8(self.version).unwrap();
        e.bytes(&self.account_id).unwrap();
        e.bytes(&self.host_id).unwrap();
        e.bytes(&self.host_authorization_id).unwrap();
        e.bytes(&self.host_key_fingerprint).unwrap();
        e.bytes(&self.rotation_id).unwrap();
        e.bytes(&self.refresh_hash).unwrap();
        e.str(&self.audience).unwrap();
        Ok(e.into_writer())
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        const MAX_CBOR: usize =
            1 + 2 + HOST_REFRESH_PROOF_DOMAIN.len() + 1 + 4 * 17 + 2 * 34 + 3 + 256;
        let invalid = "invalid canonical host refresh statement";
        if bytes.len() > MAX_CBOR {
            return Err(invalid.into());
        }
        let mut d = minicbor::Decoder::new(bytes);
        if d.array().map_err(|_| invalid)? != Some(9)
            || d.str().map_err(|_| invalid)? != HOST_REFRESH_PROOF_DOMAIN
        {
            return Err(invalid.into());
        }
        let version = d.u8().map_err(|_| invalid)?;
        let account_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let host_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let host_authorization_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let host_key_fingerprint = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let rotation_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let refresh_hash = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let audience = d.str().map_err(|_| invalid)?;
        validate_audience(audience)?;
        let value = Self {
            version,
            account_id,
            host_id,
            host_authorization_id,
            host_key_fingerprint,
            rotation_id,
            refresh_hash,
            audience: audience.to_owned(),
        };
        if d.position() != bytes.len() || value.canonical()? != bytes {
            return Err(invalid.into());
        }
        Ok(value)
    }
}

/// Independently stored authority context. Audience configuration must be the
/// canonical HTTPS origin plus exact refresh path, without query or fragment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRefreshContext {
    pub host_authorization_id: [u8; 16],
    pub rotation_id: [u8; 16],
    pub refresh_hash: [u8; 32],
    #[serde(deserialize_with = "bounded_audience")]
    pub audience: String,
}
pub fn prepare_host_refresh_statement(
    committed: &SignedHostKeyCommitment,
    initial_commitment: &[u8; 32],
    approved_account_id: [u8; 16],
    context: &HostRefreshContext,
) -> Result<HostRefreshStatement> {
    validate_audience(&context.audience)?;
    committed.verify(initial_commitment)?;
    let host = committed
        .descriptor
        .account_bound_bundle(approved_account_id)?;
    let statement = HostRefreshStatement {
        version: 1,
        account_id: approved_account_id,
        host_id: host.subject_id,
        host_authorization_id: context.host_authorization_id,
        host_key_fingerprint: host.fingerprint()?,
        rotation_id: context.rotation_id,
        refresh_hash: context.refresh_hash,
        audience: context.audience.clone(),
    };
    statement.canonical()?;
    Ok(statement)
}

/// Prepare an ordinary refresh statement carrying the internally derived
/// self-retirement audience. The caller cannot choose an arbitrary audience.
pub fn prepare_host_self_retirement_statement(
    committed: &SignedHostKeyCommitment,
    initial_commitment: &[u8; 32],
    approved_account_id: [u8; 16],
    path_host_id: [u8; 16],
    host_authorization_id: [u8; 16],
    operation_id: [u8; 16],
    refresh_credential: &str,
    origin: &str,
    expected_host_access_epoch: u64,
    prepared_at: u64,
    expires_at: u64,
) -> Result<HostRefreshStatement> {
    if path_host_id != committed.descriptor.host_id {
        return Err("self-retirement path host mismatch".into());
    }
    let refresh_hash = host_refresh_credential_hash(refresh_credential)?;
    let audience = host_self_retirement_audience(
        origin,
        path_host_id,
        expected_host_access_epoch,
        prepared_at,
        expires_at,
    )?;
    prepare_host_refresh_statement(
        committed,
        initial_commitment,
        approved_account_id,
        &HostRefreshContext {
            host_authorization_id,
            rotation_id: operation_id,
            refresh_hash,
            audience,
        },
    )
}

/// Verify a retirement proof from trusted path, origin and authority fields.
/// The expected audience is always computed here from that context.
#[allow(clippy::too_many_arguments)]
pub fn verify_host_self_retirement_proof(
    proof: &EnrollmentProof,
    committed: &SignedHostKeyCommitment,
    initial_commitment: &[u8; 32],
    approved_account_id: [u8; 16],
    path_host_id: [u8; 16],
    host_authorization_id: [u8; 16],
    operation_id: [u8; 16],
    refresh_credential: &str,
    origin: &str,
    expected_host_access_epoch: u64,
    prepared_at: u64,
    expires_at: u64,
) -> Result<()> {
    let expected = prepare_host_self_retirement_statement(
        committed,
        initial_commitment,
        approved_account_id,
        path_host_id,
        host_authorization_id,
        operation_id,
        refresh_credential,
        origin,
        expected_host_access_epoch,
        prepared_at,
        expires_at,
    )?;
    verify_host_refresh_proof(
        proof,
        &expected,
        committed,
        initial_commitment,
        approved_account_id,
    )
}

/// The shared HTTP carrier contains domain-specific canonical bytes; its name
/// does not permit enrollment signatures to authorize refresh.
pub fn verify_host_refresh_proof(
    proof: &EnrollmentProof,
    expected: &HostRefreshStatement,
    committed: &SignedHostKeyCommitment,
    initial_commitment: &[u8; 32],
    approved_account_id: [u8; 16],
) -> Result<()> {
    validate_audience(&expected.audience)?;
    let trusted = prepare_host_refresh_statement(
        committed,
        initial_commitment,
        approved_account_id,
        &HostRefreshContext {
            host_authorization_id: expected.host_authorization_id,
            rotation_id: expected.rotation_id,
            refresh_hash: expected.refresh_hash,
            audience: expected.audience.clone(),
        },
    )?;
    let bytes = crate::enrollment_wire::hex_bytes(proof.canonical_cbor.expose_wire(), 1024)?;
    if *expected != trusted || HostRefreshStatement::from_canonical(&bytes)? != trusted {
        return Err("refresh trusted context mismatch".into());
    }
    verify_signature(
        &committed.descriptor.identity_key,
        &bytes,
        &crate::enrollment_wire::signature(proof)?,
    )
}

impl Identity {
    /// Sign a one-family self-retirement proof with a purpose audience derived
    /// from the trusted origin and immutable request context.
    pub fn sign_host_self_retirement_proof(
        &self,
        host_authorization_id: [u8; 16],
        operation_id: [u8; 16],
        refresh_credential: &str,
        origin: &str,
        expected_host_access_epoch: u64,
        prepared_at: u64,
        expires_at: u64,
    ) -> Result<EnrollmentProof> {
        let audience = host_self_retirement_audience(
            origin,
            self.signed.bundle.subject_id,
            expected_host_access_epoch,
            prepared_at,
            expires_at,
        )?;
        self.sign_host_refresh_proof(
            host_authorization_id,
            operation_id,
            refresh_credential,
            &audience,
        )
    }

    /// Hash the exact bounded ASCII wire credential, with no normalization or
    /// decoding, and sign using the retained seed without exporting it.
    pub fn sign_host_refresh_proof(
        &self,
        host_authorization_id: [u8; 16],
        rotation_id: [u8; 16],
        refresh_credential: &str,
        audience: &str,
    ) -> Result<EnrollmentProof> {
        validate_audience(audience)?;
        if self.disposed
            || self.signed.bundle.role != Role::Host
            || self.signed.bundle.account_id == [0; 16]
            || refresh_credential.is_empty()
            || refresh_credential.len() > 2048
            || !refresh_credential
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("invalid host refresh signer or credential".into());
        }
        self.signed.verify(&self.signed.bundle.fingerprint()?)?;
        let statement = HostRefreshStatement {
            version: 1,
            account_id: self.signed.bundle.account_id,
            host_id: self.signed.bundle.subject_id,
            host_authorization_id,
            host_key_fingerprint: self.signed.bundle.fingerprint()?,
            rotation_id,
            refresh_hash: Sha256::digest(refresh_credential.as_bytes()).into(),
            audience: audience.to_owned(),
        };
        let canonical = statement.canonical()?;
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        Ok(EnrollmentProof {
            canonical_cbor: hex(&canonical)
                .try_into()
                .map_err(|_| "invalid refresh CBOR")?,
            signature: hex(&self.signing.sign(&canonical).to_bytes())
                .try_into()
                .map_err(|_| "invalid refresh signature")?,
        })
    }
}

#[cfg(test)]
mod self_retirement_tests {
    use super::*;
    use crate::{PendingHostIdentity, PublicBundle};
    use serde::Serialize;

    const ORIGIN: &str = "https://auth.lomi.dev";
    const HOST: &str = "11111111-1111-4111-8111-111111111111";
    const ACCOUNT: &str = "22222222-2222-4222-8222-222222222222";
    const FAMILY: &str = "33333333-3333-4333-8333-333333333333";
    const OPERATION: &str = "44444444-4444-4444-8444-444444444444";
    const ENROLLMENT: &str = "66666666-6666-4666-8666-666666666666";
    const ENROLLMENT_OPERATION: &str = "77777777-7777-4777-8777-777777777777";
    const PREPARED_AT: u64 = 1_700_000_000;
    const EXPIRES_AT: u64 = 1_700_000_300;
    const REFRESH: &str = "synthetic_retirement_refresh_credential_01";

    fn uuid(value: &str) -> [u8; 16] {
        let mut bytes = [0; 16];
        let mut output = 0;
        let mut high = None;
        for byte in value.bytes().filter(|byte| *byte != b'-') {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("fixture UUID is not lowercase hex"),
            };
            if let Some(upper) = high.take() {
                bytes[output] = upper << 4 | digit;
                output += 1;
            } else {
                high = Some(digit);
            }
        }
        assert_eq!(output, 16);
        bytes
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    struct Fixture {
        commitment: SignedHostKeyCommitment,
        initial_commitment: [u8; 32],
        identity: Identity,
        proof: EnrollmentProof,
        ordinary_proof: EnrollmentProof,
    }

    fn fixture() -> Fixture {
        fixture_at(PREPARED_AT, EXPIRES_AT, 2)
    }

    fn fixture_at(prepared_at: u64, expires_at: u64, expected_epoch: u64) -> Fixture {
        let host_id = uuid(HOST);
        let account_id = uuid(ACCOUNT);
        let family_id = uuid(FAMILY);
        let operation_id = uuid(OPERATION);
        let pending = PendingHostIdentity::generate(host_id, 1).unwrap();
        let commitment = pending.signed_commitment().unwrap();
        let initial_commitment = commitment.descriptor.commitment().unwrap();
        let identity = pending.finalize(account_id, &initial_commitment).unwrap();
        let proof = identity
            .sign_host_self_retirement_proof(
                family_id,
                operation_id,
                REFRESH,
                ORIGIN,
                expected_epoch,
                prepared_at,
                expires_at,
            )
            .unwrap();
        let ordinary_proof = identity
            .sign_host_refresh_proof(
                family_id,
                operation_id,
                REFRESH,
                &format!("{ORIGIN}/v2/remote/host-authorizations/refresh"),
            )
            .unwrap();
        Fixture {
            commitment,
            initial_commitment,
            identity,
            proof,
            ordinary_proof,
        }
    }

    #[test]
    fn audience_matches_shared_golden_context() {
        let host_id = uuid(HOST);
        let context =
            host_self_retirement_context(ORIGIN, host_id, 2, PREPARED_AT, EXPIRES_AT).unwrap();
        assert_eq!(
            hex(&context),
            "6c6f6d692d686f73742d73656c662d7265746972656d656e742d636f6e746578742d763100504f5354202f76322f72656d6f74652f686f7374732f7b686f737449647d2f726574697265000000001568747470733a2f2f617574682e6c6f6d692e646576111111111111411181111111111111110000000000000002000000006553f100000000006553f22c"
        );
        assert_eq!(
            host_self_retirement_audience(ORIGIN, host_id, 2, PREPARED_AT, EXPIRES_AT).unwrap(),
            "lomi-host-self-retirement-v1:cd0fde1a62e2466e13f034d37744e51cd1ca65783f107fce1b34a1c5f13fe541"
        );
    }

    #[test]
    fn context_inputs_are_range_checked_and_single_field_tampering_changes_authority() {
        let host_id = uuid(HOST);
        let expected =
            host_self_retirement_audience(ORIGIN, host_id, 2, PREPARED_AT, EXPIRES_AT).unwrap();
        for audience in [
            host_self_retirement_audience(
                "https://other.lomi.dev",
                host_id,
                2,
                PREPARED_AT,
                EXPIRES_AT,
            ),
            host_self_retirement_audience(
                ORIGIN,
                uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                2,
                PREPARED_AT,
                EXPIRES_AT,
            ),
            host_self_retirement_audience(ORIGIN, host_id, 3, PREPARED_AT, EXPIRES_AT),
            host_self_retirement_audience(ORIGIN, host_id, 2, PREPARED_AT + 1, EXPIRES_AT + 1),
        ] {
            assert_ne!(audience.unwrap(), expected);
        }
        assert!(
            host_self_retirement_audience(ORIGIN, host_id, 0, PREPARED_AT, EXPIRES_AT).is_err()
        );
        assert!(host_self_retirement_audience(
            ORIGIN,
            host_id,
            i64::MAX as u64 + 1,
            PREPARED_AT,
            EXPIRES_AT
        )
        .is_err());
        assert!(host_self_retirement_audience(ORIGIN, host_id, 2, 0, 300).is_err());
        assert!(host_self_retirement_audience(ORIGIN, host_id, 2, u64::MAX - 299, 1).is_err());
        assert!(
            host_self_retirement_audience(ORIGIN, host_id, 2, PREPARED_AT, EXPIRES_AT + 1).is_err()
        );
        for origin in [
            "http://auth.lomi.dev",
            "https://auth.lomi.dev/",
            "https://AUTH.lomi.dev",
            "https://auth.lomi.dev:443",
        ] {
            assert!(
                host_self_retirement_audience(origin, host_id, 2, PREPARED_AT, EXPIRES_AT).is_err()
            );
        }
        assert!(host_refresh_credential_hash("").is_err());
        assert!(host_refresh_credential_hash(&"x".repeat(2049)).is_err());
        assert!(host_refresh_credential_hash("refresh/token").is_err());
    }

    #[test]
    fn actual_retirement_proof_is_family_bound_and_cross_purpose_proofs_fail() {
        let fixture = fixture();
        let host_id = uuid(HOST);
        let account_id = uuid(ACCOUNT);
        let family_id = uuid(FAMILY);
        let operation_id = uuid(OPERATION);
        let verify = |proof: &EnrollmentProof,
                      commitment: &SignedHostKeyCommitment,
                      pin: &[u8; 32],
                      account: [u8; 16],
                      path_host: [u8; 16],
                      family: [u8; 16],
                      operation: [u8; 16],
                      refresh: &str,
                      origin: &str,
                      epoch: u64,
                      prepared: u64,
                      expires: u64| {
            verify_host_self_retirement_proof(
                proof, commitment, pin, account, path_host, family, operation, refresh, origin,
                epoch, prepared, expires,
            )
        };
        verify(
            &fixture.proof,
            &fixture.commitment,
            &fixture.initial_commitment,
            account_id,
            host_id,
            family_id,
            operation_id,
            REFRESH,
            ORIGIN,
            2,
            PREPARED_AT,
            EXPIRES_AT,
        )
        .unwrap();

        for (account, host, family, operation, refresh, origin, epoch, prepared, expires) in [
            (
                uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                host_id,
                family_id,
                operation_id,
                REFRESH,
                ORIGIN,
                2,
                PREPARED_AT,
                EXPIRES_AT,
            ),
            (
                account_id,
                uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                family_id,
                operation_id,
                REFRESH,
                ORIGIN,
                2,
                PREPARED_AT,
                EXPIRES_AT,
            ),
            (
                account_id,
                host_id,
                uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                operation_id,
                REFRESH,
                ORIGIN,
                2,
                PREPARED_AT,
                EXPIRES_AT,
            ),
            (
                account_id,
                host_id,
                family_id,
                uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                REFRESH,
                ORIGIN,
                2,
                PREPARED_AT,
                EXPIRES_AT,
            ),
            (
                account_id,
                host_id,
                family_id,
                operation_id,
                "different_refresh",
                ORIGIN,
                2,
                PREPARED_AT,
                EXPIRES_AT,
            ),
            (
                account_id,
                host_id,
                family_id,
                operation_id,
                REFRESH,
                "https://other.lomi.dev",
                2,
                PREPARED_AT,
                EXPIRES_AT,
            ),
            (
                account_id,
                host_id,
                family_id,
                operation_id,
                REFRESH,
                ORIGIN,
                3,
                PREPARED_AT,
                EXPIRES_AT,
            ),
            (
                account_id,
                host_id,
                family_id,
                operation_id,
                REFRESH,
                ORIGIN,
                2,
                PREPARED_AT + 1,
                EXPIRES_AT,
            ),
            (
                account_id,
                host_id,
                family_id,
                operation_id,
                REFRESH,
                ORIGIN,
                2,
                PREPARED_AT,
                EXPIRES_AT + 1,
            ),
        ] {
            assert!(verify(
                &fixture.proof,
                &fixture.commitment,
                &fixture.initial_commitment,
                account,
                host,
                family,
                operation,
                refresh,
                origin,
                epoch,
                prepared,
                expires,
            )
            .is_err());
        }

        let ordinary_audience = format!("{ORIGIN}/v2/remote/host-authorizations/refresh");
        let ordinary_expected = prepare_host_refresh_statement(
            &fixture.commitment,
            &fixture.initial_commitment,
            account_id,
            &HostRefreshContext {
                host_authorization_id: family_id,
                rotation_id: operation_id,
                refresh_hash: host_refresh_credential_hash(REFRESH).unwrap(),
                audience: ordinary_audience,
            },
        )
        .unwrap();
        assert!(verify_host_refresh_proof(
            &fixture.proof,
            &ordinary_expected,
            &fixture.commitment,
            &fixture.initial_commitment,
            account_id,
        )
        .is_err());
        assert!(verify(
            &fixture.ordinary_proof,
            &fixture.commitment,
            &fixture.initial_commitment,
            account_id,
            host_id,
            family_id,
            operation_id,
            REFRESH,
            ORIGIN,
            2,
            PREPARED_AT,
            EXPIRES_AT,
        )
        .is_err());
        let mut wrong_pin = fixture.initial_commitment;
        wrong_pin[0] ^= 1;
        assert!(verify(
            &fixture.proof,
            &fixture.commitment,
            &wrong_pin,
            account_id,
            host_id,
            family_id,
            operation_id,
            REFRESH,
            ORIGIN,
            2,
            PREPARED_AT,
            EXPIRES_AT,
        )
        .is_err());
        let mut wrong_commitment = fixture.commitment.clone();
        wrong_commitment.descriptor.identity_key[0] ^= 1;
        assert!(verify(
            &fixture.proof,
            &wrong_commitment,
            &fixture.initial_commitment,
            account_id,
            host_id,
            family_id,
            operation_id,
            REFRESH,
            ORIGIN,
            2,
            PREPARED_AT,
            EXPIRES_AT,
        )
        .is_err());
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PrivateVector<'a> {
        origin: &'static str,
        #[serde(rename = "hostUUID")]
        host_uuid: &'static str,
        #[serde(rename = "accountUUID")]
        account_uuid: &'static str,
        account_bytes: [u8; 16],
        #[serde(rename = "familyUUID")]
        family_uuid: &'static str,
        #[serde(rename = "operationUUID")]
        operation_uuid: &'static str,
        #[serde(rename = "enrollmentUUID")]
        enrollment_uuid: &'static str,
        #[serde(rename = "enrollmentOperationUUID")]
        enrollment_operation_uuid: &'static str,
        expected_host_access_epoch: String,
        initial_host_epoch: String,
        family_host_access_epoch: String,
        prepared_at: String,
        expires_at: String,
        refresh: &'static str,
        refresh_hash: String,
        host_key_fingerprint: String,
        initial_commitment: String,
        context_hex: String,
        audience: String,
        stored_commitment: &'a SignedHostKeyCommitment,
        finalized_host_identity: &'a EnrollmentProof,
        proof: &'a EnrollmentProof,
        ordinary_refresh_audience: String,
        ordinary_refresh_proof: &'a EnrollmentProof,
    }

    #[test]
    #[ignore = "writes a public synthetic proof vector to a caller-selected private path"]
    fn emit_synthetic_vector() {
        let prepared_at = std::env::var("LOMI_SELF_RETIREMENT_VECTOR_NOW")
            .ok()
            .map(|value| value.parse::<u64>().expect("valid decimal Unix seconds"))
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock is after Unix epoch")
                    .as_secs()
            });
        let expires_at = prepared_at
            .checked_add(300)
            .expect("deadline does not overflow");
        let expected_epoch = 1;
        let fixture = fixture_at(prepared_at, expires_at, expected_epoch);
        let signed = fixture.identity.public_bundle();
        let finalized_host_identity = signed.to_wire().unwrap();
        crate::verify_registered_host_identity(
            &fixture.commitment,
            &fixture.initial_commitment,
            uuid(ACCOUNT),
            &finalized_host_identity,
        )
        .unwrap();
        let bundle: PublicBundle = signed.bundle;
        let vector = PrivateVector {
            origin: ORIGIN,
            host_uuid: HOST,
            account_uuid: ACCOUNT,
            account_bytes: uuid(ACCOUNT),
            family_uuid: FAMILY,
            operation_uuid: OPERATION,
            enrollment_uuid: ENROLLMENT,
            enrollment_operation_uuid: ENROLLMENT_OPERATION,
            expected_host_access_epoch: expected_epoch.to_string(),
            initial_host_epoch: "1".to_owned(),
            family_host_access_epoch: "1".to_owned(),
            prepared_at: prepared_at.to_string(),
            expires_at: expires_at.to_string(),
            refresh: REFRESH,
            refresh_hash: hex(&host_refresh_credential_hash(REFRESH).unwrap()),
            host_key_fingerprint: hex(&bundle.fingerprint().unwrap()),
            initial_commitment: hex(&fixture.initial_commitment),
            context_hex: hex(&host_self_retirement_context(
                ORIGIN,
                uuid(HOST),
                expected_epoch,
                prepared_at,
                expires_at,
            )
            .unwrap()),
            audience: host_self_retirement_audience(
                ORIGIN,
                uuid(HOST),
                expected_epoch,
                prepared_at,
                expires_at,
            )
            .unwrap(),
            stored_commitment: &fixture.commitment,
            finalized_host_identity: &finalized_host_identity,
            proof: &fixture.proof,
            ordinary_refresh_audience: format!("{ORIGIN}/v2/remote/host-authorizations/refresh"),
            ordinary_refresh_proof: &fixture.ordinary_proof,
        };
        let path = std::env::var_os("LOMI_SELF_RETIREMENT_VECTOR_PATH")
            .expect("set LOMI_SELF_RETIREMENT_VECTOR_PATH to the private vector destination");
        std::fs::write(path, serde_json::to_vec_pretty(&vector).unwrap()).unwrap();
    }
}
