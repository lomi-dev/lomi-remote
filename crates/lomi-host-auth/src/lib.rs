//! Durable host credentials, independent of network, CLI, IPC and SQLite.
//!
//! The caller exclusively owns and selects the SecretStorage provider. Every
//! outbound enrollment/rotation request is available only after its intent is
//! durable. A CommitUncertain error seals this instance: drop it and explicitly
//! reopen the provider to inspect the published state before doing more work.
//! Every `now` is trusted Unix seconds projected onto a nondecreasing timeline,
//! including the required open/restart anchor. The caller must maintain that
//! projection across reopen (for example using wall time plus an Instant anchor),
//! never pass raw Instant units or independently sampled adjustable wall clocks.
//! The library rejects backward observations in one manager and persists its
//! latest observation on existing state writes. Read-only observations are not
//! persisted: cross-restart monotonicity remains the caller's clock contract.
//! Access expiry is conservatively measured from the original durable request
//! preparation, never from a retry response's arrival; server expiry remains
//! authoritative. This does not implement the caller's future clock engine.
//!
//! Request DTOs contain transport secrets: callers must protect their lifetime,
//! serialization and TLS transport. This crate never performs network requests.
use lomi_platform::secrets::{self, MAX_BUNDLE_BYTES, SecretBundle, SecretStorage, StorageState};
use lomi_remote_crypto::{
    EnrollmentChallenge, Identity, PendingHostIdentity, SignedBundle, SignedHostKeyCommitment,
    verify_host_enrollment_proof,
};
use lomi_remote_protocol::{ipc::IpcProfileId, *};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    io::{self, Write},
};
use zeroize::Zeroizing;

mod channel;
pub mod peer_policy;
pub use channel::{
    HostChannelAdmissionV3, HostChannelV3, HostResponderHandshakeV3, PublicHostIdentity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Storage(secrets::Error),
    InvalidConfig,
    InvalidState,
    InvalidBundle,
    InvalidResponse,
    Expired,
    Sealed,
    ClockRollback,
    PollTooEarly,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Storage(_) => "HOST_AUTH_STORAGE",
            Self::InvalidConfig => "HOST_AUTH_CONFIG",
            Self::InvalidState => "HOST_AUTH_STATE",
            Self::InvalidBundle => "HOST_AUTH_BUNDLE",
            Self::InvalidResponse => "HOST_AUTH_RESPONSE",
            Self::Expired => "HOST_AUTH_EXPIRED",
            Self::Sealed => "HOST_AUTH_SEALED",
            Self::ClockRollback => "HOST_AUTH_CLOCK_ROLLBACK",
            Self::PollTooEarly => "HOST_AUTH_POLL_TOO_EARLY",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn crypto<T>(value: lomi_remote_crypto::Result<T>) -> Result<T> {
    value.map_err(|_| Error::InvalidBundle)
}

/// Trusted setup configuration. Origin is canonical HTTPS, with no trailing
/// slash, user information, path, query or fragment. Audiences cannot be supplied
/// by a response or request header.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    host: HostId,
    profile: IpcProfileId,
    origin: String,
    client: String,
}
impl Config {
    pub fn new(
        host: HostId,
        profile: IpcProfileId,
        origin: String,
        client: PublicClientId,
    ) -> Result<Self> {
        let value = Self {
            host,
            profile,
            origin,
            client: client.into(),
        };
        value.validate()?;
        Ok(value)
    }
    /// Recheck configurations decoded from storage before deriving network URLs.
    pub fn validate(&self) -> Result<()> {
        let authority = self
            .origin
            .strip_prefix("https://")
            .ok_or(Error::InvalidConfig)?;
        // Deliberately narrow canonical DNS/IPv4 authority syntax; no URL parser
        // dependency or ambiguous normalization at this trust boundary.
        let (hostname, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        if self.origin.len() > 180
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
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            || port.is_some_and(|p| {
                p.is_empty()
                    || p.starts_with('0')
                    || p == "443"
                    || p.parse::<u16>().is_err()
                    || !p.bytes().all(|b| b.is_ascii_digit())
            })
            || !valid_wire_text(&self.client, 128)
        {
            return Err(Error::InvalidConfig);
        }
        let last = hostname.rsplit('.').next().ok_or(Error::InvalidConfig)?;
        let numeric_ending = last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .or_else(|| last.strip_prefix("0X"))
                .is_some_and(|suffix| suffix.bytes().all(|b| b.is_ascii_hexdigit()));
        if numeric_ending
            && !hostname
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|address| address.to_string() == hostname)
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn public_client_id(&self) -> &str {
        &self.client
    }
    pub fn exchange_audience(&self) -> String {
        format!("{}/v2/remote/host-authorizations/exchange", self.origin)
    }
    pub fn refresh_audience(&self) -> String {
        format!("{}/v2/remote/host-authorizations/refresh", self.origin)
    }
}
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Config([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Empty,
    PendingInit,
    AwaitingApproval,
    Approved,
    ExchangePrepared,
    Unconfirmed,
    Ready,
    Rotating,
    Revoked,
    Sealed,
}

/// Durable retirement acknowledgement retained for the owner's handoff.
/// The no-family case intentionally has no family ID or epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainedRevocationAcknowledgement {
    Host(HostRevokeResult),
    NoFamily {
        host_id: HostId,
        account_id: AccountId,
        enrollment_id: EnrollmentId,
        operation_id: OperationId,
    },
}

/// Explicit public login presentation. Strings retain redacted Debug output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentPresentation {
    pub user_code: UserCode,
    pub expires_at: u64,
    pub poll_interval_seconds: u64,
    pub next_poll_at: u64,
}

/// Local conservative deadlines, retained across retries and restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialDeadlines {
    pub access_expires_at: u64,
    /// Suggested refresh time: 60 seconds before the original access deadline.
    pub refresh_at: u64,
    /// Exclusive deadline of the durable rotation request, when present.
    pub rotation_expires_at: Option<u64>,
}

// All owned secret strings/bytes, including serde's temporary owned inputs,
// immediately enter zeroizing storage. No secret-bearing type derives Debug.
#[derive(Clone, PartialEq, Eq)]
struct Text(Zeroizing<String>);
impl Text {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl Serialize for Text {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}
#[derive(Clone)]
struct Seed(Zeroizing<Vec<u8>>);
impl Serialize for Seed {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.as_slice().serialize(s)
    }
}
impl<'de> Deserialize<'de> for Seed {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct SeedVisitor;
        impl<'de> serde::de::Visitor<'de> for SeedVisitor {
            type Value = Seed;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a versioned 97-byte identity seed")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Seed, A::Error> {
                // Even a malformed/truncated field keeps its partial seed in a
                // zeroizing allocation; ignore untrusted allocation size hints.
                let mut bytes = Zeroizing::new(Vec::with_capacity(97));
                while let Some(byte) = seq.next_element::<u8>()? {
                    if bytes.len() == 97 {
                        return Err(serde::de::Error::custom("seed limit"));
                    }
                    bytes.push(byte);
                }
                if bytes.len() != 97 {
                    return Err(serde::de::Error::custom("seed length"));
                }
                Ok(Seed(bytes))
            }
        }
        d.deserialize_seq(SeedVisitor)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    id: EnrollmentId,
    device: Text,
    user: Text,
    expires: u64,
    interval: u64,
    // Missing only in v1. Validation requires this field in every v2 enrollment;
    // no default may erase a missing uncertain-state intent or timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_poll_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_reserved: Option<bool>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    account: AccountId,
    challenge: EnrollmentChallenge,
    bootstrap: Text,
    signed: SignedBundle,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    account: AccountId,
    host: HostId,
    family: HostAuthorizationId,
    access: Text,
    refresh: Text,
    operation: OperationId,
    expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
enum State {
    PendingInit {},
    Revoked {
        account: AccountId,
        prior_epoch: u64,
        acknowledged_epoch: u64,
    },
    EnrollmentRevokedNoFamily {
        account: AccountId,
        enrollment_id: EnrollmentId,
        operation_id: OperationId,
    },
    AwaitingApproval {
        enrollment: Enrollment,
    },
    Approved {
        enrollment: Enrollment,
        approval: Approval,
    },
    ExchangePrepared {
        enrollment: Enrollment,
        approval: Approval,
        proof: EnrollmentProof,
        prepared_at: u64,
    },
    Unconfirmed {
        enrollment: Enrollment,
        approval: Approval,
        proof: EnrollmentProof,
        credentials: Credentials,
    },
    Ready {
        account: AccountId,
        signed: SignedBundle,
        credentials: Credentials,
        epoch: u64,
    },
    Rotating {
        account: AccountId,
        signed: SignedBundle,
        credentials: Credentials,
        epoch: u64,
        operation: OperationId,
        proof: EnrollmentProof,
        prepared_at: u64,
    },
}
// Distinguish a required v3 pin slot (possibly not yet approved) from an absent
// legacy field. The outer Option may be None ONLY in validated v1/v2 bundles.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountPin {
    #[serde(deserialize_with = "deserialize_pin_account")]
    account: Option<AccountId>,
}
fn deserialize_pin_account<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<AccountId>, D::Error> {
    Option::<AccountId>::deserialize(deserializer)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    observed_at: u64,
    config: Config,
    seed: Seed,
    commitment: SignedHostKeyCommitment,
    // Account-independent key commitment; account_pin separately prevents rebinding.
    pin: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    account_pin: Option<AccountPin>,
    lifecycle: State,
}

/// One exclusively borrowed provider and one protected bundle. Dropping a sealed
/// manager and explicitly reopening is the only recovery after uncertain commit.
pub struct HostAuth<'a, S: SecretStorage + ?Sized> {
    storage: &'a mut S,
    config: Config,
    record: Option<Record>,
    sealed: bool,
    observed: Cell<u64>,
    crypto_clock: Cell<(std::time::Duration, std::time::Instant)>,
}
impl<S: SecretStorage + ?Sized> std::fmt::Debug for HostAuth<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostAuth")
            .field("status", &self.status())
            .finish()
    }
}
impl<'a, S: SecretStorage + ?Sized> HostAuth<'a, S> {
    pub fn open(storage: &'a mut S, config: Config, now: u64) -> Result<Self> {
        config.validate()?;
        match storage.status().state {
            StorageState::Available => {}
            StorageState::Unconfigured => return Err(Error::Storage(secrets::Error::Unconfigured)),
            StorageState::Locked => return Err(Error::Storage(secrets::Error::Locked)),
            StorageState::Unavailable => return Err(Error::Storage(secrets::Error::Unavailable)),
        }
        let record = storage
            .load()
            .map_err(Error::Storage)?
            .map(|bundle| decode(&bundle, &config))
            .transpose()?;
        if record.as_ref().is_some_and(|r| now < r.observed_at) {
            return Err(Error::ClockRollback);
        }
        let mut auth = Self {
            storage,
            config,
            record,
            sealed: false,
            observed: Cell::new(now),
            crypto_clock: Cell::new((
                std::time::Duration::from_secs(now),
                std::time::Instant::now(),
            )),
        };
        if let Some(mut legacy) = auth.record.as_ref().filter(|r| r.version < 3).cloned() {
            // decode validated all old proof/intent/key material before migration.
            // V1 has no cadence reservation, so wait a full interval from open.
            if legacy.version == 1
                && let Some(enrollment) = enrollment_mut(&mut legacy.lifecycle)
            {
                enrollment.poll_reserved = Some(false);
                enrollment.next_poll_at = Some(
                    now.max(legacy.observed_at)
                        .checked_add(enrollment.interval)
                        .ok_or(Error::InvalidBundle)?,
                );
            }
            legacy.account_pin = Some(AccountPin {
                account: lifecycle_account(&legacy.lifecycle),
            });
            legacy.version = 3;
            auth.commit(legacy)?;
        }
        Ok(auth)
    }
    /// Configured public trust metadata only; this does not assert readiness.
    /// Reading this reference performs no provider IO and exposes no credentials.
    pub fn trusted_configuration(&self) -> &Config {
        &self.config
    }

    pub fn status(&self) -> Status {
        if self.sealed {
            return Status::Sealed;
        }
        match self.record.as_ref().map(|r| &r.lifecycle) {
            None => Status::Empty,
            Some(State::PendingInit {}) => Status::PendingInit,
            Some(State::AwaitingApproval { .. }) => Status::AwaitingApproval,
            Some(State::Approved { .. }) => Status::Approved,
            Some(State::ExchangePrepared { .. }) => Status::ExchangePrepared,
            Some(State::Unconfirmed { .. }) => Status::Unconfirmed,
            Some(State::Ready { .. }) => Status::Ready,
            Some(State::Rotating { .. }) => Status::Rotating,
            Some(State::Revoked { .. } | State::EnrollmentRevokedNoFamily { .. }) => {
                Status::Revoked
            }
        }
    }
    fn current(&self) -> Result<&Record> {
        if self.sealed {
            Err(Error::Sealed)
        } else {
            self.record.as_ref().ok_or(Error::InvalidState)
        }
    }
    fn observe(&self, now: u64) -> Result<()> {
        if self.sealed {
            return Err(Error::Sealed);
        }
        if now < self.observed.get() {
            return Err(Error::ClockRollback);
        }
        let (anchor, instant) = self.crypto_clock.get();
        let sampled = std::time::Instant::now();
        let observation = std::time::Duration::from_secs(now);
        if observation > anchor.saturating_add(sampled.saturating_duration_since(instant)) {
            self.crypto_clock.set((observation, sampled));
        }
        self.observed.set(now);
        Ok(())
    }
    fn commit(&mut self, mut record: Record) -> Result<()> {
        if self.sealed {
            return Err(Error::Sealed);
        }
        record.observed_at = self.observed.get();
        validate(&record, &self.config)?;
        let bundle = encode(&record)?;
        match self.storage.replace(&bundle) {
            Ok(()) => {
                self.record = Some(record);
                Ok(())
            }
            Err(secrets::Error::CommitUncertain) => {
                self.sealed = true;
                self.record = None;
                Err(Error::Storage(secrets::Error::CommitUncertain))
            }
            Err(e) => Err(Error::Storage(e)),
        }
    }
    /// Explicitly create on a provider positively observed empty by open().
    pub fn initialize(&mut self) -> Result<()> {
        if self.sealed {
            return Err(Error::Sealed);
        }
        if self.record.is_some() {
            return Err(Error::InvalidState);
        }
        // Detect unexpected provider changes, without overwriting unreadable data.
        if self.storage.load().map_err(Error::Storage)?.is_some() {
            return Err(Error::InvalidState);
        }
        let pending = crypto(PendingHostIdentity::generate(
            self.config.host.to_bytes(),
            1,
        ))?;
        let commitment = crypto(pending.signed_commitment())?;
        let pin = crypto(commitment.descriptor.commitment())?;
        self.commit(Record {
            version: 3,
            observed_at: self.observed.get(),
            config: self.config.clone(),
            seed: Seed(crypto(pending.export_secret_seed_blob())?),
            commitment,
            pin,
            account_pin: Some(AccountPin { account: None }),
            lifecycle: State::PendingInit {},
        })
    }
    pub fn init_request(&self) -> Result<EnrollmentInitiateParams> {
        let r = self.current()?;
        if !matches!(r.lifecycle, State::PendingInit {}) {
            return Err(Error::InvalidState);
        }
        Ok(EnrollmentInitiateParams {
            client_id: wire(r.config.client.clone())?,
            key_commitment: wire(hex(&r.pin))?,
            proof: EnrollmentProof {
                canonical_cbor: wire(hex(&crypto(r.commitment.descriptor.canonical())?))?,
                signature: wire(hex(&r.commitment.signature))?,
            },
        })
    }
    pub fn accept_initiation(
        &mut self,
        response: EnrollmentInitiateResult,
        now: u64,
    ) -> Result<()> {
        let device = Text::new(response.device_code.into());
        let user = Text::new(response.user_code.into());
        self.observe(now)?;
        let r = self.current()?;
        if let State::AwaitingApproval { enrollment } = &r.lifecycle {
            if enrollment.id == response.enrollment_id
                && enrollment.device == device
                && enrollment.user == user
                && enrollment.interval == response.poll_interval_seconds.0
            {
                return Ok(());
            }
            return Err(Error::InvalidResponse);
        }
        if !matches!(r.lifecycle, State::PendingInit {})
            || response.expires_in_seconds.0 == 0
            || response.poll_interval_seconds.0 == 0
        {
            return Err(Error::InvalidResponse);
        }
        let expires = now
            .checked_add(response.expires_in_seconds.0)
            .ok_or(Error::InvalidResponse)?;
        let mut next = r.clone();
        next.lifecycle = State::AwaitingApproval {
            enrollment: Enrollment {
                id: response.enrollment_id,
                device,
                user,
                expires,
                interval: response.poll_interval_seconds.0,
                next_poll_at: Some(
                    now.checked_add(response.poll_interval_seconds.0)
                        .ok_or(Error::InvalidResponse)?,
                ),
                poll_reserved: Some(false),
            },
        };
        self.commit(next)
    }
    /// Public user code only; expiry is exclusive. No network credential escapes.
    pub fn enrollment_presentation(&self, now: u64) -> Result<EnrollmentPresentation> {
        self.observe(now)?;
        let State::AwaitingApproval { enrollment } = &self.current()?.lifecycle else {
            return Err(Error::InvalidState);
        };
        check_time(enrollment.expires, now)?;
        Ok(EnrollmentPresentation {
            user_code: wire(enrollment.user.as_str().to_owned())?,
            expires_at: enrollment.expires,
            poll_interval_seconds: enrollment.interval,
            next_poll_at: enrollment.next_poll_at.ok_or(Error::InvalidBundle)?,
        })
    }
    /// Reserve the next poll durably BEFORE exposing transport-only device code.
    /// Pending responses and network failures keep this reservation unchanged.
    pub fn device_poll_credential(&mut self, now: u64) -> Result<DeviceCode> {
        self.observe(now)?;
        let r = self.current()?;
        let State::AwaitingApproval { enrollment } = &r.lifecycle else {
            return Err(Error::InvalidState);
        };
        check_time(enrollment.expires, now)?;
        if now < enrollment.next_poll_at.ok_or(Error::InvalidBundle)? {
            return Err(Error::PollTooEarly);
        }
        let mut next = r.clone();
        let enrollment = enrollment_mut(&mut next.lifecycle).ok_or(Error::InvalidState)?;
        enrollment.poll_reserved = Some(true);
        enrollment.next_poll_at = Some(
            now.checked_add(enrollment.interval)
                .ok_or(Error::InvalidState)?,
        );
        self.commit(next)?;
        let State::AwaitingApproval { enrollment } = &self.current()?.lifecycle else {
            return Err(Error::InvalidState);
        };
        wire(enrollment.device.as_str().to_owned())
    }
    /// Apply only an authenticated SlowDown response from the configured TLS peer.
    pub fn accept_tls_slow_down(&mut self, authenticated_origin: &str, now: u64) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        if authenticated_origin != r.config.origin {
            return Err(Error::InvalidResponse);
        }
        let State::AwaitingApproval { enrollment } = &r.lifecycle else {
            return Err(Error::InvalidState);
        };
        check_time(enrollment.expires, now)?;
        if enrollment.poll_reserved != Some(true) {
            return Err(Error::InvalidState);
        }
        let interval = enrollment
            .interval
            .checked_add(5)
            .ok_or(Error::InvalidResponse)?;
        let eligible = now.checked_add(interval).ok_or(Error::InvalidResponse)?;
        let mut next = r.clone();
        let enrollment = enrollment_mut(&mut next.lifecycle).ok_or(Error::InvalidState)?;
        enrollment.interval = interval;
        enrollment.poll_reserved = Some(false);
        enrollment.next_poll_at =
            Some(eligible.max(enrollment.next_poll_at.ok_or(Error::InvalidBundle)?));
        self.commit(next)
    }
    /// Explicit local logout cancellation before any exchange intent exists.
    /// This does not assert cloud revocation. Identity and commitment stay pinned.
    pub fn cancel_pending_login(&mut self, now: u64) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        match &r.lifecycle {
            State::PendingInit {} => return Ok(()),
            State::AwaitingApproval { .. } | State::Approved { .. } => {}
            _ => return Err(Error::InvalidState),
        }
        let mut next = r.clone();
        next.lifecycle = State::PendingInit {};
        self.commit(next)
    }
    /// Transport-only credential for the configured host revoke endpoint ONLY.
    /// Deliberately usable after local access expiry for an authenticated revoke
    /// acknowledgement retry. Never use for ordinary requests. Rejected/expired
    /// server credentials are not revocation proof; retain exact recovery intent.
    pub fn revocation_credential(&self) -> Result<HostAccessCredential> {
        match &self.current()?.lifecycle {
            State::Ready { credentials, .. } | State::Rotating { credentials, .. } => {
                wire(credentials.access.as_str().to_owned())
            }
            _ => Err(Error::InvalidState),
        }
    }
    /// Reset only definitely expired pre-exchange enrollment, retaining keys/pin.
    pub fn reset_expired_enrollment(&mut self, now: u64) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        let expired = match &r.lifecycle {
            State::AwaitingApproval { enrollment } => now >= enrollment.expires,
            State::Approved {
                enrollment,
                approval,
            } => now >= enrollment.expires || now >= approval.challenge.expires_at,
            _ => return Err(Error::InvalidState),
        };
        if !expired {
            return Err(Error::InvalidState);
        }
        let mut next = r.clone();
        next.lifecycle = State::PendingInit {};
        self.commit(next)
    }
    /// Explicit authenticated denial only; never use for network/invalid responses.
    pub fn reset_tls_denied_enrollment(
        &mut self,
        authenticated_origin: &str,
        now: u64,
    ) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        if authenticated_origin != r.config.origin {
            return Err(Error::InvalidResponse);
        }
        if !matches!(
            r.lifecycle,
            State::AwaitingApproval { .. } | State::Approved { .. }
        ) {
            return Err(Error::InvalidState);
        }
        let mut next = r.clone();
        next.lifecycle = State::PendingInit {};
        self.commit(next)
    }
    /// Retire family material ONLY after a closed, authenticated host revoke ACK.
    /// The peer origin is the caller's TLS assertion, never a response field.
    /// Ordinary HTTP failures, including 401, must never call this transition.
    pub fn accept_tls_revocation(
        &mut self,
        authenticated_origin: &str,
        result: HostRevokeResult,
        now: u64,
    ) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        let (account, epoch) = match &r.lifecycle {
            State::Ready { account, epoch, .. } | State::Rotating { account, epoch, .. } => {
                (*account, *epoch)
            }
            _ => return Err(Error::InvalidState),
        };
        if authenticated_origin != r.config.origin
            || result.host_id != r.config.host
            || result.host_access_epoch.0 < epoch
        {
            return Err(Error::InvalidResponse);
        }
        let mut next = r.clone();
        next.lifecycle = State::Revoked {
            account,
            prior_epoch: epoch,
            acknowledged_epoch: result.host_access_epoch.0,
        };
        self.commit(next)
    }
    /// Prepare the proof-only request for acknowledging a family that the
    /// ordinary access-token revoke endpoint already reports as unauthorized.
    /// This deliberately ignores access expiry and any rotation intent deadline:
    /// it only returns the current family's retained refresh proof and epoch.
    pub fn revocation_ack_request(&self, now: u64) -> Result<HostRevocationAckParams> {
        self.observe(now)?;
        let r = self.current()?;
        let (credentials, epoch) = match &r.lifecycle {
            State::Ready {
                credentials, epoch, ..
            }
            | State::Rotating {
                credentials, epoch, ..
            } => (credentials, *epoch),
            _ => return Err(Error::InvalidState),
        };
        Ok(HostRevocationAckParams {
            host_authorization_id: credentials.family,
            expected_host_access_epoch: DecimalU64(epoch),
            refresh: wire(credentials.refresh.as_str().to_owned())?,
        })
    }
    /// Accept a proof-only acknowledgement only for the exact retained family,
    /// refresh value, and verified epoch used by the original request. A delayed
    /// response cannot retire credentials installed after that request.
    pub fn accept_revocation_ack(
        &mut self,
        authenticated_origin: &str,
        request: &HostRevocationAckParams,
        result: HostRevokeResult,
        now: u64,
    ) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        let bound = match &r.lifecycle {
            State::Ready {
                credentials, epoch, ..
            }
            | State::Rotating {
                credentials, epoch, ..
            } => {
                request.host_authorization_id == credentials.family
                    && request.expected_host_access_epoch.0 == *epoch
                    && request.refresh.expose_wire() == credentials.refresh.as_str()
            }
            _ => return Err(Error::InvalidState),
        };
        if !bound {
            return Err(Error::InvalidResponse);
        }
        self.accept_tls_revocation(authenticated_origin, result, now)
    }
    /// Return only the retained historical enrollment identity and signed proof
    /// needed to acknowledge its retirement. Unlike exchange and registration,
    /// this retirement-only request remains available after those intents expire.
    /// It never exposes bootstrap, access, or refresh credentials.
    pub fn enrollment_revocation_ack_request(
        &self,
        now: u64,
    ) -> Result<HostEnrollmentRevocationAckParams> {
        self.observe(now)?;
        let r = self.current()?;
        let (enrollment, approval, proof) = match &r.lifecycle {
            State::ExchangePrepared {
                enrollment,
                approval,
                proof,
                ..
            }
            | State::Unconfirmed {
                enrollment,
                approval,
                proof,
                ..
            } => (enrollment, approval, proof),
            _ => return Err(Error::InvalidState),
        };
        Ok(HostEnrollmentRevocationAckParams {
            enrollment_id: enrollment.id,
            operation_id: OperationId::from_bytes(approval.challenge.operation_id)
                .map_err(|_| Error::InvalidBundle)?,
            proof: proof.clone(),
        })
    }
    /// Retire an exchange enrollment only after a typed, authenticated
    /// historical acknowledgement for the exact original request. The
    /// operation is independent of normal exchange/registration deadlines.
    pub fn accept_enrollment_revocation_ack(
        &mut self,
        authenticated_origin: &str,
        request: &HostEnrollmentRevocationAckParams,
        result: HostEnrollmentRevocationAckResult,
        now: u64,
    ) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        let (enrollment, approval, proof, family, exchange_prepared) = match &r.lifecycle {
            State::ExchangePrepared {
                enrollment,
                approval,
                proof,
                ..
            } => (enrollment, approval, proof, None, true),
            State::Unconfirmed {
                enrollment,
                approval,
                proof,
                credentials,
            } => (enrollment, approval, proof, Some(credentials.family), false),
            _ => return Err(Error::InvalidState),
        };
        let operation = OperationId::from_bytes(approval.challenge.operation_id)
            .map_err(|_| Error::InvalidBundle)?;
        if authenticated_origin != r.config.origin
            || request.enrollment_id != enrollment.id
            || request.operation_id != operation
            || request.proof != *proof
        {
            return Err(Error::InvalidResponse);
        }

        let (account, next_lifecycle) = match result {
            HostEnrollmentRevocationAckResult::RevokedFamily {
                host_id,
                enrollment_id,
                operation_id,
                account_id,
                host_authorization_id,
                family_host_access_epoch,
                host_access_epoch,
            } => {
                let family_epoch = family_host_access_epoch.0;
                let acknowledged_epoch = host_access_epoch.0;
                let valid_epoch = |epoch: u64| epoch != 0 && epoch <= i64::MAX as u64;
                if host_id != r.config.host
                    || enrollment_id != enrollment.id
                    || operation_id != operation
                    || account_id != approval.account
                    || family.is_some_and(|family| family != host_authorization_id)
                    || !valid_epoch(family_epoch)
                    || !valid_epoch(acknowledged_epoch)
                    || acknowledged_epoch < family_epoch
                {
                    return Err(Error::InvalidResponse);
                }
                (
                    account_id,
                    State::Revoked {
                        account: account_id,
                        prior_epoch: family_epoch,
                        acknowledged_epoch,
                    },
                )
            }
            HostEnrollmentRevocationAckResult::NoFamily {
                host_id,
                enrollment_id,
                operation_id,
                account_id,
            } => {
                if !exchange_prepared
                    || host_id != r.config.host
                    || enrollment_id != enrollment.id
                    || operation_id != operation
                    || account_id != approval.account
                {
                    return Err(Error::InvalidResponse);
                }
                (
                    account_id,
                    State::EnrollmentRevokedNoFamily {
                        account: account_id,
                        enrollment_id,
                        operation_id,
                    },
                )
            }
        };
        if lifecycle_account(&next_lifecycle) != Some(account) {
            return Err(Error::InvalidResponse);
        }
        let mut next = r.clone();
        next.lifecycle = next_lifecycle;
        self.commit(next)
    }
    /// Retained, authenticated ACK for the owner's durable pending-revoke handoff.
    /// No credential or request intent is exposed. Opening never consumes it.
    pub fn revocation_acknowledgement(&self) -> Result<HostRevokeResult> {
        let r = self.current()?;
        let State::Revoked {
            acknowledged_epoch, ..
        } = &r.lifecycle
        else {
            return Err(Error::InvalidState);
        };
        Ok(HostRevokeResult {
            host_id: r.config.host,
            host_access_epoch: DecimalU64(*acknowledged_epoch),
        })
    }
    /// Retained authenticated ACK for the owner's durable handoff, including
    /// the no-family result without inventing a family or epoch.
    pub fn retained_revocation_acknowledgement(&self) -> Result<RetainedRevocationAcknowledgement> {
        let r = self.current()?;
        match &r.lifecycle {
            State::Revoked {
                acknowledged_epoch, ..
            } => Ok(RetainedRevocationAcknowledgement::Host(HostRevokeResult {
                host_id: r.config.host,
                host_access_epoch: DecimalU64(*acknowledged_epoch),
            })),
            State::EnrollmentRevokedNoFamily {
                account,
                enrollment_id,
                operation_id,
            } => Ok(RetainedRevocationAcknowledgement::NoFamily {
                host_id: r.config.host,
                account_id: *account,
                enrollment_id: *enrollment_id,
                operation_id: *operation_id,
            }),
            _ => Err(Error::InvalidState),
        }
    }
    /// Explicit new-login transition after the owner durably clears its pending
    /// revoke using the retained ACK. The caller must complete that handoff first;
    /// never invoke automatically on open or while cloud revocation is pending.
    pub fn restart_after_revocation(&mut self, now: u64) -> Result<()> {
        self.reset_after_acknowledged_revocation(now)
    }
    /// Identity-preserving lifecycle reset for an explicit local profile purge.
    /// The caller must verify that the Store has a durable authenticated revoke
    /// acknowledgement (`pending_cloud_revoke == false`, locked, and cloud
    /// authorization history positively false) before calling this method.
    /// The seed and public commitment remain pinned; only lifecycle credentials
    /// and enrollment state return to PendingInit.
    pub fn reset_after_acknowledged_revocation(&mut self, now: u64) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        if !matches!(
            r.lifecycle,
            State::Revoked { .. } | State::EnrollmentRevokedNoFamily { .. }
        ) {
            return Err(Error::InvalidState);
        }
        let mut next = r.clone();
        next.lifecycle = State::PendingInit {};
        self.commit(next)
    }
    /// Epoch verified by a successful registration response, including while
    /// rotation recovery is pending. Unconfirmed enrollment has no verified epoch.
    pub fn verified_host_access_epoch(&self) -> Result<DecimalU64> {
        match &self.current()?.lifecycle {
            State::Ready { epoch, .. } | State::Rotating { epoch, .. } => Ok(DecimalU64(*epoch)),
            _ => Err(Error::InvalidState),
        }
    }
    /// Read scheduling metadata even after expiry, without emitting credentials.
    pub fn credential_deadlines(&self) -> Result<CredentialDeadlines> {
        let (credentials, rotation_expires_at) = match &self.current()?.lifecycle {
            State::Ready { credentials, .. } => (credentials, None),
            State::Rotating {
                credentials,
                prepared_at,
                ..
            } => (
                credentials,
                Some(prepared_at.checked_add(300).ok_or(Error::InvalidBundle)?),
            ),
            _ => return Err(Error::InvalidState),
        };
        Ok(CredentialDeadlines {
            access_expires_at: credentials.expires,
            refresh_at: credentials.expires.saturating_sub(60),
            rotation_expires_at,
        })
    }
    /// Caller MUST authenticate this response using TLS to the configured origin.
    /// This local library cannot authenticate a network connection. The origin
    /// argument asserts the actual authenticated peer, never a response field.
    pub fn accept_tls_approval(
        &mut self,
        authenticated_origin: &str,
        context: HostEnrollmentTokenContext,
        bootstrap: EnrollmentBootstrapCredential,
        now: u64,
    ) -> Result<()> {
        let bootstrap = Text::new(bootstrap.into());
        self.observe(now)?;
        let r = self.current()?;
        if authenticated_origin != r.config.origin {
            return Err(Error::InvalidResponse);
        }
        let challenge = crypto(EnrollmentChallenge::from_canonical(&unhex(
            context.challenge.expose_wire(),
            1024,
        )?))?;
        if let State::Approved {
            enrollment,
            approval,
        }
        | State::ExchangePrepared {
            enrollment,
            approval,
            ..
        }
        | State::Unconfirmed {
            enrollment,
            approval,
            ..
        } = &r.lifecycle
        {
            return if approval.account == context.account_id
                && approval.challenge == challenge
                && approval.bootstrap == bootstrap
            {
                check_enrollment_challenge_time(enrollment, &approval.challenge, now)?;
                Ok(())
            } else {
                Err(Error::InvalidResponse)
            };
        }
        let State::AwaitingApproval { enrollment } = &r.lifecycle else {
            return Err(Error::InvalidState);
        };
        if now >= enrollment.expires {
            return Err(Error::Expired);
        }
        if r.account_pin
            .as_ref()
            .and_then(|pin| pin.account)
            .is_some_and(|account| account != context.account_id)
        {
            return Err(Error::InvalidResponse);
        }
        validate_challenge(r, enrollment, context.account_id, &challenge)?;
        check_enrollment_challenge_time(enrollment, &challenge, now)?;
        let pending = crypto(PendingHostIdentity::import_secret_seed_blob(
            &r.seed.0,
            &r.commitment,
            &r.pin,
        ))?;
        let identity = crypto(pending.finalize(context.account_id.to_bytes(), &r.pin))?;
        let mut next = r.clone();
        next.account_pin = Some(AccountPin {
            account: Some(context.account_id),
        });
        next.lifecycle = State::Approved {
            enrollment: enrollment.clone(),
            approval: Approval {
                account: context.account_id,
                challenge,
                bootstrap,
                signed: identity.public_bundle(),
            },
        };
        self.commit(next)
    }
    pub fn prepare_exchange(&mut self, now: u64) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        if let State::ExchangePrepared {
            enrollment,
            approval,
            prepared_at,
            ..
        } = &r.lifecycle
        {
            check_enrollment_challenge_time(enrollment, &approval.challenge, now)?;
            return check_intent_time(*prepared_at, now);
        }
        let State::Approved {
            enrollment,
            approval,
        } = &r.lifecycle
        else {
            return Err(Error::InvalidState);
        };
        check_enrollment_challenge_time(enrollment, &approval.challenge, now)?;
        let identity = crypto(Identity::import_secret_seed_blob(
            &r.seed.0,
            &approval.signed,
        ))?;
        let signed = crypto(identity.sign_enrollment_proof(&approval.challenge))?;
        let proof = EnrollmentProof {
            canonical_cbor: wire(hex(&crypto(signed.challenge.canonical())?))?,
            signature: wire(hex(&signed.signature))?,
        };
        let mut next = r.clone();
        next.lifecycle = State::ExchangePrepared {
            enrollment: enrollment.clone(),
            approval: approval.clone(),
            proof,
            prepared_at: now,
        };
        self.commit(next)
    }
    pub fn exchange_request(&self, now: u64) -> Result<HostAuthorizationExchangeParams> {
        self.observe(now)?;
        let r = self.current()?;
        let State::ExchangePrepared {
            enrollment,
            approval,
            proof,
            prepared_at,
        } = &r.lifecycle
        else {
            return Err(Error::InvalidState);
        };
        check_enrollment_challenge_time(enrollment, &approval.challenge, now)?;
        check_intent_time(*prepared_at, now)?;
        Ok(HostAuthorizationExchangeParams {
            enrollment_id: enrollment.id,
            host_id: r.config.host,
            operation_id: OperationId::from_bytes(approval.challenge.operation_id)
                .map_err(|_| Error::InvalidBundle)?,
            bootstrap: wire(approval.bootstrap.as_str().to_owned())?,
            proof: proof.clone(),
        })
    }
    pub fn accept_exchange(&mut self, response: HostAuthorizationResult, now: u64) -> Result<()> {
        let response = Received::from(response);
        self.observe(now)?;
        let r = self.current()?;
        let (enrollment, approval, proof, prepared_at) = match &r.lifecycle {
            State::ExchangePrepared {
                enrollment,
                approval,
                proof,
                prepared_at,
            } => (enrollment, approval, proof, *prepared_at),
            State::Unconfirmed { credentials, .. } => return duplicate(credentials, response),
            _ => return Err(Error::InvalidState),
        };
        check_enrollment_challenge_time(enrollment, &approval.challenge, now)?;
        let credentials = credentials(
            response,
            approval.account,
            r.config.host,
            None,
            approval.challenge.operation_id,
            prepared_at,
            now,
        )?;
        let mut next = r.clone();
        next.lifecycle = State::Unconfirmed {
            enrollment: enrollment.clone(),
            approval: approval.clone(),
            proof: proof.clone(),
            credentials,
        };
        self.commit(next)
    }
    /// Unconfirmed access is exposed only with its registration request. Callers
    /// must restrict this credential to that request and retain no normal access.
    pub fn registration_request(
        &self,
        now: u64,
    ) -> Result<(HostAccessCredential, HostRegisterParams)> {
        self.observe(now)?;
        let r = self.current()?;
        let State::Unconfirmed {
            credentials,
            approval,
            ..
        } = &r.lifecycle
        else {
            return Err(Error::InvalidState);
        };
        check_time(credentials.expires, now)?;
        Ok((
            wire(credentials.access.as_str().to_owned())?,
            HostRegisterParams {
                host_id: r.config.host,
                identity: crypto(approval.signed.to_wire())?,
            },
        ))
    }
    pub fn confirm_registration(&mut self, response: HostRegisterResult) -> Result<()> {
        let r = self.current()?;
        if response.host_id != r.config.host || response.host_access_epoch.0 == 0 {
            return Err(Error::InvalidResponse);
        }
        if let State::Ready { epoch, .. } = &r.lifecycle {
            return if *epoch == response.host_access_epoch.0 {
                Ok(())
            } else {
                Err(Error::InvalidResponse)
            };
        }
        let State::Unconfirmed {
            approval,
            credentials,
            ..
        } = &r.lifecycle
        else {
            return Err(Error::InvalidState);
        };
        let mut next = r.clone();
        next.lifecycle = State::Ready {
            account: approval.account,
            signed: approval.signed.clone(),
            credentials: credentials.clone(),
            epoch: response.host_access_epoch.0,
        };
        self.commit(next)
    }
    /// Normal host authorization is available only from confirmed Ready state.
    pub fn access_credential(&self, now: u64) -> Result<HostAccessCredential> {
        self.observe(now)?;
        let State::Ready { credentials, .. } = &self.current()?.lifecycle else {
            return Err(Error::InvalidState);
        };
        check_time(credentials.expires, now)?;
        wire(credentials.access.as_str().to_owned())
    }

    pub fn prepare_rotation(&mut self, now: u64) -> Result<()> {
        self.observe(now)?;
        let r = self.current()?;
        if let State::Rotating { prepared_at, .. } = &r.lifecycle {
            return check_intent_time(*prepared_at, now);
        }
        let State::Ready {
            account,
            signed,
            credentials,
            epoch,
        } = &r.lifecycle
        else {
            return Err(Error::InvalidState);
        };
        let operation = OperationId::from_bytes(*uuid::Uuid::new_v4().as_bytes())
            .map_err(|_| Error::InvalidState)?;
        let identity = crypto(Identity::import_secret_seed_blob(&r.seed.0, signed))?;
        let proof = crypto(identity.sign_host_refresh_proof(
            credentials.family.to_bytes(),
            operation.to_bytes(),
            credentials.refresh.as_str(),
            &r.config.refresh_audience(),
        ))?;
        let mut next = r.clone();
        next.lifecycle = State::Rotating {
            account: *account,
            signed: signed.clone(),
            credentials: credentials.clone(),
            epoch: *epoch,
            operation,
            proof,
            prepared_at: now,
        };
        self.commit(next)
    }
    pub fn rotation_request(&self, now: u64) -> Result<HostAuthorizationRefreshParams> {
        self.observe(now)?;
        let r = self.current()?;
        let State::Rotating {
            credentials,
            operation,
            proof,
            prepared_at,
            ..
        } = &r.lifecycle
        else {
            return Err(Error::InvalidState);
        };
        check_intent_time(*prepared_at, now)?;
        Ok(HostAuthorizationRefreshParams {
            host_authorization_id: credentials.family,
            host_id: r.config.host,
            rotation_id: *operation,
            refresh: wire(credentials.refresh.as_str().to_owned())?,
            proof: proof.clone(),
        })
    }
    pub fn accept_rotation(&mut self, response: HostAuthorizationResult, now: u64) -> Result<()> {
        let response = Received::from(response);
        self.observe(now)?;
        let r = self.current()?;
        let (account, signed, old, epoch, operation, prepared_at) = match &r.lifecycle {
            State::Rotating {
                account,
                signed,
                credentials,
                epoch,
                operation,
                prepared_at,
                ..
            } => (account, signed, credentials, epoch, operation, *prepared_at),
            State::Ready { credentials, .. } => return duplicate(credentials, response),
            _ => return Err(Error::InvalidState),
        };
        let credentials = credentials(
            response,
            *account,
            r.config.host,
            Some(old.family),
            operation.to_bytes(),
            prepared_at,
            now,
        )?;
        if credentials.refresh == old.refresh || credentials.access == old.access {
            return Err(Error::InvalidResponse);
        }
        let mut next = r.clone();
        next.lifecycle = State::Ready {
            account: *account,
            signed: signed.clone(),
            credentials,
            epoch: *epoch,
        };
        self.commit(next)
    }
}
fn lifecycle_account(state: &State) -> Option<AccountId> {
    match state {
        State::Approved { approval, .. }
        | State::ExchangePrepared { approval, .. }
        | State::Unconfirmed { approval, .. } => Some(approval.account),
        State::Ready { account, .. }
        | State::Rotating { account, .. }
        | State::Revoked { account, .. }
        | State::EnrollmentRevokedNoFamily { account, .. } => Some(*account),
        _ => None,
    }
}
fn enrollment_mut(state: &mut State) -> Option<&mut Enrollment> {
    match state {
        State::AwaitingApproval { enrollment }
        | State::Approved { enrollment, .. }
        | State::ExchangePrepared { enrollment, .. }
        | State::Unconfirmed { enrollment, .. } => Some(enrollment),
        _ => None,
    }
}
fn enrollment_ref(state: &State) -> Option<&Enrollment> {
    match state {
        State::AwaitingApproval { enrollment }
        | State::Approved { enrollment, .. }
        | State::ExchangePrepared { enrollment, .. }
        | State::Unconfirmed { enrollment, .. } => Some(enrollment),
        _ => None,
    }
}
fn check_intent_time(prepared_at: u64, now: u64) -> Result<()> {
    check_time(
        prepared_at.checked_add(300).ok_or(Error::InvalidBundle)?,
        now,
    )
}
fn check_time(expires: u64, now: u64) -> Result<()> {
    if now >= expires {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn check_enrollment_challenge_time(
    enrollment: &Enrollment,
    challenge: &EnrollmentChallenge,
    now: u64,
) -> Result<()> {
    check_time(enrollment.expires.min(challenge.expires_at), now)
}
fn wire<T: TryFrom<String>>(s: String) -> Result<T> {
    T::try_from(s).map_err(|_| Error::InvalidBundle)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str, max: usize) -> Result<Vec<u8>> {
    if s.len() > max * 2 || !s.len().is_multiple_of(2) {
        return Err(Error::InvalidBundle);
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let n = |b: u8| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(Error::InvalidBundle),
            };
            Ok(n(p[0])? * 16 + n(p[1])?)
        })
        .collect()
}
fn validate_challenge(
    r: &Record,
    e: &Enrollment,
    account: AccountId,
    c: &EnrollmentChallenge,
) -> Result<()> {
    crypto(c.canonical())?;
    let bound = crypto(
        r.commitment
            .descriptor
            .account_bound_bundle(account.to_bytes()),
    )?;
    if c.enrollment_id != e.id.to_bytes()
        || c.host_id != r.config.host.to_bytes()
        || c.host_key_fingerprint != crypto(bound.fingerprint())?
        || c.audience != r.config.exchange_audience()
    {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}
struct Received {
    account_id: AccountId,
    host_id: HostId,
    host_authorization_id: HostAuthorizationId,
    access: Text,
    refresh: Text,
    rotation_id: OperationId,
    expires_in_seconds: DecimalU64,
}
impl From<HostAuthorizationResult> for Received {
    fn from(v: HostAuthorizationResult) -> Self {
        Self {
            account_id: v.account_id,
            host_id: v.host_id,
            host_authorization_id: v.host_authorization_id,
            access: Text::new(v.access.into()),
            refresh: Text::new(v.refresh.into()),
            rotation_id: v.rotation_id,
            expires_in_seconds: v.expires_in_seconds,
        }
    }
}
fn credentials(
    v: Received,
    account: AccountId,
    host: HostId,
    family: Option<HostAuthorizationId>,
    op: [u8; 16],
    prepared_at: u64,
    now: u64,
) -> Result<Credentials> {
    let access = v.access;
    let refresh = v.refresh;
    if v.account_id != account
        || v.host_id != host
        || family.is_some_and(|f| f != v.host_authorization_id)
        || v.rotation_id.to_bytes() != op
        || v.expires_in_seconds.0 != 300
    {
        return Err(Error::InvalidResponse);
    }
    let expires = prepared_at.checked_add(300).ok_or(Error::InvalidResponse)?;
    check_time(expires, now)?;
    Ok(Credentials {
        account,
        host,
        family: v.host_authorization_id,
        access,
        refresh,
        operation: v.rotation_id,
        expires,
    })
}
fn duplicate(c: &Credentials, v: Received) -> Result<()> {
    let access = v.access;
    let refresh = v.refresh;
    if v.account_id == c.account
        && v.host_id == c.host
        && v.host_authorization_id == c.family
        && v.rotation_id == c.operation
        && access == c.access
        && refresh == c.refresh
        && v.expires_in_seconds.0 == 300
    {
        Ok(())
    } else {
        Err(Error::InvalidResponse)
    }
}
fn validate(r: &Record, config: &Config) -> Result<()> {
    if !matches!(r.version, 1..=3)
        || &r.config != config
        || r.commitment.descriptor.host_id != config.host.to_bytes()
    {
        return Err(Error::InvalidBundle);
    }
    if let State::Revoked {
        prior_epoch,
        acknowledged_epoch,
        ..
    } = &r.lifecycle
        && (r.version != 3 || *prior_epoch == 0 || *acknowledged_epoch < *prior_epoch)
    {
        return Err(Error::InvalidBundle);
    }
    if matches!(r.lifecycle, State::EnrollmentRevokedNoFamily { .. }) && r.version != 3 {
        return Err(Error::InvalidBundle);
    }
    match (r.version, &r.account_pin) {
        (1 | 2, None) => {}
        (3, Some(pin))
            if lifecycle_account(&r.lifecycle)
                .is_none_or(|account| pin.account == Some(account)) => {}
        _ => return Err(Error::InvalidBundle),
    }
    if let Some(enrollment) = enrollment_ref(&r.lifecycle)
        && ((r.version == 1
            && (enrollment.next_poll_at.is_some() || enrollment.poll_reserved.is_some()))
            || (r.version >= 2
                && (enrollment.next_poll_at.is_none() || enrollment.poll_reserved.is_none()))
            || enrollment
                .next_poll_at
                .is_some_and(|next| next < enrollment.interval))
    {
        return Err(Error::InvalidBundle);
    }
    match &r.lifecycle {
        State::ExchangePrepared {
            enrollment,
            prepared_at,
            approval,
            ..
        } => {
            if *prepared_at > r.observed_at
                || *prepared_at >= enrollment.expires
                || *prepared_at >= approval.challenge.expires_at
                || prepared_at.checked_add(300).is_none()
            {
                return Err(Error::InvalidBundle);
            }
        }
        State::Rotating { prepared_at, .. }
            if *prepared_at > r.observed_at || prepared_at.checked_add(300).is_none() =>
        {
            return Err(Error::InvalidBundle);
        }
        _ => {}
    }
    crypto(r.commitment.verify(&r.pin))?;
    let pending = crypto(PendingHostIdentity::import_secret_seed_blob(
        &r.seed.0,
        &r.commitment,
        &r.pin,
    ))?;
    let (account, signed, creds) = match &r.lifecycle {
        State::PendingInit {} | State::Revoked { .. } | State::EnrollmentRevokedNoFamily { .. } => {
            return Ok(());
        }
        State::AwaitingApproval { enrollment } => {
            valid_enrollment(enrollment)?;
            return Ok(());
        }
        State::Approved {
            enrollment,
            approval,
        }
        | State::ExchangePrepared {
            enrollment,
            approval,
            ..
        }
        | State::Unconfirmed {
            enrollment,
            approval,
            ..
        } => {
            valid_enrollment(enrollment)?;
            validate_challenge(r, enrollment, approval.account, &approval.challenge)
                .map_err(|_| Error::InvalidBundle)?;
            require_wire_text(approval.bootstrap.as_str(), 2048)?;
            if let State::ExchangePrepared { proof, .. } | State::Unconfirmed { proof, .. } =
                &r.lifecycle
            {
                crypto(verify_host_enrollment_proof(
                    proof,
                    &approval.challenge,
                    &r.commitment,
                    &r.pin,
                    approval.account.to_bytes(),
                    0,
                ))?;
            }
            let creds = if let State::Unconfirmed { credentials, .. } = &r.lifecycle {
                if credentials.operation.to_bytes() != approval.challenge.operation_id {
                    return Err(Error::InvalidBundle);
                }
                Some(credentials)
            } else {
                None
            };
            (approval.account, &approval.signed, creds)
        }
        State::Ready {
            account,
            signed,
            credentials,
            epoch,
        }
        | State::Rotating {
            account,
            signed,
            credentials,
            epoch,
            ..
        } => {
            if *epoch == 0 {
                return Err(Error::InvalidBundle);
            }
            (*account, signed, Some(credentials))
        }
    };
    let expected = crypto(pending.finalize(account.to_bytes(), &r.pin))?;
    if expected.public_bundle() != *signed {
        return Err(Error::InvalidBundle);
    }
    crypto(Identity::import_secret_seed_blob(&r.seed.0, signed))?;
    if let Some(c) = creds {
        if c.account != account
            || c.host != config.host
            || c.expires < 300
            || c.expires - 300 > r.observed_at
        {
            return Err(Error::InvalidBundle);
        }
        require_wire_text(c.access.as_str(), 2048)?;
        require_wire_text(c.refresh.as_str(), 2048)?;
    }
    if let State::Rotating {
        credentials,
        operation,
        proof,
        ..
    } = &r.lifecycle
    {
        if *operation == credentials.operation {
            return Err(Error::InvalidBundle);
        }
        let expected_proof = crypto(expected.sign_host_refresh_proof(
            credentials.family.to_bytes(),
            operation.to_bytes(),
            credentials.refresh.as_str(),
            &config.refresh_audience(),
        ))?;
        if expected_proof != *proof {
            return Err(Error::InvalidBundle);
        }
    }
    Ok(())
}
// Match protocol/http.rs secret!'s ASCII alphabet and byte limits without
// allocating an ordinary String merely to validate protected secret material.
fn valid_wire_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn require_wire_text(value: &str, max: usize) -> Result<()> {
    if valid_wire_text(value, max) {
        Ok(())
    } else {
        Err(Error::InvalidBundle)
    }
}
fn valid_enrollment(e: &Enrollment) -> Result<()> {
    require_wire_text(e.device.as_str(), 256)?;
    require_wire_text(e.user.as_str(), 64)?;
    if e.expires == 0 || e.interval == 0 {
        Err(Error::InvalidBundle)
    } else {
        Ok(())
    }
}
// Fixed capacity prevents serialization from growing past the storage boundary;
// both the buffer and all error-path partially serialized bytes are zeroized.
struct Bounded(Zeroizing<Vec<u8>>);
impl Write for Bounded {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() > MAX_BUNDLE_BYTES - self.0.len() {
            return Err(io::Error::other("bundle limit"));
        }
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(r: &Record) -> Result<SecretBundle> {
    let mut out = Bounded(Zeroizing::new(Vec::with_capacity(MAX_BUNDLE_BYTES)));
    serde_json::to_writer(&mut out, r).map_err(|_| Error::InvalidBundle)?;
    SecretBundle::new(std::mem::take(&mut *out.0)).map_err(Error::Storage)
}
fn decode(b: &SecretBundle, config: &Config) -> Result<Record> {
    if b.expose().is_empty() || b.expose().len() > MAX_BUNDLE_BYTES {
        return Err(Error::InvalidBundle);
    }
    if b.expose()
        .iter()
        .any(|byte| !byte.is_ascii() || *byte == b'\\')
    {
        return Err(Error::InvalidBundle);
    }
    let r: Record = serde_json::from_slice(b.expose()).map_err(|_| Error::InvalidBundle)?;
    validate(&r, config)?;
    Ok(r)
}
