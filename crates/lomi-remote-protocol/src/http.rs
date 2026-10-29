//! Draft E0 HTTP control-plane contracts. Canonical cryptography remains in crypto.
use crate::*;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

pub const REMOTE_HTTP_PREFIX: &str = "/v2/remote";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpSurface {
    PublicEnrollment,
    EnrollmentBootstrap,
    HostRefresh,
    HostAccess,
    ConsumerSession,
    EitherOwnPeer,
    SelfHostOrOwnerAccount,
    OrdinarySession,
    ConsumerIdentity,
    ConsumerManagement,
    HostRevocationProof,
    HostEnrollmentRevocationProof,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRouteContract {
    pub route: HttpRoute,
    pub method: HttpMethod,
    pub path: &'static str,
    pub surface: HttpSurface,
    pub window_identity_header: bool,
}
macro_rules! routes {
    ($($name:ident: $method:ident, $path:literal, $surface:ident;)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum HttpRoute { $($name),+ }
        pub const HTTP_ROUTES: &[HttpRouteContract] = &[$(HttpRouteContract { route: HttpRoute::$name, method: HttpMethod::$method, path: $path, surface: HttpSurface::$surface, window_identity_header: matches!(HttpRoute::$name, HttpRoute::ChannelGet) }),+];
        impl HttpRoute { pub fn contract(self) -> &'static HttpRouteContract { HTTP_ROUTES.iter().find(|r| r.route == self).expect("exhaustive route registry") } }
    }
}
routes! {
    EnrollmentInitiate: Post, "/enrollments", PublicEnrollment;
    HostAuthorizationExchange: Post, "/host-authorizations/exchange", EnrollmentBootstrap;
    HostAuthorizationRefresh: Post, "/host-authorizations/refresh", HostRefresh;
    HostRegister: Post, "/hosts/register", HostAccess;
    ConsumerAuthorizationIssue: Post, "/consumer-authorizations", OrdinarySession;
    ConsumerAuthorizationRevoke: Post, "/consumer-authorizations/{consumerAuthorizationId}/revoke", ConsumerManagement;
    ConsumerWindowChallenge: Post, "/consumer-windows/challenge", ConsumerIdentity;
    ConsumerWindowRegister: Post, "/consumer-windows/register", ConsumerIdentity;
    ConsumerWindowGet: Get, "/consumer-windows/{windowIdentityId}", ConsumerIdentity;
    ConsumerWindowRevoke: Post, "/consumer-windows/{windowIdentityId}/revoke", ConsumerIdentity;
    RuntimeGet: Get, "/hosts/{hostId}/runtime", HostAccess;
    RuntimeClaim: Post, "/hosts/{hostId}/runtime/claim", HostAccess;
    Heartbeat: Post, "/hosts/{hostId}/heartbeat", HostAccess;
    Publication: Put, "/hosts/{hostId}/publication", HostAccess;
    Inventory: Get, "/inventory", ConsumerSession;
    PairingCreate: Post, "/pairings", ConsumerSession;
    PairingGet: Get, "/pairings/{pairingId}", EitherOwnPeer;
    PairingPending: Get, "/hosts/{hostId}/pairings/pending", HostAccess;
    PairingDecision: Post, "/pairings/{pairingId}/decision", HostAccess;
    ChannelCreate: Post, "/channels", EitherOwnPeer;
    ChannelGet: Get, "/channels/{channelId}", EitherOwnPeer;
    ChannelPending: Get, "/hosts/{hostId}/channels/pending", HostAccess;
    ChannelAdmission: Post, "/channels/{channelId}/admission", HostAccess;
    ChannelTicket: Post, "/channels/{channelId}/tickets", EitherOwnPeer;
    GrantRevoke: Post, "/grants/{grantId}/revoke", EitherOwnPeer;
    HostRevoke: Post, "/hosts/{hostId}/revoke", SelfHostOrOwnerAccount;
    HostRevocationAck: Post, "/hosts/{hostId}/revocation-ack", HostRevocationProof;
    HostEnrollmentRevocationAck: Post, "/hosts/{hostId}/enrollment-revocation-ack", HostEnrollmentRevocationProof;
}

// Encodings are transport representations, never a replacement signature algorithm.
macro_rules! secret {
    ($name:ident, $max:literal, $hex:literal, $exact:literal) => {
        #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl fmt::Debug for $name { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($name), "([REDACTED])")) } }
        impl $name { pub fn expose_wire(&self) -> &str { &self.0 } }
        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                let valid = if $hex { value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) } else { value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') };
                if value.is_empty() || value.len() > $max || ($exact && value.len() != $max) || !valid { Err("invalid bounded wire encoding") } else { Ok(Self(value)) }
            }
        }
        impl From<$name> for String { fn from(value: $name) -> Self { value.0 } }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static,str> { stringify!($name).into() }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                let pattern = if $hex { "^([0-9a-f]{2})+$" } else { "^[A-Za-z0-9_-]+$" };
                let forbidden = if $hex { "[^0-9a-f]" } else { "[^A-Za-z0-9_-]" };
                json_schema!({"type":"string","pattern":pattern,"not":{"pattern":forbidden},"minLength": if $exact { $max } else { 1 },"maxLength":$max})
            }
        }
    }
}
secret!(HostAccessCredential, 2048, false, false);
secret!(HostRefreshCredential, 2048, false, false);
secret!(EnrollmentBootstrapCredential, 2048, false, false);
secret!(RelayTicket, 2048, false, false);
secret!(DeviceCode, 256, false, false);
secret!(UserCode, 64, false, false);
secret!(PublicClientId, 128, false, false);
secret!(PublicKeyHex, 64, true, true);
secret!(SignatureHex, 128, true, true);
secret!(HostKeyCommitmentHex, 64, true, true);
secret!(IdentityFingerprintHex, 64, true, true);
// Exact canonical CBOR produced by the existing crypto crate, hex encoded.
// Decoding/validating its canonical schema and signature is an external crypto duty.
secret!(CanonicalCryptoCborHex, 16384, true, false);

macro_rules! dto {
    ($name:ident { $($(#[$field_attr:meta])* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name { $($(#[$field_attr])* pub $field: $ty),* }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                // Derived struct deserialization also accepts positional sequences.
                // HTTP schemas require objects, including at nested DTO positions.
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase", deny_unknown_fields)]
                struct Wire { $($(#[$field_attr])* $field: $ty),* }
                struct ObjectVisitor;
                impl<'de> serde::de::Visitor<'de> for ObjectVisitor {
                    type Value = $name;
                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str(concat!("an object for ", stringify!($name)))
                    }
                    fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                        let wire = Wire::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                        let Wire { $($field),* } = wire;
                        Ok($name { $($field),* })
                    }
                }
                deserializer.deserialize_map(ObjectVisitor)
            }
        }
    }
}
dto!(EnrollmentInitiateParams {
    client_id: PublicClientId,
    // Complete account-independent descriptor and self-signature, produced by
    // canonical crypto before approval. Authority derives host ID and all keys
    // from this descriptor; duplicate request claims are not accepted.
    key_commitment: HostKeyCommitmentHex,
    proof: EnrollmentProof
});
dto!(EnrollmentInitiateResult {
    enrollment_id: EnrollmentId,
    device_code: DeviceCode,
    user_code: UserCode,
    expires_in_seconds: DecimalU64,
    poll_interval_seconds: DecimalU64
});
// Server-owned extension of an enrolled Better Auth device-token response.
// The challenge carries enrollment/host/bootstrap/operation IDs; duplicate
// unsigned copies are unnecessary. Account approval is trusted TLS state.
dto!(HostEnrollmentTokenContext {
    account_id: AccountId,
    challenge: CanonicalCryptoCborHex
});
dto!(EnrollmentProof {
    canonical_cbor: CanonicalCryptoCborHex,
    signature: SignatureHex
});
/// Existing canonical public-bundle CBOR and its self-signature. Cryptographic
/// verification and account/subject/role binding remain mandatory in Rust crypto.
pub type SignedIdentityWire = EnrollmentProof;
dto!(HostAuthorizationExchangeParams {
    enrollment_id: EnrollmentId,
    host_id: HostId,
    operation_id: OperationId,
    bootstrap: EnrollmentBootstrapCredential,
    proof: EnrollmentProof
});
dto!(HostAuthorizationRefreshParams {
    host_authorization_id: HostAuthorizationId,
    host_id: HostId,
    rotation_id: OperationId,
    refresh: HostRefreshCredential,
    proof: EnrollmentProof
});
dto!(HostAuthorizationResult {
    account_id: AccountId,
    host_id: HostId,
    host_authorization_id: HostAuthorizationId,
    access: HostAccessCredential,
    refresh: HostRefreshCredential,
    rotation_id: OperationId,
    expires_in_seconds: DecimalU64
});
dto!(HostRegisterParams {
    host_id: HostId,
    identity: SignedIdentityWire
});
dto!(HostRegisterResult {
    host_id: HostId,
    host_access_epoch: DecimalU64
});
// Class and account management policy come only from the authenticated origin.
// Empty issuance is idempotent for that origin; a revoked origin cannot remint.
dto!(ConsumerAuthorizationIssueParams {});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConsumerClass {
    Web,
    Desktop,
    Mobile,
}
dto!(ConsumerAuthorizationContext {
    account_id: AccountId,
    consumer_authorization_id: ConsumerAuthorizationId,
    account_session_id: AccountSessionId,
    class: ConsumerClass,
    expires_at: DecimalU64,
    can_manage_account: bool
});
dto!(ConsumerAuthorizationRevokeParams {});
dto!(ConsumerAuthorizationRevokeResult {
    consumer_authorization_id: ConsumerAuthorizationId
});
dto!(ConsumerWindowRevokeParams {});
dto!(ConsumerWindowRevokeResult {
    window_identity_id: WindowIdentityId
});
dto!(ConsumerWindowChallengeParams {
    window_identity_id: WindowIdentityId,
    identity: SignedIdentityWire
});
dto!(ConsumerWindowChallengeResult {
    operation_id: OperationId,
    challenge: CanonicalCryptoCborHex
});
dto!(ConsumerWindowRegisterParams {
    window_identity_id: WindowIdentityId,
    operation_id: OperationId,
    proof: EnrollmentProof
});
dto!(ConsumerWindowRegisterResult {
    window_identity_id: WindowIdentityId,
    identity_fingerprint: IdentityFingerprintHex
});
// Read-only confirmation of an existing registration, scoped to the freshly
// authenticated authorization. This never extends a challenge or grants access.
dto!(ConsumerWindowGetResult {
    window_identity_id: WindowIdentityId,
    identity_fingerprint: IdentityFingerprintHex
});
dto!(RuntimeClaimParams {
    runtime_id: RuntimeId,
    expected_generation: DecimalU64
});
dto!(RuntimeBinding {
    runtime_id: RuntimeId,
    runtime_generation: DecimalU64,
    host_access_epoch: DecimalU64
});
// Host-only current-runtime snapshot for restart and lost-response CAS recovery.
// Generation zero has no runtime ID. Retain the monotonic generation even when
// the previous binding is unusable, and report the current host epoch separately.
// Return Some only for a binding in the current host epoch and current family;
// an expired lease may retain that binding with zero remaining durations for CAS.
// A revoked/stale-epoch binding is None, with zero effective publication sequence,
// lease and freshness. Durations are server assertions, never client authority.
// Like other HTTP DTOs, deserialization checks structure, not these state rules.
dto!(HostRuntimeGetResult {
    host_id: HostId,
    host_access_epoch: DecimalU64,
    runtime_generation: DecimalU64,
    runtime: Option<RuntimeBinding>,
    publication_seq: DecimalU64,
    lease_ms: DecimalU64,
    freshness_ms: DecimalU64
});
dto!(RuntimeClaimResult {
    runtime: RuntimeBinding,
    lease_ms: DecimalU64
});
dto!(HeartbeatParams {
    runtime: RuntimeBinding
});
dto!(HeartbeatResult {
    runtime: RuntimeBinding,
    lease_ms: DecimalU64,
    freshness_ms: DecimalU64
});
dto!(PublishedTerminal {
    pane_id: PaneId,
    session_id: TerminalSessionId,
    session_epoch: SessionEpoch
});
dto!(PublishedWorkspace {
    workspace_id: WorkspaceId,
    workspace_epoch: WorkspaceEpoch,
    terminals: PublicationTerminals
});

// Explicit implementations avoid macro type names inside serde string attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<PublishedTerminal>", into = "Vec<PublishedTerminal>")]
pub struct PublicationTerminals(Vec<PublishedTerminal>);
impl TryFrom<Vec<PublishedTerminal>> for PublicationTerminals {
    type Error = &'static str;
    fn try_from(v: Vec<PublishedTerminal>) -> Result<Self, Self::Error> {
        if v.len() > 4096
            || v.iter().enumerate().any(|(i, t)| {
                v[..i]
                    .iter()
                    .any(|p| p.pane_id == t.pane_id || p.session_id == t.session_id)
            })
        {
            Err("invalid terminal membership")
        } else {
            Ok(Self(v))
        }
    }
}
impl From<PublicationTerminals> for Vec<PublishedTerminal> {
    fn from(v: PublicationTerminals) -> Self {
        v.0
    }
}
impl PublicationTerminals {
    pub fn as_slice(&self) -> &[PublishedTerminal] {
        &self.0
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<PublishedWorkspace>", into = "Vec<PublishedWorkspace>")]
pub struct PublicationWorkspaces(Vec<PublishedWorkspace>);
impl TryFrom<Vec<PublishedWorkspace>> for PublicationWorkspaces {
    type Error = &'static str;
    fn try_from(v: Vec<PublishedWorkspace>) -> Result<Self, Self::Error> {
        let mut workspaces = BTreeSet::new();
        let mut panes = BTreeSet::new();
        let mut sessions = BTreeSet::new();
        if v.len() > 256
            || v.iter()
                .map(|w| w.terminals.as_slice().len())
                .sum::<usize>()
                > 4096
            || v.iter().any(|w| {
                !workspaces.insert(w.workspace_id)
                    || w.terminals
                        .as_slice()
                        .iter()
                        .any(|t| !panes.insert(t.pane_id) || !sessions.insert(t.session_id))
            })
        {
            Err("invalid workspace membership")
        } else {
            Ok(Self(v))
        }
    }
}
impl From<PublicationWorkspaces> for Vec<PublishedWorkspace> {
    fn from(v: PublicationWorkspaces) -> Self {
        v.0
    }
}
impl PublicationWorkspaces {
    pub fn as_slice(&self) -> &[PublishedWorkspace] {
        &self.0
    }
}
dto!(PublicationParams {
    runtime: RuntimeBinding,
    expected_publication_seq: DecimalU64,
    publication_seq: DecimalU64,
    workspaces: PublicationWorkspaces
});
dto!(PublicationResult {
    runtime: RuntimeBinding,
    publication_seq: DecimalU64
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Online,
    Offline,
    Publishing,
}
dto!(HostKeyCommitmentDescriptor {
    version: u8,
    host_id: [u8; 16],
    role: CommitmentHostRole,
    key_version: u32,
    identity_key: [u8; 32],
    channel_key: [u8; 32],
    mailbox_key: [u8; 32]
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentHostRole {
    Host,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CommitmentSignature(Vec<u8>);
impl<'de> Deserialize<'de> for CommitmentSignature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("signature must contain 64 bytes"));
        }
        Ok(Self(bytes))
    }
}
impl JsonSchema for CommitmentSignature {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CommitmentSignature".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type":"array","items":{"type":"integer","minimum":0,"maximum":255},"minItems":64,"maxItems":64})
    }
}
dto!(SignedHostKeyCommitmentWire {
    descriptor: HostKeyCommitmentDescriptor,
    signature: CommitmentSignature
});
dto!(InventoryHost {
    host_id: HostId,
    identity: SignedIdentityWire,
    identity_fingerprint: IdentityFingerprintHex,
    signed_commitment: SignedHostKeyCommitmentWire,
    initial_commitment: HostKeyCommitmentHex,
    runtime: RuntimeBinding,
    status: InventoryStatus,
    workspaces: PublicationWorkspaces
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<InventoryHost>", into = "Vec<InventoryHost>")]
pub struct InventoryHosts(Vec<InventoryHost>);
impl TryFrom<Vec<InventoryHost>> for InventoryHosts {
    type Error = &'static str;
    fn try_from(v: Vec<InventoryHost>) -> Result<Self, Self::Error> {
        let mut hosts = BTreeSet::new();
        if v.len() > 256 || v.iter().any(|h| !hosts.insert(h.host_id)) {
            Err("inventory budget exceeded")
        } else {
            Ok(Self(v))
        }
    }
}
impl From<InventoryHosts> for Vec<InventoryHost> {
    fn from(v: InventoryHosts) -> Self {
        v.0
    }
}
dto!(InventoryResult {
    authorization: ConsumerAuthorizationContext,
    hosts: InventoryHosts
});
// Full identities are registered by challenge/proof before use in pairing.
dto!(ConsumerWindow {
    window_identity_id: WindowIdentityId,
    identity: SignedIdentityWire
});
dto!(PairingCreateParams {
    operation_id: OperationId,
    host_id: HostId,
    workspace_id: WorkspaceId,
    workspace_epoch: WorkspaceEpoch,
    runtime: RuntimeBinding,
    window_identity_id: WindowIdentityId,
    requested_capabilities: CapabilitySet
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PairingStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}
dto!(SignedGrantWire {
    canonical_cbor: CanonicalCryptoCborHex,
    signature: SignatureHex
});
dto!(SignedChannelAdmissionWire {
    canonical_cbor: CanonicalCryptoCborHex,
    signature: SignatureHex
});
dto!(PeerIdentities {
    host: SignedIdentityWire,
    consumer: SignedIdentityWire,
    host_fingerprint: IdentityFingerprintHex,
    consumer_fingerprint: IdentityFingerprintHex
});
dto!(ChannelTerminalMembership {
    pane_id: PaneId,
    session_id: TerminalSessionId,
    session_epoch: SessionEpoch,
    terminal_profile: TerminalProfile
});
// Independently assembled from current authority rows in the admission
// transaction, never echoed from a submitted grant or channel context.
dto!(CurrentAuthorityBinding {
    host_authorization_id: HostAuthorizationId,
    consumer_authorization_id: ConsumerAuthorizationId,
    account_session_id: AccountSessionId,
    access_epoch: DecimalU64,
    grant_revision: DecimalU64,
    workspace_epoch: WorkspaceEpoch,
    runtime_id: RuntimeId,
    runtime_generation: DecimalU64,
    terminal_membership: Option<ChannelTerminalMembership>
});
dto!(PairingProposal {
    maximum_grant: CanonicalCryptoCborHex,
    identities: PeerIdentities,
    authority: CurrentAuthorityBinding
});
// This is a public contract DTO: boxing the large payload changes the Rust API
// without reducing its serialized wire representation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "status",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PairingResult {
    Pending {
        pairing_id: PairingId,
        proposal: PairingProposal,
    },
    Approved {
        pairing_id: PairingId,
        proposal: PairingProposal,
        grant: SignedGrantWire,
        identities: PeerIdentities,
        authority: CurrentAuthorityBinding,
    },
    Denied {
        pairing_id: PairingId,
    },
    Expired {
        pairing_id: PairingId,
    },
}
dto!(PendingPairing {
    pairing_id: PairingId,
    proposal: PairingProposal
});
// Server admission caps outstanding pending rows at this bounded poll size.
pub const MAX_PENDING_PAIRINGS: usize = 64;
pub const MAX_PENDING_CHANNELS: usize = 64;
dto!(PairingPendingResult {
    pairings: PendingPairings
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "decision", rename_all = "lowercase", deny_unknown_fields)]
pub enum PairingDecisionParams {
    Approve {
        grant: SignedGrantWire,
        runtime: RuntimeBinding,
    },
    Deny {
        runtime: RuntimeBinding,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "purpose",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ChannelTarget {
    Workspace {
        workspace_id: WorkspaceId,
        workspace_epoch: WorkspaceEpoch,
    },
    Terminal {
        workspace_id: WorkspaceId,
        workspace_epoch: WorkspaceEpoch,
        pane_id: PaneId,
        session_id: TerminalSessionId,
        session_epoch: SessionEpoch,
    },
}
dto!(ChannelCreateParams {
    operation_id: OperationId,
    grant_id: GrantId,
    grant_revision: DecimalU64,
    runtime: RuntimeBinding,
    target: ChannelTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    window_identity_id: Option<WindowIdentityId>
});
dto!(ChannelAdmissionInputs {
    expected_context: CanonicalCryptoCborHex,
    expected_context_json: serde_json::Map<String, serde_json::Value>,
    grant: SignedGrantWire,
    identities: PeerIdentities,
    authority: CurrentAuthorityBinding
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "status",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ChannelResult {
    Pending {
        channel_id: ChannelId,
        inputs: ChannelAdmissionInputs,
    },
    Admitted {
        channel_id: ChannelId,
        inputs: ChannelAdmissionInputs,
        admission: SignedChannelAdmissionWire,
    },
    Expired {
        channel_id: ChannelId,
    },
    Closed {
        channel_id: ChannelId,
    },
}
dto!(ChannelCreateResult {
    channel: ChannelResult
});
dto!(PendingChannel {
    channel_id: ChannelId,
    inputs: ChannelAdmissionInputs
});
dto!(ChannelPendingResult {
    channels: PendingChannels
});
dto!(ChannelAdmissionParams {
    runtime: RuntimeBinding,
    admission: SignedChannelAdmissionWire
});
dto!(ChannelTicketParams {
    runtime: RuntimeBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    window_identity_id: Option<WindowIdentityId>
});
dto!(ChannelTicketResult {
    channel_id: ChannelId,
    ticket: RelayTicket,
    expires_in_ms: DecimalU64
});
dto!(GrantRevokeParams {
    expected_grant_revision: DecimalU64
});
dto!(GrantRevokeResult {
    grant_id: GrantId,
    grant_revision: DecimalU64
});
dto!(HostRevokeParams {
    expected_host_access_epoch: DecimalU64
});
dto!(HostRevokeResult {
    host_id: HostId,
    host_access_epoch: DecimalU64
});
dto!(HostRevocationAckParams {
    host_authorization_id: HostAuthorizationId,
    expected_host_access_epoch: DecimalU64,
    /// Retained proof for an already-revoked family; grants no host access.
    refresh: HostRefreshCredential
});

// Historical enrollment proof used only to acknowledge retirement of that
// enrollment's already-revoked host authorization family, if one exists.
dto!(HostEnrollmentRevocationAckParams {
    enrollment_id: EnrollmentId,
    operation_id: OperationId,
    proof: EnrollmentProof
});

/// Closed, proof-only acknowledgement result. The no-family case deliberately
/// has no family ID or epoch fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "outcome",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostEnrollmentRevocationAckResult {
    RevokedFamily {
        host_id: HostId,
        enrollment_id: EnrollmentId,
        operation_id: OperationId,
        account_id: AccountId,
        host_authorization_id: HostAuthorizationId,
        #[serde(deserialize_with = "deserialize_positive_host_epoch")]
        #[schemars(schema_with = "positive_host_epoch_schema")]
        family_host_access_epoch: DecimalU64,
        #[serde(deserialize_with = "deserialize_positive_host_epoch")]
        #[schemars(schema_with = "positive_host_epoch_schema")]
        host_access_epoch: DecimalU64,
    },
    NoFamily {
        host_id: HostId,
        enrollment_id: EnrollmentId,
        operation_id: OperationId,
        account_id: AccountId,
    },
}

fn deserialize_positive_host_epoch<'de, D>(deserializer: D) -> Result<DecimalU64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let epoch = DecimalU64::deserialize(deserializer)?;
    if epoch.0 == 0 || epoch.0 > i64::MAX as u64 {
        return Err(serde::de::Error::custom("host epoch out of range"));
    }
    Ok(epoch)
}

fn positive_host_epoch_schema(_: &mut SchemaGenerator) -> Schema {
    let maximum = (i64::MAX as u64).to_string();
    let mut alternatives = vec!["[1-9][0-9]{0,17}".to_owned()];
    for (i, digit) in maximum.bytes().enumerate() {
        let low = if i == 0 { b'1' } else { b'0' };
        if digit > low {
            alternatives.push(format!(
                "{}[{}-{}][0-9]{{{}}}",
                &maximum[..i],
                low as char,
                (digit - 1) as char,
                maximum.len() - i - 1
            ));
        }
    }
    alternatives.push(maximum);
    json_schema!({
        "type": "string",
        "pattern": format!("^({})$", alternatives.join("|")),
        "minLength": 1,
        "maxLength": 19
    })
}

macro_rules! list_schema {
    ($name:ident, $item:ty, $max:literal) => {
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static,str> { stringify!($name).into() }
            fn json_schema(generator: &mut SchemaGenerator) -> Schema {
                json_schema!({"type":"array", "items":generator.subschema_for::<$item>(),"maxItems":$max, "uniqueItems":true})
            }
        }
    }
}
list_schema!(PublicationTerminals, PublishedTerminal, 4096);
list_schema!(PublicationWorkspaces, PublishedWorkspace, 256);
list_schema!(InventoryHosts, InventoryHost, 256);

macro_rules! pending_list {
    ($name:ident, $item:ty, $vec:literal, $id:ident, $max:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = $vec, into = $vec)]
        pub struct $name(Vec<$item>);
        impl TryFrom<Vec<$item>> for $name {
            type Error = &'static str;
            fn try_from(values: Vec<$item>) -> Result<Self, Self::Error> {
                let mut ids = BTreeSet::new();
                if values.len() > $max || values.iter().any(|v| !ids.insert(v.$id)) {
                    return Err("invalid bounded pending list");
                }
                Ok(Self(values))
            }
        }
        impl From<$name> for Vec<$item> {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl $name {
            pub fn as_slice(&self) -> &[$item] {
                &self.0
            }
        }
        list_schema!($name, $item, $max);
    };
}
pending_list!(
    PendingPairings,
    PendingPairing,
    "Vec<PendingPairing>",
    pairing_id,
    64
);
pending_list!(
    PendingChannels,
    PendingChannel,
    "Vec<PendingChannel>",
    channel_id,
    64
);

/// Validate bounded original HTTP JSON before dispatch. This checks the wire
/// schema only: signatures, trusted ownership, freshness and transaction effects
/// are separate server obligations. Unknown kinds and duplicate fields fail.
pub fn validate_http_wire(kind: &str, json: &str) -> Result<(), &'static str> {
    crate::json_wire::check_raw(json)?;
    macro_rules! kinds {
        ($($ty:ident),+ $(,)?) => {
            match kind {
                $(stringify!($ty) => serde_json::from_str::<$ty>(json).map(|_| ()).map_err(|_| "INVALID_ARGUMENT"),)+
                _ => Err("INVALID_ARGUMENT"),
            }
        }
    }
    kinds!(
        EnrollmentInitiateParams,
        EnrollmentInitiateResult,
        HostEnrollmentTokenContext,
        HostAuthorizationExchangeParams,
        HostAuthorizationRefreshParams,
        HostAuthorizationResult,
        HostRegisterParams,
        HostRegisterResult,
        ConsumerAuthorizationIssueParams,
        ConsumerAuthorizationContext,
        ConsumerAuthorizationRevokeParams,
        ConsumerAuthorizationRevokeResult,
        ConsumerWindowChallengeParams,
        ConsumerWindowChallengeResult,
        ConsumerWindowRegisterParams,
        ConsumerWindowRegisterResult,
        ConsumerWindowGetResult,
        ConsumerWindowRevokeParams,
        ConsumerWindowRevokeResult,
        HostRuntimeGetResult,
        RuntimeClaimParams,
        RuntimeClaimResult,
        HeartbeatParams,
        HeartbeatResult,
        PublicationParams,
        PublicationResult,
        InventoryResult,
        PairingCreateParams,
        PairingResult,
        PairingPendingResult,
        PairingDecisionParams,
        ChannelCreateParams,
        ChannelCreateResult,
        ChannelResult,
        ChannelPendingResult,
        ChannelAdmissionParams,
        ChannelTicketParams,
        ChannelTicketResult,
        GrantRevokeParams,
        GrantRevokeResult,
        HostRevokeParams,
        HostRevokeResult,
        HostRevocationAckParams,
        HostEnrollmentRevocationAckParams,
        HostEnrollmentRevocationAckResult,
    )
}
