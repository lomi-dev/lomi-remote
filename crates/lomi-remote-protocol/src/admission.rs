//! Pure admission checks. Callers must use trusted transaction snapshots and
//! existing crypto verification; this module implements no auth DB or ticket store.
use crate::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub(crate) fn admission_error(code: ErrorCode) -> RemoteError {
    RemoteError::new(code, false, Effect::None, ErrorDetails::empty(), None)
        .expect("valid admission error")
}
/// Opaque Better Auth session identity, separate from an approved UUID bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BetterAuthSessionId(AccountSessionId);
impl BetterAuthSessionId {
    pub fn new(value: AccountSessionId) -> Self {
        Self(value)
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentBootstrapSessionId(EnrollmentId);
impl EnrollmentBootstrapSessionId {
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, &'static str> {
        EnrollmentId::from_bytes(bytes).map(Self)
    }
    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_bytes()
    }
}
/// Adapter output from a trusted session store, never a deserializable request DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredPrincipal {
    OrdinaryAccount {
        account_id: AccountId,
        session_id: BetterAuthSessionId,
    },
    EnrollmentBootstrap {
        account_id: AccountId,
        host_id: HostId,
        enrollment_id: EnrollmentId,
        bootstrap_session_id: EnrollmentBootstrapSessionId,
    },
    HostAccess {
        account_id: AccountId,
        host_id: HostId,
        authorization_id: HostAuthorizationId,
        can_manage_account: bool,
    },
    HostRefresh {
        account_id: AccountId,
        host_id: HostId,
        authorization_id: HostAuthorizationId,
    },
    Consumer {
        account_id: AccountId,
        authorization_id: ConsumerAuthorizationId,
        account_session_id: AccountSessionId,
        can_manage_account: bool,
    },
}
/// Implement only at the server trust boundary. Validate expiry/revoke, immutable
/// ownership, credential audience and foreign keys before returning a record.
pub trait TrustedPrincipalStore {
    fn lookup(&self, credential: &str) -> Option<StoredPrincipal>;
}
#[derive(Clone)]
pub struct Principal(StoredPrincipal);
impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Principal([SERVER OWNED])")
    }
}
impl Principal {
    pub fn from_trusted_store(
        store: &impl TrustedPrincipalStore,
        credential: &str,
    ) -> Result<Self, RemoteError> {
        store
            .lookup(credential)
            .map(Self)
            .ok_or_else(|| admission_error(ErrorCode::AuthRequired))
    }
    fn account_id(&self) -> AccountId {
        match &self.0 {
            StoredPrincipal::OrdinaryAccount { account_id, .. }
            | StoredPrincipal::EnrollmentBootstrap { account_id, .. }
            | StoredPrincipal::HostAccess { account_id, .. }
            | StoredPrincipal::HostRefresh { account_id, .. }
            | StoredPrincipal::Consumer { account_id, .. } => *account_id,
        }
    }
}
/// Resource row resolved by the server from path/body IDs, in the same mutation
/// transaction as authorization. No request may supply ownership or peer class.
#[derive(Debug, Clone)]
pub struct StoredResourceBinding {
    pub account_id: AccountId,
    pub host_id: HostId,
    pub host_authorization_id: HostAuthorizationId,
    /// Full identity already verified against the retained enrollment commitment
    /// by canonical crypto. Never initialize this directly from request claims.
    pub host_identity: SignedIdentityWire,
    pub consumer_authorization_id: Option<ConsumerAuthorizationId>,
    pub enrollment_id: Option<EnrollmentId>,
    pub bootstrap_session_id: Option<EnrollmentBootstrapSessionId>,
}
/// This is policy checking, not authentication. Public initiation still requires
/// the caller's rate limiter; mutation adapters must recheck rows atomically.
pub fn authorize_http(
    route: HttpRoute,
    principal: Option<&Principal>,
    resource: Option<&StoredResourceBinding>,
) -> Result<(), RemoteError> {
    // This proof-only surface has its own trusted snapshot guard below. It may
    // never be authorized by any reusable principal or ordinary resource row.
    if matches!(
        route.contract().surface,
        HttpSurface::HostRevocationProof | HttpSurface::HostEnrollmentRevocationProof
    ) {
        return Err(admission_error(ErrorCode::AuthRequired));
    }
    if route == HttpRoute::EnrollmentInitiate {
        return Ok(());
    }
    let p = principal.ok_or_else(|| admission_error(ErrorCode::AuthRequired))?;
    if route.contract().surface == HttpSurface::OrdinarySession {
        return if matches!(p.0, StoredPrincipal::OrdinaryAccount { .. }) {
            Ok(())
        } else {
            Err(admission_error(ErrorCode::ScopeDenied))
        };
    }
    if route == HttpRoute::Inventory || route.contract().surface == HttpSurface::ConsumerIdentity {
        return if matches!(p.0, StoredPrincipal::Consumer { .. }) {
            Ok(())
        } else {
            Err(admission_error(ErrorCode::ScopeDenied))
        };
    }
    let r = resource.ok_or_else(|| admission_error(ErrorCode::ScopeDenied))?;
    if p.account_id() != r.account_id {
        return Err(admission_error(ErrorCode::ScopeDenied));
    }
    let owns_host = matches!(&p.0, StoredPrincipal::HostAccess { host_id, authorization_id, .. } if *host_id == r.host_id && *authorization_id == r.host_authorization_id);
    let owns_consumer = matches!(&p.0, StoredPrincipal::Consumer { authorization_id, .. } if Some(*authorization_id) == r.consumer_authorization_id);
    let allowed = match route.contract().surface {
        HttpSurface::PublicEnrollment => true,
        HttpSurface::EnrollmentBootstrap => {
            matches!(&p.0, StoredPrincipal::EnrollmentBootstrap { host_id, enrollment_id, bootstrap_session_id, .. } if *host_id == r.host_id && Some(*enrollment_id) == r.enrollment_id && Some(*bootstrap_session_id) == r.bootstrap_session_id)
        }
        HttpSurface::HostRefresh => {
            matches!(&p.0, StoredPrincipal::HostRefresh { host_id, authorization_id, .. } if *host_id == r.host_id && *authorization_id == r.host_authorization_id)
        }
        HttpSurface::HostAccess => owns_host,
        HttpSurface::ConsumerSession => matches!(p.0, StoredPrincipal::Consumer { .. }),
        HttpSurface::EitherOwnPeer => owns_host || owns_consumer,
        HttpSurface::SelfHostOrOwnerAccount => {
            owns_host
                || matches!(
                    &p.0,
                    StoredPrincipal::Consumer {
                        can_manage_account: true,
                        ..
                    }
                )
        }
        HttpSurface::ConsumerManagement => {
            matches!(p.0, StoredPrincipal::OrdinaryAccount { .. })
                || matches!(
                    p.0,
                    StoredPrincipal::Consumer {
                        can_manage_account: true,
                        ..
                    }
                )
        }
        // Handled before host resource lookup; no host binding is required.
        HttpSurface::OrdinarySession
        | HttpSurface::ConsumerIdentity
        | HttpSurface::HostRevocationProof
        | HttpSurface::HostEnrollmentRevocationProof => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(admission_error(ErrorCode::ScopeDenied))
    }
}

/// Read-only trusted rows used only to acknowledge an already-revoked host
/// authorization family. No request or `Principal` can construct this proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRevocationAckSnapshot {
    /// Host selected by the path and loaded from trusted storage.
    pub host_id: HostId,
    pub host_account_id: AccountId,
    /// Family selected by the requested authorization ID and loaded from storage.
    pub family_host_authorization_id: HostAuthorizationId,
    pub family_host_id: HostId,
    pub family_account_id: AccountId,
    /// The supplied refresh secret hashes to a retained credential row for this
    /// exact family. The adapter must compare the complete stored hash.
    pub refresh_secret_hash_matches_family: bool,
    pub family_revoked: bool,
    pub family_host_access_epoch: u64,
    pub current_host_access_epoch: u64,
}

/// Implement at the trusted storage boundary with a read-only snapshot. The
/// lookup consumes the path host, requested family and submitted refresh secret.
/// It must establish exact retained-secret hash membership for that family.
/// Retained expired or consumed refresh secrets may match only when that family
/// is already revoked; a live family is rejected by the specialized guard even
/// if its current refresh credential matches. Wrong or missing proofs fail.
/// This contract performs no authority DML and returns no reusable authority.
pub trait TrustedHostRevocationAckStore {
    fn lookup_revocation_ack(
        &self,
        path_host_id: HostId,
        family_host_authorization_id: HostAuthorizationId,
        refresh_secret: &str,
    ) -> Option<HostRevocationAckSnapshot>;
}

/// Validate the one-purpose revocation proof against a trusted storage
/// snapshot. This must be called instead of `authorize_http` for this route.
/// The only success value is the host's committed revocation acknowledgement;
/// it contains no principal, session or capabilities.
pub fn authorize_host_revocation_ack(
    path_host_id: HostId,
    request: &HostRevocationAckParams,
    store: &impl TrustedHostRevocationAckStore,
) -> Result<HostRevokeResult, RemoteError> {
    let snapshot = store
        .lookup_revocation_ack(
            path_host_id,
            request.host_authorization_id,
            request.refresh.expose_wire(),
        )
        .ok_or_else(|| admission_error(ErrorCode::AuthRequired))?;
    let requested_epoch = request.expected_host_access_epoch.0;
    if snapshot.host_id != path_host_id
        || snapshot.family_host_authorization_id != request.host_authorization_id
        || snapshot.family_host_id != path_host_id
        || snapshot.host_account_id != snapshot.family_account_id
        || !snapshot.refresh_secret_hash_matches_family
        || !snapshot.family_revoked
        || requested_epoch == 0
        || requested_epoch > i64::MAX as u64
        || requested_epoch != snapshot.family_host_access_epoch
        || snapshot.current_host_access_epoch < snapshot.family_host_access_epoch
    {
        return Err(admission_error(ErrorCode::AuthRequired));
    }
    Ok(HostRevokeResult {
        host_id: path_host_id,
        host_access_epoch: DecimalU64(snapshot.current_host_access_epoch),
    })
}

/// Family state resolved from trusted storage for one exact historical
/// enrollment. `NoFamily` is returned only after an exhaustive lookup confirms
/// there is no family for that enrollment; it does not imply a current host
/// identity row exists. Live families, missing rows and inconsistent state
/// must make the adapter return `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEnrollmentRevocationFamilySnapshot {
    NoFamily,
    RevokedFamily {
        host_authorization_id: HostAuthorizationId,
        host_id: HostId,
        /// Current owner from the committed host identity associated with this family.
        host_account_id: AccountId,
        account_id: AccountId,
        family_host_access_epoch: u64,
        host_access_epoch: u64,
    },
}

/// Read-only rows used to acknowledge retirement of one historical enrollment.
/// The trusted adapter verifies the submitted signature against the exact
/// retained enrollment key commitment and DB challenge, and binds its account,
/// operation, enrollment and proof-derived host to the path before returning
/// this snapshot. A host identity row is needed only for `RevokedFamily`, where
/// the current owner is included in that variant. It checks no current
/// enrollment TTL; approval, revocation and consumption are historical DB
/// facts for the guard to validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEnrollmentRevocationAckSnapshot {
    /// Host derived from the exact historical enrollment proof and bound to the path.
    pub host_id: HostId,
    /// Exact historical enrollment selected from the request and DB challenge.
    pub enrollment_id: EnrollmentId,
    pub operation_id: OperationId,
    pub account_id: AccountId,
    pub approved: bool,
    pub enrollment_revoked: bool,
    pub consumed: bool,
    pub family: HostEnrollmentRevocationFamilySnapshot,
}

/// Implement at the trusted storage/crypto boundary with a read-only snapshot.
/// The lookup receives the complete request so signature verification uses the
/// submitted proof, exact historical key commitment and DB challenge. It must
/// bind the request IDs and path host to the returned rows and classify only an
/// exact already-revoked family or a confirmed absence for this enrollment.
/// Return `None` for missing/wrong proof, a live family or inconsistent state.
pub trait TrustedHostEnrollmentRevocationAckStore {
    fn lookup_enrollment_revocation_ack(
        &self,
        path_host_id: HostId,
        request: &HostEnrollmentRevocationAckParams,
    ) -> Option<HostEnrollmentRevocationAckSnapshot>;
}

/// Validate a historical enrollment proof against a trusted snapshot. This
/// route is proof-only and must use this guard instead of `authorize_http`.
/// Success returns only the exact revocation acknowledgement result. A
/// `NoFamily` result requires an approved, revoked, unconsumed enrollment; a
/// matching already-revoked family may acknowledge after exchange consumed the
/// enrollment challenge or before the enrollment itself is revoked.
pub fn authorize_host_enrollment_revocation_ack(
    path_host_id: HostId,
    request: &HostEnrollmentRevocationAckParams,
    store: &impl TrustedHostEnrollmentRevocationAckStore,
) -> Result<HostEnrollmentRevocationAckResult, RemoteError> {
    let snapshot = store
        .lookup_enrollment_revocation_ack(path_host_id, request)
        .ok_or_else(|| admission_error(ErrorCode::AuthRequired))?;
    if snapshot.host_id != path_host_id
        || snapshot.enrollment_id != request.enrollment_id
        || snapshot.operation_id != request.operation_id
        || !snapshot.approved
    {
        return Err(admission_error(ErrorCode::AuthRequired));
    }
    match snapshot.family {
        HostEnrollmentRevocationFamilySnapshot::NoFamily => {
            if !snapshot.enrollment_revoked || snapshot.consumed {
                return Err(admission_error(ErrorCode::AuthRequired));
            }
            Ok(HostEnrollmentRevocationAckResult::NoFamily {
                host_id: path_host_id,
                enrollment_id: request.enrollment_id,
                operation_id: request.operation_id,
                account_id: snapshot.account_id,
            })
        }
        HostEnrollmentRevocationFamilySnapshot::RevokedFamily {
            host_authorization_id,
            host_id,
            host_account_id,
            account_id,
            family_host_access_epoch,
            host_access_epoch,
        } => {
            let valid_epoch = |epoch: u64| epoch != 0 && epoch <= i64::MAX as u64;
            if host_id != path_host_id
                || host_account_id != snapshot.account_id
                || account_id != snapshot.account_id
                || !valid_epoch(family_host_access_epoch)
                || !valid_epoch(host_access_epoch)
                || family_host_access_epoch > host_access_epoch
            {
                return Err(admission_error(ErrorCode::AuthRequired));
            }
            Ok(HostEnrollmentRevocationAckResult::RevokedFamily {
                host_id: path_host_id,
                enrollment_id: request.enrollment_id,
                operation_id: request.operation_id,
                account_id: snapshot.account_id,
                host_authorization_id,
                family_host_access_epoch: DecimalU64(family_host_access_epoch),
                host_access_epoch: DecimalU64(host_access_epoch),
            })
        }
    }
}

/// Policy comparison after canonical crypto verifies the complete finalized
/// bundle against the retained commitment and account. This is not a signature
/// verifier and cannot establish trust in a resource built from request claims.
pub fn validate_host_registration(
    request: &HostRegisterParams,
    principal: &Principal,
    resource: &StoredResourceBinding,
) -> Result<(), RemoteError> {
    authorize_http(HttpRoute::HostRegister, Some(principal), Some(resource))?;
    if request.host_id != resource.host_id || request.identity != resource.host_identity {
        return Err(admission_error(ErrorCode::ScopeDenied));
    }
    Ok(())
}

/// Check a publication against the authoritative previous row before persisting.
/// Empty workspaces are valid; no session is inferred from terminal counts.
pub fn validate_publication(
    request: &PublicationParams,
    current: &PublicationResult,
) -> Result<(), RemoteError> {
    if request.runtime != current.runtime {
        return Err(admission_error(ErrorCode::StaleEpoch));
    }
    if request.expected_publication_seq != current.publication_seq
        || current.publication_seq.0.checked_add(1) != Some(request.publication_seq.0)
    {
        return Err(RemoteError::new(
            ErrorCode::RevisionConflict,
            false,
            Effect::None,
            ErrorDetails::Revision(RevisionErrorDetails {
                expected_revision: request.expected_publication_seq,
                actual_revision: current.publication_seq,
            }),
            None,
        )
        .expect("valid CAS error"));
    }
    Ok(())
}
/// Validate an actual resource against the latest committed publication. This
/// does not validate grant signatures, capability rights, revocation or freshness.
pub fn validate_published_target(
    request: &ChannelCreateParams,
    publication: &PublicationParams,
) -> Result<(), RemoteError> {
    if request.runtime != publication.runtime {
        return Err(admission_error(ErrorCode::StaleEpoch));
    }
    let (id, epoch) = match request.target {
        ChannelTarget::Workspace {
            workspace_id,
            workspace_epoch,
        }
        | ChannelTarget::Terminal {
            workspace_id,
            workspace_epoch,
            ..
        } => (workspace_id, workspace_epoch),
    };
    let w = publication
        .workspaces
        .as_slice()
        .iter()
        .find(|w| w.workspace_id == id && w.workspace_epoch == epoch)
        .ok_or_else(|| admission_error(ErrorCode::WorkspaceUnshared))?;
    if let ChannelTarget::Terminal {
        pane_id,
        session_id,
        session_epoch,
        ..
    } = request.target
        && !w.terminals.as_slice().iter().any(|t| {
            t.pane_id == pane_id && t.session_id == session_id && t.session_epoch == session_epoch
        })
    {
        return Err(admission_error(ErrorCode::WorkspaceUnshared));
    }
    Ok(())
}

/// Routine E0 proposal, independent from crypto proof TTL and not qualification.
pub const WSS_ADMISSION_MAX_BYTES: usize = 16 * 1024;
pub const WSS_ADMISSION_TIMEOUT_MS: u64 = 5_000;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WssAdmissionFrame {
    pub channel_id: ChannelId,
    pub ticket: RelayTicket,
}
/// Caller-provided authority must atomically verify and consume the one-use
/// ticket, binding channel/peer/expiry and current grant/runtime/membership.
/// A bool supplied by a request cannot implement this boundary.
pub trait OneUseTicketAuthority {
    fn verify_and_consume(&mut self, frame: &WssAdmissionFrame) -> Result<(), RemoteError>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionPhase {
    Awaiting,
    Verifying,
    Admitted,
    Closed,
}
#[derive(Debug)]
pub struct WssAdmission {
    deadline: Instant,
    phase: AdmissionPhase,
}
impl WssAdmission {
    pub fn new(accepted_at: Instant) -> Self {
        Self {
            deadline: accepted_at + Duration::from_millis(WSS_ADMISSION_TIMEOUT_MS),
            phase: AdmissionPhase::Awaiting,
        }
    }
    pub fn admit(
        &mut self,
        bytes: &[u8],
        authority: &mut impl OneUseTicketAuthority,
        mut now: impl FnMut() -> Instant,
    ) -> Result<(), RemoteError> {
        if self.phase != AdmissionPhase::Awaiting {
            self.phase = AdmissionPhase::Closed;
            return Err(admission_error(ErrorCode::AuthRequired));
        }
        self.phase = AdmissionPhase::Closed;
        if now() >= self.deadline {
            return Err(admission_error(ErrorCode::DeadlineExceeded));
        }
        if bytes.len() > WSS_ADMISSION_MAX_BYTES {
            return Err(admission_error(ErrorCode::ResourceExhausted));
        }
        let frame: WssAdmissionFrame = serde_json::from_slice(bytes)
            .map_err(|_| admission_error(ErrorCode::InvalidArgument))?;
        if now() >= self.deadline {
            return Err(admission_error(ErrorCode::DeadlineExceeded));
        }
        self.phase = AdmissionPhase::Verifying;
        let verified = authority.verify_and_consume(&frame);
        self.phase = AdmissionPhase::Closed;
        if now() >= self.deadline {
            return Err(admission_error(ErrorCode::DeadlineExceeded));
        }
        verified?;
        self.phase = AdmissionPhase::Admitted;
        Ok(())
    }
    /// Transport must call before routing each payload; URL tickets are not an input.
    pub fn authorize_payload(&self) -> Result<(), RemoteError> {
        if self.phase == AdmissionPhase::Admitted {
            Ok(())
        } else {
            Err(admission_error(ErrorCode::AuthRequired))
        }
    }
}
