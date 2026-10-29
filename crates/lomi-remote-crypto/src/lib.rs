//! Imported historical live-profile implementation plus isolated enrollment proof.
//! Historical qualification constants do not qualify Remote API 2 or grant/context 3.
mod approval;
#[cfg(feature = "browser")]
mod browser;
#[cfg(feature = "browser")]
mod browser_authority;
#[cfg(feature = "browser")]
mod browser_authority_v3;
#[cfg(feature = "browser")]
mod browser_v3;
mod channel;
mod enrollment;
mod enrollment_wire;
pub use enrollment_wire::{
    HostEnrollmentChallengeContext, prepare_host_enrollment_challenge,
    verify_host_enrollment_proof, verify_host_key_initiation,
};
mod grant_v3;
mod grant_v3_wire;
pub use grant_v3_wire::verify_grant_proposal_v3;
mod host_key_enrollment;
mod host_refresh;
pub use host_refresh::{
    HOST_REFRESH_PROOF_DOMAIN, HostRefreshContext, HostRefreshStatement,
    prepare_host_refresh_statement, verify_host_refresh_proof,
};
mod identity;
pub use grant_v3::{
    CONTEXT_V3_DOMAIN, ChannelContextV3, ChannelPurposeV3, CurrentAuthorityV3, GRANT_V3_DOMAIN,
    GrantPurposeV3, GrantV3, SignedChannelAdmissionV3, SignedGrantV3, TerminalTargetV3,
    VerifiedChannelContextV3,
};
pub use host_key_enrollment::{
    AccountIndependentHostKey, HOST_KEY_COMMITMENT_DOMAIN, PendingHostIdentity,
    SignedHostKeyCommitment,
};
mod mailbox;
mod wire;
pub use approval::{PeerApproval, Permissions, SignedPeerApproval, pairing_fingerprint};
pub use channel::{Channel, Handshake, TransportFrame};
pub use enrollment::{ENROLLMENT_PROOF_DOMAIN, EnrollmentChallenge, SignedEnrollmentProof};
pub use identity::{Identity, PublicBundle, SignedBundle};
pub const REMOTE_V2_PRODUCTION_QUALIFIED: bool = false;
pub use mailbox::{Envelope, EnvelopeMetadata, MailboxPolicy};
pub use wire::{ChannelContext, ChannelPurpose, Role};
pub type Result<T> = std::result::Result<T, String>;
pub const PROFILE: &str = "lomi-remote-live-v1";
pub const MAX_PLAINTEXT: usize = 16 * 1024;
pub const MAX_MAILBOX_PAYLOAD: usize = 8 * 1024;
pub const MAX_JSON: usize = 128 * 1024;
pub const PRODUCTION_QUALIFIED: bool = false;
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom04::fill(&mut bytes).map_err(|_| "entropy unavailable")?;
    Ok(bytes)
}

pub const LIVE_PRODUCTION_QUALIFIED: bool = true;
pub const MAILBOX_PRODUCTION_QUALIFIED: bool = false;


mod public_identity_wire;
pub use public_identity_wire::{verify_consumer_window_identity, verify_registered_host_identity};
mod consumer_window;
pub use consumer_window::{
    CONSUMER_WINDOW_PROOF_DOMAIN, ConsumerWindowChallenge, ConsumerWindowChallengeContext,
    ConsumerWindowProofBinding, prepare_consumer_window_challenge, verify_consumer_window_proof,
};
