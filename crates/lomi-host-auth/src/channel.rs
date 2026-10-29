//! Scoped use of the identity held by the validated protected HostAuth record.
use super::*;
use lomi_remote_crypto::{
    Channel, ChannelContextV3, CurrentAuthorityV3, GrantV3, Handshake, SignedChannelAdmissionV3,
    SignedGrantV3,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Public binding of the currently confirmed, fresh host credentials.
/// This contains no seed, bearer credential or general signing capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicHostIdentity {
    pub account_id: AccountId,
    pub host_id: HostId,
    pub identity: EnrollmentProof,
    pub fingerprint: [u8; 32],
    pub host_authorization_id: HostAuthorizationId,
    pub access_epoch: u64,
}

/// Inputs retained by the authority owner, independent of the received admission.
/// `expected` must reflect approved proposal narrowing, local consent, workspace
/// fence, runtime, capabilities, terminal membership and generation. This library
/// checks the canonical bindings; it does not make those authorization decisions.
pub struct HostChannelAdmissionV3<'a> {
    pub expected: &'a ChannelContextV3,
    pub stored_grant: &'a SignedGrantV3,
    pub admission: &'a SignedChannelAdmissionV3,
    pub consumer_identity: &'a SignedBundle,
    pub consumer_fingerprint: &'a [u8; 32],
    pub current_authority: &'a CurrentAuthorityV3,
}

impl<S: SecretStorage + ?Sized> HostAuth<'_, S> {
    /// Shared guard for every new scoped cryptographic operation. It uses only
    /// the existing validated record, never another provider load or identity.
    fn crypto_ready(&self, now: u64) -> Result<(&Record, &SignedBundle, &Credentials, u64)> {
        self.observe(now)?;
        self.crypto_ready_at(now)
    }

    // Internal freshness time must not advance the caller-owned observation
    // watermark: Unix-second projections may straddle a wall-clock second.
    fn crypto_ready_at(&self, now: u64) -> Result<(&Record, &SignedBundle, &Credentials, u64)> {
        let record = self.current()?;
        validate(record, &self.config)?;
        let State::Ready {
            signed,
            credentials,
            epoch,
            ..
        } = &record.lifecycle
        else {
            return Err(Error::InvalidState);
        };
        check_time(credentials.expires, now)?;
        Ok((record, signed, credentials, *epoch))
    }

    fn scoped_identity(&self, grant: &GrantV3, now: u64) -> Result<Identity> {
        self.observe(now)?;
        self.scoped_identity_at(grant, now)
    }

    fn scoped_identity_at(&self, grant: &GrantV3, now: u64) -> Result<Identity> {
        let (record, signed, credentials, epoch) = self.crypto_ready_at(now)?;
        crypto(grant.canonical())?;
        if grant.account_id != credentials.account.to_bytes()
            || grant.host_id != credentials.host.to_bytes()
            || grant.host_fingerprint != crypto(signed.bundle.fingerprint())?
            || grant.host_authorization_id != credentials.family.to_bytes()
            || grant.access_epoch != epoch
        {
            return Err(Error::InvalidBundle);
        }
        check_time(grant.expires_at, now)?;
        crypto(Identity::import_secret_seed_blob(&record.seed.0, signed))
    }

    pub fn public_host_identity(&self, now: u64) -> Result<PublicHostIdentity> {
        let (_, signed, credentials, epoch) = self.crypto_ready(now)?;
        Ok(PublicHostIdentity {
            account_id: credentials.account,
            host_id: credentials.host,
            identity: crypto(signed.to_wire())?,
            fingerprint: crypto(signed.bundle.fingerprint())?,
            host_authorization_id: credentials.family,
            access_epoch: epoch,
        })
    }

    /// Accept an authoritative runtime GET made with this current family's host
    /// access credential against the caller's independently pinned Remote API.
    /// The caller must authenticate TLS and recheck its store generation and
    /// volatile logout gate before calling; this method cannot verify transport.
    /// `expected_local_epoch` is the saved epoch captured for that request, not a
    /// clock. Only the confirmed epoch is synchronized, never runtime ownership,
    /// lease/readiness or local workspace context.
    pub fn accept_runtime_observation(
        &mut self,
        expected_local_epoch: DecimalU64,
        snapshot: HostRuntimeGetResult,
        now: u64,
    ) -> Result<()> {
        let (record, _, _, epoch) = self.crypto_ready(now)?;
        let maximum = i64::MAX as u64;
        if epoch != expected_local_epoch.0
            || epoch == 0
            || epoch > maximum
            || snapshot.host_id != record.config.host
            || snapshot.host_access_epoch.0 < epoch
            || snapshot.host_access_epoch.0 > maximum
            || snapshot.runtime_generation.0 > maximum
            || snapshot.publication_seq.0 > maximum
            || snapshot.lease_ms.0 > 30_000
            || snapshot.freshness_ms.0 > 5_000
            || snapshot.freshness_ms.0 > snapshot.lease_ms.0
        {
            return Err(Error::InvalidResponse);
        }
        match &snapshot.runtime {
            None if snapshot.publication_seq.0 != 0
                || snapshot.lease_ms.0 != 0
                || snapshot.freshness_ms.0 != 0 =>
            {
                return Err(Error::InvalidResponse);
            }
            Some(binding)
                if snapshot.runtime_generation.0 == 0
                    || binding.runtime_generation != snapshot.runtime_generation
                    || binding.host_access_epoch != snapshot.host_access_epoch =>
            {
                return Err(Error::InvalidResponse);
            }
            _ => {}
        }
        if snapshot.host_access_epoch.0 == epoch {
            return Ok(());
        }
        let mut next = record.clone();
        let State::Ready { epoch, .. } = &mut next.lifecycle else {
            return Err(Error::InvalidState);
        };
        *epoch = snapshot.host_access_epoch.0;
        self.commit(next)
    }

    /// The caller must independently authorize the proposal and all effect scope.
    pub fn sign_grant_v3(&self, grant: &GrantV3, now: u64) -> Result<SignedGrantV3> {
        crypto(self.scoped_identity(grant, now)?.sign_grant_v3(grant))
    }

    /// Signing is not a local-consent, workspace or runtime authorization decision.
    pub fn sign_channel_admission_v3(
        &self,
        context: &ChannelContextV3,
        now: u64,
    ) -> Result<SignedChannelAdmissionV3> {
        let identity = self.scoped_identity(&context.grant, now)?;
        if now < context.issued_at {
            return Err(Error::InvalidBundle);
        }
        check_time(context.expires_at, now)?;
        crypto(identity.sign_channel_admission_v3(context))
    }

    /// Create only a host responder. Neither the host identity nor its pin can
    /// be supplied by the caller. Admission is point-in-time; the parent must
    /// enforce current authority and an effect gate throughout channel use.
    pub fn start_host_channel_v3(
        &self,
        inputs: HostChannelAdmissionV3<'_>,
    ) -> Result<HostResponderHandshakeV3> {
        // Anchor before sampling wall time and before validation/crypto work.
        // Subsecond wall time is preserved; trusted time can only shorten life.
        let anchor = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Expired)?;
        self.start_host_channel_at(inputs, anchor, wall)
    }

    fn start_host_channel_at(
        &self,
        inputs: HostChannelAdmissionV3<'_>,
        anchor: Instant,
        wall: Duration,
    ) -> Result<HostResponderHandshakeV3> {
        let sampled = Instant::now();
        let (prior, prior_anchor) = self.crypto_clock.get();
        let projected = prior
            .checked_add(sampled.saturating_duration_since(prior_anchor))
            .ok_or(Error::Expired)?;
        // Project the earlier wall sample to this same Instant before choosing
        // a floor: pauses between sampling and retaining must count as age.
        let wall = wall
            .checked_add(sampled.saturating_duration_since(anchor))
            .ok_or(Error::Expired)?;
        let effective = wall.max(projected);
        // Retain the full internal freshness floor before any expiry/validation
        // failure. A later wall correction cannot revive expired authority, and
        // this never changes the external caller-owned observed watermark.
        self.crypto_clock.set((effective, sampled));
        let now = effective.as_secs();
        let remaining = Duration::from_secs(inputs.expected.expires_at)
            .checked_sub(effective)
            .filter(|duration| !duration.is_zero())
            .ok_or(Error::Expired)?;
        let deadline = sampled.checked_add(remaining).ok_or(Error::Expired)?;
        let identity = self.scoped_identity_at(&inputs.expected.grant, now)?;
        let host = identity.public_bundle();
        let pin = crypto(host.bundle.fingerprint())?;
        let verified = crypto(inputs.admission.verify(
            inputs.stored_grant,
            inputs.expected,
            &host,
            &pin,
            inputs.consumer_identity,
            inputs.consumer_fingerprint,
            inputs.current_authority,
            now,
        ))?;
        let handshake = crypto(Handshake::new_v3(
            false,
            &identity,
            verified,
            inputs.consumer_identity,
            inputs.consumer_fingerprint,
            now,
        ))?;
        let mut owned = HostResponderHandshakeV3 {
            handshake: Some(handshake),
            deadline,
            channel_id: inputs.expected.channel_id,
        };
        owned.check_deadline(Instant::now())?;
        Ok(owned)
    }
}

/// Owned responder with an immutable admission deadline; no caller clock or
/// deadline extension is accepted. Every failed operation permanently closes it.
pub struct HostResponderHandshakeV3 {
    handshake: Option<Handshake>,
    deadline: Instant,
    channel_id: [u8; 16],
}
impl HostResponderHandshakeV3 {
    fn check_deadline(&mut self, now: Instant) -> Result<()> {
        if now >= self.deadline {
            self.dispose();
            return Err(Error::Expired);
        }
        if self.handshake.is_none() {
            return Err(Error::InvalidState);
        }
        Ok(())
    }
    fn operate<T>(
        &mut self,
        mut clock: impl FnMut() -> Instant,
        operation: impl FnOnce(&mut Handshake) -> lomi_remote_crypto::Result<T>,
    ) -> Result<T> {
        self.check_deadline(clock())?;
        let result = operation(self.handshake.as_mut().ok_or(Error::InvalidState)?);
        // Check even when crypto failed, and never release late output.
        let deadline = self.check_deadline(clock());
        match (result, deadline) {
            (Ok(output), Ok(())) => Ok(output),
            (_, Err(error)) => {
                self.dispose();
                Err(error)
            }
            (Err(_), _) => {
                self.dispose();
                Err(Error::InvalidBundle)
            }
        }
    }
    pub fn read(&mut self, message: &[u8]) -> Result<()> {
        self.operate(Instant::now, |handshake| handshake.read(message))
    }
    pub fn write(&mut self) -> Result<Vec<u8>> {
        self.operate(Instant::now, Handshake::write)
    }
    pub fn finish(mut self) -> Result<HostChannelV3> {
        self.finish_with_clock(Instant::now)
    }
    fn finish_with_clock(&mut self, mut clock: impl FnMut() -> Instant) -> Result<HostChannelV3> {
        self.check_deadline(clock())?;
        let result = self.handshake.take().ok_or(Error::InvalidState)?.finish();
        // The handshake was consumed, so check only time after finishing.
        if clock() >= self.deadline {
            return Err(Error::Expired);
        }
        Ok(HostChannelV3 {
            channel: Some(crypto(result)?),
            channel_id: self.channel_id,
        })
    }
    pub fn dispose(&mut self) {
        self.handshake.take();
    }
}
impl Drop for HostResponderHandshakeV3 {
    fn drop(&mut self) {
        self.dispose();
    }
}

/// Established bounded encrypted transport. Admission expiry does not terminate
/// it. Routing is fixed to the admitted channel ID. The authority owner must
/// check ongoing authority before every effect.
pub struct HostChannelV3 {
    channel: Option<Channel>,
    channel_id: [u8; 16],
}
impl HostChannelV3 {
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut channel = self.channel.take().ok_or(Error::InvalidState)?;
        let output = crypto(channel.seal_binary(self.channel_id, plaintext))?;
        self.channel = Some(channel);
        Ok(output)
    }
    pub fn open(&mut self, frame: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut channel = self.channel.take().ok_or(Error::InvalidState)?;
        let output = crypto(channel.open_binary(self.channel_id, frame))?;
        self.channel = Some(channel);
        Ok(output)
    }
    pub fn dispose(&mut self) {
        self.channel.take();
    }
}
impl Drop for HostChannelV3 {
    fn drop(&mut self) {
        self.dispose();
    }
}
