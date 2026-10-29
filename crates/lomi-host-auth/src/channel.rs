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

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_crypto::{ChannelContext, Role};

    #[test]
    fn internal_start_time_does_not_advance_the_external_clock_watermark() {
        use lomi_platform::secrets::{ProviderKind, ProviderStatus};
        use lomi_remote_crypto::{ChannelPurposeV3, GrantPurposeV3};

        // This provider exists only to run validated in-memory record commits.
        struct Memory;
        impl SecretStorage for Memory {
            fn status(&self) -> ProviderStatus {
                ProviderStatus {
                    kind: Some(ProviderKind::ProtectedFile),
                    state: StorageState::Available,
                }
            }
            fn load(&self) -> std::result::Result<Option<SecretBundle>, secrets::Error> {
                Ok(None)
            }
            fn replace(&mut self, _: &SecretBundle) -> std::result::Result<(), secrets::Error> {
                Ok(())
            }
        }
        for scenario in 0..3 {
            let host_id = HostId::from_bytes([2; 16]).unwrap();
            let account = AccountId::from_bytes([1; 16]).unwrap();
            let config = Config::new(
                host_id,
                IpcProfileId::from_bytes([3; 16]).unwrap(),
                "https://auth.example".into(),
                "host".to_owned().try_into().unwrap(),
            )
            .unwrap();
            let mut storage = Memory;
            let mut auth = HostAuth::open(&mut storage, config.clone(), 100).unwrap();
            let pending = PendingHostIdentity::generate(host_id.to_bytes(), 1).unwrap();
            let commitment = pending.signed_commitment().unwrap();
            let pin = commitment.descriptor.commitment().unwrap();
            let seed = pending.export_secret_seed_blob().unwrap();
            let identity = pending.finalize(account.to_bytes(), &pin).unwrap();
            let signed = identity.public_bundle();
            auth.commit(Record {
                version: 3,
                observed_at: 100,
                config,
                seed: Seed(seed),
                commitment,
                pin,
                account_pin: Some(AccountPin {
                    account: Some(account),
                }),
                lifecycle: State::Ready {
                    account,
                    signed: signed.clone(),
                    epoch: 12,
                    credentials: Credentials {
                        account,
                        host: host_id,
                        family: HostAuthorizationId::from_bytes([4; 16]).unwrap(),
                        access: Text::new("access_secret".into()),
                        refresh: Text::new("refresh_secret".into()),
                        operation: OperationId::from_bytes([5; 16]).unwrap(),
                        expires: 400,
                    },
                },
            })
            .unwrap();
            let consumer =
                Identity::generate(account.to_bytes(), [6; 16], Role::Device, 1).unwrap();
            let peer = consumer.public_bundle();
            let consumer_pin = peer.bundle.fingerprint().unwrap();
            let grant = GrantV3 {
                version: 3,
                api_major: 2,
                application_major: 2,
                account_id: account.to_bytes(),
                host_id: host_id.to_bytes(),
                host_fingerprint: signed.bundle.fingerprint().unwrap(),
                host_authorization_id: [4; 16],
                access_epoch: 12,
                consumer_authorization_id: [7; 16],
                account_session_id: "session".into(),
                consumer_id: [6; 16],
                consumer_fingerprint: consumer_pin,
                grant_id: [8; 16],
                grant_revision: 1,
                workspace_id: [9; 16],
                workspace_epoch: [10; 16],
                runtime_id: [11; 16],
                runtime_generation: 1,
                capabilities: CapabilitySet::try_from(vec![Capability::WorkspaceRead]).unwrap(),
                nonce: [12; 32],
                expires_at: 200,
                purpose: GrantPurposeV3::Workspace,
            };
            let context = ChannelContextV3 {
                version: 3,
                grant: grant.clone(),
                channel_id: [13; 16],
                initiator_role: Role::Device,
                responder_role: Role::Host,
                purpose: ChannelPurposeV3::Workspace,
                terminal: None,
                issued_at: 100,
                expires_at: 130,
            };
            let current = CurrentAuthorityV3 {
                host_authorization_id: grant.host_authorization_id,
                consumer_authorization_id: grant.consumer_authorization_id,
                account_session_id: grant.account_session_id.clone(),
                access_epoch: grant.access_epoch,
                grant_revision: grant.grant_revision,
                workspace_epoch: grant.workspace_epoch,
                runtime_id: grant.runtime_id,
                runtime_generation: grant.runtime_generation,
                terminal_membership: None,
            };
            let signed_grant = auth.sign_grant_v3(&grant, 100).unwrap();
            let admission = auth.sign_channel_admission_v3(&context, 100).unwrap();
            if scenario == 0 {
                let responder = auth
                    .start_host_channel_at(
                        HostChannelAdmissionV3 {
                            expected: &context,
                            stored_grant: &signed_grant,
                            admission: &admission,
                            consumer_identity: &peer,
                            consumer_fingerprint: &consumer_pin,
                            current_authority: &current,
                        },
                        Instant::now(),
                        Duration::from_millis(101_100),
                    )
                    .unwrap();
                drop(responder);
            } else if scenario == 1 {
                // The first attempt at the forward wall time is already expired. Its
                // internal floor must be retained even though no responder is returned.
                for wall in [Duration::from_millis(131_125), Duration::from_secs(120)] {
                    let result = auth.start_host_channel_at(
                        HostChannelAdmissionV3 {
                            expected: &context,
                            stored_grant: &signed_grant,
                            admission: &admission,
                            consumer_identity: &peer,
                            consumer_fingerprint: &consumer_pin,
                            current_authority: &current,
                        },
                        Instant::now(),
                        wall,
                    );
                    assert!(matches!(result, Err(Error::Expired)));
                    assert!(auth.crypto_clock.get().0 >= Duration::from_millis(131_125));
                }
            } else {
                // Wall 110 was sampled alongside private time 100, then a
                // 25-second pause occurred before retention. Its effective wall
                // age is at least 135, so even the first attempt is expired.
                let old_anchor = Instant::now() - Duration::from_secs(25);
                auth.crypto_clock
                    .set((Duration::from_secs(100), old_anchor));
                for (anchor, wall) in [
                    (old_anchor, Duration::from_secs(110)),
                    (Instant::now(), Duration::from_secs(120)),
                ] {
                    let result = auth.start_host_channel_at(
                        HostChannelAdmissionV3 {
                            expected: &context,
                            stored_grant: &signed_grant,
                            admission: &admission,
                            consumer_identity: &peer,
                            consumer_fingerprint: &consumer_pin,
                            current_authority: &current,
                        },
                        anchor,
                        wall,
                    );
                    assert!(matches!(result, Err(Error::Expired)));
                    assert!(auth.crypto_clock.get().0 >= Duration::from_secs(135));
                }
            }
            // The internal conservative time crossed a second; caller projection
            // still says 100. Neither ordinary access nor a durable rotation fails.
            assert_eq!(auth.observed.get(), 100);
            auth.access_credential(100).unwrap();
            auth.prepare_rotation(100).unwrap();
            assert_eq!(auth.record.as_ref().unwrap().observed_at, 100);
            assert_eq!(auth.access_credential(99), Err(Error::ClockRollback));
            assert_eq!(auth.rotation_request(99), Err(Error::ClockRollback));
        }
    }

    // Exercise the wrapper's lifecycle with actual Noise operations. The public
    // v3 construction and authority path are covered by the integration test.
    fn pair() -> (Handshake, Handshake) {
        let host = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
        let consumer = Identity::generate([1; 16], [3; 16], Role::Device, 1).unwrap();
        let context = ChannelContext {
            version: 1,
            account_id: [1; 16],
            host_id: [2; 16],
            device_id: [3; 16],
            initiator_role: Role::Device,
            responder_role: Role::Host,
            channel_id: [5; 16],
            grant_id: [4; 16],
            session_id: [6; 16],
            workspace_id: None,
            workspace_epoch: None,
            session_epoch: None,
            purpose: None,
            access_epoch: 1,
            revision: 1,
        };
        let h = host.public_bundle();
        let c = consumer.public_bundle();
        (
            Handshake::new(
                true,
                &consumer,
                &context,
                &h,
                &h.bundle.fingerprint().unwrap(),
            )
            .unwrap(),
            Handshake::new(false, &host, &context, &c, &c.bundle.fingerprint().unwrap()).unwrap(),
        )
    }
    fn clock(before: Instant, after: Instant) -> impl FnMut() -> Instant {
        let mut first = true;
        move || {
            if std::mem::take(&mut first) {
                before
            } else {
                after
            }
        }
    }
    #[test]
    fn read_and_write_check_before_and_after_and_permanently_close() {
        for write in [false, true] {
            for cross_during in [false, true] {
                let (mut client, mut responder) = pair();
                let message = client.write().unwrap();
                if write {
                    responder.read(&message).unwrap();
                }
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut owned = HostResponderHandshakeV3 {
                    handshake: Some(responder),
                    deadline,
                    channel_id: [7; 16],
                };
                let before = if cross_during {
                    deadline - Duration::from_nanos(1)
                } else {
                    deadline
                };
                let result = owned.operate(clock(before, deadline), |h| {
                    if write {
                        h.write().map(|_| ())
                    } else {
                        h.read(&message)
                    }
                });
                assert_eq!(result, Err(Error::Expired));
                assert!(owned.handshake.is_none());
                // Even a hypothetical earlier clock cannot resurrect state.
                assert_eq!(
                    owned.operate(|| before - Duration::from_secs(1), |_| Ok(())),
                    Err(Error::InvalidState)
                );
            }
        }
    }
    #[test]
    fn finish_checks_before_and_after_and_established_transport_outlives_admission() {
        for expire in [0, 1, 2] {
            let (mut client, mut responder) = pair();
            responder.read(&client.write().unwrap()).unwrap();
            client.read(&responder.write().unwrap()).unwrap();
            responder.read(&client.write().unwrap()).unwrap();
            let deadline = Instant::now() - Duration::from_secs(1);
            let before = deadline - Duration::from_nanos(1);
            let mut owned = HostResponderHandshakeV3 {
                handshake: Some(responder),
                deadline,
                channel_id: [7; 16],
            };
            let mut ticks = clock(
                if expire == 0 { deadline } else { before },
                if expire == 1 { deadline } else { before },
            );
            let result = owned.finish_with_clock(&mut ticks);
            if expire < 2 {
                assert!(matches!(result, Err(Error::Expired)));
                assert!(owned.handshake.is_none());
            } else {
                // Private clock simulates completion before a deadline which is
                // now past. Established transport has no admission-clock check.
                let mut host = result.unwrap();
                let mut browser = client.finish().unwrap();
                let frame = host.seal(b"after admission").unwrap();
                assert_eq!(
                    &**browser.open_binary([7; 16], &frame).unwrap(),
                    b"after admission"
                );
                let frame = browser
                    .seal_binary([7; 16], b"still current authority required")
                    .unwrap();
                assert_eq!(
                    &**host.open(&frame).unwrap(),
                    b"still current authority required"
                );
            }
        }
    }
    #[test]
    fn crypto_errors_permanently_close_handshake_and_transport() {
        let (_, responder) = pair();
        let mut owned = HostResponderHandshakeV3 {
            handshake: Some(responder),
            deadline: Instant::now() + Duration::from_secs(30),
            channel_id: [7; 16],
        };
        assert!(owned.read(&[0; 513]).is_err());
        assert!(owned.handshake.is_none());
        assert!(owned.write().is_err());
        assert!(owned.finish().is_err());

        let (mut client, mut responder) = pair();
        responder.read(&client.write().unwrap()).unwrap();
        client.read(&responder.write().unwrap()).unwrap();
        responder.read(&client.write().unwrap()).unwrap();
        let mut transport = HostChannelV3 {
            channel: Some(responder.finish().unwrap()),
            channel_id: [7; 16],
        };
        assert!(
            transport
                .seal(&vec![0; lomi_remote_crypto::MAX_PLAINTEXT + 1])
                .is_err()
        );
        assert!(transport.seal(b"closed").is_err());
        let mut transport = HostChannelV3 {
            channel: Some(client.finish().unwrap()),
            channel_id: [7; 16],
        };
        assert!(transport.open(&[0; 1]).is_err());
        assert!(transport.seal(b"closed").is_err());
    }
}
