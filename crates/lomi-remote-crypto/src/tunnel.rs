//! Device-to-Host tunnel: Noise XX bound to a canonical prologue, a confirmation code, and a
//! rekeying transport whose wire frame is the bare Noise ciphertext (plan-1.0/03-protokol.md §4).
use crate::{
    wire::{self, Id},
    Identity, Result, Role, SignedBundle,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const NOISE: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PROLOGUE_DOMAIN: &str = "lomi-remote/tunnel";
const CONFIRM_DOMAIN: &str = "lomi-remote/tunnel-confirm";
/// Largest payload accepted or produced in a handshake message (the encrypted `hello`).
pub const MAX_HELLO_PAYLOAD: usize = 4096;
/// Payload plus the largest Noise overhead (ephemeral + static + tags, < 128 bytes).
const MAX_HANDSHAKE_MESSAGE: usize = MAX_HELLO_PAYLOAD + 128;
const _: () = assert!(REKEY_INTERVAL == 1 << 20);
/// A relay DATA frame is type byte + 16-byte circuitId + bytes and must fit in 65535.
pub const MAX_TUNNEL_CIPHERTEXT: usize = 65535 - 17;
pub const MAX_TUNNEL_PLAINTEXT: usize = MAX_TUNNEL_CIPHERTEXT - 16;
/// Messages per direction between key rotations.
pub const REKEY_INTERVAL: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelPath {
    Relay,
    Direct,
}

/// Ids are the crate's raw 16-byte `wire::Id`, not UUID strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelPrologue {
    pub contract_hash: [u8; 32],
    pub path: TunnelPath,
    pub circuit_id: Id,
    pub nonce: [u8; 16],
    pub host_id: Id,
    pub host_fingerprint: [u8; 32],
    pub device_fingerprint: [u8; 32],
    pub account_id: Id,
}

impl TunnelPrologue {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = wire::encoder();
        e.array(9).unwrap();
        e.str(PROLOGUE_DOMAIN).unwrap();
        wire::bytes(&mut e, &self.contract_hash);
        wire::number(
            &mut e,
            match self.path {
                TunnelPath::Relay => 1,
                TunnelPath::Direct => 2,
            },
        );
        wire::bytes(&mut e, &self.circuit_id);
        wire::bytes(&mut e, &self.nonce);
        wire::bytes(&mut e, &self.host_id);
        wire::bytes(&mut e, &self.host_fingerprint);
        wire::bytes(&mut e, &self.device_fingerprint);
        wire::bytes(&mut e, &self.account_id);
        e.into_writer()
    }
}

pub struct TunnelHandshake {
    state: Option<snow::HandshakeState>,
    /// Device side: the pinned Host static key. Host side: unknown until `verify_device`.
    expected_remote: Option<[u8; 32]>,
    hash: Option<[u8; 32]>,
    /// Host side: the relay-attested device fingerprint and account the bundle must match.
    attested: Option<([u8; 32], Id)>,
    device_verified: bool,
    /// Handshake messages written or read so far.
    messages: u8,
}

fn build(
    initiator: bool,
    identity: &Identity,
    prologue: &TunnelPrologue,
    expected_remote: Option<[u8; 32]>,
    ephemeral: Option<&[u8; 32]>,
) -> Result<TunnelHandshake> {
    if identity.disposed {
        return Err("identity disposed".into());
    }
    let encoded = prologue.encode();
    let builder = snow::Builder::new(NOISE.parse().map_err(|_| "Noise profile unavailable")?)
        .local_private_key(identity.channel_secret.as_ref())
        .map_err(|_| "Noise key rejected")?
        .prologue(&encoded)
        .map_err(|_| "Noise prologue rejected")?;
    #[cfg(test)]
    let builder = match ephemeral {
        Some(key) => builder.fixed_ephemeral_key_for_testing_only(key),
        None => builder,
    };
    #[cfg(not(test))]
    let _ = ephemeral;
    let state = if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(|_| "Noise construction failed")?;
    Ok(TunnelHandshake {
        state: Some(state),
        expected_remote,
        hash: None,
        attested: (!initiator).then_some((prologue.device_fingerprint, prologue.account_id)),
        device_verified: false,
        messages: 0,
    })
}

fn check_local(
    identity: &Identity,
    role: Role,
    fingerprint: &[u8; 32],
    p: &TunnelPrologue,
) -> Result<()> {
    let b = &identity.signed.bundle;
    if b.role != role || b.account_id != p.account_id || b.fingerprint()? != *fingerprint {
        return Err("tunnel local identity mismatch".into());
    }
    Ok(())
}

impl TunnelHandshake {
    /// `pinned_host_fingerprint` must come from the device's own stored pairing or inventory,
    /// never from the relay; `host` may come from anywhere since it is checked against the pin.
    pub fn device(
        identity: &Identity,
        prologue: &TunnelPrologue,
        host: &SignedBundle,
        pinned_host_fingerprint: &[u8; 32],
    ) -> Result<Self> {
        if prologue.host_fingerprint != *pinned_host_fingerprint {
            return Err("tunnel host pin mismatch".into());
        }
        Self::device_inner(identity, prologue, host, None)
    }
    pub fn host(identity: &Identity, prologue: &TunnelPrologue) -> Result<Self> {
        Self::host_inner(identity, prologue, None)
    }
    fn device_inner(
        identity: &Identity,
        prologue: &TunnelPrologue,
        host: &SignedBundle,
        ephemeral: Option<&[u8; 32]>,
    ) -> Result<Self> {
        host.verify(&prologue.host_fingerprint)?;
        let h = &host.bundle;
        if h.role != Role::Host
            || h.account_id != prologue.account_id
            || h.subject_id != prologue.host_id
        {
            return Err("tunnel host identity mismatch".into());
        }
        check_local(
            identity,
            Role::Device,
            &prologue.device_fingerprint,
            prologue,
        )?;
        build(true, identity, prologue, Some(h.channel_key), ephemeral)
    }
    fn host_inner(
        identity: &Identity,
        prologue: &TunnelPrologue,
        ephemeral: Option<&[u8; 32]>,
    ) -> Result<Self> {
        check_local(identity, Role::Host, &prologue.host_fingerprint, prologue)?;
        if identity.signed.bundle.subject_id != prologue.host_id {
            return Err("tunnel local identity mismatch".into());
        }
        build(false, identity, prologue, None, ephemeral)
    }

    fn settle(&mut self, state: snow::HandshakeState) {
        self.messages += 1;
        if state.is_handshake_finished() {
            self.hash = state.get_handshake_hash().try_into().ok();
        }
        self.state = Some(state);
    }

    /// Any failure closes the handshake. Only message 3 may carry a payload: message 1 is
    /// cleartext and message 2 goes to a not yet authenticated device.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut state = self.state.take().ok_or("handshake closed")?;
        if payload.len() > MAX_HELLO_PAYLOAD || (self.messages < 2 && !payload.is_empty()) {
            return Err("handshake payload limit".into());
        }
        let mut out = vec![0u8; MAX_HANDSHAKE_MESSAGE];
        let n = state
            .write_message(payload, &mut out)
            .map_err(|_| "handshake write rejected")?;
        out.truncate(n);
        self.settle(state);
        Ok(out)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut state = self.state.take().ok_or("handshake closed")?;
        if message.len() > MAX_HANDSHAKE_MESSAGE {
            return Err("handshake frame limit".into());
        }
        let mut out = Zeroizing::new(vec![0u8; MAX_HANDSHAKE_MESSAGE]);
        let n = state
            .read_message(message, &mut out)
            .map_err(|_| "handshake authentication failed")?;
        out.truncate(n);
        if (self.messages < 2 && n != 0) || n > MAX_HELLO_PAYLOAD {
            return Err("unexpected handshake payload".into());
        }
        if let (Some(expected), Some(remote)) = (self.expected_remote, state.get_remote_static()) {
            if remote != expected {
                return Err("Noise static pin mismatch".into());
            }
        }
        self.settle(state);
        Ok(out)
    }

    pub fn is_finished(&self) -> bool {
        self.hash.is_some()
    }

    /// The peer's static key once received (Host: after message 3).
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.state.as_ref()?.get_remote_static()?.try_into().ok()
    }

    pub fn confirmation_code(&self) -> Result<String> {
        let h = self.hash.ok_or("handshake not finished")?;
        let mut e = wire::encoder();
        e.array(2).unwrap();
        e.str(CONFIRM_DOMAIN).unwrap();
        wire::bytes(&mut e, &h);
        let d = Sha256::digest(e.into_writer());
        let n = u64::from_be_bytes(d[..8].try_into().unwrap());
        Ok(format!("{:06}", n % 1_000_000))
    }

    /// Host side, after message 3: checks the device bundle from `hello` against the
    /// relay-attested fingerprint, the account and the Noise static key. Required before
    /// `into_transport`.
    pub fn verify_device(&mut self, bundle: &SignedBundle) -> Result<()> {
        self.device_verified = false;
        let (fingerprint, account) = self.attested.ok_or("not a Host handshake")?;
        let remote = self.remote_static().ok_or("device static not received")?;
        verify_device(bundle, &fingerprint, &account, &remote)?;
        self.device_verified = true;
        Ok(())
    }

    pub fn into_transport(mut self) -> Result<Tunnel> {
        if self.attested.is_some() && !self.device_verified {
            return Err("device bundle not verified".into());
        }
        let state = self.state.take().ok_or("handshake closed")?;
        let hash = self.hash.ok_or("handshake not finished")?;
        let remote = state.get_remote_static().ok_or("missing remote static")?;
        if self.expected_remote.is_some_and(|k| remote != k) {
            return Err("Noise static pin mismatch".into());
        }
        Ok(Tunnel {
            state: Some(
                state
                    .into_transport_mode()
                    .map_err(|_| "transport unavailable")?,
            ),
            hash,
            sent: 0,
            received: 0,
            interval: REKEY_INTERVAL,
            poisoned: false,
        })
    }
}

fn verify_device(
    bundle: &SignedBundle,
    attested_fingerprint: &[u8; 32],
    account_id: &Id,
    remote_static: &[u8; 32],
) -> Result<()> {
    bundle.verify(attested_fingerprint)?;
    let b = &bundle.bundle;
    if b.role != Role::Device || b.account_id != *account_id || b.channel_key != *remote_static {
        return Err("tunnel device identity mismatch".into());
    }
    Ok(())
}

pub struct Tunnel {
    state: Option<snow::TransportState>,
    hash: [u8; 32],
    sent: u64,
    received: u64,
    interval: u64,
    poisoned: bool,
}

impl Tunnel {
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let state = self
            .state
            .as_mut()
            .filter(|_| !self.poisoned)
            .ok_or("tunnel closed")?;
        if plaintext.len() > MAX_TUNNEL_PLAINTEXT {
            return Err("tunnel plaintext limit".into());
        }
        let mut out = vec![0u8; plaintext.len() + 16];
        let n = match state.write_message(plaintext, &mut out) {
            Ok(n) => n,
            Err(_) => {
                self.poisoned = true;
                return Err("tunnel encryption failed".into());
            }
        };
        out.truncate(n);
        self.sent += 1;
        if self.sent.is_multiple_of(self.interval) {
            state.rekey_outgoing();
        }
        Ok(out)
    }

    /// Any failure poisons the tunnel; the caller must close the circuit.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let state = self
            .state
            .as_mut()
            .filter(|_| !self.poisoned)
            .ok_or("tunnel closed")?;
        if ciphertext.len() < 16 || ciphertext.len() > MAX_TUNNEL_CIPHERTEXT {
            self.poisoned = true;
            return Err("tunnel ciphertext limit".into());
        }
        let mut out = Zeroizing::new(vec![0u8; ciphertext.len()]);
        let n = match state.read_message(ciphertext, &mut out) {
            Ok(n) => n,
            Err(_) => {
                self.poisoned = true;
                return Err("tunnel authentication failed".into());
            }
        };
        out.truncate(n);
        self.received += 1;
        if self.received.is_multiple_of(self.interval) {
            state.rekey_incoming();
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
