use crate::{wire, ChannelContext, Identity, Result, Role, SignedBundle, MAX_PLAINTEXT};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
const NOISE: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_HANDSHAKE: usize = 512;
const MAX_FRAMES: u64 = 1_000_000;
const HEADER: usize = 24;
pub struct Handshake {
    state: Option<snow::HandshakeState>,
    peer_static: [u8; 32],
}
pub struct Channel {
    state: Option<snow::TransportState>,
    send_seq: u64,
    receive_seq: u64,
    pub transcript_hash: [u8; 32],
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportFrame {
    pub sequence: u64,
    pub routing: [u8; 16],
    pub ciphertext: Vec<u8>,
}
impl Handshake {
    pub fn new(
        initiator: bool,
        identity: &Identity,
        context: &ChannelContext,
        peer: &SignedBundle,
        pinned_peer: &[u8; 32],
    ) -> Result<Self> {
        if identity.disposed {
            return Err("identity disposed".into());
        }
        context.validate()?;
        peer.verify(pinned_peer)?;
        let local = &identity.signed.bundle;
        let local_role = if initiator { Role::Device } else { Role::Host };
        let peer_role = if initiator { Role::Host } else { Role::Device };
        let subject = |role| match role {
            Role::Host => context.host_id,
            Role::Device => context.device_id,
        };
        if local.account_id != context.account_id
            || peer.bundle.account_id != context.account_id
            || local.role != local_role
            || peer.bundle.role != peer_role
            || local.subject_id != subject(local_role)
            || peer.bundle.subject_id != subject(peer_role)
        {
            return Err("channel identity/context mismatch".into());
        }
        let (device, host) = if initiator {
            (&identity.signed, peer)
        } else {
            (peer, &identity.signed)
        };
        let mut e = wire::encoder();
        wire::domain(&mut e, 5, "noise-prologue");
        wire::bytes(&mut e, &context.canonical()?);
        wire::bytes(&mut e, &device.bundle.fingerprint()?);
        wire::bytes(&mut e, &host.bundle.fingerprint()?);
        let prologue = e.into_writer();
        Self::build(initiator, identity, peer, &prologue)
    }
    fn build(
        initiator: bool,
        identity: &Identity,
        peer: &SignedBundle,
        prologue: &[u8],
    ) -> Result<Self> {
        let builder = snow::Builder::new(NOISE.parse().map_err(|_| "Noise profile unavailable")?)
            .local_private_key(identity.channel_secret.as_ref())
            .map_err(|_| "Noise key rejected")?
            .prologue(prologue)
            .map_err(|_| "Noise prologue rejected")?;
        let state = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|_| "Noise construction failed")?;
        Ok(Self {
            state: Some(state),
            peer_static: peer.bundle.channel_key,
        })
    }
    /// Starts only from an independently verified, short-lived v3 admission.
    pub fn new_v3(
        initiator: bool,
        identity: &Identity,
        validated: crate::VerifiedChannelContextV3,
        peer: &SignedBundle,
        pinned_peer: &[u8; 32],
        now: u64,
    ) -> Result<Self> {
        if identity.disposed {
            return Err("identity disposed".into());
        }
        let context = &validated.context;
        if now < context.issued_at || now >= context.expires_at {
            return Err("channel 3 admission expired".into());
        }
        let grant = &context.grant;
        peer.verify(pinned_peer)?;
        let (device, host) = if initiator {
            (&identity.signed, peer)
        } else {
            (peer, &identity.signed)
        };
        if device.bundle.role != Role::Device
            || host.bundle.role != Role::Host
            || device.bundle.account_id != grant.account_id
            || host.bundle.account_id != grant.account_id
            || device.bundle.subject_id != grant.consumer_id
            || host.bundle.subject_id != grant.host_id
            || device.bundle.fingerprint()? != grant.consumer_fingerprint
            || host.bundle.fingerprint()? != grant.host_fingerprint
        {
            return Err("channel 3 endpoint mismatch".into());
        }
        let mut e = wire::encoder();
        e.array(4).unwrap();
        e.str("lomi-remote-noise-prologue-v3").unwrap();
        wire::bytes(&mut e, &context.canonical()?);
        wire::bytes(&mut e, &grant.consumer_fingerprint);
        wire::bytes(&mut e, &grant.host_fingerprint);
        Self::build(initiator, identity, peer, &e.into_writer())
    }
    pub fn write(&mut self) -> Result<Vec<u8>> {
        let mut state = self.state.take().ok_or("handshake closed")?;
        let mut output = vec![0u8; MAX_HANDSHAKE];
        let count = state
            .write_message(&[], &mut output)
            .map_err(|_| "handshake write rejected")?;
        output.truncate(count);
        self.state = Some(state);
        Ok(output)
    }
    pub fn read(&mut self, message: &[u8]) -> Result<()> {
        let mut state = self.state.take().ok_or("handshake closed")?;
        if message.len() > MAX_HANDSHAKE {
            return Err("handshake frame limit".into());
        }
        let mut output = Zeroizing::new(vec![0u8; MAX_HANDSHAKE]);
        let count = state
            .read_message(message, &mut output)
            .map_err(|_| "handshake authentication failed")?;
        if count != 0 {
            return Err("unexpected handshake application payload".into());
        }
        if state
            .get_remote_static()
            .is_some_and(|key| key != self.peer_static)
        {
            return Err("Noise static pin mismatch".into());
        }
        self.state = Some(state);
        Ok(())
    }
    pub fn finish(mut self) -> Result<Channel> {
        let state = self.state.take().ok_or("handshake closed")?;
        if !state.is_handshake_finished()
            || state.get_remote_static() != Some(self.peer_static.as_slice())
        {
            return Err("handshake incomplete or static pin mismatch".into());
        }
        let transcript_hash = state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| "unexpected transcript hash size")?;
        let transport = state
            .into_transport_mode()
            .map_err(|_| "transport unavailable")?;
        Ok(Channel {
            state: Some(transport),
            send_seq: 0,
            receive_seq: 0,
            transcript_hash,
        })
    }
}
impl Channel {
    /// Mutable ownership serializes Snow's send nonce. Channel is deliberately not Clone.
    pub fn seal(&mut self, routing: [u8; 16], plaintext: &[u8]) -> Result<TransportFrame> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err("plaintext limit".into());
        }
        let mut state = self.state.take().ok_or("channel closed")?;
        if self.send_seq >= MAX_FRAMES {
            return Err("channel lifetime limit; new handshake required".into());
        }
        let mut input = Zeroizing::new(Vec::with_capacity(HEADER + plaintext.len()));
        input.extend_from_slice(&self.send_seq.to_be_bytes());
        input.extend_from_slice(&routing);
        input.extend_from_slice(plaintext);
        let mut ciphertext = vec![0; input.len() + 16];
        let count = state
            .write_message(&input, &mut ciphertext)
            .map_err(|_| "channel encryption failed")?;
        ciphertext.truncate(count);
        let frame = TransportFrame {
            sequence: self.send_seq,
            routing,
            ciphertext,
        };
        self.send_seq += 1;
        self.state = Some(state);
        Ok(frame)
    }
    /// Any authentication/order/context failure closes the receive channel.
    pub fn open(
        &mut self,
        expected_routing: [u8; 16],
        frame: &TransportFrame,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut state = self.state.take().ok_or("channel closed")?;
        if frame.ciphertext.len() < HEADER + 16
            || frame.ciphertext.len() > MAX_PLAINTEXT + HEADER + 16
            || frame.sequence != self.receive_seq
            || frame.routing != expected_routing
            || self.receive_seq >= MAX_FRAMES
        {
            return Err("transport limit, order, or routing mismatch".into());
        }
        let mut plaintext = Zeroizing::new(vec![0u8; frame.ciphertext.len()]);
        let count = state
            .read_message(&frame.ciphertext, &mut plaintext)
            .map_err(|_| "transport authentication failed")?;
        if count < HEADER
            || plaintext[..8] != frame.sequence.to_be_bytes()
            || plaintext[8..HEADER] != expected_routing
        {
            return Err("encrypted transport context mismatch".into());
        }
        let output = Zeroizing::new(plaintext[HEADER..count].to_vec());
        self.receive_seq += 1;
        self.state = Some(state);
        Ok(output)
    }
}

impl TransportFrame {
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        if self.ciphertext.len() < HEADER + 16
            || self.ciphertext.len() > MAX_PLAINTEXT + HEADER + 16
        {
            return Err("binary frame length".into());
        }
        let mut out = Vec::with_capacity(HEADER + self.ciphertext.len());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.routing);
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }
    pub fn from_binary(frame: &[u8]) -> Result<Self> {
        if frame.len() < HEADER * 2 + 16 || frame.len() > MAX_PLAINTEXT + HEADER * 2 + 16 {
            return Err("binary frame length".into());
        }
        Ok(Self {
            sequence: u64::from_be_bytes(frame[..8].try_into().map_err(|_| "sequence length")?),
            routing: frame[8..HEADER].try_into().map_err(|_| "routing length")?,
            ciphertext: frame[HEADER..].to_vec(),
        })
    }
}
impl Channel {
    pub fn dispose(&mut self) {
        self.state.take();
    }
    pub fn seal_binary(&mut self, routing: [u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal(routing, plaintext)?.to_binary()
    }
    pub fn open_binary(&mut self, routing: [u8; 16], frame: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let frame = match TransportFrame::from_binary(frame) {
            Ok(frame) => frame,
            Err(error) => {
                self.dispose();
                return Err(error);
            }
        };
        self.open(routing, &frame)
    }
}
impl Handshake {
    pub fn dispose(&mut self) {
        self.state.take();
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.dispose();
    }
}
impl Drop for Handshake {
    fn drop(&mut self) {
        self.dispose();
    }
}

#[cfg(test)]
mod limits_tests {
    use super::*;
    fn pair() -> (Channel, Channel) {
        let host = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
        let device = Identity::generate([1; 16], [3; 16], Role::Device, 1).unwrap();
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
        let hb = host.public_bundle();
        let db = device.public_bundle();
        let mut c = Handshake::new(
            true,
            &device,
            &context,
            &hb,
            &hb.bundle.fingerprint().unwrap(),
        )
        .unwrap();
        let mut s = Handshake::new(
            false,
            &host,
            &context,
            &db,
            &db.bundle.fingerprint().unwrap(),
        )
        .unwrap();
        s.read(&c.write().unwrap()).unwrap();
        c.read(&s.write().unwrap()).unwrap();
        s.read(&c.write().unwrap()).unwrap();
        (s.finish().unwrap(), c.finish().unwrap())
    }
    #[test]
    fn nonce_exhaustion_and_frame_lifetime_fail_closed() {
        let (mut s, mut c) = pair();
        let frame = c.seal_binary([9; 16], b"nonce").unwrap();
        s.state.as_mut().unwrap().set_receiving_nonce(u64::MAX);
        assert!(s.open_binary([9; 16], &frame).is_err());
        assert!(s.seal_binary([9; 16], b"closed").is_err());
        c.send_seq = MAX_FRAMES;
        assert!(c.seal_binary([9; 16], b"limit").is_err());
        assert!(c.state.is_none());
    }
}
