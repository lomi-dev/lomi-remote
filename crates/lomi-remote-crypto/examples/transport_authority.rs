//! Synthetic process-only authority/Noise verifier. Never a product signer.
#[cfg(feature = "test-fixtures")]
mod fixture {
    use lomi_remote_crypto::*;
    use lomi_remote_protocol::{
        DecimalU64, EnrollmentProof, SignedChannelAdmissionWire, SignedGrantWire,
    };
    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::{BufRead, Read, Write},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Authority {
        host_authorization_id: [u8; 16],
        consumer_authorization_id: [u8; 16],
        account_session_id: String,
        access_epoch: DecimalU64,
        grant_revision: DecimalU64,
        workspace_epoch: [u8; 16],
        runtime_id: [u8; 16],
        runtime_generation: DecimalU64,
        terminal_membership: Option<TerminalTargetV3>,
    }
    impl Authority {
        fn current(self) -> CurrentAuthorityV3 {
            CurrentAuthorityV3 {
                host_authorization_id: self.host_authorization_id,
                consumer_authorization_id: self.consumer_authorization_id,
                account_session_id: self.account_session_id,
                access_epoch: self.access_epoch.0,
                grant_revision: self.grant_revision.0,
                workspace_epoch: self.workspace_epoch,
                runtime_id: self.runtime_id,
                runtime_generation: self.runtime_generation.0,
                terminal_membership: self.terminal_membership,
            }
        }
    }
    #[derive(Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
    enum Command {
        Init {
            account_id: [u8; 16],
            host_id: [u8; 16],
            window_id: [u8; 16],
        },
        SignEnrollment {
            canonical_cbor: Vec<u8>,
        },
        SignWindow {
            canonical_cbor: Vec<u8>,
        },
        SignGrant {
            grant: GrantV3,
        },
        SignContext {
            context: ChannelContextV3,
        },
        Start {
            slot: String,
            initiator: bool,
            expected_context_cbor: Vec<u8>,
            stored_signed_grant_wire: SignedGrantWire,
            admission_wire: SignedChannelAdmissionWire,
            host_identity_wire: EnrollmentProof,
            consumer_identity_wire: EnrollmentProof,
            host_pin: [u8; 32],
            consumer_pin: [u8; 32],
            current_authority: Authority,
        },
        Read {
            slot: String,
            bytes: Vec<u8>,
        },
        Write {
            slot: String,
        },
        Finish {
            slot: String,
        },
        Seal {
            slot: String,
            bytes: Vec<u8>,
        },
        Open {
            slot: String,
            bytes: Vec<u8>,
        },
        Dispose {
            slot: String,
        },
        Shutdown {},
    }
    impl Command {
        fn slot(&self) -> Option<&str> {
            match self {
                Self::Start { slot, .. }
                | Self::Read { slot, .. }
                | Self::Write { slot }
                | Self::Finish { slot }
                | Self::Seal { slot, .. }
                | Self::Open { slot, .. }
                | Self::Dispose { slot } => Some(slot),
                _ => None,
            }
        }
    }
    struct Session {
        handshake: Option<Handshake>,
        channel: Option<Channel>,
        route: [u8; 16],
        deadline: Instant,
    }
    impl Drop for Session {
        fn drop(&mut self) {
            if let Some(h) = self.handshake.as_mut() {
                h.dispose();
            }
            if let Some(c) = self.channel.as_mut() {
                c.dispose();
            }
        }
    }
    impl Session {
        fn handshake(&mut self) -> Result<&mut Handshake> {
            if Instant::now() >= self.deadline {
                return Err("closed".into());
            }
            self.handshake.as_mut().ok_or("closed".into())
        }
        fn channel(&mut self) -> Result<&mut Channel> {
            self.channel.as_mut().ok_or("closed".into())
        }
    }
    struct State {
        identities: Option<(Identity, Identity)>,
        sessions: BTreeMap<String, Session>,
        slots: BTreeSet<String>,
        admissions: BTreeSet<(bool, Vec<u8>)>,
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn proof(bytes: &[u8], signature: &[u8]) -> Value {
        json!({"canonicalCbor":hex(bytes),"signature":hex(signature)})
    }
    fn wall_ms() -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock")?
            .as_millis()
            .try_into()
            .map_err(|_| "clock".into())
    }
    impl State {
        fn execute(&mut self, command: Command) -> Result<Value> {
            match command {
                Command::Init {
                    account_id,
                    host_id,
                    window_id,
                } => {
                    if self.identities.is_some()
                        || [account_id, host_id, window_id].contains(&[0; 16])
                    {
                        return Err("init".into());
                    }
                    let pending = PendingHostIdentity::generate(host_id, 1)?;
                    let commitment = pending.signed_commitment()?;
                    let pin = commitment.descriptor.commitment()?;
                    let host = pending.finalize(account_id, &pin)?;
                    let consumer = Identity::generate(account_id, window_id, Role::Device, 1)?;
                    let hb = host.public_bundle();
                    let cb = consumer.public_bundle();
                    let hw = hb.to_wire()?;
                    let cw = cb.to_wire()?;
                    verify_registered_host_identity(&commitment, &pin, account_id, &hw)?;
                    verify_consumer_window_identity(&cw, account_id, window_id)?;
                    let result = json!({"initiation":{"keyCommitment":hex(&pin),"proof":proof(&commitment.descriptor.canonical()?,&commitment.signature)},
                        "hostIdentityWire":hw,"consumerIdentityWire":cw,"hostPin":hb.bundle.fingerprint()?,"consumerPin":cb.bundle.fingerprint()?,"hostBundle":hb,"consumerBundle":cb});
                    self.identities = Some((host, consumer));
                    Ok(result)
                }
                Command::SignEnrollment { canonical_cbor } => {
                    let (h, _) = self.identities.as_ref().ok_or("init")?;
                    let challenge = EnrollmentChallenge::from_canonical(&canonical_cbor)?;
                    let signed = h.sign_enrollment_proof(&challenge)?;
                    signed.verify(
                        &challenge,
                        &h.public_bundle(),
                        &h.public_bundle().bundle.fingerprint()?,
                        wall_ms()? / 1000,
                    )?;
                    Ok(proof(&challenge.canonical()?, &signed.signature))
                }
                Command::SignWindow { canonical_cbor } => {
                    let (_, c) = self.identities.as_ref().ok_or("init")?;
                    let challenge = ConsumerWindowChallenge::from_canonical(&canonical_cbor)?;
                    let signed = c.sign_consumer_window_proof(&challenge)?;
                    verify_consumer_window_proof(
                        &signed,
                        &challenge,
                        &c.public_bundle().to_wire()?,
                        c.public_bundle().bundle.account_id,
                        wall_ms()? / 1000,
                    )?;
                    Ok(json!(signed))
                }
                Command::SignGrant { grant } => Ok(json!(self
                    .identities
                    .as_ref()
                    .ok_or("init")?
                    .0
                    .sign_grant_v3(&grant)?
                    .to_wire()?)),
                Command::SignContext { context } => Ok(json!(self
                    .identities
                    .as_ref()
                    .ok_or("init")?
                    .0
                    .sign_channel_admission_v3(&context)?
                    .to_wire()?)),
                Command::Start {
                    slot,
                    initiator,
                    expected_context_cbor,
                    stored_signed_grant_wire,
                    admission_wire,
                    host_identity_wire,
                    consumer_identity_wire,
                    host_pin,
                    consumer_pin,
                    current_authority,
                } => {
                    if slot.is_empty()
                        || slot.len() > 64
                        || self.slots.len() >= 528
                        || !self.slots.insert(slot.clone())
                    {
                        return Err("slot".into());
                    }
                    if !self
                        .admissions
                        .insert((initiator, expected_context_cbor.clone()))
                    {
                        return Err("replay".into());
                    }
                    let expected = ChannelContextV3::from_canonical(&expected_context_cbor)?;
                    let grant = SignedGrantV3::from_wire(&stored_signed_grant_wire)?;
                    let admission = SignedChannelAdmissionV3::from_wire(&admission_wire)?;
                    let host = SignedBundle::from_wire(&host_identity_wire)?;
                    let consumer = SignedBundle::from_wire(&consumer_identity_wire)?;
                    // Capture monotonic time before reading wall time: this can only shorten validity.
                    let instant = Instant::now();
                    let ms = wall_ms()?;
                    let now = ms / 1000;
                    let remaining = expected
                        .expires_at
                        .checked_mul(1000)
                        .and_then(|end| end.checked_sub(ms))
                        .ok_or("expired")?;
                    let deadline = instant
                        .checked_add(Duration::from_millis(remaining))
                        .ok_or("expired")?;
                    let token = admission.verify(
                        &grant,
                        &expected,
                        &host,
                        &host_pin,
                        &consumer,
                        &consumer_pin,
                        &current_authority.current(),
                        now,
                    )?;
                    let (h, c) = self.identities.as_ref().ok_or("init")?;
                    let handshake = if initiator {
                        Handshake::new_v3(true, c, token, &host, &host_pin, now)?
                    } else {
                        Handshake::new_v3(false, h, token, &consumer, &consumer_pin, now)?
                    };
                    if Instant::now() >= deadline {
                        return Err("expired".into());
                    }
                    self.sessions.insert(
                        slot,
                        Session {
                            handshake: Some(handshake),
                            channel: None,
                            route: expected.channel_id,
                            deadline,
                        },
                    );
                    Ok(json!([]))
                }
                Command::Read { slot, bytes } => {
                    if bytes.len() > 512 {
                        return Err("frame".into());
                    }
                    let s = self.sessions.get_mut(&slot).ok_or("slot")?;
                    s.handshake()?.read(&bytes)?;
                    s.handshake()?;
                    Ok(json!([]))
                }
                Command::Write { slot } => {
                    let s = self.sessions.get_mut(&slot).ok_or("slot")?;
                    let bytes = s.handshake()?.write()?;
                    s.handshake()?;
                    Ok(json!(bytes))
                }
                Command::Finish { slot } => {
                    let s = self.sessions.get_mut(&slot).ok_or("slot")?;
                    s.handshake()?;
                    let channel = s.handshake.take().ok_or("closed")?.finish()?;
                    if Instant::now() >= s.deadline {
                        return Err("expired".into());
                    }
                    s.channel = Some(channel);
                    Ok(json!([]))
                }
                Command::Seal { slot, bytes } => {
                    if bytes.len() > MAX_PLAINTEXT {
                        return Err("payload".into());
                    }
                    let s = self.sessions.get_mut(&slot).ok_or("slot")?;
                    let route = s.route;
                    Ok(json!(s.channel()?.seal_binary(route, &bytes)?))
                }
                Command::Open { slot, bytes } => {
                    if bytes.len() > MAX_PLAINTEXT + 128 {
                        return Err("frame".into());
                    }
                    let s = self.sessions.get_mut(&slot).ok_or("slot")?;
                    let route = s.route;
                    Ok(json!(s.channel()?.open_binary(route, &bytes)?.to_vec()))
                }
                Command::Dispose { slot } => {
                    self.sessions.remove(&slot).ok_or("slot")?;
                    Ok(json!([]))
                }
                Command::Shutdown {} => Ok(json!([])),
            }
        }
    }
    pub fn run() -> Result<()> {
        let mut state = State {
            identities: None,
            sessions: BTreeMap::new(),
            slots: BTreeSet::new(),
            admissions: BTreeSet::new(),
        };
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        for _ in 0..8192 {
            let mut line = Vec::new();
            let n = (&mut reader)
                .take((MAX_JSON + 1) as u64)
                .read_until(b'\n', &mut line)
                .map_err(|_| "io")?;
            if n == 0 {
                return Ok(());
            }
            let bounded = line.len() <= MAX_JSON && line.last() == Some(&b'\n');
            let command = if bounded {
                serde_json::from_slice::<Command>(&line).ok()
            } else {
                None
            };
            if command.is_none() {
                state.sessions.clear();
            }
            let shutdown = matches!(command, Some(Command::Shutdown {}));
            let slot = command.as_ref().and_then(Command::slot).map(str::to_owned);
            let outcome = command
                .ok_or("command".into())
                .and_then(|c| state.execute(c));
            if outcome.is_err() {
                if let Some(slot) = slot {
                    state.sessions.remove(&slot);
                }
            }
            let response = match outcome {
                Ok(result) => json!({"ok":true,"result":result}),
                Err(_) => json!({"ok":false,"error":"NATIVE_FIXTURE_REJECTED"}),
            };
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer(&mut stdout, &response).map_err(|_| "io")?;
            writeln!(stdout).map_err(|_| "io")?;
            stdout.flush().map_err(|_| "io")?;
            if shutdown || !bounded {
                return Ok(());
            }
        }
        Ok(())
    }
}
#[cfg(feature = "test-fixtures")]
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    if fixture::run().is_err() {
        std::process::exit(1);
    }
}
#[cfg(not(feature = "test-fixtures"))]
fn main() {
    std::process::exit(2);
}
