//! Bounded native peer for the unqualified Chromium/WASM v3 fixture.
#[cfg(feature = "test-fixtures")]
mod fixture {
    use lomi_remote_crypto::*;
    use lomi_remote_protocol::{Capability, CapabilitySet};
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::{
        collections::BTreeMap,
        io::{BufRead, Read, Write},
    };
    #[derive(Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SignedInput {
        grant: SignedGrantV3,
        admission: SignedChannelAdmissionV3,
        host: SignedBundle,
        consumer: SignedBundle,
    }
    #[derive(Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        signed: SignedInput,
        expected: ChannelContextV3,
        authority: Value,
        host_pin: [u8; 32],
        consumer_pin: [u8; 32],
        artifacts: Value,
    }
    fn current(c: &ChannelContextV3) -> CurrentAuthorityV3 {
        let g = &c.grant;
        CurrentAuthorityV3 {
            host_authorization_id: g.host_authorization_id,
            consumer_authorization_id: g.consumer_authorization_id,
            account_session_id: g.account_session_id.clone(),
            access_epoch: g.access_epoch,
            grant_revision: g.grant_revision,
            workspace_epoch: g.workspace_epoch,
            runtime_id: g.runtime_id,
            runtime_generation: g.runtime_generation,
            terminal_membership: c.terminal.clone(),
        }
    }
    fn authority(c: &ChannelContextV3) -> Value {
        let a = current(c);
        json!({"hostAuthorizationId":a.host_authorization_id,"consumerAuthorizationId":a.consumer_authorization_id,"accountSessionId":a.account_session_id,"accessEpoch":a.access_epoch.to_string(),"grantRevision":a.grant_revision.to_string(),"workspaceEpoch":a.workspace_epoch,"runtimeId":a.runtime_id,"runtimeGeneration":a.runtime_generation.to_string(),"terminalMembership":a.terminal_membership})
    }
    fn build(
        host: &Identity,
        consumer: SignedBundle,
        terminal: bool,
        window_b: bool,
    ) -> Result<Case> {
        let host_bundle = host.public_bundle();
        let hp = host_bundle.bundle.fingerprint()?;
        let cp = consumer.bundle.fingerprint()?;
        consumer.verify(&cp)?;
        let grant = GrantV3 {
            version: 3,
            api_major: 2,
            application_major: 2,
            account_id: [1; 16],
            host_id: [2; 16],
            host_fingerprint: hp,
            host_authorization_id: [4; 16],
            access_epoch: 5,
            consumer_authorization_id: [6; 16],
            account_session_id: "session_nanoid-7".into(),
            consumer_id: consumer.bundle.subject_id,
            consumer_fingerprint: cp,
            grant_id: [if window_b { 28 } else { 8 }; 16],
            grant_revision: 9,
            workspace_id: [10; 16],
            workspace_epoch: [11; 16],
            runtime_id: [12; 16],
            runtime_generation: 13,
            capabilities: CapabilitySet::try_from(vec![
                Capability::WorkspaceRead,
                Capability::TerminalObserve,
            ])?,
            nonce: [if window_b { 30 } else { 14 }; 32],
            expires_at: 1000,
            purpose: GrantPurposeV3::Workspace,
        };
        let target = terminal.then(|| TerminalTargetV3 {
            pane_id: [16; 16],
            session_id: [17; 16],
            session_epoch: [18; 16],
            terminal_profile: "lomi-rust-grid-v1-experimental".into(),
        });
        let c = ChannelContextV3 {
            version: 3,
            grant,
            channel_id: [if window_b { 29 } else { 15 }; 16],
            initiator_role: Role::Device,
            responder_role: Role::Host,
            purpose: if terminal {
                ChannelPurposeV3::Terminal
            } else {
                ChannelPurposeV3::Workspace
            },
            terminal: target,
            issued_at: 100,
            expires_at: 125,
        };
        let signed = SignedInput {
            grant: host.sign_grant_v3(&c.grant)?,
            admission: host.sign_channel_admission_v3(&c)?,
            host: host_bundle,
            consumer,
        };
        let artifacts = json!({"grantJson":serde_json::to_string(&c.grant).map_err(|_|"encode")?,"contextJson":serde_json::to_string(&c).map_err(|_|"encode")?,"grantCbor":c.grant.canonical()?,"contextCbor":c.canonical()?,"grantSignature":signed.grant.signature,"contextSignature":signed.admission.signature});
        Ok(Case {
            authority: authority(&c),
            signed,
            expected: c,
            host_pin: hp,
            consumer_pin: cp,
            artifacts,
        })
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn verify_goldens(cases: &BTreeMap<String, Case>) -> Result<()> {
        let a = &cases["a-workspace"];
        let t = &cases["a-terminal"];
        let actual = json!({"grantCbor":hex(&a.expected.grant.canonical()?),"grantSignature":hex(&a.signed.grant.signature),"contextCbor":hex(&a.expected.canonical()?),"contextSignature":hex(&a.signed.admission.signature),"terminalContextCbor":hex(&t.expected.canonical()?),"terminalContextSignature":hex(&t.signed.admission.signature)});
        let frozen: Value =
            serde_json::from_str(include_str!("../../../tests/grant-v3/vectors.json"))
                .map_err(|_| "golden parse")?;
        if actual != frozen {
            return Err("v3 frozen golden drift".into());
        }
        Ok(())
    }
    #[derive(Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
    enum Command {
        Fixtures {},
        Window {
            consumer: SignedBundle,
            pin: [u8; 32],
        },
        Start {
            slot: String,
            case: String,
            side: String,
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
        Open {
            slot: String,
            bytes: Vec<u8>,
        },
        Seal {
            slot: String,
            bytes: Vec<u8>,
        },
        Dispose {
            slot: String,
        },
    }
    struct Session {
        handshake: Option<Handshake>,
        channel: Option<Channel>,
        route: [u8; 16],
    }
    impl Session {
        fn handshake(&mut self) -> Result<&mut Handshake> {
            self.handshake.as_mut().ok_or("handshake absent".into())
        }
        fn channel(&mut self) -> Result<&mut Channel> {
            self.channel.as_mut().ok_or("channel absent".into())
        }
    }
    fn session<'a>(
        sessions: &'a mut BTreeMap<String, Session>,
        slot: &str,
    ) -> Result<&'a mut Session> {
        sessions.get_mut(slot).ok_or("unknown slot".into())
    }
    pub fn run() -> Result<()> {
        let host = Identity::fixture(Role::Host, 7)?;
        let device = Identity::fixture(Role::Device, 17)?;
        let mut cases = BTreeMap::from([
            (
                "a-workspace".into(),
                build(&host, device.public_bundle(), false, false)?,
            ),
            (
                "a-terminal".into(),
                build(&host, device.public_bundle(), true, false)?,
            ),
        ]);
        verify_goldens(&cases)?;
        let frozen_cases: Value = serde_json::from_str(include_str!(
            "../../../tests/crypto-v3-browser/native-vectors.json"
        ))
        .map_err(|_| "browser golden parse")?;
        if serde_json::to_value(&cases).map_err(|_| "browser golden encode")? != frozen_cases {
            return Err("native browser vector drift".into());
        }
        let mut sessions: BTreeMap<String, Session> = BTreeMap::new();
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        for _ in 0..256 {
            let mut line = Vec::new();
            let count = (&mut reader)
                .take((MAX_JSON + 1) as u64)
                .read_until(b'\n', &mut line)
                .map_err(|_| "read")?;
            if count == 0 {
                return Ok(());
            }
            if line.len() > MAX_JSON || line.last() != Some(&b'\n') {
                return Err("bounded line exceeded".into());
            }
            let outcome = (|| -> Result<Value> {
                let command: Command = serde_json::from_slice(&line).map_err(|_| "command")?;
                match command {
                    Command::Fixtures {} => Ok(json!(cases)),
                    Command::Window { consumer, pin } => {
                        consumer.verify(&pin)?;
                        if consumer.bundle.account_id != [1; 16]
                            || consumer.bundle.role != Role::Device
                            || consumer.bundle.subject_id == [3; 16]
                        {
                            return Err("window identity".into());
                        }
                        let c = build(&host, consumer, false, true)?;
                        cases.insert("b-workspace".into(), c.clone());
                        Ok(json!(c))
                    }
                    Command::Start { slot, case, side } => {
                        if sessions.len() >= 8
                            || slot.is_empty()
                            || slot.len() > 32
                            || sessions.contains_key(&slot)
                        {
                            return Err("slot limit".into());
                        }
                        let c = cases.get(&case).ok_or("case")?;
                        let initiator = match side.as_str() {
                            "host" => false,
                            "consumer" => true,
                            _ => return Err("side".into()),
                        };
                        let token = c.signed.admission.verify(
                            &c.signed.grant,
                            &c.expected,
                            &c.signed.host,
                            &c.host_pin,
                            &c.signed.consumer,
                            &c.consumer_pin,
                            &current(&c.expected),
                            100,
                        )?;
                        let (identity, peer, pin) = if initiator {
                            (&device, &c.signed.host, &c.host_pin)
                        } else {
                            (&host, &c.signed.consumer, &c.consumer_pin)
                        };
                        let h = Handshake::new_v3(initiator, identity, token, peer, pin, 100)?;
                        sessions.insert(
                            slot,
                            Session {
                                handshake: Some(h),
                                channel: None,
                                route: c.expected.channel_id,
                            },
                        );
                        Ok(json!([]))
                    }
                    Command::Read { slot, bytes } => {
                        if bytes.len() > 32768 {
                            return Err("frame limit".into());
                        }
                        session(&mut sessions, &slot)?.handshake()?.read(&bytes)?;
                        Ok(json!([]))
                    }
                    Command::Write { slot } => Ok(json!(session(&mut sessions, &slot)?
                        .handshake()?
                        .write()?)),
                    Command::Finish { slot } => {
                        let s = session(&mut sessions, &slot)?;
                        let channel = s.handshake.take().ok_or("no handshake")?.finish()?;
                        let transcript = channel.transcript_hash.to_vec();
                        s.channel = Some(channel);
                        Ok(json!(transcript))
                    }
                    Command::Open { slot, bytes } => {
                        if bytes.len() > 32768 {
                            return Err("frame limit".into());
                        }
                        let s = session(&mut sessions, &slot)?;
                        let route = s.route;
                        Ok(json!(s.channel()?.open_binary(route, &bytes)?.to_vec()))
                    }
                    Command::Seal { slot, bytes } => {
                        if bytes.len() > MAX_PLAINTEXT {
                            return Err("payload limit".into());
                        }
                        let s = session(&mut sessions, &slot)?;
                        let route = s.route;
                        Ok(json!(s.channel()?.seal_binary(route, &bytes)?))
                    }
                    Command::Dispose { slot } => {
                        let s = session(&mut sessions, &slot)?;
                        if let Some(h) = s.handshake.as_mut() {
                            h.dispose();
                        }
                        if let Some(c) = s.channel.as_mut() {
                            c.dispose();
                        }
                        Ok(json!([]))
                    }
                }
            })();
            let response = match outcome {
                Ok(value) => json!({"ok":value}),
                Err(_) => json!({"error":true}),
            };
            let encoded = serde_json::to_string(&response).map_err(|_| "encode")?;
            if encoded.len() > MAX_JSON {
                return Err("reply limit".into());
            }
            writeln!(std::io::stdout(), "{encoded}").map_err(|_| "write")?;
            std::io::stdout().flush().map_err(|_| "flush")?;
        }
        Err("command count limit".into())
    }
}
#[cfg(feature = "test-fixtures")]
fn main() {
    if fixture::run().is_err() {
        eprintln!("bounded native v3 fixture failed");
        std::process::exit(1);
    }
}
#[cfg(not(feature = "test-fixtures"))]
fn main() {
    eprintln!("not_run: test-fixtures required");
    std::process::exit(2);
}
