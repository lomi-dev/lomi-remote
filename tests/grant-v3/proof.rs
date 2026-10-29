use ed25519_dalek::{Signature, VerifyingKey};
use lomi_remote_crypto::*;
use lomi_remote_protocol::{Capability, CapabilitySet};
use serde_json::{json, Value};

fn setup() -> (Identity, Identity, ChannelContextV3, CurrentAuthorityV3) {
    let h = Identity::fixture(Role::Host, 7).unwrap();
    let d = Identity::fixture(Role::Device, 17).unwrap();
    let grant = GrantV3 {
        version: 3,
        api_major: 2,
        application_major: 2,
        account_id: [1; 16],
        host_id: [2; 16],
        host_fingerprint: h.public_bundle().bundle.fingerprint().unwrap(),
        host_authorization_id: [4; 16],
        access_epoch: 5,
        consumer_authorization_id: [6; 16],
        account_session_id: "session_nanoid-7".into(),
        consumer_id: [3; 16],
        consumer_fingerprint: d.public_bundle().bundle.fingerprint().unwrap(),
        grant_id: [8; 16],
        grant_revision: 9,
        workspace_id: [10; 16],
        workspace_epoch: [11; 16],
        runtime_id: [12; 16],
        runtime_generation: 13,
        capabilities: CapabilitySet::try_from(vec![
            Capability::WorkspaceRead,
            Capability::TerminalObserve,
        ])
        .unwrap(),
        nonce: [14; 32],
        expires_at: 1000,
        purpose: GrantPurposeV3::Workspace,
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
    let c = ChannelContextV3 {
        version: 3,
        grant,
        channel_id: [15; 16],
        initiator_role: Role::Device,
        responder_role: Role::Host,
        purpose: ChannelPurposeV3::Workspace,
        terminal: None,
        issued_at: 100,
        expires_at: 125,
    };
    (h, d, c, current)
}
fn token(
    h: &Identity,
    d: &Identity,
    c: &ChannelContextV3,
    a: &CurrentAuthorityV3,
    now: u64,
) -> Result<VerifiedChannelContextV3> {
    h.sign_channel_admission_v3(c)?.verify(
        &h.sign_grant_v3(&c.grant)?,
        c,
        &h.public_bundle(),
        &h.public_bundle().bundle.fingerprint()?,
        &d.public_bundle(),
        &d.public_bundle().bundle.fingerprint()?,
        a,
        now,
    )
}
fn handshake(
    h: &Identity,
    d: &Identity,
    c: &ChannelContextV3,
    a: &CurrentAuthorityV3,
) -> (Channel, Channel) {
    let mut client = Handshake::new_v3(
        true,
        d,
        token(h, d, c, a, 100).unwrap(),
        &h.public_bundle(),
        &h.public_bundle().bundle.fingerprint().unwrap(),
        100,
    )
    .unwrap();
    let mut host = Handshake::new_v3(
        false,
        h,
        token(h, d, c, a, 100).unwrap(),
        &d.public_bundle(),
        &d.public_bundle().bundle.fingerprint().unwrap(),
        100,
    )
    .unwrap();
    host.read(&client.write().unwrap()).unwrap();
    client.read(&host.write().unwrap()).unwrap();
    host.read(&client.write().unwrap()).unwrap();
    (client.finish().unwrap(), host.finish().unwrap())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
#[test]
fn fixed_cbor_and_ed25519_vectors() {
    let (h, _, c, _) = setup();
    let mut terminal = c.clone();
    terminal.purpose = ChannelPurposeV3::Terminal;
    terminal.terminal = Some(TerminalTargetV3 {
        pane_id: [16; 16],
        session_id: [17; 16],
        session_epoch: [18; 16],
        terminal_profile: "lomi-rust-grid-v1-experimental".into(),
    });
    let actual = json!({"grantCbor":hex(&c.grant.canonical().unwrap()),"grantSignature":hex(&h.sign_grant_v3(&c.grant).unwrap().signature),"contextCbor":hex(&c.canonical().unwrap()),"contextSignature":hex(&h.sign_channel_admission_v3(&c).unwrap().signature),"terminalContextCbor":hex(&terminal.canonical().unwrap()),"terminalContextSignature":hex(&h.sign_channel_admission_v3(&terminal).unwrap().signature)});
    assert_eq!(
        actual,
        serde_json::from_str::<Value>(include_str!("vectors.json")).unwrap()
    );
}
fn changed(value: &Value) -> Value {
    match value {
        Value::Array(a) if a.first().is_some_and(Value::is_number) => {
            let mut a = a.clone();
            a[0] = json!(a[0].as_u64().unwrap() ^ 1);
            Value::Array(a)
        }
        Value::String(s) => json!(match s.parse::<u64>() {
            Ok(n) => (n + 1).to_string(),
            Err(_) => format!("{s}x"),
        }),
        Value::Number(n) => json!(n.as_u64().unwrap() + 1),
        Value::Array(_) => json!(["workspace.read"]),
        Value::Null => json!({"paneId":vec![1;16]}),
        _ => panic!("unhandled value"),
    }
}
#[test]
fn every_signed_grant_field_is_bound() {
    let (h, _, c, _) = setup();
    let g = &c.grant;
    let original = serde_json::to_value(g).unwrap();
    let key = VerifyingKey::from_bytes(&h.public_bundle().bundle.identity_key).unwrap();
    let signature = Signature::from_slice(&h.sign_grant_v3(g).unwrap().signature).unwrap();
    for (field, value) in original.as_object().unwrap() {
        let mut mutated = original.clone();
        mutated[field] = changed(value);
        if let Ok(g) = GrantV3::from_json(&mutated.to_string()) {
            assert!(
                key.verify_strict(&g.canonical().unwrap(), &signature)
                    .is_err(),
                "unbound {field}"
            );
        }
    }
}
#[test]
fn every_signed_context_field_and_terminal_target_is_bound() {
    let (h, _, mut c, _) = setup();
    c.purpose = ChannelPurposeV3::Terminal;
    c.terminal = Some(TerminalTargetV3 {
        pane_id: [16; 16],
        session_id: [17; 16],
        session_epoch: [18; 16],
        terminal_profile: "lomi-rust-grid-v1-experimental".into(),
    });
    let original = serde_json::to_value(&c).unwrap();
    let key = VerifyingKey::from_bytes(&h.public_bundle().bundle.identity_key).unwrap();
    let signature =
        Signature::from_slice(&h.sign_channel_admission_v3(&c).unwrap().signature).unwrap();
    for field in [
        "version",
        "channelId",
        "initiatorRole",
        "responderRole",
        "purpose",
        "issuedAt",
        "expiresAt",
    ] {
        let mut v = original.clone();
        v[field] = changed(&v[field]);
        if let Ok(c) = ChannelContextV3::from_json(&v.to_string()) {
            assert!(
                key.verify_strict(&c.canonical().unwrap(), &signature)
                    .is_err(),
                "{field}"
            );
        }
    }
    for field in ["paneId", "sessionId", "sessionEpoch", "terminalProfile"] {
        let mut v = original.clone();
        v["terminal"][field] = changed(&v["terminal"][field]);
        if let Ok(c) = ChannelContextV3::from_json(&v.to_string()) {
            assert!(
                key.verify_strict(&c.canonical().unwrap(), &signature)
                    .is_err(),
                "{field}"
            );
        }
    }
    let mut v = original;
    v["terminal"] = Value::Null;
    assert!(ChannelContextV3::from_json(&v.to_string()).is_err());
}
#[test]
fn strict_json_and_capability_normalization() {
    let (_, _, c, _) = setup();
    let v = serde_json::to_value(&c.grant).unwrap();
    for field in [
        "accessEpoch",
        "grantRevision",
        "runtimeGeneration",
        "expiresAt",
    ] {
        for bad in [
            json!(1),
            json!("01"),
            json!("-1"),
            json!("18446744073709551616"),
            json!("1e2"),
        ] {
            let mut m = v.clone();
            m[field] = bad;
            assert!(GrantV3::from_json(&m.to_string()).is_err(), "{field}");
        }
    }
    for caps in [
        json!(["workspace.read", "workspace.read"]),
        json!(["terminal.control"]),
        json!(["unknown"]),
    ] {
        let mut m = v.clone();
        m["capabilities"] = caps;
        assert!(GrantV3::from_json(&m.to_string()).is_err());
    }
    let mut m = v.clone();
    m["capabilities"] = json!(["terminal.observe", "workspace.read"]);
    assert_eq!(
        GrantV3::from_json(&m.to_string())
            .unwrap()
            .canonical()
            .unwrap(),
        c.grant.canonical().unwrap()
    );
    for bad in ["", "bad session", "bad/session", &"x".repeat(129)] {
        let mut m = v.clone();
        m["accountSessionId"] = json!(bad);
        assert!(GrantV3::from_json(&m.to_string()).is_err());
    }
    let mut m = v.clone();
    m["extra"] = json!(true);
    assert!(GrantV3::from_json(&m.to_string()).is_err());
    let s = serde_json::to_string(&c.grant).unwrap();
    let s = s.replacen("{", "{\"version\":3,", 1);
    assert!(GrantV3::from_json(&s).is_err());
    for legacy in [1, 2] {
        let mut m = v.clone();
        m["version"] = json!(legacy);
        assert!(GrantV3::from_json(&m.to_string()).is_err());
    }
    let mut m = v;
    m["permissions"] = json!("control");
    assert!(GrantV3::from_json(&m.to_string()).is_err());
    const {
        assert!(!REMOTE_V2_PRODUCTION_QUALIFIED);
    }
}
#[test]
fn trusted_state_pins_expiry_and_membership() {
    let (h, d, c, a) = setup();
    assert!(token(&h, &d, &c, &a, 100).is_ok());
    assert!(token(&h, &d, &c, &a, 124).is_ok());
    for now in [99, 125, 1000] {
        assert!(token(&h, &d, &c, &a, now).is_err());
    }
    let admission = h.sign_channel_admission_v3(&c).unwrap();
    let grant = h.sign_grant_v3(&c.grant).unwrap();
    let hb = h.public_bundle();
    let db = d.public_bundle();
    let hp = hb.bundle.fingerprint().unwrap();
    let dp = db.bundle.fingerprint().unwrap();
    assert!(admission
        .verify(&grant, &c, &hb, &[9; 32], &db, &dp, &a, 100)
        .is_err());
    assert!(admission
        .verify(&grant, &c, &hb, &hp, &db, &[9; 32], &a, 100)
        .is_err());
    let mut expected = c.clone();
    expected.channel_id[0] ^= 1;
    assert!(admission
        .verify(&grant, &expected, &hb, &hp, &db, &dp, &a, 100)
        .is_err());
    let states = [
        CurrentAuthorityV3 {
            access_epoch: 6,
            ..a.clone()
        },
        CurrentAuthorityV3 {
            grant_revision: 10,
            ..a.clone()
        },
        CurrentAuthorityV3 {
            workspace_epoch: [9; 16],
            ..a.clone()
        },
        CurrentAuthorityV3 {
            runtime_generation: 14,
            ..a.clone()
        },
        CurrentAuthorityV3 {
            runtime_id: [9; 16],
            ..a.clone()
        },
        CurrentAuthorityV3 {
            host_authorization_id: [9; 16],
            ..a.clone()
        },
        CurrentAuthorityV3 {
            consumer_authorization_id: [9; 16],
            ..a.clone()
        },
        CurrentAuthorityV3 {
            account_session_id: "other".into(),
            ..a.clone()
        },
    ];
    for state in states {
        assert!(token(&h, &d, &c, &state, 100).is_err());
    }
    let mut terminal = c.clone();
    terminal.purpose = ChannelPurposeV3::Terminal;
    terminal.terminal = Some(TerminalTargetV3 {
        pane_id: [16; 16],
        session_id: [17; 16],
        session_epoch: [18; 16],
        terminal_profile: "lomi-rust-grid-v1-experimental".into(),
    });
    assert!(token(&h, &d, &terminal, &a, 100).is_err());
    let mut current = a.clone();
    current.terminal_membership = terminal.terminal.clone();
    assert!(token(&h, &d, &terminal, &current, 100).is_ok());
    current.terminal_membership.as_mut().unwrap().session_epoch[0] ^= 1;
    assert!(token(&h, &d, &terminal, &current, 100).is_err());
    for (issued, expires) in [(100, 131), (100, 100), (990, 1010)] {
        let mut m = c.clone();
        m.issued_at = issued;
        m.expires_at = expires;
        assert!(m.canonical().is_err());
    }
    assert!(
        Handshake::new_v3(true, &d, token(&h, &d, &c, &a, 100).unwrap(), &hb, &hp, 125).is_err()
    );
    assert!(Handshake::new_v3(
        false,
        &d,
        token(&h, &d, &c, &a, 100).unwrap(),
        &hb,
        &hp,
        100
    )
    .is_err());
}
#[test]
fn full_prologue_mismatch_fails_before_transport_and_windows_are_independent() {
    let (h, d, c, a) = setup();
    let mut other = c.clone();
    other.channel_id[0] ^= 1;
    let mut client = Handshake::new_v3(
        true,
        &d,
        token(&h, &d, &c, &a, 100).unwrap(),
        &h.public_bundle(),
        &c.grant.host_fingerprint,
        100,
    )
    .unwrap();
    let mut host = Handshake::new_v3(
        false,
        &h,
        token(&h, &d, &other, &a, 100).unwrap(),
        &d.public_bundle(),
        &c.grant.consumer_fingerprint,
        100,
    )
    .unwrap();
    host.read(&client.write().unwrap()).unwrap();
    assert!(client.read(&host.write().unwrap()).is_err());
    assert!(client.finish().is_err());
    let (mut client1, mut host1) = handshake(&h, &d, &c, &a);
    let d2 = Identity::generate([1; 16], [33; 16], Role::Device, 1).unwrap();
    let mut c2 = c.clone();
    c2.grant.consumer_id = [33; 16];
    c2.grant.consumer_fingerprint = d2.public_bundle().bundle.fingerprint().unwrap();
    c2.grant.grant_id = [30; 16];
    c2.channel_id = [31; 16];
    let (mut client2, mut host2) = handshake(&h, &d2, &c2, &a);
    let f1 = client1.seal([1; 16], b"first window").unwrap();
    let f2 = client2.seal([1; 16], b"second window").unwrap();
    assert_eq!(f1.sequence, 0);
    assert_eq!(f2.sequence, 0);
    assert_eq!(&*host1.open([1; 16], &f1).unwrap(), b"first window");
    assert_eq!(&*host2.open([1; 16], &f2).unwrap(), b"second window");
    assert!(host1
        .open([1; 16], &client2.seal([1; 16], b"cross").unwrap())
        .is_err());
}

fn state_for(c: &ChannelContextV3) -> CurrentAuthorityV3 {
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
fn mismatched_handshake(
    h: &Identity,
    d: &Identity,
    first: &ChannelContextV3,
    second: &ChannelContextV3,
) {
    let mut client = Handshake::new_v3(
        true,
        d,
        token(h, d, first, &state_for(first), 100).unwrap(),
        &h.public_bundle(),
        &first.grant.host_fingerprint,
        100,
    )
    .unwrap();
    let mut host = Handshake::new_v3(
        false,
        h,
        token(h, d, second, &state_for(second), 100).unwrap(),
        &d.public_bundle(),
        &second.grant.consumer_fingerprint,
        100,
    )
    .unwrap();
    host.read(&client.write().unwrap()).unwrap();
    assert!(client.read(&host.write().unwrap()).is_err());
    assert!(client.finish().is_err());
    assert!(host.finish().is_err());
}
#[test]
fn noise_binds_all_admissible_grant_and_terminal_context_changes() {
    let (h, d, c, _) = setup();
    let original = serde_json::to_value(&c.grant).unwrap();
    for field in [
        "hostAuthorizationId",
        "accessEpoch",
        "consumerAuthorizationId",
        "accountSessionId",
        "grantId",
        "grantRevision",
        "workspaceId",
        "workspaceEpoch",
        "runtimeId",
        "runtimeGeneration",
        "capabilities",
        "nonce",
        "expiresAt",
    ] {
        let mut v = original.clone();
        v[field] = changed(&v[field]);
        let mut other = c.clone();
        other.grant = GrantV3::from_json(&v.to_string()).unwrap();
        mismatched_handshake(&h, &d, &c, &other);
    }
    let mut other = c.clone();
    other.issued_at = 99;
    mismatched_handshake(&h, &d, &c, &other);
    other = c.clone();
    other.expires_at = 126;
    mismatched_handshake(&h, &d, &c, &other);
    let mut terminal = c.clone();
    terminal.purpose = ChannelPurposeV3::Terminal;
    terminal.terminal = Some(TerminalTargetV3 {
        pane_id: [16; 16],
        session_id: [17; 16],
        session_epoch: [18; 16],
        terminal_profile: "lomi-rust-grid-v1-experimental".into(),
    });
    mismatched_handshake(&h, &d, &c, &terminal);
    for field in ["paneId", "sessionId", "sessionEpoch"] {
        let mut v = serde_json::to_value(&terminal).unwrap();
        v["terminal"][field] = changed(&v["terminal"][field]);
        let other = ChannelContextV3::from_json(&v.to_string()).unwrap();
        mismatched_handshake(&h, &d, &terminal, &other);
    }
    let (mut client, mut host) = handshake(&h, &d, &terminal, &state_for(&terminal));
    assert_eq!(
        &*host
            .open_binary([1; 16], &client.seal_binary([1; 16], b"terminal").unwrap())
            .unwrap(),
        b"terminal"
    );
}
#[test]
fn signed_json_bounds_signatures_and_legacy_documents_are_rejected() {
    let (mut h, d, c, a) = setup();
    for legacy in [
        include_str!("../../crates/lomi-remote-crypto/tests/fixtures/legacy-v1.json"),
        include_str!("../../crates/lomi-remote-crypto/tests/fixtures/workspace-v2.json"),
    ] {
        assert!(SignedGrantV3::from_json(legacy).is_err());
        assert!(SignedChannelAdmissionV3::from_json(legacy).is_err());
    }
    let mut grant = h.sign_grant_v3(&c.grant).unwrap();
    let admission = h.sign_channel_admission_v3(&c).unwrap();
    let hb = h.public_bundle();
    let db = d.public_bundle();
    let hp = hb.bundle.fingerprint().unwrap();
    let dp = db.bundle.fingerprint().unwrap();
    for signature in [vec![], vec![0; 64], vec![0; 65]] {
        grant.signature = signature;
        assert!(admission
            .verify(&grant, &c, &hb, &hp, &db, &dp, &a, 100)
            .is_err());
    }
    let mut v = serde_json::to_value(&admission).unwrap();
    v["extra"] = json!(true);
    assert!(SignedChannelAdmissionV3::from_json(&v.to_string()).is_err());
    let mut v = serde_json::to_value(&c.grant).unwrap();
    for field in [
        "accessEpoch",
        "grantRevision",
        "runtimeGeneration",
        "expiresAt",
    ] {
        v[field] = json!(u64::MAX.to_string());
    }
    assert!(GrantV3::from_json(&v.to_string()).is_ok());
    assert!(GrantV3::from_json(&" ".repeat(MAX_JSON + 1)).is_err());
    h.dispose();
    assert!(h.sign_grant_v3(&c.grant).is_err());
    assert!(h.sign_channel_admission_v3(&c).is_err());
}
#[test]
fn canonical_arity_and_experimental_profile_registry_match() {
    let (_, _, c, _) = setup();
    for (bytes, arity) in [
        (c.grant.canonical().unwrap(), 23),
        (c.canonical().unwrap(), 10),
    ] {
        let mut decoder = minicbor::Decoder::new(&bytes);
        assert_eq!(decoder.array().unwrap(), Some(arity));
        for _ in 0..arity {
            decoder.skip().unwrap();
        }
        assert_eq!(decoder.position(), bytes.len());
    }
    let registry: Value = serde_json::from_str(include_str!(
        "../../contracts/terminal-profile-experimental.json"
    ))
    .unwrap();
    assert_eq!(registry["profile"], "lomi-rust-grid-v1-experimental");
    assert_eq!(registry["qualified"], false);
}
