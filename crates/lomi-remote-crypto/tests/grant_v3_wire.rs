use lomi_remote_crypto::*;
use lomi_remote_protocol::{Capability, CapabilitySet};

fn setup() -> (Identity, Identity, ChannelContextV3, CurrentAuthorityV3) {
    let h = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
    let d = Identity::generate([1; 16], [3; 16], Role::Device, 1).unwrap();
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
        account_session_id: "opaque_session-7".into(),
        consumer_id: [3; 16],
        consumer_fingerprint: d.public_bundle().bundle.fingerprint().unwrap(),
        grant_id: [8; 16],
        grant_revision: 9,
        workspace_id: [10; 16],
        workspace_epoch: [11; 16],
        runtime_id: [12; 16],
        runtime_generation: 13,
        capabilities: CapabilitySet::control_with_workspace_tools(),
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
fn fields(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut d = minicbor::Decoder::new(bytes);
    let n = d.array().unwrap().unwrap();
    (0..n)
        .map(|_| {
            let start = d.position();
            d.skip().unwrap();
            bytes[start..d.position()].to_vec()
        })
        .collect()
}
fn array(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(fields.len() as u64).unwrap();
    let mut bytes = e.into_writer();
    for field in fields {
        bytes.extend(field);
    }
    bytes
}
fn encoded(f: impl FnOnce(&mut minicbor::Encoder<Vec<u8>>)) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    f(&mut e);
    e.into_writer()
}
fn proposal(
    h: &Identity,
    d: &Identity,
    g: &GrantV3,
    s: &SignedGrantV3,
    a: &CurrentAuthorityV3,
    now: u64,
) -> Result<GrantV3> {
    verify_grant_proposal_v3(
        g,
        s,
        &h.public_bundle(),
        &h.public_bundle().bundle.fingerprint()?,
        &d.public_bundle(),
        &d.public_bundle().bundle.fingerprint()?,
        a,
        now,
    )
}
#[test]
fn canonical_and_wire_roundtrips_with_real_keys() {
    let (h, _, mut c, _) = setup();
    for terminal in [false, true] {
        if terminal {
            c.purpose = ChannelPurposeV3::Terminal;
            c.terminal = Some(TerminalTargetV3 {
                pane_id: [16; 16],
                session_id: [17; 16],
                session_epoch: [18; 16],
                terminal_profile: "lomi-rust-grid-v1-experimental".into(),
            });
        }
        assert_eq!(
            GrantV3::from_canonical(&c.grant.canonical().unwrap()).unwrap(),
            c.grant
        );
        assert_eq!(
            ChannelContextV3::from_canonical(&c.canonical().unwrap()).unwrap(),
            c
        );
        let g = h.sign_grant_v3(&c.grant).unwrap();
        assert_eq!(SignedGrantV3::from_wire(&g.to_wire().unwrap()).unwrap(), g);
        let a = h.sign_channel_admission_v3(&c).unwrap();
        assert_eq!(
            SignedChannelAdmissionV3::from_wire(&a.to_wire().unwrap()).unwrap(),
            a
        );
    }
}
#[test]
fn canonical_rejects_all_truncations_trailing_oversize_and_cross_domain() {
    let (_, _, c, _) = setup();
    let g = c.grant.canonical().unwrap();
    let ctx = c.canonical().unwrap();
    for bytes in [&g, &ctx] {
        for n in 0..bytes.len() {
            assert!(GrantV3::from_canonical(&bytes[..n]).is_err());
            assert!(ChannelContextV3::from_canonical(&bytes[..n]).is_err());
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(GrantV3::from_canonical(&extra).is_err());
        assert!(ChannelContextV3::from_canonical(&extra).is_err());
    }
    assert!(GrantV3::from_canonical(&ctx).is_err());
    assert!(ChannelContextV3::from_canonical(&g).is_err());
    assert!(GrantV3::from_canonical(&vec![0; 8193]).is_err());
    assert!(ChannelContextV3::from_canonical(&vec![0; 8193]).is_err());
}
#[test]
fn canonical_rejects_nonminimal_indefinite_types_counts_and_fixed_lengths() {
    let (_, _, c, _) = setup();
    {
        let bytes = c.grant.canonical().unwrap();
        let decode = GrantV3::from_canonical;
        let f = fields(&bytes);
        for index in [1, 2, 3, 8, 14, 18, 21] {
            let mut bad = f.clone();
            let n = minicbor::Decoder::new(&f[index]).u64().unwrap();
            for width in [
                vec![0x18, n as u8],
                [vec![0x19], (n as u16).to_be_bytes().to_vec()].concat(),
                [vec![0x1a], (n as u32).to_be_bytes().to_vec()].concat(),
                [vec![0x1b], n.to_be_bytes().to_vec()].concat(),
            ] {
                if width == f[index] || minicbor::Decoder::new(&width).u64().unwrap() != n {
                    continue;
                }
                bad[index] = width;
                assert!(decode(&array(&bad)).is_err());
            }
        }
        for index in [4, 5, 6, 7, 9, 11, 12, 13, 15, 16, 17, 20] {
            for size in [0, 15, 17, 31, 33] {
                if size == minicbor::Decoder::new(&f[index]).bytes().unwrap().len() {
                    continue;
                }
                let mut bad = f.clone();
                bad[index] = encoded(|e| {
                    e.bytes(&vec![1; size]).unwrap();
                });
                assert!(decode(&array(&bad)).is_err());
            }
        }
        for replacement in [vec![0xf6], vec![0x80], vec![0xa0], vec![0x20]] {
            for index in 0..f.len() {
                let mut bad = f.clone();
                bad[index] = replacement.clone();
                assert!(decode(&array(&bad)).is_err());
            }
        }
        let mut indefinite = vec![0x9f];
        indefinite.extend_from_slice(&bytes[1..]);
        indefinite.push(0xff);
        assert!(decode(&indefinite).is_err());
        let mut bad = f.clone();
        bad.push(vec![0xf6]);
        assert!(decode(&array(&bad)).is_err());
        assert!(decode(&array(&f[..22])).is_err());
    }
    let f = fields(&c.canonical().unwrap());
    for index in [1, 8, 9] {
        let mut bad = f.clone();
        let n = minicbor::Decoder::new(&f[index]).u64().unwrap();
        bad[index] = [vec![0x1b], n.to_be_bytes().to_vec()].concat();
        assert!(ChannelContextV3::from_canonical(&array(&bad)).is_err());
    }
    for index in [0, 2, 3, 4, 5, 6, 7] {
        let mut bad = f.clone();
        bad[index] = vec![0xa0];
        assert!(ChannelContextV3::from_canonical(&array(&bad)).is_err());
    }
}
#[test]
fn capabilities_require_sorted_unique_registry_and_closed_dependencies() {
    let (_, _, c, _) = setup();
    let f = fields(&c.grant.canonical().unwrap());
    for names in [
        vec!["workspace.read", "files.read"],
        vec!["workspace.read", "workspace.read"],
        vec!["files.write", "workspace.read"],
        vec!["git.execute", "workspace.read"],
        vec!["unknown", "workspace.read"],
        vec![],
        vec!["workspace.read"; 11],
    ] {
        let mut bad = f.clone();
        bad[19] = encoded(|e| {
            e.array(names.len() as u64).unwrap();
            for name in names {
                e.str(name).unwrap();
            }
        });
        assert!(GrantV3::from_canonical(&array(&bad)).is_err());
    }
    let mut bad = f.clone();
    bad[19] = vec![0x9f, 0xff];
    assert!(GrantV3::from_canonical(&array(&bad)).is_err());
    let mut context = fields(&c.canonical().unwrap());
    let mut nested = f.clone();
    nested.push(vec![0]);
    context[2] = encoded(|e| {
        e.bytes(&array(&nested)).unwrap();
    });
    assert!(ChannelContextV3::from_canonical(&array(&context)).is_err());
}
#[test]
fn wire_validates_canonical_carrier_and_exact_signature_without_claiming_authenticity() {
    let (h, _, c, _) = setup();
    let mut g = h.sign_grant_v3(&c.grant).unwrap();
    let mut a = h.sign_channel_admission_v3(&c).unwrap();
    for n in [0, 1, 63, 65, 128] {
        g.signature = vec![0; n];
        a.signature = vec![0; n];
        assert!(g.to_wire().is_err());
        assert!(a.to_wire().is_err());
    }
    g.signature = vec![0; 64];
    assert!(SignedGrantV3::from_wire(&g.to_wire().unwrap()).is_ok());
    let wire = g.to_wire().unwrap();
    let mut json = serde_json::to_value(wire).unwrap();
    json["signature"] = serde_json::json!("ab");
    if let Ok(wire) = serde_json::from_value(json) {
        assert!(SignedGrantV3::from_wire(&wire).is_err());
    }
    let mut wire = g.to_wire().unwrap();
    wire.canonical_cbor = "00".to_string().try_into().unwrap();
    assert!(SignedGrantV3::from_wire(&wire).is_err());
}
#[test]
fn retained_proposal_allows_only_narrowed_capabilities_and_expiry() {
    let (h, d, c, current) = setup();
    let maximum = c.grant;
    let mut candidate = maximum.clone();
    candidate.capabilities = CapabilitySet::try_from(vec![Capability::WorkspaceRead]).unwrap();
    candidate.expires_at = 500;
    let signed = h.sign_grant_v3(&candidate).unwrap();
    assert_eq!(
        proposal(&h, &d, &maximum, &signed, &current, 100).unwrap(),
        candidate
    );
    assert!(proposal(&h, &d, &maximum, &signed, &current, 500).is_err());
    candidate.expires_at = 1001;
    assert!(proposal(
        &h,
        &d,
        &maximum,
        &h.sign_grant_v3(&candidate).unwrap(),
        &current,
        100
    )
    .is_err());
    candidate = maximum.clone();
    candidate.capabilities = CapabilitySet::try_from(Capability::ALL.to_vec()).unwrap();
    assert!(candidate.capabilities.contains(Capability::GitExecute));
    assert!(!maximum.capabilities.contains(Capability::GitExecute));
    assert!(proposal(
        &h,
        &d,
        &maximum,
        &h.sign_grant_v3(&candidate).unwrap(),
        &current,
        100
    )
    .is_err());
    let signed = h.sign_grant_v3(&maximum).unwrap();
    let value = serde_json::to_value(&maximum).unwrap();
    for field in [
        "version",
        "apiMajor",
        "applicationMajor",
        "accountId",
        "hostId",
        "hostFingerprint",
        "hostAuthorizationId",
        "accessEpoch",
        "consumerAuthorizationId",
        "accountSessionId",
        "consumerId",
        "consumerFingerprint",
        "grantId",
        "grantRevision",
        "workspaceId",
        "workspaceEpoch",
        "runtimeId",
        "runtimeGeneration",
        "nonce",
        "purpose",
    ] {
        let mut changed = value.clone();
        let v = &mut changed[field];
        match v {
            serde_json::Value::Array(a) => a[0] = serde_json::json!(99),
            serde_json::Value::String(s) => {
                *s = if field == "accountSessionId" {
                    "other".into()
                } else if field == "purpose" {
                    "terminal".into()
                } else {
                    "99".into()
                }
            }
            serde_json::Value::Number(_) => *v = serde_json::json!(99),
            _ => panic!("unexpected field"),
        };
        if let Ok(expected) = serde_json::from_value::<GrantV3>(changed) {
            assert!(
                proposal(&h, &d, &expected, &signed, &current, 100).is_err(),
                "{field}"
            );
        }
    }
}
#[test]
fn proposal_verifies_signature_independent_pins_and_current_state() {
    let (h, d, c, current) = setup();
    let g = &c.grant;
    let signed = h.sign_grant_v3(g).unwrap();
    let mut corrupt = signed.clone();
    corrupt.signature[0] ^= 1;
    assert!(proposal(&h, &d, g, &corrupt, &current, 100).is_err());
    let wrong = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
    assert!(proposal(&wrong, &d, g, &signed, &current, 100).is_err());
    assert!(verify_grant_proposal_v3(
        g,
        &signed,
        &h.public_bundle(),
        &[0; 32],
        &d.public_bundle(),
        &d.public_bundle().bundle.fingerprint().unwrap(),
        &current,
        100
    )
    .is_err());
    assert!(verify_grant_proposal_v3(
        g,
        &signed,
        &h.public_bundle(),
        &h.public_bundle().bundle.fingerprint().unwrap(),
        &d.public_bundle(),
        &[0; 32],
        &current,
        100
    )
    .is_err());
    for field in 0..8 {
        let mut stale = current.clone();
        match field {
            0 => stale.access_epoch += 1,
            1 => stale.grant_revision += 1,
            2 => stale.runtime_generation += 1,
            3 => stale.runtime_id = [88; 16],
            4 => stale.workspace_epoch = [88; 16],
            5 => stale.account_session_id = "changed".into(),
            6 => stale.host_authorization_id = [88; 16],
            _ => stale.consumer_authorization_id = [88; 16],
        };
        assert!(proposal(&h, &d, g, &signed, &stale, 100).is_err());
    }
}

#[test]
fn terminal_nested_schema_and_channel_roles_are_exact() {
    let (_, _, mut c, _) = setup();
    c.purpose = ChannelPurposeV3::Terminal;
    c.terminal = Some(TerminalTargetV3 {
        pane_id: [16; 16],
        session_id: [17; 16],
        session_epoch: [18; 16],
        terminal_profile: "lomi-rust-grid-v1-experimental".into(),
    });
    let f = fields(&c.canonical().unwrap());
    let target = fields(&f[7]);
    for index in 0..3 {
        for size in [0, 15, 17, 32] {
            let mut t = target.clone();
            t[index] = encoded(|e| {
                e.bytes(&vec![1; size]).unwrap();
            });
            let mut bad = f.clone();
            bad[7] = array(&t);
            assert!(ChannelContextV3::from_canonical(&array(&bad)).is_err());
        }
    }
    for replacement in [
        vec![0xf6],
        vec![0x9f, 0xff],
        array(&target[..3]),
        array(&[target.clone(), vec![vec![0xf6]]].concat()),
    ] {
        let mut bad = f.clone();
        bad[7] = replacement;
        assert!(ChannelContextV3::from_canonical(&array(&bad)).is_err());
    }
    for (index, text) in [(4, "host"), (5, "device"), (6, "workspace"), (6, "other")] {
        let mut bad = f.clone();
        bad[index] = encoded(|e| {
            e.str(text).unwrap();
        });
        assert!(ChannelContextV3::from_canonical(&array(&bad)).is_err());
    }
    let mut t = target;
    t[3] = encoded(|e| {
        e.str(&"x".repeat(65)).unwrap();
    });
    let mut bad = f;
    bad[7] = array(&t);
    assert!(ChannelContextV3::from_canonical(&array(&bad)).is_err());
}

#[test]
fn wire_admission_still_requires_exact_independent_context_and_host_signature() {
    let (h, d, c, current) = setup();
    let grant =
        SignedGrantV3::from_wire(&h.sign_grant_v3(&c.grant).unwrap().to_wire().unwrap()).unwrap();
    let admission = SignedChannelAdmissionV3::from_wire(
        &h.sign_channel_admission_v3(&c).unwrap().to_wire().unwrap(),
    )
    .unwrap();
    let verify = |a: &SignedChannelAdmissionV3, expected: &ChannelContextV3| {
        a.verify(
            &grant,
            expected,
            &h.public_bundle(),
            &h.public_bundle().bundle.fingerprint().unwrap(),
            &d.public_bundle(),
            &d.public_bundle().bundle.fingerprint().unwrap(),
            &current,
            100,
        )
    };
    assert!(verify(&admission, &c).is_ok());
    let mut expected = c.clone();
    expected.channel_id = [99; 16];
    assert!(verify(&admission, &expected).is_err());
    let mut bad = admission.clone();
    bad.signature[0] ^= 1;
    assert!(verify(&bad, &c).is_err());
    let wrong = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
    let mut other = c.clone();
    other.grant.host_fingerprint = wrong.public_bundle().bundle.fingerprint().unwrap();
    bad.signature = wrong.sign_channel_admission_v3(&other).unwrap().signature;
    assert!(verify(&bad, &c).is_err());
    let mut wrong_grant = grant.clone();
    wrong_grant.signature = wrong.sign_grant_v3(&other.grant).unwrap().signature;
    assert!(proposal(&h, &d, &c.grant, &wrong_grant, &current, 100).is_err());
}

#[test]
fn canonical_rejects_text_bounds_nonminimal_lengths_and_context_arities() {
    let (h, _, c, _) = setup();
    let grant = c.grant.canonical().unwrap();
    let f = fields(&grant);
    for session in ["".to_owned(), "x".repeat(129), "space forbidden".to_owned()] {
        let mut bad = f.clone();
        bad[10] = encoded(|e| {
            e.str(&session).unwrap();
        });
        assert!(GrantV3::from_canonical(&array(&bad)).is_err());
    }
    let mut bad = f.clone();
    bad[4] = [vec![0x58, 16], vec![1; 16]].concat();
    assert!(GrantV3::from_canonical(&array(&bad)).is_err());
    let context = c.canonical().unwrap();
    let f = fields(&context);
    for n in [0, 15, 17, 32] {
        let mut bad = f.clone();
        bad[3] = encoded(|e| {
            e.bytes(&vec![1; n]).unwrap();
        });
        assert!(ChannelContextV3::from_canonical(&array(&bad)).is_err());
    }
    let mut bad = f.clone();
    bad.push(vec![0xf6]);
    assert!(ChannelContextV3::from_canonical(&array(&bad)).is_err());
    assert!(ChannelContextV3::from_canonical(&array(&f[..9])).is_err());
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&context[1..]);
    indefinite.push(0xff);
    assert!(ChannelContextV3::from_canonical(&indefinite).is_err());
    let mut gw = h.sign_grant_v3(&c.grant).unwrap().to_wire().unwrap();
    let mut aw = h.sign_channel_admission_v3(&c).unwrap().to_wire().unwrap();
    std::mem::swap(&mut gw.canonical_cbor, &mut aw.canonical_cbor);
    assert!(SignedGrantV3::from_wire(&gw).is_err());
    assert!(SignedChannelAdmissionV3::from_wire(&aw).is_err());
}
