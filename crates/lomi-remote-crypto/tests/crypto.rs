use lomi_remote_crypto::*;

#[test]
fn qualification_is_limited_to_live_channels() {
    const {
        assert!(LIVE_PRODUCTION_QUALIFIED);
        assert!(!PRODUCTION_QUALIFIED);
        assert!(!MAILBOX_PRODUCTION_QUALIFIED);
    }
}

fn identities() -> (Identity, Identity, ChannelContext) {
    let account = [1; 16];
    (
        Identity::generate(account, [2; 16], Role::Host, 1).unwrap(),
        Identity::generate(account, [3; 16], Role::Device, 1).unwrap(),
        ChannelContext {
            version: 1,
            account_id: account,
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
        },
    )
}
fn handshake(host: &Identity, device: &Identity, context: &ChannelContext) -> (Channel, Channel) {
    let hb = host.public_bundle();
    let db = device.public_bundle();
    let mut client = Handshake::new(
        true,
        device,
        context,
        &hb,
        &hb.bundle.fingerprint().unwrap(),
    )
    .unwrap();
    let mut server =
        Handshake::new(false, host, context, &db, &db.bundle.fingerprint().unwrap()).unwrap();
    server.read(&client.write().unwrap()).unwrap();
    client.read(&server.write().unwrap()).unwrap();
    server.read(&client.write().unwrap()).unwrap();
    (server.finish().unwrap(), client.finish().unwrap())
}
fn policy() -> MailboxPolicy {
    MailboxPolicy {
        account_id: [1; 16],
        sender_host_id: [2; 16],
        recipient_device_id: [3; 16],
        grant_ref: [4; 16],
        access_epoch: 1,
        grant_revision: 1,
        grant_deadline: 2000,
    }
}
#[test]
fn complete_bundle_signature_binds_every_key_and_role() {
    let (host, _, _) = identities();
    let bundle = host.public_bundle();
    let pin = bundle.bundle.fingerprint().unwrap();
    bundle.verify(&pin).unwrap();
    for which in 0..4 {
        let mut changed = bundle.clone();
        match which {
            0 => changed.bundle.channel_key[0] ^= 1,
            1 => changed.bundle.mailbox_key[0] ^= 1,
            2 => changed.bundle.identity_key[0] ^= 1,
            _ => changed.bundle.role = Role::Device,
        };
        assert!(changed.verify(&pin).is_err());
        let forged_pin = changed.bundle.fingerprint().unwrap();
        assert!(changed.verify(&forged_pin).is_err());
    }
}
#[test]
fn noise_roundtrip_transcript_binding_and_replay_rejection() {
    let (host, device, context) = identities();
    let (mut server, mut client) = handshake(&host, &device, &context);
    assert_eq!(server.transcript_hash, client.transcript_hash);
    let frame = client.seal([9; 16], "界e\u{301}".as_bytes()).unwrap();
    assert_eq!(
        &*server.open([9; 16], &frame).unwrap(),
        "界e\u{301}".as_bytes()
    );
    assert!(server.open([9; 16], &frame).is_err());
    assert!(server.seal([9; 16], b"closed").is_err());
}
#[test]
fn wrong_pin_context_route_and_tamper_fail_closed() {
    let (host, device, context) = identities();
    let hb = host.public_bundle();
    assert!(Handshake::new(true, &device, &context, &hb, &[0; 32]).is_err());
    let mut bad = context.clone();
    bad.account_id = [8; 16];
    assert!(Handshake::new(true, &device, &bad, &hb, &hb.bundle.fingerprint().unwrap()).is_err());
    let (mut server, mut client) = handshake(&host, &device, &context);
    let mut frame = client.seal([9; 16], b"secret").unwrap();
    frame.ciphertext[0] ^= 1;
    assert!(server.open([9; 16], &frame).is_err());
    let (mut server, mut client) = handshake(&host, &device, &context);
    let mut frame = client.seal([9; 16], b"secret").unwrap();
    frame.routing = [7; 16];
    assert!(server.open([7; 16], &frame).is_err());
}
#[test]
fn valid_signed_static_substitution_cannot_enter_transport() {
    let (host, device, context) = identities();
    let impostor = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
    let hb = host.public_bundle();
    let db = device.public_bundle();
    let mut client = Handshake::new(
        true,
        &device,
        &context,
        &hb,
        &hb.bundle.fingerprint().unwrap(),
    )
    .unwrap();
    let mut rogue = Handshake::new(
        false,
        &impostor,
        &context,
        &db,
        &db.bundle.fingerprint().unwrap(),
    )
    .unwrap();
    rogue.read(&client.write().unwrap()).unwrap();
    assert!(client.read(&rogue.write().unwrap()).is_err());
    assert!(client.finish().is_err());
}
#[test]
fn mailbox_sender_recipient_policy_signature_expiry_and_replay() {
    let (host, mut device, _) = identities();
    let hb = host.public_bundle();
    let db = device.public_bundle();
    let hp = hb.bundle.fingerprint().unwrap();
    let dp = db.bundle.fingerprint().unwrap();
    let policy = policy();
    let envelope = host
        .seal_mailbox(&db, &dp, &policy, 1000, 1500, b"completed")
        .unwrap();
    let mut changed = envelope.clone();
    changed.enc[0] ^= 1;
    assert!(device
        .open_mailbox(&changed, &hb, &hp, &policy, 1100)
        .is_err());
    let mut changed = envelope.clone();
    changed.ciphertext[0] ^= 1;
    assert!(device
        .open_mailbox(&changed, &hb, &hp, &policy, 1100)
        .is_err());
    let mut changed = envelope.clone();
    changed.metadata.recipient_device_id = [9; 16];
    assert!(device
        .open_mailbox(&changed, &hb, &hp, &policy, 1100)
        .is_err());
    let mut changed_policy = policy.clone();
    changed_policy.access_epoch = 2;
    assert!(device
        .open_mailbox(&envelope, &hb, &hp, &changed_policy, 1100)
        .is_err());
    assert!(device
        .open_mailbox(&envelope, &hb, &hp, &policy, 1500)
        .is_err());
    assert_eq!(
        &*device
            .open_mailbox(&envelope, &hb, &hp, &policy, 1100)
            .unwrap(),
        b"completed"
    );
    assert!(device
        .open_mailbox(&envelope, &hb, &hp, &policy, 1101)
        .unwrap_err()
        .contains("replay"));
    assert!(host
        .seal_mailbox(&db, &dp, &policy, 1000, 2001, b"past grant")
        .is_err());
}
#[test]
fn caps_and_wrong_key_reject() {
    let (host, mut device, _) = identities();
    let hb = host.public_bundle();
    let db = device.public_bundle();
    let policy = policy();
    assert!(host
        .seal_mailbox(
            &db,
            &db.bundle.fingerprint().unwrap(),
            &policy,
            1000,
            1500,
            &vec![0; MAX_MAILBOX_PAYLOAD + 1]
        )
        .is_err());
    let other = Identity::generate([1; 16], [3; 16], Role::Device, 2).unwrap();
    let ob = other.public_bundle();
    let envelope = host
        .seal_mailbox(
            &ob,
            &ob.bundle.fingerprint().unwrap(),
            &policy,
            1000,
            1500,
            b"future key",
        )
        .unwrap();
    assert!(device
        .open_mailbox(
            &envelope,
            &hb,
            &hb.bundle.fingerprint().unwrap(),
            &policy,
            1100
        )
        .is_err());
}

#[test]
fn malformed_and_oversized_noise_inputs_cannot_recover_channel() {
    let (host, device, context) = identities();
    let hb = host.public_bundle();
    let db = device.public_bundle();
    let mut server = Handshake::new(
        false,
        &host,
        &context,
        &db,
        &db.bundle.fingerprint().unwrap(),
    )
    .unwrap();
    assert!(server.read(&vec![0; 513]).is_err());
    assert!(server.write().is_err());
    assert!(server.finish().is_err());
    let mut client = Handshake::new(
        true,
        &device,
        &context,
        &hb,
        &hb.bundle.fingerprint().unwrap(),
    )
    .unwrap();
    assert!(client.read(b"bad").is_err());
    assert!(client.write().is_err());
    let (mut server, mut client) = handshake(&host, &device, &context);
    assert!(client.seal([9; 16], &vec![0; MAX_PLAINTEXT + 1]).is_err());
    let frame = client.seal([9; 16], &vec![1; MAX_PLAINTEXT]).unwrap();
    assert_eq!(server.open([9; 16], &frame).unwrap().len(), MAX_PLAINTEXT);
}
#[test]
fn canonical_arrays_are_versioned_and_have_exact_arity() {
    let (host, _, context) = identities();
    let public = host.public_bundle().bundle.canonical().unwrap();
    let mut d = minicbor::Decoder::new(&public);
    assert_eq!(d.array().unwrap(), Some(10));
    for _ in 0..10 {
        d.skip().unwrap();
    }
    assert_eq!(d.position(), public.len());
    let canonical = context.canonical().unwrap();
    let mut d = minicbor::Decoder::new(&canonical);
    assert_eq!(d.array().unwrap(), Some(13));
    for _ in 0..13 {
        d.skip().unwrap();
    }
    assert_eq!(d.position(), canonical.len());
}
#[cfg(feature = "test-fixtures")]
#[test]
fn fixed_bundle_fingerprints_are_stable_native_wasm_fixtures() {
    let hex = |bytes: [u8; 32]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hex(Identity::fixture(Role::Host, 11)
            .unwrap()
            .public_bundle()
            .bundle
            .fingerprint()
            .unwrap()),
        "c0938f7c2154d1441b0a0fb39724048849cb798c550258e2fc9e4b95892184ee"
    );
    assert_eq!(
        hex(Identity::fixture(Role::Device, 21)
            .unwrap()
            .public_bundle()
            .bundle
            .fingerprint()
            .unwrap()),
        "1387040ad3d2295f2ef61bfa54c14c4673bfa32836b0b6a4073b2b4090192821"
    );
}

#[test]
fn durable_identity_binary_frames_disposal_and_low_order_rejection() {
    let (mut host, device, context) = identities();
    let bundle = host.public_bundle();
    let blob = host.export_secret_seed_blob().unwrap();
    let restored = Identity::import_secret_seed_blob(&blob, &bundle).unwrap();
    assert_eq!(restored.public_bundle(), bundle);
    let mut bad = blob.to_vec();
    bad[1] ^= 1;
    assert!(Identity::import_secret_seed_blob(&bad, &bundle).is_err());
    let (mut s, mut c) = handshake(&restored, &device, &context);
    let frame = c.seal_binary([9; 16], b"one").unwrap();
    assert_eq!(frame.len(), 67);
    assert_eq!(&*s.open_binary([9; 16], &frame).unwrap(), b"one");
    let reply = s.seal_binary([9; 16], b"two").unwrap();
    assert_eq!(&*c.open_binary([9; 16], &reply).unwrap(), b"two");
    c.dispose();
    assert!(c.seal_binary([9; 16], b"closed").is_err());
    assert!(s.open_binary([9; 16], &[0; 63]).is_err());
    assert!(s.seal_binary([9; 16], b"closed").is_err());
    host.dispose();
    assert!(host.export_secret_seed_blob().is_err());
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    let mut dh = DefaultResolver
        .resolve_dh(&snow::params::DHChoice::Curve25519)
        .unwrap();
    dh.set(&[42; 32]);
    for key in [[0; 32], {
        let mut k = [0; 32];
        k[0] = 1;
        k
    }] {
        assert!(dh.dh(&key, &mut [0; 32]).is_err());
    }
}

#[test]
fn approval_binds_every_field_trusted_deadline_and_epoch() {
    let (host, device, _) = identities();
    let hb = host.public_bundle();
    let pin = hb.bundle.fingerprint().unwrap();
    let expected = PeerApproval {
        version: 1,
        account_id: [1; 16],
        host_id: [2; 16],
        device_id: [3; 16],
        host_fingerprint: pin,
        device_fingerprint: device.public_bundle().bundle.fingerprint().unwrap(),
        pairing_nonce: [8; 32],
        grant_id: [4; 16],
        session_ids: vec![[6; 16]],
        workspace_id: None,
        workspace_epoch: None,
        session_epochs: vec![],
        permissions: Permissions::Control,
        access_epoch: 1,
        revision: 1,
        expires_at: 2000,
    };
    let signed = host.sign_peer_approval(expected.clone()).unwrap();
    signed.verify(&hb, &pin, &expected, 1000, 1).unwrap();
    assert!(device.sign_peer_approval(expected.clone()).is_err());
    assert!(signed.verify(&hb, &pin, &expected, 2000, 1).is_err());
    assert!(signed.verify(&hb, &pin, &expected, 1000, 2).is_err());
    let value = serde_json::to_value(&expected).unwrap();
    for field in value.as_object().unwrap().keys() {
        let mut changed = value.clone();
        let v = &mut changed[field];
        if let Some(a) = v.as_array_mut() {
            if a[0].is_array() {
                a[0][0] = serde_json::json!(7);
            } else {
                a[0] = serde_json::json!(a[0].as_u64().unwrap() ^ 1);
            }
        } else if let Some(n) = v.as_u64() {
            *v = serde_json::json!(n + 1);
        } else {
            *v = serde_json::json!("observe");
        }
        let changed: PeerApproval = serde_json::from_value(changed).unwrap();
        assert!(
            signed.verify(&hb, &pin, &changed, 1000, 1).is_err(),
            "{field}"
        );
    }
}

#[test]
fn upstream_cacophony_xx_sha256_reference_vector() {
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    let all: serde_json::Value =
        serde_json::from_str(include_str!("../vendor/snow/tests/vectors/cacophony.txt")).unwrap();
    let v = all["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["protocol_name"] == "Noise_XX_25519_ChaChaPoly_SHA256")
        .unwrap();
    let build = |prefix: &str, initiator: bool| {
        let secret = hex(v[format!("{prefix}_static")].as_str().unwrap());
        let ephemeral = hex(v[format!("{prefix}_ephemeral")].as_str().unwrap());
        let prologue = hex(v[format!("{prefix}_prologue")].as_str().unwrap());
        let b = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
            .local_private_key(&secret)
            .unwrap()
            .fixed_ephemeral_key_for_testing_only(&ephemeral)
            .prologue(&prologue)
            .unwrap();
        if initiator {
            b.build_initiator().unwrap()
        } else {
            b.build_responder().unwrap()
        }
    };
    let mut i = build("init", true);
    let mut r = build("resp", false);
    for (n, m) in v["messages"].as_array().unwrap()[..3].iter().enumerate() {
        let (w, rd) = if n % 2 == 0 {
            (&mut i, &mut r)
        } else {
            (&mut r, &mut i)
        };
        let payload = hex(m["payload"].as_str().unwrap());
        let ciphertext = hex(m["ciphertext"].as_str().unwrap());
        let mut out = [0; 1024];
        let size = w.write_message(&payload, &mut out).unwrap();
        assert_eq!(&out[..size], ciphertext);
        let size = rd.read_message(&ciphertext, &mut out).unwrap();
        assert_eq!(&out[..size], payload);
    }
    assert_eq!(
        i.get_handshake_hash(),
        hex(v["handshake_hash"].as_str().unwrap())
    );
    let mut i = i.into_transport_mode().unwrap();
    let mut r = r.into_transport_mode().unwrap();
    for (n, m) in v["messages"].as_array().unwrap()[3..].iter().enumerate() {
        let (w, rd) = if n % 2 == 1 {
            (&mut i, &mut r)
        } else {
            (&mut r, &mut i)
        };
        let payload = hex(m["payload"].as_str().unwrap());
        let ciphertext = hex(m["ciphertext"].as_str().unwrap());
        let mut out = [0; 1024];
        let size = w.write_message(&payload, &mut out).unwrap();
        assert_eq!(&out[..size], ciphertext);
        let size = rd.read_message(&ciphertext, &mut out).unwrap();
        assert_eq!(&out[..size], payload);
    }
}
