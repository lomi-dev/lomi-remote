use super::*;
use serde_json::{json, Value};

const ACCOUNT: Id = [0xa1; 16];
const HOST_ID: Id = [0xb2; 16];
const DEVICE_ID: Id = [0xc3; 16];
const VECTOR_INTERVAL: u64 = 4;
const VECTORS: &str = include_str!("../../test-vectors/tunnel.v1.json");

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn seeded(role: Role, subject: Id, base: u8) -> Identity {
    let seed = |n: u8| Zeroizing::new([base + n; 32]);
    Identity::from_seeds(ACCOUNT, subject, role, 1, seed(0), seed(1), seed(2)).unwrap()
}

struct Fixture {
    host: Identity,
    device: Identity,
    prologue: TunnelPrologue,
}

fn fixture() -> Fixture {
    let host = seeded(Role::Host, HOST_ID, 0x10);
    let device = seeded(Role::Device, DEVICE_ID, 0x20);
    let prologue = TunnelPrologue {
        contract_hash: [0x77; 32],
        path: TunnelPath::Relay,
        circuit_id: [0x01; 16],
        nonce: [0x02; 16],
        host_id: HOST_ID,
        host_fingerprint: host.signed.bundle.fingerprint().unwrap(),
        device_fingerprint: device.signed.bundle.fingerprint().unwrap(),
        account_id: ACCOUNT,
    };
    Fixture {
        host,
        device,
        prologue,
    }
}

const E_DEVICE: [u8; 32] = [0x31; 32];
const E_HOST: [u8; 32] = [0x32; 32];
const HELLO: &[u8] = b"hello: device bundle and resume list";

/// Runs the full handshake; returns (device, host, msgs).
fn run(f: &Fixture, fixed: bool) -> (TunnelHandshake, TunnelHandshake, [Vec<u8>; 3]) {
    let (ed, eh) = (fixed.then_some(&E_DEVICE), fixed.then_some(&E_HOST));
    let mut d = TunnelHandshake::device_inner(&f.device, &f.prologue, &f.host.signed, ed).unwrap();
    let mut h = TunnelHandshake::host_inner(&f.host, &f.prologue, eh).unwrap();
    let m1 = d.write_message(&[]).unwrap();
    h.read_message(&m1).unwrap();
    let m2 = h.write_message(&[]).unwrap();
    d.read_message(&m2).unwrap();
    let m3 = d.write_message(HELLO).unwrap();
    assert_eq!(&**h.read_message(&m3).unwrap(), HELLO);
    h.verify_device(&f.device.signed).unwrap();
    (d, h, [m1, m2, m3])
}

fn pair(f: &Fixture) -> (Tunnel, Tunnel) {
    let (d, h, _) = run(f, false);
    (d.into_transport().unwrap(), h.into_transport().unwrap())
}

#[test]
fn happy_path_and_matching_codes() {
    let f = fixture();
    let (d, h, _) = run(&f, false);
    assert!(d.is_finished() && h.is_finished());
    let code = d.confirmation_code().unwrap();
    assert_eq!(code.len(), 6);
    assert_eq!(code, h.confirmation_code().unwrap());
    assert_eq!(
        h.remote_static().unwrap(),
        f.device.signed.bundle.channel_key
    );
    verify_device(
        &f.device.signed,
        &f.prologue.device_fingerprint,
        &ACCOUNT,
        &h.remote_static().unwrap(),
    )
    .unwrap();
    let (mut dt, mut ht) = (d.into_transport().unwrap(), h.into_transport().unwrap());
    assert_eq!(dt.handshake_hash(), ht.handshake_hash());
    let c = dt.encrypt(b"ping").unwrap();
    assert_eq!(&**ht.decrypt(&c).unwrap(), b"ping");
    let c = ht.encrypt(b"pong").unwrap();
    assert_eq!(&**dt.decrypt(&c).unwrap(), b"pong");
}

#[test]
fn code_unavailable_before_finish() {
    let f = fixture();
    let d = TunnelHandshake::device(&f.device, &f.prologue, &f.host.signed).unwrap();
    assert!(d.confirmation_code().is_err() && !d.is_finished());
}

/// Message 1 carries no tag, so a prologue mismatch surfaces at message 3 at the latest.
fn completes(d: &mut TunnelHandshake, h: &mut TunnelHandshake) -> bool {
    let mut go = || -> Result<()> {
        let m1 = d.write_message(&[])?;
        h.read_message(&m1)?;
        let m2 = h.write_message(&[])?;
        d.read_message(&m2)?;
        let m3 = d.write_message(HELLO)?;
        h.read_message(&m3)?;
        Ok(())
    };
    go().is_ok()
}

#[test]
fn relay_swapping_device_fingerprint_fails() {
    let f = fixture();
    let mut p = f.prologue.clone();
    p.device_fingerprint = [9; 32];
    let mut d = TunnelHandshake::device(&f.device, &f.prologue, &f.host.signed).unwrap();
    let mut h = TunnelHandshake::host(&f.host, &p).unwrap();
    assert!(!completes(&mut d, &mut h));
}

#[test]
fn replayed_message_one_with_other_circuit_fails() {
    let f = fixture();
    let mut p = f.prologue.clone();
    p.circuit_id = [0x99; 16];
    let mut d = TunnelHandshake::device(&f.device, &f.prologue, &f.host.signed).unwrap();
    let mut h = TunnelHandshake::host(&f.host, &p).unwrap();
    assert!(!completes(&mut d, &mut h));
}

#[test]
fn wrong_host_static_fails_after_message_two() {
    let f = fixture();
    // Same prologue, impostor key: built by hand to bypass the Host's own fingerprint check.
    let impostor = seeded(Role::Host, HOST_ID, 0x40);
    assert!(TunnelHandshake::host(&impostor, &f.prologue).is_err());
    let mut d = TunnelHandshake::device(&f.device, &f.prologue, &f.host.signed).unwrap();
    let mut h = build(false, &impostor, &f.prologue, None, None).unwrap();
    let m1 = d.write_message(&[]).unwrap();
    h.read_message(&m1).unwrap();
    let m2 = h.write_message(&[]).unwrap();
    assert_eq!(
        d.read_message(&m2).unwrap_err(),
        "Noise static pin mismatch"
    );
    assert!(d.write_message(&[]).is_err() && d.into_transport().is_err());
}

#[test]
fn device_bundle_with_other_channel_key_fails() {
    let f = fixture();
    let other = seeded(Role::Device, DEVICE_ID, 0x50);
    let fp = f.device.signed.bundle.fingerprint().unwrap();
    let key = other.signed.bundle.channel_key;
    assert!(verify_device(&f.device.signed, &fp, &ACCOUNT, &key).is_err());
    assert!(verify_device(
        &f.device.signed,
        &[0; 32],
        &ACCOUNT,
        &f.device.signed.bundle.channel_key
    )
    .is_err());
    assert!(verify_device(
        &f.device.signed,
        &fp,
        &[0; 16],
        &f.device.signed.bundle.channel_key
    )
    .is_err());
    assert!(verify_device(
        &f.host.signed,
        &f.prologue.host_fingerprint,
        &ACCOUNT,
        &f.host.signed.bundle.channel_key
    )
    .is_err());
}

#[test]
fn constructor_checks() {
    let f = fixture();
    assert!(TunnelHandshake::device(&f.host, &f.prologue, &f.host.signed).is_err());
    assert!(TunnelHandshake::device(&f.device, &f.prologue, &f.device.signed).is_err());
    assert!(TunnelHandshake::host(&f.device, &f.prologue).is_err());
    let mut p = f.prologue.clone();
    p.account_id = [0; 16];
    assert!(TunnelHandshake::device(&f.device, &p, &f.host.signed).is_err());
}

#[test]
fn tampered_ciphertext_poisons_tunnel() {
    let f = fixture();
    let (mut d, mut h) = pair(&f);
    let mut c = d.encrypt(b"data").unwrap();
    c[0] ^= 1;
    assert!(h.decrypt(&c).is_err());
    let good = d.encrypt(b"more").unwrap();
    assert!(h.decrypt(&good).is_err());
    assert!(h.encrypt(b"x").is_err());
}

#[test]
fn size_limits() {
    let f = fixture();
    let (mut d, mut h) = pair(&f);
    assert!(d.encrypt(&vec![0; MAX_TUNNEL_PLAINTEXT + 1]).is_err());
    let max = vec![7u8; MAX_TUNNEL_PLAINTEXT];
    let c = d.encrypt(&max).unwrap();
    assert_eq!(c.len(), MAX_TUNNEL_CIPHERTEXT);
    assert_eq!(&**h.decrypt(&c).unwrap(), &max[..]);
    assert!(h.decrypt(&vec![0; MAX_TUNNEL_CIPHERTEXT + 1]).is_err());
    let mut hs = TunnelHandshake::device(&f.device, &f.prologue, &f.host.signed).unwrap();
    assert!(hs.write_message(&vec![0; MAX_HELLO_PAYLOAD + 1]).is_err());
}

#[test]
fn rekey_stays_in_sync_across_boundaries() {
    let f = fixture();
    let (mut d, mut h) = pair(&f);
    d.interval = 3;
    h.interval = 3;
    for i in 0..10u8 {
        let c = d.encrypt(&[i]).unwrap();
        assert_eq!(&**h.decrypt(&c).unwrap(), &[i]);
        if i % 2 == 0 {
            let c = h.encrypt(&[i, i]).unwrap();
            assert_eq!(&**d.decrypt(&c).unwrap(), &[i, i]);
        }
    }
}

#[test]
fn receiver_that_skipped_rekey_fails() {
    let f = fixture();
    let (mut d, mut h) = pair(&f);
    d.interval = 2;
    h.interval = 1 << 40;
    for i in 0..2u8 {
        let c = d.encrypt(&[i]).unwrap();
        h.decrypt(&c).unwrap();
    }
    let c = d.encrypt(b"after rekey").unwrap();
    assert!(h.decrypt(&c).is_err());
}

fn vectors() -> Value {
    let f = fixture();
    let (d, h, msgs) = run(&f, true);
    let code = d.confirmation_code().unwrap();
    let (mut dt, mut ht) = (d.into_transport().unwrap(), h.into_transport().unwrap());
    dt.interval = VECTOR_INTERVAL;
    ht.interval = VECTOR_INTERVAL;
    let mut transport = Vec::new();
    for i in 0..10u8 {
        let (from, to, dir) = if i % 3 == 2 {
            (&mut ht, &mut dt, "host_to_device")
        } else {
            (&mut dt, &mut ht, "device_to_host")
        };
        let pt = vec![i; usize::from(i) + 1];
        let ct = from.encrypt(&pt).unwrap();
        assert_eq!(*to.decrypt(&ct).unwrap(), pt);
        transport.push(json!({"direction": dir, "plaintext": hex(&pt), "ciphertext": hex(&ct)}));
    }
    // Extra messages so both directions cross at least two rekey boundaries.
    for i in 10..30u8 {
        let dir = if i % 2 == 0 {
            "device_to_host"
        } else {
            "host_to_device"
        };
        let (from, to) = if i % 2 == 0 {
            (&mut dt, &mut ht)
        } else {
            (&mut ht, &mut dt)
        };
        let pt = vec![i; 3];
        let ct = from.encrypt(&pt).unwrap();
        assert_eq!(*to.decrypt(&ct).unwrap(), pt);
        transport.push(json!({"direction": dir, "plaintext": hex(&pt), "ciphertext": hex(&ct)}));
    }
    let seed = |base: u8| json!({"identity": hex(&[base; 32]), "channel": hex(&[base + 1; 32]), "mailbox": hex(&[base + 2; 32])});
    let p = &f.prologue;
    json!({
        "version": 1,
        "noise": NOISE,
        "ids": {"account": hex(&ACCOUNT), "host": hex(&HOST_ID), "device": hex(&DEVICE_ID)},
        "host_seeds": seed(0x10),
        "device_seeds": seed(0x20),
        "host_channel_key": hex(&f.host.signed.bundle.channel_key),
        "device_channel_key": hex(&f.device.signed.bundle.channel_key),
        "ephemeral": {"device": hex(&E_DEVICE), "host": hex(&E_HOST)},
        "prologue": {
            "contract_hash": hex(&p.contract_hash), "path": "relay", "circuit_id": hex(&p.circuit_id),
            "nonce": hex(&p.nonce), "host_id": hex(&p.host_id), "host_fingerprint": hex(&p.host_fingerprint),
            "device_fingerprint": hex(&p.device_fingerprint), "account_id": hex(&p.account_id),
            "encoded": hex(&p.encode()),
        },
        "hello_payload": hex(HELLO),
        "messages": [hex(&msgs[0]), hex(&msgs[1]), hex(&msgs[2])],
        "handshake_hash": hex(&dt.handshake_hash()),
        "confirmation_code": code,
        "rekey_interval": VECTOR_INTERVAL,
        "transport": transport,
    })
}

/// Regenerate with: LOMI_REGEN_VECTORS=1 cargo test -p lomi-remote-crypto tunnel_vectors
#[test]
fn tunnel_vectors() {
    let text = serde_json::to_string_pretty(&vectors()).unwrap() + "\n";
    #[cfg(not(target_arch = "wasm32"))]
    if std::env::var_os("LOMI_REGEN_VECTORS").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/tunnel.v1.json");
        std::fs::write(path, &text).unwrap();
        return;
    }
    assert_eq!(text, VECTORS, "tunnel vectors drifted");
}

#[test]
fn host_needs_verified_device_bundle() {
    let f = fixture();
    let mut d = TunnelHandshake::device(&f.device, &f.prologue, &f.host.signed).unwrap();
    let mut h = TunnelHandshake::host(&f.host, &f.prologue).unwrap();
    assert!(completes(&mut d, &mut h));
    let other = seeded(Role::Device, DEVICE_ID, 0x50);
    assert!(h.verify_device(&other.signed).is_err());
    assert!(h.into_transport().is_err());
}

#[test]
fn payload_only_in_message_three() {
    let f = fixture();
    let mut d = TunnelHandshake::device(&f.device, &f.prologue, &f.host.signed).unwrap();
    assert!(d.write_message(b"leak").is_err());
    let mut d = TunnelHandshake::device(&f.device, &f.prologue, &f.host.signed).unwrap();
    let mut h = TunnelHandshake::host(&f.host, &f.prologue).unwrap();
    h.read_message(&d.write_message(&[]).unwrap()).unwrap();
    assert!(h.write_message(b"early").is_err());
}
