#![no_main]
//! Byte 0 picks the handshake step under test, byte 1 splits the rest into two arbitrary
//! messages. Earlier steps run for real, so each step is reached with valid state.
use libfuzzer_sys::fuzz_target;
use lomi_remote_crypto::{
    Identity, Role, Tunnel, TunnelHandshake, TunnelPath, TunnelPrologue,
};
use std::sync::OnceLock;

const ACCOUNT: [u8; 16] = [0xa1; 16];
const HOST_ID: [u8; 16] = [0xb2; 16];
const DEVICE_ID: [u8; 16] = [0xc3; 16];

struct Fx {
    host: Identity,
    device: Identity,
    p: TunnelPrologue,
}

fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let host = Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap();
        let device = Identity::generate(ACCOUNT, DEVICE_ID, Role::Device, 1).unwrap();
        let p = TunnelPrologue {
            contract_hash: [0x77; 32],
            path: TunnelPath::Relay,
            circuit_id: [1; 16],
            nonce: [2; 16],
            host_id: HOST_ID,
            host_fingerprint: host.public_bundle().bundle.fingerprint().unwrap(),
            device_fingerprint: device.public_bundle().bundle.fingerprint().unwrap(),
            account_id: ACCOUNT,
        };
        Fx { host, device, p }
    })
}

fn new_device(f: &Fx) -> TunnelHandshake {
    let hb = f.host.public_bundle();
    TunnelHandshake::device(&f.device, &f.p, &hb, &f.p.host_fingerprint).unwrap()
}

/// Real handshake up to (not including) message 3: (device, host, m3).
fn until_m3(f: &Fx) -> (TunnelHandshake, TunnelHandshake, Vec<u8>) {
    let mut d = new_device(f);
    let mut h = TunnelHandshake::host(&f.host, &f.p).unwrap();
    let m1 = d.write_message(&[]).unwrap();
    h.read_message(&m1).unwrap();
    let m2 = h.write_message(&[]).unwrap();
    d.read_message(&m2).unwrap();
    let m3 = d.write_message(b"hello").unwrap();
    (d, h, m3)
}

fn transports(f: &Fx) -> (Tunnel, Tunnel) {
    let (d, mut h, m3) = until_m3(f);
    h.read_message(&m3).unwrap();
    h.verify_device(&f.device.public_bundle()).unwrap();
    (d.into_transport().unwrap(), h.into_transport().unwrap())
}

fuzz_target!(|data: &[u8]| {
    let [mode, split, rest @ ..] = data else { return };
    let (a, b) = rest.split_at((*split as usize).min(rest.len()));
    let f = fx();
    match mode % 7 {
        // Host reads an arbitrary message 1, then continues as far as it gets.
        0 => {
            let mut h = TunnelHandshake::host(&f.host, &f.p).unwrap();
            if h.read_message(a).is_ok() {
                if h.write_message(&[]).is_ok() {
                    let _ = h.read_message(b);
                }
            }
        }
        // Device sends a real message 1, then reads an arbitrary message 2.
        1 => {
            let mut d = new_device(f);
            d.write_message(&[]).unwrap();
            if d.read_message(a).is_ok() {
                let _ = d.write_message(b);
            }
        }
        // Host reads an arbitrary message 3 after a real 1 and 2.
        2 => {
            let (_d, mut h, _m3) = until_m3(f);
            if h.read_message(a).is_ok() {
                let _ = h.verify_device(&f.device.public_bundle());
                let _ = h.into_transport();
            }
        }
        // Arbitrary payloads on write at every step.
        3 => {
            let mut d = new_device(f);
            let _ = d.write_message(a);
            let _ = d.write_message(b);
            let _ = d.confirmation_code();
            let _ = d.into_transport();
        }
        // Transport: arbitrary ciphertext on either side; failure must poison, not panic.
        4 => {
            let (mut d, mut h) = transports(f);
            let _ = d.decrypt(a);
            let _ = h.decrypt(b);
            let _ = d.encrypt(a);
        }
        // A real ciphertext with a fuzzed overwrite must be rejected; then a retry must not panic.
        5 => {
            let (mut d, mut h) = transports(f);
            let mut c = d.encrypt(b"payload").unwrap();
            let mut mask = vec![0u8; c.len()];
            for (i, x) in a.iter().enumerate() {
                mask[i % c.len()] ^= x;
            }
            c.iter_mut().zip(&mask).for_each(|(c, m)| *c ^= m);
            let res = h.decrypt(&c);
            if mask.iter().any(|m| *m != 0) {
                assert!(res.is_err());
            }
            let _ = h.decrypt(b);
        }
        // Valid messages, then an oversized or short one.
        _ => {
            let (mut d, mut h) = transports(f);
            let c = d.encrypt(a).unwrap_or_default();
            let _ = h.decrypt(&c);
            let _ = h.encrypt(b);
        }
    }
});
