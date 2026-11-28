#![no_main]
//! Input is a run of calls: `op u8 | handle u8 | args_len u16 | args | payload_len u16 | payload`.
//! `handle` indexes the handles created so far in this run (0 = stateless handle 0, else an
//! arbitrary number). Handles created are freed at the end so the registry never fills up.
use libfuzzer_sys::fuzz_target;
use lomi_remote_core::bridge;

const OPS: &[&str] = &[
    "version", "frame.decode", "frame.canonical", "session.request", "session.parse", "link.new",
    "directory.new", "directory.open", "tunnel.new", "link.start", "link.stop", "link.onOpen",
    "link.onClose", "link.onMessage", "link.tick", "link.call", "link.refreshToken",
    "link.nextDeadline", "link.isReady", "link.lastServerFrame", "tunnel.nextDeadline",
    "tunnel.cursors", "tunnel.start", "tunnel.tick", "tunnel.openStream", "tunnel.send",
    "tunnel.closeStream", "tunnel.close", "directory.applySession", "directory.applyReadyState",
    "directory.applyEvent", "directory.setHostName", "directory.setWorkspaceName",
    "directory.snapshot", "directory.wipe", "directory.seal", "bogus", "tunnel.", "link.", "",
];

fn take<'a>(d: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (h, t) = d.split_at(n.min(d.len()));
    *d = t;
    h
}

fn len16(d: &mut &[u8]) -> usize {
    let b = take(d, 2);
    b.iter().fold(0usize, |a, x| a << 8 | *x as usize)
}

fuzz_target!(|data: &[u8]| {
    let mut d = data;
    let mut made: Vec<u32> = Vec::new();
    while d.len() >= 4 {
        let h = take(&mut d, 2);
        let (op, hsel) = (OPS[h[0] as usize % OPS.len()], h[1] as usize);
        let n = len16(&mut d);
        let args = take(&mut d, n);
        let n = len16(&mut d);
        let payload = take(&mut d, n);
        let handle = if hsel == 0 { 0 } else { made.get(hsel - 1).copied().unwrap_or(hsel as u32) };
        let out = bridge::call(handle, op, args, payload);
        assert!(matches!(out.first(), Some(0 | 1)));
        if out[0] == 0 {
            if let Some(n) = std::str::from_utf8(&out[1..]).ok().and_then(|s| {
                s.strip_prefix("{\"handle\":")?.strip_suffix('}')?.parse::<u32>().ok()
            }) {
                made.push(n);
            }
        }
    }
    for h in made {
        bridge::free(h);
    }
});
