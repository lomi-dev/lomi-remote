//! On-device directory on fixtures: merge, sealing, tamper, AD binding, versions, logout. No network.

use lomi_remote_core::directory::{Directory, Effect, Error, Key, NONCE_LEN};
use lomi_remote_core::json;
use lomi_remote_core::session::parse_session_response;
use serde_json::Value;

const ACC: &str = "acc-1";
const DEV: &str = "dev-1";
const N: [u8; NONCE_LEN] = [7; NONCE_LEN];

fn key(id: u32, b: u8) -> Key {
    Key::new(id, [b; 32])
}

fn host(id: &str, epoch: u64, generation: u64, online: bool, ws: &[&str]) -> String {
    let ws: Vec<String> = ws
        .iter()
        .map(|w| format!(r#"{{"workspaceId":"{w}","workspaceEpoch":"1"}}"#))
        .collect();
    format!(
        r#"{{"hostId":"{id}","online":{online},"accessEpoch":"{epoch}","runtimeGeneration":"{generation}","workspaces":[{}]}}"#,
        ws.join(",")
    )
}

fn session(
    account: &str,
    device: &str,
    hosts: &[String],
) -> lomi_remote_core::session::SessionResponse {
    let dev = match device {
        "revoked" => r#"{"state":"revoked"}"#.to_owned(),
        d => format!(r#"{{"state":"registered","deviceId":"{d}"}}"#),
    };
    let body = format!(
        r#"{{"account":{{"id":"{account}"}},"sessionExpiresAt":1795000000000,"relay":{{"token":"t","expiresAt":1795000000000}},"hosts":[{}],"device":{dev}}}"#,
        hosts.join(",")
    );
    parse_session_response(200, body.as_bytes()).unwrap()
}

fn event(data: &str) -> lomi_remote_core::json::Object {
    match json::parse(data).unwrap() {
        Value::Object(o) => o,
        _ => panic!(),
    }
}

fn loaded() -> Directory {
    let mut d = Directory::new(ACC, DEV);
    let r = session(
        ACC,
        DEV,
        &[
            host("h2", 3, 5, true, &["w1"]),
            host("h1", 1, 1, false, &["a", "b"]),
        ],
    );
    assert_eq!(d.apply_session(&r), Ok(Effect::Changed));
    d
}

#[test]
fn session_merge_is_authoritative_and_monotonic() {
    let mut d = loaded();
    assert_eq!(
        d.hosts().map(|h| h.id.as_str()).collect::<Vec<_>>(),
        ["h1", "h2"]
    );
    // Same data again: nothing to store.
    assert_eq!(
        d.apply_session(&session(
            ACC,
            DEV,
            &[
                host("h2", 3, 5, true, &["w1"]),
                host("h1", 1, 1, false, &["a", "b"])
            ]
        )),
        Ok(Effect::Unchanged)
    );
    // Stale entry for h2 is ignored, h1 is dropped by the server, h3 appears.
    let r = session(
        ACC,
        DEV,
        &[host("h2", 3, 4, false, &[]), host("h3", 1, 1, true, &[])],
    );
    assert_eq!(d.apply_session(&r), Ok(Effect::Changed));
    assert!(d.host("h1").is_none());
    assert!(d.host("h2").unwrap().online);
    assert_eq!(d.host("h2").unwrap().runtime_generation, 5);
    assert!(d.host("h3").is_some());
    // Newer epoch with lower generation wins (generation restarts per epoch).
    d.apply_session(&session(ACC, DEV, &[host("h2", 4, 1, false, &["x"])]))
        .unwrap();
    assert_eq!(d.host("h2").unwrap().access_epoch, 4);
}

#[test]
fn session_for_other_account_or_device_is_refused_and_changes_nothing() {
    let mut d = loaded();
    let before = d.clone();
    assert_eq!(
        d.apply_session(&session("acc-2", DEV, &[])),
        Err(Error::Mismatch)
    );
    assert_eq!(
        d.apply_session(&session(ACC, "dev-2", &[])),
        Err(Error::Mismatch)
    );
    assert_eq!(d, before);
}

#[test]
fn events_presence_inventory_revoke() {
    let mut d = loaded();
    let p = |h: &str, e: u64, g: u64, on: bool| {
        event(&format!(
            r#"{{"hostId":"{h}","online":{on},"accessEpoch":"{e}","runtimeGeneration":"{g}"}}"#
        ))
    };
    assert_eq!(
        d.apply_event("presence", &p("h1", 1, 2, true)),
        Ok(Effect::Changed)
    );
    assert!(d.host("h1").unwrap().online);
    // Out of order (older generation) and unknown Host: ignored.
    assert_eq!(
        d.apply_event("presence", &p("h1", 1, 1, false)),
        Ok(Effect::Unchanged)
    );
    assert_eq!(
        d.apply_event("presence", &p("zz", 1, 1, true)),
        Ok(Effect::Unchanged)
    );
    assert_eq!(
        d.apply_event("presence", &event(r#"{"hostId":"h1"}"#)),
        Err(Error::Malformed)
    );
    // Inventory snapshot adds a Host and a workspace.
    let inv = event(&format!(
        r#"{{"hosts":[{},{}]}}"#,
        host("h1", 1, 2, true, &["a", "b", "c"]),
        host("h4", 1, 1, true, &[])
    ));
    assert_eq!(
        d.apply_event("inventory.changed", &inv),
        Ok(Effect::Changed)
    );
    assert_eq!(d.host("h1").unwrap().workspaces.len(), 3);
    assert!(d.host("h2").is_none() && d.host("h4").is_some());
    // Host revoked at epoch 1: removed, and an old snapshot cannot bring it back.
    assert_eq!(
        d.apply_event(
            "host.revoked",
            &event(r#"{"hostId":"h1","accessEpoch":"1"}"#)
        ),
        Ok(Effect::Changed)
    );
    assert!(d.host("h1").is_none());
    d.apply_session(&session(ACC, DEV, &[host("h1", 1, 9, true, &[])]))
        .unwrap();
    assert!(d.host("h1").is_none());
    d.apply_session(&session(ACC, DEV, &[host("h1", 2, 1, true, &[])]))
        .unwrap();
    assert!(d.host("h1").is_some());
    assert_eq!(
        d.apply_event("terminal.output", &event("{}")),
        Ok(Effect::Unchanged)
    );
}

#[test]
fn seal_open_roundtrip_is_deterministic() {
    let d = loaded();
    let k = key(1, 9);
    let blob = d.seal(&k, N).unwrap();
    assert_eq!(blob, d.seal(&k, N).unwrap());
    assert_eq!(Directory::open(&blob, ACC, DEV, &[k], 0), Ok(d.clone()));
    // Revocation tombstones survive a round trip.
    let mut d = d;
    d.apply_event(
        "host.revoked",
        &event(r#"{"hostId":"h2","accessEpoch":"3"}"#),
    )
    .unwrap();
    let k = key(1, 9);
    let again = Directory::open(&d.seal(&k, N).unwrap(), ACC, DEV, &[k], 0).unwrap();
    assert_eq!(again, d);
}

#[test]
fn tamper_and_wrong_binding_are_rejected() {
    let d = loaded();
    let k = key(1, 9);
    let blob = d.seal(&k, N).unwrap();
    let open = |b: &[u8], a: &str, dv: &str, keys: &[Key]| Directory::open(b, a, dv, keys, 0);
    for i in 0..blob.len() {
        let mut t = blob.clone();
        t[i] ^= 1;
        assert!(open(&t, ACC, DEV, &[key(1, 9)]).is_err(), "byte {i}");
    }
    assert_eq!(
        open(&blob[..blob.len() - 1], ACC, DEV, &[key(1, 9)]),
        Err(Error::Auth)
    );
    assert_eq!(
        open(&blob[..10], ACC, DEV, &[key(1, 9)]),
        Err(Error::BadFormat)
    );
    assert_eq!(open(&blob, "acc-2", DEV, &[key(1, 9)]), Err(Error::Auth));
    assert_eq!(open(&blob, ACC, "dev-2", &[key(1, 9)]), Err(Error::Auth));
    assert_eq!(open(&blob, ACC, DEV, &[key(1, 8)]), Err(Error::Auth));
    assert_eq!(open(&blob, ACC, DEV, &[key(2, 9)]), Err(Error::NoKey));
    // Length-prefixed AD: moving a byte between account and device does not collide.
    let b2 = Directory::new("ab", "c").seal(&k, N).unwrap();
    assert_eq!(open(&b2, "a", "bc", &[key(1, 9)]), Err(Error::Auth));
}

#[test]
fn version_mismatch_is_reported_before_decrypting() {
    let k = key(1, 9);
    let mut blob = loaded().seal(&k, N).unwrap();
    blob[4] = 2;
    assert_eq!(
        Directory::open(&blob, ACC, DEV, &[k], 0),
        Err(Error::Version(2))
    );
}

#[test]
fn key_rotation_reads_old_then_reseals_with_new() {
    let d = loaded();
    let blob = d.seal(&key(1, 9), N).unwrap();
    let keys = [key(2, 5), key(1, 9)];
    let opened = Directory::open(&blob, ACC, DEV, &keys, 0).unwrap();
    let blob2 = opened.seal(&keys[0], [8; NONCE_LEN]).unwrap();
    // Old key retired: the new blob opens with the new key only, the old blob is refused.
    assert_eq!(Directory::open(&blob2, ACC, DEV, &[key(2, 5)], 2), Ok(d));
    assert_eq!(
        Directory::open(&blob, ACC, DEV, &[key(1, 9)], 2),
        Err(Error::Stale)
    );
}

#[test]
fn after_logout_the_directory_is_unreadable() {
    let mut d = loaded();
    let blob = d.seal(&key(1, 9), N).unwrap();
    assert!(Directory::open(&blob, ACC, DEV, &[key(1, 9)], 0).is_ok());

    d.wipe();
    assert!(d.is_wiped() && d.hosts().next().is_none());
    assert_eq!(d.seal(&key(1, 9), N), Err(Error::Wiped));
    assert_eq!(d.apply_session(&session(ACC, DEV, &[])), Err(Error::Wiped));
    // Platform destroyed the key: no key, then even a surviving copy of the old key is refused.
    assert_eq!(Directory::open(&blob, ACC, DEV, &[], 2), Err(Error::Stale));
    assert_eq!(Directory::open(&blob, ACC, DEV, &[], 0), Err(Error::NoKey));
    assert_eq!(
        Directory::open(&blob, ACC, DEV, &[key(1, 9)], 2),
        Err(Error::Stale)
    );
}

#[test]
fn revoke_events_and_revoked_device_wipe() {
    let mut d = loaded();
    assert_eq!(d.apply_event("revoked", &event("{}")), Ok(Effect::Revoked));
    assert!(d.is_wiped());
    let mut d = loaded();
    assert_eq!(
        d.apply_session(&session(ACC, "revoked", &[])),
        Ok(Effect::Revoked)
    );
    assert!(d.is_wiped() && d.hosts().next().is_none());
}

#[test]
fn names_survive_snapshots_and_offline_hosts_keep_workspaces() {
    let mut d = loaded();
    assert!(
        d.set_host_name("h1", "Mac")
            && !d.set_host_name("h1", "Mac")
            && !d.set_host_name("zz", "x")
    );
    assert!(d.set_workspace_name("h1", "a", "lomi") && !d.set_workspace_name("h1", "nope", "x"));
    // A nameless snapshot (what the server sends) keeps names; h1 goes offline with no workspaces listed.
    let r = session(
        ACC,
        DEV,
        &[
            host("h2", 3, 5, true, &["w1"]),
            host("h1", 1, 2, false, &[]),
        ],
    );
    assert_eq!(d.apply_session(&r), Ok(Effect::Changed));
    let h1 = d.host("h1").unwrap();
    assert_eq!(h1.name.as_deref(), Some("Mac"));
    assert!(!h1.online && h1.workspaces.len() == 2);
    assert_eq!(h1.workspaces[0].name.as_deref(), Some("lomi"));
    // Back online with workspace "a" gone and "c" new: the online list is authoritative.
    d.apply_session(&session(
        ACC,
        DEV,
        &[
            host("h2", 3, 5, true, &["w1"]),
            host("h1", 1, 3, true, &["b", "c"]),
        ],
    ))
    .unwrap();
    let ids: Vec<_> = d
        .host("h1")
        .unwrap()
        .workspaces
        .iter()
        .map(|w| w.id.as_str())
        .collect();
    assert_eq!(ids, ["b", "c"]);
    // Names and epochs round-trip through the sealed blob.
    let k = key(1, 9);
    let back = Directory::open(&d.seal(&k, N).unwrap(), ACC, DEV, &[key(1, 9)], 0).unwrap();
    assert_eq!(back, d);
    assert_eq!(back.host("h1").unwrap().name.as_deref(), Some("Mac"));
}

#[test]
fn workspace_epoch_is_monotonic() {
    let ws = |epoch: u64| {
        format!(
            r#"{{"hostId":"h1","online":true,"accessEpoch":"1","runtimeGeneration":"1","workspaces":[{{"workspaceId":"w","workspaceEpoch":"{epoch}"}}]}}"#
        )
    };
    let mut d = Directory::new(ACC, DEV);
    d.apply_session(&session(ACC, DEV, &[ws(5)])).unwrap();
    d.set_workspace_name("h1", "w", "keep");
    assert_eq!(
        d.apply_session(&session(ACC, DEV, &[ws(4)])),
        Ok(Effect::Unchanged)
    );
    assert_eq!(d.host("h1").unwrap().workspaces[0].epoch, 5);
    assert_eq!(
        d.apply_session(&session(ACC, DEV, &[ws(6)])),
        Ok(Effect::Changed)
    );
    let w = &d.host("h1").unwrap().workspaces[0];
    assert_eq!((w.epoch, w.name.as_deref()), (6, Some("keep")));
}
