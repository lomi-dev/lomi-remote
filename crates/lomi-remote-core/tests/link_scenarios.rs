//! Link client on recorded frame sequences: bytes in, bytes and events out, no network.
//! Relay frames come from the shared vectors where one exists (real recorded bytes),
//! otherwise from the codec.

use lomi_remote_core::frame::*;
use lomi_remote_core::link::*;
use lomi_remote_core::session::RelayToken;
use serde_json::Value;

const VECTORS: &str = include_str!("../test-vectors/relay-frames.v1.json");
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const WALL0: u64 = 1_794_999_000_000; // READY vectors expire at 1_795_000_000_000 (1000 s later)

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn vector(name: &str) -> Vec<u8> {
    let d: Value = serde_json::from_str(VECTORS).unwrap();
    let v = d["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap();
    hex(v["hex"].as_str().unwrap())
}
fn at(ms: u64) -> Now {
    Now {
        mono_ms: ms,
        wall_ms: WALL0 + ms,
    }
}
fn token(expires_at: u64) -> RelayToken {
    RelayToken {
        token: "T".repeat(24),
        expires_at,
    }
}
fn link() -> Link {
    Link::new(LinkConfig::new(HASH), 42)
}
fn relay(f: &Frame) -> Vec<u8> {
    encode_frame(f, MAX_FRAME_BYTES).unwrap()
}
fn events(out: &[Output]) -> Vec<&LinkEvent> {
    out.iter()
        .filter_map(|o| {
            if let Output::Event(e) = o {
                Some(e)
            } else {
                None
            }
        })
        .collect()
}
fn sent(out: &[Output]) -> Vec<Frame> {
    out.iter()
        .filter_map(|o| {
            if let Output::Send(b) = o {
                Some(decode_frame(b, Direction::Client, MAX_FRAME_BYTES).unwrap())
            } else {
                None
            }
        })
        .collect()
}
fn retry_ms(out: &[Output]) -> u64 {
    events(out)
        .iter()
        .find_map(|e| {
            if let LinkEvent::Disconnected {
                retry_in_ms: Some(d),
                ..
            } = e
            {
                Some(*d)
            } else {
                None
            }
        })
        .expect("retry delay")
}

/// Drives a fresh link to READY at t=0 using the recorded `ready-device` frame.
fn ready_link() -> Link {
    let mut l = link();
    assert_eq!(
        l.start(token(WALL0 + 1_000_000), at(0)),
        vec![Output::Connect]
    );
    let out = l.on_open(at(0));
    assert!(
        matches!(&sent(&out)[..], [Frame::Auth { role: Role::Device, contract_hash, .. }] if contract_hash == HASH)
    );
    let out = l.on_message(&vector("ready-device"), at(5));
    assert!(matches!(
        events(&out)[..],
        [LinkEvent::Ready {
            expires_at: 1_795_000_000_000,
            ..
        }]
    ));
    assert!(l.is_ready());
    l
}

#[test]
fn happy_path_events_and_calls() {
    let mut l = ready_link();
    // recorded EVENT passes through untouched
    let out = l.on_message(&vector("event-presence"), at(10));
    assert!(matches!(events(&out)[..], [LinkEvent::Server { name, .. }] if name == "presence"));
    // first call gets id 1, matching the recorded reply-ok vector
    let mut args = serde_json::Map::new();
    args.insert(
        "hostId".into(),
        "11111111-1111-4111-8111-111111111111".into(),
    );
    let (id, out) = l.call("circuit.open", args, at(20)).unwrap();
    assert_eq!(id, 1);
    assert!(
        matches!(&sent(&out)[..], [Frame::Call { call_id: 1, name, .. }] if name == "circuit.open")
    );
    let out = l.on_message(&vector("reply-ok"), at(30));
    assert!(matches!(
        events(&out)[..],
        [LinkEvent::CallDone {
            call_id: 1,
            result: Ok(_)
        }]
    ));
    // error reply
    let (id, _) = l.call("circuit.close", Default::default(), at(40)).unwrap();
    let out = l.on_message(
        &relay(&Frame::ReplyErr {
            call_id: id,
            code: "NO_CIRCUIT".into(),
        }),
        at(41),
    );
    assert_eq!(
        events(&out),
        [&LinkEvent::CallDone {
            call_id: id,
            result: Err(CallError::Remote("NO_CIRCUIT".into()))
        }]
    );
}

#[test]
fn call_rules_and_inflight_limit() {
    let mut l = link();
    assert_eq!(
        l.call("circuit.open", Default::default(), at(0))
            .unwrap_err(),
        CallError::NotReady
    );
    let mut l = ready_link();
    assert_eq!(
        l.call("publication.put", Default::default(), at(1))
            .unwrap_err(),
        CallError::UnknownCall
    );
    assert_eq!(
        l.call("token.update", Default::default(), at(1))
            .unwrap_err(),
        CallError::UnknownCall
    );
    assert_eq!(
        l.call("Bad Name", Default::default(), at(1)).unwrap_err(),
        CallError::UnknownCall
    );
    for _ in 0..8 {
        l.call("circuit.close", Default::default(), at(1)).unwrap();
    }
    assert_eq!(
        l.call("circuit.close", Default::default(), at(1))
            .unwrap_err(),
        CallError::TooManyInflight
    );
    // a reply frees a slot; an unknown or late reply is ignored
    assert!(
        events(&l.on_message(
            &relay(&Frame::ReplyOk {
                call_id: 999,
                data: Default::default()
            }),
            at(2)
        ))
        .is_empty()
    );
    l.on_message(
        &relay(&Frame::ReplyOk {
            call_id: 3,
            data: Default::default(),
        }),
        at(3),
    );
    assert!(l.call("circuit.close", Default::default(), at(4)).is_ok());
}

#[test]
fn call_timeout_is_tick_driven() {
    let mut l = ready_link();
    let (id, _) = l
        .call("circuit.close", Default::default(), at(100))
        .unwrap();
    assert_eq!(l.next_deadline(), Some(15_100));
    assert!(l.tick(at(15_099)).is_empty());
    let out = l.tick(at(15_100));
    assert_eq!(
        events(&out),
        [&LinkEvent::CallDone {
            call_id: id,
            result: Err(CallError::Timeout)
        }]
    );
    // the late reply no longer matches anything
    assert!(
        l.on_message(
            &relay(&Frame::ReplyOk {
                call_id: id,
                data: Default::default()
            }),
            at(15_200)
        )
        .is_empty()
    );
}

#[test]
fn auth_failure_stops_without_retry() {
    let mut l = link();
    l.start(token(WALL0 + 1_000_000), at(0));
    l.on_open(at(0));
    let out = l.on_message(
        &relay(&Frame::ReadyErr {
            code: ReadyErrorCode::AuthFailed,
            older: None,
        }),
        at(1),
    );
    assert_eq!(
        out,
        vec![
            Output::Close,
            Output::Event(LinkEvent::Stopped(StopReason::AuthFailed))
        ]
    );
    assert_eq!(l.next_deadline(), None);
    assert!(l.tick(at(1_000_000)).is_empty());
    // a fresh token starts it again
    assert_eq!(
        l.start(token(WALL0 + 2_000_000), at(2)),
        vec![Output::Connect]
    );
}

#[test]
fn update_required_stops_and_reports_older_side() {
    let mut l = link();
    l.start(token(WALL0 + 1_000_000), at(0));
    l.on_open(at(0));
    let out = l.on_message(&vector("ready-update-required"), at(1));
    assert_eq!(
        events(&out),
        [&LinkEvent::Stopped(StopReason::UpdateRequired {
            older: Some(Older::Unknown)
        })]
    );
    assert!(!l.is_ready() && l.next_deadline().is_none());
}

#[test]
fn unavailable_and_busy_reconnect_with_growing_backoff() {
    let mut l = link();
    l.start(token(WALL0 + 10_000_000), at(0));
    let mut now = 0;
    let mut upper = 500;
    for i in 0..8 {
        l.on_open(at(now));
        let code = if i % 2 == 0 {
            ReadyErrorCode::Unavailable
        } else {
            ReadyErrorCode::Busy
        };
        let out = l.on_message(&relay(&Frame::ReadyErr { code, older: None }), at(now));
        assert_eq!(out[0], Output::Close);
        let d = retry_ms(&out);
        assert!(
            (upper / 2..=upper).contains(&d),
            "attempt {i}: {d} not in [{}, {upper}]",
            upper / 2
        );
        assert_eq!(l.next_deadline(), Some(now + d));
        assert!(l.tick(at(now + d - 1)).is_empty());
        assert_eq!(l.tick(at(now + d)), vec![Output::Connect]);
        now += d;
        upper = (upper * 2).min(30_000);
    }
    // a successful READY resets the backoff
    l.on_open(at(now));
    l.on_message(&vector("ready-device"), at(now));
    let out = l.on_close(at(now + 1));
    assert!((250..=500).contains(&retry_ms(&out)));
}

#[test]
fn jitter_is_deterministic_per_seed() {
    let run = |seed| {
        let mut l = Link::new(LinkConfig::new(HASH), seed);
        l.start(token(WALL0 + 10_000_000), at(0));
        (0..4)
            .map(|_| {
                l.on_open(at(0));
                let d = retry_ms(&l.on_close(at(0)));
                l.tick(at(100_000));
                d
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(run(7), run(7));
    assert_ne!(run(7), run(8));
}

#[test]
fn reconnect_after_socket_loss_aborts_calls() {
    let mut l = ready_link();
    let (id, _) = l.call("circuit.close", Default::default(), at(10)).unwrap();
    let out = l.on_close(at(20));
    assert_eq!(
        events(&out)[0],
        &LinkEvent::CallDone {
            call_id: id,
            result: Err(CallError::Aborted)
        }
    );
    let d = retry_ms(&out);
    assert!(!l.is_ready());
    assert!(l.call("circuit.close", Default::default(), at(21)).is_err());
    assert_eq!(l.tick(at(20 + d)), vec![Output::Connect]);
    // second session is a full AUTH again, ids keep counting
    let out = l.on_open(at(20 + d));
    assert!(matches!(&sent(&out)[..], [Frame::Auth { .. }]));
    l.on_message(&vector("ready-device"), at(20 + d));
    assert_eq!(
        l.call("circuit.close", Default::default(), at(30 + d))
            .unwrap()
            .0,
        id + 1
    );
}

#[test]
fn connect_and_ready_timeouts_retry() {
    let mut l = link();
    l.start(token(WALL0 + 10_000_000), at(0));
    assert_eq!(l.next_deadline(), Some(10_000));
    let out = l.tick(at(10_000));
    assert_eq!(out[0], Output::Close);
    assert!(matches!(
        events(&out)[..],
        [LinkEvent::Disconnected {
            cause: DisconnectCause::ConnectTimeout,
            ..
        }]
    ));
    let d = retry_ms(&out);
    l.tick(at(10_000 + d));
    l.on_open(at(10_000 + d));
    let out = l.tick(at(20_000 + d));
    assert!(matches!(
        events(&out)[..],
        [LinkEvent::Disconnected {
            cause: DisconnectCause::ReadyTimeout,
            ..
        }]
    ));
}

#[test]
fn token_refresh_flow_and_failure() {
    // READY at t=5 carries 999_995 ms: refresh is due 300 s before that, expiry at t=1_000_000.
    let mut l = ready_link();
    let refresh_at = l.next_deadline().unwrap();
    assert_eq!(refresh_at, 700_000);
    assert!(l.tick(at(refresh_at - 1)).is_empty());
    assert_eq!(
        events(&l.tick(at(refresh_at))),
        [&LinkEvent::TokenRefreshNeeded]
    );
    assert!(l.tick(at(refresh_at + 1)).is_empty(), "asked once");
    let new_expiry = 1_795_000_000_000 + 3_600_000;
    let out = l
        .refresh_token(token(new_expiry), at(refresh_at + 10))
        .unwrap();
    let Frame::Call {
        call_id,
        name,
        args,
    } = &sent(&out)[0]
    else {
        panic!()
    };
    assert_eq!(name, "token.update");
    assert_eq!(args["token"], "T".repeat(24));
    let out = l.on_message(
        &relay(&Frame::ReplyOk {
            call_id: *call_id,
            data: Default::default(),
        }),
        at(refresh_at + 20),
    );
    assert_eq!(
        events(&out),
        [&LinkEvent::TokenRefreshed {
            expires_at: new_expiry
        }]
    );
    // the old expiry no longer closes the link
    assert!(l.tick(at(1_000_000)).is_empty() && l.is_ready());
    // rejected refresh is reported, the link stays up
    let out = l
        .refresh_token(token(new_expiry + 1), at(refresh_at + 30))
        .unwrap();
    let Frame::Call { call_id, .. } = &sent(&out)[0] else {
        panic!()
    };
    let out = l.on_message(
        &relay(&Frame::ReplyErr {
            call_id: *call_id,
            code: "AUTH_FAILED".into(),
        }),
        at(refresh_at + 40),
    );
    assert_eq!(
        events(&out),
        [&LinkEvent::TokenRefreshFailed {
            code: Some("AUTH_FAILED".into())
        }]
    );
    assert!(l.is_ready());
}

#[test]
fn token_expiry_closes_link_and_asks_for_a_token() {
    let mut l = ready_link();
    let expiry = 1_000_000;
    let refresh_at = l.next_deadline().unwrap();
    l.tick(at(refresh_at)); // TokenRefreshNeeded, nobody answers
    assert_eq!(l.next_deadline(), Some(expiry));
    let out = l.tick(at(expiry));
    assert_eq!(out[0], Output::Close);
    assert_eq!(
        events(&out),
        [
            &LinkEvent::Disconnected {
                cause: DisconnectCause::TokenExpired,
                retry_in_ms: None
            },
            &LinkEvent::TokenNeeded
        ]
    );
    assert!(!l.is_ready() && l.next_deadline().is_none());
    assert_eq!(
        l.start(token(WALL0 + 5_000_000), at(expiry + 1)),
        vec![Output::Connect]
    );
}

#[test]
fn stale_token_after_long_backoff_is_not_reused() {
    let mut l = link();
    l.start(token(WALL0 + 60_000), at(0));
    l.on_open(at(0));
    let out = l.on_message(
        &relay(&Frame::ReadyErr {
            code: ReadyErrorCode::Unavailable,
            older: None,
        }),
        at(0),
    );
    let d = retry_ms(&out);
    // the platform slept past the token's expiry
    let out = l.tick(Now {
        mono_ms: d,
        wall_ms: WALL0 + 120_000,
    });
    assert_eq!(events(&out), [&LinkEvent::TokenNeeded]);
}

#[test]
fn malformed_frames_drop_the_socket_and_retry() {
    for bad in [
        vec![],
        vec![0x10, b'{', b'}'], // DATA is not valid on the link yet
        vec![0x02, 0xff],       // bad UTF-8
        vec![0x03, b'{'],       // truncated JSON
        relay(&Frame::Auth {
            role: Role::Device,
            token: "T".repeat(24),
            contract_hash: HASH.into(),
        }), // client frame from the relay
        vec![0x05, b'[', b']'],
    ] {
        let mut l = ready_link();
        let out = l.on_message(&bad, at(50));
        assert_eq!(out[0], Output::Close, "{bad:?}");
        assert!(matches!(
            events(&out)[..],
            [LinkEvent::Disconnected {
                cause: DisconnectCause::Protocol,
                retry_in_ms: Some(_)
            }]
        ));
        assert!(!l.is_ready());
    }
}

#[test]
fn frames_outside_the_state_table_are_violations() {
    // EVENT before READY
    let mut l = link();
    l.start(token(WALL0 + 1_000_000), at(0));
    l.on_open(at(0));
    let out = l.on_message(&vector("event-presence"), at(1));
    assert!(matches!(
        events(&out)[..],
        [LinkEvent::Disconnected {
            cause: DisconnectCause::Protocol,
            ..
        }]
    ));
    // READY twice
    let mut l = ready_link();
    assert!(matches!(
        events(&l.on_message(&vector("ready-device"), at(9)))[..],
        [LinkEvent::Disconnected {
            cause: DisconnectCause::Protocol,
            ..
        }]
    ));
    // READY for the wrong role
    let mut l = link();
    l.start(token(WALL0 + 1_000_000), at(0));
    l.on_open(at(0));
    assert!(matches!(
        events(&l.on_message(&vector("ready-host"), at(1)))[..],
        [LinkEvent::Disconnected {
            cause: DisconnectCause::Protocol,
            ..
        }]
    ));
    // messages after we closed are ignored
    assert!(l.on_message(&vector("event-presence"), at(2)).is_empty());
}

#[test]
fn bad_token_shape_is_fatal() {
    let mut l = link();
    l.start(
        RelayToken {
            token: "short".into(),
            expires_at: WALL0 + 1_000_000,
        },
        at(0),
    );
    let out = l.on_open(at(0));
    assert_eq!(
        out,
        vec![
            Output::Close,
            Output::Event(LinkEvent::Stopped(StopReason::BadToken))
        ]
    );
}

#[test]
fn stop_closes_and_does_not_retry() {
    let mut l = ready_link();
    let (id, _) = l.call("circuit.close", Default::default(), at(10)).unwrap();
    let out = l.stop();
    assert_eq!(out[0], Output::Close);
    assert!(events(&out).contains(&&LinkEvent::CallDone {
        call_id: id,
        result: Err(CallError::Aborted)
    }));
    assert_eq!(
        events(&out).last(),
        Some(&&LinkEvent::Stopped(StopReason::Requested))
    );
    assert!(l.tick(at(10_000_000)).is_empty());
}
