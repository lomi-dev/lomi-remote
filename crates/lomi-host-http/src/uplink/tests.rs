use super::*;
use serde_json::json;

const HOST: &str = "11111111-1111-4111-8111-111111111111";
const RUNTIME: &str = "22222222-2222-4222-8222-222222222222";
const HASH: &str = "ab00000000000000000000000000000000000000000000000000000000000001";
const TOKEN: &str = "tok_AAAAAAAAAAAAAAAAAAAAAAAA";
const TOKEN2: &str = "tok_BBBBBBBBBBBBBBBBBBBBBBBB";

fn binding() -> Binding {
    Binding {
        host: HOST.into(),
        runtime_id: RUNTIME.into(),
        generation: 5,
        epoch: 6,
    }
}
fn runtime_binding() -> RuntimeBinding {
    serde_json::from_value(
        json!({"runtimeId": RUNTIME, "runtimeGeneration": "5", "hostAccessEpoch": "6"}),
    )
    .unwrap()
}
fn host_id() -> HostId {
    HostId::try_from(HOST.to_owned()).unwrap()
}
fn access(token: &str) -> HostAccessCredential {
    HostAccessCredential::try_from(token.to_owned()).unwrap()
}
fn relay_frame(frame: &Frame) -> Vec<u8> {
    encode_frame(frame, MAX_FRAME_BYTES).unwrap()
}
fn reply_ok(call_id: u32, data: Value) -> Frame {
    let Value::Object(data) = data else { panic!() };
    Frame::ReplyOk { call_id, data }
}
fn event(name: &str) -> Frame {
    Frame::Event {
        name: name.into(),
        data: Object::new(),
    }
}
fn uuid(n: u64) -> String {
    format!("{:08x}-0000-4000-8000-{:012x}", n, n)
}
fn params(workspaces: usize, terminals: usize) -> PublicationParams {
    let mut n = 1000u64;
    let workspaces: Vec<Value> = (0..workspaces)
        .map(|_| {
            n += 1;
            let w = uuid(n);
            let e = uuid(n + 5_000_000);
            let terminals: Vec<Value> = (0..terminals)
                .map(|_| {
                    n += 1;
                    json!({"paneId": uuid(n), "sessionId": uuid(n + 1_000_000), "sessionEpoch": uuid(n + 2_000_000)})
                })
                .collect();
            json!({"workspaceId": w, "workspaceEpoch": e, "terminals": terminals})
        })
        .collect();
    serde_json::from_value(json!({
        "runtime": {"runtimeId": RUNTIME, "runtimeGeneration": "5", "hostAccessEpoch": "6"},
        "expectedPublicationSeq": "9", "publicationSeq": "10", "workspaces": workspaces
    }))
    .unwrap()
}
fn leaked() -> &'static Shared {
    Box::leak(Box::new(Shared::new(HASH.into())))
}
fn go_live(sh: &Shared, token: &str) {
    let mut st = lock(&sh.state);
    st.desired = Some(Desired {
        binding: binding(),
        token: Zeroizing::new(token.into()),
        offered_at: Instant::now(),
    });
    st.live = Some(Live {
        binding: binding(),
        last_fresh: Instant::now(),
        token_current: true,
        publication_seq: Some(9),
    });
}

#[test]
fn auth_frame_is_the_canonical_recorded_bytes() {
    let bytes = auth_frame(HASH, TOKEN, &binding()).unwrap();
    let expected = format!(
        "\u{1}{{\"role\":\"host\",\"token\":\"{TOKEN}\",\"contractHash\":\"{HASH}\",\"claim\":{{\"hostId\":\"{HOST}\",\"runtimeId\":\"{RUNTIME}\",\"expectedGeneration\":\"4\"}}}}"
    );
    assert_eq!(bytes, expected.as_bytes());
    // generation 0 has no predecessor to claim from
    assert!(
        auth_frame(
            HASH,
            TOKEN,
            &Binding {
                generation: 0,
                ..binding()
            }
        )
        .is_none()
    );
}

#[test]
fn ready_must_match_the_actor_binding() {
    let ready = |runtime_generation: &str| {
        relay_frame(&Frame::ReadyOk {
            role: Role::Host,
            expires_at: 1_900_000_000_000,
            state: match json!({"hostId": HOST, "runtime": {"runtimeId": RUNTIME, "runtimeGeneration": runtime_generation, "hostAccessEpoch": "6"}, "leaseMs": "29988", "publicationSeq": "9"})
            {
                Value::Object(o) => o,
                _ => unreachable!(),
            },
        })
    };
    let ok = parse_ready(&ready("5"), &binding()).unwrap();
    assert_eq!(ok.publication_seq, 9);
    assert_eq!(
        parse_ready(&ready("6"), &binding()).err(),
        Some(Refusal::Invalid)
    );
    assert_eq!(
        parse_ready(
            &ready("5"),
            &Binding {
                host: uuid(7),
                ..binding()
            }
        )
        .err(),
        Some(Refusal::Invalid)
    );
    for (code, refusal) in [
        (ReadyErrorCode::HostBusy, Refusal::Busy),
        (ReadyErrorCode::StaleEpoch, Refusal::StaleEpoch),
        (ReadyErrorCode::AuthFailed, Refusal::AuthFailed),
        (ReadyErrorCode::UpdateRequired, Refusal::UpdateRequired),
        (ReadyErrorCode::Busy, Refusal::Unavailable),
    ] {
        let bytes = relay_frame(&Frame::ReadyErr { code, older: None });
        assert_eq!(parse_ready(&bytes, &binding()).err(), Some(refusal));
    }
}

#[test]
fn events_map_to_wake_hints_and_close() {
    let mut s = Session::new(Zeroizing::new(TOKEN.into()));
    assert!(matches!(
        s.on_frame(event("authority.fresh"))[..],
        [Effect::Fresh]
    ));
    assert!(matches!(
        s.on_frame(event("channel.pending"))[..],
        [Effect::Wake(Pending::Channels)]
    ));
    assert!(matches!(
        s.on_frame(event("pairing.pending"))[..],
        [Effect::Wake(Pending::Pairings)]
    ));
    assert!(matches!(
        s.on_frame(event("host.revoked"))[..],
        [Effect::Close]
    ));
    assert!(s.on_frame(event("devices.changed")).is_empty());
    assert!(s.on_frame(event("device.revoked")).is_empty());
    // a reply nobody asked for is a protocol violation
    assert!(matches!(
        s.on_frame(reply_ok(77, json!({})))[..],
        [Effect::Close]
    ));
}

#[test]
fn rotation_sends_token_update_without_closing_the_link() {
    let mut s = Session::new(Zeroizing::new(TOKEN.into()));
    let mut queue = VecDeque::new();
    assert!(s.next_send(TOKEN, &binding(), &mut queue).is_none());
    let bytes = s
        .next_send(TOKEN2, &binding(), &mut queue)
        .expect("token.update");
    let Frame::Call {
        call_id,
        name,
        args,
    } = decode_frame(&bytes, Direction::Client, MAX_FRAME_BYTES).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        (name.as_str(), args.get("token").and_then(Value::as_str)),
        ("token.update", Some(TOKEN2))
    );
    // one call at a time: nothing else goes out until the ack
    assert!(s.next_send(TOKEN2, &binding(), &mut queue).is_none());
    assert!(matches!(
        s.on_frame(reply_ok(
            call_id,
            json!({"expiresAt": 1_900_000_000_000u64})
        ))[..],
        [Effect::TokenAcked]
    ));
    assert_eq!(s.sent_token.as_str(), TOKEN2);
    assert!(s.next_send(TOKEN2, &binding(), &mut queue).is_none());
}

#[test]
fn a_refused_token_update_ends_the_link_so_it_reconnects_with_the_new_token() {
    let mut s = Session::new(Zeroizing::new(TOKEN.into()));
    let mut queue = VecDeque::new();
    let bytes = s.next_send(TOKEN2, &binding(), &mut queue).unwrap();
    let Frame::Call { call_id, .. } =
        decode_frame(&bytes, Direction::Client, MAX_FRAME_BYTES).unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        s.on_frame(Frame::ReplyErr {
            call_id,
            code: "AUTH_FAILED".into()
        })[..],
        [Effect::Close]
    ));
}

#[test]
fn chunks_respect_the_size_bound_and_the_relays_continuation_rule() {
    let p = params(3, 700);
    let chunks = publication_chunks(&p).unwrap();
    assert!(chunks.len() > 1 && chunks.len() <= MAX_CHUNKS);
    let mut terminals = 0;
    let mut last: Option<Object> = None;
    for (i, args) in chunks.iter().enumerate() {
        let frame = relay_frame(&Frame::Call {
            call_id: 1,
            name: "publication.put".into(),
            args: args.clone(),
        });
        assert!(
            frame.len() <= MAX_FRAME_BYTES,
            "chunk {i} is {} bytes",
            frame.len()
        );
        assert_eq!(args["chunk"], json!({"index": i, "count": chunks.len()}));
        assert_eq!(
            (&args["expectedPublicationSeq"], &args["publicationSeq"]),
            (&json!("9"), &json!("10"))
        );
        let entries = args["workspaces"].as_array().unwrap();
        for (j, entry) in entries.iter().enumerate() {
            let entry = entry.as_object().unwrap();
            terminals += entry["terminals"].as_array().unwrap().len();
            // only the first entry of a later chunk may repeat the previous chunk's last workspace
            if let Some(prev) = last
                .as_ref()
                .filter(|p| j == 0 && p["workspaceId"] == entry["workspaceId"])
            {
                assert!(i > 0);
                assert_eq!(prev["workspaceEpoch"], entry["workspaceEpoch"]);
            }
            if j > 0 {
                assert_ne!(entries[j - 1]["workspaceId"], entry["workspaceId"]);
            }
        }
        last = entries.last().and_then(Value::as_object).cloned();
    }
    assert_eq!(terminals, 2100);
    // a publication that cannot fit 32 chunks is left to HTTP
    assert!(publication_chunks(&params(1, 4000)).is_some());
    assert_eq!(publication_chunks(&params(0, 0)).unwrap().len(), 1);
}

#[test]
fn heartbeat_is_served_only_for_the_admitted_runtime_and_a_fresh_link() {
    let sh = leaked();
    // no link yet: HTTP
    assert!(heartbeat_on(sh, host_id(), &runtime_binding(), &access(TOKEN)).is_none());
    go_live(sh, TOKEN);
    let r = heartbeat_on(sh, host_id(), &runtime_binding(), &access(TOKEN)).unwrap();
    assert_eq!(
        (r.lease_ms.0, r.freshness_ms.0, r.runtime.clone()),
        (15_000, 5_000, runtime_binding())
    );
    let other: RuntimeBinding = serde_json::from_value(
        json!({"runtimeId": RUNTIME, "runtimeGeneration": "6", "hostAccessEpoch": "6"}),
    )
    .unwrap();
    assert!(heartbeat_on(sh, host_id(), &other, &access(TOKEN)).is_none());
    // authority.fresh stopped: the relay is not confirmed, so the heartbeat goes to HTTP again
    go_live(sh, TOKEN);
    lock(&sh.state).live.as_mut().unwrap().last_fresh =
        Instant::now() - FRESH_MAX_AGE - Duration::from_millis(50);
    assert!(heartbeat_on(sh, host_id(), &runtime_binding(), &access(TOKEN)).is_none());
}

#[test]
fn pending_reads_skip_http_until_a_wake_hint_and_a_fresh_http_heartbeat() {
    let sh = leaked();
    assert!(
        pending_gate_on(sh, Pending::Channels) == Gate::Http,
        "down: legacy polling"
    );
    go_live(sh, TOKEN);
    assert!(pending_gate_on(sh, Pending::Channels) == Gate::Skip);
    assert!(
        !lock(&sh.state).peer_active(Instant::now()),
        "idle: no peer window"
    );
    // channel.pending arrived (or the link just connected)
    lock(&sh.state).fetch = [true, false];
    assert!(
        pending_gate_on(sh, Pending::Pairings) == Gate::Skip,
        "a channel hint does not wake pairings"
    );
    // the hint opens the peer window but the read waits for an HTTP heartbeat
    assert!(pending_gate_on(sh, Pending::Channels) == Gate::Skip);
    assert!(lock(&sh.state).peer_active(Instant::now()));
    assert!(lock(&sh.state).fetch[0], "the hint is kept");
    assert!(
        heartbeat_on(sh, host_id(), &runtime_binding(), &access(TOKEN)).is_none(),
        "peers active: the heartbeat goes to the server"
    );
    lock(&sh.state).http_heartbeat_at = Some(Instant::now());
    assert!(pending_gate_on(sh, Pending::Channels) == Gate::Fetch);
    assert!(
        pending_gate_on(sh, Pending::Channels) == Gate::Skip,
        "one hint, one read"
    );
    // the window ends: heartbeats and runtime reads come from the link again
    lock(&sh.state).peer_until = Some(Instant::now() - Duration::from_secs(1));
    assert!(heartbeat_on(sh, host_id(), &runtime_binding(), &access(TOKEN)).is_some());
    assert!(runtime_get_on(sh, host_id()).is_some());
}

#[test]
fn publication_over_the_link_follows_the_http_outcomes() {
    let run = |reply: fn(u32, usize, usize) -> Frame, p: PublicationParams| {
        let sh = leaked();
        go_live(sh, TOKEN);
        let relay = std::thread::spawn(move || {
            // plays the relay against the real Session, like the uplink thread does
            let mut s = Session::new(Zeroizing::new(TOKEN.into()));
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut sent = 0;
            while Instant::now() < deadline {
                let bytes = {
                    let mut st = lock(&sh.state);
                    s.next_send(TOKEN, &binding(), &mut st.jobs)
                };
                match bytes {
                    Some(b) => {
                        let Frame::Call { call_id, args, .. } =
                            decode_frame(&b, Direction::Client, MAX_FRAME_BYTES).unwrap()
                        else {
                            panic!()
                        };
                        let count = args["chunk"]["count"].as_u64().unwrap() as usize;
                        sent += 1;
                        s.on_frame(reply(call_id, sent, count));
                        if sent == count {
                            return;
                        }
                    }
                    None => std::thread::sleep(Duration::from_millis(2)),
                }
            }
            panic!("publication never reached the relay");
        });
        let result = publication_on(sh, host_id(), &p, None).expect("served by the link");
        relay.join().unwrap();
        result
    };
    let ok = |id, sent, count| {
        if sent == count {
            reply_ok(id, json!({"publicationSeq": "10"}))
        } else {
            reply_ok(id, json!({"received": sent - 1}))
        }
    };
    let r = run(ok, params(2, 600)).unwrap();
    assert_eq!((r.publication_seq.0, r.runtime), (10, runtime_binding()));
    let stale = |id, _, _| Frame::ReplyErr {
        call_id: id,
        code: "STALE_EPOCH".into(),
    };
    assert_eq!(
        run(stale, params(1, 1)).unwrap_err(),
        Error::DataRemote(DataFailure::StaleEpoch)
    );
    let unavailable = |id, _, _| Frame::ReplyErr {
        call_id: id,
        code: "UNAVAILABLE".into(),
    };
    assert_eq!(
        run(unavailable, params(1, 1)).unwrap_err(),
        Error::DataRemote(DataFailure::OutcomeUnknown)
    );
    let wrong_seq = |id, _, _| reply_ok(id, json!({"publicationSeq": "11"}));
    assert_eq!(
        run(wrong_seq, params(1, 1)).unwrap_err(),
        Error::DataRemote(DataFailure::OutcomeUnknown)
    );
}

#[test]
fn publication_goes_to_http_while_a_token_update_is_pending() {
    let sh = leaked();
    go_live(sh, TOKEN);
    lock(&sh.state).live.as_mut().unwrap().token_current = false;
    assert!(publication_on(sh, host_id(), &params(1, 1), None).is_none());
}

#[test]
fn a_dropped_link_fails_jobs_by_whether_the_final_chunk_went_out() {
    let mut s = Session::new(Zeroizing::new(TOKEN.into()));
    let job = |p| {
        Arc::new(Job {
            binding: binding(),
            next: 10,
            chunks: publication_chunks(&p).unwrap(),
            out: Mutex::new(JobOut::Pending {
                final_sent: false,
                abandoned: false,
            }),
            cv: Condvar::new(),
        })
    };
    let (a, b) = (job(params(1, 1)), job(params(1, 1)));
    let mut queue: VecDeque<_> = [a.clone(), b.clone()].into();
    assert!(s.next_send(TOKEN, &binding(), &mut queue).is_some());
    s.fail_jobs(&mut queue);
    let outcome = |j: &Job| match &*lock(&j.out) {
        JobOut::Done(r) => r.unwrap_err(),
        _ => panic!("pending"),
    };
    assert_eq!(outcome(&a), Error::DataRemote(DataFailure::OutcomeUnknown));
    assert_eq!(
        outcome(&b),
        Error::DataRemote(DataFailure::ServiceUnavailable)
    );
}

#[test]
fn backoff_grows_to_thirty_seconds_with_jitter() {
    assert!(backoff(1) >= Duration::from_millis(250) && backoff(1) <= Duration::from_millis(500));
    assert!(backoff(3) >= Duration::from_secs(1) && backoff(3) <= Duration::from_secs(2));
    assert!(backoff(40) >= Duration::from_secs(15) && backoff(40) <= Duration::from_secs(30));
}

#[test]
fn runtime_reads_are_served_by_the_link_until_a_publication_is_uncertain() {
    let sh = leaked();
    assert!(runtime_get_on(sh, host_id()).is_none(), "no link: HTTP");
    go_live(sh, TOKEN);
    let r = runtime_get_on(sh, host_id()).unwrap();
    assert_eq!(
        (r.publication_seq.0, r.runtime),
        (9, Some(runtime_binding()))
    );
    assert_eq!((r.lease_ms.0, r.freshness_ms.0), (15_000, 5_000));
    // our own acknowledged publication moves the sequence; an uncertain one loses track of it
    let mut s = Session::new(Zeroizing::new(TOKEN.into()));
    let job = |p| {
        Arc::new(Job {
            binding: binding(),
            next: 10,
            chunks: publication_chunks(&p).unwrap(),
            out: Mutex::new(JobOut::Pending {
                final_sent: false,
                abandoned: false,
            }),
            cv: Condvar::new(),
        })
    };
    let mut queue: VecDeque<_> = [job(params(1, 1))].into();
    let bytes = s.next_send(TOKEN, &binding(), &mut queue).unwrap();
    let Frame::Call { call_id, .. } =
        decode_frame(&bytes, Direction::Client, MAX_FRAME_BYTES).unwrap()
    else {
        panic!()
    };
    let effects = s.on_frame(Frame::ReplyErr {
        call_id,
        code: "UNAVAILABLE".into(),
    });
    assert!(matches!(effects[..], [Effect::Published(None)]));
    lock(&sh.state).live.as_mut().unwrap().publication_seq = None;
    assert!(
        runtime_get_on(sh, host_id()).is_none(),
        "sequence unknown: ask the server"
    );
    // a different binding than the actor last used is never answered locally
    go_live(sh, TOKEN);
    lock(&sh.state).desired.as_mut().unwrap().binding.generation = 6;
    assert!(runtime_get_on(sh, host_id()).is_none());
}
