use lomi_remote_core::session::*;
use serde_json::json;

fn body() -> serde_json::Value {
    json!({
        "account": {"id": "acc-1", "email": "a@example.test"},
        "sessionExpiresAt": 1795000000000u64,
        "relay": {"token": "TTTTTTTTabcdefghijklmnopqrstuvwxyz0123456789_-", "expiresAt": 1794003600000u64},
        "hosts": [{
            "hostId": "11111111-1111-4111-8111-111111111111", "online": true,
            "accessEpoch": "3", "runtimeGeneration": "7",
            "workspaces": [{"workspaceId": "22222222-2222-4222-8222-222222222222", "workspaceEpoch": "4"}]
        }],
        "device": {"state": "registered", "deviceId": "dev-1"},
        "futureField": {"ignored": true}
    })
}
fn parse(status: u16, v: &serde_json::Value) -> Result<SessionResponse, SessionError> {
    match parse_session_response(status, v.to_string().as_bytes())? {
        SessionOutcome::Full(r) => Ok(*r),
        SessionOutcome::Degraded { .. } => panic!("unexpected degraded answer"),
    }
}

#[test]
fn request_for_browser_and_mobile() {
    let r = session_request("ab", &Credential::Cookie);
    assert_eq!((r.method, r.path), ("POST", "/remote/session"));
    assert_eq!(r.body, br#"{"contractHash":"ab"}"#);
    let r = session_request("ab", &Credential::Refresh("rc".into()));
    assert_eq!(r.body, br#"{"contractHash":"ab","refreshCredential":"rc"}"#);
}

#[test]
fn parses_one_response() {
    let r = parse(200, &body()).unwrap();
    assert_eq!(
        r.account,
        Account {
            id: "acc-1".into(),
            email: Some("a@example.test".into())
        }
    );
    assert_eq!(r.relay.expires_at, 1794003600000);
    assert_eq!(r.hosts[0].name, None);
    assert_eq!(r.hosts[0].workspaces[0].name, None);
    assert_eq!(r.hosts[0].workspaces[0].epoch, "4");
    assert!(r.hosts[0].online && r.hosts[0].access_epoch == "3");
    assert_eq!(
        r.device,
        DeviceState::Registered {
            device_id: "dev-1".into()
        }
    );
    assert!(r.access_token.is_none() && r.refresh_credential.is_none());
    let mut v = body();
    v["accessToken"] = json!({"token": "x", "expiresAt": 5});
    v["refreshCredential"] = json!("rot");
    let r = parse(200, &v).unwrap();
    assert_eq!(r.access_token.unwrap().expires_at, 5);
    assert_eq!(r.refresh_credential.as_deref(), Some("rot"));
}

#[test]
fn rejects_bad_status_and_shapes() {
    assert_eq!(parse(401, &body()), Err(SessionError::Unauthorized));
    assert_eq!(parse(503, &body()), Err(SessionError::Http(503)));
    assert!(
        SessionError::Http(503).is_retryable()
            && !SessionError::Http(400).is_retryable()
            && !SessionError::Unauthorized.is_retryable()
    );
    for key in ["account", "relay", "hosts", "device", "sessionExpiresAt"] {
        let mut v = body();
        v.as_object_mut().unwrap().remove(key);
        assert_eq!(parse(200, &v), Err(SessionError::Malformed), "{key}");
    }
    let mut v = body();
    v["device"]["state"] = json!("weird");
    assert_eq!(parse(200, &v), Err(SessionError::Malformed));
    let mut v = body();
    v["hosts"][0]["online"] = json!("yes");
    assert_eq!(parse(200, &v), Err(SessionError::Malformed));
    assert_eq!(
        parse_session_response(200, b"{\"a\":1,\"a\":2}"),
        Err(SessionError::Malformed)
    );
    assert_eq!(
        parse_session_response(200, b"[]"),
        Err(SessionError::Malformed)
    );
    assert_eq!(
        parse_session_response(200, &vec![b' '; (1 << 20) + 1]),
        Err(SessionError::TooLarge)
    );
}

// Exactly the keys the server emits (auth-app session.ts): no names, no email, workspaceEpoch,
// device always `registered`; the mobile variant adds accessToken and the opaque refreshCredential.
fn server_body() -> serde_json::Value {
    json!({
        "account": {"id": "3f1c6a52-9b1e-4c1e-8f55-0a1b2c3d4e5f"},
        "sessionExpiresAt": 1795000000000u64,
        "relay": {"token": "eyJ2IjoxfQ.c2ln", "expiresAt": 1794003600000u64},
        "hosts": [
            {"hostId": "11111111-1111-4111-8111-111111111111", "online": true,
             "accessEpoch": "3", "runtimeGeneration": "18446744073709551615",
             "workspaces": [
                {"workspaceId": "22222222-2222-4222-8222-222222222222", "workspaceEpoch": "1"},
                {"workspaceId": "33333333-3333-4333-8333-333333333333", "workspaceEpoch": "0"}]},
            {"hostId": "44444444-4444-4444-8444-444444444444", "online": false,
             "accessEpoch": "1", "runtimeGeneration": "2", "workspaces": []}
        ],
        "device": {"state": "registered", "deviceId": "55555555-5555-4555-8555-555555555555"}
    })
}

#[test]
fn parses_server_shaped_session_without_names() {
    let r = parse(200, &server_body()).unwrap();
    assert_eq!(r.account.email, None);
    assert!(r.hosts[0].name.is_none() && r.hosts[0].workspaces[1].name.is_none());
    assert_eq!(r.hosts[0].runtime_generation, "18446744073709551615");
    assert!(!r.hosts[1].online && r.hosts[1].workspaces.is_empty());
    let mut v = server_body();
    v["accessToken"] = json!({"token": "at", "expiresAt": 1794000900000u64});
    v["refreshCredential"] = json!("sess_1-a.bm90LWluc3BlY3RlZA");
    let r = parse(200, &v).unwrap();
    assert_eq!(r.access_token.unwrap().expires_at, 1794000900000);
    assert_eq!(
        r.refresh_credential.as_deref(),
        Some("sess_1-a.bm90LWluc3BlY3RlZA")
    );
    // Names, when a future server or Host stream sends them, are still read; null counts as absent.
    let mut v = server_body();
    v["hosts"][0]["name"] = json!("Mac");
    v["hosts"][0]["workspaces"][0]["name"] = json!(null);
    let r = parse(200, &v).unwrap();
    assert_eq!(r.hosts[0].name.as_deref(), Some("Mac"));
    assert_eq!(r.hosts[0].workspaces[0].name, None);
    // P3a states stay parseable.
    let mut v = server_body();
    v["device"] = json!({"state": "unregistered"});
    assert_eq!(parse(200, &v).unwrap().device, DeviceState::Unregistered);
    v["device"] = json!({"state": "revoked"});
    assert_eq!(parse(200, &v).unwrap().device, DeviceState::Revoked);
    // workspaceEpoch is required.
    let mut v = server_body();
    v["hosts"][0]["workspaces"][0]
        .as_object_mut()
        .unwrap()
        .remove("workspaceEpoch");
    assert_eq!(parse(200, &v), Err(SessionError::Malformed));
}

#[test]
fn conflicts_are_told_apart() {
    let err = |code: &str| json!({"code": code, "message": "m", "retryable": false, "effect": "none", "details": {}});
    assert_eq!(
        parse(409, &err("UPDATE_REQUIRED")),
        Err(SessionError::UpdateRequired)
    );
    assert_eq!(
        parse(409, &err("OUTCOME_UNKNOWN")),
        Err(SessionError::OutcomeUnknown)
    );
    assert_eq!(parse(409, &err("SOMETHING")), Err(SessionError::Http(409)));
    assert_eq!(
        parse_session_response(409, b"not json"),
        Err(SessionError::Http(409))
    );
    assert!(
        !SessionError::UpdateRequired.is_retryable()
            && !SessionError::OutcomeUnknown.is_retryable()
    );
}

// Shape of auth-app `degraded()` (session.ts, session.test.ts): 200 after a successful refresh
// rotation when a later step failed; no account, relay, hosts or device.
fn degraded_body() -> serde_json::Value {
    json!({
        "degraded": true, "reason": "AUTH_REQUIRED",
        "accessToken": {"token": "newAccess_-1", "expiresAt": 1794000900000u64},
        "refreshCredential": "sess-1.bmV3UmVmcmVzaA"
    })
}

#[test]
fn degraded_answer_is_its_own_outcome() {
    let out = parse_session_response(200, degraded_body().to_string().as_bytes()).unwrap();
    assert_eq!(
        out,
        SessionOutcome::Degraded {
            reason: "AUTH_REQUIRED".into(),
            access_token: RelayToken {
                token: "newAccess_-1".into(),
                expires_at: 1794000900000
            },
            refresh_credential: "sess-1.bmV3UmVmcmVzaA".into(),
        }
    );
    let bad = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v = degraded_body();
        f(&mut v);
        parse_session_response(200, v.to_string().as_bytes())
    };
    // A degraded answer must carry the new credentials, a code and degraded:true.
    assert_eq!(
        bad(&|v| {
            v.as_object_mut().unwrap().remove("refreshCredential");
        }),
        Err(SessionError::Malformed)
    );
    assert_eq!(
        bad(&|v| {
            v.as_object_mut().unwrap().remove("accessToken");
        }),
        Err(SessionError::Malformed)
    );
    assert_eq!(
        bad(&|v| v["degraded"] = json!(false)),
        Err(SessionError::Malformed)
    );
    assert_eq!(
        bad(&|v| v["reason"] = json!("lower case")),
        Err(SessionError::Malformed)
    );
    assert_eq!(
        bad(&|v| {
            v.as_object_mut().unwrap().remove("reason");
        }),
        Err(SessionError::Malformed)
    );
    // A full answer still parses as Full.
    assert!(matches!(
        parse_session_response(200, server_body().to_string().as_bytes()),
        Ok(SessionOutcome::Full(_))
    ));
}
