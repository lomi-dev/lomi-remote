use lomi_remote_core::session::*;
use serde_json::json;

fn body() -> serde_json::Value {
    json!({
        "account": {"id": "acc-1", "email": "a@example.test"},
        "sessionExpiresAt": 1795000000000u64,
        "relay": {"token": "TTTTTTTTabcdefghijklmnopqrstuvwxyz0123456789_-", "expiresAt": 1794003600000u64},
        "hosts": [{
            "hostId": "11111111-1111-4111-8111-111111111111", "name": "Mac", "online": true,
            "accessEpoch": "3", "runtimeGeneration": "7",
            "workspaces": [{"workspaceId": "22222222-2222-4222-8222-222222222222", "name": "lomi"}]
        }],
        "device": {"state": "registered", "deviceId": "dev-1"},
        "futureField": {"ignored": true}
    })
}
fn parse(status: u16, v: &serde_json::Value) -> Result<SessionResponse, SessionError> {
    parse_session_response(status, v.to_string().as_bytes())
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
    assert_eq!(r.hosts[0].workspaces[0].name, "lomi");
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
