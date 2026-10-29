use super::*;
use std::{
    net::{TcpListener, TcpStream},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::Instant,
};

// The production resolver intentionally rejects simultaneous lookups. Serialize
// independent HTTPS fixtures so test scheduling does not manufacture contention.
fn network_guard() -> std::sync::MutexGuard<'static, ()> {
    static NETWORK: Mutex<()> = Mutex::new(());
    NETWORK.lock().unwrap_or_else(|poison| poison.into_inner())
}
fn is_transport_network_error(error: &Error) -> bool {
    match error {
        Error::Network => true,
        #[cfg(feature = "test-fixtures")]
        Error::FixtureTls
        | Error::FixtureIoConnect
        | Error::FixtureIoTls
        | Error::FixtureIoOther
        | Error::FixtureConnect
        | Error::FixtureHost
        | Error::FixtureProtocol
        | Error::FixtureOther => true,
        _ => false,
    }
}
fn assert_transport_network_error<T>(result: Result<T>) {
    assert!(result.as_ref().is_err_and(is_transport_network_error));
}
fn config(port: u16) -> Config {
    Config::new(
        HostId::from_bytes([1; 16]).unwrap(),
        lomi_remote_protocol::ipc::IpcProfileId::from_bytes([2; 16]).unwrap(),
        format!("https://localhost:{port}"),
        "test_client".to_owned().try_into().unwrap(),
    )
    .unwrap()
}
fn device() -> DeviceCode {
    "synthetic_device".to_owned().try_into().unwrap()
}
fn approved() -> Vec<u8> {
    br#"{"access_token":"synthetic_bootstrap","token_type":"Bearer","expires_in":300,"scope":"","host_enrollment":{"accountId":"10000000-0000-4000-8000-000000000002","challenge":"aa"}}"#.to_vec()
}
fn reply(status: u16, body: &[u8]) -> Vec<u8> {
    let mut response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(body);
    response
}
struct Certificate {
    root: Vec<u8>,
    config: Arc<rustls::ServerConfig>,
}
fn certificate(host: &str, expired: bool) -> Certificate {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, date_time_ymd,
    };
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().unwrap();
    let root = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);
    let mut leaf = CertificateParams::new(vec![host.into()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if expired {
        leaf.not_before = date_time_ymd(2019, 1, 1);
        leaf.not_after = date_time_ymd(2020, 1, 1);
    }
    let key = KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&key, &issuer).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf.der().clone()], key.into())
    .unwrap();
    Certificate {
        root: root.der().to_vec(),
        config: Arc::new(config),
    }
}
fn client(server: &Server, root: &[u8]) -> Transport {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .root_certs(ureq::tls::RootCerts::new_with_certs(&[
            ureq::tls::Certificate::from_der(root).to_owned(),
        ]))
        .build();
    Transport::with_tls(&config(server.port), tls).unwrap()
}
#[derive(Clone)]
enum Action {
    Reply(Vec<u8>),
    Drop,
    StallTls,
    StallHeaders,
    StallBody,
}
struct Server {
    port: u16,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    connections: Arc<AtomicUsize>,
}
impl Server {
    fn new(cert: &Certificate, action: Action) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (done, captured, count, tls) = (
            stop.clone(),
            requests.clone(),
            connections.clone(),
            cert.config.clone(),
        );
        let join = std::thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                let socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(_) => break,
                };
                count.fetch_add(1, Ordering::SeqCst);
                socket
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                if matches!(action, Action::StallTls) {
                    wait_stop(&done);
                    continue;
                }
                let connection = rustls::ServerConnection::new(tls.clone()).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, socket);
                if let Some(request) = read_request(&mut stream, &done) {
                    captured.lock().unwrap().push(request);
                    match &action {
                        Action::Reply(bytes) => {
                            let _ = stream.write_all(bytes);
                            let _ = stream.flush();
                        }
                        Action::Drop => {}
                        Action::StallHeaders => wait_stop(&done),
                        Action::StallBody => {
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\na");
                            let _ = stream.flush();
                            wait_stop(&done);
                        }
                        Action::StallTls => unreachable!(),
                    }
                }
            }
        });
        Self {
            port,
            stop,
            join: Some(join),
            requests,
            connections,
        }
    }
    fn captured(&self) -> Vec<Vec<u8>> {
        self.requests.lock().unwrap().clone()
    }
}
fn wait_stop(stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(2));
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}
fn read_request(
    stream: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    stop: &AtomicBool,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut bytes = Vec::new();
    let mut scratch = [0u8; 4096];
    while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        match stream.read(&mut scratch) {
            Ok(0) => return None,
            Ok(count) => bytes.extend_from_slice(&scratch[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => return None,
        }
        if bytes.len() > 32 * 1024 {
            return None;
        }
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).ok()?;
            let length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse::<usize>())
                })
                .transpose()
                .ok()?
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                return Some(bytes);
            }
        }
    }
    None
}
#[test]
fn tls_chain_name_and_expiry_are_verified() {
    let _network = network_guard();
    let good = certificate("localhost", false);
    let server = Server::new(&good, Action::Reply(reply(200, &approved())));
    assert!(matches!(
        client(&server, &good.root).poll(&device()),
        Ok(PollOutcome::Approved { .. })
    ));
    let wrong = certificate("localhost", false);
    assert_transport_network_error(client(&server, &wrong.root).poll(&device()));
    for (host, expired) in [("wrong.invalid", false), ("localhost", true)] {
        let cert = certificate(host, expired);
        let server = Server::new(&cert, Action::Reply(reply(200, &approved())));
        assert_transport_network_error(client(&server, &cert.root).poll(&device()));
        assert!(server.captured().is_empty());
    }
}
#[test]
fn polling_uses_fixed_body_and_no_authorization_or_cookie() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let server = Server::new(&cert, Action::Reply(reply(200, &approved())));
    let transport = client(&server, &cert.root);
    assert!(transport.agent.config().proxy().is_none());
    assert_eq!(transport.agent.config().max_redirects(), 0);
    transport.poll(&device()).ok().unwrap();
    let captured = server.captured();
    let raw = std::str::from_utf8(&captured[0]).unwrap();
    assert!(raw.starts_with("POST /api/auth/device/token HTTP/1.1\r\n"));
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
    assert!(!headers.to_ascii_lowercase().contains("authorization:"));
    assert!(!headers.to_ascii_lowercase().contains("cookie:"));
    assert!(!headers.contains("synthetic_device"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(body).unwrap(),
        serde_json::json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":"synthetic_device","client_id":"test_client"})
    );
}
#[test]
fn redirects_and_dropped_responses_never_repeat_posts() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let redirect = b"HTTP/1.1 302 Found\r\nLocation: https://localhost:1/leak?credential=synthetic\r\nContent-Length: 0\r\n\r\n".to_vec();
    let server = Server::new(&cert, Action::Reply(redirect));
    assert!(matches!(
        client(&server, &cert.root).poll(&device()),
        Err(Error::Redirect)
    ));
    assert_eq!(server.captured().len(), 1);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    let server = Server::new(&cert, Action::Drop);
    assert_transport_network_error(client(&server, &cert.root).poll(&device()));
    assert_eq!(server.captured().len(), 1);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}
#[test]
fn response_byte_limits_cover_length_chunked_close_and_truncation() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let mut exact = approved();
    exact.resize(RESPONSE_LIMIT, b' ');
    let server = Server::new(&cert, Action::Reply(reply(200, &exact)));
    assert!(matches!(
        client(&server, &cert.root).poll(&device()),
        Ok(PollOutcome::Approved { .. })
    ));
    let mut oversized = exact;
    oversized.push(b' ');
    let chunked = [
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n{:x}\r\n",
            oversized.len()
        )
        .into_bytes(),
        oversized.clone(),
        b"\r\n0\r\n\r\n".to_vec(),
    ]
    .concat();
    let close = [
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n".to_vec(),
        oversized.clone(),
    ]
    .concat();
    for response in [reply(200, &oversized), chunked, close] {
        let server = Server::new(&cert, Action::Reply(response));
        assert!(matches!(
            client(&server, &cert.root).poll(&device()),
            Err(Error::ResponseTooLarge)
        ));
    }
    let server = Server::new(
        &cert,
        Action::Reply(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{}"
                .to_vec(),
        ),
    );
    assert_transport_network_error(client(&server, &cert.root).poll(&device()));
}
#[test]
fn tls_headers_and_body_stalls_have_closed_deadlines() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    for action in [Action::StallTls, Action::StallHeaders, Action::StallBody] {
        let server = Server::new(&cert, action);
        let started = Instant::now();
        assert!(matches!(
            client(&server, &cert.root).poll(&device()),
            Err(Error::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(8));
    }
}
#[test]
fn malformed_strict_poll_responses_and_integer_bounds() {
    for bytes in [b"{}".as_slice(), b"null", b"not JSON"] {
        assert!(parse_poll(200, bytes).is_err());
    }
    let value: serde_json::Value = serde_json::from_slice(&approved()).unwrap();
    for key in [
        "access_token",
        "token_type",
        "expires_in",
        "scope",
        "host_enrollment",
    ] {
        let mut invalid = value.clone();
        invalid.as_object_mut().unwrap().remove(key);
        assert!(parse_poll(200, &serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    for expires in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!("300"),
        serde_json::json!(9_007_199_254_740_992u64),
    ] {
        let mut invalid = value.clone();
        invalid["expires_in"] = expires;
        assert!(parse_poll(200, &serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    let mut invalid = value.clone();
    invalid["unknown"] = serde_json::json!(true);
    assert!(parse_poll(200, &serde_json::to_vec(&invalid).unwrap()).is_err());
    let mut invalid = value;
    invalid["host_enrollment"]["unknown"] = serde_json::json!(true);
    assert!(parse_poll(200, &serde_json::to_vec(&invalid).unwrap()).is_err());
}
#[test]
fn known_oauth_errors_are_closed_and_descriptions_are_discarded() {
    for code in [
        "authorization_pending",
        "slow_down",
        "expired_token",
        "access_denied",
        "invalid_request",
        "invalid_grant",
    ] {
        let body = serde_json::to_vec(
            &serde_json::json!({"error":code,"error_description":"sensitive\nserver text"}),
        )
        .unwrap();
        assert!(parse_poll(400, &body).is_ok());
    }
    assert!(matches!(
        parse_poll(429, b"untrusted arbitrary text"),
        Ok(PollOutcome::RateLimited)
    ));
    assert!(parse_poll(400, br#"{"error":"surprise"}"#).is_err());
    assert!(parse_poll(500, br#"{"error":"authorization_pending"}"#).is_err());
}
#[test]
fn raw_oauth_error_json_edges_follow_the_poll_schema() {
    for bytes in [
        br#"{"error":"authorization_pending","error_description":["detail"]}"#.as_slice(),
        br#"{"error":"authorization\u005fpending"}"#,
        b"\xef\xbb\xbf{\"error\":\"authorization_pending\"}",
        br#"{"error":"authorization_pending","error":"slow_down"}"#,
    ] {
        assert!(parse_poll(400, bytes).is_err());
    }

    assert!(matches!(
        parse_poll(
            400,
            br#"{"\u0065rror":"access_denied","error_description":"Public [help] with \"quoted brackets [here]\""}"#
        ),
        Ok(PollOutcome::Denied)
    ));
    assert!(matches!(
        parse_poll(
            400,
            br#"{"error":"authorization_pending","error_description":{"note":"first","note":"second"}}"#
        ),
        Ok(PollOutcome::Pending)
    ));
}
#[test]
fn serialization_is_bounded_during_writes() {
    struct Oversized;
    impl Serialize for Oversized {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            serializer.serialize_str(&"a".repeat(REQUEST_LIMIT + 1))
        }
    }
    assert!(matches!(encode(&Oversized), Err(Error::Request)));
    let mut buffer = Bounded(Zeroizing::new(Vec::with_capacity(REQUEST_LIMIT)));
    buffer.write_all(&vec![1; REQUEST_LIMIT]).unwrap();
    assert!(buffer.write_all(&[1]).is_err());
    assert_eq!(buffer.0.len(), REQUEST_LIMIT);
}
#[test]
fn typed_credential_endpoints_preserve_full_identity_and_ids() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let id = "10000000-0000-4000-8000-000000000001";
    let proof = serde_json::json!({"canonicalCbor":"aa","signature":"aa".repeat(64)});
    let initiation =
        serde_json::json!({"clientId":"test_client","keyCommitment":"aa".repeat(32),"proof":proof});
    let exchange = serde_json::json!({"enrollmentId":id,"hostId":id,"operationId":id,"bootstrap":"synthetic_bootstrap","proof":proof});
    let refresh = serde_json::json!({"hostAuthorizationId":id,"hostId":id,"rotationId":id,"refresh":"synthetic_refresh","proof":proof});
    let registration = serde_json::json!({"hostId":id,"identity":proof});
    let authorization = serde_json::to_vec(&serde_json::json!({"accountId":id,"hostId":id,"hostAuthorizationId":id,"access":"synthetic_access","refresh":"synthetic_refresh","rotationId":id,"expiresInSeconds":"300"})).unwrap();
    for (path, request, response) in [
        ("/v2/remote/enrollments", &initiation, serde_json::to_vec(&serde_json::json!({"enrollmentId":id,"deviceCode":"synthetic_device","userCode":"synthetic_user","expiresInSeconds":"300","pollIntervalSeconds":"5"})).unwrap()),
        ("/v2/remote/host-authorizations/exchange", &exchange, authorization.clone()),
        ("/v2/remote/host-authorizations/refresh", &refresh, authorization),
        ("/v2/remote/hosts/register", &registration, serde_json::to_vec(&serde_json::json!({"hostId":id,"hostAccessEpoch":"1"})).unwrap()),
    ] {
        let server = Server::new(&cert, Action::Reply(reply(200, &response)));
        let transport = client(&server, &cert.root);
        match path {
            "/v2/remote/enrollments" => { transport.initiate(&serde_json::from_value(request.clone()).unwrap()).unwrap(); }
            "/v2/remote/host-authorizations/exchange" => { transport.exchange(&serde_json::from_value(request.clone()).unwrap()).unwrap(); }
            "/v2/remote/host-authorizations/refresh" => { transport.refresh(&serde_json::from_value(request.clone()).unwrap()).unwrap(); }
            _ => { transport.register(&serde_json::from_value(request.clone()).unwrap(), &"synthetic_unconfirmed".to_owned().try_into().unwrap()).unwrap(); }
        }
        let captured = server.captured();
        let text = std::str::from_utf8(&captured[0]).unwrap();
        assert!(text.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
        let (headers, body) = text.split_once("\r\n\r\n").unwrap();
        assert_eq!(&serde_json::from_str::<serde_json::Value>(body).unwrap(), request);
        assert!(!headers.to_ascii_lowercase().contains("cookie:"));
        if path.ends_with("register") {
            assert!(headers.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("authorization")
                        && value.trim() == "Bearer synthetic_unconfirmed"
                })
            }));
            assert!(!body.contains("synthetic_unconfirmed"));
        } else {
            assert!(!headers.to_ascii_lowercase().contains("authorization:"));
        }
    }
}
#[test]
fn revoke_posts_only_expected_epoch_and_retains_closed_acknowledgement() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let id = HostId::from_bytes([1; 16]).unwrap();
    let path = format!("/v2/remote/hosts/{}/revoke", String::from(id));
    let request = HostRevokeParams {
        expected_host_access_epoch: DecimalU64(7),
    };
    let access = "synthetic_revocation_only".to_owned().try_into().unwrap();
    for epoch in [7, 8, 12] {
        let body = serde_json::to_vec(&serde_json::json!({
            "hostId":id,"hostAccessEpoch":epoch.to_string()
        }))
        .unwrap();
        let server = Server::new(&cert, Action::Reply(reply(200, &body)));
        let result = client(&server, &cert.root)
            .revoke(id, &request, &access)
            .unwrap();
        assert_eq!(result.host_id, id);
        assert_eq!(result.host_access_epoch, DecimalU64(epoch));
        let captured = server.captured();
        assert_eq!(captured.len(), 1);
        let text = std::str::from_utf8(&captured[0]).unwrap();
        assert!(text.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
        let (headers, sent) = text.split_once("\r\n\r\n").unwrap();
        assert!(headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(key, value)| {
                key.eq_ignore_ascii_case("authorization")
                    && value.trim() == "Bearer synthetic_revocation_only"
            })
        }));
        assert!(!headers.to_ascii_lowercase().contains("cookie:"));
        assert_eq!(sent, r#"{"expectedHostAccessEpoch":"7"}"#);
        assert!(!sent.contains("synthetic_revocation_only"));
    }
    let denial = serde_json::to_vec(&failure_body(HostFailure::AuthRequired)).unwrap();
    let server = Server::new(&cert, Action::Reply(reply(401, &denial)));
    assert_eq!(
        client(&server, &cert.root).revoke(id, &request, &access),
        Err(Error::Remote(HostFailure::AuthRequired))
    );
    assert_eq!(server.captured().len(), 1);
}

#[test]
fn revocation_ack_posts_refresh_proof_in_body_without_reusable_authorization() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let id = HostId::from_bytes([1; 16]).unwrap();
    let family = HostAuthorizationId::from_bytes([3; 16]).unwrap();
    let request = HostRevocationAckParams {
        host_authorization_id: family,
        expected_host_access_epoch: DecimalU64(7),
        refresh: "retained_refresh_proof".to_owned().try_into().unwrap(),
    };
    let response = serde_json::to_vec(&serde_json::json!({
        "hostId": id,
        "hostAccessEpoch": "12"
    }))
    .unwrap();
    let server = Server::new(&cert, Action::Reply(reply(200, &response)));
    let result = client(&server, &cert.root)
        .revocation_ack(id, &request)
        .unwrap();
    assert_eq!(result.host_id, id);
    assert_eq!(result.host_access_epoch, DecimalU64(12));
    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    let text = std::str::from_utf8(&captured[0]).unwrap();
    assert!(text.starts_with(&format!(
        "POST /v2/remote/hosts/{}/revocation-ack HTTP/1.1\r\n",
        String::from(id)
    )));
    let (headers, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(!headers.to_ascii_lowercase().contains("authorization:"));
    assert!(!headers.to_ascii_lowercase().contains("cookie:"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(body).unwrap(),
        serde_json::json!({
            "hostAuthorizationId": family,
            "expectedHostAccessEpoch": "7",
            "refresh": "retained_refresh_proof"
        })
    );
    let debug = format!("{request:?}");
    assert!(!debug.contains("retained_refresh_proof"));
    assert!(debug.contains("REDACTED"));

    let denial = serde_json::to_vec(&failure_body(HostFailure::AuthRequired)).unwrap();
    let server = Server::new(&cert, Action::Reply(reply(401, &denial)));
    let error = client(&server, &cert.root)
        .revocation_ack(id, &request)
        .unwrap_err();
    assert_eq!(error, Error::Remote(HostFailure::AuthRequired));
    assert_eq!(server.captured().len(), 1);
    assert!(!format!("{error:?} {error}").contains("retained_refresh_proof"));

    let unavailable = serde_json::to_vec(&failure_body(HostFailure::ServiceUnavailable)).unwrap();
    let server = Server::new(&cert, Action::Reply(reply(503, &unavailable)));
    assert_eq!(
        client(&server, &cert.root).revocation_ack(id, &request),
        Err(Error::Remote(HostFailure::ServiceUnavailable))
    );
    assert_eq!(
        server.captured().len(),
        1,
        "POST is not retried automatically"
    );
}

#[test]
fn enrollment_revocation_ack_uses_tls_json_without_authorization_or_retry() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let host = HostId::from_bytes([1; 16]).unwrap();
    let enrollment_id = EnrollmentId::from_bytes([5; 16]).unwrap();
    let operation_id = OperationId::from_bytes([6; 16]).unwrap();
    let request = HostEnrollmentRevocationAckParams {
        enrollment_id,
        operation_id,
        proof: EnrollmentProof {
            canonical_cbor: "aa".to_owned().try_into().unwrap(),
            signature: "ab".repeat(64).try_into().unwrap(),
        },
    };
    let no_family = HostEnrollmentRevocationAckResult::NoFamily {
        host_id: host,
        enrollment_id,
        operation_id,
        account_id: AccountId::from_bytes([4; 16]).unwrap(),
    };
    let response = serde_json::to_vec(&no_family).unwrap();
    let server = Server::new(&cert, Action::Reply(reply(200, &response)));
    assert_eq!(
        client(&server, &cert.root)
            .enrollment_revocation_ack(host, &request)
            .unwrap(),
        no_family
    );
    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    let text = std::str::from_utf8(&captured[0]).unwrap();
    assert!(text.starts_with(&format!(
        "POST /v2/remote/hosts/{}/enrollment-revocation-ack HTTP/1.1\r\n",
        String::from(host)
    )));
    let (headers, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(!headers.to_ascii_lowercase().contains("authorization:"));
    assert!(!headers.to_ascii_lowercase().contains("cookie:"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(body).unwrap(),
        serde_json::json!({
            "enrollmentId":enrollment_id,
            "operationId":operation_id,
            "proof":{"canonicalCbor":"aa","signature":"ab".repeat(64)}
        })
    );

    let revoked_family = serde_json::to_vec(&HostEnrollmentRevocationAckResult::RevokedFamily {
        host_id: host,
        enrollment_id,
        operation_id,
        account_id: AccountId::from_bytes([4; 16]).unwrap(),
        host_authorization_id: HostAuthorizationId::from_bytes([3; 16]).unwrap(),
        family_host_access_epoch: DecimalU64(7),
        host_access_epoch: DecimalU64(12),
    })
    .unwrap();
    let server = Server::new(&cert, Action::Reply(reply(200, &revoked_family)));
    assert!(matches!(
        client(&server, &cert.root).enrollment_revocation_ack(host, &request),
        Ok(HostEnrollmentRevocationAckResult::RevokedFamily {
            family_host_access_epoch: DecimalU64(7),
            host_access_epoch: DecimalU64(12),
            ..
        })
    ));
    assert_eq!(server.captured().len(), 1);

    let malformed = serde_json::to_vec(&serde_json::json!({
        "outcome":"noFamily",
        "hostId":host,
        "enrollmentId":enrollment_id,
        "operationId":operation_id,
        "accountId":AccountId::from_bytes([4; 16]).unwrap(),
        "hostAuthorizationId":HostAuthorizationId::from_bytes([3; 16]).unwrap()
    }))
    .unwrap();
    let server = Server::new(&cert, Action::Reply(reply(200, &malformed)));
    assert_eq!(
        client(&server, &cert.root).enrollment_revocation_ack(host, &request),
        Err(Error::InvalidResponse)
    );
    assert_eq!(server.captured().len(), 1);

    let denial = serde_json::to_vec(&failure_body(HostFailure::AuthRequired)).unwrap();
    let server = Server::new(&cert, Action::Reply(reply(401, &denial)));
    assert_eq!(
        client(&server, &cert.root).enrollment_revocation_ack(host, &request),
        Err(Error::Remote(HostFailure::AuthRequired))
    );
    assert_eq!(server.captured().len(), 1);

    let unavailable = serde_json::to_vec(&failure_body(HostFailure::ServiceUnavailable)).unwrap();
    let server = Server::new(&cert, Action::Reply(reply(503, &unavailable)));
    assert_eq!(
        client(&server, &cert.root).enrollment_revocation_ack(host, &request),
        Err(Error::Remote(HostFailure::ServiceUnavailable))
    );
    assert_eq!(
        server.captured().len(),
        1,
        "proof-only POST is not retried automatically"
    );

    let redirect =
        b"HTTP/1.1 302 Found\r\nLocation: https://localhost:1/retry\r\nContent-Length: 0\r\n\r\n"
            .to_vec();
    let server = Server::new(&cert, Action::Reply(redirect));
    assert_eq!(
        client(&server, &cert.root).enrollment_revocation_ack(host, &request),
        Err(Error::Redirect)
    );
    assert_eq!(server.captured().len(), 1);
}

#[test]
fn typed_results_reject_unknown_fields_and_decimal_overflow() {
    let id = "10000000-0000-4000-8000-000000000001";
    for epoch in [
        serde_json::json!(1),
        serde_json::json!("18446744073709551616"),
        serde_json::json!("01"),
    ] {
        let bytes =
            serde_json::to_vec(&serde_json::json!({"hostId":id,"hostAccessEpoch":epoch})).unwrap();
        assert!(decode::<HostRegisterResult>(&bytes).is_err());
    }
    let bytes =
        serde_json::to_vec(&serde_json::json!({"hostId":id,"hostAccessEpoch":"1","extra":true}))
            .unwrap();
    assert!(decode::<HostRegisterResult>(&bytes).is_err());
}
#[test]
fn headers_have_a_separate_byte_limit() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let raw = format!(
        "HTTP/1.1 200 OK\r\nX-Large: {}\r\nContent-Length: 0\r\n\r\n",
        "a".repeat(16 * 1024)
    )
    .into_bytes();
    let server = Server::new(&cert, Action::Reply(raw));
    assert_transport_network_error(client(&server, &cert.root).poll(&device()));
}
#[test]
fn dropped_exchange_preserves_original_operation_for_caller_retry() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let server = Server::new(&cert, Action::Drop);
    let transport = client(&server, &cert.root);
    let request: HostAuthorizationExchangeParams = serde_json::from_value(serde_json::json!({
        "enrollmentId":"10000000-0000-4000-8000-000000000001",
        "hostId":"10000000-0000-4000-8000-000000000002",
        "operationId":"10000000-0000-4000-8000-000000000003",
        "bootstrap":"synthetic_original_bootstrap",
        "proof":{"canonicalCbor":"aa","signature":"aa".repeat(64)}
    }))
    .unwrap();
    assert_transport_network_error(transport.exchange(&request));
    assert_eq!(server.captured().len(), 1);
    // Only this explicit second invocation retries; transport never mints IDs.
    assert_transport_network_error(transport.exchange(&request));
    let captured = server.captured();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0], captured[1]);
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
}
#[test]
fn https_poll_maps_each_known_oauth_status() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    for (code, expected) in [
        ("authorization_pending", PollOutcome::Pending),
        ("slow_down", PollOutcome::SlowDown),
        ("expired_token", PollOutcome::Expired),
        ("access_denied", PollOutcome::Denied),
        ("invalid_request", PollOutcome::InvalidRequest),
        ("invalid_grant", PollOutcome::InvalidGrant),
    ] {
        let body = serde_json::to_vec(
            &serde_json::json!({"error":code,"error_description":"sensitive server text"}),
        )
        .unwrap();
        let server = Server::new(&cert, Action::Reply(reply(400, &body)));
        let actual = client(&server, &cert.root).poll(&device()).ok().unwrap();
        assert_eq!(
            std::mem::discriminant(&actual),
            std::mem::discriminant(&expected)
        );
    }
    let server = Server::new(
        &cert,
        Action::Reply(reply(429, b"arbitrary rate limit text")),
    );
    assert!(matches!(
        client(&server, &cert.root).poll(&device()),
        Ok(PollOutcome::RateLimited)
    ));
}
#[test]
fn deserialized_config_is_revalidated_before_transport_creation() {
    let original = serde_json::to_value(config(1443)).unwrap();
    for origin in [
        "http://example.com",
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com/",
        "https://EXAMPLE.com",
        "https://127.1",
        "https://0177.0.0.1",
        "https://2130706433",
        "https://example.com:443",
        "https://example.com:01443",
    ] {
        let mut value = original.clone();
        value["origin"] = serde_json::json!(origin);
        let invalid: Config = serde_json::from_value(value).unwrap();
        assert!(matches!(
            Transport::new(&invalid),
            Err(Error::InvalidConfig)
        ));
    }
    for client in ["", "bad client", "bad/client", &"a".repeat(129)] {
        let mut value = original.clone();
        value["client"] = serde_json::json!(client);
        let invalid: Config = serde_json::from_value(value).unwrap();
        assert!(matches!(
            Transport::new(&invalid),
            Err(Error::InvalidConfig)
        ));
    }
}
#[test]
fn https_responses_require_json_media_and_forbid_content_encoding() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let body = approved();
    for header in [
        "",
        "Content-Type: text/plain\r\n",
        "Content-Type: application/problem+json\r\n",
        "Content-Type: application/json; charset=iso-8859-1\r\n",
        "Content-Type: application/json; charset=utf-8; other=1\r\n",
        "Content-Type: application/json\r\nContent-Type: application/json\r\n",
        "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
        "Content-Type: application/json\r\nContent-Encoding: identity\r\n",
    ] {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{header}Connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        let server = Server::new(&cert, Action::Reply(response));
        assert!(matches!(
            client(&server, &cert.root).poll(&device()),
            Err(Error::InvalidResponse)
        ));
    }
    for media in [
        "application/json",
        "application/json; charset=utf-8",
        "Application/JSON; Charset=\"UTF-8\"",
    ] {
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
        response.extend_from_slice(&body);
        let server = Server::new(&cert, Action::Reply(response));
        assert!(matches!(
            client(&server, &cert.root).poll(&device()),
            Ok(PollOutcome::Approved { .. })
        ));
    }
}
#[test]
fn https_host_gate_denial_requires_exact_403_access_denied_shape() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    // auth-app's enrollment transaction gate returns this exact status/shape.
    let server = Server::new(
        &cert,
        Action::Reply(reply(403, br#"{"error":"access_denied"}"#)),
    );
    assert!(matches!(
        client(&server, &cert.root).poll(&device()),
        Ok(PollOutcome::Denied)
    ));
    for body in [
        br#"{"error":"authorization_pending"}"#.as_slice(),
        br#"{"error":"slow_down"}"#,
        br#"{"error":"invalid_grant"}"#,
        br#"{"error":"access_denied","unknown":true}"#,
        br#"{"error":"unknown"}"#,
        b"not JSON",
    ] {
        let server = Server::new(&cert, Action::Reply(reply(403, body)));
        assert!(matches!(
            client(&server, &cert.root).poll(&device()),
            Err(Error::InvalidResponse)
        ));
    }
}
fn synthetic_exchange() -> HostAuthorizationExchangeParams {
    serde_json::from_value(serde_json::json!({
        "enrollmentId":"10000000-0000-4000-8000-000000000001",
        "hostId":"10000000-0000-4000-8000-000000000002",
        "operationId":"10000000-0000-4000-8000-000000000003",
        "bootstrap":"synthetic_bootstrap",
        "proof":{"canonicalCbor":"aa","signature":"aa".repeat(64)}
    }))
    .unwrap()
}
fn failure_body(failure: HostFailure) -> serde_json::Value {
    serde_json::json!({
        "code":failure.code(), "message":failure.code().message(),
        "retryable":failure.retryable(), "effect":failure.effect(), "details":{}
    })
}
#[test]
fn https_host_failures_preserve_only_canonical_closed_outcomes() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let request = synthetic_exchange();
    for expected in [
        HostFailure::InvalidArgument,
        HostFailure::AuthRequired,
        HostFailure::ResourceNotFound,
        HostFailure::OutcomeUnknown,
        HostFailure::ServiceUnavailable,
    ] {
        let body = serde_json::to_vec(&failure_body(expected)).unwrap();
        let server = Server::new(
            &cert,
            Action::Reply(reply(expected.code().http_status(), &body)),
        );
        let error = client(&server, &cert.root).exchange(&request).unwrap_err();
        assert_eq!(error, Error::Remote(expected));
        assert_eq!(
            expected.retryable(),
            expected == HostFailure::ServiceUnavailable
        );
        assert_eq!(
            expected.effect(),
            if expected == HostFailure::OutcomeUnknown {
                Effect::Unknown
            } else {
                Effect::None
            }
        );
        assert_eq!(server.captured().len(), 1);
        let display = format!("{error:?} {error}");
        assert!(!display.contains("synthetic_bootstrap"));
        assert!(!display.contains("message"));
        assert!(!display.contains("details"));
    }
}
#[test]
fn https_noncanonical_host_errors_remain_ambiguous_and_redacted() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let request = synthetic_exchange();
    let canonical = failure_body(HostFailure::AuthRequired);
    let mut cases = Vec::new();
    for (field, value) in [
        ("code", serde_json::json!("UNRECOGNIZED")),
        ("code", serde_json::json!("SCOPE_DENIED")),
        (
            "message",
            serde_json::json!("synthetic_untrusted_body_secret"),
        ),
        ("retryable", serde_json::json!(true)),
        ("effect", serde_json::json!("unknown")),
        ("effect", serde_json::json!("committed")),
        ("effect", serde_json::json!("invented")),
        (
            "details",
            serde_json::json!({"secret":"synthetic_untrusted_body_secret"}),
        ),
        ("details", serde_json::json!([])),
        ("details", serde_json::json!(null)),
        ("operation", serde_json::json!(null)),
        (
            "unknown",
            serde_json::json!("synthetic_untrusted_body_secret"),
        ),
    ] {
        let mut body = canonical.clone();
        body[field] = value;
        cases.push((401, serde_json::to_vec(&body).unwrap()));
    }
    for field in ["code", "message", "retryable", "effect", "details"] {
        let mut body = canonical.clone();
        body.as_object_mut().unwrap().remove(field);
        cases.push((401, serde_json::to_vec(&body).unwrap()));
    }
    cases.push((400, serde_json::to_vec(&canonical).unwrap()));
    cases.push((500, serde_json::to_vec(&canonical).unwrap()));
    let body = serde_json::to_string(&canonical).unwrap();
    cases.push((
        401,
        format!("{{\"code\":\"AUTH_REQUIRED\",{}", &body[1..]).into_bytes(),
    ));
    cases.push((
        401,
        body.replace("required.", "required\\u002e").into_bytes(),
    ));
    cases.push((401, b"synthetic_untrusted_body_secret".to_vec()));
    cases.push((
        401,
        br#"["AUTH_REQUIRED","Authentication required.",false,"none",{}]"#.to_vec(),
    ));
    for (status, body) in cases {
        let server = Server::new(&cert, Action::Reply(reply(status, &body)));
        let error = client(&server, &cert.root).exchange(&request).unwrap_err();
        assert_eq!(error, Error::HttpStatus);
        let formatted = format!("{error:?} {error}");
        assert!(!formatted.contains("synthetic_untrusted_body_secret"));
        assert!(!formatted.contains("synthetic_bootstrap"));
    }
    for (failure, field, value) in [
        (
            HostFailure::OutcomeUnknown,
            "effect",
            serde_json::json!("none"),
        ),
        (
            HostFailure::OutcomeUnknown,
            "retryable",
            serde_json::json!(true),
        ),
        (
            HostFailure::ServiceUnavailable,
            "retryable",
            serde_json::json!(false),
        ),
        (
            HostFailure::ServiceUnavailable,
            "effect",
            serde_json::json!("unknown"),
        ),
    ] {
        let mut body = failure_body(failure);
        body[field] = value;
        let server = Server::new(
            &cert,
            Action::Reply(reply(
                failure.code().http_status(),
                &serde_json::to_vec(&body).unwrap(),
            )),
        );
        assert_eq!(
            client(&server, &cert.root).exchange(&request).unwrap_err(),
            Error::HttpStatus
        );
    }
}
#[test]
fn https_response_structs_reject_positional_arrays_at_any_depth() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let id = "10000000-0000-4000-8000-000000000001";
    let mut nested: serde_json::Value = serde_json::from_slice(&approved()).unwrap();
    nested["host_enrollment"] = serde_json::json!([id, "aa"]);
    let tuple = serde_json::json!(["synthetic_bootstrap", "Bearer", 300, "", {"accountId":id,"challenge":"aa"}]);
    for (status, body) in [
        (403, br#"["access_denied",null]"#.to_vec()),
        (400, br#"["authorization_pending",null]"#.to_vec()),
        (200, serde_json::to_vec(&tuple).unwrap()),
        (200, serde_json::to_vec(&nested).unwrap()),
    ] {
        let server = Server::new(&cert, Action::Reply(reply(status, &body)));
        assert!(matches!(
            client(&server, &cert.root).poll(&device()),
            Err(Error::InvalidResponse)
        ));
    }
    let server = Server::new(
        &cert,
        Action::Reply(reply(
            200,
            &serde_json::to_vec(&serde_json::json!([id, "1"])).unwrap(),
        )),
    );
    let request: HostRegisterParams = serde_json::from_value(serde_json::json!({"hostId":id,"identity":{"canonicalCbor":"aa","signature":"aa".repeat(64)}})).unwrap();
    assert_eq!(
        client(&server, &cert.root)
            .register(
                &request,
                &"synthetic_unconfirmed".to_owned().try_into().unwrap()
            )
            .unwrap_err(),
        Error::InvalidResponse
    );
}
#[test]
fn https_literal_brackets_inside_public_strings_remain_valid() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let mut body: serde_json::Value = serde_json::from_slice(&approved()).unwrap();
    body["scope"] = serde_json::json!("https://public.example/[help]");
    let server = Server::new(
        &cert,
        Action::Reply(reply(200, &serde_json::to_vec(&body).unwrap())),
    );
    assert!(matches!(
        client(&server, &cert.root).poll(&device()),
        Ok(PollOutcome::Approved { .. })
    ));
    let body = serde_json::to_vec(&serde_json::json!({"error":"access_denied","error_description":"Public [help] with \"quoted brackets [here]\""})).unwrap();
    let server = Server::new(&cert, Action::Reply(reply(403, &body)));
    assert!(matches!(
        client(&server, &cert.root).poll(&device()),
        Ok(PollOutcome::Denied)
    ));
}
