use super::*;
use crate::data::{Scope, data_failure, decode_data, encode_bounded};

fn data_client(server: &Server, root: &[u8]) -> DataTransport {
    data_client_for_identity(&config(1), server, root)
}
fn data_client_for_identity(identity: &Config, server: &Server, root: &[u8]) -> DataTransport {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .root_certs(ureq::tls::RootCerts::new_with_certs(&[
            ureq::tls::Certificate::from_der(root).to_owned(),
        ]))
        .build();
    let origin =
        RemoteApiOrigin::new(identity, format!("https://localhost:{}", server.port)).unwrap();
    DataTransport::with_tls(origin, tls).unwrap()
}

fn access() -> HostAccessCredential {
    "synthetic_access".to_owned().try_into().unwrap()
}
fn binding() -> RuntimeBinding {
    RuntimeBinding {
        runtime_id: RuntimeId::from_bytes([3; 16]).unwrap(),
        runtime_generation: DecimalU64(1),
        host_access_epoch: DecimalU64(1),
    }
}
fn data_reply(status: u16, body: &[u8]) -> Vec<u8> {
    let mut result = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    result.extend_from_slice(body);
    result
}
fn assert_request(server: &Server, method: &str, path: &str, body: Option<&[u8]>) {
    let captured = server.captured();
    assert_eq!(captured.len(), 1);
    let bytes = &captured[0];
    let end = bytes.windows(4).position(|x| x == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&bytes[..end]).unwrap();
    assert!(headers.starts_with(&format!("{method} {path} HTTP/1.1\r\n")));
    assert!(
        headers
            .lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer synthetic_access"))
    );
    for forbidden in ["cookie:", "origin:", "proxy-authorization:"] {
        assert!(!headers.to_ascii_lowercase().contains(forbidden));
    }
    assert_eq!(&bytes[end + 4..], body.unwrap_or_default());
    if body.is_none() {
        assert!(!headers.to_ascii_lowercase().contains("content-type:"));
    }
}
#[test]
fn eleven_data_routes_stay_on_separate_remote_origin() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let identity_cert = certificate("localhost", false);
    let identity_failure = br#"{"code":"AUTH_REQUIRED","message":"Authentication required.","retryable":false,"effect":"none","details":{}}"#;
    let identity_server = Server::new(&identity_cert, Action::Reply(reply(401, identity_failure)));
    let identity_config = config(identity_server.port);
    let identity_transport = client(&identity_server, &identity_cert.root);
    assert_eq!(
        identity_transport.register(
            &HostRegisterParams {
                host_id: HostId::from_bytes([1; 16]).unwrap(),
                identity: EnrollmentProof {
                    canonical_cbor: "aa".to_owned().try_into().unwrap(),
                    signature: "aa".repeat(64).try_into().unwrap()
                }
            },
            &access()
        ),
        Err(Error::Remote(HostFailure::AuthRequired))
    );
    let identity_requests = identity_server.captured();
    assert_eq!(identity_requests.len(), 1);
    assert_request(
        &identity_server,
        "POST",
        "/v2/remote/hosts/register",
        Some(
            &serde_json::to_vec(&HostRegisterParams {
                host_id: HostId::from_bytes([1; 16]).unwrap(),
                identity: EnrollmentProof {
                    canonical_cbor: "aa".to_owned().try_into().unwrap(),
                    signature: "aa".repeat(64).try_into().unwrap(),
                },
            })
            .unwrap(),
        ),
    );
    let host = HostId::from_bytes([1; 16]).unwrap();
    let pairing = PairingId::from_bytes([4; 16]).unwrap();
    let channel = ChannelId::from_bytes([5; 16]).unwrap();
    let host_path = format!("/v2/remote/hosts/{}", String::from(host));
    // A canonical failure exercises wire dispatch without inventing response semantics.
    let body = br#"{"code":"AUTH_REQUIRED","message":"Authentication required.","retryable":false,"effect":"none","details":{}}"#;
    macro_rules! check {
        ($method:expr,$path:expr,$request:expr,$call:expr) => {{
            let server = Server::new(&cert, Action::Reply(data_reply(401, body)));
            let transport = data_client_for_identity(&identity_config, &server, &cert.root);
            let call: &dyn Fn(&DataTransport) -> Error = &$call;
            assert_eq!(
                call(&transport),
                Error::DataRemote(DataFailure::AuthRequired)
            );
            assert_request(&server, $method, &$path, $request);
            assert_eq!(identity_server.captured(), identity_requests);
        }};
    }
    check!(
        "GET",
        format!("{host_path}/runtime"),
        None,
        |t: &DataTransport| t.runtime_get(host, &access()).unwrap_err()
    );
    let claim = RuntimeClaimParams {
        runtime_id: binding().runtime_id,
        expected_generation: DecimalU64(0),
    };
    let encoded = serde_json::to_vec(&claim).unwrap();
    check!(
        "POST",
        format!("{host_path}/runtime/claim"),
        Some(encoded.as_slice()),
        |t: &DataTransport| t.runtime_claim(host, &claim, &access()).unwrap_err()
    );
    let heartbeat = HeartbeatParams { runtime: binding() };
    let encoded = serde_json::to_vec(&heartbeat).unwrap();
    check!(
        "POST",
        format!("{host_path}/heartbeat"),
        Some(encoded.as_slice()),
        |t: &DataTransport| t.heartbeat(host, &heartbeat, &access()).unwrap_err()
    );
    let publication = PublicationParams {
        runtime: binding(),
        expected_publication_seq: DecimalU64(0),
        publication_seq: DecimalU64(1),
        workspaces: Vec::new().try_into().unwrap(),
    };
    let encoded = serde_json::to_vec(&publication).unwrap();
    check!(
        "PUT",
        format!("{host_path}/publication"),
        Some(encoded.as_slice()),
        |t: &DataTransport| t.publication(host, &publication, &access()).unwrap_err()
    );
    check!(
        "GET",
        format!("{host_path}/pairings/pending"),
        None,
        |t: &DataTransport| t.pairing_pending(host, &access()).unwrap_err()
    );
    let decision = PairingDecisionParams::Deny { runtime: binding() };
    check!(
        "GET",
        format!("/v2/remote/pairings/{}", String::from(pairing)),
        None,
        |t: &DataTransport| t.pairing_get(pairing, &access()).unwrap_err()
    );
    let encoded = serde_json::to_vec(&decision).unwrap();
    check!(
        "POST",
        format!("/v2/remote/pairings/{}/decision", String::from(pairing)),
        Some(encoded.as_slice()),
        |t: &DataTransport| t
            .pairing_decision(pairing, &decision, &access())
            .unwrap_err()
    );
    check!(
        "GET",
        format!("{host_path}/channels/pending"),
        None,
        |t: &DataTransport| t.channel_pending(host, &access()).unwrap_err()
    );
    let admission = ChannelAdmissionParams {
        runtime: binding(),
        admission: SignedChannelAdmissionWire {
            canonical_cbor: "aa".to_owned().try_into().unwrap(),
            signature: "aa".repeat(64).try_into().unwrap(),
        },
    };
    check!(
        "GET",
        format!("/v2/remote/channels/{}", String::from(channel)),
        None,
        |t: &DataTransport| t.channel_get(channel, &access()).unwrap_err()
    );
    let encoded = serde_json::to_vec(&admission).unwrap();
    check!(
        "POST",
        format!("/v2/remote/channels/{}/admission", String::from(channel)),
        Some(encoded.as_slice()),
        |t: &DataTransport| t
            .channel_admission(channel, &admission, &access())
            .unwrap_err()
    );
    let ticket = ChannelTicketParams { runtime: binding(), window_identity_id: None };
    let encoded = serde_json::to_vec(&ticket).unwrap();
    check!(
        "POST",
        format!("/v2/remote/channels/{}/tickets", String::from(channel)),
        Some(encoded.as_slice()),
        |t: &DataTransport| t.channel_ticket(channel, &ticket, &access()).unwrap_err()
    );
}
fn identities() -> PeerIdentities {
    let signed = EnrollmentProof {
        canonical_cbor: "aa".to_owned().try_into().unwrap(),
        signature: "aa".repeat(64).try_into().unwrap(),
    };
    PeerIdentities {
        host: signed.clone(),
        consumer: signed,
        host_fingerprint: "aa".repeat(32).try_into().unwrap(),
        consumer_fingerprint: "bb".repeat(32).try_into().unwrap(),
    }
}
fn authority() -> CurrentAuthorityBinding {
    CurrentAuthorityBinding {
        host_authorization_id: HostAuthorizationId::from_bytes([1; 16]).unwrap(),
        consumer_authorization_id: ConsumerAuthorizationId::from_bytes([2; 16]).unwrap(),
        account_session_id: "synthetic_session".to_owned().try_into().unwrap(),
        access_epoch: DecimalU64(1),
        grant_revision: DecimalU64(1),
        workspace_epoch: WorkspaceEpoch::from_bytes([3; 16]).unwrap(),
        runtime_id: binding().runtime_id,
        runtime_generation: DecimalU64(1),
        terminal_membership: None,
    }
}
#[test]
fn bounded_pending_lists_and_nested_objects() {
    let entries: Vec<_> = (1..=64)
        .map(|n| PendingPairing {
            pairing_id: PairingId::from_bytes([n; 16]).unwrap(),
            proposal: PairingProposal {
                maximum_grant: "aa".to_owned().try_into().unwrap(),
                identities: identities(),
                authority: authority(),
            },
        })
        .collect();
    let result = PairingPendingResult {
        pairings: entries.clone().try_into().unwrap(),
    };
    let bytes = serde_json::to_vec(&result).unwrap();
    assert_eq!(decode_data::<PairingPendingResult>(&bytes).unwrap(), result);
    assert!(decode::<PairingPendingResult>(&bytes).is_err());
    let entry = serde_json::to_string(&entries[0]).unwrap();
    let mut too_many_entries = entries.clone();
    let mut extra = entries[0].clone();
    extra.pairing_id = PairingId::from_bytes([65; 16]).unwrap();
    too_many_entries.push(extra);
    let too_many = format!(
        "{{\"pairings\":{}}}",
        serde_json::to_string(&too_many_entries).unwrap()
    );
    assert!(decode_data::<PairingPendingResult>(too_many.as_bytes()).is_err());
    let duplicates = format!("{{\"pairings\":[{entry},{entry}]}}");
    assert!(decode_data::<PairingPendingResult>(duplicates.as_bytes()).is_err());
    let invalid = String::from_utf8(bytes).unwrap().replacen(
        "\"identities\":{",
        "\"identities\":{\"unknown\":0,",
        1,
    );
    assert!(decode_data::<PairingPendingResult>(invalid.as_bytes()).is_err());
    let nested = br#"{"runtime":["03030303-0303-0303-0303-030303030303","1","1"],"leaseMs":"1"}"#;
    assert!(decode_data::<RuntimeClaimResult>(nested).is_err());
    let channels: Vec<_> = (1..=64)
        .map(|n| PendingChannel {
            channel_id: ChannelId::from_bytes([n; 16]).unwrap(),
            inputs: ChannelAdmissionInputs {
                expected_context: "aa".to_owned().try_into().unwrap(),
                expected_context_json: serde_json::Map::new(),
                grant: SignedGrantWire {
                    canonical_cbor: "aa".to_owned().try_into().unwrap(),
                    signature: "aa".repeat(64).try_into().unwrap(),
                },
                identities: identities(),
                authority: authority(),
            },
        })
        .collect();
    let result = ChannelPendingResult {
        channels: channels.try_into().unwrap(),
    };
    let bytes = serde_json::to_vec(&result).unwrap();
    assert_eq!(decode_data::<ChannelPendingResult>(&bytes).unwrap(), result);
    let text = std::str::from_utf8(&bytes).unwrap();
    let entry = serde_json::to_string(&result.channels.as_slice()[0]).unwrap();
    let mut too_many_channels = result.channels.as_slice().to_vec();
    let mut extra = too_many_channels[0].clone();
    extra.channel_id = ChannelId::from_bytes([65; 16]).unwrap();
    too_many_channels.push(extra);
    let invalid = format!(
        "{{\"channels\":{}}}",
        serde_json::to_string(&too_many_channels).unwrap()
    );
    assert!(decode_data::<ChannelPendingResult>(invalid.as_bytes()).is_err());
    let invalid = format!("{{\"channels\":[{entry},{entry}]}}");
    assert!(decode_data::<ChannelPendingResult>(invalid.as_bytes()).is_err());
    assert!(
        decode_data::<ChannelPendingResult>(
            text.replace("\"authority\":{", "\"authority\":{\"unknown\":0,")
                .as_bytes()
        )
        .is_err()
    );
}
#[test]
fn exact_closed_data_failures_and_ambiguity() {
    let failures = [
        DataFailure::InvalidArgument,
        DataFailure::AuthRequired,
        DataFailure::ScopeDenied,
        DataFailure::ResourceNotFound,
        DataFailure::StaleEpoch,
        DataFailure::HostBusy,
        DataFailure::IdempotencyConflict,
        DataFailure::ResourceExhausted,
        DataFailure::OutcomeUnknown,
        DataFailure::ServiceUnavailable,
    ];
    for scope in [Scope::Runtime, Scope::Peer] {
        for failure in failures {
            let code = failure.code();
            let wire = format!(
                "{{\"code\":{},\"message\":{},\"retryable\":{},\"effect\":{},\"details\":{{}}}}",
                serde_json::to_string(&code).unwrap(),
                serde_json::to_string(code.message()).unwrap(),
                failure.retryable(),
                serde_json::to_string(&failure.effect()).unwrap()
            );
            let admitted = match scope {
                Scope::Runtime => !matches!(
                    failure,
                    DataFailure::IdempotencyConflict | DataFailure::ResourceExhausted
                ),
                Scope::Peer => failure != DataFailure::HostBusy,
            };
            assert_eq!(
                data_failure(code.http_status(), wire.as_bytes(), scope),
                if admitted {
                    Error::DataRemote(failure)
                } else {
                    Error::HttpStatus
                }
            );
            for malformed in [
                wire.replace(code.message(), "bad"),
                wire.replace("\"details\":{}", "\"details\":[]"),
                wire.replace("\"details\":{}", "\"details\":{\"x\":1}"),
                wire.replace("\"details\":{}", "\"details\":{},\"extra\":0"),
                wire.replace(
                    &format!("\"retryable\":{}", failure.retryable()),
                    &format!("\"retryable\":{}", !failure.retryable()),
                ),
                wire.replace("\"effect\":\"none\"", "\"effect\":\"committed\"")
                    .replace("\"effect\":\"unknown\"", "\"effect\":\"none\""),
            ] {
                assert_eq!(
                    data_failure(code.http_status(), malformed.as_bytes(), scope),
                    Error::HttpStatus
                );
            }
            assert_eq!(data_failure(500, wire.as_bytes(), scope), Error::HttpStatus);
        }
    }
}
#[test]
fn ticket_reply_text_and_expiry_are_restricted() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let channel = ChannelId::from_bytes([5; 16]).unwrap();
    for (ticket, expiry, valid) in [
        ("synthetic_ticket", "1", true),
        ("synthetic_ticket", "5000", true),
        ("synthetic_ticket", "0", false),
        ("synthetic_ticket", "5001", false),
        ("synthetic_\\u0074icket", "1", false),
        ("synthetic_é", "1", false),
    ] {
        let body = format!(
            "{{\"channelId\":\"{}\",\"ticket\":\"{ticket}\",\"expiresInMs\":\"{expiry}\"}}",
            String::from(channel)
        );
        let server = Server::new(&cert, Action::Reply(data_reply(200, body.as_bytes())));
        assert_eq!(
            data_client(&server, &cert.root)
                .channel_ticket(
                    channel,
                    &ChannelTicketParams { runtime: binding(), window_identity_id: None },
                    &access()
                )
                .is_ok(),
            valid
        );
    }
}
#[test]
fn data_budgets_and_no_store_and_dropped_mutation() {
    assert!(encode_bounded(&"a".repeat(1024 * 1024 - 2), 1024 * 1024).is_ok());
    assert!(encode_bounded(&"a".repeat(1024 * 1024 - 1), 1024 * 1024).is_err());
    assert!(encode(&"a".repeat(REQUEST_LIMIT - 2)).is_ok());
    assert!(encode(&"a".repeat(REQUEST_LIMIT - 1)).is_err());
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let host = HostId::from_bytes([1; 16]).unwrap();
    for limit in [RESPONSE_LIMIT, 1024 * 1024] {
        for extra in [0, 1] {
            let mut body = if limit == RESPONSE_LIMIT {
                serde_json::to_vec(&RuntimeClaimResult {
                    runtime: binding(),
                    lease_ms: DecimalU64(1),
                })
                .unwrap()
            } else {
                b"{\"pairings\":[]}".to_vec()
            };
            body.resize(limit + extra, b' ');
            let server = large_reply_server(&cert, data_reply(200, &body));
            let transport = data_client(&server, &cert.root);
            let result = if limit == RESPONSE_LIMIT {
                transport
                    .runtime_claim(
                        host,
                        &RuntimeClaimParams {
                            runtime_id: binding().runtime_id,
                            expected_generation: DecimalU64(0),
                        },
                        &access(),
                    )
                    .map(|_| ())
            } else {
                transport.pairing_pending(host, &access()).map(|_| ())
            };
            assert_eq!(
                result,
                if extra == 0 {
                    Ok(())
                } else {
                    Err(Error::ResponseTooLarge)
                },
                "response limit {limit} extra {extra}"
            );
        }
    }
    let server = Server::new(&cert, Action::Reply(reply(200, b"{\"pairings\":[]}")));
    assert_eq!(
        data_client(&server, &cert.root).pairing_pending(host, &access()),
        Err(Error::InvalidResponse)
    );
    drop(server);
    let server = Server::new(&cert, Action::Drop);
    let publication = PublicationParams {
        runtime: binding(),
        expected_publication_seq: DecimalU64(0),
        publication_seq: DecimalU64(1),
        workspaces: Vec::new().try_into().unwrap(),
    };
    assert_eq!(
        data_client(&server, &cert.root).publication(host, &publication, &access()),
        Err(Error::DataRemote(DataFailure::OutcomeUnknown))
    );
    assert_request(
        &server,
        "PUT",
        &format!("/v2/remote/hosts/{}/publication", String::from(host)),
        Some(&serde_json::to_vec(&publication).unwrap()),
    );
    assert_eq!(server.captured().len(), 1);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}

#[test]
fn full_publication_uses_large_request_budget_and_canonical_membership() {
    let terminals: Vec<_> = (1u128..=4096)
        .map(|n| PublishedTerminal {
            pane_id: PaneId::from_bytes(n.to_be_bytes()).unwrap(),
            session_id: TerminalSessionId::from_bytes((n + 4096).to_be_bytes()).unwrap(),
            session_epoch: SessionEpoch::from_bytes([1; 16]).unwrap(),
        })
        .collect();
    let mut too_many = terminals.clone();
    too_many.push(terminals[0].clone());
    assert!(PublicationTerminals::try_from(too_many).is_err());
    let mut workspaces: Vec<_> = (1u128..=256)
        .map(|n| PublishedWorkspace {
            workspace_id: WorkspaceId::from_bytes(n.to_be_bytes()).unwrap(),
            workspace_epoch: WorkspaceEpoch::from_bytes([1; 16]).unwrap(),
            terminals: Vec::new().try_into().unwrap(),
        })
        .collect();
    workspaces[0].terminals = terminals.try_into().unwrap();
    let mut too_many = workspaces.clone();
    too_many.push(workspaces[0].clone());
    assert!(PublicationWorkspaces::try_from(too_many).is_err());
    let request = PublicationParams {
        runtime: binding(),
        expected_publication_seq: DecimalU64(0),
        publication_seq: DecimalU64(1),
        workspaces: workspaces.try_into().unwrap(),
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    assert!(bytes.len() > REQUEST_LIMIT && bytes.len() < 1024 * 1024);
    assert_eq!(decode_data::<PublicationParams>(&bytes).unwrap(), request);
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let response = PublicationResult {
        runtime: binding(),
        publication_seq: DecimalU64(1),
    };
    let server = large_reply_server(
        &cert,
        data_reply(200, &serde_json::to_vec(&response).unwrap()),
    );
    let host = HostId::from_bytes([1; 16]).unwrap();
    assert_eq!(
        data_client(&server, &cert.root)
            .publication(host, &request, &access())
            .unwrap(),
        response
    );
    assert_request(
        &server,
        "PUT",
        &format!("/v2/remote/hosts/{}/publication", String::from(host)),
        Some(&bytes),
    );
}

// Extend the existing owned TLS fixture for data budgets. Its original request
// reader intentionally caps credential fixtures at 32 KiB. Chunked writes and
// close_notify also keep large TLS fixture responses complete before teardown.
fn large_reply_server(cert: &Certificate, response: Vec<u8>) -> Server {
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
            // Darwin accepted sockets inherit the listener's nonblocking flag.
            // Explicit blocking mode gives the owned read/write timeouts effect.
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let connection = rustls::ServerConnection::new(tls.clone()).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut bytes = Vec::new();
            let mut scratch = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_secs(10);
            let complete = loop {
                if done.load(Ordering::Acquire) || Instant::now() >= deadline {
                    break false;
                }
                match stream.read(&mut scratch) {
                    Ok(0) => break false,
                    Ok(n) => bytes.extend_from_slice(&scratch[..n]),
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break false,
                }
                if bytes.len() > 1024 * 1024 + 16 * 1024 {
                    break false;
                }
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break true;
                    }
                }
            };
            if complete {
                captured.lock().unwrap().push(bytes);
                // Drive writes only after the request is complete; reading again
                // here can race a client's close after its declared body length.
                let _ = (|| -> io::Result<()> {
                    for chunk in response.chunks(4096) {
                        stream.conn.writer().write_all(chunk)?;
                        while stream.conn.wants_write() {
                            stream.conn.write_tls(&mut stream.sock)?;
                        }
                    }
                    stream.conn.send_close_notify();
                    while stream.conn.wants_write() {
                        stream.conn.write_tls(&mut stream.sock)?;
                    }
                    Ok(())
                })();
            }
        }
    });
    Server {
        port,
        stop,
        join: Some(join),
        requests,
        connections,
    }
}

#[test]
fn streamed_data_overflow_and_noncanonical_cache_headers_fail_closed() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let host = HostId::from_bytes([1; 16]).unwrap();
    for extra in [0, 1] {
        let mut body = b"{\"channels\":[]}".to_vec();
        body.resize(1024 * 1024 + extra, b' ');
        let mut response=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(&body);
        let server = large_reply_server(&cert, response);
        assert_eq!(
            data_client(&server, &cert.root)
                .channel_pending(host, &access())
                .map(|_| ()),
            if extra == 0 {
                Ok(())
            } else {
                Err(Error::ResponseTooLarge)
            }
        );
    }
    for value in [
        "public",
        "no-store, public",
        "no-store\r\nCache-Control: no-store",
    ] {
        let response = String::from_utf8(data_reply(200, b"{\"channels\":[]}"))
            .unwrap()
            .replace(
                "Cache-Control: no-store",
                &format!("Cache-Control: {value}"),
            );
        let server = Server::new(&cert, Action::Reply(response.into_bytes()));
        assert_eq!(
            data_client(&server, &cert.root).channel_pending(host, &access()),
            Err(Error::InvalidResponse)
        );
    }
    let admission = ChannelAdmissionParams {
        runtime: binding(),
        admission: SignedChannelAdmissionWire {
            canonical_cbor: "aa".repeat(8192).try_into().unwrap(),
            signature: "aa".repeat(64).try_into().unwrap(),
        },
    };
    let server = Server::new(&cert, Action::Drop);
    assert_eq!(
        data_client(&server, &cert.root).channel_admission(
            ChannelId::from_bytes([5; 16]).unwrap(),
            &admission,
            &access()
        ),
        Err(Error::Request)
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn identity_enrollment_and_credentials_stay_on_identity_origin() {
    let _network = network_guard();
    let identity_cert = certificate("localhost", false);
    let remote_cert = certificate("localhost", false);
    let failure=br#"{"code":"AUTH_REQUIRED","message":"Authentication required.","retryable":false,"effect":"none","details":{}}"#;
    let identity_server = Server::new(&identity_cert, Action::Reply(reply(401, failure)));
    let remote_server = Server::new(&remote_cert, Action::Reply(data_reply(401, failure)));
    let identity = client(&identity_server, &identity_cert.root);
    let remote = data_client_for_identity(
        &config(identity_server.port),
        &remote_server,
        &remote_cert.root,
    );
    let host = HostId::from_bytes([1; 16]).unwrap();
    let proof = EnrollmentProof {
        canonical_cbor: "aa".to_owned().try_into().unwrap(),
        signature: "aa".repeat(64).try_into().unwrap(),
    };
    let expected = Error::Remote(HostFailure::AuthRequired);
    assert_eq!(
        identity.initiate(&EnrollmentInitiateParams {
            client_id: "test_client".to_owned().try_into().unwrap(),
            key_commitment: "aa".repeat(32).try_into().unwrap(),
            proof: proof.clone()
        }),
        Err(expected)
    );
    assert_eq!(
        identity.exchange(&HostAuthorizationExchangeParams {
            enrollment_id: EnrollmentId::from_bytes([2; 16]).unwrap(),
            host_id: host,
            operation_id: OperationId::from_bytes([3; 16]).unwrap(),
            bootstrap: "synthetic_bootstrap".to_owned().try_into().unwrap(),
            proof: proof.clone()
        }),
        Err(expected)
    );
    assert_eq!(
        identity.refresh(&HostAuthorizationRefreshParams {
            host_authorization_id: HostAuthorizationId::from_bytes([4; 16]).unwrap(),
            host_id: host,
            rotation_id: OperationId::from_bytes([5; 16]).unwrap(),
            refresh: "synthetic_refresh".to_owned().try_into().unwrap(),
            proof: proof.clone()
        }),
        Err(expected)
    );
    assert_eq!(
        identity.register(
            &HostRegisterParams {
                host_id: host,
                identity: proof
            },
            &access()
        ),
        Err(expected)
    );
    assert_eq!(
        identity.revoke(
            host,
            &HostRevokeParams {
                expected_host_access_epoch: DecimalU64(1)
            },
            &access()
        ),
        Err(expected)
    );
    assert!(matches!(identity.poll(&device()), Err(Error::HttpStatus)));
    assert_eq!(remote_server.connections.load(Ordering::SeqCst), 0);
    let requests = identity_server.captured();
    let expected_paths = [
        "/v2/remote/enrollments".to_owned(),
        "/v2/remote/host-authorizations/exchange".to_owned(),
        "/v2/remote/host-authorizations/refresh".to_owned(),
        "/v2/remote/hosts/register".to_owned(),
        format!("/v2/remote/hosts/{}/revoke", String::from(host)),
        "/api/auth/device/token".to_owned(),
    ];
    assert_eq!(requests.len(), expected_paths.len());
    for (index, (request, path)) in requests.iter().zip(expected_paths).enumerate() {
        let text = std::str::from_utf8(request).unwrap();
        assert!(text.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
        let headers = text.split_once("\r\n\r\n").unwrap().0;
        assert_eq!(
            headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("authorization: Bearer synthetic_access")),
            matches!(index, 3 | 4)
        );
    }
    assert_eq!(
        remote.runtime_get(host, &access()),
        Err(Error::DataRemote(DataFailure::AuthRequired))
    );
    assert_eq!(identity_server.captured(), requests);
    assert_request(
        &remote_server,
        "GET",
        &format!("/v2/remote/hosts/{}/runtime", String::from(host)),
        None,
    );
}

#[test]
fn origin_pins_reject_equal_or_ambiguous_values_before_network() {
    let _network = network_guard();
    let identity_cert = certificate("localhost", false);
    let remote_cert = certificate("localhost", false);
    let identity_server = Server::new(&identity_cert, Action::Drop);
    let remote_server = Server::new(&remote_cert, Action::Drop);
    let identity = config(identity_server.port);
    let mut invalid = vec![identity.origin().to_owned()];
    invalid.extend(
        [
            "http://remote.example",
            "HTTPS://remote.example",
            "https://REMOTE.example",
            "https://remote.example/",
            "https://remote.example/path",
            "https://remote.example?x=1",
            "https://remote.example#x",
            "https://user@remote.example",
            "https://remote.example:443",
            "https://remote.example:0",
            "https://remote.example:0443",
            "https://remote.example:65536",
            "https://remote.example:",
            "https://remote.example.",
            "https://.remote.example",
            "https://remote..example",
            "https://-remote.example",
            "https://remote-.example",
            "https://127.1",
            "https://2130706433",
            "https://0177.0.0.1",
            "https://0x7f000001",
            "https://127.0.0.01",
            "https://[::1]",
            "https://remote.example\\path",
            "https://remote%2eexample",
            "https://remote.example\n",
            " https://remote.example",
            "https://rémote.example",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    invalid.push(format!("https://{}.example", "a".repeat(64)));
    invalid.push(format!("https://{}", vec!["a".repeat(60); 3].join(".")));
    for value in invalid {
        assert!(matches!(
            RemoteApiOrigin::new(&identity, value),
            Err(Error::InvalidConfig)
        ));
    }
    for value in [
        "https://remote.example",
        "https://remote.example:8443",
        "https://127.0.0.1:8443",
    ] {
        assert!(RemoteApiOrigin::new(&identity, value.to_owned()).is_ok());
    }
    let default_identity = Config::new(
        HostId::from_bytes([1; 16]).unwrap(),
        lomi_remote_protocol::ipc::IpcProfileId::from_bytes([2; 16]).unwrap(),
        "https://identity.example".to_owned(),
        "test_client".to_owned().try_into().unwrap(),
    )
    .unwrap();
    assert!(matches!(
        RemoteApiOrigin::new(&default_identity, "https://identity.example".to_owned()),
        Err(Error::InvalidConfig)
    ));
    assert!(matches!(
        RemoteApiOrigin::new(&default_identity, "https://identity.example:443".to_owned()),
        Err(Error::InvalidConfig)
    ));
    let invalid_identity: Config = serde_json::from_str(
        &serde_json::to_string(&identity)
            .unwrap()
            .replace("https://", "http://"),
    )
    .unwrap();
    assert!(matches!(
        RemoteApiOrigin::new(
            &invalid_identity,
            format!("https://localhost:{}", remote_server.port)
        ),
        Err(Error::InvalidConfig)
    ));
    assert_eq!(identity_server.connections.load(Ordering::SeqCst), 0);
    assert_eq!(remote_server.connections.load(Ordering::SeqCst), 0);
}

// Original-budget adapter regressions. Retain all earlier fixture/test bodies.
fn budget_data_stall_server(cert: &Certificate, body: bool) -> (Server, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let ready = Arc::new(AtomicBool::new(false));
    let (done, captured, count, waiting, tls) = (stop.clone(), requests.clone(), connections.clone(), ready.clone(), cert.config.clone());
    let join = std::thread::spawn(move || {
        let socket = loop {
            if done.load(Ordering::Acquire) { return; }
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => return,
            }
        };
        count.fetch_add(1, Ordering::SeqCst);
        socket.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        socket.set_write_timeout(Some(Duration::from_millis(20))).unwrap();
        let connection = rustls::ServerConnection::new(tls).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let Some(request) = read_request(&mut stream, &done) else { return; };
        captured.lock().unwrap().push(request);
        if body {
            // A valid no-store header is necessary to reach the DATA body read.
            // The older shared StallBody action intentionally lacks this header.
            if stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n{").is_err() || stream.flush().is_err() { return; }
        }
        waiting.store(true, Ordering::Release);
        wait_stop(&done);
    });
    (Server { port, stop, join: Some(join), requests, connections }, ready)
}
#[test]
fn budgeted_data_runtime_get_consumes_tls_success_and_bounds_header_body_waits() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let host = HostId::from_bytes([1; 16]).unwrap();
    let expected = HostRuntimeGetResult {
        host_id: host,
        host_access_epoch: DecimalU64(1),
        runtime_generation: DecimalU64(1),
        runtime: Some(binding()),
        publication_seq: DecimalU64(0),
        lease_ms: DecimalU64(1000),
        freshness_ms: DecimalU64(1),
    };
    let body = serde_json::to_vec(&expected).unwrap();
    let server = Server::new(&cert, Action::Reply(data_reply(200, &body)));
    let transport = data_client(&server, &cert.root);
    let check = || Ok(());
    assert_eq!(transport.with_budget(Instant::now() + Duration::from_secs(2), &check).runtime_get(host, &access()), Ok(expected));
    assert_request(&server, "GET", &format!("/v2/remote/hosts/{}/runtime", String::from(host)), None);
    drop(server);
    for (body, cancel) in [(false, false), (true, false), (false, true), (true, true)] {
        let (server, ready) = budget_data_stall_server(&cert, body);
        let transport = data_client(&server, &cert.root);
        let sticky = AtomicBool::new(false);
        let check = || {
            if cancel && ready.load(Ordering::Acquire) { sticky.store(true, Ordering::SeqCst); }
            if sticky.load(Ordering::SeqCst) { Err(BudgetStop::Cancelled) } else { Ok(()) }
        };
        let started = Instant::now();
        let duration = if cancel { Duration::from_secs(3) } else { Duration::from_millis(180) };
        let result = transport.with_budget(started + duration, &check).runtime_get(host, &access());
        assert_eq!(result, Err(if cancel { Error::Cancelled } else { Error::Timeout }));
        assert!(ready.load(Ordering::Acquire));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
        assert_request(&server, "GET", &format!("/v2/remote/hosts/{}/runtime", String::from(host)), None);
    }
}
