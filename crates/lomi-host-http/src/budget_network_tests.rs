// Authored regressions. These require the existing synthetic TLS fixtures and
// must run only after the source proposal and Cargo-generated lock edge land.
use super::*;

#[test]
fn original_budget_bounds_genuine_tls_header_and_body_stalls() {
    let _network = network_guard();
    for action in [Action::StallTls, Action::StallHeaders, Action::StallBody] {
        let cert = certificate("localhost", false);
        let server = Server::new(&cert, action);
        let transport = client(&server, &cert.root);
        let started = Instant::now();
        let result = transport.with_budget(started + Duration::from_millis(180), &|| Ok(())).poll(&device());
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }
}

// Use a real rustls-generated handshake flight, rather than arbitrary bytes
// which the client could reject immediately. Every fixture thread is joined.
#[derive(Clone, Copy)]
enum Trickle { TlsFlight, Headers, Body }
fn trickle_server(cert: &Certificate, mode: Trickle) -> (Server, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let progress = Arc::new(AtomicUsize::new(0));
    let (done, captured, count, sent, tls) = (stop.clone(), requests.clone(), connections.clone(), progress.clone(), cert.config.clone());
    let join = std::thread::spawn(move || {
        let mut socket = loop {
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
        let mut connection = rustls::ServerConnection::new(tls).unwrap();
        if matches!(mode, Trickle::TlsFlight) {
            while !done.load(Ordering::Acquire) && !connection.wants_write() {
                match connection.read_tls(&mut socket) {
                    Ok(0) => return,
                    Ok(_) => { if connection.process_new_packets().is_err() { return; } },
                    Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {},
                    Err(_) => return,
                }
            }
            let mut flight = Vec::new();
            while connection.wants_write() { connection.write_tls(&mut flight).unwrap(); }
            assert!(flight.len() > 100);
            for byte in flight {
                if done.load(Ordering::Acquire) || socket.write_all(&[byte]).is_err() { return; }
                sent.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(15));
            }
            return;
        }
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let Some(request) = read_request(&mut stream, &done) else { return; };
        captured.lock().unwrap().push(request);
        let response = reply(200, &approved());
        let boundary = response.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
        let bytes = if matches!(mode, Trickle::Body) {
            if stream.write_all(&response[..boundary]).is_err() { return; }
            if stream.flush().is_err() { return; }
            &response[boundary..]
        } else { &response[..] };
        for byte in bytes {
            if done.load(Ordering::Acquire) || stream.write_all(&[*byte]).is_err() || stream.flush().is_err() { return; }
            sent.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(15));
        }
    });
    (Server { port, stop, join: Some(join), requests, connections }, progress)
}
#[test]
fn valid_tls_flight_and_header_body_trickles_cannot_renew_original_budget() {
    let _network = network_guard();
    for mode in [Trickle::TlsFlight, Trickle::Headers, Trickle::Body] {
        let cert = certificate("localhost", false);
        let (server, sent) = trickle_server(&cert, mode);
        let transport = client(&server, &cert.root);
        let started = Instant::now();
        assert!(matches!(transport.with_budget(started + Duration::from_millis(180), &|| Ok(())).poll(&device()), Err(Error::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(sent.load(Ordering::SeqCst) > 2);
    }
}
#[test]
fn near_exhausted_original_budget_is_not_replaced_at_http_entry() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let server = Server::new(&cert, Action::StallTls);
    let transport = client(&server, &cert.root);
    let admitted = Instant::now();
    let check = || Ok(());
    let bound = transport.with_budget(admitted + Duration::from_millis(120), &check);
    std::thread::sleep(Duration::from_millis(90));
    assert!(matches!(bound.poll(&device()), Err(Error::Timeout)));
    assert!(admitted.elapsed() < Duration::from_millis(500));
}
#[test]
fn observed_authoritative_cancel_survives_external_latch_reset() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let server = Server::new(&cert, Action::StallBody);
    let transport = client(&server, &cert.root);
    let latch = AtomicBool::new(false);
    let observed = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let reset = scope.spawn(|| {
            let limit = Instant::now() + Duration::from_secs(2);
            while server.captured().is_empty() && Instant::now() < limit { std::thread::sleep(Duration::from_millis(2)); }
            latch.store(true, Ordering::SeqCst);
            while !observed.load(Ordering::SeqCst) && Instant::now() < limit { std::thread::sleep(Duration::from_millis(1)); }
            latch.store(false, Ordering::SeqCst);
        });
        let check = || {
            if latch.load(Ordering::SeqCst) { observed.store(true, Ordering::SeqCst); Err(BudgetStop::Cancelled) } else { Ok(()) }
        };
        let result = transport.with_budget(Instant::now() + Duration::from_secs(3), &check).poll(&device());
        reset.join().unwrap();
        assert!(observed.load(Ordering::SeqCst));
        assert!(!latch.load(Ordering::SeqCst));
        assert!(matches!(result, Err(Error::Cancelled)));
    });
}
#[test]
fn expired_original_budget_sends_no_request_and_watcher_joins_after_decode_error() {
    let _network = network_guard();
    let cert = certificate("localhost", false);
    let server = Server::new(&cert, Action::Reply(reply(200, b"invalid")));
    let transport = client(&server, &cert.root);
    assert!(matches!(transport.with_budget(Instant::now(), &|| Ok(())).poll(&device()), Err(Error::Timeout)));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    let calls = AtomicUsize::new(0);
    let check = || { calls.fetch_add(1, Ordering::SeqCst); Ok(()) };
    assert!(matches!(transport.with_budget(Instant::now() + Duration::from_secs(2), &check).poll(&device()), Err(Error::InvalidResponse)));
    let after = calls.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(calls.load(Ordering::SeqCst), after);
}

#[test]
fn budget_adapter_retains_tls_trust_verification() {
    let _network = network_guard();
    let server_cert = certificate("localhost", false);
    let other_root = certificate("localhost", false);
    let server = Server::new(&server_cert, Action::Reply(reply(200, &approved())));
    let transport = client(&server, &other_root.root);
    super::assert_transport_network_error(
        transport
            .with_budget(Instant::now() + Duration::from_secs(2), &|| Ok(()))
            .poll(&device()),
    );
    assert!(server.captured().is_empty());
}
