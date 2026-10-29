#![cfg(unix)]
use lomi_platform::unix::{Error, LocalClient, LocalDiscovery, OwnerEndpoint, OwnerLock};
use lomi_remote_protocol::{
    HostId, LocalIpcVersion, RuntimeId,
    ipc::{self, IpcProfileId, LocalCall, LocalResponse, LocalResult, LocalSharing, LocalStatus},
};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn discovery() -> LocalDiscovery {
    LocalDiscovery {
        version: LocalIpcVersion::CURRENT,
        profile_id: IpcProfileId::from_bytes(*Uuid::new_v4().as_bytes()).unwrap(),
        host_id: HostId::from_bytes(*Uuid::new_v4().as_bytes()).unwrap(),
        runtime_id: RuntimeId::from_bytes(*Uuid::new_v4().as_bytes()).unwrap(),
        build_id: "test-0.1".into(),
    }
}
fn profile() -> tempfile::TempDir {
    // A short canonical path also exercises the Darwin socket path budget.
    let root = tempfile::Builder::new()
        .prefix("lr-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn endpoint() -> (tempfile::TempDir, OwnerEndpoint) {
    let root = profile();
    let path = root.path().canonicalize().unwrap();
    let endpoint = OwnerEndpoint::bind(OwnerLock::acquire(&path).unwrap(), discovery()).unwrap();
    (root, endpoint)
}
fn accept(endpoint: &OwnerEndpoint) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(stream) = endpoint.accept().unwrap() {
            return stream;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn real_client_authenticates_and_correlates_a_versioned_request() {
    let (root, endpoint) = endpoint();
    let path = root.path().canonicalize().unwrap();
    let d = endpoint.discovery().clone();
    let server = thread::spawn(move || {
        let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
        connection.set_deadline(Instant::now() + Duration::from_secs(3));
        let request = connection.read_request().unwrap();
        assert!(matches!(request.call, LocalCall::Status {}));
        connection
            .write(&LocalResponse {
                version: request.version,
                request_id: request.request_id,
                result: Ok(LocalResult::Status(LocalStatus {
                    host_id: d.host_id,
                    runtime_id: d.runtime_id,
                    sharing: LocalSharing::Disabled,
                })),
            })
            .unwrap();
    });
    let mut client = LocalClient::connect(&path).unwrap();
    assert!(matches!(
        client.request(LocalCall::Status {}).unwrap().result,
        Ok(LocalResult::Status(_))
    ));
    server.join().unwrap();
    assert!(!path.join("host.sock").exists());
    assert!(!path.join("discovery.json").exists());
    assert!(path.join("owner.lock").exists());
}

#[test]
fn owner_lock_is_process_exclusive_and_released_on_crash() {
    let root = profile();
    let path = root.path().canonicalize().unwrap();
    let lock = OwnerLock::acquire(&path).unwrap();
    assert!(matches!(OwnerLock::acquire(&path), Err(Error::Busy)));
    // The same test executable is a real, independently spawned contender.
    let exe = std::env::current_exe().unwrap();
    let result = Command::new(&exe)
        .args(["--exact", "lock_child", "--ignored"])
        .env("LOMI_TEST_LOCK_PATH", &path)
        .env("LOMI_TEST_EXPECT_BUSY", "1")
        .output()
        .unwrap();
    assert!(result.status.success());
    drop(lock);
    let mut child = Command::new(exe)
        .args(["--exact", "lock_child", "--ignored", "--nocapture"])
        .env("LOMI_TEST_LOCK_PATH", &path)
        .env_remove("LOMI_TEST_EXPECT_BUSY")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut bytes = [0u8; 5];
    // Test harness prints a prefix first; use a bounded pipe read in another
    // thread so a failed contender cannot hang the parent indefinitely.
    let mut output = child.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        let mut found = Vec::new();
        while output.read(&mut bytes).is_ok_and(|n| {
            found.extend_from_slice(&bytes[..n]);
            n > 0
        }) {
            if found.windows(5).any(|w| w == b"READY") {
                let _ = send.send(());
                break;
            }
        }
    });
    let ready = receive.recv_timeout(Duration::from_secs(5));
    child.kill().unwrap();
    child.wait().unwrap();
    reader.join().unwrap();
    ready.unwrap();
    OwnerLock::acquire(&path).unwrap();
}
#[test]
#[ignore = "child process entrypoint"]
fn lock_child() {
    let path = PathBuf::from(std::env::var_os("LOMI_TEST_LOCK_PATH").unwrap());
    if std::env::var_os("LOMI_TEST_EXPECT_BUSY").is_some() {
        assert!(matches!(OwnerLock::acquire(&path), Err(Error::Busy)));
    } else {
        let _lock = OwnerLock::acquire(&path).unwrap();
        println!("READY");
        std::io::stdout().flush().unwrap();
        thread::sleep(Duration::from_secs(30));
    }
}

#[test]
fn unsafe_profiles_lock_aliases_and_non_socket_entries_are_rejected() {
    let root = profile();
    let path = root.path().canonicalize().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        OwnerLock::acquire(&path),
        Err(Error::InvalidProfile)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let victim = path.join("victim");
    fs::write(&victim, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&victim, path.join("owner.lock")).unwrap();
    assert!(OwnerLock::acquire(&path).is_err());
    assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    fs::remove_file(path.join("owner.lock")).unwrap();
    fs::write(path.join("host.sock"), b"preserve").unwrap();
    assert!(OwnerEndpoint::bind(OwnerLock::acquire(&path).unwrap(), discovery()).is_err());
    assert_eq!(fs::read(path.join("host.sock")).unwrap(), b"preserve");
}

#[test]
fn stale_socket_is_replaced_only_after_acquiring_lifetime_lock() {
    let root = profile();
    let path = root.path().canonicalize().unwrap();
    let socket = std::os::unix::net::UnixListener::bind(path.join("host.sock")).unwrap();
    fs::set_permissions(path.join("host.sock"), fs::Permissions::from_mode(0o600)).unwrap();
    drop(socket);
    let endpoint = OwnerEndpoint::bind(OwnerLock::acquire(&path).unwrap(), discovery()).unwrap();
    assert!(matches!(OwnerLock::acquire(&path), Err(Error::Busy)));
    drop(endpoint);
    assert!(!path.join("host.sock").exists());
}

#[test]
fn absolute_frame_deadline_stops_a_trickling_client() {
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    let server = thread::spawn(move || {
        let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
        let start = Instant::now();
        connection.set_deadline(start + Duration::from_millis(120));
        assert!(connection.read_request().is_err());
        assert!(start.elapsed() < Duration::from_millis(500));
    });
    let mut stream = UnixStream::connect(path.join("host.sock")).unwrap();
    let d: LocalDiscovery =
        serde_json::from_slice(&fs::read(path.join("discovery.json")).unwrap()).unwrap();
    let hello = ipc::LocalClientHello {
        version: LocalIpcVersion::CURRENT,
        profile_id: d.profile_id,
        nonce: ipc::IpcNonce::from_bytes(*Uuid::new_v4().as_bytes()).unwrap(),
    };
    stream
        .write_all(&ipc::encode_local_frame(&hello).unwrap())
        .unwrap();
    let _: ipc::LocalServerHello = ipc::read_local_frame(&mut stream).unwrap();
    for byte in [0, 0, 0, 128] {
        if stream.write_all(&[byte]).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(70));
    }
    server.join().unwrap();
}

#[test]
fn replacement_endpoint_entries_survive_owner_cleanup() {
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    fs::remove_file(path.join("host.sock")).unwrap();
    fs::write(path.join("host.sock"), b"replacement").unwrap();
    drop(endpoint);
    assert_eq!(fs::read(path.join("host.sock")).unwrap(), b"replacement");
}

#[test]
fn delayed_hello_and_chunked_request_receive_the_frame_budget() {
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    let d = endpoint.discovery().clone();
    let server = thread::spawn(move || {
        let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
        connection.set_deadline(Instant::now() + Duration::from_secs(2));
        assert!(matches!(
            connection.read_request().unwrap().call,
            LocalCall::Status {}
        ));
    });
    let mut stream = UnixStream::connect(path.join("host.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    thread::sleep(Duration::from_millis(80));
    let hello = ipc::LocalClientHello {
        version: LocalIpcVersion::CURRENT,
        profile_id: d.profile_id,
        nonce: ipc::IpcNonce::from_bytes(*Uuid::new_v4().as_bytes()).unwrap(),
    };
    stream
        .write_all(&ipc::encode_local_frame(&hello).unwrap())
        .unwrap();
    let _: ipc::LocalServerHello = ipc::read_local_frame(&mut stream).unwrap();
    let request = ipc::LocalRequest {
        version: LocalIpcVersion::CURRENT,
        request_id: "chunked".to_owned().try_into().unwrap(),
        call: LocalCall::Status {},
    };
    for chunk in ipc::encode_local_frame(&request).unwrap().chunks(16) {
        stream.write_all(chunk).unwrap();
        thread::sleep(Duration::from_millis(12));
    }
    server.join().unwrap();
}

#[test]
fn wrong_reply_variants_and_native_target_substitution_are_rejected() {
    for native in [false, true] {
        let (root, endpoint) = endpoint();
        let path = root.path().canonicalize().unwrap();
        let server = thread::spawn(move || {
            let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
            connection.set_deadline(Instant::now() + Duration::from_secs(2));
            let request = connection.read_request().unwrap();
            let result = if native {
                LocalResult::NativeLease(ipc::NativeLease {
                    intent_id: ipc::NativeIntentId::from_bytes(*Uuid::new_v4().as_bytes()).unwrap(),
                    fence: lomi_remote_protocol::DecimalU64(1),
                    expires_at_ms: lomi_remote_protocol::DecimalU64(100),
                    state: ipc::NativeWriterState::Active,
                })
            } else {
                LocalResult::Workspaces(lomi_remote_protocol::rpc::BoundedList(vec![]))
            };
            connection
                .write(&LocalResponse {
                    version: request.version,
                    request_id: request.request_id,
                    result: Ok(result),
                })
                .unwrap();
        });
        let mut client = LocalClient::connect(&path).unwrap();
        let call = if native {
            LocalCall::NativeCheck(ipc::NativeIntentTarget {
                intent_id: ipc::NativeIntentId::from_bytes(*Uuid::new_v4().as_bytes()).unwrap(),
            })
        } else {
            LocalCall::Status {}
        };
        let reply = client.request(call);
        assert!(
            matches!(reply, Err(Error::InvalidFrame)),
            "native={native}, error={:?}",
            reply.as_ref().err()
        );
        server.join().unwrap();
    }
}

#[test]
fn incompatible_discovery_and_hello_major_have_a_closed_update_error() {
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    let mut value = serde_json::to_value(endpoint.discovery()).unwrap();
    value["version"]["major"] = 2.into();
    fs::write(
        path.join("discovery.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        LocalClient::connect(&path),
        Err(Error::Incompatible)
    ));
    let d = endpoint.discovery().clone();
    let server = thread::spawn(move || {
        assert!(matches!(
            endpoint.handshake(accept(&endpoint)),
            Err(Error::Incompatible)
        ));
    });
    let mut stream = UnixStream::connect(path.join("host.sock")).unwrap();
    let hello = serde_json::json!({"version":{"major":2,"minor":0},"profileId":d.profile_id,
        "nonce":Uuid::new_v4().to_string()});
    stream
        .write_all(&ipc::encode_local_frame(&hello).unwrap())
        .unwrap();
    server.join().unwrap();
}

#[test]
fn mutable_nonsticky_ancestry_is_rejected_before_creating_owner_entries() {
    let root = profile();
    let parent = root.path().canonicalize().unwrap().join("replaceable");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    let path = parent.join("profile");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        OwnerLock::acquire(&path),
        Err(Error::InvalidProfile)
    ));
    assert!(!path.join("owner.lock").exists());
    // An alias introduced by substituting the writable ancestor is refused too.
    let renamed = parent.with_file_name("old");
    fs::rename(&parent, &renamed).unwrap();
    std::os::unix::fs::symlink(&renamed, &parent).unwrap();
    assert!(OwnerLock::acquire(&path).is_err());
    assert!(!renamed.join("profile/owner.lock").exists());
}

#[test]
fn saturated_accept_backlog_cannot_hang_connection_acquisition() {
    let root = profile();
    let path = root.path().canonicalize().unwrap();
    let _lock = OwnerLock::acquire(&path).unwrap();
    let address = socket2::SockAddr::unix(path.join("host.sock")).unwrap();
    let listener =
        socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    listener.bind(&address).unwrap();
    listener.listen(1).unwrap();
    fs::set_permissions(path.join("host.sock"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        path.join("discovery.json"),
        serde_json::to_vec(&discovery()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        path.join("discovery.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut pending = Vec::new();
    let mut saturated = false;
    for _ in 0..10 {
        let socket =
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
        if socket
            .connect_timeout(&address, Duration::from_millis(30))
            .is_err()
        {
            saturated = true;
            break;
        }
        pending.push(socket);
    }
    assert!(
        saturated,
        "fixture must actually fill the native accept backlog"
    );
    let started = Instant::now();
    assert!(LocalClient::connect_with_timeout(&path, Duration::from_millis(100)).is_err());
    assert!(started.elapsed() < Duration::from_millis(600));
}

#[cfg(target_os = "macos")]
#[test]
fn extended_acl_grants_are_rejected_even_when_mode_bits_are_private() {
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("/bin/chmod").arg("-N").arg(&self.0).status();
        }
    }
    let root = profile();
    let path = root.path().canonicalize().unwrap();
    let _cleanup = Cleanup(path.clone());
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow list,add_file,search,delete_child"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(matches!(
        OwnerLock::acquire(&path),
        Err(Error::InvalidProfile)
    ));
    assert!(
        Command::new("/bin/chmod")
            .arg("-N")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    drop(OwnerLock::acquire(&path).unwrap());
    let lock = path.join("owner.lock");
    let _cleanup_lock = Cleanup(lock.clone());
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,write"])
            .arg(&lock)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(matches!(
        OwnerLock::acquire(&path),
        Err(Error::InvalidProfile)
    ));
}

fn stream_metadata(d: &LocalDiscovery) -> lomi_remote_protocol::streams::TerminalSnapshotMetadata {
    serde_json::from_value(serde_json::json!({
        "terminal":{"workspace":{"workspaceId":Uuid::new_v4().to_string(),"workspaceEpoch":Uuid::new_v4().to_string(),
            "runtimeId":d.runtime_id,"runtimeGeneration":"1","hostAccessEpoch":"0","grantRevision":"0"},
            "paneId":Uuid::new_v4().to_string(),"sessionId":Uuid::new_v4().to_string(),"sessionEpoch":Uuid::new_v4().to_string(),
            "profile":"lomi-rust-grid-v1-experimental"},
        "subscriptionId":"sub-1","throughSeq":"0","outputOffset":"0","columns":80,"rows":24,"chunkCount":1,"totalBytes":"1"
    })).unwrap()
}
fn attach_request(terminal: lomi_remote_protocol::TerminalContext) -> LocalCall {
    use lomi_remote_protocol::{rpc::*, *};
    LocalCall::Rpc(Box::new(RpcRequest {
        v: ApplicationMajor::try_from(2).unwrap(),
        r#type: RequestKind::Request,
        request_id: "attach".to_owned().try_into().unwrap(),
        timeout_ms: TimeoutMs::new(1000).unwrap(),
        call: RpcCall::TerminalAttach(TerminalReadParams { terminal }),
    }))
}
fn attach_reply(
    connection: &mut lomi_platform::unix::LocalConnection,
    metadata: &lomi_remote_protocol::streams::TerminalSnapshotMetadata,
) {
    use lomi_remote_protocol::rpc::*;
    let request = connection.read_request().unwrap();
    let LocalCall::Rpc(rpc) = request.call else {
        panic!("attach request")
    };
    connection
        .write(&LocalResponse {
            version: request.version,
            request_id: request.request_id,
            result: Ok(LocalResult::Rpc(Box::new(RpcResponse::Result {
                v: rpc.v,
                request_id: rpc.request_id,
                result: RpcResult::TerminalAttach(metadata.clone()),
            }))),
        })
        .unwrap();
}

#[test]
fn stream_events_are_demultiplexed_before_a_correlated_rpc_reply() {
    use lomi_remote_protocol::{
        DecimalU64,
        rpc::{BoundedList, ChunkIndex},
        streams::*,
    };
    let (root, endpoint) = endpoint();
    let path = root.path().canonicalize().unwrap();
    let metadata = stream_metadata(endpoint.discovery());
    let server_metadata = metadata.clone();
    let d = endpoint.discovery().clone();
    let server = thread::spawn(move || {
        let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
        connection.set_deadline(Instant::now() + Duration::from_secs(3));
        attach_reply(&mut connection, &server_metadata);
        connection
            .write(&ipc::LocalStreamEvent::Terminal(
                TerminalStreamFrame::SnapshotChunk(TerminalSnapshotChunk {
                    terminal: server_metadata.terminal.clone(),
                    subscription_id: server_metadata.subscription_id.clone(),
                    index: ChunkIndex(0),
                    bytes: BoundedList(vec![65]),
                }),
            ))
            .unwrap();
        connection
            .write(&ipc::LocalStreamEvent::Terminal(
                TerminalStreamFrame::SnapshotComplete(TerminalSnapshotComplete {
                    terminal: server_metadata.terminal,
                    subscription_id: server_metadata.subscription_id,
                    through_seq: TerminalSeq(DecimalU64(0)),
                    output_offset: DecimalU64(0),
                }),
            ))
            .unwrap();
        let request = connection.read_request().unwrap();
        connection
            .write(&LocalResponse {
                version: request.version,
                request_id: request.request_id,
                result: Ok(LocalResult::Status(LocalStatus {
                    host_id: d.host_id,
                    runtime_id: d.runtime_id,
                    sharing: LocalSharing::Disabled,
                })),
            })
            .unwrap();
    });
    let mut client = LocalClient::connect(&path).unwrap();
    client.request(attach_request(metadata.terminal)).unwrap();
    assert!(matches!(
        client.request(LocalCall::Status {}).unwrap().result,
        Ok(LocalResult::Status(_))
    ));
    assert!(matches!(
        client.try_next_event(),
        Some(ipc::LocalStreamEvent::Terminal(
            TerminalStreamFrame::SnapshotChunk(_)
        ))
    ));
    assert!(matches!(
        client.try_next_event(),
        Some(ipc::LocalStreamEvent::Terminal(
            TerminalStreamFrame::SnapshotComplete(_)
        ))
    ));
    assert!(client.try_next_event().is_none());
    server.join().unwrap();
}

#[test]
fn foreign_stream_binding_poisoning_prevents_reuse_of_the_connection() {
    use lomi_remote_protocol::{
        rpc::{BoundedList, ChunkIndex},
        streams::*,
    };
    let (root, endpoint) = endpoint();
    let path = root.path().canonicalize().unwrap();
    let metadata = stream_metadata(endpoint.discovery());
    let mut wrong = metadata.clone();
    wrong.subscription_id = "foreign-sub".to_owned().try_into().unwrap();
    let server_metadata = metadata.clone();
    let server = thread::spawn(move || {
        let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
        connection.set_deadline(Instant::now() + Duration::from_secs(3));
        attach_reply(&mut connection, &server_metadata);
        connection
            .write(&ipc::LocalStreamEvent::Terminal(
                TerminalStreamFrame::SnapshotChunk(TerminalSnapshotChunk {
                    terminal: wrong.terminal,
                    subscription_id: wrong.subscription_id,
                    index: ChunkIndex(0),
                    bytes: BoundedList(vec![65]),
                }),
            ))
            .unwrap();
    });
    let mut client = LocalClient::connect(&path).unwrap();
    client.request(attach_request(metadata.terminal)).unwrap();
    assert!(matches!(
        client.next_event(Duration::from_secs(1)),
        Err(Error::InvalidFrame)
    ));
    assert!(matches!(
        client.request(LocalCall::Status {}),
        Err(Error::InvalidFrame)
    ));
    server.join().unwrap();
}

#[test]
fn stream_queue_overflow_closes_the_connection_without_unbounded_buffering() {
    use lomi_remote_protocol::{
        rpc::{BoundedList, ChunkIndex},
        streams::*,
    };
    let (root, endpoint) = endpoint();
    let path = root.path().canonicalize().unwrap();
    let metadata = stream_metadata(endpoint.discovery());
    let server_metadata = metadata.clone();
    let server = thread::spawn(move || {
        let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
        connection.set_deadline(Instant::now() + Duration::from_secs(3));
        attach_reply(&mut connection, &server_metadata);
        for _ in 0..40 {
            let event = ipc::LocalStreamEvent::Terminal(TerminalStreamFrame::SnapshotChunk(
                TerminalSnapshotChunk {
                    terminal: server_metadata.terminal.clone(),
                    subscription_id: server_metadata.subscription_id.clone(),
                    index: ChunkIndex(0),
                    bytes: BoundedList(vec![65; 16384]),
                },
            ));
            if connection.write(&event).is_err() {
                return;
            }
        }
    });
    let mut client = LocalClient::connect(&path).unwrap();
    client.request(attach_request(metadata.terminal)).unwrap();
    assert!(matches!(
        client.request(LocalCall::Status {}),
        Err(Error::InvalidFrame)
    ));
    assert!(client.try_next_event().is_none());
    assert!(matches!(
        client.request(LocalCall::Status {}),
        Err(Error::InvalidFrame)
    ));
    server.join().unwrap();
}

#[test]
fn callback_applies_large_live_transfer_while_waiting_for_a_reply() {
    use lomi_remote_protocol::{
        DecimalU64,
        rpc::{BoundedList, ChunkCount, ChunkIndex},
        streams::*,
    };
    let (root, endpoint) = endpoint();
    let path = root.path().canonicalize().unwrap();
    let mut metadata = stream_metadata(endpoint.discovery());
    metadata.chunk_count = ChunkCount(40);
    metadata.total_bytes = DecimalU64(40 * 16384);
    let server_metadata = metadata.clone();
    let d = endpoint.discovery().clone();
    let server = thread::spawn(move || {
        let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
        connection.set_deadline(Instant::now() + Duration::from_secs(5));
        attach_reply(&mut connection, &server_metadata);
        let request = connection.read_request().unwrap();
        for index in 0..40 {
            connection
                .write(&ipc::LocalStreamEvent::Terminal(
                    TerminalStreamFrame::SnapshotChunk(TerminalSnapshotChunk {
                        terminal: server_metadata.terminal.clone(),
                        subscription_id: server_metadata.subscription_id.clone(),
                        index: ChunkIndex(index),
                        bytes: BoundedList(vec![65; 16384]),
                    }),
                ))
                .unwrap();
        }
        connection
            .write(&ipc::LocalStreamEvent::Terminal(
                TerminalStreamFrame::SnapshotComplete(TerminalSnapshotComplete {
                    terminal: server_metadata.terminal,
                    subscription_id: server_metadata.subscription_id,
                    through_seq: TerminalSeq(DecimalU64(0)),
                    output_offset: DecimalU64(0),
                }),
            ))
            .unwrap();
        connection
            .write(&LocalResponse {
                version: request.version,
                request_id: request.request_id,
                result: Ok(LocalResult::Status(LocalStatus {
                    host_id: d.host_id,
                    runtime_id: d.runtime_id,
                    sharing: LocalSharing::Disabled,
                })),
            })
            .unwrap();
    });
    let mut client = LocalClient::connect(&path).unwrap();
    client.request(attach_request(metadata.terminal)).unwrap();
    let mut chunks = 0;
    let mut complete = false;
    let reply = client
        .request_with_events(LocalCall::Status {}, &mut |event| {
            match event {
                ipc::LocalStreamEvent::Terminal(TerminalStreamFrame::SnapshotChunk(chunk)) => {
                    assert_eq!(chunk.index.0, chunks);
                    chunks += 1;
                }
                ipc::LocalStreamEvent::Terminal(TerminalStreamFrame::SnapshotComplete(_)) => {
                    complete = true
                }
                _ => panic!("unexpected large-transfer frame"),
            }
            Ok(())
        })
        .unwrap();
    assert!(matches!(reply.result, Ok(LocalResult::Status(_))));
    assert_eq!(chunks, 40);
    assert!(complete);
    assert!(
        client.try_next_event().is_none(),
        "callback consumption must not retain a second transport copy"
    );
    server.join().unwrap();
}

#[test]
fn ended_stream_bindings_do_not_exhaust_historical_subscription_capacity() {
    use lomi_remote_protocol::{DecimalU64, rpc::BoundedList, streams::*};
    let (root, endpoint) = endpoint();
    let path = root.path().canonicalize().unwrap();
    let metadata = stream_metadata(endpoint.discovery());
    let server_metadata = metadata.clone();
    let server = thread::spawn(move || {
        let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
        connection.set_deadline(Instant::now() + Duration::from_secs(8));
        for index in 0..70 {
            let mut metadata = server_metadata.clone();
            metadata.subscription_id = format!("retire-{index}").try_into().unwrap();
            attach_reply(&mut connection, &metadata);
            connection
                .write(&ipc::LocalStreamEvent::Terminal(
                    TerminalStreamFrame::SnapshotChunk(TerminalSnapshotChunk {
                        terminal: metadata.terminal.clone(),
                        subscription_id: metadata.subscription_id.clone(),
                        index: lomi_remote_protocol::rpc::ChunkIndex(0),
                        bytes: BoundedList(vec![65]),
                    }),
                ))
                .unwrap();
            connection
                .write(&ipc::LocalStreamEvent::Terminal(
                    TerminalStreamFrame::SnapshotComplete(TerminalSnapshotComplete {
                        terminal: metadata.terminal.clone(),
                        subscription_id: metadata.subscription_id.clone(),
                        through_seq: metadata.through_seq,
                        output_offset: metadata.output_offset,
                    }),
                ))
                .unwrap();
            connection
                .write(&ipc::LocalStreamEvent::Terminal(
                    TerminalStreamFrame::Delta(TerminalDelta {
                        terminal: metadata.terminal,
                        subscription_id: metadata.subscription_id,
                        seq: TerminalSeq(DecimalU64(1)),
                        change: TerminalChange::Exit(TerminalExit { exit_code: Some(0) }),
                    }),
                ))
                .unwrap();
        }
    });
    let mut client = LocalClient::connect(&path).unwrap();
    for _ in 0..70 {
        client
            .request(attach_request(metadata.terminal.clone()))
            .unwrap();
        for _ in 0..3 {
            assert!(client.next_event(Duration::from_secs(2)).unwrap().is_some());
        }
    }
    server.join().unwrap();
}
