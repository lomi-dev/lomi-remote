use super::*;
use lomi_remote_protocol::ipc::{LocalResult, LocalSharing, LocalStatus};
use std::{
    process::{Command, Stdio},
    thread,
};

#[test]
fn setup_start_mode_result_validation_binds_save_to_requested_value() {
    let requested = ipc::LocalStartModePreference {
        start_mode: ipc::LocalStartMode::Boot,
    };
    assert_eq!(
        setup_start_mode_result_matches(
            &LocalCall::SetupStartModeRead {},
            &LocalResult::SetupStartMode(requested.clone()),
        ),
        Some(true)
    );
    assert_eq!(
        setup_start_mode_result_matches(
            &LocalCall::SetupStartModeSave(requested.clone()),
            &LocalResult::SetupStartMode(requested.clone()),
        ),
        Some(true)
    );
    assert_eq!(
        setup_start_mode_result_matches(
            &LocalCall::SetupStartModeSave(requested),
            &LocalResult::SetupStartMode(ipc::LocalStartModePreference {
                start_mode: ipc::LocalStartMode::Login,
            }),
        ),
        Some(false)
    );
}

fn discovery() -> LocalDiscovery {
    LocalDiscovery {
        version: LocalIpcVersion::CURRENT,
        profile_id: IpcProfileId::from_bytes(Uuid::new_v4().into_bytes()).unwrap(),
        host_id: HostId::from_bytes(Uuid::new_v4().into_bytes()).unwrap(),
        runtime_id: RuntimeId::from_bytes(Uuid::new_v4().into_bytes()).unwrap(),
        build_id: "native-windows-test".into(),
    }
}
fn test_root() -> tempfile::TempDir {
    // AppData/Local/Temp permits AppPackage DELETE on this machine. A profile
    // intentionally cannot live beneath a replaceable ancestor. Use our fresh
    // UUID directory directly beneath the protected native user profile instead.
    tempfile::Builder::new()
        .prefix(&format!("lomi-platform-native-{}-", Uuid::new_v4()))
        .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
        .unwrap()
}
fn endpoint() -> (tempfile::TempDir, OwnerEndpoint) {
    let root = test_root();
    let path = normalized(&root.path().canonicalize().unwrap())
        .unwrap()
        .join("profile");
    let endpoint = OwnerEndpoint::bind(OwnerLock::acquire(&path).unwrap(), discovery()).unwrap();
    (root, endpoint)
}
fn accept(endpoint: &OwnerEndpoint) -> PipeStream {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(stream) = endpoint.accept().unwrap() {
            return stream;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
}
fn raw_client(endpoint: &OwnerEndpoint) -> LocalConnection {
    let pipe = Arc::new(
        Handle::new(unsafe {
            CreateFileW(
                wide(&endpoint.name).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        })
        .unwrap(),
    );
    let process = peer_process(pipe.0, true, &endpoint.lock.profile.sid).unwrap();
    LocalConnection::new(
        PipeStream {
            pipe,
            _process: process,
            _permit: None,
            sid: endpoint.lock.profile.sid.clone(),
        },
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap()
}
fn raw_handshake(endpoint: &OwnerEndpoint, client: &mut LocalConnection) {
    let hello = LocalClientHello {
        version: LocalIpcVersion::CURRENT,
        profile_id: endpoint.discovery.profile_id,
        nonce: IpcNonce::from_bytes(Uuid::new_v4().into_bytes()).unwrap(),
    };
    client.write(&hello).unwrap();
}
#[test]
fn native_pipe_authenticates_correlates_and_cleans_discovery() {
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    let d = endpoint.discovery().clone();
    let server = thread::spawn(move || {
        let mut c = endpoint.handshake(accept(&endpoint)).unwrap();
        c.set_deadline(Instant::now() + Duration::from_secs(3));
        let request = c.read_request().unwrap();
        assert!(matches!(request.call, LocalCall::Status {}));
        c.write(&LocalResponse {
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
    assert!(!path.join(DISCOVERY).exists());
    assert!(path.join("owner.lock").exists());
}
#[test]
fn native_request_timeout_rejects_late_response_and_poisons_connection() {
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    let d = endpoint.discovery().clone();
    let server = thread::spawn(move || {
        let mut c = endpoint.handshake(accept(&endpoint)).unwrap();
        let request = c.read_request().unwrap();
        thread::sleep(Duration::from_millis(150));
        // A valid but late reply cannot extend the client's absolute budget.
        let _ = c.write(&LocalResponse {
            version: request.version,
            request_id: request.request_id,
            result: Ok(LocalResult::Status(LocalStatus {
                host_id: d.host_id,
                runtime_id: d.runtime_id,
                sharing: LocalSharing::Disabled,
            })),
        });
    });
    let mut client = LocalClient::connect(&path).unwrap();
    let start = Instant::now();
    assert!(matches!(
        client.request_with_timeout(LocalCall::Status {}, Duration::from_millis(25)),
        Err(Error::Deadline)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(matches!(
        client.request(LocalCall::Status {}),
        Err(Error::InvalidFrame)
    ));
    server.join().unwrap();
}
#[test]
fn native_owner_lock_excludes_processes_and_releases_after_death() {
    let root = test_root();
    let path = normalized(&root.path().canonicalize().unwrap())
        .unwrap()
        .join("profile");
    let lock = OwnerLock::acquire(&path).unwrap();
    assert!(matches!(OwnerLock::acquire(&path), Err(Error::Busy)));
    let exe = std::env::current_exe().unwrap();
    let status = Command::new(&exe)
        .args(["--exact", "windows::tests::owner_child", "--ignored"])
        .env("LOMI_WIN_OWNER_PATH", &path)
        .env("LOMI_WIN_EXPECT_BUSY", "1")
        .status()
        .unwrap();
    assert!(status.success());
    drop(lock);
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "windows::tests::owner_child",
            "--ignored",
            "--nocapture",
        ])
        .env("LOMI_WIN_OWNER_PATH", &path)
        .env_remove("LOMI_WIN_EXPECT_BUSY")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = child.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        let mut found = Vec::new();
        let mut chunk = [0; 64];
        while let Ok(n) = output.read(&mut chunk) {
            if n == 0 {
                break;
            }
            found.extend_from_slice(&chunk[..n]);
            if found.windows(5).any(|w| w == b"READY") {
                let _ = send.send(());
                break;
            }
        }
    });
    let ready = receive.recv_timeout(Duration::from_secs(4));
    child.kill().unwrap();
    child.wait().unwrap();
    reader.join().unwrap();
    ready.unwrap();
    OwnerLock::acquire(&path).unwrap();
}
#[test]
#[ignore = "bounded subprocess entrypoint"]
fn owner_child() {
    let path = PathBuf::from(std::env::var_os("LOMI_WIN_OWNER_PATH").unwrap());
    if std::env::var_os("LOMI_WIN_EXPECT_BUSY").is_some() {
        assert!(matches!(OwnerLock::acquire(&path), Err(Error::Busy)));
    } else {
        let _lock = OwnerLock::acquire(&path).unwrap();
        println!("READY");
        io::stdout().flush().unwrap();
        thread::sleep(Duration::from_secs(20));
    }
}
#[test]
fn native_profile_rejects_hardlinks_reparse_aliases_and_public_acl() {
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    drop(endpoint);
    let lock = path.join("owner.lock");
    let alias = path.join("alias");
    fs::hard_link(&lock, &alias).unwrap();
    assert!(matches!(
        OwnerLock::acquire(&path),
        Err(Error::InvalidProfile)
    ));
    fs::remove_file(alias).unwrap();
    let junction = path.parent().unwrap().join("junction");
    let result = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&path)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(matches!(
        OwnerLock::acquire(&junction),
        Err(Error::InvalidProfile)
    ));
    fs::remove_dir(&junction).unwrap();
    let bad = Security::new(&format!(
        "O:{}D:P(A;OICI;FA;;;{})(A;OICI;FR;;;WD)",
        current_sid().unwrap(),
        current_sid().unwrap()
    ))
    .unwrap();
    let h = Handle::new(unsafe {
        CreateFileW(
            wide(&path).as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    })
    .unwrap();
    let code = unsafe {
        SetSecurityInfo(
            h.0,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            {
                let mut acl = ptr::null_mut();
                let mut present = 0;
                let mut defaulted = 0;
                check(GetSecurityDescriptorDacl(
                    bad.attributes.lpSecurityDescriptor,
                    &mut present,
                    &mut acl,
                    &mut defaulted,
                ))
                .unwrap();
                acl
            },
            ptr::null_mut(),
        )
    };
    assert_eq!(code, ERROR_SUCCESS);
    drop(h);
    assert!(matches!(
        OwnerLock::acquire(&path),
        Err(Error::InvalidProfile)
    ));
}
#[test]
fn native_named_pipe_first_instance_refuses_squatting() {
    let (_root, endpoint) = endpoint();
    let name = endpoint.name.clone();
    let sid = endpoint.lock.profile.sid.clone();
    assert!(matches!(Listener::new(&name, &sid, true), Err(Error::Busy)));
    let client = raw_client(&endpoint);
    let stream = accept(&endpoint);
    assert!(matches!(Listener::new(&name, &sid, true), Err(Error::Busy)));
    drop(stream);
    drop(client);
    assert!(matches!(Listener::new(&name, &sid, true), Err(Error::Busy)));
}
#[test]
fn native_identification_sqos_limits_impersonation_authority() {
    let (_root, endpoint) = endpoint();
    let mut client = raw_client(&endpoint);
    raw_handshake(&endpoint, &mut client);
    let stream = accept(&endpoint);
    let mut connection =
        LocalConnection::new(stream, Instant::now() + Duration::from_secs(2)).unwrap();
    let _: LocalClientHello = connection.read().unwrap();
    unsafe {
        check(ImpersonateNamedPipeClient(connection.stream.pipe.0)).unwrap();
    }
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            unsafe {
                RevertToSelf();
            }
        }
    }
    let revert = Revert;
    let mut token = ptr::null_mut();
    unsafe {
        check(OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY,
            1,
            &mut token,
        ))
        .unwrap();
    }
    let token = Handle::new(token).unwrap();
    let mut level = 99i32;
    let mut length = 0;
    unsafe {
        check(GetTokenInformation(
            token.0,
            TokenImpersonationLevel,
            (&mut level as *mut i32).cast(),
            mem::size_of::<i32>() as u32,
            &mut length,
        ))
        .unwrap();
    }
    drop(revert);
    assert!(level <= SecurityIdentification);
    assert!(peer_process(client.stream.pipe.0, true, "S-1-5-18").is_err());
}
#[test]
fn native_absolute_frame_deadline_cancels_silent_or_trickling_peer() {
    let (_root, endpoint) = endpoint();
    let mut client = raw_client(&endpoint);
    raw_handshake(&endpoint, &mut client);
    let mut server = endpoint.handshake(accept(&endpoint)).unwrap();
    let _: LocalServerHello = client.read().unwrap();
    let start = Instant::now();
    server.set_deadline(start + Duration::from_millis(120));
    let worker = thread::spawn(move || {
        for b in [0, 0, 0, 128] {
            if client.write_all(&[b]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(65));
        }
    });
    assert!(matches!(server.read_request(), Err(Error::Deadline)));
    assert!(start.elapsed() < Duration::from_millis(700));
    worker.join().unwrap();
}
#[test]
fn native_handshake_nonce_runtime_and_incompatible_major_are_rejected() {
    for mode in ["nonce", "runtime", "major"] {
        let (_root, endpoint) = endpoint();
        let path = endpoint.profile().path().to_path_buf();
        let worker = thread::spawn(move || {
            let stream = accept(&endpoint);
            let mut connection =
                LocalConnection::new(stream, Instant::now() + Duration::from_secs(2)).unwrap();
            let hello: LocalClientHello = connection.read().unwrap();
            let reply = LocalServerHello {
                version: hello.version,
                profile_id: hello.profile_id,
                host_id: endpoint.discovery.host_id,
                runtime_id: endpoint.discovery.runtime_id,
                nonce: hello.nonce,
            };
            let mut value = serde_json::to_value(reply).unwrap();
            match mode {
                "nonce" => {
                    value["nonce"] = serde_json::json!(String::from(
                        IpcNonce::from_bytes(Uuid::new_v4().into_bytes()).unwrap()
                    ))
                }
                "runtime" => value["runtimeId"] = serde_json::json!(Uuid::new_v4().to_string()),
                _ => value["version"]["major"] = serde_json::json!(2),
            };
            connection.write(&value).unwrap();
        });
        assert!(matches!(
            LocalClient::connect_with_timeout(&path, Duration::from_secs(2)),
            Err(Error::Incompatible)
        ));
        worker.join().unwrap();
    }
}

#[test]
fn native_connection_count_and_frame_prefix_are_bounded() {
    let (_root, endpoint) = endpoint();
    let mut clients = Vec::new();
    let mut streams = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        clients.push(raw_client(&endpoint));
        streams.push(accept(&endpoint));
    }
    assert!(endpoint.accept().unwrap().is_none());
    assert!(!endpoint.wait(Duration::from_millis(1)).unwrap());
    drop(streams);
    drop(clients);
    let mut client = raw_client(&endpoint);
    let mut server =
        LocalConnection::new(accept(&endpoint), Instant::now() + Duration::from_secs(2)).unwrap();
    client
        .write_all(&((ipc::LOCAL_IPC_FRAME_BYTES + 1) as u32).to_be_bytes())
        .unwrap();
    assert!(matches!(
        server.read::<serde_json::Value>(),
        Err(Error::InvalidFrame)
    ));
}
#[test]
fn native_client_hello_deadline_is_absolute() {
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    let stream_ready = thread::spawn(move || {
        let _stream = accept(&endpoint);
        thread::sleep(Duration::from_millis(450));
    });
    let now = Instant::now();
    assert!(matches!(
        LocalClient::connect_with_timeout(&path, Duration::from_millis(100)),
        Err(Error::Deadline)
    ));
    assert!(now.elapsed() < Duration::from_millis(700));
    stream_ready.join().unwrap();
}
#[test]
fn native_disconnected_connect_does_not_wedge_the_next_listener() {
    let (_root, endpoint) = endpoint();
    let abandoned = raw_client(&endpoint);
    drop(abandoned);
    assert!(endpoint.wait(Duration::from_secs(1)).unwrap());
    let _ = endpoint.accept();
    let mut client = raw_client(&endpoint);
    raw_handshake(&endpoint, &mut client);
    let _server = endpoint.handshake(accept(&endpoint)).unwrap();
    let reply: LocalServerHello = client.read().unwrap();
    assert_eq!(reply.runtime_id, endpoint.discovery.runtime_id);
}
#[test]
fn native_mismatched_response_poison_closes_the_pipe_before_client_drop() {
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    let d = endpoint.discovery.clone();
    let worker = thread::spawn(move || {
        let mut c = endpoint.handshake(accept(&endpoint)).unwrap();
        c.set_deadline(Instant::now() + Duration::from_secs(2));
        let request = c.read_request().unwrap();
        c.write(&LocalResponse {
            version: request.version,
            request_id: RequestId::try_from("wrong-id".to_string()).unwrap(),
            result: Ok(LocalResult::Status(LocalStatus {
                host_id: d.host_id,
                runtime_id: d.runtime_id,
                sharing: LocalSharing::Disabled,
            })),
        })
        .unwrap();
        assert!(c.wait_readable(Duration::from_secs(1)).unwrap());
        assert!(c.read_request().is_err());
    });
    let mut client = LocalClient::connect(&path).unwrap();
    assert!(matches!(
        client.request(LocalCall::Status {}),
        Err(Error::InvalidFrame)
    ));
    assert!(matches!(
        client.request(LocalCall::Status {}),
        Err(Error::InvalidFrame)
    ));
    worker.join().unwrap();
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
    connection: &mut LocalConnection,
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
fn native_callback_applies_large_live_transfer_without_queue_overflow() {
    use lomi_remote_protocol::{
        DecimalU64,
        rpc::{BoundedList, ChunkCount, ChunkIndex},
        streams::*,
    };
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
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
fn native_profile_rejects_inherit_only_world_before_creating_private_files() {
    let root = test_root();
    let parent = normalized(&root.path().canonicalize().unwrap()).unwrap();
    let sid = current_sid().unwrap();
    for (name, extra, valid) in [
        ("world", "(A;OICIIO;FA;;;WD)", false),
        ("owner", "", true),
        ("deny", "(D;OICIIO;FA;;;WD)", true),
    ] {
        let path = parent.join(name);
        let sd = Security::new(&format!("O:{sid}D:P{extra}(A;OICI;FA;;;{sid})")).unwrap();
        unsafe {
            check(CreateDirectoryW(wide(&path).as_ptr(), &sd.attributes)).unwrap();
        }
        let result = OwnerLock::acquire(&path);
        if valid {
            assert!(
                result.is_ok(),
                "owner-only and deny-only inheritance remain valid"
            );
        } else {
            assert!(matches!(result, Err(Error::InvalidProfile)));
            assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
            for file in [
                "owner.lock",
                DISCOVERY,
                "host.db",
                "host.db-wal",
                "host.db-shm",
            ] {
                assert!(!path.join(file).exists(), "reject before creating {file}");
            }
        }
    }
}

#[test]
fn native_client_retires_seventy_sequential_terminal_bindings() {
    use lomi_remote_protocol::{DecimalU64, streams::*};
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    let metadata = stream_metadata(endpoint.discovery());
    let server_metadata = metadata.clone();
    let server = thread::spawn(move || {
        let mut connection = endpoint.handshake(accept(&endpoint)).unwrap();
        connection.set_deadline(Instant::now() + Duration::from_secs(10));
        for index in 0..70 {
            let mut metadata = server_metadata.clone();
            metadata.subscription_id = format!("sub-{index}").try_into().unwrap();
            attach_reply(&mut connection, &metadata);
            let frame = if index % 2 == 0 {
                TerminalStreamFrame::Delta(TerminalDelta {
                    terminal: metadata.terminal,
                    subscription_id: metadata.subscription_id,
                    seq: TerminalSeq(DecimalU64(1)),
                    change: TerminalChange::Exit(TerminalExit { exit_code: Some(0) }),
                })
            } else {
                TerminalStreamFrame::ResyncRequired(TerminalResync {
                    terminal: metadata.terminal,
                    subscription_id: metadata.subscription_id,
                    reason: ResyncReason::SubscriberOverflow,
                })
            };
            connection
                .write(&ipc::LocalStreamEvent::Terminal(frame))
                .unwrap();
        }
    });
    let mut client = LocalClient::connect(&path).unwrap();
    for _ in 0..70 {
        client
            .request(attach_request(metadata.terminal.clone()))
            .unwrap();
        assert!(client.next_event(Duration::from_secs(2)).unwrap().is_some());
        assert!(client.subscriptions.is_empty());
    }
    server.join().unwrap();
}

#[test]
fn native_client_retires_workspace_only_after_validated_resync() {
    use lomi_remote_protocol::streams::*;
    let (_root, endpoint) = endpoint();
    let path = endpoint.profile().path().to_path_buf();
    let metadata = stream_metadata(endpoint.discovery());
    let server = thread::spawn(move || {
        let _connection = endpoint.handshake(accept(&endpoint)).unwrap();
        thread::sleep(Duration::from_millis(100));
    });
    let mut client = LocalClient::connect(&path).unwrap();
    let context = metadata.terminal.workspace;
    client.subscriptions.insert(
        metadata.subscription_id.as_str().to_owned(),
        StreamBinding::Workspace(context.clone()),
    );
    let mut wrong = context.clone();
    wrong.runtime_generation = lomi_remote_protocol::DecimalU64(2);
    let frame = |context| {
        serde_json::to_value(ipc::LocalStreamEvent::Workspace(
            WorkspaceStreamFrame::ResyncRequired(WorkspaceResync {
                context,
                subscription_id: metadata.subscription_id.clone(),
                reason: ResyncReason::SubscriberOverflow,
            }),
        ))
        .unwrap()
    };
    assert!(matches!(
        client.decode_event(frame(wrong)),
        Err(Error::InvalidFrame)
    ));
    assert_eq!(client.subscriptions.len(), 1);
    client.decode_event(frame(context)).unwrap();
    assert!(client.subscriptions.is_empty());
    server.join().unwrap();
}
