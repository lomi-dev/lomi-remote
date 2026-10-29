use lomi_remote_protocol::{ipc::*, *};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn id() -> String {
    "11111111-1111-1111-1111-111111111111".into()
}
fn other() -> String {
    "22222222-2222-2222-2222-222222222222".into()
}
struct Os(LocalOsOwner);
impl TrustedLocalPeerAdapter for Os {
    fn connected_owner(&self) -> Result<LocalOsOwner, &'static str> {
        Ok(self.0.clone())
    }
}
fn peer() -> AuthenticatedLocalPeer {
    AuthenticatedLocalPeer::from_os_adapter(
        &Os(LocalOsOwner::UnixUid(7)),
        &LocalOsOwner::UnixUid(7),
    )
    .unwrap()
}
fn hello() -> LocalClientHello {
    serde_json::from_value(json!({"version":{"major":1,"minor":9},"profileId":id(),"nonce":id()}))
        .unwrap()
}
#[test]
fn framing_rejects_partial_oversized_extra_and_non_json() {
    let frame = encode_local_frame(&hello()).unwrap();
    assert!(decode_local_frame::<LocalClientHello>(&frame).is_ok());
    for size in 0..frame.len() {
        assert!(decode_local_frame::<LocalClientHello>(&frame[..size]).is_err());
    }
    let mut extra = frame.clone();
    extra.push(b' ');
    assert!(decode_local_frame::<LocalClientHello>(&extra).is_err());
    for n in [0, LOCAL_IPC_FRAME_BYTES as u32 + 1, u32::MAX] {
        assert!(read_local_frame::<LocalClientHello>(&mut n.to_be_bytes().as_slice()).is_err());
    }
    let mut extra_json = serde_json::to_vec(&hello()).unwrap();
    extra_json.extend_from_slice(b" {}");
    let mut invalid = (extra_json.len() as u32).to_be_bytes().to_vec();
    invalid.extend(extra_json);
    assert!(decode_local_frame::<LocalClientHello>(&invalid).is_err());
    assert!(encode_local_frame(&"a".repeat(LOCAL_IPC_FRAME_BYTES)).is_err());
}
#[test]
fn identity_cannot_be_asserted_by_json_and_os_owner_must_match() {
    for owner in [
        LocalOsOwner::UnixUid(8),
        LocalOsOwner::WindowsSid("S-1-5-21-other".into()),
    ] {
        assert!(
            AuthenticatedLocalPeer::from_os_adapter(&Os(owner), &LocalOsOwner::UnixUid(7)).is_err()
        );
    }
    for field in [
        "uid",
        "sid",
        "owner",
        "clientClass",
        "authenticated",
        "hostRefreshToken",
    ] {
        let mut value = serde_json::to_value(hello()).unwrap();
        value[field] = json!(7);
        assert!(serde_json::from_value::<LocalClientHello>(value).is_err());
    }
    let mut value = serde_json::to_value(hello()).unwrap();
    value["version"]["major"] = json!(2);
    assert!(serde_json::from_value::<LocalClientHello>(value).is_err());
    assert_eq!(
        LocalIpcVersion::CURRENT.negotiate_wire(2, 0),
        Err("UPDATE_REQUIRED")
    );
    assert_eq!(
        LocalIpcVersion::CURRENT.negotiate_wire(1, 9).unwrap().minor,
        0
    );
}
#[test]
fn hello_binds_profile_owner_host_runtime_nonce_and_consumes_probe() {
    let request = hello();
    let host = HostId::try_from(id()).unwrap();
    let runtime = RuntimeId::try_from(id()).unwrap();
    let reply = answer_local_hello(
        &request,
        &peer(),
        &LocalOsOwner::UnixUid(7),
        request.profile_id,
        host,
        runtime,
    )
    .unwrap();
    assert_eq!(reply.version.minor, 0);
    for field in ["profileId", "hostId", "runtimeId", "nonce"] {
        let mut value = serde_json::to_value(&reply).unwrap();
        value[field] = json!(other());
        let wrong = serde_json::from_value::<LocalServerHello>(value).unwrap();
        let mut probe =
            LocalHelloProbe::new(request.clone(), host, runtime, LocalOsOwner::UnixUid(7));
        assert!(probe.verify(&wrong, &peer()).is_err());
        assert!(probe.verify(&reply, &peer()).is_err());
    }
    let mut probe = LocalHelloProbe::new(request.clone(), host, runtime, LocalOsOwner::UnixUid(8));
    assert!(probe.verify(&reply, &peer()).is_err());
    let mut probe = LocalHelloProbe::new(request, host, runtime, LocalOsOwner::UnixUid(7));
    assert!(probe.verify(&reply, &peer()).is_ok());
    assert!(probe.verify(&reply, &peer()).is_err());
}
#[test]
fn local_root_requires_explicit_intent_and_sharing_starts_disabled() {
    assert_eq!(LocalSharing::default(), LocalSharing::Disabled);
    let good = json!({"name":"project","rootPath":"/local/project","operatorIntent":"confirmed"});
    assert!(serde_json::from_value::<LocalWorkspaceAdd>(good.clone()).is_ok());
    for (field, value) in [
        ("rootPath", json!("")),
        ("rootPath", json!("/x\u{0}y")),
        ("name", json!("\u{1b}[31m")),
        ("operatorIntent", json!(false)),
        ("sharing", json!("enabled")),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(serde_json::from_value::<LocalWorkspaceAdd>(bad).is_err());
    }
    let mut bad = good;
    bad.as_object_mut().unwrap().remove("operatorIntent");
    assert!(serde_json::from_value::<LocalWorkspaceAdd>(bad).is_err());
    assert!(
        serde_json::from_value::<LocalWorkspaceTarget>(
            json!({"workspaceId":id(),"operatorIntent":"confirmed","rootPath":"/remote"})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<DoctorDiagnostic>(
            json!({"check":"shell","health":"unknown","env":"SECRET"})
        )
        .is_err()
    );
}
struct Resolver;
impl TrustedNativeIntentResolver for Resolver {
    fn resolve(&self, _: &NativeIntentScope) -> Result<PhysicalWriteScope, &'static str> {
        Ok(PhysicalWriteScope::from_server_identities(BTreeSet::from(
            ["physical-project".into(), "git-common-dir".into()],
        )))
    }
}
struct Verifier(NativeCompletion);
impl TrustedNativeCompletionVerifier for Verifier {
    fn verify_stopped(&mut self, _: NativeIntentId) -> NativeCompletion {
        match self.0 {
            NativeCompletion::VerifiedStopped => NativeCompletion::VerifiedStopped,
            NativeCompletion::Unknown => NativeCompletion::Unknown,
        }
    }
}
fn intent(scope: NativeIntentScope) -> StoredNativeIntent {
    StoredNativeIntent::register(
        &NativeIntentRequest {
            intent_id: NativeIntentId::try_from(id()).unwrap(),
            scope,
        },
        IpcNonce::try_from(id()).unwrap(),
        &peer(),
        &Resolver,
    )
    .unwrap()
}
#[test]
fn native_intents_conflict_by_physical_identity_and_fail_closed() {
    let connection = IpcNonce::try_from(id()).unwrap();
    let common =
        PhysicalWriteScope::from_server_identities(BTreeSet::from(["git-common-dir".into()]));
    let unrelated =
        PhysicalWriteScope::from_server_identities(BTreeSet::from(["other-project".into()]));
    let mut scoped = intent(NativeIntentScope::Workspace {
        workspace_id: WorkspaceId::try_from(id()).unwrap(),
    });
    scoped.acquire(connection, 10, 20, 1).unwrap();
    assert!(scoped.blocks(&common));
    assert!(!scoped.blocks(&unrelated));
    assert!(
        scoped
            .check(IpcNonce::try_from(other()).unwrap(), 11)
            .is_err()
    );
    scoped.renew(connection, 11, 30).unwrap();
    assert!(scoped.check(connection, 30).is_err());
    assert_eq!(scoped.state(), NativeWriterState::Quarantine);
    assert!(scoped.blocks(&common));
    assert!(scoped.renew(connection, 31, 40).is_err());
    assert_eq!(
        scoped.request_finish(&mut Verifier(NativeCompletion::Unknown)),
        NativeWriterState::Quarantine
    );
    assert!(scoped.blocks(&common));
    assert_eq!(
        scoped.request_finish(&mut Verifier(NativeCompletion::VerifiedStopped)),
        NativeWriterState::Finished
    );
    assert!(!scoped.blocks(&common));
    for restart in [false, true] {
        let mut unscoped = intent(NativeIntentScope::Unscoped {});
        unscoped.acquire(connection, 10, 20, 2).unwrap();
        if restart {
            unscoped.host_restarted();
        } else {
            unscoped.connection_lost();
        }
        assert_eq!(unscoped.state(), NativeWriterState::Quarantine);
        assert!(unscoped.blocks(&common));
        assert!(unscoped.blocks(&unrelated));
    }
}
#[test]
fn native_wire_never_accepts_writer_class_or_finish_proof() {
    for field in ["verified", "confirmedTerminated", "pid", "kind", "rootPath"] {
        let mut target = json!({"intentId":id()});
        target[field] = Value::Bool(true);
        assert!(serde_json::from_value::<NativeIntentTarget>(target).is_err());
    }
    assert!(
        serde_json::from_value::<LocalCall>(
            json!({"method":"native.finish","params":{"intentId":id(),"verified":true}})
        )
        .is_err()
    );
}

#[test]
fn setup_start_mode_calls_are_closed_and_round_trip() {
    for (call, mode) in [
        (LocalCall::SetupStartModeRead {}, None),
        (
            LocalCall::SetupStartModeSave(LocalStartModePreference {
                start_mode: LocalStartMode::Boot,
            }),
            Some("boot"),
        ),
    ] {
        let value = serde_json::to_value(&call).unwrap();
        if let Some(mode) = mode {
            assert_eq!(value["params"]["startMode"], json!(mode));
        }
        assert_eq!(serde_json::from_value::<LocalCall>(value).unwrap(), call);
    }
    assert!(serde_json::from_value::<LocalStartMode>(json!("service")).is_err());
}

#[test]
fn canonical_rpc_routes_without_a_second_method_catalog_or_root_paths() {
    let context = json!({"workspaceId":id(),"workspaceEpoch":id(),"runtimeId":id(),"runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"});
    let request = json!({"version":{"major":1,"minor":0},"requestId":"local_1","call":{"method":"rpc","params":{"v":2,"type":"request","requestId":"rpc_1","timeoutMs":1000,"call":{"method":"workspace.get","params":{"context":context}}}}});
    let frame = encode_local_frame(&request).unwrap();
    let decoded = decode_local_request(&frame).unwrap();
    assert!(
        matches!(decoded.call, LocalCall::Rpc(rpc) if matches!(rpc.call, RpcCall::WorkspaceGet(_)))
    );
    let mut bad = request.clone();
    bad["call"]["params"]["call"]["params"]["rootPath"] = json!("/root");
    assert!(decode_local_request(&encode_local_frame(&bad).unwrap()).is_err());
    let mut bad = request;
    bad["ownerUid"] = json!(7);
    assert!(decode_local_request(&encode_local_frame(&bad).unwrap()).is_err());
}
