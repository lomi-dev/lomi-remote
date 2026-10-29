use lomi_remote_protocol::*;
use serde_json::{from_value, json};
use std::collections::BTreeSet;

fn operation() -> OperationId {
    OperationId::from_bytes([9; 16]).unwrap()
}
fn actor(byte: u8) -> ConsumerAuthorizationId {
    ConsumerAuthorizationId::from_bytes([byte; 16]).unwrap()
}
fn workspace(byte: u8) -> WorkspaceId {
    WorkspaceId::from_bytes([byte; 16]).unwrap()
}
fn full() -> CapabilitySet {
    CapabilitySet::try_from(Capability::ALL.to_vec()).unwrap()
}
fn git_write() -> CapabilitySet {
    from_value(json!(["workspace.read", "git.read", "git.write"])).unwrap()
}

#[test]
fn registry_has_exactly_39_unique_typed_methods_and_dynamic_operations() {
    assert_eq!(Method::ALL.len(), 39);
    assert_eq!(METHODS.len(), 39);
    let unique: BTreeSet<_> = Method::ALL.iter().map(|method| method.as_str()).collect();
    assert_eq!(unique.len(), 39);
    assert_eq!(unique, METHODS.iter().copied().collect());
    for method in Method::ALL {
        assert_eq!(Method::parse(method.as_str()), Some(*method));
        assert_eq!(
            from_value::<Method>(json!(method.as_str())).unwrap(),
            *method
        );
        if matches!(method, Method::OperationStatus | Method::OperationCancel) {
            assert_eq!(method.rights(), MethodRights::StoredOperationRights);
            assert!(required_capabilities(method.as_str()).is_none());
            assert!(full().authorize(method.as_str(), false).is_err());
        } else {
            assert!(matches!(method.rights(),MethodRights::Static(rights) if !rights.is_empty()));
        }
    }
    assert!(Method::parse("operation.unknown").is_none());
    assert!(from_value::<Method>(json!("unknown")).is_err());
}

#[test]
fn operation_lookup_checks_actor_workspace_and_current_original_rights() {
    let record = StoredOperationRights::new(
        operation(),
        actor(1),
        workspace(2),
        Method::GitCommit,
        git_write(),
        false,
    )
    .unwrap();
    assert_eq!(record.original_method(), Method::GitCommit);
    assert_eq!(
        full().authorize_operation(
            Method::OperationStatus,
            OperationId::from_bytes([8; 16]).unwrap(),
            actor(1),
            workspace(2),
            Some(&record)
        ),
        Err(OperationAuthorizationError::NotFound)
    );
    let workspace_only: CapabilitySet = from_value(json!(["workspace.read"])).unwrap();
    for method in [Method::OperationStatus, Method::OperationCancel] {
        assert_eq!(
            git_write().authorize_operation(
                method,
                operation(),
                actor(1),
                workspace(2),
                Some(&record)
            ),
            Ok(())
        );
        assert_eq!(
            workspace_only.authorize_operation(
                method,
                operation(),
                actor(1),
                workspace(2),
                Some(&record)
            ),
            Err(OperationAuthorizationError::ScopeDenied)
        );
        for caps in [full(), workspace_only.clone()] {
            for (a, w, r) in [
                (actor(3), workspace(2), Some(&record)),
                (actor(1), workspace(3), Some(&record)),
                (actor(1), workspace(2), None),
            ] {
                assert_eq!(
                    caps.authorize_operation(method, operation(), a, w, r),
                    Err(OperationAuthorizationError::NotFound)
                );
            }
        }
    }
    assert_eq!(
        full().authorize_operation(
            Method::WorkspaceGet,
            operation(),
            actor(1),
            workspace(2),
            Some(&record)
        ),
        Err(OperationAuthorizationError::InvalidMethod)
    );
}

#[test]
fn operation_records_require_complete_original_and_actual_execution_rights() {
    let insufficient: CapabilitySet = from_value(json!(["workspace.read", "git.read"])).unwrap();
    assert!(
        StoredOperationRights::new(
            operation(),
            actor(1),
            workspace(2),
            Method::GitCommit,
            insufficient,
            false
        )
        .is_err()
    );
    assert!(
        StoredOperationRights::new(
            operation(),
            actor(1),
            workspace(2),
            Method::GitCommit,
            git_write(),
            true
        )
        .is_err()
    );
    assert!(
        StoredOperationRights::new(
            operation(),
            actor(1),
            workspace(2),
            Method::GitStatus,
            full(),
            true
        )
        .is_err()
    );
    assert!(
        StoredOperationRights::new(
            operation(),
            actor(1),
            workspace(2),
            Method::OperationStatus,
            full(),
            false
        )
        .is_err()
    );
    let rights: CapabilitySet = from_value(json!([
        "workspace.read",
        "git.read",
        "git.write",
        "git.execute"
    ]))
    .unwrap();
    let record = StoredOperationRights::new(
        operation(),
        actor(1),
        workspace(2),
        Method::GitCommit,
        rights,
        true,
    )
    .unwrap();
    for method in [Method::OperationStatus, Method::OperationCancel] {
        assert_eq!(
            git_write().authorize_operation(
                method,
                operation(),
                actor(1),
                workspace(2),
                Some(&record)
            ),
            Err(OperationAuthorizationError::ScopeDenied)
        );
        assert_eq!(
            full().authorize_operation(method, operation(), actor(1), workspace(2), Some(&record)),
            Ok(())
        );
    }
}

#[test]
fn uuid_types_validate_canonical_text_and_preserve_binary_identity() {
    let text = "01234567-89ab-cdef-0123-456789abcdef";
    let id: WorkspaceId = from_value(json!(text)).unwrap();
    assert_eq!(
        id.to_bytes(),
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef
        ]
    );
    assert_eq!(WorkspaceId::from_bytes(id.to_bytes()).unwrap(), id);
    assert_eq!(serde_json::to_value(id).unwrap(), json!(text));
    for bad in [
        "",
        "0123456789abcdef0123456789abcdef",
        "{01234567-89ab-cdef-0123-456789abcdef}",
        "01234567-89AB-CDEF-0123-456789ABCDEF",
        "01234567_89ab-cdef-0123-456789abcdef",
        "g1234567-89ab-cdef-0123-456789abcdef",
        "00000000-0000-0000-0000-000000000000",
    ] {
        assert!(from_value::<WorkspaceId>(json!(bad)).is_err(), "{bad}");
    }
    assert!(from_value::<WorkspaceId>(json!(7)).is_err());
    assert!(WorkspaceId::from_bytes([0; 16]).is_err());
    // Distinct domain newtypes share bytes without changing existing CBOR APIs.
    assert_eq!(
        OperationId::from_bytes(id.to_bytes()).unwrap().to_bytes(),
        id.to_bytes()
    );
}

#[test]
fn opaque_tokens_are_bounded_and_account_sessions_remain_text() {
    macro_rules! check {
        ($kind:ty, $max:expr) => {{
            assert!(from_value::<$kind>(json!("a_-09Z")).is_ok());
            assert!(from_value::<$kind>(json!("a".repeat($max))).is_ok());
            for bad in [
                "".to_owned(),
                "a".repeat($max + 1),
                "a b".to_owned(),
                "a\nb".to_owned(),
                "a/b".to_owned(),
                "é".to_owned(),
                "a.b".to_owned(),
            ] {
                assert!(from_value::<$kind>(json!(bad)).is_err());
            }
            assert!(from_value::<$kind>(json!(1)).is_err());
        }};
    }
    check!(RequestId, 128);
    check!(AccountSessionId, 128);
    check!(EventCursor, 1024);
    check!(FileRevision, 256);
    check!(RepoStateToken, 256);
    assert!(from_value::<AccountSessionId>(json!("upstream-session_1")).is_ok());
}

#[test]
fn ipc_negotiation_is_independent_and_fails_closed_before_data() {
    let local: LocalIpcVersion = from_value(json!({"major":1,"minor":7})).unwrap();
    assert_eq!(local.negotiate_wire(1, 4).unwrap().minor, 4);
    assert_eq!(local.negotiate_wire(1, 9).unwrap().minor, 7);
    for major in [0, 2, 17, 255] {
        assert_eq!(local.negotiate_wire(major, 0), Err("UPDATE_REQUIRED"));
        assert!(from_value::<LocalIpcVersion>(json!({"major":major,"minor":0})).is_err());
    }
    assert!(from_value::<LocalIpcVersion>(json!({"major":1,"minor":0,"extra":1})).is_err());
    assert!(from_value::<LocalIpcVersion>(json!({"major":1,"minor":65536})).is_err());
    for profile in [
        "draft-unqualified",
        "legacy",
        "lomi-rust-grid-v1-experimental-v2",
    ] {
        assert!(from_value::<TerminalProfile>(json!(profile)).is_err());
    }
    assert!(from_value::<TerminalProfile>(json!("lomi-rust-grid-v1-experimental")).is_ok());
}

#[test]
fn typed_context_rejects_unknown_duplicate_and_malformed_fields() {
    let good = json!({"workspaceId":"11111111-1111-1111-1111-111111111111","workspaceEpoch":"22222222-2222-2222-2222-222222222222","runtimeId":"33333333-3333-3333-3333-333333333333","runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"});
    assert!(from_value::<WorkspaceContext>(good.clone()).is_ok());
    for (field, value) in [
        ("workspaceId", json!("bad")),
        ("runtimeGeneration", json!(1)),
        ("grantRevision", json!("18446744073709551616")),
        ("actorClass", json!("host")),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(from_value::<WorkspaceContext>(bad).is_err());
    }
    let raw = serde_json::to_string(&good).unwrap();
    let duplicate = raw.replacen('{', "{\"runtimeGeneration\":\"1\",", 1);
    assert!(serde_json::from_str::<WorkspaceContext>(&duplicate).is_err());
}
