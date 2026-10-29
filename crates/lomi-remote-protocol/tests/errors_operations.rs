use lomi_remote_protocol::*;
use serde_json::{from_value, json};
fn rights() -> StoredOperationRights {
    StoredOperationRights::new(
        OperationId::from_bytes([1; 16]).unwrap(),
        ConsumerAuthorizationId::from_bytes([2; 16]).unwrap(),
        WorkspaceId::from_bytes([3; 16]).unwrap(),
        Method::FilesCreate,
        CapabilitySet::control_with_workspace_tools(),
        false,
    )
    .unwrap()
}
fn receipt(state: OperationState, effect: Effect) -> Result<OperationReceipt, &'static str> {
    OperationReceipt::new(
        &rights(),
        "a".repeat(64).try_into().unwrap(),
        state,
        false,
        effect,
        if state == OperationState::Succeeded || effect == Effect::Partial {
            Some(OperationResult::File {
                entry_id: EntryId::from_bytes([4; 16]).unwrap(),
                file_revision: "revision".to_owned().try_into().unwrap(),
            })
        } else {
            None
        },
    )
}
#[test]
fn errors_reject_unknown_codes_fields_details_and_secrets() {
    let good = serde_json::to_value(
        RemoteError::new(
            ErrorCode::InvalidArgument,
            false,
            Effect::None,
            ErrorDetails::empty(),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(from_value::<RemoteError>(good.clone()).is_ok());
    for (key, value) in [
        ("code", json!("INTERNAL_STACK")),
        ("message", json!("/private/root token=secret")),
        ("details", json!({"root":"/secret"})),
        (
            "details",
            json!({"expectedRevision":"1","actualRevision":"2"}),
        ),
        ("stack", json!("secret")),
        ("effect", json!("unknown")),
        ("retryable", json!(true)),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(from_value::<RemoteError>(bad).is_err(), "{key}");
    }
    let revision = RemoteError::new(
        ErrorCode::RevisionConflict,
        false,
        Effect::None,
        ErrorDetails::Revision(RevisionErrorDetails {
            expected_revision: DecimalU64(1),
            actual_revision: DecimalU64(2),
        }),
        None,
    )
    .unwrap();
    let mut bad = serde_json::to_value(revision).unwrap();
    bad["details"]["actualRevision"] = json!(2);
    assert!(from_value::<RemoteError>(bad).is_err());
}
#[test]
fn mutation_effects_require_status_binding_and_read_context_rejects_them() {
    let ephemeral = RemoteError::new(
        ErrorCode::OutcomeUnknown,
        false,
        Effect::Unknown,
        ErrorDetails::empty(),
        None,
    )
    .unwrap();
    assert!(ephemeral.validate_for_method(Method::TerminalInput).is_ok());
    assert!(
        ephemeral
            .validate_for_method(Method::TerminalResize)
            .is_ok()
    );
    assert!(
        ephemeral
            .validate_for_method(Method::TerminalCreate)
            .is_err()
    );
    assert!(ephemeral.validate_for_method(Method::WorkspaceGet).is_err());
    let err = RemoteError::new(
        ErrorCode::OutcomeUnknown,
        false,
        Effect::Unknown,
        ErrorDetails::empty(),
        Some(OperationLookup {
            workspace_id: rights().workspace(),
            operation_id: rights().operation_id(),
        }),
    )
    .unwrap();
    assert!(err.validate_for_method(Method::FilesCreate).is_ok());
    assert!(err.validate_for_method(Method::FilesRead).is_err());
    assert!(err.validate_for_method(Method::TerminalResize).is_err());
    assert_eq!(err.http_status(), 409);
    assert_eq!(ErrorCode::OperationExpired.http_status(), 410);
    assert_eq!(ErrorCode::RepositoryExecutionRequired.http_status(), 403);
}
#[test]
fn receipts_validate_state_effect_result_and_original_method() {
    let good = serde_json::to_value(receipt(OperationState::Succeeded, Effect::Committed).unwrap())
        .unwrap();
    for (key, value) in [
        ("state", json!("cancel_confirmed")),
        ("state", json!("cancelled")),
        ("effect", json!("none")),
        ("result", json!(null)),
        ("originalMethod", json!("files.read")),
        ("repositoryExecution", json!(true)),
        ("parameterHash", json!("token")),
        ("cancelOutcome", json!("stopped")),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(from_value::<OperationReceipt>(bad).is_err(), "{key}");
    }
    assert!(receipt(OperationState::Failed, Effect::Partial).is_ok());
    assert!(receipt(OperationState::Cancelled, Effect::Partial).is_err());
    assert!(receipt(OperationState::OutcomeUnknown, Effect::Unknown).is_ok());
    assert!(!OperationState::Succeeded.can_transition_to(OperationState::Running));
    assert!(!OperationState::Accepted.can_transition_to(OperationState::Succeeded));
    assert!(OperationState::Accepted.can_transition_to(OperationState::Cancelled));
}
#[test]
fn receipt_and_tombstone_disclosure_require_current_actor_workspace_and_rights() {
    let r = receipt(OperationState::Succeeded, Effect::Committed).unwrap();
    let caps = CapabilitySet::control_with_workspace_tools();
    let actor = rights().actor();
    let workspace = rights().workspace();
    assert!(r.authorize_disclosure(&caps, actor, workspace).is_ok());
    assert_eq!(
        r.authorize_disclosure(
            &caps,
            ConsumerAuthorizationId::from_bytes([9; 16]).unwrap(),
            workspace
        ),
        Err(OperationAuthorizationError::NotFound)
    );
    assert_eq!(
        r.authorize_disclosure(&caps, actor, WorkspaceId::from_bytes([9; 16]).unwrap()),
        Err(OperationAuthorizationError::NotFound)
    );
    let read =
        CapabilitySet::try_from(vec![Capability::WorkspaceRead, Capability::FilesRead]).unwrap();
    assert_eq!(
        r.authorize_disclosure(&read, actor, workspace),
        Err(OperationAuthorizationError::ScopeDenied)
    );
    let minimal = CapabilitySet::try_from(vec![
        Capability::WorkspaceRead,
        Capability::FilesRead,
        Capability::FilesWrite,
    ])
    .unwrap();
    assert!(r.authorize_disclosure(&minimal, actor, workspace).is_ok());
    let tombstone = OperationTombstone::from_receipt(&r).unwrap();
    assert!(
        tombstone
            .authorize_disclosure(&caps, actor, workspace)
            .is_ok()
    );
    assert!(
        OperationTombstone::from_receipt(&receipt(OperationState::Running, Effect::None).unwrap())
            .is_err()
    );
}
#[test]
fn input_receipts_are_bounded_ephemeral_epoch_receipts_without_hash() {
    let good = InputReceipt::new(
        TerminalSessionId::from_bytes([1; 16]).unwrap(),
        SessionEpoch::from_bytes([2; 16]).unwrap(),
        DecimalU64(1),
        DecimalU64(u64::MAX),
        InputBytes::new(10).unwrap(),
        InputBytes::new(5).unwrap(),
    )
    .unwrap();
    assert!(
        good.validate_binding(
            TerminalSessionId::from_bytes([1; 16]).unwrap(),
            SessionEpoch::from_bytes([2; 16]).unwrap(),
            DecimalU64(1),
            DecimalU64(u64::MAX),
            InputBytes::new(10).unwrap()
        )
        .is_ok()
    );
    assert!(
        good.validate_binding(
            TerminalSessionId::from_bytes([1; 16]).unwrap(),
            SessionEpoch::from_bytes([9; 16]).unwrap(),
            DecimalU64(1),
            DecimalU64(u64::MAX),
            InputBytes::new(10).unwrap()
        )
        .is_err()
    );
    let wire = serde_json::to_value(good).unwrap();
    assert!(wire.get("parameterHash").is_none());
    for (key, value) in [
        ("acceptedBytes", json!(11)),
        ("submittedBytes", json!(16385)),
        ("inputSeq", json!(1)),
        ("sessionEpoch", json!("old")),
        ("parameterHash", json!("hash")),
    ] {
        let mut bad = wire.clone();
        bad[key] = value;
        assert!(from_value::<InputReceipt>(bad).is_err());
    }
}
#[test]
fn budgets_reject_overflow_and_exhaustion() {
    assert_eq!(InputBytes::new(INPUT_BYTES).unwrap().get(), 16 * 1024);
    assert!(InputBytes::new(INPUT_BYTES + 1).is_err());
    assert!(
        ControlMessageBytes::new(CONTROL_MESSAGE_BYTES)
            .unwrap()
            .checked_add(1)
            .is_err()
    );
    assert!(
        SnapshotBytes::new(1)
            .unwrap()
            .checked_add(u64::MAX)
            .is_err()
    );
    assert!(ListPageSize::new(0).is_err());
    assert!(ListPageSize::new(201).is_err());
    assert!(JournalEventCount::new(4097).is_err());
    assert!(SubscriberQueueBytes::new(SUBSCRIBER_QUEUE_BYTES + 1).is_err());
    assert_eq!(RECEIPT_RETENTION_SECONDS, 86400);
    assert_eq!(FRAME_CIPHERTEXT_BYTES, FRAME_PLAINTEXT_BYTES + 16);
}
