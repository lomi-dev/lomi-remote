use lomi_remote_protocol::*;
use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

fn identity_wire(byte: &str) -> SignedIdentityWire {
    EnrollmentProof {
        canonical_cbor: byte.to_owned().try_into().unwrap(),
        signature: byte.repeat(64).try_into().unwrap(),
    }
}
fn account(n: u8) -> AccountId {
    AccountId::from_bytes([n; 16]).unwrap()
}
fn host(n: u8) -> HostId {
    HostId::from_bytes([n; 16]).unwrap()
}
fn consumer(n: u8) -> ConsumerAuthorizationId {
    ConsumerAuthorizationId::from_bytes([n; 16]).unwrap()
}
struct Store(StoredPrincipal);
impl TrustedPrincipalStore for Store {
    fn lookup(&self, _: &str) -> Option<StoredPrincipal> {
        Some(self.0.clone())
    }
}
fn principal(record: StoredPrincipal) -> Principal {
    Principal::from_trusted_store(&Store(record), "trusted-credential").unwrap()
}
fn host_principal() -> Principal {
    principal(StoredPrincipal::HostAccess {
        account_id: account(1),
        host_id: host(2),
        authorization_id: HostAuthorizationId::from_bytes([3; 16]).unwrap(),
        can_manage_account: false,
    })
}
fn consumer_principal(management: bool) -> Principal {
    principal(StoredPrincipal::Consumer {
        account_id: account(1),
        authorization_id: consumer(4),
        account_session_id: AccountSessionId::try_from("opaque-session".to_owned()).unwrap(),
        can_manage_account: management,
    })
}
fn resource() -> StoredResourceBinding {
    StoredResourceBinding {
        account_id: account(1),
        host_id: host(2),
        host_authorization_id: HostAuthorizationId::from_bytes([3; 16]).unwrap(),
        host_identity: identity_wire("ab"),
        consumer_authorization_id: Some(consumer(4)),
        enrollment_id: None,
        bootstrap_session_id: None,
    }
}
fn runtime() -> RuntimeBinding {
    RuntimeBinding {
        runtime_id: RuntimeId::from_bytes([5; 16]).unwrap(),
        runtime_generation: DecimalU64(9),
        host_access_epoch: DecimalU64(2),
    }
}
fn publication() -> PublicationParams {
    PublicationParams {
        runtime: runtime(),
        expected_publication_seq: DecimalU64(8),
        publication_seq: DecimalU64(9),
        workspaces: vec![PublishedWorkspace {
            workspace_id: WorkspaceId::from_bytes([6; 16]).unwrap(),
            workspace_epoch: WorkspaceEpoch::from_bytes([7; 16]).unwrap(),
            terminals: vec![PublishedTerminal {
                pane_id: PaneId::from_bytes([8; 16]).unwrap(),
                session_id: TerminalSessionId::from_bytes([9; 16]).unwrap(),
                session_epoch: SessionEpoch::from_bytes([10; 16]).unwrap(),
            }]
            .try_into()
            .unwrap(),
        }]
        .try_into()
        .unwrap(),
    }
}

#[test]
fn exact_route_registry_has_twenty_six_distinct_policies() {
    assert_eq!(HTTP_ROUTES.len(), 26);
    for (i, r) in HTTP_ROUTES.iter().enumerate() {
        assert!(
            !HTTP_ROUTES[..i]
                .iter()
                .any(|p| p.method == r.method && p.path == r.path)
        );
    }
    assert_eq!(
        HttpRoute::HostAuthorizationRefresh.contract().surface,
        HttpSurface::HostRefresh
    );
    assert_eq!(
        HttpRoute::Inventory.contract().surface,
        HttpSurface::ConsumerSession
    );
    assert_eq!(
        HttpRoute::HostRevoke.contract().surface,
        HttpSurface::SelfHostOrOwnerAccount
    );
    assert_eq!(
        HttpRoute::HostRevocationAck.contract().surface,
        HttpSurface::HostRevocationProof
    );
    assert_eq!(
        HttpRoute::HostRevocationAck.contract().path,
        "/hosts/{hostId}/revocation-ack"
    );
    assert_eq!(
        HttpRoute::HostEnrollmentRevocationAck.contract().surface,
        HttpSurface::HostEnrollmentRevocationProof
    );
    assert_eq!(
        HttpRoute::HostEnrollmentRevocationAck.contract().path,
        "/hosts/{hostId}/enrollment-revocation-ack"
    );
}

fn host_authorization(n: u8) -> HostAuthorizationId {
    HostAuthorizationId::from_bytes([n; 16]).unwrap()
}
fn revocation_ack_request(epoch: u64) -> HostRevocationAckParams {
    HostRevocationAckParams {
        host_authorization_id: host_authorization(3),
        expected_host_access_epoch: DecimalU64(epoch),
        refresh: "retained_refresh_proof".to_owned().try_into().unwrap(),
    }
}
fn revocation_ack_snapshot() -> HostRevocationAckSnapshot {
    HostRevocationAckSnapshot {
        host_id: host(2),
        host_account_id: account(1),
        family_host_authorization_id: host_authorization(3),
        family_host_id: host(2),
        family_account_id: account(1),
        refresh_secret_hash_matches_family: true,
        family_revoked: true,
        family_host_access_epoch: 7,
        current_host_access_epoch: 12,
    }
}
struct RevocationAckStore {
    snapshot: Option<HostRevocationAckSnapshot>,
    lookup: RefCell<Option<(HostId, HostAuthorizationId, String)>>,
}
impl TrustedHostRevocationAckStore for RevocationAckStore {
    fn lookup_revocation_ack(
        &self,
        path_host_id: HostId,
        family_host_authorization_id: HostAuthorizationId,
        refresh_secret: &str,
    ) -> Option<HostRevocationAckSnapshot> {
        *self.lookup.borrow_mut() = Some((
            path_host_id,
            family_host_authorization_id,
            refresh_secret.to_owned(),
        ));
        self.snapshot.clone()
    }
}
fn revocation_ack_store(snapshot: Option<HostRevocationAckSnapshot>) -> RevocationAckStore {
    RevocationAckStore {
        snapshot,
        lookup: RefCell::new(None),
    }
}

#[test]
fn revocation_proof_surface_is_denied_by_generic_authorization_for_every_class() {
    let ordinary = principal(StoredPrincipal::OrdinaryAccount {
        account_id: account(1),
        session_id: BetterAuthSessionId::new("ordinary".to_owned().try_into().unwrap()),
    });
    let bootstrap = principal(StoredPrincipal::EnrollmentBootstrap {
        account_id: account(1),
        host_id: host(2),
        enrollment_id: EnrollmentId::from_bytes([5; 16]).unwrap(),
        bootstrap_session_id: EnrollmentBootstrapSessionId::from_bytes([6; 16]).unwrap(),
    });
    let host_access = host_principal();
    let host_refresh = principal(StoredPrincipal::HostRefresh {
        account_id: account(1),
        host_id: host(2),
        authorization_id: host_authorization(3),
    });
    let consumer = consumer_principal(true);
    let resource = resource();
    for route in [
        HttpRoute::HostRevocationAck,
        HttpRoute::HostEnrollmentRevocationAck,
    ] {
        for principal in [
            &ordinary,
            &bootstrap,
            &host_access,
            &host_refresh,
            &consumer,
        ] {
            assert!(authorize_http(route, Some(principal), Some(&resource)).is_err());
        }
        assert!(authorize_http(route, None, None).is_err());
        assert!(authorize_http(route, None, Some(&resource)).is_err());
    }
}

#[test]
fn revocation_ack_uses_only_the_bound_retained_refresh_proof() {
    let request = revocation_ack_request(7);
    let store = revocation_ack_store(Some(revocation_ack_snapshot()));
    assert_eq!(
        authorize_host_revocation_ack(host(2), &request, &store).unwrap(),
        HostRevokeResult {
            host_id: host(2),
            host_access_epoch: DecimalU64(12),
        }
    );
    assert_eq!(
        store.lookup.into_inner(),
        Some((
            host(2),
            host_authorization(3),
            "retained_refresh_proof".to_owned(),
        ))
    );
}

#[test]
fn revocation_ack_denies_missing_wrong_live_and_inconsistent_proofs() {
    let request = revocation_ack_request(7);
    assert!(authorize_host_revocation_ack(host(2), &request, &revocation_ack_store(None)).is_err());

    let mut invalid_snapshots = Vec::new();
    let mut wrong_host = revocation_ack_snapshot();
    wrong_host.host_id = host(9);
    invalid_snapshots.push(wrong_host);
    let mut wrong_family_host = revocation_ack_snapshot();
    wrong_family_host.family_host_id = host(9);
    invalid_snapshots.push(wrong_family_host);
    let mut wrong_family_account = revocation_ack_snapshot();
    wrong_family_account.family_account_id = account(9);
    invalid_snapshots.push(wrong_family_account);
    let mut wrong_host_account = revocation_ack_snapshot();
    wrong_host_account.host_account_id = account(9);
    invalid_snapshots.push(wrong_host_account);
    let mut wrong_family_id = revocation_ack_snapshot();
    wrong_family_id.family_host_authorization_id = host_authorization(9);
    invalid_snapshots.push(wrong_family_id);
    let mut missing_membership = revocation_ack_snapshot();
    missing_membership.refresh_secret_hash_matches_family = false;
    invalid_snapshots.push(missing_membership);
    let mut live_family = revocation_ack_snapshot();
    live_family.family_revoked = false;
    invalid_snapshots.push(live_family);
    let mut stale_host_epoch = revocation_ack_snapshot();
    stale_host_epoch.current_host_access_epoch = 6;
    invalid_snapshots.push(stale_host_epoch);
    for snapshot in invalid_snapshots {
        assert!(
            authorize_host_revocation_ack(host(2), &request, &revocation_ack_store(Some(snapshot)))
                .is_err()
        );
    }
    for epoch in [0, i64::MAX as u64 + 1, 8] {
        assert!(
            authorize_host_revocation_ack(
                host(2),
                &revocation_ack_request(epoch),
                &revocation_ack_store(Some(revocation_ack_snapshot()))
            )
            .is_err()
        );
    }
    assert!(
        authorize_host_revocation_ack(
            host(9),
            &request,
            &revocation_ack_store(Some(revocation_ack_snapshot()))
        )
        .is_err()
    );
}

fn enrollment_revocation_request() -> HostEnrollmentRevocationAckParams {
    HostEnrollmentRevocationAckParams {
        enrollment_id: EnrollmentId::from_bytes([5; 16]).unwrap(),
        operation_id: OperationId::from_bytes([6; 16]).unwrap(),
        proof: EnrollmentProof {
            canonical_cbor: "aa".to_owned().try_into().unwrap(),
            signature: "ab".repeat(64).try_into().unwrap(),
        },
    }
}

fn enrollment_revocation_snapshot(
    family: HostEnrollmentRevocationFamilySnapshot,
) -> HostEnrollmentRevocationAckSnapshot {
    HostEnrollmentRevocationAckSnapshot {
        host_id: host(2),
        enrollment_id: EnrollmentId::from_bytes([5; 16]).unwrap(),
        operation_id: OperationId::from_bytes([6; 16]).unwrap(),
        account_id: account(1),
        approved: true,
        enrollment_revoked: true,
        consumed: false,
        family,
    }
}

struct EnrollmentRevocationAckStore {
    snapshot: Option<HostEnrollmentRevocationAckSnapshot>,
    lookup: RefCell<Option<(HostId, HostEnrollmentRevocationAckParams)>>,
}
impl TrustedHostEnrollmentRevocationAckStore for EnrollmentRevocationAckStore {
    fn lookup_enrollment_revocation_ack(
        &self,
        path_host_id: HostId,
        request: &HostEnrollmentRevocationAckParams,
    ) -> Option<HostEnrollmentRevocationAckSnapshot> {
        *self.lookup.borrow_mut() = Some((path_host_id, request.clone()));
        self.snapshot.clone()
    }
}

fn enrollment_revocation_store(
    snapshot: Option<HostEnrollmentRevocationAckSnapshot>,
) -> EnrollmentRevocationAckStore {
    EnrollmentRevocationAckStore {
        snapshot,
        lookup: RefCell::new(None),
    }
}

#[test]
fn enrollment_revocation_ack_returns_only_the_exact_revoked_family_or_no_family() {
    let request = enrollment_revocation_request();
    let revoked_family = HostEnrollmentRevocationFamilySnapshot::RevokedFamily {
        host_authorization_id: host_authorization(3),
        host_id: host(2),
        host_account_id: account(1),
        account_id: account(1),
        family_host_access_epoch: 7,
        host_access_epoch: i64::MAX as u64,
    };
    let store = enrollment_revocation_store(Some(enrollment_revocation_snapshot(revoked_family)));
    assert_eq!(
        authorize_host_enrollment_revocation_ack(host(2), &request, &store).unwrap(),
        HostEnrollmentRevocationAckResult::RevokedFamily {
            host_id: host(2),
            enrollment_id: request.enrollment_id,
            operation_id: request.operation_id,
            account_id: account(1),
            host_authorization_id: host_authorization(3),
            family_host_access_epoch: DecimalU64(7),
            host_access_epoch: DecimalU64(i64::MAX as u64),
        }
    );
    let (looked_up_host, looked_up_request) = store.lookup.into_inner().unwrap();
    assert_eq!(looked_up_host, host(2));
    assert_eq!(looked_up_request, request);

    // Enrollment exchange consumes the challenge. A later family revocation
    // acknowledgement remains valid when the exact family is already revoked.
    let mut exchanged =
        enrollment_revocation_snapshot(HostEnrollmentRevocationFamilySnapshot::RevokedFamily {
            host_authorization_id: host_authorization(3),
            host_id: host(2),
            host_account_id: account(1),
            account_id: account(1),
            family_host_access_epoch: 7,
            host_access_epoch: 12,
        });
    exchanged.enrollment_revoked = false;
    exchanged.consumed = true;
    assert_eq!(
        authorize_host_enrollment_revocation_ack(
            host(2),
            &request,
            &enrollment_revocation_store(Some(exchanged))
        )
        .unwrap(),
        HostEnrollmentRevocationAckResult::RevokedFamily {
            host_id: host(2),
            enrollment_id: request.enrollment_id,
            operation_id: request.operation_id,
            account_id: account(1),
            host_authorization_id: host_authorization(3),
            family_host_access_epoch: DecimalU64(7),
            host_access_epoch: DecimalU64(12),
        }
    );

    // This snapshot has no current HostIdentity owner because the enrollment
    // was never exchanged into a host identity.
    let no_family_store = enrollment_revocation_store(Some(enrollment_revocation_snapshot(
        HostEnrollmentRevocationFamilySnapshot::NoFamily,
    )));
    let result =
        authorize_host_enrollment_revocation_ack(host(2), &request, &no_family_store).unwrap();
    assert_eq!(
        result,
        HostEnrollmentRevocationAckResult::NoFamily {
            host_id: host(2),
            enrollment_id: request.enrollment_id,
            operation_id: request.operation_id,
            account_id: account(1),
        }
    );
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::json!({
            "outcome":"noFamily",
            "hostId":host(2),
            "enrollmentId":request.enrollment_id,
            "operationId":request.operation_id,
            "accountId":account(1)
        })
    );
}

#[test]
fn enrollment_revocation_ack_no_family_requires_approved_revoked_unconsumed_enrollment() {
    let request = enrollment_revocation_request();
    for (approved, enrollment_revoked, consumed) in [
        (false, true, false),
        (true, false, false),
        (true, false, true),
        (true, true, true),
        (false, false, false),
    ] {
        let mut snapshot =
            enrollment_revocation_snapshot(HostEnrollmentRevocationFamilySnapshot::NoFamily);
        snapshot.approved = approved;
        snapshot.enrollment_revoked = enrollment_revoked;
        snapshot.consumed = consumed;
        assert!(
            authorize_host_enrollment_revocation_ack(
                host(2),
                &request,
                &enrollment_revocation_store(Some(snapshot))
            )
            .is_err()
        );
    }
}

#[test]
fn enrollment_revocation_ack_rejects_wrong_proof_bindings_and_epoch_boundaries() {
    let request = enrollment_revocation_request();
    assert!(
        authorize_host_enrollment_revocation_ack(
            host(2),
            &request,
            &enrollment_revocation_store(None)
        )
        .is_err()
    );
    assert!(
        authorize_host_enrollment_revocation_ack(
            host(9),
            &request,
            &enrollment_revocation_store(Some(enrollment_revocation_snapshot(
                HostEnrollmentRevocationFamilySnapshot::NoFamily
            )))
        )
        .is_err()
    );

    let mut invalid_snapshots = Vec::new();
    let mut wrong_host =
        enrollment_revocation_snapshot(HostEnrollmentRevocationFamilySnapshot::NoFamily);
    wrong_host.host_id = host(9);
    invalid_snapshots.push(wrong_host);
    let mut wrong_enrollment =
        enrollment_revocation_snapshot(HostEnrollmentRevocationFamilySnapshot::NoFamily);
    wrong_enrollment.enrollment_id = EnrollmentId::from_bytes([9; 16]).unwrap();
    invalid_snapshots.push(wrong_enrollment);
    let mut wrong_operation =
        enrollment_revocation_snapshot(HostEnrollmentRevocationFamilySnapshot::NoFamily);
    wrong_operation.operation_id = OperationId::from_bytes([9; 16]).unwrap();
    invalid_snapshots.push(wrong_operation);
    let mut unapproved =
        enrollment_revocation_snapshot(HostEnrollmentRevocationFamilySnapshot::NoFamily);
    unapproved.approved = false;
    invalid_snapshots.push(unapproved);
    let wrong_family_host =
        enrollment_revocation_snapshot(HostEnrollmentRevocationFamilySnapshot::RevokedFamily {
            host_authorization_id: host_authorization(3),
            host_id: host(9),
            host_account_id: account(1),
            account_id: account(1),
            family_host_access_epoch: 7,
            host_access_epoch: 12,
        });
    invalid_snapshots.push(wrong_family_host);
    invalid_snapshots.push(enrollment_revocation_snapshot(
        HostEnrollmentRevocationFamilySnapshot::RevokedFamily {
            host_authorization_id: host_authorization(3),
            host_id: host(2),
            host_account_id: account(1),
            account_id: account(9),
            family_host_access_epoch: 7,
            host_access_epoch: 12,
        },
    ));
    invalid_snapshots.push(enrollment_revocation_snapshot(
        HostEnrollmentRevocationFamilySnapshot::RevokedFamily {
            host_authorization_id: host_authorization(3),
            host_id: host(2),
            host_account_id: account(9),
            account_id: account(1),
            family_host_access_epoch: 7,
            host_access_epoch: 12,
        },
    ));
    for snapshot in invalid_snapshots {
        assert!(
            authorize_host_enrollment_revocation_ack(
                host(2),
                &request,
                &enrollment_revocation_store(Some(snapshot))
            )
            .is_err()
        );
    }

    for (family_epoch, host_epoch) in [
        (0, 12),
        (i64::MAX as u64 + 1, i64::MAX as u64),
        (7, 0),
        (7, i64::MAX as u64 + 1),
        (13, 12),
    ] {
        let snapshot =
            enrollment_revocation_snapshot(HostEnrollmentRevocationFamilySnapshot::RevokedFamily {
                host_authorization_id: host_authorization(3),
                host_id: host(2),
                host_account_id: account(1),
                account_id: account(1),
                family_host_access_epoch: family_epoch,
                host_access_epoch: host_epoch,
            });
        assert!(
            authorize_host_enrollment_revocation_ack(
                host(2),
                &request,
                &enrollment_revocation_store(Some(snapshot))
            )
            .is_err()
        );
    }
    let boundary =
        enrollment_revocation_snapshot(HostEnrollmentRevocationFamilySnapshot::RevokedFamily {
            host_authorization_id: host_authorization(3),
            host_id: host(2),
            host_account_id: account(1),
            account_id: account(1),
            family_host_access_epoch: 1,
            host_access_epoch: i64::MAX as u64,
        });
    assert!(
        authorize_host_enrollment_revocation_ack(
            host(2),
            &request,
            &enrollment_revocation_store(Some(boundary))
        )
        .is_ok()
    );
}

#[test]
fn consumer_issuance_and_window_proofs_keep_session_classes_separate() {
    let ordinary = principal(StoredPrincipal::OrdinaryAccount {
        account_id: account(1),
        session_id: BetterAuthSessionId::new("opaque-parent".to_owned().try_into().unwrap()),
    });
    let host = host_principal();
    let consumer = consumer_principal(false);
    assert!(authorize_http(HttpRoute::ConsumerAuthorizationIssue, Some(&ordinary), None).is_ok());
    for p in [&host, &consumer] {
        assert!(authorize_http(HttpRoute::ConsumerAuthorizationIssue, Some(p), None).is_err());
    }
    for route in [
        HttpRoute::ConsumerWindowChallenge,
        HttpRoute::ConsumerWindowRegister,
    ] {
        assert!(authorize_http(route, Some(&consumer), None).is_ok());
        for p in [&ordinary, &host] {
            assert!(authorize_http(route, Some(p), None).is_err());
        }
    }
    let r = resource();
    for route in [
        HttpRoute::PairingPending,
        HttpRoute::ChannelPending,
        HttpRoute::ChannelAdmission,
    ] {
        assert!(authorize_http(route, Some(&host), Some(&r)).is_ok());
        assert!(authorize_http(route, Some(&consumer), Some(&r)).is_err());
    }
    assert!(
        authorize_http(
            HttpRoute::ConsumerAuthorizationRevoke,
            Some(&host),
            Some(&r)
        )
        .is_err()
    );
    assert!(
        authorize_http(
            HttpRoute::ConsumerAuthorizationRevoke,
            Some(&consumer),
            Some(&r)
        )
        .is_err()
    );
    assert!(
        authorize_http(
            HttpRoute::ConsumerAuthorizationRevoke,
            Some(&consumer_principal(true)),
            Some(&r)
        )
        .is_ok()
    );
    assert!(
        authorize_http(
            HttpRoute::ConsumerAuthorizationRevoke,
            Some(&ordinary),
            Some(&r)
        )
        .is_ok()
    );
    let mut foreign = r;
    foreign.account_id = account(99);
    assert!(
        authorize_http(
            HttpRoute::ConsumerAuthorizationRevoke,
            Some(&ordinary),
            Some(&foreign)
        )
        .is_err()
    );
}

#[test]
fn channel_targets_use_canonical_camel_case_fields() {
    let uuid = "11111111-1111-4111-8111-111111111111";
    for terminal in [false, true] {
        let mut wire = serde_json::json!({
            "purpose": if terminal { "terminal" } else { "workspace" },
            "workspaceId": uuid,
            "workspaceEpoch": uuid
        });
        if terminal {
            for field in ["paneId", "sessionId", "sessionEpoch"] {
                wire[field] = serde_json::json!(uuid);
            }
        }
        let target: ChannelTarget = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(target).unwrap(), wire);
        for (camel, snake) in [
            ("workspaceId", "workspace_id"),
            ("workspaceEpoch", "workspace_epoch"),
            ("paneId", "pane_id"),
            ("sessionId", "session_id"),
            ("sessionEpoch", "session_epoch"),
        ] {
            let mut invalid = wire.clone();
            let object = invalid.as_object_mut().unwrap();
            if let Some(value) = object.remove(camel) {
                object.insert(snake.to_owned(), value);
                assert!(serde_json::from_value::<ChannelTarget>(invalid).is_err());
            }
        }
    }
}
#[test]
fn class_confusion_and_public_client_id_do_not_authorize() {
    let h = host_principal();
    let c = consumer_principal(false);
    let r = resource();
    assert!(authorize_http(HttpRoute::Inventory, Some(&h), None).is_err());
    assert!(authorize_http(HttpRoute::PairingCreate, Some(&h), Some(&r)).is_err());
    for route in [
        HttpRoute::Publication,
        HttpRoute::Heartbeat,
        HttpRoute::RuntimeGet,
        HttpRoute::RuntimeClaim,
        HttpRoute::HostAuthorizationRefresh,
        HttpRoute::HostAuthorizationExchange,
    ] {
        assert!(authorize_http(route, Some(&c), Some(&r)).is_err());
    }
    assert!(authorize_http(HttpRoute::Publication, None, Some(&r)).is_err());
    let ordinary = principal(StoredPrincipal::OrdinaryAccount {
        account_id: account(1),
        session_id: BetterAuthSessionId::new(
            AccountSessionId::try_from("session_nanoid-7".to_owned()).unwrap(),
        ),
    });
    assert!(
        authorize_http(
            HttpRoute::HostAuthorizationExchange,
            Some(&ordinary),
            Some(&r)
        )
        .is_err()
    );
    let fixtures: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/enrollment/wire.json"
    ))
    .unwrap();
    let init = fixtures[0]["value"].clone();
    assert!(serde_json::from_value::<EnrollmentInitiateParams>(init.clone()).is_ok());
    let mut forged = init;
    forged["class"] = serde_json::json!("H");
    assert!(serde_json::from_value::<EnrollmentInitiateParams>(forged).is_err());
    assert!(authorize_http(HttpRoute::EnrollmentInitiate, None, None).is_ok());
}

#[test]
fn initialization_requires_complete_committed_key_proof_without_duplicate_claims() {
    let fixtures: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/enrollment/wire.json"
    ))
    .unwrap();
    for fixture in fixtures {
        let accepted =
            serde_json::from_value::<EnrollmentInitiateParams>(fixture["value"].clone()).is_ok();
        assert_eq!(
            Some(accepted),
            fixture["accepted"].as_bool(),
            "{}",
            fixture["name"]
        );
    }
    // This boundary validates bounded wire encodings. Canonical crypto must
    // decode the descriptor and verify the signature before authority effects.
}
#[test]
fn host_token_context_uses_remote_account_uuid_and_bounded_canonical_bytes() {
    let fixtures: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/enrollment/token-context.json"
    ))
    .unwrap();
    for fixture in fixtures {
        let accepted =
            serde_json::from_value::<HostEnrollmentTokenContext>(fixture["value"].clone()).is_ok();
        assert_eq!(
            Some(accepted),
            fixture["accepted"].as_bool(),
            "{}",
            fixture["name"]
        );
    }
}
#[test]
fn immutable_ownership_and_account_management_are_required() {
    let h = host_principal();
    let c = consumer_principal(false);
    let mut r = resource();
    assert!(authorize_http(HttpRoute::Publication, Some(&h), Some(&r)).is_ok());
    assert!(authorize_http(HttpRoute::ChannelTicket, Some(&c), Some(&r)).is_ok());
    r.host_id = host(42);
    assert!(authorize_http(HttpRoute::Publication, Some(&h), Some(&r)).is_err());
    r = resource();
    r.account_id = account(42);
    assert!(authorize_http(HttpRoute::ChannelTicket, Some(&h), Some(&r)).is_err());
    assert!(authorize_http(HttpRoute::ChannelTicket, Some(&c), Some(&r)).is_err());
    r = resource();
    r.consumer_authorization_id = Some(consumer(42));
    assert!(authorize_http(HttpRoute::ChannelTicket, Some(&c), Some(&r)).is_err());
    assert!(authorize_http(HttpRoute::HostRevoke, Some(&h), Some(&resource())).is_ok());
    let mut other_host = resource();
    other_host.host_id = host(42);
    assert!(authorize_http(HttpRoute::HostRevoke, Some(&h), Some(&other_host)).is_err());
    let mut other_family = resource();
    other_family.host_authorization_id = HostAuthorizationId::from_bytes([42; 16]).unwrap();
    assert!(authorize_http(HttpRoute::HostRevoke, Some(&h), Some(&other_family)).is_err());
    assert!(authorize_http(HttpRoute::HostRevoke, Some(&c), Some(&resource())).is_err());
    assert!(
        authorize_http(
            HttpRoute::HostRevoke,
            Some(&consumer_principal(true)),
            Some(&resource())
        )
        .is_ok()
    );
}
#[test]
fn enrollment_requires_exact_approved_session_binding() {
    let session = EnrollmentBootstrapSessionId::from_bytes([12; 16]).unwrap();
    let enrollment = EnrollmentId::from_bytes([13; 16]).unwrap();
    let p = principal(StoredPrincipal::EnrollmentBootstrap {
        account_id: account(1),
        host_id: host(2),
        enrollment_id: enrollment,
        bootstrap_session_id: session,
    });
    let mut r = resource();
    r.enrollment_id = Some(enrollment);
    r.bootstrap_session_id = Some(session);
    assert!(authorize_http(HttpRoute::HostAuthorizationExchange, Some(&p), Some(&r)).is_ok());
    r.bootstrap_session_id = Some(EnrollmentBootstrapSessionId::from_bytes([14; 16]).unwrap());
    assert!(authorize_http(HttpRoute::HostAuthorizationExchange, Some(&p), Some(&r)).is_err());
}
#[test]
fn publication_rejects_plaintext_stale_runtime_and_sequence() {
    let p = publication();
    let mut wire = serde_json::to_value(&p).unwrap();
    for key in ["name", "root", "title", "payload", "env", "tokenUrl"] {
        wire[key] = serde_json::json!("private");
        assert!(serde_json::from_value::<PublicationParams>(wire.clone()).is_err());
        wire.as_object_mut().unwrap().remove(key);
    }
    let mut current = PublicationResult {
        runtime: runtime(),
        publication_seq: DecimalU64(8),
    };
    assert!(validate_publication(&p, &current).is_ok());
    current.publication_seq = DecimalU64(9);
    assert_eq!(
        validate_publication(&p, &current).unwrap_err().code(),
        ErrorCode::RevisionConflict
    );
    current.runtime.runtime_generation = DecimalU64(10);
    assert_eq!(
        validate_publication(&p, &current).unwrap_err().code(),
        ErrorCode::StaleEpoch
    );
    let duplicate = vec![p.workspaces.as_slice()[0].clone(); 2];
    assert!(PublicationWorkspaces::try_from(duplicate).is_err());
}
#[test]
fn dynamic_membership_checks_actual_ids_and_all_epochs() {
    let p = publication();
    let w = &p.workspaces.as_slice()[0];
    let t = &w.terminals.as_slice()[0];
    let mut req = ChannelCreateParams {
        operation_id: OperationId::from_bytes([44; 16]).unwrap(),
        grant_id: GrantId::from_bytes([15; 16]).unwrap(),
        grant_revision: DecimalU64(1),
        runtime: runtime(),
        target: ChannelTarget::Terminal {
            workspace_id: w.workspace_id,
            workspace_epoch: w.workspace_epoch,
            pane_id: t.pane_id,
            session_id: t.session_id,
            session_epoch: t.session_epoch,
        },
        window_identity_id: None,
    };
    assert!(validate_published_target(&req, &p).is_ok());
    if let ChannelTarget::Terminal {
        ref mut session_epoch,
        ..
    } = req.target
    {
        *session_epoch = SessionEpoch::from_bytes([99; 16]).unwrap();
    }
    assert_eq!(
        validate_published_target(&req, &p).unwrap_err().code(),
        ErrorCode::WorkspaceUnshared
    );
    req.target = ChannelTarget::Workspace {
        workspace_id: w.workspace_id,
        workspace_epoch: w.workspace_epoch,
    };
    let mut empty = p.clone();
    empty.workspaces = vec![PublishedWorkspace {
        workspace_id: w.workspace_id,
        workspace_epoch: w.workspace_epoch,
        terminals: vec![].try_into().unwrap(),
    }]
    .try_into()
    .unwrap();
    assert!(validate_published_target(&req, &empty).is_ok());
    req.runtime.runtime_generation = DecimalU64(10);
    assert!(validate_published_target(&req, &empty).is_err());
}
#[test]
fn two_windows_have_independent_keys_on_one_opaque_account_session() {
    let account_session = AccountSessionId::try_from("not-a-uuid-session".to_owned()).unwrap();
    let a = ConsumerWindow {
        window_identity_id: WindowIdentityId::from_bytes([1; 16]).unwrap(),
        identity: identity_wire("aa"),
    };
    let b = ConsumerWindow {
        window_identity_id: WindowIdentityId::from_bytes([2; 16]).unwrap(),
        identity: identity_wire("bb"),
    };
    assert_ne!(a, b);
    assert_eq!(account_session.as_str(), "not-a-uuid-session");
}
fn frame() -> Vec<u8> {
    serde_json::to_vec(&WssAdmissionFrame {
        channel_id: ChannelId::from_bytes([16; 16]).unwrap(),
        ticket: RelayTicket::try_from("secret-ticket".to_owned()).unwrap(),
    })
    .unwrap()
}
struct TicketStore {
    consumed: bool,
    calls: usize,
}
impl OneUseTicketAuthority for TicketStore {
    fn verify_and_consume(&mut self, _: &WssAdmissionFrame) -> Result<(), RemoteError> {
        self.calls += 1;
        if self.consumed {
            return Err(RemoteError::new(
                ErrorCode::AuthRequired,
                false,
                Effect::None,
                ErrorDetails::empty(),
                None,
            )
            .unwrap());
        }
        self.consumed = true;
        Ok(())
    }
}
#[test]
fn wss_payload_requires_first_frame_and_one_use_authority() {
    let start = Instant::now();
    let mut a = WssAdmission::new(start);
    let mut store = TicketStore {
        consumed: false,
        calls: 0,
    };
    assert!(a.authorize_payload().is_err());
    a.admit(&frame(), &mut store, || start).unwrap();
    assert!(a.authorize_payload().is_ok());
    assert!(a.admit(&frame(), &mut store, || start).is_err());
    assert!(a.authorize_payload().is_err());
    let mut b = WssAdmission::new(start);
    assert!(b.admit(&frame(), &mut store, || start).is_err());
    assert!(b.authorize_payload().is_err());
}
#[test]
fn wss_deadline_is_checked_before_and_after_verification_and_at_boundary() {
    let start = Instant::now();
    let deadline = start + Duration::from_millis(WSS_ADMISSION_TIMEOUT_MS);
    let mut store = TicketStore {
        consumed: false,
        calls: 0,
    };
    let mut a = WssAdmission::new(start);
    assert_eq!(
        a.admit(&frame(), &mut store, || deadline)
            .unwrap_err()
            .code(),
        ErrorCode::DeadlineExceeded
    );
    assert_eq!(store.calls, 0);
    let mut b = WssAdmission::new(start);
    let calls = Cell::new(0);
    assert_eq!(
        b.admit(&frame(), &mut store, || {
            let n = calls.get();
            calls.set(n + 1);
            if n < 2 { start } else { deadline }
        })
        .unwrap_err()
        .code(),
        ErrorCode::DeadlineExceeded
    );
    assert_eq!(store.calls, 1);
    assert!(b.authorize_payload().is_err());
}
#[test]
fn wss_oversize_payload_and_url_fallback_fail_before_verification() {
    let start = Instant::now();
    let mut store = TicketStore {
        consumed: false,
        calls: 0,
    };
    for bytes in [
        vec![b' '; WSS_ADMISSION_MAX_BYTES + 1],
        br#"{"payload":"route-me"}"#.to_vec(),
        br#"{"ticketUrl":"wss://relay/?ticket=secret"}"#.to_vec(),
    ] {
        let mut a = WssAdmission::new(start);
        assert!(a.admit(&bytes, &mut store, || start).is_err());
        assert!(a.authorize_payload().is_err());
    }
    assert_eq!(store.calls, 0);
}
#[test]
fn secret_encodings_are_bounded_and_redacted() {
    let ticket = RelayTicket::try_from("secret-ticket".to_owned()).unwrap();
    assert!(!format!("{ticket:?}").contains("secret-ticket"));
    for s in [
        "https://relay/#token",
        "a?token=x",
        "a&token=x",
        "secret-ticket\n",
        "secret-ticket\u{85}",
        "",
    ] {
        assert!(RelayTicket::try_from(s.to_owned()).is_err());
    }
    assert!(PublicKeyHex::try_from("AA".repeat(32)).is_err());
    assert!(SignatureHex::try_from("aa".repeat(63)).is_err());
    assert!(CanonicalCryptoCborHex::try_from("a".to_owned()).is_err());
}

#[test]
fn registration_checks_immutable_host_key_and_authorization() {
    let p = host_principal();
    let mut r = resource();
    let mut request = HostRegisterParams {
        host_id: r.host_id,
        identity: r.host_identity.clone(),
    };
    assert!(validate_host_registration(&request, &p, &r).is_ok());
    request.identity = identity_wire("cd");
    assert!(validate_host_registration(&request, &p, &r).is_err());
    r.host_authorization_id = HostAuthorizationId::from_bytes([99; 16]).unwrap();
    assert!(authorize_http(HttpRoute::Publication, Some(&p), Some(&r)).is_err());
}

#[test]
fn publication_rejects_cross_workspace_identity_aliases_and_schema_has_limits() {
    let p = publication();
    let mut second = p.workspaces.as_slice()[0].clone();
    second.workspace_id = WorkspaceId::from_bytes([98; 16]).unwrap();
    assert!(
        PublicationWorkspaces::try_from(vec![p.workspaces.as_slice()[0].clone(), second]).is_err()
    );
    let schema = serde_json::to_value(schemars::schema_for!(PublicationWorkspaces)).unwrap();
    assert_eq!(schema["maxItems"], 256);
    let session = BetterAuthSessionId::new(
        AccountSessionId::try_from("session_nanoid-7".to_owned()).unwrap(),
    );
    assert_eq!(session.as_str(), "session_nanoid-7");
}

#[test]
fn runtime_lookup_requires_exact_host_authority() {
    let h = host_principal();
    let c = consumer_principal(false);
    let r = resource();
    let route = HttpRoute::RuntimeGet;
    assert_eq!(route.contract().method, HttpMethod::Get);
    assert_eq!(route.contract().path, "/hosts/{hostId}/runtime");
    assert_eq!(route.contract().surface, HttpSurface::HostAccess);
    assert!(authorize_http(route, Some(&h), Some(&r)).is_ok());
    assert!(authorize_http(route, Some(&c), Some(&r)).is_err());
    assert!(authorize_http(route, None, Some(&r)).is_err());
    assert!(authorize_http(route, Some(&h), None).is_err());
    let mut other = r.clone();
    other.host_id = host(99);
    assert!(authorize_http(route, Some(&h), Some(&other)).is_err());
    let mut other_family = r;
    other_family.host_authorization_id = HostAuthorizationId::from_bytes([99; 16]).unwrap();
    assert!(authorize_http(route, Some(&h), Some(&other_family)).is_err());
}
