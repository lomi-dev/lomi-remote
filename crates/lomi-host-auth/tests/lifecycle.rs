use lomi_host_auth::{Config, Error, HostAuth, RetainedRevocationAcknowledgement, Status};
use lomi_platform::secrets::{
    self, ProviderKind, ProviderStatus, SecretBundle, SecretStorage, StorageState,
};
use lomi_remote_crypto::{
    HostEnrollmentChallengeContext, prepare_host_enrollment_challenge, verify_host_key_initiation,
};
use lomi_remote_protocol::{ipc::IpcProfileId, *};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
enum Fault {
    None,
    Before,
    Uncertain,
    UncertainOld,
}
struct Memory {
    bytes: Option<Zeroizing<Vec<u8>>>,
    fault: Fault,
    writes: usize,
    state: StorageState,
}
impl Default for Memory {
    fn default() -> Self {
        Self {
            bytes: None,
            fault: Fault::None,
            writes: 0,
            state: StorageState::Available,
        }
    }
}
impl SecretStorage for Memory {
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            kind: Some(ProviderKind::ProtectedFile),
            state: self.state,
        }
    }
    fn load(&self) -> Result<Option<SecretBundle>, secrets::Error> {
        self.bytes
            .as_ref()
            .map(|b| SecretBundle::new(b.to_vec()))
            .transpose()
    }
    fn replace(&mut self, b: &SecretBundle) -> Result<(), secrets::Error> {
        self.writes += 1;
        if matches!(self.fault, Fault::Before) {
            self.fault = Fault::None;
            return Err(secrets::Error::Io);
        }
        if matches!(self.fault, Fault::UncertainOld) {
            self.fault = Fault::None;
            return Err(secrets::Error::CommitUncertain);
        }
        self.bytes = Some(Zeroizing::new(b.expose().to_vec()));
        if matches!(self.fault, Fault::Uncertain) {
            self.fault = Fault::None;
            return Err(secrets::Error::CommitUncertain);
        }
        Ok(())
    }
}
fn cfg() -> Config {
    Config::new(
        HostId::from_bytes([1; 16]).unwrap(),
        IpcProfileId::from_bytes([2; 16]).unwrap(),
        "https://auth.example".into(),
        "host".to_owned().try_into().unwrap(),
    )
    .unwrap()
}
fn stored_time(s: &Memory) -> u64 {
    #[derive(serde::Deserialize)]
    struct Floor {
        observed_at: u64,
    }
    s.bytes
        .as_ref()
        .and_then(|bytes| serde_json::from_slice::<Floor>(bytes).ok())
        .map_or(0, |f| f.observed_at)
}
fn open(s: &mut Memory) -> HostAuth<'_, Memory> {
    let now = stored_time(s);
    HostAuth::open(s, cfg(), now).unwrap()
}
fn rotation(s: &mut Memory) -> Result<HostAuthorizationRefreshParams, Error> {
    let now = stored_time(s);
    open(s).rotation_request(now)
}

fn initiation() -> EnrollmentInitiateResult {
    EnrollmentInitiateResult {
        enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
        device_code: "device_secret".to_owned().try_into().unwrap(),
        user_code: "user_secret".to_owned().try_into().unwrap(),
        expires_in_seconds: DecimalU64(600),
        poll_interval_seconds: DecimalU64(5),
    }
}
fn approval(s: &mut Memory) {
    approval_for(s, [4; 16], 100).unwrap();
}
fn approval_for(s: &mut Memory, account: [u8; 16], start: u64) -> Result<(), Error> {
    approval_for_ids(s, account, start, [3; 16], [6; 16])
}
fn approval_for_ids(
    s: &mut Memory,
    account: [u8; 16],
    start: u64,
    enrollment_id: [u8; 16],
    operation_id: [u8; 16],
) -> Result<(), Error> {
    approve_with_challenge_expiry(
        s,
        account,
        start,
        enrollment_id,
        operation_id,
        start + 500,
        start + 1,
    )
    .map(|_| ())
}
fn challenge_with_expiry(
    s: &mut Memory,
    account: [u8; 16],
    start: u64,
    enrollment_id: [u8; 16],
    operation_id: [u8; 16],
    challenge_expires_at: u64,
) -> lomi_remote_crypto::EnrollmentChallenge {
    let initial = open(s).init_request().unwrap();
    let committed = verify_host_key_initiation(&initial).unwrap();
    let pin = committed.descriptor.commitment().unwrap();
    let mut initiated = initiation();
    initiated.enrollment_id = EnrollmentId::from_bytes(enrollment_id).unwrap();
    open(s).accept_initiation(initiated, start).unwrap();
    let challenge = prepare_host_enrollment_challenge(
        &committed,
        &pin,
        account,
        &HostEnrollmentChallengeContext {
            enrollment_id,
            bootstrap_session_id: [5; 16],
            operation_id,
            nonce: [7; 32],
            audience: cfg().exchange_audience(),
            expires_at: DecimalU64(challenge_expires_at),
        },
    )
    .unwrap();
    challenge
}
fn accept_challenge(
    s: &mut Memory,
    account: [u8; 16],
    challenge: &lomi_remote_crypto::EnrollmentChallenge,
    approval_at: u64,
) -> Result<(), Error> {
    let context = HostEnrollmentTokenContext {
        account_id: AccountId::from_bytes(account).unwrap(),
        challenge: hex(&challenge.canonical().unwrap()).try_into().unwrap(),
    };
    open(s).accept_tls_approval(
        "https://auth.example",
        context,
        "bootstrap_secret".to_owned().try_into().unwrap(),
        approval_at,
    )
}
fn approve_with_challenge_expiry(
    s: &mut Memory,
    account: [u8; 16],
    start: u64,
    enrollment_id: [u8; 16],
    operation_id: [u8; 16],
    challenge_expires_at: u64,
    approval_at: u64,
) -> Result<lomi_remote_crypto::EnrollmentChallenge, Error> {
    let challenge = challenge_with_expiry(
        s,
        account,
        start,
        enrollment_id,
        operation_id,
        challenge_expires_at,
    );
    accept_challenge(s, account, &challenge, approval_at)?;
    Ok(challenge)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn approval_keeps_server_challenge_expiry_independent_of_local_enrollment_ttl() {
    let request_started = 100;
    let local_expiry = request_started + initiation().expires_in_seconds.0;
    let server_issued = request_started + 1;
    let server_expiry = server_issued + initiation().expires_in_seconds.0;
    assert_eq!((local_expiry, server_expiry), (700, 701));

    for challenge_expiry in [600, local_expiry, server_expiry] {
        let mut storage = Memory::default();
        open(&mut storage).initialize().unwrap();
        let challenge = approve_with_challenge_expiry(
            &mut storage,
            [4; 16],
            request_started,
            [3; 16],
            [6; 16],
            challenge_expiry,
            request_started + 5,
        )
        .unwrap();
        assert_eq!(open(&mut storage).status(), Status::Approved);

        let deadline = local_expiry.min(challenge_expiry);
        open(&mut storage).prepare_exchange(deadline - 1).unwrap();
        let request = open(&mut storage).exchange_request(deadline - 1).unwrap();
        assert_eq!(
            request.proof.canonical_cbor.expose_wire(),
            hex(&challenge.canonical().unwrap())
        );

        let writes = storage.writes;
        let mut reopened = HostAuth::open(&mut storage, cfg(), deadline).unwrap();
        assert_eq!(reopened.prepare_exchange(deadline), Err(Error::Expired));
        assert_eq!(reopened.exchange_request(deadline), Err(Error::Expired));
        assert_eq!(
            reopened.accept_exchange(response(request.operation_id, 1), deadline),
            Err(Error::Expired)
        );
        assert_eq!(reopened.status(), Status::ExchangePrepared);
        drop(reopened);
        assert_eq!(storage.writes, writes);
    }
}

#[test]
fn approval_and_preparation_deadlines_are_exclusive_without_state_advance() {
    let request_started = 100;
    let enrollment_expiry = request_started + initiation().expires_in_seconds.0;
    for challenge_expiry in [600, enrollment_expiry, enrollment_expiry + 1] {
        let deadline = enrollment_expiry.min(challenge_expiry);

        let mut approval_storage = Memory::default();
        open(&mut approval_storage).initialize().unwrap();
        let challenge = challenge_with_expiry(
            &mut approval_storage,
            [4; 16],
            request_started,
            [3; 16],
            [6; 16],
            challenge_expiry,
        );
        let before = approval_storage.writes;
        assert_eq!(
            accept_challenge(&mut approval_storage, [4; 16], &challenge, deadline),
            Err(Error::Expired)
        );
        assert_eq!(
            open(&mut approval_storage).status(),
            Status::AwaitingApproval
        );
        assert_eq!(approval_storage.writes, before);

        // The failed call did not persist its later observation, so a fresh
        // owner can still accept immediately before the exclusive deadline.
        accept_challenge(&mut approval_storage, [4; 16], &challenge, deadline - 1).unwrap();
        assert_eq!(open(&mut approval_storage).status(), Status::Approved);

        let mut approved_storage = Memory::default();
        open(&mut approved_storage).initialize().unwrap();
        let approved_challenge = approve_with_challenge_expiry(
            &mut approved_storage,
            [4; 16],
            request_started,
            [3; 16],
            [6; 16],
            challenge_expiry,
            request_started + 1,
        )
        .unwrap();
        let before = approved_storage.writes;
        assert_eq!(
            open(&mut approved_storage).prepare_exchange(deadline),
            Err(Error::Expired)
        );
        assert_eq!(open(&mut approved_storage).status(), Status::Approved);
        assert_eq!(approved_storage.writes, before);
        drop(open(&mut approved_storage));
        let mut reopened = HostAuth::open(&mut approved_storage, cfg(), deadline - 1).unwrap();
        reopened.prepare_exchange(deadline - 1).unwrap();
        let request = reopened.exchange_request(deadline - 1).unwrap();
        assert_eq!(
            request.proof.canonical_cbor.expose_wire(),
            hex(&approved_challenge.canonical().unwrap())
        );
        drop(reopened);
        assert_eq!(
            open(&mut approved_storage).status(),
            Status::ExchangePrepared
        );
    }
}

#[test]
fn exchange_retries_keep_the_original_three_hundred_second_intent() {
    let mut storage = Memory::default();
    open(&mut storage).initialize().unwrap();
    approve_with_challenge_expiry(&mut storage, [4; 16], 100, [3; 16], [6; 16], 701, 101).unwrap();
    open(&mut storage).prepare_exchange(300).unwrap();
    let original = open(&mut storage).exchange_request(300).unwrap();

    let writes = storage.writes;
    let mut reopened = HostAuth::open(&mut storage, cfg(), 599).unwrap();
    reopened.prepare_exchange(599).unwrap();
    assert_eq!(reopened.exchange_request(599).unwrap(), original);
    assert_eq!(
        reopened.accept_exchange(response(original.operation_id, 1), 600),
        Err(Error::Expired)
    );
    assert_eq!(reopened.exchange_request(600), Err(Error::Expired));
    assert_eq!(reopened.status(), Status::ExchangePrepared);
    drop(reopened);
    assert_eq!(storage.writes, writes);
}

#[test]
fn prepared_exchange_must_precede_both_persisted_deadlines() {
    let mut challenge_expired = Memory::default();
    prepared(&mut challenge_expired);
    let mut value: serde_json::Value =
        serde_json::from_slice(challenge_expired.bytes.as_ref().unwrap().as_slice()).unwrap();
    value["observed_at"] = 600.into();
    value["lifecycle"]["prepared_at"] = 600.into();
    challenge_expired.bytes = Some(Zeroizing::new(serde_json::to_vec(&value).unwrap()));
    assert!(matches!(
        HostAuth::open(&mut challenge_expired, cfg(), 600),
        Err(Error::InvalidBundle)
    ));

    let mut enrollment_expired = Memory::default();
    prepared(&mut enrollment_expired);
    let mut value: serde_json::Value =
        serde_json::from_slice(enrollment_expired.bytes.as_ref().unwrap().as_slice()).unwrap();
    value["lifecycle"]["enrollment"]["expires"] = 102.into();
    enrollment_expired.bytes = Some(Zeroizing::new(serde_json::to_vec(&value).unwrap()));
    assert!(matches!(
        HostAuth::open(&mut enrollment_expired, cfg(), 102),
        Err(Error::InvalidBundle)
    ));
}

fn response(op: OperationId, n: u8) -> HostAuthorizationResult {
    HostAuthorizationResult {
        account_id: AccountId::from_bytes([4; 16]).unwrap(),
        host_id: HostId::from_bytes([1; 16]).unwrap(),
        host_authorization_id: HostAuthorizationId::from_bytes([8; 16]).unwrap(),
        access: format!("access_secret_{n}").try_into().unwrap(),
        refresh: format!("refresh_secret_{n}").try_into().unwrap(),
        rotation_id: op,
        expires_in_seconds: DecimalU64(300),
    }
}
fn prepared(s: &mut Memory) {
    open(s).initialize().unwrap();
    approval(s);
    open(s).prepare_exchange(102).unwrap();
}
fn unconfirmed(s: &mut Memory) {
    prepared(s);
    let op = open(s).exchange_request(102).unwrap().operation_id;
    open(s).accept_exchange(response(op, 1), 103).unwrap();
}
fn ready(s: &mut Memory) {
    unconfirmed(s);
    open(s)
        .confirm_registration(HostRegisterResult {
            host_id: HostId::from_bytes([1; 16]).unwrap(),
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
}

#[test]
fn restart_at_every_stage_and_exact_retries() {
    let mut s = Memory::default();
    assert_eq!(open(&mut s).status(), Status::Empty);
    open(&mut s).initialize().unwrap();
    assert_eq!(open(&mut s).status(), Status::PendingInit);
    let init = open(&mut s).init_request().unwrap();
    assert_eq!(init, open(&mut s).init_request().unwrap());
    approval(&mut s);
    assert_eq!(open(&mut s).status(), Status::Approved);
    open(&mut s).prepare_exchange(102).unwrap();
    let exchange = open(&mut s).exchange_request(102).unwrap();
    open(&mut s).prepare_exchange(103).unwrap();
    assert_eq!(exchange, open(&mut s).exchange_request(103).unwrap());
    let issued = response(exchange.operation_id, 1);
    open(&mut s).accept_exchange(issued.clone(), 104).unwrap();
    assert_eq!(open(&mut s).status(), Status::Unconfirmed);
    assert!(open(&mut s).access_credential(105).is_err());
    assert!(open(&mut s).prepare_rotation(105).is_err());
    open(&mut s).accept_exchange(issued, 105).unwrap();
    let (_, registration) = open(&mut s).registration_request(105).unwrap();
    let finalized = lomi_remote_crypto::SignedBundle::from_wire(&registration.identity).unwrap();
    let committed = lomi_remote_crypto::verify_host_key_initiation(&init).unwrap();
    let account = finalized.bundle.account_id;
    assert_eq!(finalized.bundle.subject_id, registration.host_id.to_bytes());
    lomi_remote_crypto::verify_registered_host_identity(
        &committed,
        &committed.descriptor.commitment().unwrap(),
        account,
        &registration.identity,
    )
    .unwrap();
    open(&mut s)
        .confirm_registration(HostRegisterResult {
            host_id: HostId::from_bytes([1; 16]).unwrap(),
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
    assert_eq!(open(&mut s).status(), Status::Ready);
    open(&mut s).access_credential(105).unwrap();
    open(&mut s).prepare_rotation(105).unwrap();
    assert_eq!(open(&mut s).status(), Status::Rotating);
    assert!(open(&mut s).access_credential(105).is_err());
    let request = rotation(&mut s).unwrap();
    open(&mut s).prepare_rotation(105).unwrap();
    assert_eq!(request, rotation(&mut s).unwrap());
    let rotated = response(request.rotation_id, 2);
    open(&mut s).accept_rotation(rotated.clone(), 106).unwrap();
    assert_eq!(open(&mut s).status(), Status::Ready);
    open(&mut s).accept_rotation(rotated, 107).unwrap();
    assert!(open(&mut s).access_credential(107).unwrap().expose_wire() == "access_secret_2");
    assert_eq!(open(&mut s).access_credential(406), Err(Error::Expired));
    // Bootstrap/device material is erased from the committed Ready bundle.
    let b = std::str::from_utf8(s.bytes.as_ref().unwrap()).unwrap();
    assert!(!b.contains("bootstrap_secret"));
    assert!(!b.contains("device_secret"));
}
#[test]
fn failure_before_publication_preserves_each_old_state() {
    let mut s = Memory {
        fault: Fault::Before,
        ..Memory::default()
    };
    assert!(open(&mut s).initialize().is_err());
    assert_eq!(open(&mut s).status(), Status::Empty);
    prepared(&mut s);
    let op = open(&mut s).exchange_request(102).unwrap().operation_id;
    s.fault = Fault::Before;
    assert!(open(&mut s).accept_exchange(response(op, 1), 103).is_err());
    assert_eq!(open(&mut s).status(), Status::ExchangePrepared);
    open(&mut s).accept_exchange(response(op, 1), 103).unwrap();
    s.fault = Fault::Before;
    assert!(
        open(&mut s)
            .confirm_registration(HostRegisterResult {
                host_id: HostId::from_bytes([1; 16]).unwrap(),
                host_access_epoch: DecimalU64(12)
            })
            .is_err()
    );
    assert_eq!(open(&mut s).status(), Status::Unconfirmed);
    open(&mut s)
        .confirm_registration(HostRegisterResult {
            host_id: HostId::from_bytes([1; 16]).unwrap(),
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
    s.fault = Fault::Before;
    assert!(open(&mut s).prepare_rotation(105).is_err());
    assert_eq!(open(&mut s).status(), Status::Ready);
    open(&mut s).prepare_rotation(104).unwrap();
    let req = rotation(&mut s).unwrap();
    s.fault = Fault::Before;
    assert!(
        open(&mut s)
            .accept_rotation(response(req.rotation_id, 2), 104)
            .is_err()
    );
    assert_eq!(rotation(&mut s).unwrap(), req);
}
#[test]
fn uncertain_publication_seals_instance_and_reopen_inspects_published_state() {
    for stage in 0..4 {
        let mut s = Memory::default();
        match stage {
            0 => {}
            1 => prepared(&mut s),
            2 => unconfirmed(&mut s),
            _ => ready(&mut s),
        };
        s.fault = Fault::Uncertain;
        let mut auth = open(&mut s);
        let result = match stage {
            0 => auth.initialize(),
            1 => {
                let op = auth.exchange_request(102).unwrap().operation_id;
                auth.accept_exchange(response(op, 1), 103)
            }
            2 => auth.confirm_registration(HostRegisterResult {
                host_id: HostId::from_bytes([1; 16]).unwrap(),
                host_access_epoch: DecimalU64(12),
            }),
            _ => auth.prepare_rotation(105),
        };
        assert_eq!(result, Err(Error::Storage(secrets::Error::CommitUncertain)));
        assert_eq!(auth.status(), Status::Sealed);
        assert_eq!(auth.initialize(), Err(Error::Sealed));
        assert_eq!(auth.prepare_rotation(105), Err(Error::Sealed));
        assert_eq!(auth.access_credential(104), Err(Error::Sealed));
        drop(auth);
        assert_eq!(
            open(&mut s).status(),
            [
                Status::PendingInit,
                Status::Unconfirmed,
                Status::Ready,
                Status::Rotating
            ][stage]
        );
    }
    let mut s = Memory::default();
    ready(&mut s);
    open(&mut s).prepare_rotation(104).unwrap();
    let req = rotation(&mut s).unwrap();
    s.fault = Fault::Uncertain;
    let mut a = open(&mut s);
    assert_eq!(
        a.accept_rotation(response(req.rotation_id, 2), 105),
        Err(Error::Storage(secrets::Error::CommitUncertain))
    );
    assert_eq!(a.status(), Status::Sealed);
    drop(a);
    assert!(open(&mut s).access_credential(106).unwrap().expose_wire() == "access_secret_2");
}
#[test]
fn wrong_response_bindings_rejected_without_write() {
    let mut s = Memory::default();
    prepared(&mut s);
    let op = open(&mut s).exchange_request(102).unwrap().operation_id;
    for field in 0..4 {
        let mut v = response(op, 1);
        match field {
            0 => v.account_id = AccountId::from_bytes([9; 16]).unwrap(),
            1 => v.host_id = HostId::from_bytes([9; 16]).unwrap(),
            2 => v.rotation_id = OperationId::from_bytes([9; 16]).unwrap(),
            _ => v.expires_in_seconds = DecimalU64(301),
        };
        let writes = s.writes;
        assert!(open(&mut s).accept_exchange(v, 103).is_err());
        assert_eq!(s.writes, writes);
    }
    open(&mut s).accept_exchange(response(op, 1), 103).unwrap();
    open(&mut s)
        .confirm_registration(HostRegisterResult {
            host_id: HostId::from_bytes([1; 16]).unwrap(),
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
    open(&mut s).prepare_rotation(104).unwrap();
    let req = rotation(&mut s).unwrap();
    let mut wrong = response(req.rotation_id, 2);
    wrong.host_authorization_id = HostAuthorizationId::from_bytes([9; 16]).unwrap();
    assert!(open(&mut s).accept_rotation(wrong, 104).is_err());
    assert_eq!(req, rotation(&mut s).unwrap());
}
#[test]
fn corrupt_unknown_profile_and_provider_fail_closed() {
    let mut s = Memory::default();
    open(&mut s).initialize().unwrap();
    let other = Config::new(
        HostId::from_bytes([1; 16]).unwrap(),
        IpcProfileId::from_bytes([9; 16]).unwrap(),
        "https://auth.example".into(),
        "host".to_owned().try_into().unwrap(),
    )
    .unwrap();
    assert!(HostAuth::open(&mut s, other, 10000).is_err());
    let saved = s.bytes.as_ref().unwrap().clone();
    for bytes in [
        b"{".to_vec(),
        b"{}".to_vec(),
        saved[..saved.len() - 1].to_vec(),
        {
            let mut v = saved.to_vec();
            v.splice(1..1, b"\"unknown\":1,".iter().copied());
            v
        },
    ] {
        s.bytes = Some(Zeroizing::new(bytes));
        assert!(HostAuth::open(&mut s, cfg(), 10000).is_err());
    }
    s.bytes = Some(saved);
    for state in [
        StorageState::Locked,
        StorageState::Unconfigured,
        StorageState::Unavailable,
    ] {
        s.state = state;
        assert!(HostAuth::open(&mut s, cfg(), 10000).is_err());
    }
}
#[test]
fn redacted_debug_and_closed_errors() {
    let mut s = Memory::default();
    unconfirmed(&mut s);
    let debug = format!("{:?}", open(&mut s));
    assert_eq!(debug, "HostAuth { status: Unconfirmed }");
    for secret in [
        "device_secret",
        "user_secret",
        "bootstrap_secret",
        "access_secret",
        "refresh_secret",
    ] {
        assert!(!debug.contains(secret));
        assert!(!format!("{:?}", Error::InvalidBundle).contains(secret));
    }
    assert!(SecretBundle::new(vec![1; 32769]).is_err());
}

#[test]
fn pending_transition_failures_and_approval_bindings() {
    let mut s = Memory::default();
    open(&mut s).initialize().unwrap();
    let initial = open(&mut s).init_request().unwrap();
    let committed = verify_host_key_initiation(&initial).unwrap();
    let pin = committed.descriptor.commitment().unwrap();
    s.fault = Fault::Before;
    assert!(open(&mut s).accept_initiation(initiation(), 100).is_err());
    assert_eq!(open(&mut s).status(), Status::PendingInit);
    open(&mut s).accept_initiation(initiation(), 100).unwrap();
    let make_context = |account, host, enrollment, audience: String| {
        let mut c = prepare_host_enrollment_challenge(
            &committed,
            &pin,
            account,
            &HostEnrollmentChallengeContext {
                enrollment_id: enrollment,
                bootstrap_session_id: [5; 16],
                operation_id: [6; 16],
                nonce: [7; 32],
                audience,
                expires_at: DecimalU64(600),
            },
        )
        .unwrap();
        c.host_id = host;
        HostEnrollmentTokenContext {
            account_id: AccountId::from_bytes([4; 16]).unwrap(),
            challenge: hex(&c.canonical().unwrap()).try_into().unwrap(),
        }
    };
    let valid = make_context([4; 16], [1; 16], [3; 16], cfg().exchange_audience());
    for bad in [
        make_context([9; 16], [1; 16], [3; 16], cfg().exchange_audience()),
        make_context([4; 16], [9; 16], [3; 16], cfg().exchange_audience()),
        make_context([4; 16], [1; 16], [9; 16], cfg().exchange_audience()),
        make_context([4; 16], [1; 16], [3; 16], cfg().refresh_audience()),
    ] {
        let before = s.writes;
        assert!(
            open(&mut s)
                .accept_tls_approval(
                    "https://auth.example",
                    bad,
                    "bootstrap_secret".to_owned().try_into().unwrap(),
                    101
                )
                .is_err()
        );
        assert_eq!(s.writes, before);
    }
    assert!(
        open(&mut s)
            .accept_tls_approval(
                "https://wrong.example",
                valid.clone(),
                "bootstrap_secret".to_owned().try_into().unwrap(),
                101
            )
            .is_err()
    );
    s.fault = Fault::Before;
    assert!(
        open(&mut s)
            .accept_tls_approval(
                "https://auth.example",
                valid.clone(),
                "bootstrap_secret".to_owned().try_into().unwrap(),
                101
            )
            .is_err()
    );
    assert_eq!(open(&mut s).status(), Status::AwaitingApproval);
    open(&mut s)
        .accept_tls_approval(
            "https://auth.example",
            valid.clone(),
            "bootstrap_secret".to_owned().try_into().unwrap(),
            101,
        )
        .unwrap();
    let writes = s.writes;
    open(&mut s)
        .accept_tls_approval(
            "https://auth.example",
            valid,
            "bootstrap_secret".to_owned().try_into().unwrap(),
            102,
        )
        .unwrap();
    assert_eq!(s.writes, writes);
    s.fault = Fault::Before;
    assert!(open(&mut s).prepare_exchange(102).is_err());
    assert_eq!(open(&mut s).status(), Status::Approved);
    open(&mut s).prepare_exchange(102).unwrap();
}

#[test]
fn persisted_seed_version_key_and_state_corruption_are_rejected() {
    let mut s = Memory::default();
    ready(&mut s);
    let original = s.bytes.as_ref().unwrap().clone();
    for (needle, replacement) in [
        (b"\"version\":3".as_slice(), b"\"version\":9".as_slice()),
        (b"\"seed\":[1,".as_slice(), b"\"seed\":[0,".as_slice()),
        (b"\"epoch\":12".as_slice(), b"\"epoch\":0".as_slice()),
        (
            b"\"state\":\"Ready\"".as_slice(),
            b"\"state\":\"PendingInit\"".as_slice(),
        ),
        (
            b"\"access\":\"access_secret_1\"".as_slice(),
            b"\"access\":\"bad!token\"".as_slice(),
        ),
    ] {
        let mut bytes = original.clone();
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        bytes.splice(at..at + needle.len(), replacement.iter().copied());
        s.bytes = Some(bytes);
        assert!(HostAuth::open(&mut s, cfg(), 10000).is_err());
    }
    // Changing even one retained seed byte cannot substitute a keypair.
    let mut bytes = original.clone();
    let needle = b"\"seed\":[1,";
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
        + needle.len();
    let end = bytes[at..].iter().position(|b| *b == b',').unwrap() + at;
    let replacement = if &bytes[at..end] == b"0" {
        b"1".as_slice()
    } else {
        b"0".as_slice()
    };
    bytes.splice(at..end, replacement.iter().copied());
    s.bytes = Some(bytes);
    assert!(HostAuth::open(&mut s, cfg(), 10000).is_err());
    s.bytes = Some(original);
    assert_eq!(open(&mut s).status(), Status::Ready);
}

#[test]
fn origin_requires_canonical_dns_ipv4_and_port() {
    let configured = |origin: String| {
        Config::new(
            HostId::from_bytes([1; 16]).unwrap(),
            IpcProfileId::from_bytes([2; 16]).unwrap(),
            origin,
            "host".to_owned().try_into().unwrap(),
        )
    };
    for origin in [
        "https://auth.example",
        "https://localhost",
        "https://a-b.example",
        "https://127.0.0.1",
        "https://0.0.0.0",
        "https://255.255.255.255",
        "https://auth.example:8443",
        "https://127.0.0.1:8443",
    ] {
        assert!(configured(origin.to_owned()).is_ok(), "{origin}");
    }
    for origin in [
        "https://127.1",
        "https://0177.0.0.1",
        "https://127.0.01",
        "https://127.0.0.01",
        "https://2130706433",
        "https://0x7f000001",
        "https://0x7f.0.0.1",
        "https://127.0.1",
        "https://1.2.3.256",
        "https://example.123",
        "https://example.0x12",
        "https://example.0X12",
        "https://example.0x",
        "https://AUTH.example",
        "https://auth.example:443",
        "https://auth.example:0443",
        "https://auth.example:0",
        "https://auth.example:65536",
        "https://auth.example/",
        "https://auth.example/path",
        "https://auth.example?query",
        "https://auth.example#fragment",
        "https://user@auth.example",
        "http://auth.example",
        "https://[::1]",
        "https://auth.example.",
    ] {
        assert!(configured(origin.to_owned()).is_err(), "{origin}");
    }
    assert!(configured(format!("https://{}.example", "a".repeat(64))).is_err());
    assert!(configured(format!("https://{}", vec!["a".repeat(63); 4].join("."))).is_err());
}

#[test]
fn escaped_secret_or_malformed_escaped_state_is_rejected_before_deserialization() {
    let mut s = Memory::default();
    ready(&mut s);
    let original = s.bytes.as_ref().unwrap().clone();
    for (needle, replacement) in [
        (
            b"\"access\":\"access_secret_1\"".as_slice(),
            br#""access":"access_\u0073ecret_1""#.as_slice(),
        ),
        (
            b"\"state\":\"Ready\"".as_slice(),
            br#""state":"R\u0065ady"#.as_slice(),
        ),
    ] {
        let mut bytes = original.clone();
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        bytes.splice(at..at + needle.len(), replacement.iter().copied());
        s.bytes = Some(bytes);
        assert!(matches!(
            HostAuth::open(&mut s, cfg(), 10000),
            Err(Error::InvalidBundle)
        ));
    }
}

#[test]
fn uncertain_commit_with_old_bytes_retained_requires_inspection_and_exact_retry() {
    let mut s = Memory::default();
    ready(&mut s);
    open(&mut s).prepare_rotation(105).unwrap();
    let original = rotation(&mut s).unwrap();
    s.fault = Fault::UncertainOld;
    let mut a = open(&mut s);
    assert_eq!(
        a.accept_rotation(response(original.rotation_id, 2), 106),
        Err(Error::Storage(secrets::Error::CommitUncertain))
    );
    assert_eq!(a.status(), Status::Sealed);
    assert_eq!(a.prepare_rotation(107), Err(Error::Sealed));
    assert_eq!(a.rotation_request(107), Err(Error::Sealed));
    drop(a);
    assert_eq!(open(&mut s).status(), Status::Rotating);
    assert_eq!(rotation(&mut s).unwrap(), original);
    open(&mut s)
        .accept_rotation(response(original.rotation_id, 2), 108)
        .unwrap();
    assert_eq!(open(&mut s).status(), Status::Ready);
}

#[test]
fn time_inputs_never_move_backward_and_restart_anchor_obeys_durable_floor() {
    let mut s = Memory::default();
    ready(&mut s);
    let a = open(&mut s);
    assert_eq!(a.access_credential(403), Err(Error::Expired));
    assert_eq!(a.access_credential(104), Err(Error::ClockRollback));
    drop(a);
    assert!(matches!(
        HostAuth::open(&mut s, cfg(), 102),
        Err(Error::ClockRollback)
    ));
    let a = HostAuth::open(&mut s, cfg(), 500).unwrap();
    assert_eq!(a.access_credential(499), Err(Error::ClockRollback));
}

#[test]
fn delayed_exchange_and_rotation_responses_cannot_extend_original_intent_deadline() {
    let mut s = Memory::default();
    prepared(&mut s);
    let request = open(&mut s).exchange_request(102).unwrap();
    open(&mut s)
        .accept_exchange(response(request.operation_id, 1), 132)
        .unwrap();
    open(&mut s)
        .accept_exchange(response(request.operation_id, 1), 140)
        .unwrap();
    assert!(open(&mut s).registration_request(401).is_ok());
    assert!(matches!(
        open(&mut s).registration_request(402),
        Err(Error::Expired)
    ));
    let mut s = Memory::default();
    ready(&mut s);
    open(&mut s).prepare_rotation(200).unwrap();
    let original = rotation(&mut s).unwrap();
    open(&mut s).prepare_rotation(220).unwrap();
    assert_eq!(rotation(&mut s).unwrap(), original);
    open(&mut s)
        .accept_rotation(response(original.rotation_id, 2), 230)
        .unwrap();
    assert!(open(&mut s).access_credential(499).is_ok());
    assert_eq!(open(&mut s).access_credential(500), Err(Error::Expired));
    // A response first arriving after its locally conservative deadline cannot
    // publish credentials, even if its fixed wire lifetime remains 300 seconds.
    let mut late = Memory::default();
    prepared(&mut late);
    let op = open(&mut late).exchange_request(102).unwrap().operation_id;
    let writes = late.writes;
    assert_eq!(
        open(&mut late).accept_exchange(response(op, 1), 402),
        Err(Error::Expired)
    );
    assert_eq!(late.writes, writes);
}

#[test]
fn restart_request_emission_obeys_exclusive_original_deadlines() {
    let mut exchange = Memory::default();
    prepared(&mut exchange);
    let original = open(&mut exchange).exchange_request(102).unwrap();
    for now in [401, 402, 403] {
        let writes = exchange.writes;
        let mut a = HostAuth::open(&mut exchange, cfg(), now).unwrap();
        if now < 402 {
            assert_eq!(a.exchange_request(now).unwrap(), original);
            a.prepare_exchange(now).unwrap();
            assert_eq!(a.exchange_request(now).unwrap(), original);
        } else {
            assert_eq!(a.exchange_request(now), Err(Error::Expired));
            assert_eq!(a.prepare_exchange(now), Err(Error::Expired));
        }
        assert_eq!(a.status(), Status::ExchangePrepared);
        drop(a);
        assert_eq!(exchange.writes, writes);
    }
    let mut refresh = Memory::default();
    ready(&mut refresh);
    open(&mut refresh).prepare_rotation(200).unwrap();
    let original = HostAuth::open(&mut refresh, cfg(), 200)
        .unwrap()
        .rotation_request(200)
        .unwrap();
    for now in [499, 500, 501] {
        let writes = refresh.writes;
        let mut a = HostAuth::open(&mut refresh, cfg(), now).unwrap();
        if now < 500 {
            assert_eq!(a.rotation_request(now).unwrap(), original);
            a.prepare_rotation(now).unwrap();
            assert_eq!(a.rotation_request(now).unwrap(), original);
        } else {
            assert_eq!(a.rotation_request(now), Err(Error::Expired));
            assert_eq!(a.prepare_rotation(now), Err(Error::Expired));
        }
        assert_eq!(a.status(), Status::Rotating);
        drop(a);
        assert_eq!(refresh.writes, writes);
    }
}

fn pending(s: &mut Memory) {
    open(s).initialize().unwrap();
    open(s).accept_initiation(initiation(), 100).unwrap();
}
fn replace_bytes(bytes: &mut Vec<u8>, needle: &[u8], replacement: &[u8]) {
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    bytes.splice(at..at + needle.len(), replacement.iter().copied());
}
// Reconstruct the exact v1 stored schema in RAM, retaining real generated keys,
// signed proof and credentials. No provider contents enter output or artifacts.
fn remove_account_pin(bytes: &mut Vec<u8>) {
    let name = b",\"account_pin\":{";
    let at = bytes.windows(name.len()).position(|w| w == name).unwrap();
    let end = at
        + name.len()
        + bytes[at + name.len()..]
            .iter()
            .position(|b| *b == b'}')
            .unwrap()
        + 1;
    bytes.drain(at..end);
}
fn legacy_bytes(s: &mut Memory) {
    let bytes = s.bytes.as_mut().unwrap();
    replace_bytes(bytes, b"\"version\":3", b"\"version\":1");
    remove_account_pin(bytes);
    for name in [
        b",\"next_poll_at\":".as_slice(),
        b",\"poll_reserved\":".as_slice(),
    ] {
        if let Some(at) = bytes.windows(name.len()).position(|w| w == name) {
            let end = bytes[at + name.len()..]
                .iter()
                .position(|b| *b == b',' || *b == b'}')
                .unwrap()
                + at
                + name.len();
            bytes.drain(at..end);
        }
    }
}

#[test]
fn poll_reservation_is_durable_and_slow_down_is_authenticated() {
    let mut s = Memory::default();
    pending(&mut s);
    let view = open(&mut s).enrollment_presentation(100).unwrap();
    assert!(view.user_code.expose_wire() == "user_secret");
    assert!(!format!("{view:?}").contains("user_secret"));
    assert_eq!(
        (
            view.expires_at,
            view.poll_interval_seconds,
            view.next_poll_at
        ),
        (700, 5, 105)
    );
    assert_eq!(
        open(&mut s).accept_tls_slow_down("https://auth.example", 100),
        Err(Error::InvalidState)
    );
    let writes = s.writes;
    assert_eq!(
        open(&mut s).device_poll_credential(104),
        Err(Error::PollTooEarly)
    );
    assert_eq!(s.writes, writes);
    assert!(
        open(&mut s)
            .device_poll_credential(105)
            .unwrap()
            .expose_wire()
            == "device_secret"
    );
    assert_eq!(
        open(&mut s).device_poll_credential(109),
        Err(Error::PollTooEarly)
    );
    assert_eq!(
        open(&mut s).accept_tls_slow_down("https://wrong.example", 106),
        Err(Error::InvalidResponse)
    );
    open(&mut s)
        .accept_tls_slow_down("https://auth.example", 106)
        .unwrap();
    let view = open(&mut s).enrollment_presentation(106).unwrap();
    assert_eq!((view.poll_interval_seconds, view.next_poll_at), (10, 116));
    assert_eq!(
        open(&mut s).accept_tls_slow_down("https://auth.example", 106),
        Err(Error::InvalidState)
    );
    assert_eq!(
        open(&mut s).device_poll_credential(115),
        Err(Error::PollTooEarly)
    );
    open(&mut s).device_poll_credential(116).unwrap();
    // Dropped response/network failure still consumes the durable reservation.
    assert_eq!(
        open(&mut s).device_poll_credential(125),
        Err(Error::PollTooEarly)
    );
    assert_eq!(
        open(&mut s).device_poll_credential(700),
        Err(Error::Expired)
    );
    assert!(matches!(
        open(&mut s).enrollment_presentation(700),
        Err(Error::Expired)
    ));
}

#[test]
fn poll_publication_failures_never_emit_device_code() {
    for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
        let mut s = Memory::default();
        pending(&mut s);
        s.fault = fault;
        let mut a = open(&mut s);
        let error = a.device_poll_credential(105).unwrap_err();
        if matches!(fault, Fault::Before) {
            assert_eq!(error, Error::Storage(secrets::Error::Io));
        } else {
            assert_eq!(error, Error::Storage(secrets::Error::CommitUncertain));
            assert_eq!(a.status(), Status::Sealed);
            assert_eq!(a.device_poll_credential(105), Err(Error::Sealed));
            assert!(matches!(a.enrollment_presentation(105), Err(Error::Sealed)));
        }
        drop(a);
        if matches!(fault, Fault::Uncertain) {
            assert_eq!(
                open(&mut s).device_poll_credential(105),
                Err(Error::PollTooEarly)
            );
        } else {
            open(&mut s).device_poll_credential(105).unwrap();
        }
    }
}

#[test]
fn expired_or_authenticated_denied_reset_retains_exact_identity() {
    for denied in [false, true] {
        let mut s = Memory::default();
        pending(&mut s);
        let original = {
            // Compare the whole durable identity after resetting, in RAM only.
            let mut original = s.bytes.as_ref().unwrap().clone();
            let start = original
                .windows(b"\"lifecycle\":".len())
                .position(|w| w == b"\"lifecycle\":")
                .unwrap();
            original.truncate(start);
            original
        };
        assert_eq!(
            open(&mut s).reset_expired_enrollment(699),
            Err(Error::InvalidState)
        );
        assert_eq!(
            open(&mut s).reset_tls_denied_enrollment("https://wrong.example", 699),
            Err(Error::InvalidResponse)
        );
        if denied {
            open(&mut s)
                .reset_tls_denied_enrollment("https://auth.example", 699)
                .unwrap();
        } else {
            open(&mut s).reset_expired_enrollment(700).unwrap();
        }
        assert_eq!(open(&mut s).status(), Status::PendingInit);
        let bytes = s.bytes.as_ref().unwrap();
        // observed_at alone advances; key/config/commitment/pin remain exact.
        let key_start = original
            .windows(9)
            .position(|w| w == b"\"config\":")
            .unwrap();
        let new_start = bytes.windows(9).position(|w| w == b"\"config\":").unwrap();
        assert!(bytes[new_start..].starts_with(&original[key_start..]));
        open(&mut s).accept_initiation(initiation(), 701).unwrap();
    }
    let mut approved = Memory::default();
    open(&mut approved).initialize().unwrap();
    approval(&mut approved);
    assert_eq!(
        open(&mut approved).reset_expired_enrollment(599),
        Err(Error::InvalidState)
    );
    open(&mut approved).reset_expired_enrollment(600).unwrap();
    for stage in 0..4 {
        let mut s = Memory::default();
        match stage {
            0 => prepared(&mut s),
            1 => unconfirmed(&mut s),
            _ => ready(&mut s),
        }
        if stage == 3 {
            open(&mut s).prepare_rotation(200).unwrap();
        }
        let writes = s.writes;
        assert_eq!(
            open(&mut s).reset_expired_enrollment(1000),
            Err(Error::InvalidState)
        );
        assert_eq!(
            open(&mut s).reset_tls_denied_enrollment("https://auth.example", 1000),
            Err(Error::InvalidState)
        );
        assert_eq!(s.writes, writes);
    }
}

#[test]
fn v1_migration_persists_wait_before_emission_and_preserves_intents() {
    for stage in 0..7 {
        let mut s = Memory::default();
        match stage {
            0 => open(&mut s).initialize().unwrap(),
            1 => pending(&mut s),
            2 => {
                open(&mut s).initialize().unwrap();
                approval(&mut s);
            }
            3 => prepared(&mut s),
            4 => unconfirmed(&mut s),
            _ => ready(&mut s),
        }
        if stage == 6 {
            open(&mut s).prepare_rotation(200).unwrap();
        }
        let original_status = open(&mut s).status();
        let original_init = if stage == 0 {
            Some(open(&mut s).init_request().unwrap())
        } else {
            None
        };
        let original_exchange = if stage == 3 {
            Some(open(&mut s).exchange_request(102).unwrap())
        } else {
            None
        };
        let original_rotation = if stage == 6 {
            Some(rotation(&mut s).unwrap())
        } else {
            None
        };
        legacy_bytes(&mut s);
        let old = s.bytes.as_ref().unwrap().clone();
        let writes = s.writes;
        let mut a = HostAuth::open(&mut s, cfg(), 200).unwrap();
        assert_eq!(a.status(), original_status);
        if let Some(request) = original_init {
            assert_eq!(a.init_request().unwrap(), request);
        }
        if let Some(request) = original_exchange {
            assert_eq!(a.exchange_request(200).unwrap(), request);
        }
        if let Some(request) = original_rotation {
            assert_eq!(a.rotation_request(200).unwrap(), request);
        }
        if stage == 1 {
            assert_eq!(a.enrollment_presentation(200).unwrap().next_poll_at, 205);
            assert_eq!(a.device_poll_credential(204), Err(Error::PollTooEarly));
        }
        drop(a);
        assert_eq!(s.writes, writes + 1);
        assert!(
            s.bytes
                .as_ref()
                .unwrap()
                .windows(11)
                .any(|w| w == b"\"version\":3")
        );
        // Migration preserved identity bytes, beyond the changing observed time.
        let needle = b"\"config\":";
        let start = old.windows(needle.len()).position(|w| w == needle).unwrap();
        let end = old
            .windows(b",\"lifecycle\":".len())
            .position(|w| w == b",\"lifecycle\":")
            .unwrap();
        assert!(
            s.bytes
                .as_ref()
                .unwrap()
                .windows(end - start)
                .any(|w| w == &old[start..end])
        );
    }
}

#[test]
fn migration_failure_is_closed_and_v2_fields_are_required() {
    for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
        let mut s = Memory::default();
        pending(&mut s);
        legacy_bytes(&mut s);
        s.fault = fault;
        assert!(matches!(
            HostAuth::open(&mut s, cfg(), 200),
            Err(Error::Storage(_))
        ));
        let mut a = HostAuth::open(&mut s, cfg(), 200).unwrap();
        assert_eq!(a.device_poll_credential(200), Err(Error::PollTooEarly));
    }
    let mut s = Memory::default();
    prepared(&mut s);
    legacy_bytes(&mut s);
    replace_bytes(
        s.bytes.as_mut().unwrap(),
        b"\"prepared_at\":102",
        b"\"missing_at\":102",
    );
    let writes = s.writes;
    assert!(matches!(
        HostAuth::open(&mut s, cfg(), 200),
        Err(Error::InvalidBundle)
    ));
    assert_eq!(writes, s.writes);
    let mut s = Memory::default();
    pending(&mut s);
    legacy_bytes(&mut s);
    replace_bytes(
        s.bytes.as_mut().unwrap(),
        b"\"version\":1",
        b"\"version\":2",
    );
    assert!(matches!(
        HostAuth::open(&mut s, cfg(), 200),
        Err(Error::InvalidBundle)
    ));
}

#[test]
fn scheduling_overflow_fails_closed_and_deadlines_keep_original_request_time() {
    let mut s = Memory::default();
    open(&mut s).initialize().unwrap();
    let mut initial = initiation();
    initial.poll_interval_seconds = DecimalU64(u64::MAX);
    assert_eq!(
        open(&mut s).accept_initiation(initial, 100),
        Err(Error::InvalidResponse)
    );
    let mut initial = initiation();
    initial.poll_interval_seconds = DecimalU64(u64::MAX - 5);
    initial.expires_in_seconds = DecimalU64(u64::MAX);
    open(&mut s).accept_initiation(initial, 0).unwrap();
    let now = u64::MAX - 5;
    assert_eq!(
        open(&mut s).device_poll_credential(now),
        Err(Error::InvalidState)
    );
    let mut s = Memory::default();
    ready(&mut s);
    let deadline = open(&mut s).credential_deadlines().unwrap();
    assert_eq!(
        (
            deadline.access_expires_at,
            deadline.refresh_at,
            deadline.rotation_expires_at
        ),
        (402, 342, None)
    );
    open(&mut s).prepare_rotation(200).unwrap();
    open(&mut s).prepare_rotation(220).unwrap();
    let deadline = open(&mut s).credential_deadlines().unwrap();
    assert_eq!(
        (
            deadline.access_expires_at,
            deadline.refresh_at,
            deadline.rotation_expires_at
        ),
        (402, 342, Some(500))
    );
    let request = rotation(&mut s).unwrap();
    open(&mut s)
        .accept_rotation(response(request.rotation_id, 2), 250)
        .unwrap();
    assert_eq!(
        open(&mut s)
            .credential_deadlines()
            .unwrap()
            .access_expires_at,
        500
    );
}

#[test]
fn reset_storage_faults_preserve_pending_and_seal_uncertain_instances() {
    for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
        let mut s = Memory::default();
        pending(&mut s);
        s.fault = fault;
        let mut a = open(&mut s);
        assert!(a.reset_expired_enrollment(700).is_err());
        if matches!(fault, Fault::Before) {
            assert_eq!(a.status(), Status::AwaitingApproval);
        } else {
            assert_eq!(a.status(), Status::Sealed);
            assert_eq!(
                a.reset_tls_denied_enrollment("https://auth.example", 700),
                Err(Error::Sealed)
            );
        }
        drop(a);
        assert_eq!(
            open(&mut s).status(),
            if matches!(fault, Fault::Uncertain) {
                Status::PendingInit
            } else {
                Status::AwaitingApproval
            }
        );
    }
}

#[test]
fn verified_epoch_is_available_during_rotation_without_changing_intent() {
    let mut s = Memory::default();
    unconfirmed(&mut s);
    assert_eq!(
        open(&mut s).verified_host_access_epoch(),
        Err(Error::InvalidState)
    );
    open(&mut s)
        .confirm_registration(HostRegisterResult {
            host_id: HostId::from_bytes([1; 16]).unwrap(),
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
    assert_eq!(
        open(&mut s).verified_host_access_epoch().unwrap(),
        DecimalU64(12)
    );
    open(&mut s).prepare_rotation(200).unwrap();
    let request = rotation(&mut s).unwrap();
    assert_eq!(
        open(&mut s).verified_host_access_epoch().unwrap(),
        DecimalU64(12)
    );
    assert_eq!(rotation(&mut s).unwrap(), request);
}

#[test]
fn slow_down_faults_and_overflow_never_reduce_durable_schedule() {
    for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
        let mut s = Memory::default();
        pending(&mut s);
        open(&mut s).device_poll_credential(105).unwrap();
        s.fault = fault;
        let mut a = open(&mut s);
        assert!(a.accept_tls_slow_down("https://auth.example", 106).is_err());
        if !matches!(fault, Fault::Before) {
            assert_eq!(a.status(), Status::Sealed);
        }
        drop(a);
        let view = open(&mut s).enrollment_presentation(106).unwrap();
        assert_eq!(
            view.next_poll_at,
            if matches!(fault, Fault::Uncertain) {
                116
            } else {
                110
            }
        );
    }
    let mut s = Memory::default();
    pending(&mut s);
    open(&mut s).device_poll_credential(105).unwrap();
    // Valid bounded persisted schema with no representable SlowDown arithmetic.
    replace_bytes(
        s.bytes.as_mut().unwrap(),
        b"\"interval\":5",
        format!("\"interval\":{}", u64::MAX - 1).as_bytes(),
    );
    replace_bytes(
        s.bytes.as_mut().unwrap(),
        b"\"next_poll_at\":110",
        format!("\"next_poll_at\":{}", u64::MAX - 1).as_bytes(),
    );
    let writes = s.writes;
    assert_eq!(
        open(&mut s).accept_tls_slow_down("https://auth.example", 106),
        Err(Error::InvalidResponse)
    );
    assert_eq!(s.writes, writes);
    assert_eq!(
        open(&mut s).device_poll_credential(106),
        Err(Error::PollTooEarly)
    );
}

fn revoke_result(epoch: u64) -> HostRevokeResult {
    HostRevokeResult {
        host_id: HostId::from_bytes([1; 16]).unwrap(),
        host_access_epoch: DecimalU64(epoch),
    }
}
fn enrollment_revoked_family_result(
    family: HostAuthorizationId,
    family_epoch: u64,
    current_epoch: u64,
) -> HostEnrollmentRevocationAckResult {
    HostEnrollmentRevocationAckResult::RevokedFamily {
        host_id: HostId::from_bytes([1; 16]).unwrap(),
        enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
        operation_id: OperationId::from_bytes([6; 16]).unwrap(),
        account_id: AccountId::from_bytes([4; 16]).unwrap(),
        host_authorization_id: family,
        family_host_access_epoch: DecimalU64(family_epoch),
        host_access_epoch: DecimalU64(current_epoch),
    }
}
fn enrollment_no_family_result() -> HostEnrollmentRevocationAckResult {
    HostEnrollmentRevocationAckResult::NoFamily {
        host_id: HostId::from_bytes([1; 16]).unwrap(),
        enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
        operation_id: OperationId::from_bytes([6; 16]).unwrap(),
        account_id: AccountId::from_bytes([4; 16]).unwrap(),
    }
}
fn stored_identity(s: &Memory) -> Zeroizing<Vec<u8>> {
    let bytes = s.bytes.as_ref().unwrap();
    let start = bytes.windows(9).position(|w| w == b"\"config\":").unwrap();
    let end = bytes
        .windows(13)
        .position(|w| w == b",\"lifecycle\":")
        .unwrap();
    Zeroizing::new(bytes[start..end].to_vec())
}

#[test]
fn explicit_local_cancel_is_pre_exchange_only_and_idempotent() {
    let mut empty = Memory::default();
    assert_eq!(
        open(&mut empty).cancel_pending_login(0),
        Err(Error::InvalidState)
    );
    for stage in 0..7 {
        let mut s = Memory::default();
        match stage {
            0 => open(&mut s).initialize().unwrap(),
            1 => pending(&mut s),
            2 => {
                open(&mut s).initialize().unwrap();
                approval(&mut s);
            }
            3 => prepared(&mut s),
            4 => unconfirmed(&mut s),
            _ => ready(&mut s),
        }
        if stage == 6 {
            open(&mut s).prepare_rotation(200).unwrap();
        }
        let identity = stored_identity(&s);
        let original = s.bytes.as_ref().unwrap().clone();
        let writes = s.writes;
        let result = open(&mut s).cancel_pending_login(201);
        if stage <= 2 {
            result.unwrap();
            assert_eq!(open(&mut s).status(), Status::PendingInit);
            assert!(stored_identity(&s).as_slice() == identity.as_slice());
            assert_eq!(s.writes, writes + usize::from(stage != 0));
            let writes = s.writes;
            open(&mut s).cancel_pending_login(202).unwrap();
            assert_eq!(s.writes, writes);
        } else {
            assert_eq!(result, Err(Error::InvalidState));
            assert!(s.bytes.as_ref().unwrap().as_slice() == original.as_slice());
            assert_eq!(s.writes, writes);
        }
    }
}

#[test]
fn authenticated_revocation_retires_only_confirmed_family_material() {
    for rotating in [false, true] {
        for epoch in [12, 13] {
            let mut s = Memory::default();
            ready(&mut s);
            if rotating {
                open(&mut s).prepare_rotation(200).unwrap();
            }
            let identity = stored_identity(&s);
            open(&mut s)
                .accept_tls_revocation("https://auth.example", revoke_result(epoch), 1000)
                .unwrap();
            assert_eq!(open(&mut s).status(), Status::Revoked);
            assert!(stored_identity(&s).as_slice() == identity.as_slice());
            assert_eq!(
                open(&mut s).revocation_credential(),
                Err(Error::InvalidState)
            );
            let bytes = s.bytes.as_ref().unwrap();
            for retired in [
                b"access_secret".as_slice(),
                b"refresh_secret".as_slice(),
                b"\"proof\"".as_slice(),
                b"\"operation\"".as_slice(),
            ] {
                assert!(!bytes.windows(retired.len()).any(|w| w == retired));
            }
        }
    }
    let mut s = Memory::default();
    unconfirmed(&mut s);
    let writes = s.writes;
    assert_eq!(
        open(&mut s).accept_tls_revocation("https://auth.example", revoke_result(13), 1000),
        Err(Error::InvalidState)
    );
    assert_eq!(
        open(&mut s).revocation_credential(),
        Err(Error::InvalidState)
    );
    assert_eq!(s.writes, writes);
}

#[test]
fn invalid_revocation_ack_preserves_exact_rotation_and_family() {
    let mut s = Memory::default();
    ready(&mut s);
    open(&mut s).prepare_rotation(200).unwrap();
    let request = rotation(&mut s).unwrap();
    let bytes = s.bytes.as_ref().unwrap().clone();
    let writes = s.writes;
    for (origin, result) in [
        ("https://wrong.example", revoke_result(13)),
        ("https://auth.example", revoke_result(11)),
        (
            "https://auth.example",
            HostRevokeResult {
                host_id: HostId::from_bytes([9; 16]).unwrap(),
                host_access_epoch: DecimalU64(13),
            },
        ),
    ] {
        assert_eq!(
            open(&mut s).accept_tls_revocation(origin, result, 201),
            Err(Error::InvalidResponse)
        );
        assert_eq!(rotation(&mut s).unwrap(), request);
        assert!(s.bytes.as_ref().unwrap().as_slice() == bytes.as_slice());
    }
    assert_eq!(s.writes, writes);
    assert!(open(&mut s).revocation_credential().unwrap().expose_wire() == "access_secret_1");
}

#[test]
fn revocation_ack_request_survives_access_and_rotation_deadlines() {
    for rotating in [false, true] {
        let mut s = Memory::default();
        ready(&mut s);
        if rotating {
            open(&mut s).prepare_rotation(200).unwrap();
        }
        let writes = s.writes;
        let auth = HostAuth::open(&mut s, cfg(), 600).unwrap();
        let request = auth.revocation_ack_request(600).unwrap();
        assert_eq!(
            request.host_authorization_id,
            HostAuthorizationId::from_bytes([8; 16]).unwrap()
        );
        assert_eq!(request.expected_host_access_epoch, DecimalU64(12));
        assert_eq!(request.refresh.expose_wire(), "refresh_secret_1");
        assert_eq!(
            auth.status(),
            if rotating {
                Status::Rotating
            } else {
                Status::Ready
            }
        );
        if rotating {
            assert_eq!(auth.rotation_request(600), Err(Error::Expired));
        } else {
            assert_eq!(auth.access_credential(600), Err(Error::Expired));
        }
        drop(auth);
        assert_eq!(s.writes, writes);
    }
}

#[test]
fn historical_enrollment_ack_survives_enrollment_challenge_and_exchange_deadlines() {
    for unconfirmed_state in [false, true] {
        let mut s = Memory::default();
        if unconfirmed_state {
            unconfirmed(&mut s);
        } else {
            prepared(&mut s);
        }
        let now = stored_time(&s);
        let original = HostAuth::open(&mut s, cfg(), now)
            .unwrap()
            .enrollment_revocation_ack_request(now)
            .unwrap();

        // The fixture enrollment expires at 700, the challenge at 600, and
        // the exchange intent at 402. Retirement still returns its exact proof.
        let auth = HostAuth::open(&mut s, cfg(), 701).unwrap();
        assert_eq!(auth.enrollment_revocation_ack_request(701), Ok(original));
        assert_eq!(
            auth.enrollment_revocation_ack_request(700),
            Err(Error::ClockRollback)
        );
        if unconfirmed_state {
            assert!(matches!(
                auth.registration_request(701),
                Err(Error::Expired)
            ));
        } else {
            assert!(matches!(auth.exchange_request(701), Err(Error::Expired)));
        }
    }
}

#[test]
fn historical_enrollment_ack_obeys_the_monotonic_clock_floor() {
    let mut s = Memory::default();
    prepared(&mut s);
    let bytes = s.bytes.as_ref().unwrap().clone();
    let writes = s.writes;
    let mut auth = HostAuth::open(&mut s, cfg(), 701).unwrap();
    let request = auth.enrollment_revocation_ack_request(701).unwrap();
    assert_eq!(
        auth.accept_enrollment_revocation_ack(
            "https://auth.example",
            &request,
            enrollment_no_family_result(),
            700,
        ),
        Err(Error::ClockRollback)
    );
    assert_eq!(auth.status(), Status::ExchangePrepared);
    auth.accept_enrollment_revocation_ack(
        "https://auth.example",
        &request,
        enrollment_no_family_result(),
        701,
    )
    .unwrap();
    drop(auth);
    assert_ne!(s.bytes.as_ref().unwrap().as_slice(), bytes.as_slice());
    assert_eq!(s.writes, writes + 1);
}

#[test]
fn historical_enrollment_ack_retires_exact_family_or_no_family() {
    let mut family = Memory::default();
    prepared(&mut family);
    let request = HostAuth::open(&mut family, cfg(), 701)
        .unwrap()
        .enrollment_revocation_ack_request(701)
        .unwrap();
    open(&mut family)
        .accept_enrollment_revocation_ack(
            "https://auth.example",
            &request,
            enrollment_revoked_family_result(
                HostAuthorizationId::from_bytes([8; 16]).unwrap(),
                12,
                15,
            ),
            701,
        )
        .unwrap();
    assert_eq!(open(&mut family).status(), Status::Revoked);
    assert_eq!(
        open(&mut family)
            .retained_revocation_acknowledgement()
            .unwrap(),
        RetainedRevocationAcknowledgement::Host(revoke_result(15))
    );
    assert_eq!(
        open(&mut family).revocation_acknowledgement().unwrap(),
        revoke_result(15)
    );
    let family_bytes = family.bytes.as_ref().unwrap().clone();
    let family_writes = family.writes;
    assert_eq!(
        open(&mut family).accept_enrollment_revocation_ack(
            "https://auth.example",
            &request,
            enrollment_revoked_family_result(
                HostAuthorizationId::from_bytes([8; 16]).unwrap(),
                12,
                15,
            ),
            702,
        ),
        Err(Error::InvalidState)
    );
    assert_eq!(
        family.bytes.as_ref().unwrap().as_slice(),
        family_bytes.as_slice()
    );
    assert_eq!(family.writes, family_writes);

    let mut no_family = Memory::default();
    prepared(&mut no_family);
    let identity = stored_identity(&no_family);
    let request = HostAuth::open(&mut no_family, cfg(), 701)
        .unwrap()
        .enrollment_revocation_ack_request(701)
        .unwrap();
    open(&mut no_family)
        .accept_enrollment_revocation_ack(
            "https://auth.example",
            &request,
            enrollment_no_family_result(),
            701,
        )
        .unwrap();
    assert_eq!(open(&mut no_family).status(), Status::Revoked);
    assert_eq!(
        open(&mut no_family)
            .retained_revocation_acknowledgement()
            .unwrap(),
        RetainedRevocationAcknowledgement::NoFamily {
            host_id: HostId::from_bytes([1; 16]).unwrap(),
            account_id: AccountId::from_bytes([4; 16]).unwrap(),
            enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
            operation_id: OperationId::from_bytes([6; 16]).unwrap(),
        }
    );
    assert_eq!(
        open(&mut no_family).revocation_acknowledgement(),
        Err(Error::InvalidState)
    );
    assert_eq!(
        open(&mut no_family).init_request(),
        Err(Error::InvalidState)
    );
    assert!(stored_identity(&no_family).as_slice() == identity.as_slice());
    let no_family_bytes = no_family.bytes.as_ref().unwrap().clone();
    let no_family_writes = no_family.writes;
    assert_eq!(
        open(&mut no_family).accept_enrollment_revocation_ack(
            "https://auth.example",
            &request,
            enrollment_no_family_result(),
            702,
        ),
        Err(Error::InvalidState)
    );
    assert_eq!(
        no_family.bytes.as_ref().unwrap().as_slice(),
        no_family_bytes.as_slice()
    );
    assert_eq!(no_family.writes, no_family_writes);
    let bytes = no_family.bytes.as_ref().unwrap();
    for retired in [
        b"bootstrap_secret".as_slice(),
        b"device_secret".as_slice(),
        b"user_secret".as_slice(),
        b"access_secret".as_slice(),
        b"refresh_secret".as_slice(),
        b"\"proof\"".as_slice(),
        b"\"bootstrap\"".as_slice(),
    ] {
        assert!(!bytes.windows(retired.len()).any(|window| window == retired));
    }
    let mut malformed = no_family_bytes.to_vec();
    let pin_field = b"\"account_pin\":{\"account\":\"";
    let pin_at = malformed
        .windows(pin_field.len())
        .position(|window| window == pin_field)
        .unwrap()
        + pin_field.len();
    malformed[pin_at] = if malformed[pin_at] == b'0' {
        b'1'
    } else {
        b'0'
    };
    no_family.bytes = Some(Zeroizing::new(malformed));
    assert!(matches!(
        HostAuth::open(&mut no_family, cfg(), 701),
        Err(Error::InvalidBundle)
    ));
    assert_eq!(no_family.writes, no_family_writes);
    no_family.bytes = Some(no_family_bytes.clone());

    // The owner explicitly completes its handoff before permitting LoginStart.
    open(&mut no_family).restart_after_revocation(702).unwrap();
    assert_eq!(open(&mut no_family).status(), Status::PendingInit);
    assert!(stored_identity(&no_family).as_slice() == identity.as_slice());
    assert_eq!(
        approval_for(&mut no_family, [9; 16], 703),
        Err(Error::InvalidResponse)
    );
}

#[test]
fn expired_unconfirmed_family_ack_survives_reopen_and_uncertain_publication() {
    for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
        let mut s = Memory::default();
        unconfirmed(&mut s);
        let request = HostAuth::open(&mut s, cfg(), 701)
            .unwrap()
            .enrollment_revocation_ack_request(701)
            .unwrap();
        let original = s.bytes.as_ref().unwrap().clone();
        s.fault = fault;

        let mut auth = HostAuth::open(&mut s, cfg(), 701).unwrap();
        let ack = auth.accept_enrollment_revocation_ack(
            "https://auth.example",
            &request,
            enrollment_revoked_family_result(
                HostAuthorizationId::from_bytes([8; 16]).unwrap(),
                12,
                15,
            ),
            701,
        );
        if matches!(fault, Fault::Before) {
            assert_eq!(ack, Err(Error::Storage(secrets::Error::Io)));
            assert_eq!(auth.status(), Status::Unconfirmed);
        } else {
            assert_eq!(ack, Err(Error::Storage(secrets::Error::CommitUncertain)));
            assert_eq!(auth.status(), Status::Sealed);
        }
        drop(auth);

        let reopened = HostAuth::open(&mut s, cfg(), 701).unwrap();
        if matches!(fault, Fault::Uncertain) {
            assert_eq!(reopened.status(), Status::Revoked);
            assert_eq!(
                reopened.retained_revocation_acknowledgement().unwrap(),
                RetainedRevocationAcknowledgement::Host(revoke_result(15))
            );
            continue;
        }

        assert_eq!(reopened.status(), Status::Unconfirmed);
        assert_eq!(
            reopened.enrollment_revocation_ack_request(701).unwrap(),
            request
        );
        drop(reopened);
        assert_eq!(s.bytes.as_ref().unwrap().as_slice(), original.as_slice());
        let mut reopened = HostAuth::open(&mut s, cfg(), 701).unwrap();
        reopened
            .accept_enrollment_revocation_ack(
                "https://auth.example",
                &request,
                enrollment_revoked_family_result(
                    HostAuthorizationId::from_bytes([8; 16]).unwrap(),
                    12,
                    15,
                ),
                701,
            )
            .unwrap();
        drop(reopened);

        let reopened = HostAuth::open(&mut s, cfg(), 701).unwrap();
        assert_eq!(reopened.status(), Status::Revoked);
        assert_eq!(
            reopened.retained_revocation_acknowledgement().unwrap(),
            RetainedRevocationAcknowledgement::Host(revoke_result(15))
        );
    }
}

#[test]
fn historical_enrollment_ack_rejects_mismatches_and_unconfirmed_no_family() {
    for unconfirmed_state in [false, true] {
        let mut s = Memory::default();
        if unconfirmed_state {
            unconfirmed(&mut s);
        } else {
            prepared(&mut s);
        }
        let now = stored_time(&s);
        let request = HostAuth::open(&mut s, cfg(), now)
            .unwrap()
            .enrollment_revocation_ack_request(now)
            .unwrap();
        let bytes = s.bytes.as_ref().unwrap().clone();
        let writes = s.writes;
        let family = HostAuthorizationId::from_bytes([8; 16]).unwrap();
        let good = enrollment_revoked_family_result(family, 12, 15);
        let mut wrong_enrollment = request.clone();
        wrong_enrollment.enrollment_id = EnrollmentId::from_bytes([9; 16]).unwrap();
        let mut wrong_operation = request.clone();
        wrong_operation.operation_id = OperationId::from_bytes([9; 16]).unwrap();
        let mut wrong_proof = request.clone();
        let mut wrong_signature = wrong_proof.proof.signature.expose_wire().to_owned();
        let replacement = if wrong_signature.starts_with('0') {
            "1"
        } else {
            "0"
        };
        wrong_signature.replace_range(0..1, replacement);
        wrong_proof.proof.signature = wrong_signature.try_into().unwrap();

        for (origin, proof_request, result) in [
            ("https://wrong.example", request.clone(), good.clone()),
            ("https://auth.example", wrong_enrollment, good.clone()),
            ("https://auth.example", wrong_operation, good.clone()),
            ("https://auth.example", wrong_proof, good.clone()),
            (
                "https://auth.example",
                request.clone(),
                enrollment_revoked_family_result(family, 0, 15),
            ),
            (
                "https://auth.example",
                request.clone(),
                enrollment_revoked_family_result(family, i64::MAX as u64 + 1, i64::MAX as u64 + 1),
            ),
            (
                "https://auth.example",
                request.clone(),
                enrollment_revoked_family_result(family, 15, 14),
            ),
            (
                "https://auth.example",
                request.clone(),
                HostEnrollmentRevocationAckResult::RevokedFamily {
                    host_id: HostId::from_bytes([9; 16]).unwrap(),
                    enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
                    operation_id: OperationId::from_bytes([6; 16]).unwrap(),
                    account_id: AccountId::from_bytes([4; 16]).unwrap(),
                    host_authorization_id: family,
                    family_host_access_epoch: DecimalU64(12),
                    host_access_epoch: DecimalU64(15),
                },
            ),
            (
                "https://auth.example",
                request.clone(),
                HostEnrollmentRevocationAckResult::RevokedFamily {
                    host_id: HostId::from_bytes([1; 16]).unwrap(),
                    enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
                    operation_id: OperationId::from_bytes([9; 16]).unwrap(),
                    account_id: AccountId::from_bytes([4; 16]).unwrap(),
                    host_authorization_id: family,
                    family_host_access_epoch: DecimalU64(12),
                    host_access_epoch: DecimalU64(15),
                },
            ),
            (
                "https://auth.example",
                request.clone(),
                HostEnrollmentRevocationAckResult::RevokedFamily {
                    host_id: HostId::from_bytes([1; 16]).unwrap(),
                    enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
                    operation_id: OperationId::from_bytes([6; 16]).unwrap(),
                    account_id: AccountId::from_bytes([9; 16]).unwrap(),
                    host_authorization_id: family,
                    family_host_access_epoch: DecimalU64(12),
                    host_access_epoch: DecimalU64(15),
                },
            ),
            (
                "https://auth.example",
                request.clone(),
                HostEnrollmentRevocationAckResult::NoFamily {
                    host_id: HostId::from_bytes([1; 16]).unwrap(),
                    enrollment_id: EnrollmentId::from_bytes([9; 16]).unwrap(),
                    operation_id: OperationId::from_bytes([9; 16]).unwrap(),
                    account_id: AccountId::from_bytes([4; 16]).unwrap(),
                },
            ),
            (
                "https://auth.example",
                request.clone(),
                HostEnrollmentRevocationAckResult::NoFamily {
                    host_id: HostId::from_bytes([1; 16]).unwrap(),
                    enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
                    operation_id: OperationId::from_bytes([6; 16]).unwrap(),
                    account_id: AccountId::from_bytes([9; 16]).unwrap(),
                },
            ),
        ] {
            assert_eq!(
                open(&mut s).accept_enrollment_revocation_ack(origin, &proof_request, result, 701,),
                Err(Error::InvalidResponse)
            );
            assert_eq!(s.bytes.as_ref().unwrap().as_slice(), bytes.as_slice());
        }
        if unconfirmed_state {
            assert_eq!(
                open(&mut s).accept_enrollment_revocation_ack(
                    "https://auth.example",
                    &request,
                    enrollment_no_family_result(),
                    701,
                ),
                Err(Error::InvalidResponse)
            );
            assert_eq!(
                open(&mut s).accept_enrollment_revocation_ack(
                    "https://auth.example",
                    &request,
                    enrollment_revoked_family_result(
                        HostAuthorizationId::from_bytes([9; 16]).unwrap(),
                        12,
                        15,
                    ),
                    701,
                ),
                Err(Error::InvalidResponse)
            );
        }
        assert_eq!(
            open(&mut s).status(),
            if unconfirmed_state {
                Status::Unconfirmed
            } else {
                Status::ExchangePrepared
            }
        );
        assert_eq!(s.bytes.as_ref().unwrap().as_slice(), bytes.as_slice());
        assert_eq!(s.writes, writes);
    }
}

#[test]
fn delayed_enrollment_ack_cannot_retire_a_replacement_login_intent() {
    let mut s = Memory::default();
    prepared(&mut s);
    let old_request = HostAuth::open(&mut s, cfg(), 701)
        .unwrap()
        .enrollment_revocation_ack_request(701)
        .unwrap();
    open(&mut s)
        .accept_enrollment_revocation_ack(
            "https://auth.example",
            &old_request,
            enrollment_no_family_result(),
            701,
        )
        .unwrap();
    open(&mut s).restart_after_revocation(702).unwrap();
    approval_for_ids(&mut s, [4; 16], 703, [9; 16], [10; 16]).unwrap();
    open(&mut s).prepare_exchange(705).unwrap();
    let replacement = HostAuth::open(&mut s, cfg(), 706)
        .unwrap()
        .enrollment_revocation_ack_request(706)
        .unwrap();
    assert_ne!(old_request.enrollment_id, replacement.enrollment_id);
    assert_ne!(old_request.operation_id, replacement.operation_id);
    let bytes = s.bytes.as_ref().unwrap().clone();
    let writes = s.writes;

    assert_eq!(
        open(&mut s).accept_enrollment_revocation_ack(
            "https://auth.example",
            &old_request,
            enrollment_no_family_result(),
            706,
        ),
        Err(Error::InvalidResponse)
    );
    assert_eq!(
        HostAuth::open(&mut s, cfg(), 706)
            .unwrap()
            .enrollment_revocation_ack_request(706)
            .unwrap(),
        replacement
    );
    assert_eq!(s.bytes.as_ref().unwrap().as_slice(), bytes.as_slice());
    assert_eq!(s.writes, writes);
}

#[test]
fn historical_enrollment_ack_secret_commit_uncertainty_is_repaired_by_reopen() {
    for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
        let mut s = Memory::default();
        prepared(&mut s);
        let request = HostAuth::open(&mut s, cfg(), 701)
            .unwrap()
            .enrollment_revocation_ack_request(701)
            .unwrap();
        let old_bytes = s.bytes.as_ref().unwrap().clone();
        s.fault = fault;
        let result = open(&mut s).accept_enrollment_revocation_ack(
            "https://auth.example",
            &request,
            enrollment_no_family_result(),
            701,
        );
        assert_eq!(
            result,
            Err(Error::Storage(if matches!(fault, Fault::Before) {
                secrets::Error::Io
            } else {
                secrets::Error::CommitUncertain
            }))
        );

        let auth = HostAuth::open(&mut s, cfg(), 701).unwrap();
        let published = matches!(fault, Fault::Uncertain);
        if published {
            assert_eq!(auth.status(), Status::Revoked);
            assert!(matches!(
                auth.retained_revocation_acknowledgement().unwrap(),
                RetainedRevocationAcknowledgement::NoFamily { .. }
            ));
        } else {
            assert_eq!(auth.status(), Status::ExchangePrepared);
            assert!(auth.enrollment_revocation_ack_request(701).is_ok());
        }
        drop(auth);
        if !published {
            assert_eq!(s.bytes.as_ref().unwrap().as_slice(), old_bytes.as_slice());
        }
    }
}

#[test]
fn revocation_ack_response_is_bound_to_the_exact_current_request() {
    let mut s = Memory::default();
    ready(&mut s);
    open(&mut s).prepare_rotation(200).unwrap();
    let request = HostAuth::open(&mut s, cfg(), 201)
        .unwrap()
        .revocation_ack_request(201)
        .unwrap();
    let bytes = s.bytes.as_ref().unwrap().clone();
    let writes = s.writes;
    let wrong_request = [
        {
            let mut wrong = request.clone();
            wrong.expected_host_access_epoch = DecimalU64(13);
            wrong
        },
        {
            let mut wrong = request.clone();
            wrong.refresh = "different_refresh".to_owned().try_into().unwrap();
            wrong
        },
    ];
    for wrong in wrong_request {
        assert_eq!(
            open(&mut s).accept_revocation_ack(
                "https://auth.example",
                &wrong,
                revoke_result(13),
                202,
            ),
            Err(Error::InvalidResponse)
        );
    }
    for (origin, result) in [
        ("https://wrong.example", revoke_result(13)),
        ("https://auth.example", revoke_result(11)),
        (
            "https://auth.example",
            HostRevokeResult {
                host_id: HostId::from_bytes([9; 16]).unwrap(),
                host_access_epoch: DecimalU64(13),
            },
        ),
    ] {
        assert_eq!(
            open(&mut s).accept_revocation_ack(origin, &request, result, 202),
            Err(Error::InvalidResponse)
        );
    }
    assert_eq!(open(&mut s).status(), Status::Rotating);
    assert_eq!(s.bytes.as_ref().unwrap().as_slice(), bytes.as_slice());
    assert_eq!(s.writes, writes);
}

#[test]
fn delayed_revocation_ack_cannot_retire_replacement_credentials() {
    let mut s = Memory::default();
    ready(&mut s);
    let original = HostAuth::open(&mut s, cfg(), 103)
        .unwrap()
        .revocation_ack_request(103)
        .unwrap();
    open(&mut s).prepare_rotation(200).unwrap();
    let rotation = rotation(&mut s).unwrap();
    open(&mut s)
        .accept_rotation(response(rotation.rotation_id, 2), 230)
        .unwrap();
    let replacement = HostAuth::open(&mut s, cfg(), 231)
        .unwrap()
        .revocation_ack_request(231)
        .unwrap();
    assert_ne!(
        original.refresh.expose_wire(),
        replacement.refresh.expose_wire()
    );
    let bytes = s.bytes.as_ref().unwrap().clone();
    let writes = s.writes;
    assert_eq!(
        open(&mut s).accept_revocation_ack(
            "https://auth.example",
            &original,
            revoke_result(13),
            232,
        ),
        Err(Error::InvalidResponse)
    );
    assert_eq!(open(&mut s).status(), Status::Ready);
    assert_eq!(s.bytes.as_ref().unwrap().as_slice(), bytes.as_slice());
    assert_eq!(s.writes, writes);
}

#[test]
fn uncertain_revocation_ack_publication_is_recovered_by_reopen() {
    let mut s = Memory::default();
    ready(&mut s);
    let request = HostAuth::open(&mut s, cfg(), 103)
        .unwrap()
        .revocation_ack_request(103)
        .unwrap();
    s.fault = Fault::Uncertain;
    let mut auth = open(&mut s);
    assert_eq!(
        auth.accept_revocation_ack("https://auth.example", &request, revoke_result(13), 104,),
        Err(Error::Storage(secrets::Error::CommitUncertain))
    );
    assert_eq!(auth.status(), Status::Sealed);
    drop(auth);
    let auth = open(&mut s);
    assert_eq!(auth.status(), Status::Revoked);
    assert_eq!(
        auth.revocation_acknowledgement().unwrap(),
        revoke_result(13)
    );
}

#[test]
fn revoke_credentials_are_endpoint_only_and_do_not_expand_general_access() {
    let mut s = Memory::default();
    ready(&mut s);
    assert_eq!(open(&mut s).access_credential(402), Err(Error::Expired));
    assert!(open(&mut s).revocation_credential().unwrap().expose_wire() == "access_secret_1");
    open(&mut s).prepare_rotation(403).unwrap();
    let request = rotation(&mut s).unwrap();
    assert_eq!(
        open(&mut s).access_credential(404),
        Err(Error::InvalidState)
    );
    assert!(open(&mut s).revocation_credential().unwrap().expose_wire() == "access_secret_1");
    assert_eq!(rotation(&mut s).unwrap(), request);
}

#[test]
fn cancel_and_revocation_write_faults_retain_exact_old_or_new_state() {
    for revoke in [false, true] {
        for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
            let mut s = Memory::default();
            if revoke {
                ready(&mut s);
                open(&mut s).prepare_rotation(200).unwrap();
            } else {
                pending(&mut s);
            }
            let bytes = s.bytes.as_ref().unwrap().clone();
            s.fault = fault;
            let mut a = open(&mut s);
            let result = if revoke {
                a.accept_tls_revocation("https://auth.example", revoke_result(13), 201)
            } else {
                a.cancel_pending_login(201)
            };
            assert!(result.is_err());
            if !matches!(fault, Fault::Before) {
                assert_eq!(a.status(), Status::Sealed);
                assert_eq!(a.revocation_credential(), Err(Error::Sealed));
                assert_eq!(a.cancel_pending_login(202), Err(Error::Sealed));
            }
            drop(a);
            if matches!(fault, Fault::Uncertain) {
                assert_eq!(
                    open(&mut s).status(),
                    if revoke {
                        Status::Revoked
                    } else {
                        Status::PendingInit
                    }
                );
            } else {
                assert!(s.bytes.as_ref().unwrap().as_slice() == bytes.as_slice());
            }
        }
    }
}

#[test]
fn approved_account_pin_survives_cancellation_and_verified_revocation() {
    for revoked in [false, true] {
        let mut s = Memory::default();
        if revoked {
            ready(&mut s);
            open(&mut s)
                .accept_tls_revocation("https://auth.example", revoke_result(12), 104)
                .unwrap();
            open(&mut s).restart_after_revocation(104).unwrap();
        } else {
            open(&mut s).initialize().unwrap();
            approval(&mut s);
            open(&mut s).cancel_pending_login(104).unwrap();
        }
        let identity = stored_identity(&s);
        // A correctly bound challenge approved by the trusted origin for another
        // account still cannot rebind the same persistent host identity.
        assert_eq!(
            approval_for(&mut s, [9; 16], 105),
            Err(Error::InvalidResponse)
        );
        assert!(stored_identity(&s).as_slice() == identity.as_slice());
        open(&mut s).cancel_pending_login(107).unwrap();
        approval_for(&mut s, [4; 16], 108).unwrap();
        assert_eq!(open(&mut s).status(), Status::Approved);
    }
}

#[test]
fn v2_account_pin_migration_preserves_schedule_and_rotation_intent() {
    for stage in 0..7 {
        let mut s = Memory::default();
        match stage {
            0 => open(&mut s).initialize().unwrap(),
            1 => pending(&mut s),
            2 => {
                open(&mut s).initialize().unwrap();
                approval(&mut s);
            }
            3 => prepared(&mut s),
            4 => unconfirmed(&mut s),
            _ => ready(&mut s),
        }
        if stage == 6 {
            open(&mut s).prepare_rotation(200).unwrap();
        }
        let status = open(&mut s).status();
        let rotation = if stage == 6 {
            Some(rotation(&mut s).unwrap())
        } else {
            None
        };
        remove_account_pin(s.bytes.as_mut().unwrap());
        replace_bytes(
            s.bytes.as_mut().unwrap(),
            b"\"version\":3",
            b"\"version\":2",
        );
        let writes = s.writes;
        let mut a = HostAuth::open(&mut s, cfg(), 200).unwrap();
        assert_eq!(a.status(), status);
        if stage == 1 {
            assert_eq!(a.enrollment_presentation(200).unwrap().next_poll_at, 105);
        }
        if let Some(request) = rotation {
            assert_eq!(a.rotation_request(200).unwrap(), request);
        }
        if stage == 2 {
            a.cancel_pending_login(201).unwrap();
        }
        drop(a);
        assert_eq!(s.writes, writes + 1 + usize::from(stage == 2));
        if stage == 2 {
            assert_eq!(
                approval_for(&mut s, [9; 16], 202),
                Err(Error::InvalidResponse)
            );
        }
    }
    for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
        let mut s = Memory::default();
        ready(&mut s);
        open(&mut s).prepare_rotation(200).unwrap();
        let request = rotation(&mut s).unwrap();
        remove_account_pin(s.bytes.as_mut().unwrap());
        replace_bytes(
            s.bytes.as_mut().unwrap(),
            b"\"version\":3",
            b"\"version\":2",
        );
        s.fault = fault;
        assert!(matches!(
            HostAuth::open(&mut s, cfg(), 201),
            Err(Error::Storage(_))
        ));
        assert_eq!(
            HostAuth::open(&mut s, cfg(), 201)
                .unwrap()
                .rotation_request(201)
                .unwrap(),
            request
        );
    }
}

#[test]
fn v3_account_pin_is_required_and_matches_authenticated_state() {
    for mutation in 0..4 {
        let mut s = Memory::default();
        ready(&mut s);
        match mutation {
            0 => remove_account_pin(s.bytes.as_mut().unwrap()),
            1 => {
                let bytes = s.bytes.as_mut().unwrap();
                let needle = b"\"account_pin\":{\"account\":";
                let at = bytes
                    .windows(needle.len())
                    .position(|w| w == needle)
                    .unwrap()
                    + needle.len();
                let end = at + bytes[at..].iter().position(|b| *b == b'}').unwrap();
                bytes.splice(at..end, b"null".iter().copied());
            }
            2 => {
                let bytes = s.bytes.as_mut().unwrap();
                let needle = b"\"account_pin\":{\"account\":\"";
                let at = bytes
                    .windows(needle.len())
                    .position(|w| w == needle)
                    .unwrap()
                    + needle.len();
                // Account UUID remains syntactically valid, but differs.
                bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
            }
            _ => {
                let bytes = s.bytes.as_mut().unwrap();
                let needle = b"\"account_pin\":{";
                let at = bytes
                    .windows(needle.len())
                    .position(|w| w == needle)
                    .unwrap()
                    + needle.len();
                let end = at + bytes[at..].iter().position(|b| *b == b'}').unwrap();
                bytes.drain(at..end);
            }
        }
        let writes = s.writes;
        assert!(matches!(
            HostAuth::open(&mut s, cfg(), 300),
            Err(Error::InvalidBundle)
        ));
        assert_eq!(s.writes, writes);
    }
}

#[test]
fn retained_revocation_ack_survives_crash_until_explicit_new_login() {
    let mut s = Memory::default();
    ready(&mut s);
    open(&mut s).prepare_rotation(200).unwrap();
    let identity = stored_identity(&s);
    // Secret-provider publication succeeds, then owner crashes before its
    // separate SQLite pending-revoke acknowledgement. Reopen recovers the ACK.
    open(&mut s)
        .accept_tls_revocation("https://auth.example", revoke_result(13), 201)
        .unwrap();
    for now in [201, 202, 1000] {
        let writes = s.writes;
        let mut a = HostAuth::open(&mut s, cfg(), now).unwrap();
        assert_eq!(a.status(), Status::Revoked);
        assert_eq!(a.revocation_acknowledgement().unwrap(), revoke_result(13));
        assert_eq!(a.init_request(), Err(Error::InvalidState));
        assert_eq!(a.device_poll_credential(now), Err(Error::InvalidState));
        assert_eq!(a.access_credential(now), Err(Error::InvalidState));
        assert_eq!(a.revocation_credential(), Err(Error::InvalidState));
        assert_eq!(a.rotation_request(now), Err(Error::InvalidState));
        assert_eq!(a.cancel_pending_login(now), Err(Error::InvalidState));
        drop(a);
        assert_eq!(s.writes, writes);
    }
    // Owner finishes its handoff, then receives explicit new LoginStart.
    open(&mut s).restart_after_revocation(1000).unwrap();
    assert_eq!(open(&mut s).status(), Status::PendingInit);
    assert!(stored_identity(&s).as_slice() == identity.as_slice());
    assert_eq!(
        open(&mut s).revocation_acknowledgement(),
        Err(Error::InvalidState)
    );
    assert!(open(&mut s).init_request().is_ok());
    approval_for(&mut s, [4; 16], 1001).unwrap();
    assert_eq!(
        open(&mut s).revocation_acknowledgement(),
        Err(Error::InvalidState)
    );
    assert_eq!(
        open(&mut s).accept_tls_revocation("https://auth.example", revoke_result(13), 1002),
        Err(Error::InvalidState)
    );
}

#[test]
fn retained_revocation_ack_and_restart_obey_uncertain_publication() {
    for restart in [false, true] {
        for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
            let mut s = Memory::default();
            ready(&mut s);
            if restart {
                open(&mut s)
                    .accept_tls_revocation("https://auth.example", revoke_result(13), 201)
                    .unwrap();
            }
            s.fault = fault;
            let mut a = open(&mut s);
            let result = if restart {
                a.restart_after_revocation(202)
            } else {
                a.accept_tls_revocation("https://auth.example", revoke_result(13), 201)
            };
            assert!(result.is_err());
            if !matches!(fault, Fault::Before) {
                assert_eq!(a.status(), Status::Sealed);
                assert_eq!(a.revocation_acknowledgement(), Err(Error::Sealed));
            }
            drop(a);
            let a = open(&mut s);
            let published = matches!(fault, Fault::Uncertain);
            let ack_present = if restart { !published } else { published };
            if ack_present {
                assert_eq!(a.revocation_acknowledgement().unwrap(), revoke_result(13));
            } else {
                assert_eq!(a.revocation_acknowledgement(), Err(Error::InvalidState));
            }
        }
    }
}

#[test]
fn malformed_retained_revocation_ack_fails_closed() {
    let mut s = Memory::default();
    ready(&mut s);
    open(&mut s)
        .accept_tls_revocation("https://auth.example", revoke_result(13), 201)
        .unwrap();
    let original = s.bytes.as_ref().unwrap().clone();
    for (needle, replacement) in [
        (
            b"\"prior_epoch\":12".as_slice(),
            b"\"prior_epoch\":0".as_slice(),
        ),
        (
            b"\"acknowledged_epoch\":13".as_slice(),
            b"\"acknowledged_epoch\":11".as_slice(),
        ),
        (
            b"\"account_pin\":{\"account\":".as_slice(),
            b"\"unknown_pin\":{\"account\":".as_slice(),
        ),
        (b"\"version\":3".as_slice(), b"\"version\":2".as_slice()),
    ] {
        s.bytes = Some(original.clone());
        replace_bytes(s.bytes.as_mut().unwrap(), needle, replacement);
        let writes = s.writes;
        assert!(matches!(
            HostAuth::open(&mut s, cfg(), 202),
            Err(Error::InvalidBundle)
        ));
        assert_eq!(s.writes, writes);
    }
}

fn scoped_context(
    binding: &lomi_host_auth::PublicHostIdentity,
    now: u64,
) -> (
    lomi_remote_crypto::Identity,
    lomi_remote_crypto::ChannelContextV3,
    lomi_remote_crypto::CurrentAuthorityV3,
) {
    use lomi_remote_crypto::*;
    let consumer =
        Identity::generate(binding.account_id.to_bytes(), [30; 16], Role::Device, 1).unwrap();
    let grant = GrantV3 {
        version: 3,
        api_major: 2,
        application_major: 2,
        account_id: binding.account_id.to_bytes(),
        host_id: binding.host_id.to_bytes(),
        host_fingerprint: binding.fingerprint,
        host_authorization_id: binding.host_authorization_id.to_bytes(),
        access_epoch: binding.access_epoch,
        consumer_authorization_id: [31; 16],
        account_session_id: "independent_session".into(),
        consumer_id: [30; 16],
        consumer_fingerprint: consumer.public_bundle().bundle.fingerprint().unwrap(),
        grant_id: [32; 16],
        grant_revision: 1,
        workspace_id: [33; 16],
        workspace_epoch: [34; 16],
        runtime_id: [35; 16],
        runtime_generation: 1,
        capabilities: CapabilitySet::try_from(vec![Capability::WorkspaceRead]).unwrap(),
        nonce: [36; 32],
        expires_at: now + 100,
        purpose: GrantPurposeV3::Workspace,
    };
    let current = CurrentAuthorityV3 {
        host_authorization_id: grant.host_authorization_id,
        consumer_authorization_id: grant.consumer_authorization_id,
        account_session_id: grant.account_session_id.clone(),
        access_epoch: grant.access_epoch,
        grant_revision: grant.grant_revision,
        workspace_epoch: grant.workspace_epoch,
        runtime_id: grant.runtime_id,
        runtime_generation: grant.runtime_generation,
        terminal_membership: None,
    };
    let context = ChannelContextV3 {
        version: 3,
        grant,
        channel_id: [37; 16],
        initiator_role: Role::Device,
        responder_role: Role::Host,
        purpose: ChannelPurposeV3::Workspace,
        terminal: None,
        issued_at: now,
        expires_at: now + 30,
    };
    (consumer, context, current)
}

#[test]
fn scoped_crypto_checks_saved_binding_family_epoch_expiry_and_clock() {
    let mut s = Memory::default();
    ready(&mut s);
    let auth = open(&mut s);
    let public = auth.public_host_identity(104).unwrap();
    let (_, context, _) = scoped_context(&public, 104);
    auth.sign_grant_v3(&context.grant, 104).unwrap();
    auth.sign_channel_admission_v3(&context, 104).unwrap();
    let identity = lomi_remote_crypto::SignedBundle::from_wire(&public.identity).unwrap();
    assert_eq!(identity.bundle.fingerprint().unwrap(), public.fingerprint);
    for field in ["account", "host", "fingerprint", "family", "epoch"] {
        let mut changed = context.clone();
        match field {
            "account" => changed.grant.account_id[0] ^= 1,
            "host" => changed.grant.host_id[0] ^= 1,
            "fingerprint" => changed.grant.host_fingerprint[0] ^= 1,
            "family" => changed.grant.host_authorization_id[0] ^= 1,
            "epoch" => changed.grant.access_epoch += 1,
            _ => unreachable!(),
        }
        assert!(auth.sign_grant_v3(&changed.grant, 104).is_err(), "{field}");
        assert!(
            auth.sign_channel_admission_v3(&changed, 104).is_err(),
            "{field}"
        );
    }
    let mut expired = context.clone();
    expired.grant.expires_at = 104;
    assert_eq!(auth.sign_grant_v3(&expired.grant, 104), Err(Error::Expired));
    expired = context.clone();
    expired.issued_at = 103;
    expired.expires_at = 104;
    assert_eq!(
        auth.sign_channel_admission_v3(&expired, 104),
        Err(Error::Expired)
    );
    assert_eq!(auth.public_host_identity(103), Err(Error::ClockRollback));
    assert_eq!(auth.public_host_identity(402), Err(Error::Expired));
    assert_eq!(auth.sign_grant_v3(&context.grant, 402), Err(Error::Expired));
    assert_eq!(
        auth.sign_channel_admission_v3(&context, 402),
        Err(Error::Expired)
    );
}

fn runtime_snapshot(epoch: u64) -> HostRuntimeGetResult {
    HostRuntimeGetResult {
        host_id: HostId::from_bytes([1; 16]).unwrap(),
        host_access_epoch: DecimalU64(epoch),
        runtime_generation: DecimalU64(7),
        runtime: Some(RuntimeBinding {
            runtime_id: RuntimeId::from_bytes([9; 16]).unwrap(),
            runtime_generation: DecimalU64(7),
            host_access_epoch: DecimalU64(epoch),
        }),
        publication_seq: DecimalU64(3),
        lease_ms: DecimalU64(30_000),
        freshness_ms: DecimalU64(5_000),
    }
}

#[test]
fn runtime_observation_advances_durably_and_rejects_prior_epoch_signing() {
    let mut s = Memory::default();
    ready(&mut s);
    let original = open(&mut s).public_host_identity(104).unwrap();
    let (_, old_context, _) = scoped_context(&original, 104);
    let before = Zeroizing::new(s.bytes.as_ref().unwrap().to_vec());
    let writes = s.writes;
    open(&mut s)
        .accept_runtime_observation(DecimalU64(12), runtime_snapshot(13), 105)
        .unwrap();
    assert_eq!(s.writes, writes + 1);
    // Only the epoch and the existing persisted observation watermark change.
    let changed_epoch = Zeroizing::new(
        std::str::from_utf8(&before)
            .unwrap()
            .replace("\"epoch\":12", "\"epoch\":13"),
    );
    let expected =
        Zeroizing::new(changed_epoch.replace("\"observed_at\":103", "\"observed_at\":105"));
    assert!(s.bytes.as_ref().unwrap().as_slice() == expected.as_bytes());
    {
        let auth = open(&mut s);
        let mut expected_public = original;
        expected_public.access_epoch = 13;
        assert_eq!(auth.public_host_identity(105).unwrap(), expected_public);
        assert_eq!(
            auth.sign_grant_v3(&old_context.grant, 105),
            Err(Error::InvalidBundle)
        );
        assert_eq!(
            auth.sign_channel_admission_v3(&old_context, 105),
            Err(Error::InvalidBundle)
        );
        let (_, current, _) = scoped_context(&expected_public, 105);
        auth.sign_grant_v3(&current.grant, 105).unwrap();
        auth.sign_channel_admission_v3(&current, 105).unwrap();
    }
    let saved = Zeroizing::new(s.bytes.as_ref().unwrap().to_vec());
    assert_eq!(
        open(&mut s).accept_runtime_observation(DecimalU64(12), runtime_snapshot(13), 106),
        Err(Error::InvalidResponse)
    );
    open(&mut s)
        .accept_runtime_observation(DecimalU64(13), runtime_snapshot(13), 106)
        .unwrap();
    assert_eq!(s.writes, writes + 1);
    assert!(s.bytes.as_ref().unwrap().as_slice() == saved.as_slice());
}

#[test]
fn runtime_observation_validates_full_snapshot_before_equal_epoch_retry() {
    let mut s = Memory::default();
    ready(&mut s);
    let saved = Zeroizing::new(s.bytes.as_ref().unwrap().to_vec());
    let writes = s.writes;
    for epoch in [12, 13] {
        for case in 0..15 {
            let mut snapshot = runtime_snapshot(epoch);
            let mut expected = DecimalU64(12);
            match case {
                0 => expected = DecimalU64(11),
                1 => snapshot.host_id = HostId::from_bytes([2; 16]).unwrap(),
                2 => snapshot.host_access_epoch = DecimalU64(11),
                3 => snapshot.host_access_epoch = DecimalU64(0),
                4 => snapshot.host_access_epoch = DecimalU64(i64::MAX as u64 + 1),
                5 => snapshot.runtime_generation = DecimalU64(i64::MAX as u64 + 1),
                6 => snapshot.publication_seq = DecimalU64(i64::MAX as u64 + 1),
                7 => snapshot.runtime_generation = DecimalU64(0),
                8 => snapshot.runtime.as_mut().unwrap().runtime_generation = DecimalU64(8),
                9 => snapshot.runtime.as_mut().unwrap().host_access_epoch = DecimalU64(14),
                10 => snapshot.lease_ms = DecimalU64(30_001),
                11 => snapshot.freshness_ms = DecimalU64(5_001),
                12 => snapshot.lease_ms = DecimalU64(4_999),
                13 => snapshot.lease_ms = DecimalU64(0),
                14 => expected = DecimalU64(13),
                _ => unreachable!(),
            }
            assert_eq!(
                open(&mut s).accept_runtime_observation(expected, snapshot, 104),
                Err(Error::InvalidResponse),
                "epoch {epoch}, case {case}"
            );
        }
        for field in 0..3 {
            let mut snapshot = runtime_snapshot(epoch);
            snapshot.runtime = None;
            snapshot.publication_seq = DecimalU64(0);
            snapshot.lease_ms = DecimalU64(0);
            snapshot.freshness_ms = DecimalU64(0);
            match field {
                0 => snapshot.publication_seq = DecimalU64(1),
                1 => snapshot.lease_ms = DecimalU64(1),
                2 => snapshot.freshness_ms = DecimalU64(1),
                _ => unreachable!(),
            }
            assert_eq!(
                open(&mut s).accept_runtime_observation(DecimalU64(12), snapshot, 104),
                Err(Error::InvalidResponse)
            );
        }
    }
    assert_eq!(s.writes, writes);
    assert!(s.bytes.as_ref().unwrap().as_slice() == saved.as_slice());
}

#[test]
fn runtime_observation_accepts_retained_generation_and_expired_binding() {
    for generation in [0, 7, i64::MAX as u64] {
        let mut s = Memory::default();
        ready(&mut s);
        let mut snapshot = runtime_snapshot(13);
        snapshot.runtime = None;
        snapshot.runtime_generation = DecimalU64(generation);
        snapshot.publication_seq = DecimalU64(0);
        snapshot.lease_ms = DecimalU64(0);
        snapshot.freshness_ms = DecimalU64(0);
        open(&mut s)
            .accept_runtime_observation(DecimalU64(12), snapshot, 104)
            .unwrap();
        assert_eq!(
            open(&mut s).public_host_identity(104).unwrap().access_epoch,
            13
        );
    }
    let mut s = Memory::default();
    ready(&mut s);
    let mut snapshot = runtime_snapshot(i64::MAX as u64);
    snapshot.runtime_generation = DecimalU64(i64::MAX as u64);
    snapshot.runtime.as_mut().unwrap().runtime_generation = snapshot.runtime_generation;
    snapshot.publication_seq = DecimalU64(i64::MAX as u64);
    snapshot.lease_ms = DecimalU64(0);
    snapshot.freshness_ms = DecimalU64(0);
    open(&mut s)
        .accept_runtime_observation(DecimalU64(12), snapshot, 104)
        .unwrap();
    assert_eq!(
        open(&mut s).public_host_identity(104).unwrap().access_epoch,
        i64::MAX as u64
    );
}

#[test]
fn runtime_observation_requires_fresh_ready_and_monotonic_time() {
    let mut s = Memory::default();
    ready(&mut s);
    {
        let mut auth = open(&mut s);
        auth.public_host_identity(105).unwrap();
        assert_eq!(
            auth.accept_runtime_observation(DecimalU64(12), runtime_snapshot(13), 104),
            Err(Error::ClockRollback)
        );
        assert_eq!(
            auth.accept_runtime_observation(DecimalU64(12), runtime_snapshot(13), 402),
            Err(Error::Expired)
        );
    }
    for stage in 0..8 {
        let mut s = Memory::default();
        match stage {
            0 => {}
            1 => open(&mut s).initialize().unwrap(),
            2 => {
                open(&mut s).initialize().unwrap();
                open(&mut s).accept_initiation(initiation(), 100).unwrap();
            }
            3 => {
                open(&mut s).initialize().unwrap();
                approval(&mut s);
            }
            4 => prepared(&mut s),
            5 => unconfirmed(&mut s),
            6 => {
                ready(&mut s);
                open(&mut s).prepare_rotation(104).unwrap();
            }
            7 => {
                ready(&mut s);
                open(&mut s)
                    .accept_tls_revocation("https://auth.example", revoke_result(13), 104)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            open(&mut s).accept_runtime_observation(DecimalU64(12), runtime_snapshot(13), 104),
            Err(Error::InvalidState),
            "stage {stage}"
        );
    }
}

#[test]
fn runtime_observation_preserves_old_epoch_on_failure_and_seals_uncertainty() {
    for fault in [Fault::Before, Fault::Uncertain, Fault::UncertainOld] {
        let mut s = Memory::default();
        ready(&mut s);
        s.fault = fault;
        {
            let mut auth = open(&mut s);
            let error = auth
                .accept_runtime_observation(DecimalU64(12), runtime_snapshot(13), 104)
                .unwrap_err();
            if matches!(fault, Fault::Before) {
                assert_eq!(error, Error::Storage(secrets::Error::Io));
                assert_eq!(auth.public_host_identity(104).unwrap().access_epoch, 12);
                auth.accept_runtime_observation(DecimalU64(12), runtime_snapshot(13), 104)
                    .unwrap();
            } else {
                assert_eq!(error, Error::Storage(secrets::Error::CommitUncertain));
                assert_eq!(auth.status(), Status::Sealed);
                assert_eq!(
                    auth.accept_runtime_observation(DecimalU64(12), runtime_snapshot(13), 104),
                    Err(Error::Sealed)
                );
                assert_eq!(auth.public_host_identity(104), Err(Error::Sealed));
            }
        }
        let expected = if matches!(fault, Fault::UncertainOld) {
            12
        } else {
            13
        };
        assert_eq!(
            open(&mut s).public_host_identity(104).unwrap().access_epoch,
            expected
        );
    }
}

#[test]
fn scoped_crypto_rejects_nonready_and_uncertain_storage() {
    // A legitimate grant from the same retained identity is insufficient while
    // lifecycle intent or registration remains unresolved.
    let mut s = Memory::default();
    ready(&mut s);
    let public = open(&mut s).public_host_identity(104).unwrap();
    let (_, context, _) = scoped_context(&public, 104);
    open(&mut s).prepare_rotation(104).unwrap();
    {
        let auth = open(&mut s);
        assert_eq!(auth.public_host_identity(104), Err(Error::InvalidState));
        assert!(auth.sign_grant_v3(&context.grant, 104).is_err());
        assert!(auth.sign_channel_admission_v3(&context, 104).is_err());
    }
    open(&mut s)
        .accept_tls_revocation("https://auth.example", revoke_result(13), 105)
        .unwrap();
    assert_eq!(
        open(&mut s).public_host_identity(105),
        Err(Error::InvalidState)
    );
    for stage in 0..6 {
        let mut s = Memory::default();
        match stage {
            0 => {}
            1 => open(&mut s).initialize().unwrap(),
            2 => {
                open(&mut s).initialize().unwrap();
                open(&mut s).accept_initiation(initiation(), 100).unwrap();
            }
            3 => {
                open(&mut s).initialize().unwrap();
                approval(&mut s);
            }
            4 => prepared(&mut s),
            5 => unconfirmed(&mut s),
            _ => unreachable!(),
        }
        let auth = open(&mut s);
        assert!(auth.public_host_identity(104).is_err());
        assert!(auth.sign_grant_v3(&context.grant, 104).is_err());
        assert!(auth.sign_channel_admission_v3(&context, 104).is_err());
    }
    let mut s = Memory::default();
    ready(&mut s);
    s.fault = Fault::Uncertain;
    let mut auth = open(&mut s);
    assert!(auth.prepare_rotation(104).is_err());
    assert_eq!(auth.public_host_identity(104), Err(Error::Sealed));
    assert_eq!(auth.sign_grant_v3(&context.grant, 104), Err(Error::Sealed));
    assert_eq!(
        auth.sign_channel_admission_v3(&context, 104),
        Err(Error::Sealed)
    );
}

#[test]
fn scoped_host_responder_verifies_independent_authority_and_exchanges_noise() {
    use lomi_host_auth::HostChannelAdmissionV3;
    use lomi_remote_crypto::{Handshake, SignedBundle};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut s = Memory::default();
    open(&mut s).initialize().unwrap();
    approval_for(&mut s, [4; 16], now - 3).unwrap();
    open(&mut s).prepare_exchange(now - 1).unwrap();
    let op = open(&mut s).exchange_request(now - 1).unwrap().operation_id;
    open(&mut s).accept_exchange(response(op, 1), now).unwrap();
    open(&mut s)
        .confirm_registration(HostRegisterResult {
            host_id: HostId::from_bytes([1; 16]).unwrap(),
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
    let auth = open(&mut s);
    let public = auth.public_host_identity(now).unwrap();
    let (consumer, context, current) = scoped_context(&public, now);
    let grant = auth.sign_grant_v3(&context.grant, now).unwrap();
    let admission = auth.sign_channel_admission_v3(&context, now).unwrap();
    let peer = consumer.public_bundle();
    let pin = peer.bundle.fingerprint().unwrap();
    let inputs = |current_authority| HostChannelAdmissionV3 {
        expected: &context,
        stored_grant: &grant,
        admission: &admission,
        consumer_identity: &peer,
        consumer_fingerprint: &pin,
        current_authority,
    };
    let mut stale = current.clone();
    stale.runtime_generation += 1;
    assert!(auth.start_host_channel_v3(inputs(&stale)).is_err());
    let mut host = auth.start_host_channel_v3(inputs(&current)).unwrap();
    let host_bundle = SignedBundle::from_wire(&public.identity).unwrap();
    let verified = admission
        .verify(
            &grant,
            &context,
            &host_bundle,
            &public.fingerprint,
            &peer,
            &pin,
            &current,
            now,
        )
        .unwrap();
    let mut browser = Handshake::new_v3(
        true,
        &consumer,
        verified,
        &host_bundle,
        &public.fingerprint,
        now,
    )
    .unwrap();
    host.read(&browser.write().unwrap()).unwrap();
    browser.read(&host.write().unwrap()).unwrap();
    host.read(&browser.write().unwrap()).unwrap();
    let mut host = host.finish().unwrap();
    let mut browser = browser.finish().unwrap();
    let request = browser
        .seal_binary([37; 16], b"browser to protected host")
        .unwrap();
    assert_eq!(
        &**host.open(&request).unwrap(),
        b"browser to protected host"
    );
    let reply = host.seal(b"protected host to browser").unwrap();
    assert_eq!(
        &**browser.open_binary([37; 16], &reply).unwrap(),
        b"protected host to browser"
    );
    let wrong_route = browser.seal_binary([38; 16], b"wrong channel").unwrap();
    assert!(host.open(&wrong_route).is_err());
    assert!(host.seal(b"closed after wrong channel").is_err());
    host.dispose();
    assert!(host.seal(b"closed").is_err());
}

#[test]
fn scoped_channel_start_uses_forward_wall_time_for_credential_freshness() {
    use lomi_host_auth::HostChannelAdmissionV3;
    use lomi_remote_crypto::{SignedChannelAdmissionV3, SignedGrantV3};
    let mut s = Memory::default();
    ready(&mut s);
    let auth = open(&mut s);
    // The persisted and trusted anchor is historical, and access expired at 402.
    let public = auth.public_host_identity(104).unwrap();
    let wall_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (consumer, context, current) = scoped_context(&public, wall_now);
    let peer = consumer.public_bundle();
    let pin = peer.bundle.fingerprint().unwrap();
    // Signature verification must never be reached: internally sampled forward
    // wall time expires the saved credential while this context remains live.
    let grant = SignedGrantV3 {
        grant: context.grant.clone(),
        signature: Vec::new(),
    };
    let admission = SignedChannelAdmissionV3 {
        context: context.clone(),
        signature: Vec::new(),
    };
    let result = auth.start_host_channel_v3(HostChannelAdmissionV3 {
        expected: &context,
        stored_grant: &grant,
        admission: &admission,
        consumer_identity: &peer,
        consumer_fingerprint: &pin,
        current_authority: &current,
    });
    assert!(matches!(result, Err(Error::Expired)));
}

// Authored/unrun: immutable public trust metadata performs no storage IO.
struct AccessorStorage {
    memory: Memory,
    calls: std::rc::Rc<std::cell::Cell<usize>>,
}
impl SecretStorage for AccessorStorage {
    fn status(&self) -> ProviderStatus {
        self.calls.set(self.calls.get() + 1);
        self.memory.status()
    }
    fn load(&self) -> Result<Option<SecretBundle>, secrets::Error> {
        self.calls.set(self.calls.get() + 1);
        self.memory.load()
    }
    fn replace(&mut self, bundle: &SecretBundle) -> Result<(), secrets::Error> {
        self.calls.set(self.calls.get() + 1);
        self.memory.replace(bundle)
    }
}
#[test]
fn trusted_configuration_returns_exact_config_without_storage_io_or_ready() {
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut storage = AccessorStorage {
        memory: Memory::default(),
        calls: calls.clone(),
    };
    let auth = HostAuth::open(&mut storage, cfg(), 0).unwrap();
    let before = calls.get();
    let first = auth.trusted_configuration() as *const Config;
    assert_eq!(auth.trusted_configuration(), &cfg());
    assert_eq!(first, auth.trusted_configuration() as *const Config);
    assert_eq!(calls.get(), before);
    assert_ne!(auth.status(), Status::Ready);
    assert_eq!(
        auth.registration_request(0).err(),
        Some(Error::InvalidState)
    );
    assert_eq!(calls.get(), before);
}
#[test]
fn trusted_configuration_is_readable_when_provider_is_sealed_without_reopening() {
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut storage = AccessorStorage {
        memory: Memory {
            fault: Fault::Uncertain,
            ..Memory::default()
        },
        calls: calls.clone(),
    };
    let mut auth = HostAuth::open(&mut storage, cfg(), 0).unwrap();
    assert_eq!(
        auth.initialize(),
        Err(Error::Storage(secrets::Error::CommitUncertain))
    );
    let before = calls.get();
    assert_eq!(auth.trusted_configuration(), &cfg());
    assert_ne!(auth.status(), Status::Ready);
    assert_eq!(auth.access_credential(0).err(), Some(Error::Sealed));
    assert_eq!(calls.get(), before);
}
