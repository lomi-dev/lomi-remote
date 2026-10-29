use lomi_remote_crypto::*;

fn scope() -> (Identity, PeerApproval, ChannelContext) {
    let host = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
    let device = Identity::generate([1; 16], [3; 16], Role::Device, 1).unwrap();
    let approval = PeerApproval {
        version: 2,
        account_id: [1; 16],
        host_id: [2; 16],
        device_id: [3; 16],
        host_fingerprint: host.public_bundle().bundle.fingerprint().unwrap(),
        device_fingerprint: device.public_bundle().bundle.fingerprint().unwrap(),
        pairing_nonce: [8; 32],
        grant_id: [4; 16],
        workspace_id: Some([9; 16]),
        workspace_epoch: Some([10; 16]),
        session_ids: vec![[6; 16]],
        session_epochs: vec![[11; 16]],
        permissions: Permissions::Control,
        access_epoch: 1,
        revision: 2,
        expires_at: 2000,
    };
    let context = ChannelContext {
        version: 2,
        account_id: [1; 16],
        host_id: [2; 16],
        device_id: [3; 16],
        initiator_role: Role::Device,
        responder_role: Role::Host,
        channel_id: [5; 16],
        grant_id: [4; 16],
        session_id: [6; 16],
        access_epoch: 1,
        revision: 2,
        workspace_id: Some([9; 16]),
        workspace_epoch: Some([10; 16]),
        session_epoch: Some([11; 16]),
        purpose: Some(ChannelPurpose::Terminal),
    };
    (host, approval, context)
}

#[test]
fn workspace_signature_rejects_tampering_even_when_expected_is_changed() {
    let (host, approval, _) = scope();
    let signed = host.sign_peer_approval(approval.clone()).unwrap();
    let bundle = host.public_bundle();
    signed
        .verify(&bundle, &approval.host_fingerprint, &approval, 1000, 1)
        .unwrap();
    let value = serde_json::to_value(&approval).unwrap();
    for field in value.as_object().unwrap().keys() {
        let mut changed = value.clone();
        let v = &mut changed[field];
        if let Some(a) = v.as_array_mut() {
            if a[0].is_array() {
                a[0][0] = serde_json::json!(7);
            } else {
                a[0] = serde_json::json!(a[0].as_u64().unwrap() ^ 1);
            }
        } else if let Some(n) = v.as_u64() {
            *v = serde_json::json!(n + 1);
        } else {
            *v = serde_json::json!("observe");
        }
        let changed: PeerApproval = serde_json::from_value(changed).unwrap();
        let mut forged = signed.clone();
        forged.approval = changed.clone();
        assert!(
            forged
                .verify(&bundle, &approval.host_fingerprint, &changed, 1000, 1)
                .is_err(),
            "{field}"
        );
    }
    let mut downgrade = signed;
    downgrade.approval.version = 1;
    downgrade.approval.workspace_id = None;
    downgrade.approval.workspace_epoch = None;
    downgrade.approval.session_epochs.clear();
    assert!(downgrade
        .verify(
            &bundle,
            &approval.host_fingerprint,
            &downgrade.approval,
            1000,
            1
        )
        .is_err());
}

#[test]
fn terminal_scope_rejects_every_context_change_and_stale_epoch() {
    let (_, approval, context) = scope();
    context.validate_approval(&approval).unwrap();
    let value = serde_json::to_value(&context).unwrap();
    for field in [
        "version",
        "account_id",
        "host_id",
        "device_id",
        "grant_id",
        "session_id",
        "access_epoch",
        "revision",
        "workspace_id",
        "workspace_epoch",
        "session_epoch",
        "purpose",
    ] {
        let mut changed = value.clone();
        let v = &mut changed[field];
        if let Some(a) = v.as_array_mut() {
            a[0] = serde_json::json!(a[0].as_u64().unwrap() ^ 1);
        } else if let Some(n) = v.as_u64() {
            *v = serde_json::json!(n + 1);
        } else {
            *v = serde_json::json!("metadata");
        }
        let changed: ChannelContext = serde_json::from_value(changed).unwrap();
        assert!(changed.validate_approval(&approval).is_err(), "{field}");
    }
    let mut restarted = approval.clone();
    restarted.session_epochs[0] = [12; 16];
    assert!(context.validate_approval(&restarted).is_err());
    let mut multi = approval;
    multi.session_ids.push([7; 16]);
    assert!(multi.canonical().is_err());
    multi.session_epochs.push([13; 16]);
    context.validate_approval(&multi).unwrap();
    let mut second = context.clone();
    second.session_id = [7; 16];
    second.session_epoch = Some([13; 16]);
    second.validate_approval(&multi).unwrap();
    multi.session_epochs.swap(0, 1);
    assert!(context.validate_approval(&multi).is_err());
    assert!(second.validate_approval(&multi).is_err());
}

#[test]
fn zero_sessions_only_authorize_exact_metadata_route() {
    let (host, mut approval, mut context) = scope();
    approval.session_ids.clear();
    approval.session_epochs.clear();
    let signed = host.sign_peer_approval(approval.clone()).unwrap();
    signed
        .verify(
            &host.public_bundle(),
            &approval.host_fingerprint,
            &approval,
            1000,
            1,
        )
        .unwrap();
    assert!(context.validate_approval(&approval).is_err());
    context.purpose = Some(ChannelPurpose::Metadata);
    context.session_id = approval.workspace_id.unwrap();
    context.session_epoch = approval.workspace_epoch;
    context.validate_approval(&approval).unwrap();
    context.session_id = [6; 16];
    assert!(context.validate().is_err());
    context.session_id = approval.workspace_id.unwrap();
    context.session_epoch = Some([11; 16]);
    assert!(context.validate().is_err());
}

#[test]
fn version_fields_counts_duplicates_and_bounds_are_strict() {
    let (_, approval, context) = scope();
    for field in ["workspace_id", "workspace_epoch", "session_epochs"] {
        let mut json = serde_json::to_value(&approval).unwrap();
        json.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<PeerApproval>(json)
            .unwrap()
            .canonical()
            .is_err());
    }
    for field in [
        "workspace_id",
        "workspace_epoch",
        "session_epoch",
        "purpose",
    ] {
        let mut json = serde_json::to_value(&context).unwrap();
        json.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<ChannelContext>(json)
            .unwrap()
            .canonical()
            .is_err());
    }
    let mut invalid = approval.clone();
    invalid.session_ids.push(invalid.session_ids[0]);
    invalid.session_epochs.push([12; 16]);
    assert!(invalid.canonical().is_err());
    invalid.session_ids = (0..33).map(|i| [i; 16]).collect();
    invalid.session_epochs = vec![[12; 16]; 33];
    assert!(invalid.canonical().is_err());
    invalid = approval;
    invalid.version = 1;
    assert!(invalid.canonical().is_err());
    let mut invalid = context;
    invalid.version = 1;
    assert!(invalid.canonical().is_err());
}

#[cfg(feature = "test-fixtures")]
#[test]
fn golden_workspace_vectors_match_canonical_bytes_and_signatures() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/workspace-v2.json")).unwrap();
    let host: SignedBundle = serde_json::from_value(value["host_bundle"].clone()).unwrap();
    let pin = host.bundle.fingerprint().unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    for purpose in ["terminal", "metadata"] {
        let vector = &value[purpose];
        let signed: SignedPeerApproval =
            serde_json::from_value(vector["approval"].clone()).unwrap();
        let context: ChannelContext = serde_json::from_value(vector["context"].clone()).unwrap();
        assert_eq!(
            hex(&signed.approval.canonical().unwrap()),
            vector["approval_canonical_hex"]
        );
        assert_eq!(
            hex(&context.canonical().unwrap()),
            vector["context_canonical_hex"]
        );
        signed
            .verify(&host, &pin, &signed.approval, 1000, 1)
            .unwrap();
        context.validate_approval(&signed.approval).unwrap();
        for (bytes, arity) in [
            (signed.approval.canonical().unwrap(), 18),
            (context.canonical().unwrap(), 17),
        ] {
            let mut decoder = minicbor::Decoder::new(&bytes);
            assert_eq!(decoder.array().unwrap(), Some(arity));
            for _ in 0..arity {
                decoder.skip().unwrap();
            }
            assert_eq!(decoder.position(), bytes.len());
        }
    }
}

#[test]
fn noise_authentication_binds_workspace_epoch_revision_and_purpose() {
    let (host, _, context) = scope();
    let device = Identity::generate([1; 16], [3; 16], Role::Device, 1).unwrap();
    let hb = host.public_bundle();
    let db = device.public_bundle();
    for field in [
        "workspace_id",
        "workspace_epoch",
        "session_epoch",
        "revision",
        "purpose",
    ] {
        let mut json = serde_json::to_value(&context).unwrap();
        if field == "purpose" {
            json["purpose"] = serde_json::json!("metadata");
            json["session_id"] = json["workspace_id"].clone();
            json["session_epoch"] = json["workspace_epoch"].clone();
        } else if field == "revision" {
            json[field] = serde_json::json!(3);
        } else {
            json[field][0] = serde_json::json!(42);
        }
        let altered: ChannelContext = serde_json::from_value(json).unwrap();
        let mut client = Handshake::new(
            true,
            &device,
            &context,
            &hb,
            &hb.bundle.fingerprint().unwrap(),
        )
        .unwrap();
        let mut server = Handshake::new(
            false,
            &host,
            &altered,
            &db,
            &db.bundle.fingerprint().unwrap(),
        )
        .unwrap();
        server.read(&client.write().unwrap()).unwrap();
        assert!(client.read(&server.write().unwrap()).is_err(), "{field}");
        assert!(client.write().is_err());
    }
}

#[cfg(feature = "test-fixtures")]
#[test]
fn legacy_json_and_canonical_bytes_remain_identical() {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/legacy-v1.json")).unwrap();
    let signed: SignedPeerApproval = serde_json::from_value(value["approval"].clone()).unwrap();
    let context: ChannelContext = serde_json::from_value(value["context"].clone()).unwrap();
    assert_eq!(serde_json::to_value(&signed).unwrap(), value["approval"]);
    assert_eq!(serde_json::to_value(&context).unwrap(), value["context"]);
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(&signed.approval.canonical().unwrap()),
        value["approval_canonical_hex"]
    );
    assert_eq!(
        hex(&context.canonical().unwrap()),
        value["context_canonical_hex"]
    );
    context.validate_approval(&signed.approval).unwrap();
}
