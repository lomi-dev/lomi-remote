use lomi_remote_protocol::*;

#[test]
fn authority_transport_vectors_match_native_wire_checks() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/authority-v2/wire.json"
    ))
    .unwrap();
    assert_eq!(cases.len(), 77);
    for case in cases {
        assert_eq!(
            validate_http_wire(
                case["schema"].as_str().unwrap(),
                &serde_json::to_string(&case["value"]).unwrap()
            )
            .is_ok(),
            case["accepted"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn original_text_duplicates_in_tagged_states_and_nested_inputs_fail() {
    let id = "11111111-1111-4111-8111-111111111111";
    for json in [
        format!(r#"{{"status":"denied","status":"expired","pairingId":"{id}"}}"#),
        format!(r#"{{"status":"denied","pairingId":"{id}","pairingId":"{id}"}}"#),
        format!(r#"{{"status":"denied","pairingId":"{id}","pairing\u0049d":"{id}"}}"#),
    ] {
        assert_eq!(
            validate_http_wire("PairingResult", &json),
            Err("INVALID_ARGUMENT")
        );
    }
    assert!(validate_http_wire("ConsumerAuthorizationIssueParams", "{} {}").is_err());
    assert!(validate_http_wire("ConsumerAuthorizationIssueParams", r#"{"class":"web"}"#).is_err());
    assert!(validate_http_wire("UnknownAuthorityDto", "{}").is_err());
    assert_eq!(
        validate_http_wire(
            "ConsumerAuthorizationIssueParams",
            &" ".repeat(CONTROL_MESSAGE_BYTES as usize + 1)
        ),
        Err("RESOURCE_EXHAUSTED")
    );
}

#[test]
fn admitted_channels_require_separate_host_admission_and_current_state() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/authority-v2/wire.json"
    ))
    .unwrap();
    let admitted = &cases
        .iter()
        .find(|v| {
            v["schema"] == "ChannelResult"
                && v["value"]["status"] == "admitted"
                && v["accepted"] == true
        })
        .unwrap()["value"];
    for path in ["admission", "inputs"] {
        let mut bad = admitted.clone();
        bad.as_object_mut().unwrap().remove(path);
        assert!(validate_http_wire("ChannelResult", &bad.to_string()).is_err());
    }
    for path in [
        "authority",
        "identities",
        "grant",
        "expectedContext",
        "expectedContextJson",
    ] {
        let mut bad = admitted.clone();
        bad["inputs"].as_object_mut().unwrap().remove(path);
        assert!(validate_http_wire("ChannelResult", &bad.to_string()).is_err());
    }
    let mut bad = admitted.clone();
    bad["inputs"]["authority"]["runtimeGeneration"] = serde_json::json!(1);
    assert!(validate_http_wire("ChannelResult", &bad.to_string()).is_err());
    let mut bad = admitted.clone();
    bad["inputs"]["unexpected"] = serde_json::json!(true);
    assert!(validate_http_wire("ChannelResult", &bad.to_string()).is_err());
}

#[test]
fn dto_deserialization_preserves_duplicate_and_unknown_field_checks() {
    let id = "11111111-1111-1111-1111-111111111111";
    let signature = "ab".repeat(64);
    for json in [
        format!(r#"{{"hostId":"{id}","hostId":"{id}","hostAccessEpoch":"1"}}"#),
        format!(r#"{{"hostId":"{id}","hostAccessEpoch":"1","extra":true}}"#),
    ] {
        assert!(serde_json::from_str::<HostRegisterResult>(&json).is_err());
    }
    for json in [
        format!(
            r#"{{"hostId":"{id}","identity":{{"canonicalCbor":"80","canonicalCbor":"80","signature":"{signature}"}}}}"#
        ),
        format!(
            r#"{{"hostId":"{id}","identity":{{"canonicalCbor":"80","signature":"{signature}","extra":true}}}}"#
        ),
    ] {
        assert!(serde_json::from_str::<HostRegisterParams>(&json).is_err());
    }
    assert!(serde_json::from_str::<ConsumerAuthorizationIssueParams>("{}").is_ok());
    assert!(serde_json::from_str::<ConsumerAuthorizationRevokeParams>("{}").is_ok());
}

#[test]
fn dto_objects_reject_tuples_at_root_and_nested_positions() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/authority-v2/wire.json"
    ))
    .unwrap();
    for case in cases
        .iter()
        .filter(|case| case["name"].as_str().unwrap().contains("/object-required/"))
    {
        let json = case["value"].to_string();
        // Exercise Deserialize directly, independently of the raw JSON checker.
        macro_rules! rejected {
            ($($ty:ident),+ $(,)?) => {
                match case["schema"].as_str().unwrap() {
                    $(stringify!($ty) => serde_json::from_str::<$ty>(&json).is_err(),)+
                    other => panic!("unhandled object regression schema: {other}"),
                }
            };
        }
        assert!(
            rejected!(
                ConsumerAuthorizationIssueParams,
                ConsumerAuthorizationRevokeParams,
                HostRegisterResult,
                ConsumerAuthorizationContext,
                ConsumerWindowRegisterParams,
                HostRegisterParams,
                HostRevocationAckParams,
                ChannelCreateParams,
                ChannelResult,
                ChannelCreateResult,
                ChannelPendingResult,
                InventoryResult,
            ),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn revocation_ack_wire_is_exact_and_its_refresh_secret_debug_is_redacted() {
    let id = "11111111-1111-4111-8111-111111111111";
    let wire = serde_json::json!({
        "hostAuthorizationId": id,
        "expectedHostAccessEpoch": "7",
        "refresh": "retained_refresh_proof"
    });
    assert!(validate_http_wire("HostRevocationAckParams", &wire.to_string()).is_ok());
    let parsed: HostRevocationAckParams = serde_json::from_value(wire.clone()).unwrap();
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("retained_refresh_proof"));
    assert!(debug.contains("REDACTED"));
    for bad in [
        serde_json::json!({"hostAuthorizationId":id,"expectedHostAccessEpoch":"7"}),
        serde_json::json!({"hostAuthorizationId":id,"expectedHostAccessEpoch":"7","refresh":"retained_refresh_proof","access":"ordinary_access"}),
        serde_json::json!({"hostAuthorizationId":id,"expectedHostAccessEpoch":7,"refresh":"retained_refresh_proof"}),
        serde_json::json!({"hostAuthorizationId":id,"expectedHostAccessEpoch":"07","refresh":"retained_refresh_proof"}),
        serde_json::json!({"hostAuthorizationId":id,"expectedHostAccessEpoch":"7","refresh":"bad proof"}),
    ] {
        assert!(validate_http_wire("HostRevocationAckParams", &bad.to_string()).is_err());
    }
    assert_eq!(
        serde_json::to_value(parsed).unwrap(),
        wire,
        "refresh proof stays in the exact request body DTO"
    );
}

#[test]
fn enrollment_revocation_ack_wire_is_closed_and_has_disjoint_outcomes() {
    let host = "11111111-1111-4111-8111-111111111111";
    let enrollment = "22222222-2222-4222-8222-222222222222";
    let operation = "33333333-3333-4333-8333-333333333333";
    let account = "44444444-4444-4444-8444-444444444444";
    let authorization = "55555555-5555-4555-8555-555555555555";
    let no_family = serde_json::json!({
        "outcome":"noFamily",
        "hostId":host,
        "enrollmentId":enrollment,
        "operationId":operation,
        "accountId":account
    });
    assert!(
        validate_http_wire("HostEnrollmentRevocationAckResult", &no_family.to_string()).is_ok()
    );
    let parsed: HostEnrollmentRevocationAckResult =
        serde_json::from_value(no_family.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), no_family);

    let revoked = serde_json::json!({
        "outcome":"revokedFamily",
        "hostId":host,
        "enrollmentId":enrollment,
        "operationId":operation,
        "accountId":account,
        "hostAuthorizationId":authorization,
        "familyHostAccessEpoch":"1",
        "hostAccessEpoch":"9223372036854775807"
    });
    assert!(validate_http_wire("HostEnrollmentRevocationAckResult", &revoked.to_string()).is_ok());
    let parsed: HostEnrollmentRevocationAckResult =
        serde_json::from_value(revoked.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), revoked);

    let mut invalid = vec![
        serde_json::json!({"outcome":"noFamily","hostId":host,"enrollmentId":enrollment,"operationId":operation,"accountId":account,"extra":true}),
        serde_json::json!({"outcome":"noFamily","hostId":host,"enrollmentId":enrollment,"operationId":operation,"accountId":account,"hostAuthorizationId":authorization}),
        serde_json::json!({"outcome":"noFamily","hostId":host,"enrollmentId":enrollment,"operationId":operation,"accountId":account,"familyHostAccessEpoch":"1"}),
        serde_json::json!({"outcome":"noFamily","hostId":host,"enrollmentId":enrollment,"operationId":operation,"accountId":account,"hostAccessEpoch":"1"}),
        serde_json::json!({"outcome":"revokedFamily","hostId":host,"enrollmentId":enrollment,"operationId":operation,"accountId":account,"hostAuthorizationId":authorization,"familyHostAccessEpoch":"1","hostAccessEpoch":"2","extra":true}),
    ];
    for epoch in [
        serde_json::json!(0),
        serde_json::json!("0"),
        serde_json::json!("01"),
        serde_json::json!(1),
        serde_json::json!("9223372036854775808"),
        serde_json::json!("18446744073709551615"),
    ] {
        let mut bad_family = revoked.clone();
        bad_family["familyHostAccessEpoch"] = epoch.clone();
        invalid.push(bad_family);
        let mut bad_host = revoked.clone();
        bad_host["hostAccessEpoch"] = epoch;
        invalid.push(bad_host);
    }
    for bad in invalid {
        assert!(validate_http_wire("HostEnrollmentRevocationAckResult", &bad.to_string()).is_err());
        assert!(serde_json::from_value::<HostEnrollmentRevocationAckResult>(bad).is_err());
    }

    for bad in [
        serde_json::json!({"outcome":"no_family","hostId":host,"enrollmentId":enrollment,"operationId":operation,"accountId":account}),
        serde_json::json!({"outcome":"other","hostId":host,"enrollmentId":enrollment,"operationId":operation,"accountId":account}),
        serde_json::json!({"outcome":"noFamily","hostId":"00000000-0000-0000-0000-000000000000","enrollmentId":enrollment,"operationId":operation,"accountId":account}),
    ] {
        assert!(serde_json::from_value::<HostEnrollmentRevocationAckResult>(bad).is_err());
    }

    let request = serde_json::json!({
        "enrollmentId":enrollment,
        "operationId":operation,
        "proof":{"canonicalCbor":"aa","signature":"ab".repeat(64)}
    });
    assert!(validate_http_wire("HostEnrollmentRevocationAckParams", &request.to_string()).is_ok());
    for field in ["hostId", "accountId", "unknown"] {
        let mut bad = request.clone();
        bad[field] = serde_json::json!(host);
        assert!(validate_http_wire("HostEnrollmentRevocationAckParams", &bad.to_string()).is_err());
    }
}

#[test]
fn bounded_publication_inventory_and_pending_lists_remain_arrays() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/authority-v2/wire.json"
    ))
    .unwrap();
    let mut inventory = cases
        .iter()
        .find(|case| case["schema"] == "InventoryResult" && case["accepted"] == true)
        .unwrap()["value"]
        .clone();
    let id = "11111111-1111-1111-1111-111111111111";
    inventory["hosts"][0]["workspaces"] = serde_json::json!([{
        "workspaceId": id,
        "workspaceEpoch": id,
        "terminals": [{"paneId": id, "sessionId": id, "sessionEpoch": id}]
    }]);
    assert!(serde_json::from_value::<InventoryResult>(inventory.clone()).is_ok());
    let publication = serde_json::json!({
        "runtime": inventory["hosts"][0]["runtime"],
        "expectedPublicationSeq": "0",
        "publicationSeq": "1",
        "workspaces": inventory["hosts"][0]["workspaces"]
    });
    assert!(serde_json::from_value::<PublicationParams>(publication).is_ok());
    for schema in ["PairingPendingResult", "ChannelPendingResult"] {
        let value = &cases
            .iter()
            .find(|case| case["schema"] == schema && case["accepted"] == true)
            .unwrap()["value"];
        assert!(validate_http_wire(schema, &value.to_string()).is_ok());
    }
}

#[test]
fn inventory_accepts_persisted_signed_host_commitment_and_rejects_bad_byte_lengths() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/authority-v2/wire.json"
    ))
    .unwrap();
    let mut inventory = cases
        .iter()
        .find(|case| case["schema"] == "InventoryResult" && case["accepted"] == true)
        .unwrap()["value"]
        .clone();
    let commitment = inventory["hosts"][0]["signedCommitment"].clone();
    assert!(serde_json::from_value::<InventoryResult>(inventory.clone()).is_ok());
    assert_eq!(
        commitment["descriptor"]["identityKey"]
            .as_array()
            .unwrap()
            .len(),
        32
    );

    inventory["hosts"][0]["signedCommitment"]["signature"] = serde_json::json!(vec![5; 63]);
    assert!(serde_json::from_value::<InventoryResult>(inventory.clone()).is_err());
    inventory["hosts"][0]["signedCommitment"] = commitment;
    inventory["hosts"][0]["signedCommitment"]["descriptor"]["mailboxKey"] =
        serde_json::json!(vec![4; 31]);
    assert!(serde_json::from_value::<InventoryResult>(inventory).is_err());

    assert!(
        serde_json::from_value::<SignedHostKeyCommitmentWire>(serde_json::json!([{}, []])).is_err()
    );
    assert!(
        serde_json::from_value::<HostKeyCommitmentDescriptor>(serde_json::json!([
            1,
            [],
            "host",
            1,
            [],
            [],
            []
        ]))
        .is_err()
    );
}

#[test]
fn runtime_lookup_vectors_validate_strict_structure_without_server_state_claims() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/authority-v2/runtime-get.json"
    ))
    .unwrap();
    for case in cases {
        let json = case["value"].to_string();
        let accepted = case["accepted"].as_bool().unwrap();
        assert_eq!(
            validate_http_wire("HostRuntimeGetResult", &json).is_ok(),
            accepted,
            "{}",
            case["name"]
        );
        assert_eq!(
            serde_json::from_str::<HostRuntimeGetResult>(&json).is_ok(),
            accepted,
            "{}",
            case["name"]
        );
    }
}

#[test]
fn runtime_lookup_rejects_duplicate_fields_and_has_no_get_params_kind() {
    let id = "11111111-1111-4111-8111-111111111111";
    let json = format!(
        r#"{{"hostId":"{id}","hostAccessEpoch":"1","runtimeGeneration":"0","runtime":null,"publicationSeq":"0","leaseMs":"0","freshnessMs":"0"}}"#
    );
    for duplicate in [
        json.replacen(
            "\"hostId\":",
            &format!("\"hostId\":\"{id}\",\"hostId\":"),
            1,
        ),
        json.replacen("\"runtime\":null", "\"runtime\":null,\"runtime\":null", 1),
        json.replacen(
            "\"leaseMs\":\"0\"",
            "\"leaseMs\":\"0\",\"leaseMs\":\"0\"",
            1,
        ),
    ] {
        assert!(validate_http_wire("HostRuntimeGetResult", &duplicate).is_err());
        assert!(serde_json::from_str::<HostRuntimeGetResult>(&duplicate).is_err());
    }
    assert!(validate_http_wire("RuntimeGetParams", "{}").is_err());
    assert!(validate_http_wire("HostRuntimeGetParams", "{}").is_err());
}
