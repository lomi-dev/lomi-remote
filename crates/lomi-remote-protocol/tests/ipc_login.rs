use lomi_remote_protocol::{ipc::*, *};
use serde_json::json;
#[test]
fn auth_configuration_preserves_legacy_missing_pin_and_round_trips_explicit_pin() {
    let legacy = json!({"version":1,"origin":"https://identity.example","clientId":"host","provider":"protectedFile","keychainPath":null,"protectedFileAcknowledgement":"osPermissionsOnly"});
    let config: LocalAuthConfiguration = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(config.remote_api_origin, None);
    config.validate().unwrap();
    assert_eq!(serde_json::to_value(&config).unwrap(), legacy);
    let mut pinned = legacy;
    pinned["remoteApiOrigin"] = json!("https://remote.example");
    let config: LocalAuthConfiguration = serde_json::from_value(pinned.clone()).unwrap();
    config.validate().unwrap();
    assert_eq!(
        config.remote_api_origin.as_ref().unwrap().as_str(),
        "https://remote.example"
    );
    assert_eq!(serde_json::to_value(&config).unwrap(), pinned);
}

#[test]
fn auth_configuration_pin_keeps_strict_types_bounds_and_version() {
    let config = json!({"version":1,"origin":"https://identity.example","clientId":"host","provider":"protectedFile","keychainPath":null,"protectedFileAcknowledgement":"osPermissionsOnly","remoteApiOrigin":null});
    assert!(serde_json::from_value::<LocalAuthConfiguration>(config.clone()).is_ok());
    for pin in [
        json!(""),
        json!("x".repeat(181)),
        json!("https://remote.example\n"),
        json!(42),
        json!([]),
        json!({"origin":"https://remote.example"}),
    ] {
        let mut bad = config.clone();
        bad["remoteApiOrigin"] = pin;
        assert!(serde_json::from_value::<LocalAuthConfiguration>(bad).is_err());
    }
    let mut bad = config.clone();
    bad["remote_api_origin"] = json!("https://remote.example");
    assert!(serde_json::from_value::<LocalAuthConfiguration>(bad).is_err());
    let mut bad = config;
    bad["version"] = json!(2);
    assert!(
        serde_json::from_value::<LocalAuthConfiguration>(bad)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn auth_serialization_attribute_keeps_optional_pin_and_envelope_schemas() {
    let config = serde_json::to_value(schemars::schema_for!(LocalAuthConfiguration)).unwrap();
    assert_eq!(config["type"], json!("object"));
    assert_eq!(config["additionalProperties"], json!(false));
    assert_eq!(
        config["required"],
        json!(["version", "origin", "clientId", "provider"])
    );
    assert_eq!(
        config["properties"]["remoteApiOrigin"],
        json!({"anyOf":[{"$ref":"#/$defs/LocalAuthOrigin"},{"type":"null"}]})
    );
    let request = serde_json::to_value(schemars::schema_for!(LocalRequest)).unwrap();
    assert_eq!(
        request["properties"]["call"],
        json!({"$ref":"#/$defs/LocalCall"})
    );
    let response = serde_json::to_value(schemars::schema_for!(LocalResponse)).unwrap();
    assert_eq!(
        response["properties"]["result"],
        json!({"$ref":"#/$defs/Result_of_LocalResult_or_LocalError"})
    );
}

#[test]
fn auth_ipc_rejects_secret_fields_unknown_choices_and_positional_envelopes() {
    let config = json!({"version":1,"origin":"https://identity.example","clientId":"host","provider":"protectedFile","keychainPath":null,"protectedFileAcknowledgement":"osPermissionsOnly"});
    let request = json!({"version":{"major":1,"minor":0},"requestId":"11111111-1111-1111-1111-111111111111","call":{"method":"auth.configure","params":{"configuration":config,"operatorIntent":"confirmed"}}});
    assert!(serde_json::from_value::<LocalRequest>(request.clone()).is_ok());
    for key in [
        "deviceCode",
        "bootstrapToken",
        "accessToken",
        "refreshToken",
        "privateKey",
        "seed",
    ] {
        let mut bad = request.clone();
        bad["call"]["params"]["configuration"][key] = json!("synthetic-secret");
        assert!(serde_json::from_value::<LocalRequest>(bad).is_err());
    }
    let mut bad = request.clone();
    bad["call"]["params"]["configuration"]["provider"] = json!("automatic");
    assert!(serde_json::from_value::<LocalRequest>(bad).is_err());
    let mut bad = request.clone();
    bad["call"]["params"]["configuration"]["origin"] = json!("x".repeat(181));
    assert!(serde_json::from_value::<LocalRequest>(bad).is_err());
    let mut bad = request.clone();
    bad["call"]["params"] = json!([config, "confirmed"]);
    assert!(serde_json::from_value::<LocalRequest>(bad).is_err());
    assert!(
        serde_json::from_value::<LocalRequest>(json!([
            request["version"],
            request["requestId"],
            request["call"]
        ]))
        .is_err()
    );
    let positional = json!([
        1,
        "https://identity.example",
        "host",
        "protectedFile",
        null,
        "osPermissionsOnly"
    ]);
    assert!(serde_json::from_value::<LocalAuthConfiguration>(positional).is_err());
}
#[test]
fn presentation_is_explicit_and_debug_redacts_user_code() {
    let value = LocalLoginPresentation {
        user_code: "SYNTHETIC-CODE".to_owned().try_into().unwrap(),
        verification_url: "https://identity.example/device"
            .to_owned()
            .try_into()
            .unwrap(),
        expires_at: DecimalU64(10),
        next_poll_at: DecimalU64(5),
    };
    assert!(!format!("{value:?}").contains("SYNTHETIC-CODE"));
    assert!(
        serde_json::to_string(&value)
            .unwrap()
            .contains("SYNTHETIC-CODE")
    );
    assert!(
        serde_json::from_value::<LocalLoginStatus>(json!({"userCode":"SYNTHETIC-CODE"})).is_err()
    );
}

#[test]
fn request_and_response_envelopes_reject_nested_positional_call_and_result() {
    let id = "11111111-1111-1111-1111-111111111111";
    let request = json!({"version":{"major":1,"minor":0},"requestId":id,"call":["login.start",{"operationId":id}]});
    assert!(serde_json::from_value::<LocalRequest>(request).is_err());
    let response = json!({"version":{"major":1,"minor":0},"requestId":id,"result":{"Ok":["authConfigured",{}]}});
    assert!(serde_json::from_value::<LocalResponse>(response).is_err());
    let valid = json!({"version":{"major":1,"minor":0},"requestId":id,"result":{"Ok":{"type":"workspaces","value":[]}}});
    assert!(serde_json::from_value::<LocalResponse>(valid).is_ok());
}

#[test]
fn relay_endpoint_canonical_matrix_is_the_shared_native_wasm_sdk_source() {
    let corpus: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/local-relay/wire.json"
    ))
    .unwrap();
    for case in corpus {
        let value = &case["value"];
        let accepted = case["accepted"].as_bool().unwrap();
        assert_eq!(
            decode_local_request(&encode_local_frame(value).unwrap()).is_ok(),
            accepted,
            "case={}",
            case["name"]
        );
        let endpoint = &value["call"]["params"]["configuration"]["relayEndpoint"];
        if let Some(endpoint) = endpoint.as_str() {
            assert_eq!(
                LocalRelayEndpoint::try_from(endpoint.to_owned()).is_ok(),
                accepted,
                "case={}",
                case["name"]
            );
            assert_eq!(
                serde_json::from_value::<LocalRelayEndpoint>(json!(endpoint)).is_ok(),
                accepted,
                "case={}",
                case["name"]
            );
        }
    }
}
#[test]
fn relay_endpoint_has_exact_189_byte_boundary_and_strict_carrier_types() {
    let host = format!("{}.{}.{}", "a".repeat(56), "b".repeat(56), "c".repeat(60));
    let endpoint = format!("wss://{host}/v2/relay");
    assert_eq!(endpoint.len(), 189);
    let pin = LocalRelayEndpoint::try_from(endpoint.clone()).unwrap();
    assert_eq!(pin.as_str(), endpoint);
    assert_eq!(String::from(pin.clone()), endpoint);
    assert_eq!(serde_json::to_value(pin).unwrap(), json!(endpoint));
    assert!(LocalRelayEndpoint::try_from(format!("wss://x{host}/v2/relay")).is_err());
    for bad in [
        json!(null),
        json!(42),
        json!([]),
        json!({"endpoint":"wss://relay.example/v2/relay"}),
    ] {
        assert!(serde_json::from_value::<LocalRelayEndpoint>(bad).is_err());
    }
}
#[test]
fn relay_pin_legacy_null_omission_and_camelcase_schema_are_explicit() {
    let legacy = json!({"version":1,"origin":"https://identity.example","clientId":"host","provider":"protectedFile","keychainPath":null,"protectedFileAcknowledgement":"osPermissionsOnly"});
    for extra in [None, Some(json!(null))] {
        let mut wire = legacy.clone();
        if let Some(extra) = extra {
            wire["relayEndpoint"] = extra;
        }
        let config: LocalAuthConfiguration = serde_json::from_value(wire).unwrap();
        assert!(config.relay_endpoint.is_none());
        assert_eq!(serde_json::to_value(config).unwrap(), legacy);
    }
    let mut pinned = legacy.clone();
    pinned["relayEndpoint"] = json!("wss://relay.example/v2/relay");
    let config: LocalAuthConfiguration = serde_json::from_value(pinned.clone()).unwrap();
    assert_eq!(serde_json::to_value(config).unwrap(), pinned);
    let mut bad = legacy;
    bad["relay_endpoint"] = json!("wss://relay.example/v2/relay");
    assert!(serde_json::from_value::<LocalAuthConfiguration>(bad).is_err());
    let schema = serde_json::to_value(schemars::schema_for!(LocalAuthConfiguration)).unwrap();
    assert_eq!(
        schema["properties"]["relayEndpoint"],
        json!({"anyOf":[{"$ref":"#/$defs/LocalRelayEndpoint"},{"type":"null"}]})
    );
    assert_eq!(
        schema["required"],
        json!(["version", "origin", "clientId", "provider"])
    );
    let endpoint = &schema["$defs"]["LocalRelayEndpoint"];
    assert_eq!(endpoint["maxLength"], 189);
    assert_eq!(endpoint["x-lomi-maxUtf8Bytes"], 189);
    assert!(endpoint["if"].is_object());
    assert!(endpoint["then"].is_object());
}
