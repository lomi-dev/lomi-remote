use super::*;

const AUTH: &str = "version = 1\nrevision = 1\n[authentication]\nversion = 1\norigin = 'https://identity.example'\nremoteApiOrigin = 'https://api.example'\nrelayEndpoint = 'wss://relay.example/v2/relay'\nclientId = 'host-client'\nprovider = 'protectedFile'\nprotectedFileAcknowledgement = 'osPermissionsOnly'\n";

#[test]
fn roundtrip_uses_the_canonical_dto() {
    let value = decode(AUTH.as_bytes()).unwrap();
    assert_eq!(
        value.authentication.as_ref().unwrap().client_id.as_str(),
        "host-client"
    );
    assert_eq!(decode(&encode(&value).unwrap()).unwrap(), value);
    let empty = Configuration {
        version: 1,
        revision: MAX_REVISION,
        authentication: None,
    };
    assert_eq!(decode(&encode(&empty).unwrap()).unwrap(), empty);
}
#[test]
fn malformed_unknown_duplicate_and_unsupported_inputs_are_opaque() {
    for input in [
        "",
        "version = 1",
        "revision = 1",
        "version = 1\nrevision = 0",
        "version = 2\nrevision = 1",
        "version = 1\nrevision = -1",
        "version = 1\nrevision = 9223372036854775808",
        "version = 1\nrevision = 18446744073709551616",
        "version = 1\nrevision = 1\nrevision = 2",
        "version = 1\nrevision = 1\nsecret = 'fixture-sensitive-value'",
        "version = [fixture-sensitive-value",
    ] {
        let error = decode(input.as_bytes()).unwrap_err();
        assert_eq!(error, Error::Invalid);
        assert_eq!(error.to_string(), "PUBLIC_CONFIG_INVALID");
        assert!(!format!("{error:?}").contains("fixture-sensitive-value"));
    }
    assert_eq!(decode(&[0xff]), Err(Error::Invalid));
    assert_eq!(
        decode(format!("{AUTH}unknown = 'fixture'\n").as_bytes()),
        Err(Error::Invalid)
    );
    assert_eq!(
        decode(format!("{AUTH}clientId = 'duplicate'\n").as_bytes()),
        Err(Error::Invalid)
    );
}
#[test]
fn provider_validation_is_explicit_after_deserialization_and_before_encoding() {
    let invalid = AUTH.replace("provider = 'protectedFile'", "provider = 'windowsDpapi'");
    assert_eq!(decode(invalid.as_bytes()), Err(Error::Invalid));
    let invalid = AUTH.replace("version = 1\norigin", "version = 2\norigin");
    assert_eq!(decode(invalid.as_bytes()), Err(Error::Invalid));
    let mut value = decode(AUTH.as_bytes()).unwrap();
    value
        .authentication
        .as_mut()
        .unwrap()
        .protected_file_acknowledgement = None;
    assert_eq!(encode(&value), Err(Error::Invalid));
}
#[test]
fn exact_limit_is_accepted_and_read_never_consumes_more_than_limit_plus_one() {
    let mut bytes = b"version = 1\nrevision = 1\n#".to_vec();
    bytes.resize(MAX_BYTES, b' ');
    assert!(decode(&bytes).is_ok());
    bytes.push(b' ');
    assert_eq!(decode(&bytes), Err(Error::TooLarge));
    bytes.resize(MAX_BYTES * 2, b' ');
    let mut reader = std::io::Cursor::new(bytes);
    assert_eq!(read(&mut reader), Err(Error::TooLarge));
    assert_eq!(reader.position(), (MAX_BYTES + 1) as u64);
}
