use sha2::{Digest, Sha256};
use std::{env, fs, io::Read, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=LOMI_UPDATE_ROOT_FILE");
    println!("cargo:rerun-if-env-changed=LOMI_UPDATE_ROOT_SHA256");
    println!("cargo:rerun-if-env-changed=LOMI_RELEASE_NATIVE_SIGNER");
    println!("cargo:rerun-if-env-changed=LOMI_LOCAL_TEST_CA_FILE");
    println!("cargo:rerun-if-env-changed=LOMI_LOCAL_TEST_CA_SHA256");
    if env::var_os("CARGO_FEATURE_RELEASE_ROOT").is_none() {
        return;
    }
    let root_path = env::var_os("LOMI_UPDATE_ROOT_FILE")
        .map(PathBuf::from)
        .expect("release-root requires operator-supplied LOMI_UPDATE_ROOT_FILE");
    let expected = env::var("LOMI_UPDATE_ROOT_SHA256")
        .expect("release-root requires the independently pinned LOMI_UPDATE_ROOT_SHA256")
        .to_ascii_lowercase();
    assert!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "LOMI_UPDATE_ROOT_SHA256 must be 64 lowercase hexadecimal characters"
    );
    let bytes = fs::read(&root_path).expect("cannot read operator-supplied public TUF root");
    assert!(
        !bytes.is_empty() && bytes.len() <= 1024 * 1024,
        "public TUF root exceeds limit"
    );
    let actual = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(
        actual == expected,
        "public TUF root does not match the independent digest pin"
    );
    let local_test_ca = if env::var_os("CARGO_FEATURE_LOCAL_RELEASE_TEST").is_some() {
        let ca_path = env::var_os("LOMI_LOCAL_TEST_CA_FILE")
            .map(PathBuf::from)
            .expect("local-release-test requires LOMI_LOCAL_TEST_CA_FILE");
        println!("cargo:rerun-if-changed={}", ca_path.display());
        let mut ca_file = fs::File::open(&ca_path).expect("cannot read local HTTPS test CA");
        let ca_file_metadata = ca_file
            .metadata()
            .expect("cannot inspect local HTTPS test CA");
        assert!(
            ca_file_metadata.is_file() && (128..=1024 * 1024).contains(&ca_file_metadata.len()),
            "local HTTPS test CA must be between 128 bytes and 1 MiB"
        );
        let mut ca_bytes = Vec::with_capacity(ca_file_metadata.len() as usize);
        ca_file
            .by_ref()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut ca_bytes)
            .expect("cannot read local HTTPS test CA");
        assert!(
            (128..=1024 * 1024).contains(&ca_bytes.len()),
            "local HTTPS test CA must be between 128 bytes and 1 MiB"
        );
        assert!(
            is_der_sequence(&ca_bytes),
            "local HTTPS test CA must be a single DER sequence"
        );
        let expected_ca = env::var("LOMI_LOCAL_TEST_CA_SHA256")
            .expect("local-release-test requires LOMI_LOCAL_TEST_CA_SHA256");
        let actual_ca = Sha256::digest(&ca_bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            actual_ca, expected_ca,
            "local HTTPS test CA differs from its digest pin"
        );
        Some(ca_bytes)
    } else {
        None
    };
    let macos_team = if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let team = env::var("LOMI_RELEASE_NATIVE_SIGNER")
            .ok()
            .filter(|value| !value.is_empty());
        if let Some(team) = &team {
            assert!(
                team.len() == 10
                    && team
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()),
                "LOMI_RELEASE_NATIVE_SIGNER must be the pinned macOS Team ID"
            );
        }
        assert!(
            env::var("PROFILE").as_deref() != Ok("release") || team.is_some(),
            "a macOS release-root release build requires LOMI_RELEASE_NATIVE_SIGNER"
        );
        match team {
            Some(team) => format!("Some(\"{team}\")"),
            None => "None".to_owned(),
        }
    } else {
        "None".to_owned()
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    fs::write(output.join("bootstrap-root.json"), bytes)
        .expect("cannot stage the public TUF root for embedding");
    if let Some(ca_bytes) = local_test_ca {
        fs::write(output.join("local-test-ca.der"), ca_bytes)
            .expect("cannot stage the local HTTPS test CA for embedding");
    }
    fs::write(
        output.join("embedded_root.rs"),
        format!(
            "pub const ROOT: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/bootstrap-root.json\"));\npub const SHA256: &str = \"{expected}\";\n#[cfg(target_os = \"macos\")]\npub const MACOS_TEAM_ID: Option<&str> = {macos_team};\n"
        ),
    )
    .expect("cannot generate embedded public-root constants");
}

fn is_der_sequence(bytes: &[u8]) -> bool {
    if bytes.first() != Some(&0x30) || bytes.len() < 2 {
        return false;
    }
    let first_length = bytes[1];
    let (header_len, content_len) = if first_length & 0x80 == 0 {
        (2, usize::from(first_length))
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > 4 || bytes.len() < 2 + length_bytes {
            return false;
        }
        if bytes[2] == 0 {
            return false;
        }
        let mut content_len = 0usize;
        for byte in &bytes[2..2 + length_bytes] {
            let Some(next) = content_len
                .checked_mul(256)
                .and_then(|length| length.checked_add(usize::from(*byte)))
            else {
                return false;
            };
            content_len = next;
        }
        if content_len < 128 {
            return false;
        }
        (2 + length_bytes, content_len)
    };
    header_len.checked_add(content_len) == Some(bytes.len())
}
