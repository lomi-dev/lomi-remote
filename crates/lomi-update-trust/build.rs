use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=LOMI_UPDATE_ROOT_FILE");
    println!("cargo:rerun-if-env-changed=LOMI_UPDATE_ROOT_SHA256");
    println!("cargo:rerun-if-env-changed=LOMI_RELEASE_NATIVE_SIGNER");
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
    fs::write(
        output.join("embedded_root.rs"),
        format!(
            "pub const ROOT: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/bootstrap-root.json\"));\npub const SHA256: &str = \"{expected}\";\n#[cfg(target_os = \"macos\")]\npub const MACOS_TEAM_ID: Option<&str> = {macos_team};\n"
        ),
    )
    .expect("cannot generate embedded public-root constants");
}
