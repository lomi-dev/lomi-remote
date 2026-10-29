use std::{env, fs, path::PathBuf};

const KEYS: [&str; 5] = [
    "LOMI_HOST_IDENTITY_ORIGIN",
    "LOMI_HOST_REMOTE_API_ORIGIN",
    "LOMI_HOST_RELAY_ENDPOINT",
    "LOMI_HOST_CLIENT_ID",
    "LOMI_HOST_REMOTE_WEB_ORIGIN",
];

fn canonical_authority(authority: &str) -> bool {
    let (hostname, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname.starts_with('.')
        || hostname.ends_with('.')
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || port.is_some_and(|value| {
            value.is_empty()
                || value.starts_with('0')
                || value == "443"
                || value.parse::<u16>().is_err()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return false;
    }
    let Some(last) = hostname.rsplit('.').next() else {
        return false;
    };
    let numeric_ending = last.bytes().all(|byte| byte.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
    !numeric_ending
        || hostname
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.to_string() == hostname)
}

fn canonical_https_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    !authority.is_empty()
        && !authority.contains(['/', '?', '#', '@', '\\'])
        && canonical_authority(authority)
}

fn canonical_release_origin(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let authority = &rest[..slash];
    let path = &rest[slash..];
    let components: Vec<_> = path.split('/').collect();
    value.len() <= 2048
        && !authority.is_empty()
        && canonical_authority(authority)
        && path.ends_with('/')
        && path.bytes().all(|byte| {
            byte == b'/'
                || byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'~' | b'-')
        })
        && components
            .get(1..components.len().saturating_sub(1))
            .is_some_and(|parts| {
                parts
                    .iter()
                    .all(|part| !part.is_empty() && !matches!(*part, "." | ".."))
            })
}

fn canonical_relay_endpoint(value: &str) -> bool {
    let Some(authority) = value
        .strip_prefix("wss://")
        .and_then(|rest| rest.strip_suffix("/v2/relay"))
    else {
        return false;
    };
    value.len() <= 189
        && !authority.is_empty()
        && canonical_authority(authority)
        && !authority.contains(['/', '?', '#', '@', '\\'])
}

fn rust_string(value: &str) -> String {
    format!("{value:?}")
}

fn linux_bootstrap_pins() -> Option<[String; 3]> {
    for key in [
        "LOMI_LINUX_RELEASE_ORIGIN",
        "LOMI_LINUX_PRIMARY_TARGET",
        "LOMI_LINUX_PLATFORM",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    if env::var_os("CARGO_FEATURE_LINUX_SETUP_HANDOFF").is_none() {
        return None;
    }
    let rust_target = env::var("TARGET").expect("Cargo sets TARGET");
    assert!(
        matches!(
            rust_target.as_str(),
            "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
        ),
        "linux-setup-handoff is supported only for the Linux x86_64 and aarch64 release targets"
    );
    let origin = env::var("LOMI_LINUX_RELEASE_ORIGIN")
        .expect("Linux selected setup requires a fixed release origin");
    let target = env::var("LOMI_LINUX_PRIMARY_TARGET")
        .expect("Linux selected setup requires a fixed TUF target name");
    let platform = env::var("LOMI_LINUX_PLATFORM")
        .expect("Linux selected setup requires a fixed platform name");
    assert!(
        canonical_release_origin(&origin),
        "invalid Linux release origin"
    );
    assert!(
        !target.is_empty()
            && target.len() <= 255
            && target.is_ascii()
            && !target.starts_with('/')
            && !target.contains('\\')
            && target
                .split('/')
                .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
            && target
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
        "invalid Linux TUF target name"
    );
    let expected_target = match platform.as_str() {
        "linux-x86_64" => "x86_64-unknown-linux-gnu",
        "linux-aarch64" => "aarch64-unknown-linux-gnu",
        _ => panic!("unsupported Linux platform pin"),
    };
    assert_eq!(
        rust_target, expected_target,
        "Linux platform pin does not match the Rust target"
    );
    Some([origin, target, platform])
}

fn valid_target_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.is_ascii()
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte))
}

fn maintenance_release_pins() -> Option<[String; 5]> {
    for key in [
        "LOMI_RELEASE_ORIGIN",
        "LOMI_RELEASE_PRIMARY_TARGET",
        "LOMI_RELEASE_HELPER_TARGET",
        "LOMI_RELEASE_PLATFORM",
        "LOMI_RELEASE_NATIVE_SIGNER",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    if env::var_os("CARGO_FEATURE_RELEASE_MAINTENANCE").is_none() {
        return None;
    }
    let origin = env::var("LOMI_RELEASE_ORIGIN")
        .expect("release maintenance requires a fixed release origin");
    let primary = env::var("LOMI_RELEASE_PRIMARY_TARGET")
        .expect("release maintenance requires a fixed primary TUF target");
    let helper = env::var("LOMI_RELEASE_HELPER_TARGET")
        .expect("release maintenance requires a fixed helper target value");
    let platform = env::var("LOMI_RELEASE_PLATFORM")
        .expect("release maintenance requires a fixed platform name");
    let signer = env::var("LOMI_RELEASE_NATIVE_SIGNER")
        .expect("release maintenance requires a fixed native signer pin value");
    assert!(canonical_release_origin(&origin), "invalid release origin");
    assert!(
        valid_target_name(&primary),
        "invalid primary TUF target name"
    );

    let rust_target = env::var("TARGET").expect("Cargo sets TARGET");
    let expected_platform = match rust_target.as_str() {
        "x86_64-unknown-linux-gnu" => "linux-x86_64",
        "aarch64-unknown-linux-gnu" => "linux-aarch64",
        "x86_64-apple-darwin" => "macos-x86_64",
        "aarch64-apple-darwin" => "macos-aarch64",
        "x86_64-pc-windows-msvc" => "windows-x86_64",
        "aarch64-pc-windows-msvc" => "windows-aarch64",
        _ => panic!("release maintenance is unsupported for this Rust target"),
    };
    assert_eq!(
        platform, expected_platform,
        "release platform pin does not match the Rust target"
    );
    if platform.starts_with("windows-") {
        assert!(valid_target_name(&helper), "invalid helper TUF target name");
        assert_ne!(primary, helper, "Windows TUF target names must be distinct");
        assert!(
            primary.to_ascii_lowercase().ends_with(".exe")
                && helper.to_ascii_lowercase().ends_with(".exe"),
            "Windows TUF target names must identify PE executables"
        );
        assert!(
            signer.len() == 40
                && signer
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)),
            "Windows release requires a canonical Authenticode thumbprint pin"
        );
    } else if platform.starts_with("macos-") {
        assert!(
            signer.len() == 10
                && signer
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'A'..=b'Z').contains(&byte)),
            "macOS release requires a canonical Developer ID team pin"
        );
    } else {
        assert!(
            helper.is_empty(),
            "a helper target is supported only on Windows"
        );
        assert!(
            signer.is_empty(),
            "native signer pin is unsupported on Linux"
        );
    }
    Some([origin, primary, helper, platform, signer])
}

fn main() {
    for key in [
        "LOMI_WINDOWS_RELEASE_ORIGIN",
        "LOMI_WINDOWS_PRIMARY_TARGET",
        "LOMI_WINDOWS_HELPER_TARGET",
        "LOMI_WINDOWS_PLATFORM",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
        if env::var("TARGET").is_ok_and(|target| target.contains("windows"))
            && env::var("PROFILE").is_ok_and(|profile| profile == "release")
        {
            let value = env::var(key)
                .expect("Windows releases require embedded administrator update coordinates");
            assert!(
                !value.is_empty()
                    && value.is_ascii()
                    && !value
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()),
                "invalid Windows administrator update coordinate"
            );
        }
    }
    for key in KEYS {
        println!("cargo:rerun-if-env-changed={key}");
    }
    let values = KEYS.map(|key| env::var(key).ok());
    let present = values.iter().filter(|value| value.is_some()).count();
    let release = env::var("PROFILE").is_ok_and(|profile| profile == "release");
    let pins = if present == 0 && !release {
        None
    } else {
        if present != KEYS.len() {
            panic!("release host bootstrap requires all five public LOMI_HOST_* pins");
        }
        let [
            Some(identity),
            Some(remote_api),
            Some(relay),
            Some(client),
            Some(web),
        ] = values
        else {
            unreachable!("the public bootstrap pin count was checked");
        };
        if !canonical_https_origin(&identity)
            || !canonical_https_origin(&remote_api)
            || !canonical_https_origin(&web)
            || identity == remote_api
            || !canonical_relay_endpoint(&relay)
            || client.is_empty()
            || client.len() > 128
            || !client
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            panic!("host bootstrap pins are incomplete or noncanonical");
        }
        Some([identity, remote_api, relay, client, web])
    };

    let generated = match pins {
        Some([identity, remote_api, relay, client, web]) => format!(
            "pub const RELEASE_PINS: Option<super::PublicPins> = Some(super::PublicPins {{ identity_origin: {}, remote_api_origin: {}, relay_endpoint: {}, client_id: {}, remote_web_origin: {} }});\n",
            rust_string(&identity),
            rust_string(&remote_api),
            rust_string(&relay),
            rust_string(&client),
            rust_string(&web),
        ),
        None => "pub const RELEASE_PINS: Option<super::PublicPins> = None;\n".to_owned(),
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(out.join("bootstrap_pins.rs"), generated)
        .expect("write compiled host bootstrap pins");
    let linux = match linux_bootstrap_pins() {
        Some([origin, target, platform]) => format!(
            "pub const LINUX_SETUP_RELEASE: Option<super::LinuxSetupRelease> = Some(super::LinuxSetupRelease {{ origin: {}, target_name: {}, platform: {} }});\n",
            rust_string(&origin),
            rust_string(&target),
            rust_string(&platform),
        ),
        None => {
            "pub const LINUX_SETUP_RELEASE: Option<super::LinuxSetupRelease> = None;\n".to_owned()
        }
    };
    fs::write(out.join("linux_setup_release.rs"), linux)
        .expect("write compiled Linux selected setup pins");
    let maintenance = match maintenance_release_pins() {
        Some([origin, primary, helper, platform, signer]) => format!(
            "pub const RELEASE_PINS: Option<super::MaintenanceReleasePins> = Some(super::MaintenanceReleasePins {{ origin: {}, primary_target: {}, helper_target: {}, platform: {}, native_signer: {} }});\n",
            rust_string(&origin),
            rust_string(&primary),
            if helper.is_empty() {
                "None".to_owned()
            } else {
                format!("Some({})", rust_string(&helper))
            },
            rust_string(&platform),
            if signer.is_empty() {
                "None".to_owned()
            } else {
                format!("Some({})", rust_string(&signer))
            },
        ),
        None => {
            "pub const RELEASE_PINS: Option<super::MaintenanceReleasePins> = None;\n".to_owned()
        }
    };
    fs::write(out.join("maintenance_release.rs"), maintenance)
        .expect("write compiled release maintenance pins");
}
