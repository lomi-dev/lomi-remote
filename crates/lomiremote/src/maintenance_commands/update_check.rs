use std::{
    cmp::Ordering,
    io::{self, Write},
    time::Duration,
};

const MAX_METADATA_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CANONICAL_PLATFORMS: [&str; 6] = [
    "linux-x86_64",
    "linux-aarch64",
    "macos-x86_64",
    "macos-aarch64",
    "windows-x86_64",
    "windows-aarch64",
];
const RELEASE_TAGS_URL: &str = "https://github.com/lomi-dev/lomi-remote/releases/tag/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckError {
    Unavailable,
    Redirect,
    ResponseTooLarge,
    InvalidMetadata,
}

impl CheckError {
    fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "UPDATE_CHECK_UNAVAILABLE",
            Self::Redirect => "UPDATE_CHECK_REDIRECT_REJECTED",
            Self::ResponseTooLarge => "UPDATE_CHECK_RESPONSE_TOO_LARGE",
            Self::InvalidMetadata => "UPDATE_CHECK_METADATA_INVALID",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "Could not reach the pinned release information service.",
            Self::Redirect => {
                "The pinned release information endpoint redirected; the response was rejected."
            }
            Self::ResponseTooLarge => "The release information response exceeded the 64 KiB limit.",
            Self::InvalidMetadata => {
                "The release information response was malformed or inconsistent."
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct UpdateInfo {
    current_version: String,
    latest_version: String,
    tag: String,
    release_url: String,
    available: bool,
}

pub(super) fn run(json: bool) -> u8 {
    match check() {
        Ok(info) => {
            if json {
                write_json(&serde_json::json!({
                    "format": 1,
                    "available": info.available,
                    "currentVersion": info.current_version,
                    "latestVersion": info.latest_version,
                    "tag": info.tag,
                    "releaseUrl": info.release_url,
                }))
            } else {
                print_text(&info, current_platform())
            }
        }
        Err(error) => {
            if json {
                write_json(&serde_json::json!({
                    "format": 1,
                    "error": {"code": error.code()},
                }));
                4
            } else {
                eprintln!("{}: {}", error.code(), error.message());
                4
            }
        }
    }
}

fn check() -> Result<UpdateInfo, CheckError> {
    let pins = crate::bootstrap::maintenance_release_pins().ok_or(CheckError::Unavailable)?;
    if !CANONICAL_PLATFORMS.contains(&pins.platform) {
        return Err(CheckError::Unavailable);
    }
    let current_version = env!("CARGO_PKG_VERSION");
    let metadata_url = format!("{}latest.json", pins.origin);
    let metadata = fetch(&metadata_url)?;
    parse_latest(&metadata, current_version, pins.platform)
}

fn fetch(url: &str) -> Result<Vec<u8>, CheckError> {
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .max_response_header_size(16 * 1024)
        .timeout_global(Some(REQUEST_TIMEOUT))
        .timeout_per_call(Some(REQUEST_TIMEOUT));
    #[cfg(feature = "local-release-test")]
    let config = config.tls_config(lomi_update_trust::local_release_test_tls_config());
    let config = config.build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent.get(url).call().map_err(|_| CheckError::Unavailable)?;
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return Err(CheckError::Redirect);
    }
    if status != 200 {
        return Err(CheckError::Unavailable);
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit((MAX_METADATA_BYTES + 1) as u64)
        .read_to_vec()
        .map_err(|error| match error {
            ureq::Error::BodyExceedsLimit(_) => CheckError::ResponseTooLarge,
            _ => CheckError::Unavailable,
        })?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(CheckError::ResponseTooLarge);
    }
    Ok(bytes)
}

fn parse_latest(
    bytes: &[u8],
    current_version: &str,
    platform: &str,
) -> Result<UpdateInfo, CheckError> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(CheckError::ResponseTooLarge);
    }
    let current = StableVersion::parse(current_version).ok_or(CheckError::Unavailable)?;
    let document: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CheckError::InvalidMetadata)?;
    let object = document
        .as_object()
        .filter(|object| {
            object.len() == 4
                && object.contains_key("version")
                && object.contains_key("tag")
                && object.contains_key("platforms")
                && object.contains_key("releaseUrl")
        })
        .ok_or(CheckError::InvalidMetadata)?;
    let latest_version = object["version"]
        .as_str()
        .ok_or(CheckError::InvalidMetadata)?;
    let latest = StableVersion::parse(latest_version).ok_or(CheckError::InvalidMetadata)?;
    let tag = object["tag"].as_str().ok_or(CheckError::InvalidMetadata)?;
    if tag != format!("v{latest_version}") {
        return Err(CheckError::InvalidMetadata);
    }
    let release_url = object["releaseUrl"]
        .as_str()
        .ok_or(CheckError::InvalidMetadata)?;
    if release_url != format!("{RELEASE_TAGS_URL}{tag}") {
        return Err(CheckError::InvalidMetadata);
    }
    let platforms = object["platforms"]
        .as_array()
        .filter(|platforms| !platforms.is_empty())
        .ok_or(CheckError::InvalidMetadata)?;
    let mut available_platforms = Vec::with_capacity(platforms.len());
    for value in platforms {
        let value = value.as_str().ok_or(CheckError::InvalidMetadata)?;
        if !CANONICAL_PLATFORMS.contains(&value) || available_platforms.contains(&value) {
            return Err(CheckError::InvalidMetadata);
        }
        available_platforms.push(value);
    }
    if !CANONICAL_PLATFORMS.contains(&platform) {
        return Err(CheckError::Unavailable);
    }
    let available =
        current.compare(&latest) == Ordering::Less && available_platforms.contains(&platform);

    Ok(UpdateInfo {
        current_version: current_version.to_owned(),
        latest_version: latest_version.to_owned(),
        tag: tag.to_owned(),
        release_url: release_url.to_owned(),
        available,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct StableVersion<'a> {
    components: [&'a str; 3],
}

impl<'a> StableVersion<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        let (core, build) = value
            .split_once('+')
            .map_or((value, None), |(core, build)| (core, Some(build)));
        if let Some(build) = build
            && (build.is_empty()
                || build.split('.').any(|identifier| {
                    identifier.is_empty()
                        || !identifier
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                }))
        {
            return None;
        }
        let mut parts = core.split('.');
        let components = [parts.next()?, parts.next()?, parts.next()?];
        if parts.next().is_some()
            || components.iter().any(|component| {
                component.is_empty()
                    || (component.len() > 1 && component.starts_with('0'))
                    || !component.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return None;
        }
        Some(Self { components })
    }

    fn compare(&self, other: &Self) -> Ordering {
        for (left, right) in self.components.iter().zip(other.components) {
            let ordering = left
                .len()
                .cmp(&right.len())
                .then_with(|| (*left).cmp(right));
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        Ordering::Equal
    }
}

fn current_platform() -> &'static str {
    crate::bootstrap::maintenance_release_pins()
        .map(|pins| pins.platform)
        .unwrap_or("unknown")
}

fn print_text(info: &UpdateInfo, platform: &str) -> u8 {
    println!("Current version: {}", info.current_version);
    println!("Latest version: {} ({})", info.latest_version, info.tag);
    if info.available {
        println!("Update available for {platform}.");
        println!(
            "To install it, run: lomiremote update --version {} --confirm",
            info.latest_version
        );
    } else if info.current_version == info.latest_version {
        println!("This installation is up to date.");
    } else {
        println!("No newer release is available for {platform}.");
    }
    0
}

fn write_json(value: &serde_json::Value) -> u8 {
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, value).is_err() || writeln!(stdout).is_err() {
        return 4;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::{CheckError, StableVersion, parse_latest};
    use crate::cli;

    fn metadata(version: &str, platforms: &[&str]) -> Vec<u8> {
        serde_json::json!({
            "version": version,
            "tag": format!("v{version}"),
            "platforms": platforms,
            "releaseUrl": format!("https://github.com/lomi-dev/lomi-remote/releases/tag/v{version}"),
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn reports_only_newer_releases_for_a_supported_platform() {
        let info = parse_latest(
            &metadata("0.2.0", &["linux-x86_64", "macos-aarch64"]),
            "0.1.9",
            "linux-x86_64",
        )
        .unwrap();
        assert!(info.available);
        assert_eq!(info.latest_version, "0.2.0");

        let unsupported = parse_latest(
            &metadata("0.2.0", &["macos-aarch64"]),
            "0.1.9",
            "linux-x86_64",
        )
        .unwrap();
        assert!(!unsupported.available);

        let current = parse_latest(
            &metadata("0.1.9", &["linux-x86_64"]),
            "0.1.9",
            "linux-x86_64",
        )
        .unwrap();
        assert!(!current.available);
    }

    #[test]
    fn parses_stable_semver_components_numerically() {
        let older = StableVersion::parse("0.9.99").unwrap();
        let newer = StableVersion::parse("0.10.0").unwrap();
        assert!(older.compare(&newer).is_lt());
        assert!(StableVersion::parse("1.2.3-rc.1").is_none());
        assert!(StableVersion::parse("1.02.3").is_none());
        assert!(StableVersion::parse("1.2").is_none());
    }

    #[test]
    fn rejects_inconsistent_or_noncanonical_release_metadata() {
        for json in [
            r#"{"version":"1.2.3-rc.1","tag":"v1.2.3-rc.1","platforms":["linux-x86_64"],"releaseUrl":"https://github.com/lomi-dev/lomi-remote/releases/tag/v1.2.3-rc.1"}"#,
            r#"{"version":"1.2.3","tag":"v1.2.3","platforms":["linux-x86_64","unknown"],"releaseUrl":"https://github.com/lomi-dev/lomi-remote/releases/tag/v1.2.3"}"#,
            r#"{"version":"1.2.3","tag":"v1.2.3","platforms":["linux-x86_64","linux-x86_64"],"releaseUrl":"https://github.com/lomi-dev/lomi-remote/releases/tag/v1.2.3"}"#,
            r#"{"version":"1.2.3","tag":"v1.2.4","platforms":["linux-x86_64"],"releaseUrl":"https://github.com/lomi-dev/lomi-remote/releases/tag/v1.2.4"}"#,
            r#"{"version":"1.2.3","tag":"v1.2.3","platforms":["linux-x86_64"],"releaseUrl":"https://example.com/v1.2.3"}"#,
            r#"{"version":"1.2.3","tag":"v1.2.3","platforms":["linux-x86_64"],"releaseUrl":"https://github.com/lomi-dev/lomi-remote/releases/tag/v1.2.3","extra":true}"#,
        ] {
            assert_eq!(
                parse_latest(json.as_bytes(), "1.0.0", "linux-x86_64"),
                Err(CheckError::InvalidMetadata),
                "accepted {json}"
            );
        }
    }

    #[test]
    fn rejects_metadata_over_the_body_limit() {
        let bytes = vec![b' '; 64 * 1024 + 1];
        assert_eq!(
            parse_latest(&bytes, "1.0.0", "linux-x86_64"),
            Err(CheckError::ResponseTooLarge)
        );
    }

    #[test]
    fn check_flag_dispatches_only_the_update_check_path() {
        let matches = cli::command()
            .try_get_matches_from(["lomiremote", "update", "--check"])
            .unwrap();
        let (_, args) = matches.subcommand().unwrap();
        assert!(super::super::is_update_check("update", args));
        assert!(!super::super::is_update_check("uninstall", args));

        let matches = cli::command()
            .try_get_matches_from(["lomiremote", "update"])
            .unwrap();
        let (_, args) = matches.subcommand().unwrap();
        assert!(!super::super::is_update_check("update", args));
    }
}
