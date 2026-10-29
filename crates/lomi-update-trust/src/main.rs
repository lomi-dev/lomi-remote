#[cfg(any(unix, windows))]
fn main() -> lomi_update_trust::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    #[cfg(all(feature = "release-root", target_os = "macos"))]
    if args.get(1).map(String::as_str) == Some("prepare-admin-profile") {
        if args.len() != 4 {
            return Err("usage: prepare-admin-profile ACCOUNT PROFILE".into());
        }
        let profile = lomi_platform::service_macos::prepare_boot_profile_in_helper(
            &args[2],
            std::path::Path::new(&args[3]),
        )?;
        println!("{}", profile.display());
        return Ok(());
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(args))
}

#[cfg(all(feature = "release-root", target_os = "macos"))]
fn admin_host_mode(
    value: Option<&str>,
) -> lomi_update_trust::Result<lomi_platform::service_macos::AdminHostMode> {
    value.unwrap_or("boot").parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "admin Host mode must be exactly manual, login, or boot",
        )
        .into()
    })
}

#[cfg(any(unix, windows))]
async fn run(args: Vec<String>) -> lomi_update_trust::Result<()> {
    use lomi_update_trust::TrustStore;
    #[cfg(not(feature = "release-root"))]
    use std::fs::File;
    use std::{io::Read, path::Path};
    match args.get(1).map(String::as_str) {
        #[cfg(not(feature = "release-root"))]
        Some("initialize") if args.len() == 4 => {
            let mut root = Vec::new();
            File::open(&args[3])?
                .take(lomi_update_trust::MAX_METADATA as u64 + 1)
                .read_to_end(&mut root)?;
            let store = TrustStore::initialize(Path::new(&args[2]), &root)?;
            println!("{}", store.generation()?);
        }
        Some("status") if args.len() == 3 => {
            let store = TrustStore::open(Path::new(&args[2]))?;
            println!("{}", store.generation()?);
        }
        #[cfg(not(feature = "release-root"))]
        Some("update") if (5..=6).contains(&args.len()) => {
            let mut store = TrustStore::open(Path::new(&args[2]))?;
            let target = args
                .get(5)
                .filter(|s| s.as_str() != "-")
                .map(String::as_str);
            let result = store
                .update(Path::new(&args[3]), Path::new(&args[4]), target)
                .await?;
            println!(
                "{}",
                serde_json::json!({"generation": store.generation()?, "verifiedTargetBytes": result.map(|v| v.len())})
            );
        }
        #[cfg(target_os = "linux")]
        #[cfg(not(feature = "release-root"))]
        Some("activate") if args.len() == 7 => {
            let mut store = TrustStore::open(Path::new(&args[2]))?;
            let object = store
                .update_and_activate(
                    Path::new(&args[3]),
                    Path::new(&args[4]),
                    &args[5],
                    Path::new(&args[6]),
                )
                .await?;
            println!(
                "{}",
                serde_json::json!({
                    "generation": store.generation()?,
                    "activeObject": object
                })
            );
        }
        #[cfg(feature = "release-root")]
        Some("initialize-release") if args.len() == 3 => {
            let store = TrustStore::initialize_embedded(Path::new(&args[2]))?;
            println!("{}", store.generation()?);
        }
        #[cfg(feature = "release-root")]
        Some("status-release") if args.len() == 3 => {
            let store = TrustStore::open_embedded(Path::new(&args[2]))?;
            println!("{}", store.generation()?);
        }
        #[cfg(feature = "release-root")]
        Some("root-pin") if args.len() == 2 => {
            println!("{}", lomi_update_trust::embedded_root_sha256()?);
        }
        #[cfg(feature = "release-root")]
        Some("validate-install-dir") if args.len() == 3 => {
            lomi_update_trust::validate_install_directory(Path::new(&args[2]))?;
        }
        #[cfg(all(feature = "release-root", unix))]
        Some("verify-installed-maintenance-cli") if args.len() == 4 => {
            lomi_update_trust::verify_installed_maintenance_cli(Path::new(&args[2]), &args[3])?;
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("verify-admin-installed-maintenance-cli") if args.len() == 4 => {
            lomi_update_trust::verify_admin_installed_maintenance_cli(
                Path::new(&args[2]),
                &args[3],
            )?;
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("validate-admin-boot-install-dir") if args.len() == 3 => {
            lomi_update_trust::validate_admin_boot_install_directory(Path::new(&args[2]))?;
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("admin-macos-profile") if args.len() == 3 => {
            println!(
                "{}",
                lomi_update_trust::admin_boot_profile_path(&args[2])?.display()
            );
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("admin-macos-install-dir") if args.len() == 3 => {
            println!(
                "{}",
                lomi_update_trust::admin_boot_install_path(&args[2])?.display()
            );
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("bind-admin-boot-profile") if args.len() == 5 || args.len() == 6 => {
            let host_mode = admin_host_mode(args.get(5).map(String::as_str))?;
            lomi_update_trust::bind_admin_host_profile(
                Path::new(&args[2]),
                Path::new(&args[3]),
                &args[4],
                host_mode,
            )?;
        }
        #[cfg(feature = "release-root")]
        Some("release-recovery-needed") if args.len() == 3 => {
            println!(
                "{}",
                if lomi_update_trust::release_recovery_pending(Path::new(&args[2]))? {
                    "pending"
                } else {
                    "clear"
                }
            );
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("admin-boot-recovery-needed") if args.len() == 3 => {
            println!(
                "{}",
                if lomi_update_trust::admin_boot_release_recovery_pending(Path::new(&args[2]))? {
                    "pending"
                } else {
                    "clear"
                }
            );
        }
        #[cfg(feature = "release-root")]
        Some("recover-release") if args.len() == 5 => {
            match lomi_update_trust::recover_interrupted_release(
                Path::new(&args[2]),
                Path::new(&args[3]),
                &args[4],
            )? {
                Some(schema) => println!("{schema}"),
                None => println!("not-pending"),
            }
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("recover-release-admin-boot") if args.len() == 6 || args.len() == 7 => {
            let host_mode = admin_host_mode(args.get(6).map(String::as_str))?;
            match lomi_update_trust::recover_interrupted_admin_host_release(
                Path::new(&args[2]),
                Path::new(&args[3]),
                &args[4],
                &args[5],
                host_mode,
            )? {
                Some(schema) => println!("{schema}"),
                None => println!("not-pending"),
            }
        }
        #[cfg(feature = "release-root")]
        Some("maintenance-schema") if args.len() == 2 => {
            let mut input = Vec::new();
            std::io::stdin()
                .take(64 * 1024 + 1)
                .read_to_end(&mut input)?;
            let (schema, active_terminals) =
                parse_maintenance_response(&input).map_err(std::io::Error::other)?;
            println!("{schema}\n{active_terminals}");
        }
        #[cfg(all(feature = "release-root", unix))]
        Some("install-release") if args.len() == 9 || args.len() == 10 => {
            let profile_schema = args[8].parse::<u64>()?;
            let mut store = TrustStore::open_embedded(Path::new(&args[2]))?;
            let object = if let Some(version) = args.get(9) {
                store
                    .install_release_https_pinned(
                        &args[3],
                        &args[4],
                        Path::new(&args[5]),
                        Path::new(&args[6]),
                        &args[7],
                        profile_schema,
                        version,
                    )
                    .await?
            } else {
                store
                    .install_release_https(
                        &args[3],
                        &args[4],
                        Path::new(&args[5]),
                        Path::new(&args[6]),
                        &args[7],
                        profile_schema,
                    )
                    .await?
            };
            println!(
                "{}",
                serde_json::json!({
                    "generation": store.generation()?,
                    "activeObject": object
                })
            );
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("install-release-admin-boot") if (10..=12).contains(&args.len()) => {
            let host_mode = admin_host_mode(args.get(10).map(String::as_str))?;
            let schema_hint = if args[8] == "-" {
                None
            } else {
                Some(args[8].parse::<u64>()?)
            };
            lomi_update_trust::bind_admin_host_profile(
                Path::new(&args[5]),
                Path::new(&args[6]),
                &args[9],
                host_mode,
            )?;
            let mut store = TrustStore::open_embedded(Path::new(&args[2]))?;
            let object = if let Some(version) = args.get(11) {
                store
                    .install_release_admin_host_https_pinned(
                        &args[3],
                        &args[4],
                        Path::new(&args[5]),
                        Path::new(&args[6]),
                        &args[7],
                        schema_hint,
                        &args[9],
                        host_mode,
                        Some(version),
                    )
                    .await?
            } else {
                store
                    .install_release_admin_host_https(
                        &args[3],
                        &args[4],
                        Path::new(&args[5]),
                        Path::new(&args[6]),
                        &args[7],
                        schema_hint,
                        &args[9],
                        host_mode,
                    )
                    .await?
            };
            println!(
                "{}",
                serde_json::json!({
                    "generation": store.generation()?,
                    "activeObject": object
                })
            );
        }
        #[cfg(all(feature = "release-root", windows))]
        Some("install-release-pair") if args.len() == 10 || args.len() == 11 => {
            let profile_schema = args[9].parse::<u64>()?;
            let mut store = TrustStore::open_embedded(Path::new(&args[2]))?;
            let objects = if let Some(version) = args.get(10) {
                store
                    .install_release_pair_https_pinned(
                        &args[3],
                        &args[4],
                        &args[5],
                        Path::new(&args[6]),
                        Path::new(&args[7]),
                        &args[8],
                        profile_schema,
                        version,
                    )
                    .await?
            } else {
                store
                    .install_release_pair_https(
                        &args[3],
                        &args[4],
                        &args[5],
                        Path::new(&args[6]),
                        Path::new(&args[7]),
                        &args[8],
                        profile_schema,
                    )
                    .await?
            };
            println!(
                "{}",
                serde_json::json!({
                    "activeObject": objects.0,
                    "activeCompanionObject": objects.1,
                    "generation": store.generation()?
                })
            );
        }
        #[cfg(feature = "release-root")]
        Some("rollback-release") if args.len() == 7 => {
            let profile_schema = args[6].parse::<u64>()?;
            let store = TrustStore::open_embedded(Path::new(&args[2]))?;
            let object = store.rollback_activation(
                Path::new(&args[3]),
                Path::new(&args[4]),
                &args[5],
                profile_schema,
            )?;
            println!("{}", serde_json::json!({"activeObject": object}));
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("rollback-release-admin-boot") if args.len() == 8 || args.len() == 9 => {
            let host_mode = admin_host_mode(args.get(8).map(String::as_str))?;
            let schema_hint = if args[6] == "-" {
                None
            } else {
                Some(args[6].parse::<u64>()?)
            };
            lomi_update_trust::bind_admin_host_profile(
                Path::new(&args[3]),
                Path::new(&args[4]),
                &args[7],
                host_mode,
            )?;
            let store = TrustStore::open_embedded(Path::new(&args[2]))?;
            let object = store.rollback_admin_host_activation(
                Path::new(&args[3]),
                Path::new(&args[4]),
                &args[5],
                schema_hint,
                &args[7],
                host_mode,
            )?;
            println!("{}", serde_json::json!({"activeObject": object}));
        }
        #[cfg(feature = "release-root")]
        Some("uninstall-release") if args.len() == 4 => {
            let removed_objects =
                lomi_update_trust::uninstall_release(Path::new(&args[2]), Path::new(&args[3]))?;
            println!(
                "{}",
                serde_json::json!({"removedObjects": removed_objects, "profilePreserved": true})
            );
        }
        #[cfg(all(feature = "release-root", windows))]
        Some("file-security") => {
            let message = file_security_release_command(&args).await?;
            println!("{message}");
        }
        #[cfg(all(feature = "release-root", target_os = "macos"))]
        Some("uninstall-release-admin-boot") if args.len() == 5 || args.len() == 6 => {
            let host_mode = admin_host_mode(args.get(5).map(String::as_str))?;
            let removed_objects = lomi_update_trust::uninstall_admin_host_release(
                Path::new(&args[2]),
                Path::new(&args[3]),
                &args[4],
                host_mode,
            )?;
            println!(
                "{}",
                serde_json::json!({"removedObjects": removed_objects, "profilePreserved": true})
            );
        }
        _ => {
            #[cfg(feature = "release-root")]
            let usage = "usage: lomi-update-trust root-pin | maintenance-schema | validate-install-dir INSTALL_DIR | verify-installed-maintenance-cli INSTALL_DIR PLATFORM | verify-admin-installed-maintenance-cli INSTALL_DIR PLATFORM | release-recovery-needed INSTALL_DIR | recover-release PROFILE_DIR INSTALL_DIR PLATFORM | install-release TRUST_DIR HTTPS_ORIGIN TARGET PROFILE_DIR INSTALL_DIR PLATFORM PROFILE_SCHEMA [EXPECTED_VERSION] | install-release-pair TRUST_DIR HTTPS_ORIGIN PRIMARY COMPANION PROFILE_DIR INSTALL_DIR PLATFORM PROFILE_SCHEMA [EXPECTED_VERSION] | rollback-release TRUST_DIR PROFILE_DIR INSTALL_DIR PLATFORM PROFILE_SCHEMA | uninstall-release PROFILE_DIR INSTALL_DIR | file-security install|upgrade --owner-sid SID --confirm-system-service HTTPS_ORIGIN TARGET PLATFORM | file-security uninstall --owner-sid SID | prepare-admin-profile ACCOUNT PROFILE | admin-macos-profile ACCOUNT | admin-macos-install-dir ACCOUNT | bind-admin-boot-profile PROFILE_DIR INSTALL_DIR ACCOUNT [MODE] | validate-admin-boot-install-dir INSTALL_DIR | admin-boot-recovery-needed INSTALL_DIR | recover-release-admin-boot PROFILE_DIR INSTALL_DIR PLATFORM ACCOUNT [MODE] | install-release-admin-boot TRUST_DIR HTTPS_ORIGIN TARGET PROFILE_DIR INSTALL_DIR PLATFORM SCHEMA_HINT|- ACCOUNT [MODE [EXPECTED_VERSION]] | rollback-release-admin-boot TRUST_DIR PROFILE_DIR INSTALL_DIR PLATFORM SCHEMA_HINT|- ACCOUNT [MODE] | uninstall-release-admin-boot PROFILE_DIR INSTALL_DIR ACCOUNT [MODE] (MODE: manual|login|boot; omitted means boot)";
            #[cfg(not(feature = "release-root"))]
            let usage = "usage: lomi-update-trust initialize DIR ROOT | status DIR | update DIR METADATA TARGETS [TARGET] | activate DIR METADATA TARGETS TARGET INSTALL_DIR";
            return Err(usage.into());
        }
    }
    Ok(())
}

#[cfg(all(feature = "release-root", windows))]
async fn file_security_release_command(args: &[String]) -> lomi_update_trust::Result<String> {
    use lomi_platform::windows::file_security_service as broker;
    use lomi_update_trust::TrustStore;

    let (operation, owner_sid, release_origin, target_name, platform) = match args.get(2).map(String::as_str) {
        Some("install" | "upgrade")
            if args.len() == 9
                && args[3] == "--owner-sid"
                && args[5] == "--confirm-system-service" =>
        {
            (
                args[2].as_str(),
                args[4].as_str(),
                Some(args[6].as_str()),
                Some(args[7].as_str()),
                Some(args[8].as_str()),
            )
        }
        Some("uninstall") if args.len() == 5 && args[3] == "--owner-sid" => {
            ("uninstall", args[4].as_str(), None, None, None)
        }
        _ => return Err("usage: file-security install|upgrade --owner-sid SID --confirm-system-service HTTPS_ORIGIN TARGET PLATFORM | file-security uninstall --owner-sid SID".into()),
    };

    if operation == "uninstall" {
        let executable = std::env::current_exe()?;
        return broker::run("uninstall", Some(owner_sid), false, &executable).map_err(Into::into);
    }

    let release_origin = release_origin.ok_or("missing release origin")?;
    let target_name = target_name.ok_or("missing target name")?;
    let platform = platform.ok_or("missing release platform")?;
    let area = broker::prepare_broker_release_area(owner_sid)?;
    let trust_dir = area.path().join("trust");
    let mut store = match std::fs::symlink_metadata(&trust_dir) {
        Ok(_) => TrustStore::open_embedded(&trust_dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            TrustStore::initialize_embedded(&trust_dir)?
        }
        Err(error) => return Err(error.into()),
    };
    if let Some(message) = broker::resume_pending_upgrade(owner_sid)? {
        println!("{message}");
    }
    let bytes = store
        .update_file_security_release_https(release_origin, target_name, platform)
        .await?;
    let source = area.stage_source(&bytes)?;
    drop(bytes);
    // The trust-state lock serializes the verified release choice through the
    // corresponding SCM apply, so a concurrent updater cannot activate an
    // older target after this command has verified a newer one. The broker's
    // separate management lock is acquired only inside `run`.
    let result = broker::run(operation, Some(owner_sid), true, source.path()).map_err(Into::into);
    drop(store);
    result
}

#[cfg(feature = "release-root")]
fn parse_maintenance_response(input: &[u8]) -> Result<(String, String), &'static str> {
    use serde_json::Value;

    fn exact_keys(value: &Value, keys: &[&str]) -> bool {
        value.as_object().is_some_and(|object| {
            object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
        })
    }
    fn uuid(value: &Value) -> bool {
        let Some(value) = value.as_str() else {
            return false;
        };
        value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
            })
    }
    fn decimal(value: &Value) -> Option<String> {
        let value = value.as_str()?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || value.parse::<u64>().is_err()
        {
            return None;
        }
        Some(value.to_owned())
    }

    if input.len() > 64 * 1024 {
        return Err("maintenance response exceeds its input limit");
    }
    let response: Value =
        serde_json::from_slice(input).map_err(|_| "maintenance response is not valid JSON")?;
    if !exact_keys(&response, &["requestId", "result", "version"])
        || !response.get("requestId").is_some_and(uuid)
    {
        return Err("maintenance response envelope is unsupported");
    }
    let version = response
        .get("version")
        .ok_or("maintenance response has no version")?;
    if !exact_keys(version, &["major", "minor"])
        || version.get("major").and_then(Value::as_u64) != Some(1)
        || version.get("minor").and_then(Value::as_u64) != Some(0)
    {
        return Err("maintenance response IPC version is unsupported");
    }
    let result = response
        .get("result")
        .ok_or("maintenance response has no result")?;
    if !exact_keys(result, &["Ok"]) {
        return Err("maintenance response does not contain a successful status result");
    }
    let result = result
        .get("Ok")
        .ok_or("maintenance response has no successful result")?;
    if !exact_keys(result, &["type", "value"])
        || result.get("type").and_then(Value::as_str) != Some("maintenanceStatus")
    {
        return Err("maintenance response is not an authenticated status result");
    }
    let value = result
        .get("value")
        .ok_or("maintenance response has no status value")?;
    if !exact_keys(
        value,
        &["activeTerminals", "hostId", "profileSchema", "runtimeId"],
    ) || !value.get("hostId").is_some_and(uuid)
        || !value.get("runtimeId").is_some_and(uuid)
    {
        return Err("maintenance status has an unsupported shape");
    }
    let schema = decimal(
        value
            .get("profileSchema")
            .ok_or("maintenance status has no profile schema")?,
    )
    .ok_or("maintenance status profile schema is invalid")?;
    let terminals = decimal(
        value
            .get("activeTerminals")
            .ok_or("maintenance status has no terminal count")?,
    )
    .ok_or("maintenance status terminal count is invalid")?;
    Ok((schema, terminals))
}
#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("update trust private directory/locking adapter is not qualified on this platform");
    std::process::exit(1);
}
