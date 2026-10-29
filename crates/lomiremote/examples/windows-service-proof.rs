//! Explicit feature-only native management fixture. The actual SCM host is the
//! separately built default lomiremote.exe, never this controller.
#[cfg(not(all(windows, feature = "service-fixture")))]
fn main() {}
#[cfg(all(windows, feature = "service-fixture"))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        std::process::exit(2)
    }
    #[cfg(feature = "dpapi-fixture")]
    if let Some(operation) = args[1].strip_prefix("dpapi-") {
        let value = match lomi_platform::windows::dpapi_fixture::operator(&args[0], operation) {
            Ok(value) => serde_json::json!({"ok":true,"value":value}),
            Err(error) => serde_json::json!({"ok":false,"error":error.to_string()}),
        };
        println!("{value}");
        return;
    }
    #[cfg(feature = "dpapi-fixture")]
    if args[1] == "probe-dpapi" {
        if lomi_platform::service_windows::fixture_probe(&args[0], "dpapi").is_err() {
            std::process::exit(1)
        }
        return;
    }
    if matches!(
        args[1].as_str(),
        "probe-before" | "probe-after" | "probe-cleanup"
    ) {
        if lomi_platform::service_windows::fixture_probe(
            &args[0],
            args[1].strip_prefix("probe-").unwrap(),
        )
        .is_err()
        {
            std::process::exit(1)
        }
        return;
    }
    let result = if args[1] == "audit" {
        lomi_platform::service_windows::fixture_audit_absence(&args[0])
            .map(|()| "All UUID services absent.".to_owned())
    } else {
        lomi_platform::service_windows::fixture_run(&args[0], &args[1])
    };
    let value = match result {
        Ok(state) => serde_json::json!({"ok":true,"state":state}),
        Err(error) => serde_json::json!({"ok":false,"error":error.to_string()}),
    };
    println!("{value}");
}
