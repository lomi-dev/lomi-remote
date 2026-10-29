#[cfg(target_os = "macos")]
mod macos;
fn main() {
    #[cfg(target_os = "macos")]
    {
        if lomi_platform::process::initialize_child_ownership().is_err() {
            std::process::exit(4);
        }
        if std::env::args_os().nth(1).as_deref()
            == Some(std::ffi::OsStr::new("--internal-keychain-helper"))
        {
            std::process::exit(if std::env::args_os().nth(2).is_none() {
                lomi_platform::unix::keychain::internal_helper()
            } else {
                2
            });
        }
    }
    #[cfg(target_os = "macos")]
    if let Err(error) = macos::run() {
        eprintln!("storage_fixture_failed:{error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("not_run: native macOS required");
        std::process::exit(2);
    }
}
