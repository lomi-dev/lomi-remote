#[cfg(windows)]
mod windows;

fn main() {
    #[cfg(windows)]
    if let Err(error) = windows::main() {
        // Never print OS payloads, console output, secret bytes, or config.
        eprintln!("Windows synthetic fixture failed: {}", error.kind());
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        eprintln!("Windows native fixture: not_run (requires Windows)");
        std::process::exit(2);
    }
}
