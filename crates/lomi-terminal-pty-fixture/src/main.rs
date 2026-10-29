//! Bounded local interactive Vim evidence; never parses PTY output in a client.
#[cfg(unix)]
mod native;
fn main() {
    #[cfg(unix)]
    if let Err(error) = native::run() {
        // All errors are static stage labels or OS errors; never include PTY output.
        eprintln!("terminal PTY fixture failed: {error}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        eprintln!("not_run: Unix PTY fixture; Windows requires a native harness");
        std::process::exit(2);
    }
}
