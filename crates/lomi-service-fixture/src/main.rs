#[cfg(unix)]
mod unix;
#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    unix::run()
}
#[cfg(not(unix))]
fn main() {
    eprintln!("not_run: Unix native fixture adapter required");
    std::process::exit(2);
}
