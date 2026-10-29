#[cfg(unix)]
fn main() {
    std::process::exit(lomi_terminal::owned_host_fixture_main());
}
#[cfg(not(unix))]
fn main() {
    std::process::exit(2);
}
