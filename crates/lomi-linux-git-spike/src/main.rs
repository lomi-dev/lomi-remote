//! Bounded native ARM64 Linux experiment; never a production git.read adapter.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod linux;
fn main() {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    std::process::exit(linux::main());
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        eprintln!("not_run: only the pinned Linux ARM64 fixture is implemented");
        std::process::exit(2);
    }
}
