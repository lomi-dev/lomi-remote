//! Synthetic S0.3a feasibility probe, not a qualified production Git service.
//! Design adapted from Lomi's macOS git_read.rs; see PROVENANCE.md.
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedPlatform,
    UnsupportedRepository,
    UntrustedRuntime,
    Rejected,
    LimitExceeded,
    DeadlineExceeded,
    Changed,
    Io,
}

/// Closed observations: callers cannot supply executable, environment or argv.
pub enum Observation {
    Status,
    Diff,
}

/// Observe one ordinary repository. No adapter is enabled on Linux or Windows.
/// Output is raw internal fixture data; this is not a remote API.
pub fn read(root: &Path, observation: Observation) -> Result<Vec<u8>, Error> {
    #[cfg(target_os = "macos")]
    {
        macos::read(root, observation)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (root, observation);
        Err(Error::UnsupportedPlatform)
    }
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    #[test]
    fn unsupported_platform_does_not_run_git() {
        assert_eq!(
            super::read(std::path::Path::new("."), super::Observation::Status),
            Err(super::Error::UnsupportedPlatform)
        );
    }
}
