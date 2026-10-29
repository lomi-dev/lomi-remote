//! Compile-time public host endpoints for first-run configuration.
//!
//! Values are supplied by the release operator during compilation and never
//! read from process environment at runtime. This module creates only a public
//! `LocalAuthConfiguration` candidate; the caller must obtain explicit user
//! confirmation before sending `LocalCall::AuthConfigure`.

#[cfg(target_os = "linux")]
use lomi_remote_protocol::ipc::LocalFileAcknowledgement;
#[cfg(target_os = "macos")]
use lomi_remote_protocol::ipc::LocalRootPath;
use lomi_remote_protocol::ipc::{
    LocalAuthClientId, LocalAuthConfiguration, LocalAuthOrigin, LocalAuthProvider,
    LocalRelayEndpoint,
};
use std::{error::Error, fmt, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicPins {
    pub identity_origin: &'static str,
    pub remote_api_origin: &'static str,
    pub relay_endpoint: &'static str,
    pub client_id: &'static str,
    pub remote_web_origin: &'static str,
}

/// Public release coordinates for the administrator-managed Windows Host.
/// TUF and Authenticode still authenticate every fetched target. Runtime
/// callers cannot substitute mirrors, target names, platforms or signer pins.
#[cfg(windows)]
pub struct WindowsReleasePins {
    pub release_origin: &'static str,
    pub primary_target: &'static str,
    pub helper_target: &'static str,
    pub platform: &'static str,
}

/// Public TUF coordinates compiled into a product release. These values are
/// never read from the runtime environment or accepted from command-line
/// arguments. The Windows helper target is present only for paired releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceReleasePins {
    pub origin: &'static str,
    pub primary_target: &'static str,
    pub helper_target: Option<&'static str>,
    pub platform: &'static str,
    /// Authenticode thumbprint on Windows, Developer ID Team ID on macOS.
    pub native_signer: Option<&'static str>,
}

#[cfg(windows)]
pub fn windows_release_pins() -> Option<WindowsReleasePins> {
    Some(WindowsReleasePins {
        release_origin: option_env!("LOMI_WINDOWS_RELEASE_ORIGIN")?,
        primary_target: option_env!("LOMI_WINDOWS_PRIMARY_TARGET")?,
        helper_target: option_env!("LOMI_WINDOWS_HELPER_TARGET")?,
        platform: option_env!("LOMI_WINDOWS_PLATFORM")?,
    })
}

mod compiled {
    include!(concat!(env!("OUT_DIR"), "/bootstrap_pins.rs"));
}

mod maintenance_compiled {
    include!(concat!(env!("OUT_DIR"), "/maintenance_release.rs"));
}

/// Return this build's validated public release coordinates, if maintenance
/// support was enabled by its release build.
pub fn maintenance_release_pins() -> Option<MaintenanceReleasePins> {
    maintenance_compiled::RELEASE_PINS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeProvider {
    MacOsKeychainPathRequired,
    WindowsDpapi,
    LinuxStorageChoiceRequired,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapError {
    ConfigurationRequired,
    ProtectedFileConsentRequired,
    KeychainPathRequired,
    InvalidKeychainPath,
    UnexpectedKeychainPath,
    UnexpectedProtectedFileAcknowledgement,
    UnsupportedProvider,
    InvalidCompiledConfiguration,
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConfigurationRequired => "HOST_BOOTSTRAP_CONFIGURATION_REQUIRED",
            Self::ProtectedFileConsentRequired => "HOST_PROTECTED_FILE_CONSENT_REQUIRED",
            Self::KeychainPathRequired => "HOST_KEYCHAIN_PATH_REQUIRED",
            Self::InvalidKeychainPath => "HOST_KEYCHAIN_PATH_INVALID",
            Self::UnexpectedKeychainPath => "HOST_KEYCHAIN_PATH_UNEXPECTED",
            Self::UnexpectedProtectedFileAcknowledgement => {
                "HOST_PROTECTED_FILE_ACKNOWLEDGEMENT_UNEXPECTED"
            }
            Self::UnsupportedProvider => "HOST_BOOTSTRAP_PROVIDER_UNSUPPORTED",
            Self::InvalidCompiledConfiguration => "HOST_BOOTSTRAP_CONFIGURATION_INVALID",
        })
    }
}

impl Error for BootstrapError {}

/// Return the release's validated public pins, or `None` for an unconfigured
/// debug build. Runtime environment variables cannot override these values.
pub fn public_release_pins() -> Option<PublicPins> {
    compiled::RELEASE_PINS
}

pub fn native_provider() -> NativeProvider {
    #[cfg(target_os = "macos")]
    {
        NativeProvider::MacOsKeychainPathRequired
    }
    #[cfg(windows)]
    {
        NativeProvider::WindowsDpapi
    }
    #[cfg(target_os = "linux")]
    {
        NativeProvider::LinuxStorageChoiceRequired
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    {
        NativeProvider::Unsupported
    }
}

/// Construct the native provider selection and the embedded public pins.
///
/// `protected_file_acknowledged` must only be true after the UI has shown that
/// this provider stores plaintext protected by OS permissions. This function
/// does not save the configuration, start login, or grant sharing consent.
/// On Linux, an unacknowledged protected-file choice is never inferred: false
/// selects Secret Service, whose availability is checked by the selected Host
/// account at runtime. A storage failure never changes that selection.
pub fn default_auth_configuration(
    keychain_path: Option<&Path>,
    protected_file_acknowledged: bool,
) -> Result<LocalAuthConfiguration, BootstrapError> {
    let pins = public_release_pins().ok_or(BootstrapError::ConfigurationRequired)?;
    let (provider, encoded_keychain_path, acknowledgement) = {
        #[cfg(target_os = "macos")]
        {
            if protected_file_acknowledged {
                return Err(BootstrapError::UnexpectedProtectedFileAcknowledgement);
            }
            let path = keychain_path.ok_or(BootstrapError::KeychainPathRequired)?;
            if !path.is_absolute()
                || path.canonicalize().ok().as_deref() != Some(path)
                || !path.is_file()
            {
                return Err(BootstrapError::InvalidKeychainPath);
            }
            let text = path.to_str().ok_or(BootstrapError::InvalidKeychainPath)?;
            let encoded = LocalRootPath::try_from(text.to_owned())
                .map_err(|_| BootstrapError::InvalidKeychainPath)?;
            (LocalAuthProvider::MacOsKeychain, Some(encoded), None)
        }
        #[cfg(windows)]
        {
            if keychain_path.is_some() {
                return Err(BootstrapError::UnexpectedKeychainPath);
            }
            if protected_file_acknowledged {
                return Err(BootstrapError::UnexpectedProtectedFileAcknowledgement);
            }
            (LocalAuthProvider::WindowsDpapi, None, None)
        }
        #[cfg(target_os = "linux")]
        {
            if keychain_path.is_some() {
                return Err(BootstrapError::UnexpectedKeychainPath);
            }
            if protected_file_acknowledged {
                (
                    LocalAuthProvider::ProtectedFile,
                    None,
                    Some(LocalFileAcknowledgement::OsPermissionsOnly),
                )
            } else {
                (LocalAuthProvider::LinuxSecretService, None, None)
            }
        }
        #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
        {
            let _ = (keychain_path, protected_file_acknowledged);
            return Err(BootstrapError::UnsupportedProvider);
        }
    };

    let configuration = LocalAuthConfiguration {
        version: 1,
        origin: LocalAuthOrigin::try_from(pins.identity_origin.to_owned())
            .map_err(|_| BootstrapError::InvalidCompiledConfiguration)?,
        remote_api_origin: Some(
            LocalAuthOrigin::try_from(pins.remote_api_origin.to_owned())
                .map_err(|_| BootstrapError::InvalidCompiledConfiguration)?,
        ),
        relay_endpoint: Some(
            LocalRelayEndpoint::try_from(pins.relay_endpoint.to_owned())
                .map_err(|_| BootstrapError::InvalidCompiledConfiguration)?,
        ),
        client_id: LocalAuthClientId::try_from(pins.client_id.to_owned())
            .map_err(|_| BootstrapError::InvalidCompiledConfiguration)?,
        provider,
        keychain_path: encoded_keychain_path,
        protected_file_acknowledgement: acknowledgement,
    };
    configuration
        .validate()
        .map_err(|_| BootstrapError::InvalidCompiledConfiguration)?;
    Ok(configuration)
}
