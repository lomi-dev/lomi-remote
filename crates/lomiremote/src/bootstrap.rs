//! Compile-time public host endpoints for first-run configuration.
//!
//! Values are supplied by the release operator during compilation and never
//! read from process environment at runtime. This module creates only a public
//! `LocalAuthConfiguration` candidate; the caller must obtain explicit user
//! confirmation before sending `LocalCall::AuthConfigure`.

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

/// Outcome of the automatic storage choice. The protected file is never
/// chosen here: it needs an explicit, plain-language confirmation first.
#[derive(Debug)]
pub enum QuickAuth {
    SecureStore(LocalAuthConfiguration),
    FileConsentRequired,
}

/// Prefer the OS secure store when it is usable for the Host's context:
/// the login Keychain on macOS and Secret Service on Linux (session bus
/// present), only for a Host that starts inside a login session. Otherwise
/// the caller must ask for the protected-file consent.
pub fn quick_auth_configuration(login_session: bool) -> Result<QuickAuth, BootstrapError> {
    quick_auth_for(
        native_provider(),
        login_keychain().as_deref(),
        std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some(),
        login_session,
    )
}

fn quick_auth_for(
    provider: NativeProvider,
    keychain: Option<&Path>,
    session_bus: bool,
    login_session: bool,
) -> Result<QuickAuth, BootstrapError> {
    if !secure_store_usable(provider, keychain, session_bus, login_session) {
        return if provider == NativeProvider::Unsupported {
            Err(BootstrapError::UnsupportedProvider)
        } else {
            Ok(QuickAuth::FileConsentRequired)
        };
    }
    let keychain = (provider == NativeProvider::MacOsKeychainPathRequired)
        .then_some(keychain)
        .flatten();
    default_auth_configuration(keychain, false).map(QuickAuth::SecureStore)
}

fn secure_store_usable(
    provider: NativeProvider,
    keychain: Option<&Path>,
    session_bus: bool,
    login_session: bool,
) -> bool {
    match provider {
        NativeProvider::MacOsKeychainPathRequired => login_session && keychain.is_some(),
        NativeProvider::LinuxStorageChoiceRequired => login_session && session_bus,
        NativeProvider::WindowsDpapi => true,
        NativeProvider::Unsupported => false,
    }
}

/// The signed-in user's default file Keychain, only for a local login (a
/// remote shell cannot rely on an unlocked Keychain).
fn login_keychain() -> Option<std::path::PathBuf> {
    if !cfg!(target_os = "macos") || std::env::var_os("SSH_CONNECTION").is_some() {
        return None;
    }
    let path = Path::new(&std::env::var_os("HOME")?)
        .join("Library/Keychains/login.keychain-db")
        .canonicalize()
        .ok()?;
    path.is_file().then_some(path)
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
            // A boot-mode Host runs without a signed-in user, so no Keychain is
            // unlocked for it; the acknowledged protected file is its option.
            if protected_file_acknowledged {
                if keychain_path.is_some() {
                    return Err(BootstrapError::UnexpectedKeychainPath);
                }
                (
                    LocalAuthProvider::ProtectedFile,
                    None,
                    Some(LocalFileAcknowledgement::OsPermissionsOnly),
                )
            } else {
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

#[cfg(test)]
mod quick_auth_tests {
    use super::*;
    use NativeProvider::*;

    #[test]
    fn secure_store_is_preferred_only_when_usable() {
        let keychain = Some(Path::new("/Users/a/Library/Keychains/login.keychain-db"));
        assert!(secure_store_usable(
            MacOsKeychainPathRequired,
            keychain,
            false,
            true
        ));
        assert!(secure_store_usable(
            LinuxStorageChoiceRequired,
            None,
            true,
            true
        ));
        assert!(secure_store_usable(WindowsDpapi, None, false, false));
        assert!(!secure_store_usable(
            MacOsKeychainPathRequired,
            None,
            false,
            true
        ));
        assert!(!secure_store_usable(
            LinuxStorageChoiceRequired,
            None,
            false,
            true
        ));
        // Boot-mode Hosts have no unlocked user keychain or session bus.
        assert!(!secure_store_usable(
            MacOsKeychainPathRequired,
            keychain,
            false,
            false
        ));
        assert!(!secure_store_usable(
            LinuxStorageChoiceRequired,
            None,
            true,
            false
        ));
    }

    #[test]
    fn unusable_store_requires_consent_and_never_picks_the_file() {
        for (provider, keychain, bus, login) in [
            (MacOsKeychainPathRequired, None, false, true),
            (LinuxStorageChoiceRequired, None, false, true),
            (LinuxStorageChoiceRequired, None, true, false),
        ] {
            assert!(matches!(
                quick_auth_for(provider, keychain, bus, login),
                Ok(QuickAuth::FileConsentRequired)
            ));
        }
        assert!(matches!(
            quick_auth_for(Unsupported, None, true, true),
            Err(BootstrapError::UnsupportedProvider)
        ));
    }

    #[test]
    fn usable_store_never_asks_for_file_consent() {
        let result = quick_auth_for(LinuxStorageChoiceRequired, None, true, true);
        // Debug builds without release pins fail closed instead.
        assert!(!matches!(result, Ok(QuickAuth::FileConsentRequired)));
        if let Ok(QuickAuth::SecureStore(configuration)) = result {
            assert!(configuration.protected_file_acknowledgement.is_none());
        }
    }
}
