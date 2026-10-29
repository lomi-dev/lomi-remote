//! Public configuration only. No credential or provider payload is represented.
use lomi_remote_protocol::ipc::LocalAuthConfiguration;
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const MAX_BYTES: usize = 65_536;
pub const MAX_REVISION: u64 = i64::MAX as u64;

/// Errors deliberately retain neither parser diagnostics nor source values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io,
    Invalid,
    TooLarge,
    InvalidStorage,
    Stale,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Io => "PUBLIC_CONFIG_IO",
            Self::Invalid => "PUBLIC_CONFIG_INVALID",
            Self::TooLarge => "PUBLIC_CONFIG_TOO_LARGE",
            Self::InvalidStorage => "PUBLIC_CONFIG_INVALID_STORAGE",
            Self::Stale => "PUBLIC_CONFIG_STALE",
        })
    }
}
impl std::error::Error for Error {}

/// Version and revision are mandatory. DTO validation also runs after decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub version: u32,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<LocalAuthConfiguration>,
}
impl Configuration {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != 1 || !(1..=MAX_REVISION).contains(&self.revision) {
            return Err(Error::Invalid);
        }
        if let Some(auth) = &self.authentication {
            auth.validate().map_err(|_| Error::Invalid)?;
        }
        Ok(())
    }
}

pub fn decode(bytes: &[u8]) -> Result<Configuration, Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid)?;
    let configuration: Configuration = toml::from_str(text).map_err(|_| Error::Invalid)?;
    configuration.validate()?;
    Ok(configuration)
}
pub fn read(reader: impl Read) -> Result<Configuration, Error> {
    decode(&read_bytes(reader)?)
}
pub(crate) fn read_bytes(reader: impl Read) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    if bytes.len() > MAX_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}
pub fn encode(configuration: &Configuration) -> Result<Vec<u8>, Error> {
    configuration.validate()?;
    let text = toml::to_string_pretty(configuration).map_err(|_| Error::Invalid)?;
    if text.len() > MAX_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(text.into_bytes())
}

#[cfg(test)]
mod tests;
