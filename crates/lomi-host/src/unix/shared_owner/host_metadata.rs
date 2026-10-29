//! Local display name storage and trusted native hostname defaults.
use super::{Error, HostNameWrite, Operation, SharedOwner, StoreError};
use lomi_remote_protocol::{HostId, ipc::LocalHostName};

pub(crate) fn suggested_host_display_name(host_id: Option<HostId>) -> LocalHostName {
    if let Some(name) =
        native_host_name().and_then(|name| LocalHostName::try_from(name.trim().to_owned()).ok())
    {
        return name;
    }
    if let Some(host_id) = host_id {
        let id = String::from(host_id);
        if let Ok(name) = LocalHostName::try_from(format!("LomiHost-{}", &id[..8])) {
            return name;
        }
    }
    LocalHostName::try_from("LomiHost".to_owned()).expect("fixed fallback Host name is valid")
}

#[cfg(unix)]
fn native_host_name() -> Option<String> {
    let mut bytes = [0u8; 256];
    // Leave one byte for a guaranteed terminator even if the platform reports
    // a hostname at the buffer limit.
    let result = unsafe {
        libc::gethostname(
            bytes.as_mut_ptr().cast::<libc::c_char>(),
            bytes.len().saturating_sub(1),
        )
    };
    if result != 0 {
        return None;
    }
    let length = bytes.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&bytes[..length])
        .ok()
        .map(str::to_owned)
}

#[cfg(windows)]
fn native_host_name() -> Option<String> {
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsHostname, GetComputerNameExW,
    };

    let mut buffer = [0u16; 256];
    let mut length = buffer.len() as u32;
    let succeeded =
        unsafe { GetComputerNameExW(ComputerNameDnsHostname, buffer.as_mut_ptr(), &mut length) };
    if succeeded == 0 || length == 0 || length as usize > buffer.len() {
        return None;
    }
    String::from_utf16(&buffer[..length as usize]).ok()
}

#[cfg(not(any(unix, windows)))]
fn native_host_name() -> Option<String> {
    None
}

fn expected_host_name_set(error: StoreError) -> bool {
    matches!(error, StoreError::Invalid | StoreError::RevisionConflict)
}

impl SharedOwner {
    pub(crate) fn begin_host_name_set<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        expected: Option<LocalHostName>,
        name: LocalHostName,
    ) -> Result<HostNameWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| store.set_host_display_name(expected.as_ref(), name.clone()),
            expected_host_name_set,
        )
        .map(HostNameWrite)
    }
}
