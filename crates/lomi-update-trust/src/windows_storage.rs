//! Windows private-state adapter for TUF metadata and the updater lock.
//!
//! Every file/directory is opened with OPEN_REPARSE_POINT. Private state has a
//! protected, current-user-only DACL; ordinary mirror inputs are read-only but
//! still reject reparse points and multiply-linked files.

use crate::{MAX_TARGET, Result, invalid};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    mem,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Com::CoTaskMemFree, IO::*, SystemServices::*, Threading::*},
    UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct Local(*mut core::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Security {
    _descriptor: Local,
    attributes: SECURITY_ATTRIBUTES,
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn checked_handle(handle: HANDLE) -> io::Result<Handle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(Handle(handle))
    }
}

fn check(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn current_sid() -> Result<String> {
    let mut token = ptr::null_mut();
    unsafe {
        check(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ))?
    };
    let token = checked_handle(token)?;
    let mut length = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut length);
    }
    if length == 0 || length > 4096 {
        return Err(invalid("could not identify the current Windows account"));
    }
    let mut storage = vec![0usize; (length as usize).div_ceil(mem::size_of::<usize>())];
    unsafe {
        check(GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            length,
            &mut length,
        ))?;
        sid_text((*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid)
    }
}

fn sid_text(sid: PSID) -> Result<String> {
    let mut text = ptr::null_mut();
    unsafe { check(ConvertSidToStringSidW(sid, &mut text))? };
    let guard = Local(text.cast());
    let mut length = 0usize;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
            if length > 256 {
                return Err(invalid("Windows account SID exceeds its bound"));
            }
        }
        let result = String::from_utf16(std::slice::from_raw_parts(text, length))
            .map_err(|_| invalid("invalid Windows account SID"))?;
        drop(guard);
        Ok(result)
    }
}

fn security(sid: &str, directory: bool) -> Result<Security> {
    let inheritance = if directory { "OICI" } else { "" };
    security_sddl(&format!("O:{sid}D:P(A;{inheritance};FA;;;{sid})"))
}

fn security_sddl(sddl: &str) -> Result<Security> {
    let sddl = wide(sddl);
    let mut descriptor = ptr::null_mut();
    unsafe {
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        ))?;
    }
    Ok(Security {
        _descriptor: Local(descriptor.cast()),
        attributes: SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        },
    })
}

fn information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut value = unsafe { mem::zeroed() };
    unsafe { check(GetFileInformationByHandle(handle, &mut value))? };
    Ok(value)
}

fn trusted_sid(sid: &str, owner: &str) -> bool {
    sid == owner
        || matches!(
            sid,
            "S-1-5-18"
                | "S-1-5-32-544"
                | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        )
}

fn validate_security(handle: HANDLE, owner: &str, private: bool, directory: bool) -> Result<()> {
    let (mut descriptor, mut sid, mut acl) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut sid,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS || descriptor.is_null() || acl.is_null() {
        return Err(invalid("cannot inspect updater file security"));
    }
    let _descriptor = Local(descriptor.cast());
    let actual_owner = sid_text(sid)?;
    if (private && actual_owner != owner) || (!private && !trusted_sid(&actual_owner, owner)) {
        return Err(invalid("updater file has an untrusted owner"));
    }
    if private && directory {
        let mut control = 0;
        let mut revision = 0;
        unsafe {
            check(GetSecurityDescriptorControl(
                descriptor,
                &mut control,
                &mut revision,
            ))?
        };
        if control & SE_DACL_PROTECTED == 0 {
            return Err(invalid("updater state directory DACL is not protected"));
        }
    }
    let mut sizes: ACL_SIZE_INFORMATION = unsafe { mem::zeroed() };
    unsafe {
        check(GetAclInformation(
            acl,
            (&mut sizes as *mut ACL_SIZE_INFORMATION).cast(),
            mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ))?;
    }
    let mut owner_grant = false;
    for index in 0..sizes.AceCount {
        let mut ace = ptr::null_mut();
        unsafe { check(GetAce(acl, index, &mut ace))? };
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(invalid("updater DACL contains an unsupported ACE"));
        }
        // Inherited-only allow ACEs govern children, not the current trusted
        // ancestor. Keep this exception out of exact private-leaf validation.
        if !private && directory && header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let who = sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?;
        let flags = header.AceFlags as u32 & !INHERITED_ACE;
        if private {
            let expected_flags = if directory {
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            } else {
                0
            };
            if who != owner || allowed.Mask != FILE_ALL_ACCESS || flags != expected_flags {
                return Err(invalid("updater state DACL is not current-user-only"));
            }
            owner_grant = true;
        } else if !trusted_sid(&who, owner) {
            // Trusted directory ancestors such as ProgramData and a drive root
            // may let ordinary users create files or subdirectories. Those
            // create-only rights cannot replace an existing protected child;
            // DELETE and DELETE_CHILD remain forbidden, as do descriptor and
            // file-data/attribute changes. Every existing component is opened
            // without following reparse points; a pre-created wrong-owner path
            // or reparse point therefore fails its owner/type/DACL checks.
            let mut forbidden = FILE_DELETE_CHILD
                | WRITE_DAC
                | WRITE_OWNER
                | DELETE
                | GENERIC_ALL
                | GENERIC_WRITE
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES;
            if !directory {
                forbidden |= FILE_WRITE_DATA | FILE_APPEND_DATA;
            }
            if allowed.Mask & forbidden != 0 {
                return Err(invalid("updater path is writable by an untrusted account"));
            }
        }
    }
    if private && !owner_grant {
        return Err(invalid("updater state DACL omits the current account"));
    }
    Ok(())
}

const SYSTEM_SID: &str = "S-1-5-18";
const ADMIN_SID: &str = "S-1-5-32-544";

#[derive(Clone, Copy)]
struct ExpectedAce<'a> {
    sid: &'a str,
    mask: u32,
    flags: u8,
}

fn file_access_mask(mut mask: u32) -> u32 {
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    unsafe { MapGenericMask(&mut mask, &mapping) };
    mask
}

fn validate_host_area_acl(
    handle: HANDLE,
    expected_owner: &str,
    expected: &[ExpectedAce<'_>],
) -> Result<()> {
    let (mut descriptor, mut owner, mut acl) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() || acl.is_null() {
        return Err(invalid("cannot inspect administrator Host release ACL"));
    }
    let _descriptor = Local(descriptor.cast());
    if sid_text(owner)? != expected_owner {
        return Err(invalid("administrator Host release owner mismatch"));
    }
    let (mut control, mut revision) = (0u16, 0u32);
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(invalid("administrator Host release DACL is not protected"));
    }
    let acl = unsafe { &*acl };
    if acl.AceCount as usize != expected.len() || acl.AceCount > 16 {
        return Err(invalid(
            "administrator Host release ACL has unexpected ACEs",
        ));
    }
    let mut seen = vec![false; expected.len()];
    for index in 0..acl.AceCount {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 || ace.is_null() {
            return Err(invalid("cannot read administrator Host release ACE"));
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(invalid(
                "administrator Host release ACL has unsupported ACE",
            ));
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?;
        let mask = file_access_mask(allowed.Mask);
        let Some((slot, _)) = expected.iter().enumerate().find(|(slot, expected)| {
            !seen[*slot]
                && expected.sid == sid
                && expected.mask == mask
                && expected.flags == header.AceFlags
        }) else {
            return Err(invalid(
                "administrator Host release ACL differs from policy",
            ));
        };
        seen[slot] = true;
    }
    if seen.iter().any(|value| !value) {
        return Err(invalid("administrator Host release ACL is incomplete"));
    }
    Ok(())
}

fn open_host_area_directory(path: &Path) -> Result<Handle> {
    let path = normalized(path)?;
    let handle = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    let handle = checked_handle(handle)?;
    let info = information(handle.0)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(invalid("administrator Host path is not a real directory"));
    }
    Ok(handle)
}

fn ensure_host_area_directory(path: &Path, sddl: &str) -> Result<Handle> {
    let descriptor = security_sddl(sddl)?;
    let result =
        unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &descriptor.attributes) };
    let created = result != 0;
    if !created && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
        return Err(io::Error::last_os_error().into());
    }
    let result = (|| {
        let handle = open_host_area_directory(path)?;
        if normalized(&fs::canonicalize(path)?)? != normalized(path)? {
            return Err(invalid("administrator Host path is not canonical"));
        }
        Ok(handle)
    })();
    if result.is_err() && created {
        let _ = unsafe { RemoveDirectoryW(wide(path.as_os_str()).as_ptr()) };
    }
    result
}

fn known_program_data() -> Result<PathBuf> {
    let mut output = ptr::null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut output) };
    if result < 0 || output.is_null() {
        return Err(invalid("cannot resolve the native ProgramData folder"));
    }
    let path = unsafe {
        let mut length = 0usize;
        while *output.add(length) != 0 {
            length += 1;
            if length > 32768 {
                CoTaskMemFree(output.cast());
                return Err(invalid("ProgramData path exceeds its bound"));
            }
        }
        let value = PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(
            output, length,
        )));
        CoTaskMemFree(output.cast());
        value
    };
    normalized(&path)
}

fn pin_program_data_chain(path: &Path, owner: &str) -> Result<Vec<Handle>> {
    let path = normalized(path)?;
    if normalized(&fs::canonicalize(&path)?)? != path {
        return Err(invalid("ProgramData path is not canonical"));
    }
    let mut pins = Vec::new();
    let mut ancestors = path.ancestors().map(Path::to_path_buf).collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        if !ancestor.is_absolute() {
            continue;
        }
        let handle = open_host_area_directory(&ancestor)?;
        validate_security(handle.0, owner, false, true)?;
        pins.push(handle);
    }
    Ok(pins)
}

/// Pinned native ProgramData area for the administrator-managed Host pair.
/// Trust and activation state are private to the invoking administrator;
/// only the fixed Install images are readable/executable by the selected SID.
pub(crate) struct AdminHostReleaseArea {
    owner_sid: String,
    trust: PathBuf,
    activation: PathBuf,
    install: PathBuf,
    _pins: Vec<Handle>,
}

impl AdminHostReleaseArea {
    pub(crate) fn open_or_create(owner_sid: &str) -> Result<Self> {
        if owner_sid.len() > 184
            || !owner_sid.starts_with("S-1-5-")
            || !owner_sid.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte == b'S'
                } else {
                    byte.is_ascii_digit() || byte == b'-'
                }
            })
            || owner_sid.ends_with('-')
            || owner_sid.contains("--")
        {
            return Err(invalid("selected Windows account SID is malformed"));
        }
        let administrator = current_sid()?;
        if owner_sid == administrator {
            return Err(invalid(
                "administrator Host requires a distinct ordinary SID",
            ));
        }
        let program_data = known_program_data()?;
        let mut pins = pin_program_data_chain(&program_data, &administrator)?;
        let root = program_data.join("LomiRemote");
        let host_services = root.join("HostServices");
        let owner = host_services.join(owner_sid);
        let trust = owner.join("trust");
        let activation = owner.join("activation");
        let install = owner.join("Install");

        let root_sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GX;;;AU)";
        for directory in [&root, &host_services] {
            let handle = ensure_host_area_directory(directory, root_sddl)?;
            validate_host_area_acl(
                handle.0,
                ADMIN_SID,
                &[
                    ExpectedAce {
                        sid: SYSTEM_SID,
                        mask: FILE_ALL_ACCESS,
                        flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                    },
                    ExpectedAce {
                        sid: ADMIN_SID,
                        mask: FILE_ALL_ACCESS,
                        flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                    },
                    ExpectedAce {
                        sid: "S-1-5-11",
                        mask: FILE_GENERIC_EXECUTE,
                        flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                    },
                ],
            )?;
            pins.push(handle);
        }
        let owner_sddl = format!(
            "O:BA G:BA D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GX;;;AU)(A;OICI;GRGX;;;{owner_sid})"
        );
        let owner_handle = ensure_host_area_directory(&owner, &owner_sddl)?;
        validate_host_area_acl(
            owner_handle.0,
            ADMIN_SID,
            &[
                ExpectedAce {
                    sid: SYSTEM_SID,
                    mask: FILE_ALL_ACCESS,
                    flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                },
                ExpectedAce {
                    sid: ADMIN_SID,
                    mask: FILE_ALL_ACCESS,
                    flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                },
                ExpectedAce {
                    sid: "S-1-5-11",
                    mask: FILE_GENERIC_EXECUTE,
                    flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                },
                ExpectedAce {
                    sid: owner_sid,
                    mask: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                    flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                },
            ],
        )?;
        pins.push(owner_handle);

        match fs::symlink_metadata(&trust) {
            Ok(_) => {
                private_dir(&trust)?;
                pins.push(open_host_area_directory(&trust)?);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match fs::symlink_metadata(&activation) {
            Ok(_) => private_dir(&activation)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_dir(&activation)?;
            }
            Err(error) => return Err(error.into()),
        }
        pins.push(open_host_area_directory(&activation)?);
        let install_sddl =
            format!("O:BA G:BA D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{owner_sid})");
        let install_handle = ensure_host_area_directory(&install, &install_sddl)?;
        validate_host_area_acl(
            install_handle.0,
            ADMIN_SID,
            &[
                ExpectedAce {
                    sid: SYSTEM_SID,
                    mask: FILE_ALL_ACCESS,
                    flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                },
                ExpectedAce {
                    sid: ADMIN_SID,
                    mask: FILE_ALL_ACCESS,
                    flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                },
                ExpectedAce {
                    sid: owner_sid,
                    mask: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                    flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
                },
            ],
        )?;
        pins.push(install_handle);
        Ok(Self {
            owner_sid: owner_sid.to_owned(),
            trust,
            activation,
            install,
            _pins: pins,
        })
    }

    pub(crate) fn trust_path(&self) -> &Path {
        &self.trust
    }

    pub(crate) fn activation_path(&self) -> &Path {
        &self.activation
    }

    pub(crate) fn install_path(&self) -> &Path {
        &self.install
    }

    pub(crate) fn owner_sid(&self) -> &str {
        &self.owner_sid
    }

    pub(crate) fn pin_trust(&mut self) -> Result<()> {
        private_dir(&self.trust)?;
        self._pins.push(open_host_area_directory(&self.trust)?);
        Ok(())
    }

    pub(crate) fn require_fresh_install_area(&self) -> Result<()> {
        match fs::symlink_metadata(&self.trust) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(invalid("cannot initialize existing Host trust state")),
            Err(error) => return Err(error.into()),
        }
        let owner_directory = self
            .install
            .parent()
            .ok_or_else(|| invalid("administrator Host owner directory is missing"))?;
        let mut names = Vec::with_capacity(2);
        for entry in fs::read_dir(owner_directory)? {
            if names.len() == 2 {
                return Err(invalid(
                    "cannot initialize Host trust beside unexpected release state",
                ));
            }
            names.push(
                entry?
                    .file_name()
                    .into_string()
                    .map_err(|_| invalid("administrator Host state has a non-Unicode entry"))?,
            );
        }
        names.sort_unstable();
        if names != ["Install", "activation"] {
            return Err(invalid(
                "cannot initialize Host trust beside unexpected release state",
            ));
        }
        for directory in [&self.activation, &self.install] {
            let mut entries = fs::read_dir(directory)?;
            if entries.next().transpose()?.is_some() {
                return Err(invalid(
                    "cannot initialize Host trust beside existing release images",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn publish_pair(
        &self,
        primary: &[u8],
        helper: &[u8],
        previous: Option<(&str, &str)>,
        allow_missing: bool,
    ) -> Result<(String, String)> {
        let primary_digest = sha256(primary);
        let helper_digest = sha256(helper);
        let old = previous;
        let current_primary =
            existing_image_digest(&self.install.join("lomiremote.exe"), &self.owner_sid)?;
        let current_helper =
            existing_image_digest(&self.install.join("lomiremote-host.exe"), &self.owner_sid)?;
        validate_image_transition(
            current_primary.as_deref(),
            &primary_digest,
            old.map(|pair| pair.0),
            allow_missing,
        )?;
        validate_image_transition(
            current_helper.as_deref(),
            &helper_digest,
            old.map(|pair| pair.1),
            allow_missing,
        )?;
        publish_host_image_from(
            &self.install,
            "lomiremote.exe",
            &self.owner_sid,
            primary,
            &primary_digest,
            old.map(|pair| pair.0),
            allow_missing,
        )?;
        publish_host_image_from(
            &self.install,
            "lomiremote-host.exe",
            &self.owner_sid,
            helper,
            &helper_digest,
            old.map(|pair| pair.1),
            allow_missing,
        )?;
        if existing_image_digest(&self.install.join("lomiremote.exe"), &self.owner_sid)?.as_deref()
            != Some(primary_digest.as_str())
            || existing_image_digest(&self.install.join("lomiremote-host.exe"), &self.owner_sid)?
                .as_deref()
                != Some(helper_digest.as_str())
        {
            return Err(invalid("published Host image pair failed verification"));
        }
        Ok((primary_digest, helper_digest))
    }

    pub(crate) fn remove_pair(&self, primary: &str, helper: &str) -> Result<()> {
        let primary_path = self.install.join("lomiremote.exe");
        let helper_path = self.install.join("lomiremote-host.exe");
        let current_primary = existing_image_digest(&primary_path, &self.owner_sid)?;
        let current_helper = existing_image_digest(&helper_path, &self.owner_sid)?;
        if current_primary
            .as_deref()
            .is_some_and(|value| value != primary)
            || current_helper
                .as_deref()
                .is_some_and(|value| value != helper)
        {
            return Err(invalid("refusing to remove an unrecognized Host image"));
        }
        if current_primary.is_some()
            && unsafe { DeleteFileW(wide(primary_path.as_os_str()).as_ptr()) } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if current_helper.is_some()
            && unsafe { DeleteFileW(wide(helper_path.as_os_str()).as_ptr()) } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_image_transition(
    current: Option<&str>,
    desired: &str,
    previous: Option<&str>,
    allow_missing: bool,
) -> Result<()> {
    if current == Some(desired)
        || current == previous
        || (current.is_none() && (previous.is_none() || allow_missing))
    {
        Ok(())
    } else {
        Err(invalid(
            "existing Host image is outside the authenticated update pair",
        ))
    }
}

fn expected_host_file_acl(handle: HANDLE, owner_sid: &str) -> Result<()> {
    validate_host_area_acl(
        handle,
        ADMIN_SID,
        &[
            ExpectedAce {
                sid: SYSTEM_SID,
                mask: FILE_ALL_ACCESS,
                flags: 0,
            },
            ExpectedAce {
                sid: ADMIN_SID,
                mask: FILE_ALL_ACCESS,
                flags: 0,
            },
            ExpectedAce {
                sid: owner_sid,
                mask: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                flags: 0,
            },
        ],
    )
}

fn open_host_image(path: &Path, owner_sid: &str) -> Result<File> {
    let path = normalized(path)?;
    let raw = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    let handle = checked_handle(raw)?;
    let info = information(handle.0)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
        || info.nFileSizeHigh != 0
        || ((info.nFileSizeHigh as u64) << 32 | info.nFileSizeLow as u64) > MAX_TARGET as u64
    {
        return Err(invalid(
            "Host image is not a bounded single-link regular file",
        ));
    }
    expected_host_file_acl(handle.0, owner_sid)?;
    let raw = handle.0;
    mem::forget(handle);
    Ok(unsafe { File::from_raw_handle(raw) })
}

fn existing_image_digest(path: &Path, owner_sid: &str) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => {
            let mut file = open_host_image(path, owner_sid)?;
            let metadata = file.metadata()?;
            if metadata.len() == 0 || metadata.len() > MAX_TARGET as u64 {
                return Err(invalid("existing Host image is outside its size bound"));
            }
            let mut hash = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            let mut total = 0u64;
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                total = total
                    .checked_add(count as u64)
                    .ok_or_else(|| invalid("Host image size overflow"))?;
                if total > MAX_TARGET as u64 {
                    return Err(invalid("existing Host image exceeds its bound"));
                }
                hash.update(&buffer[..count]);
            }
            Ok(Some(format!("{:x}", hash.finalize())))
        }
    }
}

struct HostImageStage {
    directory: PathBuf,
    image: PathBuf,
    handle: Option<Handle>,
    published: bool,
}

impl Drop for HostImageStage {
    fn drop(&mut self) {
        drop(self.handle.take());
        if !self.published {
            let _ = unsafe { DeleteFileW(wide(self.image.as_os_str()).as_ptr()) };
        }
        let _ = unsafe { RemoveDirectoryW(wide(self.directory.as_os_str()).as_ptr()) };
    }
}

fn publish_host_image_from(
    install: &Path,
    name: &str,
    owner_sid: &str,
    bytes: &[u8],
    digest: &str,
    previous: Option<&str>,
    allow_missing: bool,
) -> Result<()> {
    let destination = install.join(name);
    let initial = existing_image_digest(&destination, owner_sid)?;
    validate_image_transition(initial.as_deref(), digest, previous, allow_missing)?;
    if initial.as_deref() == Some(digest) {
        return Ok(());
    }
    if bytes.is_empty() || bytes.len() > MAX_TARGET || sha256(bytes) != digest {
        return Err(invalid(
            "verified Host image bytes changed before publication",
        ));
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock is before the Unix epoch"))?
        .as_nanos();
    let stage_dir = install.join(format!(
        ".lomi-admin-image-{}-{timestamp}-{sequence}",
        std::process::id()
    ));
    let stage_sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    let stage_handle = ensure_host_area_directory(&stage_dir, stage_sddl)?;
    let stage = stage_dir.join(name);
    let mut stage_guard = HostImageStage {
        directory: stage_dir,
        image: stage,
        handle: Some(stage_handle),
        published: false,
    };
    validate_host_area_acl(
        stage_guard
            .handle
            .as_ref()
            .ok_or_else(|| invalid("lost Host image stage pin"))?
            .0,
        ADMIN_SID,
        &[
            ExpectedAce {
                sid: SYSTEM_SID,
                mask: FILE_ALL_ACCESS,
                flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
            },
            ExpectedAce {
                sid: ADMIN_SID,
                mask: FILE_ALL_ACCESS,
                flags: (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
            },
        ],
    )?;
    let file_sddl = format!("O:BA G:BA D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;{owner_sid})");
    let descriptor = security_sddl(&file_sddl)?;
    let raw = unsafe {
        CreateFileW(
            wide(stage_guard.image.as_os_str()).as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &descriptor.attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    let handle = checked_handle(raw)?;
    let raw = handle.0;
    mem::forget(handle);
    let mut file = unsafe { File::from_raw_handle(raw) };
    file.write_all(bytes)?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count)
            .ok_or_else(|| invalid("staged Host image size overflow"))?;
        if total > MAX_TARGET {
            return Err(invalid("staged Host image exceeds its bound"));
        }
        hash.update(&buffer[..count]);
    }
    if total != bytes.len() || format!("{:x}", hash.finalize()) != digest {
        return Err(invalid("staged Host image hash mismatch"));
    }
    expected_host_file_acl(file.as_raw_handle().cast(), owner_sid)?;
    drop(file);

    let before_publish = existing_image_digest(&destination, owner_sid)?;
    validate_image_transition(before_publish.as_deref(), digest, previous, allow_missing)?;
    if before_publish.as_deref() == Some(digest) {
        return Ok(());
    }
    let replace = before_publish.is_some();
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    if unsafe {
        MoveFileExW(
            wide(stage_guard.image.as_os_str()).as_ptr(),
            wide(destination.as_os_str()).as_ptr(),
            flags,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    stage_guard.published = true;
    existing_image_digest(&destination, owner_sid)?
        .filter(|actual| actual == digest)
        .ok_or_else(|| invalid("published Host image failed hash verification"))?;
    Ok(())
}

fn normalized(path: &Path) -> Result<PathBuf> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid("updater path is not Unicode"))?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    if !Path::new(text).is_absolute()
        || text.len() > 2048
        || text.chars().any(char::is_control)
        || Path::new(text)
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid("updater path is not canonical and absolute"));
    }
    Ok(PathBuf::from(text))
}

fn open_handle_unvalidated(
    path: &Path,
    write: bool,
    directory: bool,
    create_new: bool,
    sid: &str,
) -> Result<Handle> {
    let path = normalized(path)?;
    let descriptor = security(sid, directory)?;
    let access = READ_CONTROL
        | FILE_READ_ATTRIBUTES
        | if directory {
            0
        } else {
            GENERIC_READ | if write { GENERIC_WRITE } else { 0 }
        };
    let disposition = if create_new {
        CREATE_NEW
    } else {
        OPEN_EXISTING
    };
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let handle = unsafe {
        CreateFileW(
            wide(&path).as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &descriptor.attributes,
            disposition,
            flags,
            ptr::null_mut(),
        )
    };
    let handle = checked_handle(handle)?;
    let info = information(handle.0)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(invalid(
            "updater path is a reparse point, wrong type, or hard link",
        ));
    }
    Ok(handle)
}

fn open_handle(path: &Path, write: bool, directory: bool, create_new: bool) -> Result<Handle> {
    let sid = current_sid()?;
    let handle = open_handle_unvalidated(path, write, directory, create_new, &sid)?;
    validate_security(handle.0, &sid, true, directory)?;
    Ok(handle)
}

fn open_mirror_file(path: &Path) -> Result<File> {
    let path = normalized(path)?;
    let sid = current_sid()?;
    if let Some(parent) = path.parent() {
        for ancestor in parent.ancestors() {
            let directory = normalized(ancestor)?;
            let descriptor = security(&sid, true)?;
            let handle = unsafe {
                CreateFileW(
                    wide(&directory).as_ptr(),
                    READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    &descriptor.attributes,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    ptr::null_mut(),
                )
            };
            let handle = checked_handle(handle)?;
            let info = information(handle.0)?;
            if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            {
                return Err(invalid(
                    "mirror path contains a reparse point or non-directory",
                ));
            }
            validate_security(handle.0, &sid, false, true)?;
        }
    }
    let descriptor = security(&sid, false)?;
    let handle = unsafe {
        CreateFileW(
            wide(&path).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &descriptor.attributes,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    let handle = checked_handle(handle)?;
    let info = information(handle.0)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(invalid("mirror input is not a single-link regular file"));
    }
    let raw = handle.0;
    mem::forget(handle);
    Ok(unsafe { File::from_raw_handle(raw) })
}

pub(crate) fn private_file(path: &Path) -> Result<()> {
    let handle = open_handle(path, false, false, false)?;
    drop(handle);
    Ok(())
}

fn validate_directory_path(path: &Path, leaf_private: bool) -> Result<()> {
    let normalized_path = normalized(path)?;
    let canonical = normalized(&fs::canonicalize(&normalized_path)?)?;
    if canonical != normalized_path {
        return Err(invalid("updater directory is not canonical"));
    }
    let owner = current_sid()?;
    for ancestor in normalized_path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        // Ancestors may be administrator- or system-owned; check only that
        // each component is a real directory without following reparse points,
        // then apply the explicitly selected trusted-ancestor/private-leaf
        // security policy exactly once.
        let handle = open_handle_unvalidated(ancestor, false, true, false, &owner)?;
        validate_security(
            handle.0,
            &owner,
            leaf_private && ancestor == normalized_path,
            true,
        )?;
    }
    Ok(())
}

pub(crate) fn private_dir(path: &Path) -> Result<()> {
    validate_directory_path(path, true)
}

pub(crate) fn create_private_dir(path: &Path) -> Result<()> {
    let path = normalized(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("updater directory has no parent"))?;
    validate_directory_path(parent, false)?;
    let sid = current_sid()?;
    let descriptor = security(&sid, true)?;
    unsafe {
        if CreateDirectoryW(wide(&path).as_ptr(), &descriptor.attributes) == 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    validate_directory_path(&path, true)
}

static NEXT_STAGE_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub(crate) struct PrivateTempDir {
    path: PathBuf,
    handle: Option<File>,
}
impl PrivateTempDir {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        drop(self.handle.take());
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Create a fresh verification directory with its exact current-account DACL
/// in place before any metadata or target bytes are written.
pub(crate) fn create_private_tempdir(parent: &Path, prefix: &str) -> Result<PrivateTempDir> {
    let parent = normalized(parent)?;
    private_dir(&parent)?;
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(invalid("invalid private verification directory prefix"));
    }
    let sid = current_sid()?;
    let descriptor = security(&sid, true)?;
    let parent_path = PathBuf::from(parent);
    for _ in 0..32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("system clock is before the Unix epoch"))?
            .as_nanos();
        let sequence = NEXT_STAGE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = parent_path.join(format!("{prefix}{}-{now}-{sequence}", std::process::id()));
        let created =
            unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &descriptor.attributes) };
        if created == 0 {
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                continue;
            }
            return Err(io::Error::last_os_error().into());
        }
        let result = (|| {
            if normalized(&fs::canonicalize(&path)?)? != normalized(&path)? {
                return Err(invalid("verification stage directory is not canonical"));
            }
            private_dir(&path)?;
            let handle = unsafe {
                CreateFileW(
                    wide(path.as_os_str()).as_ptr(),
                    READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &descriptor.attributes,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    ptr::null_mut(),
                )
            };
            let handle = checked_handle(handle)?;
            let info = information(handle.0)?;
            if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(invalid("verification stage is not a real directory"));
            }
            validate_security(handle.0, &sid, true, true)?;
            let raw = handle.0;
            mem::forget(handle);
            Ok(unsafe { File::from_raw_handle(raw.cast()) })
        })();
        return match result {
            Ok(handle) => Ok(PrivateTempDir {
                path,
                handle: Some(handle),
            }),
            Err(error) => {
                let _ = fs::remove_dir_all(&path);
                Err(error)
            }
        };
    }
    Err(invalid(
        "could not allocate a private verification directory",
    ))
}

pub(crate) fn create_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("updater file has no parent"))?;
    private_dir(parent)?;
    let handle = open_handle(path, true, false, true)?;
    let raw = handle.0;
    mem::forget(handle);
    let mut file = unsafe { File::from_raw_handle(raw) };
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if result.is_err() {
        // This helper creates the path exclusively. Remove an incomplete stage
        // after write/flush failure so later immutable publication can retry.
        let _ = fs::remove_file(path);
    }
    result.map_err(Into::into)
}

pub(crate) fn open_private_file(path: &Path, write: bool) -> Result<File> {
    let handle = open_handle(path, write, false, false)?;
    let raw = handle.0;
    mem::forget(handle);
    Ok(unsafe { File::from_raw_handle(raw) })
}

pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = open_mirror_file(path)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(invalid("file exceeds verification limit"));
    }
    let mut output = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut output)?;
    if output.len() > limit {
        return Err(invalid("file exceeds verification limit"));
    }
    Ok(output)
}

pub(crate) fn ensure_private_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => private_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_private_file(path, b""),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn sync_dir(_path: &Path) -> io::Result<()> {
    // Windows uses file FlushFileBuffers and MOVEFILE_WRITE_THROUGH for the
    // updater's durable boundaries; there is no Unix directory-fsync analogue.
    Ok(())
}

pub(crate) fn lock_file(file: &File) -> Result<()> {
    let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } == 0
    {
        return if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "updater state is already owned").into())
        } else {
            Err(io::Error::last_os_error().into())
        };
    }
    Ok(())
}
