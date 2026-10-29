//! Narrow Security/CoreFoundation ABI. No global configuration setters except
//! the helper-only process-local UI prohibition. All searches are explicit.
use super::{Object, object};
use crate::secrets::Error;
use std::os::unix::fs::MetadataExt;
use std::{
    ffi::{CString, c_char, c_void},
    fs,
    path::Path,
    ptr,
};
use zeroize::Zeroizing;
type Ref = *const c_void;
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainSetUserInteractionAllowed(allowed: u8) -> i32;
    fn SecKeychainOpen(path: *const c_char, keychain: *mut Ref) -> i32;
    fn SecKeychainGetPath(keychain: Ref, length: *mut u32, path: *mut c_char) -> i32;
    fn SecKeychainGetStatus(keychain: Ref, status: *mut u32) -> i32;
    fn SecAccessCreate(descriptor: Ref, trusted: Ref, access: *mut Ref) -> i32;
    fn SecItemCopyMatching(query: Ref, result: *mut Ref) -> i32;
    fn SecItemAdd(attributes: Ref, result: *mut Ref) -> i32;
    static kSecClass: Ref;
    static kSecClassGenericPassword: Ref;
    static kSecAttrService: Ref;
    static kSecAttrAccount: Ref;
    static kSecMatchSearchList: Ref;
    static kSecMatchLimit: Ref;
    static kSecMatchLimitOne: Ref;
    static kSecReturnData: Ref;
    static kSecUseKeychain: Ref;
    static kSecValueData: Ref;
    static kSecAttrAccess: Ref;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: Ref);
    fn CFGetTypeID(value: Ref) -> usize;
    fn CFStringCreateWithBytes(
        allocator: Ref,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: u8,
    ) -> Ref;
    fn CFArrayCreate(allocator: Ref, values: *const Ref, count: isize, callbacks: Ref) -> Ref;
    fn CFDictionaryCreate(
        allocator: Ref,
        keys: *const Ref,
        values: *const Ref,
        count: isize,
        key_callbacks: Ref,
        value_callbacks: Ref,
    ) -> Ref;
    fn CFDataCreate(allocator: Ref, bytes: *const u8, length: isize) -> Ref;
    fn CFDataGetTypeID() -> usize;
    fn CFDataGetLength(data: Ref) -> isize;
    fn CFDataGetBytePtr(data: Ref) -> *const u8;
    static kCFBooleanTrue: Ref;
    static kCFTypeArrayCallBacks: u8;
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
}
struct Owned(Ref);
impl Owned {
    fn new(value: Ref) -> Result<Self, Error> {
        if value.is_null() {
            Err(Error::Unavailable)
        } else {
            Ok(Self(value))
        }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}
fn string(value: &str) -> Result<Owned, Error> {
    Owned::new(unsafe {
        CFStringCreateWithBytes(
            ptr::null(),
            value.as_ptr(),
            value.len() as isize,
            0x08000100,
            0,
        )
    })
}
fn dict(entries: &[(Ref, Ref)]) -> Result<Owned, Error> {
    let keys: Vec<_> = entries.iter().map(|v| v.0).collect();
    let values: Vec<_> = entries.iter().map(|v| v.1).collect();
    Owned::new(unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            entries.len() as isize,
            ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast(),
            ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast(),
        )
    })
}
pub(super) fn disable_ui() -> Result<(), Error> {
    if unsafe { SecKeychainSetUserInteractionAllowed(0) } == 0 {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}
pub(super) fn validate_path(path: &Path) -> Result<(), Error> {
    // Require the actual existing database path, not a legacy alias that could
    // select another file. Security's returned path is checked separately.
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 1024
        || !(path
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(b".keychain-db")
            || path.as_os_str().as_encoded_bytes().ends_with(b".keychain"))
        || fs::canonicalize(path).map_err(|_| Error::InvalidStorage)? != path
        || !fs::symlink_metadata(path)
            .map_err(|_| Error::InvalidStorage)?
            .is_file()
    {
        return Err(Error::InvalidStorage);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::InvalidStorage)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(Error::InvalidStorage);
    }
    Ok(())
}
fn unlocked(keychain: Ref) -> Result<(), Error> {
    let mut status = 0;
    if unsafe { SecKeychainGetStatus(keychain, &mut status) } != 0 {
        return Err(Error::Unavailable);
    }
    if status & 1 == 0 {
        Err(Error::Locked)
    } else {
        Ok(())
    }
}
fn read(keychain: Ref, service: Ref, account: Ref) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
    unlocked(keychain)?;
    let search = Owned::new(unsafe {
        CFArrayCreate(
            ptr::null(),
            &keychain,
            1,
            ptr::addr_of!(kCFTypeArrayCallBacks).cast(),
        )
    })?;
    let query = dict(&unsafe {
        [
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service),
            (kSecAttrAccount, account),
            (kSecMatchSearchList, search.0),
            (kSecReturnData, kCFBooleanTrue),
            (kSecMatchLimit, kSecMatchLimitOne),
        ]
    })?;
    let mut result = Owned(ptr::null());
    let status = unsafe { SecItemCopyMatching(query.0, &mut result.0) };
    // Lock is reported only from observed status, never inferred from generic
    // authentication or interaction errors. Access denied while unlocked fails.
    unlocked(keychain)?;
    if status == -25300 && result.0.is_null() {
        return Ok(None);
    }
    if status != 0 || result.0.is_null() {
        return Err(Error::Unavailable);
    }
    if unsafe { CFGetTypeID(result.0) != CFDataGetTypeID() || CFDataGetLength(result.0) != 32 } {
        return Err(Error::InvalidStorage);
    }
    let data = unsafe { CFDataGetBytePtr(result.0) };
    if data.is_null() {
        return Err(Error::InvalidStorage);
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(unsafe { std::slice::from_raw_parts(data, 32) });
    // CFData is immutable and owned by Security; never cast away const or
    // corrupt its backing storage. The helper exits immediately after transfer.
    Ok(Some(key))
}
pub(super) fn key(
    path: &Path,
    account: &str,
    create: bool,
    identity: Object,
) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
    validate_path(path)?;
    if object(&fs::metadata(path).map_err(|_| Error::InvalidStorage)?) != identity {
        return Err(Error::InvalidStorage);
    }
    let path_string =
        CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error::InvalidStorage)?;
    let mut keychain = Owned(ptr::null());
    if unsafe { SecKeychainOpen(path_string.as_ptr(), &mut keychain.0) } != 0
        || keychain.0.is_null()
    {
        return Err(Error::Unavailable);
    }
    let mut returned = [0u8; 1025];
    let mut len = returned.len() as u32;
    if unsafe { SecKeychainGetPath(keychain.0, &mut len, returned.as_mut_ptr().cast()) } != 0
        || len as usize > returned.len()
    {
        return Err(Error::InvalidStorage);
    }
    let returned = &returned[..len as usize];
    let returned = returned.strip_suffix(&[0]).unwrap_or(returned);
    // Legacy APIs can report the .keychain alias for the corresponding -db.
    // Only that exact suffix mapping to the pinned existing path is accepted.
    let expected = path.as_os_str().as_encoded_bytes();
    if returned != expected && !(expected.strip_suffix(b"-db") == Some(returned)) {
        return Err(Error::InvalidStorage);
    }
    if returned != expected {
        use std::os::unix::ffi::OsStrExt;
        let alias = Path::new(std::ffi::OsStr::from_bytes(returned));
        // If a separate real alias file exists, never guess which database
        // Security selected. A dangling alias is rejected as well.
        match fs::symlink_metadata(alias) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err(Error::InvalidStorage),
        }
    }
    validate_path(path)?;
    if object(&fs::metadata(path).map_err(|_| Error::InvalidStorage)?) != identity {
        return Err(Error::InvalidStorage);
    }
    let service = string("app.lomi.host-secrets.static-kek.v1")?;
    let account = string(account)?;
    if let Some(value) = read(keychain.0, service.0, account.0)? {
        validate_read_identity(path, identity)?;
        return Ok(Some(value));
    }
    validate_read_identity(path, identity)?;
    if !create {
        return Ok(None);
    }
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(&mut key[..]).map_err(|_| Error::Unavailable)?;
    let data = Owned::new(unsafe { CFDataCreate(ptr::null(), key.as_ptr(), 32) })?;
    // NULL trusted list means only the creating application. An empty array or
    // an allow-all ACL is never installed. Helpers use the same executable.
    let descriptor = string("Lomi host secret encryption key")?;
    let mut access = Owned(ptr::null());
    if unsafe { SecAccessCreate(descriptor.0, ptr::null(), &mut access.0) } != 0
        || access.0.is_null()
    {
        return Err(Error::Unavailable);
    }
    unlocked(keychain.0)?;
    let attributes = dict(&unsafe {
        [
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, service.0),
            (kSecAttrAccount, account.0),
            (kSecUseKeychain, keychain.0),
            (kSecValueData, data.0),
            (kSecAttrAccess, access.0),
        ]
    })?;
    let status = unsafe { SecItemAdd(attributes.0, ptr::null_mut()) };
    // SecItemAdd can legitimately replace the Keychain database inode. Keep
    // the explicit path/ownership checks; authenticate its exact fresh key in
    // this helper and again in a fresh helper before first cipher publication.
    validate_path(path).map_err(|_| Error::CommitUncertain)?;
    if status == -25299 {
        // Never overwrite an existing key. Racing initialization may succeed
        // only when it produced exactly the same key; otherwise fail closed.
        return match read(keychain.0, service.0, account.0)? {
            Some(existing) if existing[..] == key[..] => Ok(Some(existing)),
            _ => Err(Error::CommitUncertain),
        };
    }
    if status != 0 {
        return Err(Error::CommitUncertain);
    }
    match read(keychain.0, service.0, account.0) {
        Ok(Some(existing)) if existing[..] == key[..] => Ok(Some(existing)),
        _ => Err(Error::CommitUncertain),
    }
}
fn validate_read_identity(path: &Path, identity: Object) -> Result<(), Error> {
    validate_path(path)?;
    if object(&fs::metadata(path).map_err(|_| Error::InvalidStorage)?) != identity {
        Err(Error::InvalidStorage)
    } else {
        Ok(())
    }
}
