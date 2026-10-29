//! Explicit user-scope DPAPI storage for one validated host profile.
//!
//! Same-account processes and privileged administrators remain trusted. This
//! does not promise isolation from another process running as the host account.
use super::{
    Handle, Local, Object, PrivateProfile, current_sid, information, object, security,
    validate_security, wide,
};
use crate::secrets::{
    Error, MAX_BUNDLE_BYTES, ProviderKind, ProviderStatus, SecretBundle, SecretStorage, Selection,
    StorageState,
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    mem,
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Cryptography::*, *},
    Storage::FileSystem::*,
    System::Threading::{GetCurrentThread, OpenThreadToken},
};
use zeroize::{Zeroize, Zeroizing};

type Result<T> = std::result::Result<T, Error>;
const BUNDLE: &str = "host-secrets.dpapi";
const LOCK: &str = "host-secrets.lock";
const MAGIC: &[u8; 8] = b"LMDPAPI2";
const HEADER: usize = 12;
const INNER_MAGIC: &[u8; 8] = b"LMSECRT2";
const INNER_VERSION: u32 = 2;
const INNER_HEADER: usize = 16;
const DIGEST_BYTES: usize = 32;
const EMPTY_MAGIC: &[u8; 8] = b"LMDPCLR1";
const EMPTY_VERSION: u32 = 1;
const EMPTY_HEADER: usize = 12;
const EMPTY_LENGTH: usize = EMPTY_HEADER + DIGEST_BYTES;
const MAX_PLAINTEXT: usize = INNER_HEADER + MAX_BUNDLE_BYTES + DIGEST_BYTES;
const DIGEST_DOMAIN: &[u8] = b"lomi-remote/host-secret-bundle/inner-checksum/v2\0";
// DPAPI adds a bounded envelope to the 32 KiB plaintext. Unknown future formats
// that exceed this bound fail closed rather than allocating from an input size.
const MAX_CIPHERTEXT: usize = 64 * 1024;
// Domain separation, not a secret or an encryption key stored beside the blob.
const PURPOSE: &[u8] = b"lomi-remote/host-secret-bundle/dpapi-user/v2";

fn invalid(_: super::Error) -> Error {
    Error::InvalidStorage
}
fn io_error(_: std::io::Error) -> Error {
    Error::Io
}

/// Owns the OS allocation even on rejected output or a failed DPAPI operation.
/// In particular, decrypted plaintext is wiped BEFORE LocalFree on every path.
struct CryptOutput(CRYPT_INTEGER_BLOB);
impl Drop for CryptOutput {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                LocalFree(self.0.pbData.cast());
            }
        }
    }
}
fn crypt(bytes: &[u8], protect: bool, purpose: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let limit = if protect {
        MAX_PLAINTEXT
    } else {
        MAX_CIPHERTEXT
    };
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::InvalidBundle);
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: purpose.len() as u32,
        pbData: purpose.as_ptr().cast_mut(),
    };
    let mut output = CryptOutput(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    });
    // Deliberately user scope: never CRYPTPROTECT_LOCAL_MACHINE, no prompt,
    // impersonation, UI, alternate account, or fallback backend.
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                ptr::null(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    if ok == 0 {
        // DPAPI cannot reliably distinguish a locked account/profile from
        // unavailable key material or corrupt data. Do not claim "locked".
        return Err(Error::Unavailable);
    }
    let limit = if protect {
        MAX_CIPHERTEXT
    } else {
        MAX_PLAINTEXT
    };
    if output.0.pbData.is_null() || output.0.cbData == 0 || output.0.cbData as usize > limit {
        return Err(Error::InvalidBundle);
    }
    Ok(Zeroizing::new(unsafe {
        std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec()
    }))
}
// This checksum detects invalid/corrupt decrypted output inside the DPAPI
// protection. It is not standalone authentication against the trusted account.
// CryptUnprotectData success alone does not establish plaintext integrity.
struct HashAlgorithm(BCRYPT_ALG_HANDLE);
impl Drop for HashAlgorithm {
    fn drop(&mut self) {
        unsafe {
            BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}
fn checksum(bytes: &[u8]) -> Result<Zeroizing<[u8; DIGEST_BYTES]>> {
    if bytes.len() > INNER_HEADER + MAX_BUNDLE_BYTES {
        return Err(Error::InvalidBundle);
    }
    let mut algorithm = ptr::null_mut();
    if unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0)
    } < 0
    {
        return Err(Error::Unavailable);
    }
    let algorithm = HashAlgorithm(algorithm);
    let mut input = Zeroizing::new(Vec::with_capacity(DIGEST_DOMAIN.len() + bytes.len()));
    input.extend_from_slice(DIGEST_DOMAIN);
    input.extend_from_slice(bytes);
    let mut digest = Zeroizing::new([0; DIGEST_BYTES]);
    if unsafe {
        BCryptHash(
            algorithm.0,
            ptr::null(),
            0,
            input.as_ptr(),
            input.len() as u32,
            digest.as_mut_ptr(),
            DIGEST_BYTES as u32,
        )
    } < 0
    {
        return Err(Error::Unavailable);
    }
    Ok(digest)
}
fn encode(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
        return Err(Error::InvalidBundle);
    }
    let mut envelope = Zeroizing::new(Vec::with_capacity(
        INNER_HEADER + bytes.len() + DIGEST_BYTES,
    ));
    envelope.extend_from_slice(INNER_MAGIC);
    envelope.extend_from_slice(&INNER_VERSION.to_be_bytes());
    envelope.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    envelope.extend_from_slice(bytes);
    let digest = checksum(&envelope)?;
    envelope.extend_from_slice(&digest[..]);
    Ok(envelope)
}
fn encode_empty() -> Result<Zeroizing<Vec<u8>>> {
    let mut envelope = Zeroizing::new(Vec::with_capacity(EMPTY_LENGTH));
    envelope.extend_from_slice(EMPTY_MAGIC);
    envelope.extend_from_slice(&EMPTY_VERSION.to_be_bytes());
    let digest = checksum(&envelope)?;
    envelope.extend_from_slice(&digest[..]);
    Ok(envelope)
}
fn is_empty_envelope(envelope: &[u8]) -> Result<bool> {
    if envelope.len() < EMPTY_MAGIC.len() || &envelope[..EMPTY_MAGIC.len()] != EMPTY_MAGIC {
        return Ok(false);
    }
    if envelope.len() != EMPTY_LENGTH || envelope[8..EMPTY_HEADER] != EMPTY_VERSION.to_be_bytes() {
        return Err(Error::InvalidBundle);
    }
    let expected = checksum(&envelope[..EMPTY_HEADER])?;
    let mismatch = expected
        .iter()
        .zip(&envelope[EMPTY_HEADER..])
        .fold(0u8, |difference, (a, b)| difference | (a ^ b));
    if mismatch != 0 {
        return Err(Error::InvalidBundle);
    }
    Ok(true)
}
fn decode(mut envelope: Zeroizing<Vec<u8>>) -> Result<SecretBundle> {
    if !(INNER_HEADER + 1 + DIGEST_BYTES..=MAX_PLAINTEXT).contains(&envelope.len())
        || &envelope[..8] != INNER_MAGIC
        || envelope[8..12] != INNER_VERSION.to_be_bytes()
    {
        return Err(Error::InvalidBundle);
    }
    let length = u32::from_be_bytes(
        envelope[12..16]
            .try_into()
            .map_err(|_| Error::InvalidBundle)?,
    ) as usize;
    if length == 0
        || length > MAX_BUNDLE_BYTES
        || envelope.len() != INNER_HEADER + length + DIGEST_BYTES
    {
        return Err(Error::InvalidBundle);
    }
    let end = INNER_HEADER + length;
    let expected = checksum(&envelope[..end])?;
    let mismatch = expected
        .iter()
        .zip(&envelope[end..])
        .fold(0u8, |difference, (a, b)| difference | (a ^ b));
    if mismatch != 0 {
        return Err(Error::InvalidBundle);
    }
    // Reuse the already zeroizing allocation; erase the duplicate tail before
    // truncating so neither payload copies nor the checksum survive in capacity.
    envelope.copy_within(INNER_HEADER..end, 0);
    envelope[length..].zeroize();
    envelope.truncate(length);
    Ok(SecretBundle::from_zeroizing(envelope))
}
fn probe() -> Result<()> {
    let envelope = encode(b"lomi-dpapi-availability-v2")?;
    let ciphertext = crypt(&envelope, true, PURPOSE)?;
    let plaintext = decode(crypt(&ciphertext, false, PURPOSE)?)?;
    if plaintext.expose() != b"lomi-dpapi-availability-v2" {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn validate(file: &File, sid: &str) -> Result<()> {
    let info = information(file.as_raw_handle()).map_err(invalid)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(Error::InvalidStorage);
    }
    validate_security(file.as_raw_handle(), sid, true, false).map_err(invalid)?;
    let (mut descriptor, mut acl) = (ptr::null_mut(), ptr::null_mut());
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _guard = Local(descriptor);
    if code != ERROR_SUCCESS || acl.is_null() {
        return Err(Error::InvalidStorage);
    }
    let (mut control, mut revision) = (0, 0);
    // Exactly one full-access current-SID ACE, with a protected DACL. Reject
    // extra allow/deny/inherit-only/unknown entries rather than guessing policy.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
        || unsafe { (*acl).AceCount } != 1
    {
        return Err(Error::InvalidStorage);
    }
    Ok(())
}
#[derive(Debug)]
enum OpenError {
    Storage(Error),
    Io(std::io::Error),
}
impl From<OpenError> for Error {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Storage(error) => error,
            OpenError::Io(_) => Error::Io,
        }
    }
}
fn open_file(
    path: &Path,
    sid: &str,
    write: bool,
    creation: u32,
) -> std::result::Result<File, OpenError> {
    let sd = security(sid, false).map_err(|_| OpenError::Storage(Error::InvalidStorage))?;
    let handle = Handle::new(unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            READ_CONTROL | GENERIC_READ | if write { GENERIC_WRITE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sd.attributes,
            creation,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    })
    .map_err(OpenError::Io)?;
    let raw = handle.0;
    mem::forget(handle);
    let file = unsafe { File::from_raw_handle(raw) };
    validate(&file, sid).map_err(OpenError::Storage)?;
    Ok(file)
}

/// Borrows the validated profile and holds a separate exclusive kernel lock.
/// All names are internal; no secret-derived paths, configuration, or logging.
pub struct WindowsDpapi<'a> {
    profile: &'a PrivateProfile,
    lock: File,
}
impl<'a> WindowsDpapi<'a> {
    pub fn open(profile: &'a PrivateProfile, selection: Selection) -> Result<Self> {
        match selection {
            Selection::WindowsDpapi => {}
            Selection::Unconfigured => return Err(Error::Unconfigured),
            _ => return Err(Error::Unavailable),
        }
        check_profile(profile)?;
        let lock = open_file(&profile.path.join(LOCK), &profile.sid, true, OPEN_ALWAYS)?;
        let mut overlap = unsafe { mem::zeroed() };
        if unsafe {
            LockFileEx(
                lock.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlap,
            )
        } == 0
        {
            return Err(if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
                Error::Locked
            } else {
                Error::Io
            });
        }
        let this = Self { profile, lock };
        this.check()?;
        probe()?;
        drop(this.load()?);
        Ok(this)
    }
    fn check(&self) -> Result<()> {
        check_profile(self.profile)?;
        validate(&self.lock, &self.profile.sid)?;
        if self.lock.metadata().map_err(io_error)?.len() != 0 {
            return Err(Error::InvalidStorage);
        }
        let current = open_file(
            &self.profile.path.join(LOCK),
            &self.profile.sid,
            false,
            OPEN_EXISTING,
        )?;
        if object(&information(current.as_raw_handle()).map_err(invalid)?)
            != object(&information(self.lock.as_raw_handle()).map_err(invalid)?)
        {
            return Err(Error::InvalidStorage);
        }
        Ok(())
    }
    fn existing(&self, write: bool) -> Result<Option<File>> {
        match open_file(
            &self.profile.path.join(BUNDLE),
            &self.profile.sid,
            write,
            OPEN_EXISTING,
        ) {
            Ok(file) => Ok(Some(file)),
            // Only a genuinely missing final entry is an empty store. An invalid
            // ACL, reparse point, sharing error, or inaccessible file fails closed.
            Err(OpenError::Io(error))
                if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
    fn write(
        &mut self,
        bundle: &SecretBundle,
        before_publish: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let envelope = encode(bundle.expose())?;
        self.write_envelope(envelope, before_publish).map(|_| ())
    }
    fn write_envelope(
        &mut self,
        envelope: Zeroizing<Vec<u8>>,
        before_publish: impl FnOnce() -> Result<()>,
    ) -> Result<Object> {
        self.check()?;
        drop(self.existing(false)?);
        let ciphertext = crypt(&envelope, true, PURPOSE)?;
        let path = self
            .profile
            .path
            .join(format!(".host-secrets-{}.tmp", uuid::Uuid::new_v4()));
        let file = open_file(&path, &self.profile.sid, true, CREATE_NEW)?;
        let identity = object(&information(file.as_raw_handle()).map_err(invalid)?);
        let mut temporary = Temporary {
            path,
            file: Some(file),
            identity,
            sid: &self.profile.sid,
            attempted: false,
        };
        let file = temporary.file.as_mut().ok_or(Error::Io)?;
        file.write_all(MAGIC).map_err(io_error)?;
        file.write_all(&(ciphertext.len() as u32).to_be_bytes())
            .map_err(io_error)?;
        file.write_all(&ciphertext).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        before_publish()?;
        self.check()?;
        drop(self.existing(false)?);
        let current = open_file(&temporary.path, &self.profile.sid, false, OPEN_EXISTING)?;
        if object(&information(current.as_raw_handle()).map_err(invalid)?) != identity {
            return Err(Error::InvalidStorage);
        }
        drop(current);
        // Windows does not permit renaming a file pinned without DELETE sharing.
        // Close only this fully flushed temporary file at the commit boundary;
        // the profile's entire directory ancestry and stable lock remain pinned.
        drop(temporary.file.take());
        temporary.attempted = true;
        // Same directory/volume, no COPY_ALLOWED, never truncate the old bundle.
        // WRITE_THROUGH waits for the move to disk. Once invoked, retain any
        // remnant and report uncertain effects on failure, without retrying.
        if unsafe {
            MoveFileExW(
                wide(&temporary.path).as_ptr(),
                wide(self.profile.path.join(BUNDLE)).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(Error::CommitUncertain);
        }
        let committed = self
            .existing(true)
            .map_err(|_| Error::CommitUncertain)?
            .ok_or(Error::CommitUncertain)?;
        if object(&information(committed.as_raw_handle()).map_err(|_| Error::CommitUncertain)?)
            != identity
        {
            return Err(Error::CommitUncertain);
        }
        committed.sync_all().map_err(|_| Error::CommitUncertain)?;
        self.check().map_err(|_| Error::CommitUncertain)?;
        Ok(identity)
    }
}
fn check_profile(profile: &PrivateProfile) -> Result<()> {
    // DPAPI can use a thread impersonation token, while profile ownership was
    // established with the process token. Never let those contexts diverge.
    let mut thread_token = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) } != 0 {
        drop(Handle::new(thread_token).map_err(io_error)?);
        return Err(Error::InvalidStorage);
    }
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err(Error::Unavailable);
    }
    if current_sid().map_err(invalid)? != profile.sid {
        return Err(Error::InvalidStorage);
    }
    profile.check_current().map_err(invalid)?;
    for (index, directory) in profile._directories.iter().enumerate() {
        validate_security(
            directory.0,
            &profile.sid,
            index + 1 == profile._directories.len(),
            true,
        )
        .map_err(invalid)?;
    }
    // Reopen every component without following reparse points, and confirm the
    // same final object while the original no-DELETE-share ancestry stays pinned.
    let current = PrivateProfile::open(&profile.path, false).map_err(invalid)?;
    if current.identity != profile.identity {
        return Err(Error::InvalidStorage);
    }
    Ok(())
}
impl SecretStorage for WindowsDpapi<'_> {
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            kind: Some(ProviderKind::WindowsDpapi),
            state: match self
                .check()
                .and_then(|()| probe())
                .and_then(|()| self.load().map(drop))
            {
                Ok(()) => StorageState::Available,
                Err(error) => error.state(),
            },
        }
    }
    fn load(&self) -> Result<Option<SecretBundle>> {
        self.check()?;
        let Some(mut file) = self.existing(false)? else {
            return Ok(None);
        };
        let size = file.metadata().map_err(io_error)?.len();
        if !(HEADER as u64 + 1..=HEADER as u64 + MAX_CIPHERTEXT as u64).contains(&size) {
            return Err(Error::InvalidBundle);
        }
        let mut header = [0u8; HEADER];
        file.read_exact(&mut header)
            .map_err(|_| Error::InvalidBundle)?;
        let length = u32::from_be_bytes(header[8..12].try_into().map_err(|_| Error::InvalidBundle)?)
            as usize;
        if &header[..8] != MAGIC
            || length == 0
            || length > MAX_CIPHERTEXT
            || size != (HEADER + length) as u64
        {
            return Err(Error::InvalidBundle);
        }
        let mut ciphertext = Zeroizing::new(vec![0; length]);
        file.read_exact(&mut ciphertext)
            .map_err(|_| Error::InvalidBundle)?;
        let mut extra = [0; 1];
        if file.read(&mut extra).map_err(io_error)? != 0 {
            return Err(Error::InvalidBundle);
        }
        let envelope = crypt(&ciphertext, false, PURPOSE)?;
        if is_empty_envelope(&envelope)? {
            validate(&file, &self.profile.sid)?;
            self.check()?;
            return Ok(None);
        }
        let bundle = decode(envelope)?;
        validate(&file, &self.profile.sid)?;
        self.check()?;
        Ok(Some(bundle))
    }
    fn replace(&mut self, bundle: &SecretBundle) -> Result<()> {
        self.write(bundle, || Ok(()))
    }
    fn clear(&mut self) -> Result<()> {
        // Validate any current payload, but always publish a fresh durable
        // empty marker. A readable marker from a prior uncertain rename is
        // not itself proof that its directory entry reached stable storage.
        drop(self.load()?);
        self.check()?;
        let identity = self
            .write_envelope(encode_empty()?, || Ok(()))
            .map_err(|_| Error::CommitUncertain)?;
        if self.load().map_err(|_| Error::CommitUncertain)?.is_some() {
            return Err(Error::CommitUncertain);
        }
        let current = self
            .existing(false)
            .map_err(|_| Error::CommitUncertain)?
            .ok_or(Error::CommitUncertain)?;
        if object(&information(current.as_raw_handle()).map_err(|_| Error::CommitUncertain)?)
            != identity
        {
            return Err(Error::CommitUncertain);
        }
        validate(&current, &self.profile.sid).map_err(|_| Error::CommitUncertain)?;
        self.check().map_err(|_| Error::CommitUncertain)?;
        Ok(())
    }
}
struct Temporary<'a> {
    path: PathBuf,
    file: Option<File>,
    identity: super::Object,
    sid: &'a str,
    attempted: bool,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if self.attempted {
            return;
        }
        drop(self.file.take());
        if let Ok(current) = open_file(&self.path, self.sid, false, OPEN_EXISTING)
            && information(current.as_raw_handle())
                .ok()
                .is_some_and(|i| object(&i) == self.identity)
        {
            drop(current);
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        secrets::ProtectedFileAcknowledgement,
        windows::{OwnerLock, Security, normalized},
    };
    use std::process::Command;
    const SYNTHETIC: &[u8] = b"LOMI-SYNTHETIC-DPAPI-PRODUCT-V1";
    fn fixture() -> (tempfile::TempDir, OwnerLock) {
        // Only our fresh UUID fixture beneath the trusted account profile.
        // AppData/Temp is intentionally rejected by the ancestry policy.
        let root = tempfile::Builder::new()
            .prefix(&format!("lomi-dpapi-native-{}-", uuid::Uuid::new_v4()))
            .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
            .unwrap();
        let path = normalized(&root.path().canonicalize().unwrap())
            .unwrap()
            .join("profile");
        let owner = OwnerLock::acquire(&path).unwrap();
        (root, owner)
    }
    fn bundle() -> SecretBundle {
        SecretBundle::new(SYNTHETIC.to_vec()).unwrap()
    }
    fn child_process(profile: &PrivateProfile, mode: &str) {
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows::secrets::tests::child", "--ignored"])
            // Test-only fixture location and mode; never bundle bytes or a
            // credential in arguments, environment, or captured diagnostics.
            .env("LOMI_DPAPI_TEST_PROFILE", profile.path())
            .env("LOMI_DPAPI_TEST_MODE", mode)
            .status()
            .unwrap();
        assert!(result.success());
    }
    #[test]
    #[ignore = "child entry point, launched only with an owned fixture"]
    fn child() {
        let path = std::env::var_os("LOMI_DPAPI_TEST_PROFILE").unwrap();
        let profile = PrivateProfile::open(Path::new(&path), false).unwrap();
        let mode = std::env::var("LOMI_DPAPI_TEST_MODE").unwrap();
        let opened = WindowsDpapi::open(&profile, Selection::WindowsDpapi);
        if mode == "locked" {
            assert!(matches!(opened, Err(Error::Locked)));
            return;
        }
        let mut store = opened.unwrap();
        if mode == "interrupt" {
            let _ = store.write(
                &SecretBundle::new(b"synthetic-interrupted".to_vec()).unwrap(),
                || {
                    // Simulates death after temp flush, before atomic publication.
                    // No destructor runs; Windows releases the process-owned lock.
                    std::process::exit(0)
                },
            );
            panic!("interruption hook not reached");
        }
        assert_eq!(mode, "read");
        assert_eq!(store.load().unwrap().unwrap().expose(), SYNTHETIC);
    }
    #[test]
    fn explicit_selection_redaction_and_concrete_availability() {
        let (_root, owner) = fixture();
        for (selection, expected) in [
            (Selection::Unconfigured, Error::Unconfigured),
            (Selection::MacOsKeychain, Error::Unavailable),
            (Selection::SecretService, Error::Unavailable),
            (
                Selection::ProtectedFile(ProtectedFileAcknowledgement::OsPermissionsOnly),
                Error::Unavailable,
            ),
        ] {
            assert!(
                matches!(WindowsDpapi::open(owner.profile(), selection), Err(e) if e == expected)
            );
        }
        assert!(!owner.profile().path().join(LOCK).exists());
        assert_eq!(
            Selection::WindowsDpapi.status().state,
            StorageState::Unavailable
        );
        assert_eq!(
            Selection::Unconfigured.status().state,
            StorageState::Unconfigured
        );
        assert_eq!(format!("{:?}", bundle()), "SecretBundle([REDACTED])");
        assert!(matches!(
            SecretBundle::new(vec![]),
            Err(Error::InvalidBundle)
        ));
        assert!(matches!(
            SecretBundle::new(vec![1; MAX_BUNDLE_BYTES + 1]),
            Err(Error::InvalidBundle)
        ));
        let store = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        assert!(store.load().unwrap().is_none());
        assert_eq!(store.status().state, StorageState::Available);
        assert!(!owner.profile().path().join(BUNDLE).exists());
    }
    #[test]
    fn same_account_new_process_roundtrip_and_exclusive_lock() {
        let (_root, owner) = fixture();
        let mut store = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        store.replace(&bundle()).unwrap();
        assert_eq!(store.load().unwrap().unwrap().expose(), SYNTHETIC);
        let ciphertext = fs::read(owner.profile().path().join(BUNDLE)).unwrap();
        assert!(!ciphertext.windows(SYNTHETIC.len()).any(|v| v == SYNTHETIC));
        assert!(matches!(
            WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi),
            Err(Error::Locked)
        ));
        child_process(owner.profile(), "locked");
        drop(store);
        child_process(owner.profile(), "read");
        let mut reopened = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        let maximum = SecretBundle::new(vec![0x5a; MAX_BUNDLE_BYTES]).unwrap();
        reopened.replace(&maximum).unwrap();
        assert_eq!(reopened.load().unwrap().unwrap().expose(), maximum.expose());
    }
    #[test]
    fn sha256_checksum_matches_fixed_domain_known_answer() {
        assert_eq!(
            &checksum(b"abc").unwrap()[..],
            &[
                230, 192, 141, 221, 7, 90, 197, 0, 51, 246, 193, 122, 83, 158, 238, 58, 247, 148,
                53, 90, 90, 45, 163, 197, 160, 121, 128, 254, 101, 67, 58, 209,
            ]
        );
    }
    #[test]
    fn dpapi_success_with_invalid_inner_envelope_is_rejected_without_modification() {
        let (_root, owner) = fixture();
        let mut store = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        store.replace(&bundle()).unwrap();
        let path = owner.profile().path().join(BUNDLE);
        let original = fs::read(&path).unwrap();
        let valid = encode(SYNTHETIC).unwrap();
        assert_eq!(decode(valid.clone()).unwrap().expose(), SYNTHETIC);
        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 1;
        let mut bad_version = valid.clone();
        bad_version[8..12].copy_from_slice(&3u32.to_be_bytes());
        let mut zero_length = valid.clone();
        zero_length[12..16].copy_from_slice(&0u32.to_be_bytes());
        let mut oversized_length = valid.clone();
        oversized_length[12..16].copy_from_slice(&((MAX_BUNDLE_BYTES + 1) as u32).to_be_bytes());
        let mut wrong_length = valid.clone();
        wrong_length[12..16].copy_from_slice(&((SYNTHETIC.len() - 1) as u32).to_be_bytes());
        let mut bad_payload = valid.clone();
        bad_payload[INNER_HEADER] ^= 1;
        let mut bad_digest = valid.clone();
        let last = bad_digest.len() - 1;
        bad_digest[last] ^= 1;
        let mut truncated = valid.clone();
        truncated.last_mut().unwrap().zeroize();
        truncated.pop();
        let mut trailing = Zeroizing::new(Vec::with_capacity(valid.len() + 1));
        trailing.extend_from_slice(&valid);
        trailing.push(0);
        let legacy = Zeroizing::new(SYNTHETIC.to_vec());
        for invalid in [
            bad_magic,
            bad_version,
            zero_length,
            oversized_length,
            wrong_length,
            bad_payload,
            bad_digest,
            truncated,
            trailing,
            legacy,
        ] {
            // Real DPAPI protects the malformed inner bytes. The matching real
            // Unprotect call succeeds and returns them exactly: rejection must
            // therefore come from our envelope validation, not DPAPI's BOOL.
            let ciphertext = crypt(&invalid, true, PURPOSE).unwrap();
            assert_eq!(
                &crypt(&ciphertext, false, PURPOSE).unwrap()[..],
                &invalid[..]
            );
            let mut file = open_file(&path, &owner.profile().sid, true, OPEN_EXISTING).unwrap();
            file.set_len(0).unwrap();
            file.write_all(MAGIC).unwrap();
            file.write_all(&(ciphertext.len() as u32).to_be_bytes())
                .unwrap();
            file.write_all(&ciphertext).unwrap();
            file.sync_all().unwrap();
            drop(file);
            let stored = fs::read(&path).unwrap();
            assert!(matches!(store.load(), Err(Error::InvalidBundle)));
            assert_eq!(store.status().state, StorageState::Unavailable);
            assert_eq!(fs::read(&path).unwrap(), stored);
        }
        drop(store);
        let stored = fs::read(&path).unwrap();
        assert!(matches!(
            WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi),
            Err(Error::InvalidBundle)
        ));
        assert_eq!(fs::read(&path).unwrap(), stored);
        fs::write(&path, original).unwrap();
        let reopened = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        assert_eq!(reopened.load().unwrap().unwrap().expose(), SYNTHETIC);
    }
    #[test]
    fn dpapi_rejects_tampering_and_wrong_purpose() {
        let ciphertext = crypt(SYNTHETIC, true, PURPOSE).unwrap();
        assert_eq!(&crypt(&ciphertext, false, PURPOSE).unwrap()[..], SYNTHETIC);
        assert!(crypt(&ciphertext, false, b"lomi-wrong-purpose").is_err());
        let mut tampered = ciphertext;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        assert!(crypt(&tampered, false, PURPOSE).is_err());
        assert!(matches!(
            crypt(&vec![0; MAX_CIPHERTEXT + 1], false, PURPOSE),
            Err(Error::InvalidBundle)
        ));
    }
    #[test]
    fn failed_and_interrupted_updates_preserve_previous_bundle() {
        let (_root, owner) = fixture();
        let mut store = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        store.replace(&bundle()).unwrap();
        let before = fs::read(owner.profile().path().join(BUNDLE)).unwrap();
        assert_eq!(
            store.write(
                &SecretBundle::new(b"synthetic-new".to_vec()).unwrap(),
                || Err(Error::Io)
            ),
            Err(Error::Io)
        );
        assert_eq!(
            fs::read(owner.profile().path().join(BUNDLE)).unwrap(),
            before
        );
        assert_eq!(fs::read_dir(owner.profile().path()).unwrap().count(), 3);
        drop(store);
        child_process(owner.profile(), "interrupt");
        assert_eq!(
            fs::read(owner.profile().path().join(BUNDLE)).unwrap(),
            before
        );
        let store = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        assert_eq!(store.load().unwrap().unwrap().expose(), SYNTHETIC);
        for entry in fs::read_dir(owner.profile().path()).unwrap() {
            let entry = entry.unwrap();
            if entry
                .file_name()
                .to_str()
                .unwrap()
                .starts_with(".host-secrets-")
            {
                let file =
                    open_file(&entry.path(), &owner.profile().sid, false, OPEN_EXISTING).unwrap();
                validate(&file, &owner.profile().sid).unwrap();
                assert!(file.metadata().unwrap().len() > HEADER as u64);
            }
        }
        assert_eq!(fs::read_dir(owner.profile().path()).unwrap().count(), 4);
        drop(store);
        child_process(owner.profile(), "read");
    }
    #[test]
    fn attempted_publication_reports_uncertainty_without_retry_or_recovery() {
        let (_root, owner) = fixture();
        let mut store = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        store.replace(&bundle()).unwrap();
        let before = fs::read(owner.profile().path().join(BUNDLE)).unwrap();
        // A reader without DELETE sharing prevents publication. Once the move
        // syscall was attempted the provider reports uncertainty conservatively,
        // retaining the flushed candidate for explicit inspection, never retrying.
        let reader = store.existing(false).unwrap().unwrap();
        assert_eq!(
            store.replace(&SecretBundle::new(b"synthetic-blocked".to_vec()).unwrap()),
            Err(Error::CommitUncertain)
        );
        assert_eq!(
            fs::read(owner.profile().path().join(BUNDLE)).unwrap(),
            before
        );
        assert_eq!(fs::read_dir(owner.profile().path()).unwrap().count(), 4);
        drop(reader);
        drop(store);
        child_process(owner.profile(), "read");
        assert_eq!(
            fs::read(owner.profile().path().join(BUNDLE)).unwrap(),
            before
        );
    }
    #[test]
    fn bounded_envelope_and_corrupt_storage_fail_closed() {
        let (_root, owner) = fixture();
        let mut store = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        store.replace(&bundle()).unwrap();
        let path = owner.profile().path().join(BUNDLE);
        let original = fs::read(&path).unwrap();
        let mut bad_magic = original.clone();
        bad_magic[0] ^= 1;
        let mut bad_length = original.clone();
        bad_length[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut tampered = original.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        for invalid_bytes in [
            vec![],
            vec![0; HEADER],
            bad_magic,
            bad_length,
            tampered,
            original[..original.len() - 1].to_vec(),
        ] {
            fs::write(&path, invalid_bytes).unwrap();
            assert!(store.load().is_err());
            assert_eq!(store.status().state, StorageState::Unavailable);
        }
        let file = open_file(&path, &owner.profile().sid, true, OPEN_EXISTING).unwrap();
        file.set_len((HEADER + MAX_CIPHERTEXT + 1) as u64).unwrap();
        assert!(matches!(store.load(), Err(Error::InvalidBundle)));
        drop(file);
        fs::write(&path, &original).unwrap();
        drop(store);
        let mut wrong = original;
        let ciphertext = crypt(SYNTHETIC, true, b"other-product-purpose").unwrap();
        wrong.truncate(HEADER);
        wrong[8..12].copy_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        wrong.extend_from_slice(&ciphertext);
        fs::write(&path, wrong).unwrap();
        assert!(WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).is_err());
    }
    fn set_acl(path: &Path, directory: bool, sddl: &str) {
        let sd = Security::new(sddl).unwrap();
        let handle = Handle::new(unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
                ptr::null_mut(),
            )
        })
        .unwrap();
        let (mut acl, mut present, mut defaulted) = (ptr::null_mut(), 0, 0);
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    sd.attributes.lpSecurityDescriptor,
                    &mut present,
                    &mut acl,
                    &mut defaulted,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    handle.0,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null_mut(),
                )
            },
            ERROR_SUCCESS
        );
    }
    #[test]
    fn private_acl_hardlink_reparse_and_ancestry_checks() {
        let (_root, owner) = fixture();
        let mut store = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        store.replace(&bundle()).unwrap();
        let path = owner.profile().path().join(BUNDLE);
        let sid = &owner.profile().sid;
        let alias = owner.profile().path().join("synthetic-hardlink");
        fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(store.load(), Err(Error::InvalidStorage)));
        fs::remove_file(alias).unwrap();
        let private_file = format!("O:{sid}D:P(A;;FA;;;{sid})");
        for name in [BUNDLE, LOCK] {
            let target = owner.profile().path().join(name);
            set_acl(
                &target,
                false,
                &format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FR;;;WD)"),
            );
            assert_eq!(store.status().state, StorageState::Unavailable);
            assert!(store.load().is_err());
            set_acl(&target, false, &private_file);
        }
        // Recheck even ACL-only changes to already pinned ancestors.
        let parent = owner.profile().path().parent().unwrap();
        set_acl(
            parent,
            true,
            &format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;WD;;;WD)"),
        );
        assert!(store.load().is_err());
        set_acl(parent, true, &format!("O:{sid}D:P(A;OICI;FA;;;{sid})"));
        assert_eq!(store.load().unwrap().unwrap().expose(), SYNTHETIC);
        drop(store);
        fs::remove_file(&path).unwrap();
        let directory = owner.profile().path().join("synthetic-junction-target");
        fs::create_dir(&directory).unwrap();
        let result = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&path)
            .arg(&directory)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).is_err());
        fs::remove_dir(path).unwrap();
    }
    #[test]
    fn impersonated_thread_cannot_select_a_different_dpapi_context() {
        let (_root, owner) = fixture();
        let store = WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi).unwrap();
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                assert_ne!(unsafe { RevertToSelf() }, 0);
            }
        }
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        let revert = Revert;
        assert!(matches!(store.load(), Err(Error::InvalidStorage)));
        assert_eq!(store.status().state, StorageState::Unavailable);
        assert!(matches!(
            WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi),
            Err(Error::InvalidStorage)
        ));
        drop(revert);
        assert_eq!(store.status().state, StorageState::Available);
    }
    // Actual wrong-OS-account DPAPI decryption is not covered by same-account
    // subprocess tests. Qualification requires an independently provisioned OS
    // account, handing over ONLY a synthetic ciphertext and attempting the same
    // entropy/user-scope CryptUnprotectData call there. No account is created or
    // impersonated by these tests, and no cross-account isolation is claimed.
}
