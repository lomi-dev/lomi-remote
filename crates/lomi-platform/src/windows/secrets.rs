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
