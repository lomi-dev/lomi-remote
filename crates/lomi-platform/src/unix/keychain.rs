//! Explicit legacy macOS Keychain KEK and profile-bound encrypted secret bundle.
//!
//! Each operation reads the static KEK in a fresh helper. Disabling legacy
//! Security UI is process-local, so it must never run on a host thread. A lock
//! occurring after the helper read cannot revoke a key already in flight.
mod native;
use super::{Object, PrivateProfile, object, private_regular, secrets::ProtectedFile};
use crate::secrets::{
    Error, MAX_BUNDLE_BYTES, ProviderKind, ProviderStatus, SecretBundle, SecretStorage, Selection,
    StorageState,
};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use lomi_remote_protocol::ipc::IpcProfileId;
use std::{
    ffi::CStr,
    fs::{self, File},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const BUNDLE: &CStr = c"host-secrets.keychain.bundle";
const MAGIC: &[u8; 8] = b"LMKCB001";
const HEADER: usize = 24; // magic, plaintext length, random 96-bit nonce
const TAG: usize = 16;
const HELPER: &str = "--internal-keychain-helper";
const REQUEST_LIMIT: usize = 1536;

/// Trusted setup supplies an existing, canonical explicit file Keychain path
/// and a profile identity read from the trusted host store, never bundle input.
/// This provider never creates/unlocks/deletes a Keychain, changes its search
/// list/default, or falls back to plaintext. It owns the shared storage lock.
pub struct MacOsKeychain<'a> {
    profile: &'a PrivateProfile,
    guard: ProtectedFile<'a>,
    profile_id: IpcProfileId,
    keychain: PathBuf,
    executable: File,
    executable_path: PathBuf,
}
impl<'a> MacOsKeychain<'a> {
    pub fn open(
        profile: &'a PrivateProfile,
        selection: Selection,
        profile_id: IpcProfileId,
        keychain: &Path,
    ) -> Result<Self, Error> {
        match selection {
            Selection::MacOsKeychain => (),
            Selection::Unconfigured => return Err(Error::Unconfigured),
            _ => return Err(Error::Unavailable),
        }
        native::validate_path(keychain)?;
        reject_plaintext(profile)?;
        let executable_path = std::env::current_exe()
            .map_err(|_| Error::Unavailable)?
            .canonicalize()
            .map_err(|_| Error::Unavailable)?;
        let executable = File::open(&executable_path).map_err(|_| Error::Unavailable)?;
        let guard = ProtectedFile::open_keychain_guard(profile)?;
        let this = Self {
            profile,
            guard,
            profile_id,
            keychain: keychain.to_path_buf(),
            executable,
            executable_path,
        };
        this.check()?;
        // An existing encrypted store requires a readable authentic key now.
        drop(this.load()?);
        Ok(this)
    }
    fn check(&self) -> Result<(), Error> {
        reject_plaintext(self.profile)?;
        self.guard.check()?;
        validate_executable(&self.executable_path, &self.executable)?;
        native::validate_path(&self.keychain)?;
        Ok(())
    }
    fn existing(&self) -> Result<Option<File>, Error> {
        match open_at(self.profile, BUNDLE, libc::O_RDONLY) {
            Ok(file) => {
                private_regular(&file).map_err(|_| Error::InvalidStorage)?;
                Ok(Some(file))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::InvalidStorage),
        }
    }
    fn aad(&self, header: &[u8]) -> Vec<u8> {
        let mut aad = b"lomi.host-secrets.keychain.static-kek.v1\0".to_vec();
        aad.extend_from_slice(&16_u32.to_be_bytes());
        aad.extend_from_slice(&self.profile_id.to_bytes());
        aad.extend_from_slice(header);
        aad
    }
    fn key(&self, create: bool) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
        self.check()?;
        crate::process::require_child_ownership().map_err(|_| Error::Unavailable)?;
        let mut request = Zeroizing::new(Vec::new());
        request.push(u8::from(create));
        // Keychain's own legitimate mutations can replace its database inode.
        // Pin each read request, while profile/lock identities stay permanent.
        let identity = object(&fs::metadata(&self.keychain).map_err(|_| Error::InvalidStorage)?);
        request.extend_from_slice(&identity.device.to_be_bytes());
        request.extend_from_slice(&identity.inode.to_be_bytes());
        let account = String::from(self.profile_id);
        for value in [
            self.keychain.as_os_str().as_encoded_bytes(),
            account.as_bytes(),
        ] {
            request.extend_from_slice(&(value.len() as u32).to_be_bytes());
            request.extend_from_slice(value);
        }
        if request.len() > REQUEST_LIMIT {
            return Err(Error::InvalidStorage);
        }
        let mut child = Command::new(&self.executable_path)
            .arg(HELPER)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Unavailable)?;
        let result = (|| {
            child
                .stdin
                .take()
                .ok_or(Error::Unavailable)?
                .write_all(&request)
                .map_err(|_| Error::Unavailable)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().map_err(|_| Error::Unavailable)? {
                    if !status.success() {
                        return Err(Error::Unavailable);
                    }
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(Error::Unavailable);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let mut response = Zeroizing::new(Vec::with_capacity(34));
            child
                .stdout
                .take()
                .ok_or(Error::Unavailable)?
                .take(34)
                .read_to_end(&mut response)
                .map_err(|_| Error::Unavailable)?;
            match response.as_slice() {
                [0] => Ok(None),
                [1, bytes @ ..] if bytes.len() == 32 => {
                    let mut key = Zeroizing::new([0; 32]);
                    key.copy_from_slice(bytes);
                    Ok(Some(key))
                }
                [2] => Err(Error::Locked),
                [3] => Err(Error::Unavailable),
                [4] => Err(Error::InvalidStorage),
                [5] => Err(Error::CommitUncertain),
                _ => Err(Error::Unavailable),
            }
        })();
        // Retain and reap the private child on every failure. Never signal a
        // reused PID, or return with a detached helper capable of adding a key.
        if child.try_wait().ok().flatten().is_none() {
            crate::process::require_unreaped_child(&child).map_err(|_| Error::Unavailable)?;
            child.kill().map_err(|_| Error::Unavailable)?;
            child.wait().map_err(|_| Error::Unavailable)?;
        }
        if create && result.is_err() {
            return Err(Error::CommitUncertain);
        }
        result
    }
    fn read_cipher(&self) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        self.check()?;
        let Some(mut file) = self.existing()? else {
            return Ok(None);
        };
        let size = file.metadata().map_err(|_| Error::Io)?.len();
        if !(HEADER as u64 + TAG as u64 + 1..=(HEADER + TAG + MAX_BUNDLE_BYTES) as u64)
            .contains(&size)
        {
            return Err(Error::InvalidBundle);
        }
        let mut bytes = Zeroizing::new(vec![0; size as usize]);
        file.read_exact(&mut bytes)
            .map_err(|_| Error::InvalidBundle)?;
        let mut extra = [0; 1];
        if file.read(&mut extra).map_err(|_| Error::Io)? != 0 {
            return Err(Error::InvalidBundle);
        }
        if &bytes[..8] != MAGIC
            || u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize
                != bytes.len() - HEADER - TAG
        {
            return Err(Error::InvalidBundle);
        }
        private_regular(&file).map_err(|_| Error::InvalidStorage)?;
        self.check()?;
        Ok(Some(bytes))
    }
    fn publish(
        &mut self,
        bytes: &[u8],
        before_publish: impl FnOnce() -> Result<(), Error>,
        sync_directory: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<(), Error> {
        self.check()?;
        drop(self.existing()?);
        let name =
            std::ffi::CString::new(format!(".host-keychain-{}.tmp", uuid::Uuid::new_v4())).unwrap();
        let file = open_at(
            self.profile,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| Error::Io)?;
        let mut temp = Temporary {
            profile: self.profile,
            name: &name,
            file,
            published: false,
        };
        private_regular(&temp.file).map_err(|_| Error::InvalidStorage)?;
        temp.file.write_all(bytes).map_err(|_| Error::Io)?;
        temp.file.sync_all().map_err(|_| Error::Io)?;
        before_publish()?;
        self.check()?;
        drop(self.existing()?);
        private_regular(&temp.file).map_err(|_| Error::InvalidStorage)?;
        let current =
            open_at(self.profile, &name, libc::O_RDONLY).map_err(|_| Error::InvalidStorage)?;
        private_regular(&current).map_err(|_| Error::InvalidStorage)?;
        if object(&current.metadata().map_err(|_| Error::Io)?)
            != object(&temp.file.metadata().map_err(|_| Error::Io)?)
        {
            return Err(Error::InvalidStorage);
        }
        if unsafe {
            libc::renameat(
                self.profile.directory.as_raw_fd(),
                name.as_ptr(),
                self.profile.directory.as_raw_fd(),
                BUNDLE.as_ptr(),
            )
        } != 0
        {
            return Err(Error::Io);
        }
        temp.published = true;
        sync_directory(&self.profile.directory).map_err(|_| Error::CommitUncertain)
    }
}
impl SecretStorage for MacOsKeychain<'_> {
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            kind: Some(ProviderKind::MacOsKeychain),
            state: match self.load() {
                Ok(_) => StorageState::Available,
                Err(error) => error.state(),
            },
        }
    }
    fn load(&self) -> Result<Option<SecretBundle>, Error> {
        let bytes = self.read_cipher()?;
        // Even an empty store observes current lock/access denial.
        let key = self.key(false)?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let key = key.ok_or(Error::InvalidStorage)?;
        let aad = self.aad(&bytes[..HEADER]);
        let mut plaintext = Zeroizing::new(bytes[HEADER..bytes.len() - TAG].to_vec());
        ChaCha20Poly1305::new(GenericArray::from_slice(&key[..]))
            .decrypt_in_place_detached(
                Nonce::from_slice(&bytes[12..HEADER]),
                &aad,
                &mut plaintext,
                GenericArray::from_slice(&bytes[bytes.len() - TAG..]),
            )
            .map_err(|_| Error::InvalidBundle)?;
        Ok(Some(SecretBundle::from_zeroizing(plaintext)))
    }
    fn replace(&mut self, bundle: &SecretBundle) -> Result<(), Error> {
        // Validate/authenticate old ciphertext before any key establishment.
        let exists = self.load()?.is_some();
        let mut key = self.key(false)?;
        if key.is_none() {
            if exists {
                return Err(Error::InvalidStorage);
            }
            key = self.key(true)?;
            let fresh = self.key(false)?.ok_or(Error::CommitUncertain)?;
            if key.as_ref().is_none_or(|key| key[..] != fresh[..]) {
                return Err(Error::CommitUncertain);
            }
        }
        let key = key.ok_or(Error::InvalidStorage)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER + TAG + bundle.expose().len()));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(bundle.expose().len() as u32).to_be_bytes());
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
        bytes.extend_from_slice(&nonce);
        let aad = self.aad(&bytes);
        let mut encrypted = Zeroizing::new(bundle.expose().to_vec());
        let tag = ChaCha20Poly1305::new(GenericArray::from_slice(&key[..]))
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut encrypted)
            .map_err(|_| Error::Unavailable)?;
        bytes.extend_from_slice(&encrypted);
        bytes.extend_from_slice(&tag);
        self.publish(&bytes, || Ok(()), File::sync_all)
    }
    fn clear(&mut self) -> Result<(), Error> {
        drop(self.load()?);
        self.check()?;
        let Some(file) = self.existing()? else {
            self.profile
                .directory
                .sync_all()
                .map_err(|_| Error::CommitUncertain)?;
            self.check().map_err(|_| Error::CommitUncertain)?;
            if self
                .existing()
                .map_err(|_| Error::CommitUncertain)?
                .is_some()
            {
                return Err(Error::CommitUncertain);
            }
            return Ok(());
        };
        let identity = object(&file.metadata().map_err(|_| Error::Io)?);
        drop(file);
        self.check()?;
        let Some(current) = self.existing()? else {
            self.profile
                .directory
                .sync_all()
                .map_err(|_| Error::CommitUncertain)?;
            self.check().map_err(|_| Error::CommitUncertain)?;
            if self
                .existing()
                .map_err(|_| Error::CommitUncertain)?
                .is_some()
            {
                return Err(Error::CommitUncertain);
            }
            return Ok(());
        };
        if object(&current.metadata().map_err(|_| Error::Io)?) != identity {
            return Err(Error::InvalidStorage);
        }
        drop(current);
        if unsafe { libc::unlinkat(self.profile.directory.as_raw_fd(), BUNDLE.as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(Error::Io);
            }
        }
        self.profile
            .directory
            .sync_all()
            .map_err(|_| Error::CommitUncertain)?;
        self.check().map_err(|_| Error::CommitUncertain)?;
        if self
            .existing()
            .map_err(|_| Error::CommitUncertain)?
            .is_some()
        {
            return Err(Error::CommitUncertain);
        }
        Ok(())
    }
}
fn open_at(profile: &PrivateProfile, name: &CStr, flags: i32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            profile.directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn reject_plaintext(profile: &PrivateProfile) -> Result<(), Error> {
    match open_at(profile, c"host-secrets.bundle", libc::O_RDONLY) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(Error::InvalidStorage),
    }
}
fn validate_executable(path: &Path, pinned: &File) -> Result<(), Error> {
    let mut directory = File::open("/").map_err(|_| Error::Unavailable)?;
    super::trusted_directory(&directory, false).map_err(|_| Error::Unavailable)?;
    let parent = path.parent().ok_or(Error::Unavailable)?;
    for component in parent.components().skip(1) {
        let std::path::Component::Normal(name) = component else {
            return Err(Error::Unavailable);
        };
        let name =
            std::ffi::CString::new(name.as_encoded_bytes()).map_err(|_| Error::Unavailable)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::Unavailable);
        }
        directory = unsafe { File::from_raw_fd(fd) };
        super::trusted_directory(&directory, false).map_err(|_| Error::Unavailable)?;
    }
    let name = std::ffi::CString::new(
        path.file_name()
            .ok_or(Error::Unavailable)?
            .as_encoded_bytes(),
    )
    .map_err(|_| Error::Unavailable)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::Unavailable);
    }
    let current = unsafe { File::from_raw_fd(fd) };
    let current_metadata = current.metadata().map_err(|_| Error::Unavailable)?;
    let pinned_metadata = pinned.metadata().map_err(|_| Error::Unavailable)?;
    if !current_metadata.is_file()
        || object(&current_metadata) != object(&pinned_metadata)
        || current_metadata.uid() != 0 && current_metadata.uid() != unsafe { libc::geteuid() }
        || current_metadata.mode() & 0o022 != 0
    {
        return Err(Error::Unavailable);
    }
    super::reject_acl_grants(&current).map_err(|_| Error::Unavailable)
}
struct Temporary<'a> {
    profile: &'a PrivateProfile,
    name: &'a CStr,
    file: File,
    published: bool,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if !self.published
            && let Ok(file) = open_at(self.profile, self.name, libc::O_RDONLY)
            && file
                .metadata()
                .ok()
                .zip(self.file.metadata().ok())
                .is_some_and(|(a, b)| object(&a) == object(&b))
        {
            unsafe {
                libc::unlinkat(self.profile.directory.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

/// Private same-executable route. No arguments, environment secrets, or logs.
/// The very first Security operation disables legacy UI in this process only.
pub fn internal_helper() -> i32 {
    if native::disable_ui().is_err() {
        return 4;
    }
    let result = (|| {
        let mut request = Zeroizing::new(Vec::new());
        std::io::stdin()
            .take((REQUEST_LIMIT + 1) as u64)
            .read_to_end(&mut request)
            .map_err(|_| Error::Unavailable)?;
        if request.len() > REQUEST_LIMIT || request.len() < 17 || request[0] > 1 {
            return Err(Error::InvalidStorage);
        }
        let create = request[0] == 1;
        let identity = Object {
            device: u64::from_be_bytes(request[1..9].try_into().unwrap()),
            inode: u64::from_be_bytes(request[9..17].try_into().unwrap()),
        };
        let mut remaining = &request[17..];
        fn field<'b>(remaining: &mut &'b [u8]) -> Result<&'b [u8], Error> {
            if remaining.len() < 4 {
                return Err(Error::InvalidStorage);
            }
            let len = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
            *remaining = &remaining[4..];
            if len == 0 || len > remaining.len() {
                return Err(Error::InvalidStorage);
            }
            let value = &remaining[..len];
            *remaining = &remaining[len..];
            Ok(value)
        }
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(field(&mut remaining)?));
        let account =
            std::str::from_utf8(field(&mut remaining)?).map_err(|_| Error::InvalidStorage)?;
        IpcProfileId::try_from(account.to_owned()).map_err(|_| Error::InvalidStorage)?;
        if !remaining.is_empty() {
            return Err(Error::InvalidStorage);
        }
        native::key(path, account, create, identity)
    })();
    let mut response = Zeroizing::new(Vec::new());
    match result {
        Ok(None) => response.push(0),
        Ok(Some(key)) => {
            response.push(1);
            response.extend_from_slice(&key[..]);
        }
        Err(Error::Locked) => response.push(2),
        Err(Error::InvalidStorage) => response.push(4),
        Err(Error::CommitUncertain) => response.push(5),
        Err(_) => response.push(3),
    }
    if std::io::stdout().write_all(&response).is_ok() {
        0
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix::OwnerLock;
    use std::os::unix::fs::PermissionsExt;

    // Filesystem fault injection never touches any real Keychain. The dummy
    // database is used only by path validation; no helper is invoked here.
    fn store<'a>(owner: &'a OwnerLock, keychain: PathBuf) -> MacOsKeychain<'a> {
        fs::write(&keychain, []).unwrap();
        let executable_path = std::env::current_exe().unwrap().canonicalize().unwrap();
        MacOsKeychain {
            profile: owner.profile(),
            guard: ProtectedFile::open_keychain_guard(owner.profile()).unwrap(),
            profile_id: IpcProfileId::from_bytes([1; 16]).unwrap(),
            keychain,
            executable: File::open(&executable_path).unwrap(),
            executable_path,
        }
    }
    #[test]
    fn publication_faults_preserve_previous_or_report_uncertainty() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let owner = OwnerLock::acquire(&root_path.join("profile")).unwrap();
        let mut store = store(&owner, root_path.join("dummy.keychain-db"));
        store
            .publish(b"old-ciphertext", || Ok(()), File::sync_all)
            .unwrap();
        assert_eq!(
            store.publish(b"new-ciphertext", || Err(Error::Io), File::sync_all),
            Err(Error::Io)
        );
        let path = owner.profile().path().join("host-secrets.keychain.bundle");
        assert_eq!(fs::read(&path).unwrap(), b"old-ciphertext");
        assert_eq!(
            store.publish(
                b"new-ciphertext",
                || Ok(()),
                |_| Err(io::ErrorKind::Other.into())
            ),
            Err(Error::CommitUncertain)
        );
        assert_eq!(fs::read(&path).unwrap(), b"new-ciphertext");
        assert!(
            !fs::read_dir(owner.profile().path()).unwrap().any(|v| v
                .unwrap()
                .file_name()
                .as_encoded_bytes()
                .ends_with(b".tmp"))
        );
    }
    #[test]
    fn replaced_lock_or_profile_fails_before_publication() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let owner = OwnerLock::acquire(&root_path.join("profile")).unwrap();
        let mut store = store(&owner, root_path.join("dummy.keychain-db"));
        let lock = owner.profile().path().join("host-secrets.lock");
        fs::rename(&lock, owner.profile().path().join("retired-lock")).unwrap();
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock)
            .unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        assert_eq!(
            store.publish(b"ciphertext", || Ok(()), File::sync_all),
            Err(Error::InvalidStorage)
        );
        drop(store);
        fs::rename(owner.profile().path(), root_path.join("retired-profile")).unwrap();
        fs::create_dir(owner.profile().path()).unwrap();
        fs::set_permissions(owner.profile().path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            MacOsKeychain::open(
                owner.profile(),
                Selection::MacOsKeychain,
                IpcProfileId::from_bytes([1; 16]).unwrap(),
                &root_path.join("dummy.keychain-db")
            )
            .is_err()
        );
    }
    #[test]
    fn provider_switches_reject_foreign_payload_presence() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let owner = OwnerLock::acquire(&root_path.join("profile")).unwrap();
        let mut store = store(&owner, root_path.join("dummy.keychain-db"));
        store
            .publish(b"ciphertext", || Ok(()), File::sync_all)
            .unwrap();
        drop(store);
        assert!(matches!(
            ProtectedFile::open(
                owner.profile(),
                Selection::ProtectedFile(
                    crate::secrets::ProtectedFileAcknowledgement::OsPermissionsOnly
                )
            ),
            Err(Error::InvalidStorage)
        ));
        fs::remove_file(owner.profile().path().join("host-secrets.keychain.bundle")).unwrap();
        // Dangling foreign entries count as presence. No payload is opened.
        std::os::unix::fs::symlink(
            "nonexistent",
            owner.profile().path().join("host-secrets.bundle"),
        )
        .unwrap();
        assert!(matches!(
            ProtectedFile::open_keychain_guard(owner.profile()),
            Err(Error::InvalidStorage)
        ));
        fs::remove_file(owner.profile().path().join("host-secrets.bundle")).unwrap();
        let guard = ProtectedFile::open_keychain_guard(owner.profile()).unwrap();
        fs::write(owner.profile().path().join("host-secrets.bundle"), []).unwrap();
        assert_eq!(guard.check(), Err(Error::InvalidStorage));
    }
    #[test]
    fn extended_acl_is_rejected_before_publication() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let owner = OwnerLock::acquire(&root_path.join("profile")).unwrap();
        let mut store = store(&owner, root_path.join("dummy.keychain-db"));
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow read"])
                .arg(owner.profile().path())
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            store.publish(b"ciphertext", || Ok(()), File::sync_all),
            Err(Error::InvalidStorage)
        );
    }
    #[test]
    fn helper_identity_requires_trusted_ancestors_and_exact_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let binary = path.join("helper");
        fs::write(&binary, []).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = File::open(&binary).unwrap();
        assert!(validate_executable(&binary, &pinned).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            validate_executable(&binary, &pinned),
            Err(Error::Unavailable)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&binary, path.join("old-helper")).unwrap();
        fs::write(&binary, []).unwrap();
        assert_eq!(
            validate_executable(&binary, &pinned),
            Err(Error::Unavailable)
        );
    }
}
