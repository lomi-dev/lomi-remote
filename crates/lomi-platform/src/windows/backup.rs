//! Pinned private-profile destinations for SQLite's path-based backup API.
use super::*;

/// Retains every validated ancestor without delete sharing while SQLite uses
/// the destination path. Source and destination must share the exact profile.
pub struct Destination {
    profile: PrivateProfile,
    _source: File,
    path: PathBuf,
}
impl Destination {
    pub fn new(source: &Path, destination: &Path) -> Result<Self> {
        let source = normalized(source)?;
        let destination = normalized(destination)?;
        let name = destination
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or(Error::InvalidProfile)?;
        // Win32 stream syntax and trailing-dot/space aliases must not select a
        // different object from the caller's literal destination filename.
        if name.contains(':') || name.ends_with(['.', ' ']) {
            return Err(Error::InvalidProfile);
        }
        let parent = source.parent().ok_or(Error::InvalidProfile)?;
        if destination.parent() != Some(parent) || destination == source {
            return Err(Error::InvalidProfile);
        }
        let profile = PrivateProfile::open(parent, false)?;
        let source = open_regular(&source, false, false, &profile.sid)?;
        profile.check_current()?;
        Ok(Self {
            profile,
            _source: source,
            path: destination,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn create(&self) -> Result<BackupFile> {
        self.profile.check_current()?;
        let sd = security(&self.profile.sid, false)?;
        let handle = Handle::new(unsafe {
            CreateFileW(
                wide(&self.path).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sd.attributes,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        })?;
        self.finish_open(handle)
    }
    pub fn existing(&self) -> Result<Option<BackupFile>> {
        self.profile.check_current()?;
        match open_path(&self.path, true, false, false, &self.profile.sid) {
            Ok(handle) => self.finish_open(handle).map(Some),
            Err(Error::Io(error)) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    fn finish_open(&self, handle: Handle) -> Result<BackupFile> {
        validate_security(handle.0, &self.profile.sid, true, false)?;
        let info = information(handle.0)?;
        if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
            || info.nNumberOfLinks != 1
        {
            return Err(Error::InvalidProfile);
        }
        // Unlike inherited files, backups must retain the protected DACL that
        // was installed atomically at CREATE_NEW, including on migration reuse.
        let mut descriptor = ptr::null_mut();
        let code = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(Error::PermissionDenied);
        }
        let _descriptor = Local(descriptor);
        let (mut control, mut revision) = (0, 0);
        unsafe {
            check(GetSecurityDescriptorControl(
                descriptor,
                &mut control,
                &mut revision,
            ))?;
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(Error::InvalidProfile);
        }
        let identity = object(&info);
        let raw = handle.0;
        mem::forget(handle);
        Ok(BackupFile {
            file: unsafe { File::from_raw_handle(raw) },
            identity,
        })
    }
    pub fn sync(&self, file: &BackupFile) -> Result<()> {
        self.profile.check_current()?;
        let current = self.existing()?.ok_or(Error::InvalidProfile)?;
        if current.identity != file.identity {
            return Err(Error::InvalidProfile);
        }
        file.file.sync_all()?;
        Ok(())
    }
}

/// Denies delete sharing for the lifetime of the SQLite backup and checks.
pub struct BackupFile {
    file: File,
    identity: Object,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> (tempfile::TempDir, OwnerLock, PathBuf) {
        let root = tempfile::Builder::new()
            .prefix("lomi-backup-native-")
            .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
            .unwrap();
        let path = normalized(&root.path().canonicalize().unwrap())
            .unwrap()
            .join("profile");
        let lock = OwnerLock::acquire(&path).unwrap();
        let source = lock.prepare_database().unwrap();
        (root, lock, source)
    }
    #[test]
    fn native_backup_private_before_bytes_pinned_and_never_overwrites() {
        let (_root, lock, source) = profile();
        let path = lock.profile().path().join("backup.sqlite");
        let destination = Destination::new(&source, &path).unwrap();
        let file = destination.create().unwrap();
        assert_eq!(file.file.metadata().unwrap().len(), 0);
        validate_security(
            file.file.as_raw_handle(),
            &current_sid().unwrap(),
            true,
            false,
        )
        .unwrap();
        assert!(destination.create().is_err());
        assert!(fs::remove_file(&path).is_err());
        assert!(
            fs::rename(
                lock.profile().path(),
                lock.profile().path().with_extension("moved")
            )
            .is_err()
        );
        destination.sync(&file).unwrap();
        drop(file);
        assert!(destination.existing().unwrap().is_some());
    }
    #[test]
    fn native_backup_rejects_other_parent_and_hardlinks() {
        let (_root, lock, source) = profile();
        let path = lock.profile().path().join("backup.sqlite");
        assert!(
            Destination::new(
                &source,
                &source.with_file_name("..").join("elsewhere.sqlite")
            )
            .is_err()
        );
        let destination = Destination::new(&source, &path).unwrap();
        drop(destination.create().unwrap());
        let alias = lock.profile().path().join("alias.sqlite");
        fs::hard_link(&path, &alias).unwrap();
        assert!(destination.existing().is_err());
        fs::remove_file(alias).unwrap();
    }
    #[test]
    fn native_backup_rejects_alias_names_and_foreign_owner() {
        let (_root, lock, source) = profile();
        for name in ["backup.sqlite:stream", "host.sqlite3.", "backup.sqlite "] {
            assert!(Destination::new(&source, &lock.profile().path().join(name)).is_err());
        }
        let path = lock.profile().path().join("foreign.sqlite");
        let sid = current_sid().unwrap();
        let sd = Security::new(&format!("O:BAD:P(A;;FA;;;{sid})")).unwrap();
        let handle = match Handle::new(unsafe {
            CreateFileW(
                wide(&path).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sd.attributes,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        }) {
            Ok(handle) => handle,
            // Creating a file owned by Administrators needs an elevated token
            // (ERROR_INVALID_OWNER otherwise). A standard user cannot build the
            // foreign-owner fixture, so only the alias-name half ran here.
            Err(error) if error.raw_os_error() == Some(1307) => {
                eprintln!("skipped foreign-owner half: needs an elevated token ({error})");
                return;
            }
            Err(error) => panic!("foreign-owner fixture: {error}"),
        };
        assert!(validate_security(handle.0, &sid, true, false).is_err());
        drop(handle);
        let destination = Destination::new(&source, &path).unwrap();
        assert!(destination.existing().is_err());
        assert!(path.exists());
    }
    #[test]
    fn native_backup_rejects_reparse_and_public_parent() {
        let (root, lock, source) = profile();
        let junction = normalized(&root.path().canonicalize().unwrap())
            .unwrap()
            .join("junction");
        let output = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(lock.profile().path())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            Destination::new(
                &junction.join("host.sqlite3"),
                &junction.join("backup.sqlite")
            )
            .is_err()
        );
        fs::remove_dir(&junction).unwrap();
        let parent = normalized(&root.path().canonicalize().unwrap())
            .unwrap()
            .join("public");
        let sid = current_sid().unwrap();
        let sd = Security::new(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FR;;;WD)")).unwrap();
        unsafe {
            check(CreateDirectoryW(wide(&parent).as_ptr(), &sd.attributes)).unwrap();
        }
        assert!(
            Destination::new(&parent.join("source.sqlite"), &parent.join("backup.sqlite")).is_err()
        );
        assert!(!parent.join("backup.sqlite").exists());
        assert!(source.exists());
    }
}
