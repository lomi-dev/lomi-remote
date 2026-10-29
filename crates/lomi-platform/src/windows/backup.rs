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
