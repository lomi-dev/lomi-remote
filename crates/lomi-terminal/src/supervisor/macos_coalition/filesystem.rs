use super::*;
use std::ffi::{CStr, CString, OsStr};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

pub(super) struct Directory {
    pub path: PathBuf,
    pub(super) file: File,
}
fn name(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| Error::InvalidArgument)
}
impl Directory {
    pub fn open(path: &Path, create: bool) -> Result<Self> {
        Self::open_inner(path, create, true)
    }
    pub fn ancestry(path: &Path) -> Result<Self> {
        Self::open_inner(path, false, false)
    }
    fn open_inner(path: &Path, create: bool, private: bool) -> Result<Self> {
        if !path.is_absolute() {
            return Err(Error::InvalidArgument);
        }
        let mut current = File::open("/").map_err(|_| Error::SpawnFailed)?;
        if unsafe { lomi_coalition_safe_acl(current.as_raw_fd()) } != 0 {
            return Err(Error::InvalidArgument);
        }
        for component in path.components().skip(1) {
            let std::path::Component::Normal(part) = component else {
                return Err(Error::InvalidArgument);
            };
            let part = name(part)?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let mut fd = unsafe { libc::openat(current.as_raw_fd(), part.as_ptr(), flags) };
            if fd < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                if unsafe { libc::mkdirat(current.as_raw_fd(), part.as_ptr(), 0o700) } != 0
                    && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                {
                    return Err(Error::SpawnFailed);
                }
                fd = unsafe { libc::openat(current.as_raw_fd(), part.as_ptr(), flags) };
            }
            if fd < 0 {
                return Err(Error::InvalidArgument);
            }
            let next = unsafe { File::from_raw_fd(fd) };
            let metadata = next.metadata().map_err(|_| Error::SpawnFailed)?;
            if !metadata.is_dir()
                || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
                || metadata.mode() & 0o022 != 0
                || unsafe { lomi_coalition_safe_acl(fd) } != 0
            {
                return Err(Error::InvalidArgument);
            }
            if create {
                current.sync_all().map_err(|_| Error::CleanupFailed)?;
            }
            current = next;
        }
        let metadata = current.metadata().map_err(|_| Error::SpawnFailed)?;
        if private
            && (metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o700)
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            path: path.into(),
            file: current,
        })
    }
    pub fn sync(&self) -> Result<()> {
        self.file.sync_all().map_err(|_| Error::CleanupFailed)
    }
    pub fn child(&self, name_value: &str) -> Result<Self> {
        let part = name(OsStr::new(name_value))?;
        if name_value.contains('/') || name_value == "." || name_value == ".." {
            return Err(Error::InvalidArgument);
        }
        if unsafe { libc::mkdirat(self.file.as_raw_fd(), part.as_ptr(), 0o700) } != 0
            && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
        {
            return Err(Error::SpawnFailed);
        }
        self.sync()?;
        Self::open(&self.path.join(name_value), false)
    }
    pub fn file(&self, key: &str, create: bool) -> Result<Option<File>> {
        if key.contains('/') || key == "." || key == ".." {
            return Err(Error::InvalidArgument);
        }
        let key = name(OsStr::new(key))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                key.as_ptr(),
                libc::O_RDWR
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC
                    | if create { libc::O_CREAT } else { 0 },
                0o600,
            )
        };
        if fd < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(Error::CleanupFailed)
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || unsafe { lomi_coalition_safe_acl(fd) } != 0
        {
            return Err(Error::CleanupFailed);
        }
        Ok(Some(file))
    }
    pub fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.file(key, false)?
            .map(|mut file| {
                let mut bytes = Vec::new();
                (&mut file)
                    .take(131073)
                    .read_to_end(&mut bytes)
                    .map_err(|_| Error::CleanupFailed)?;
                if bytes.len() > 131072 {
                    return Err(Error::CleanupFailed);
                }
                Ok(bytes)
            })
            .transpose()
    }
    pub fn write(&self, key: &str, bytes: &[u8], expected: Option<&[u8]>) -> Result<()> {
        if self.read(key)?.as_deref() != expected {
            return Err(Error::CleanupFailed);
        }
        let temporary = format!(".tmp-{}", uuid::Uuid::new_v4());
        let temp = name(OsStr::new(&temporary))?;
        let target = name(OsStr::new(key))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(Error::CleanupFailed);
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| Error::CleanupFailed)?;
            if self.read(key)?.as_deref() != expected {
                return Err(Error::CleanupFailed);
            }
            let flags = if expected.is_none() {
                libc::RENAME_EXCL
            } else {
                0
            };
            if unsafe {
                libc::renameatx_np(
                    self.file.as_raw_fd(),
                    temp.as_ptr(),
                    self.file.as_raw_fd(),
                    target.as_ptr(),
                    flags,
                )
            } != 0
            {
                return Err(Error::CleanupFailed);
            }
            Ok(())
        })();
        unsafe { libc::unlinkat(self.file.as_raw_fd(), temp.as_ptr(), 0) };
        self.sync()?;
        result
    }
    pub fn remove(&self, key: &str, expected: &[u8]) -> Result<()> {
        if let Some(bytes) = self.read(key)? {
            if bytes != expected {
                return Err(Error::CleanupFailed);
            }
            let key = name(OsStr::new(key))?;
            if unsafe { libc::unlinkat(self.file.as_raw_fd(), key.as_ptr(), 0) } != 0 {
                return Err(Error::CleanupFailed);
            }
        }
        self.sync()
    }
    pub fn lock(&self, key: &str, wait: Duration) -> Result<File> {
        let file = self.file(key, true)?.ok_or(Error::CleanupFailed)?;
        self.sync()?;
        let deadline = Instant::now() + wait;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(file);
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock
                || Instant::now() >= deadline
            {
                return Err(Error::CleanupFailed);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        self.visit_names(|name| {
            names.push(name.to_owned());
            if names.len() > 4096 {
                return Err(Error::CleanupFailed);
            }
            Ok(())
        })?;
        Ok(names)
    }
    pub fn visit_names(&self, mut visit: impl FnMut(&str) -> Result<()>) -> Result<()> {
        // dup shares a directory offset. Use a new open description so repeated
        // passes always begin at the first entry and do not affect the anchor.
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(Error::CleanupFailed);
        }
        let directory = unsafe { libc::fdopendir(fd) };
        if directory.is_null() {
            unsafe { libc::close(fd) };
            return Err(Error::CleanupFailed);
        }
        let result = (|| {
            loop {
                unsafe {
                    *libc::__error() = 0;
                }
                let entry = unsafe { libc::readdir(directory) };
                if entry.is_null() {
                    return if io::Error::last_os_error().raw_os_error() == Some(0) {
                        Ok(())
                    } else {
                        Err(Error::CleanupFailed)
                    };
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                    .to_str()
                    .map_err(|_| Error::CleanupFailed)?;
                if name != "." && name != ".." {
                    visit(name)?;
                }
            }
        })();
        unsafe { libc::closedir(directory) };
        result
    }
}
