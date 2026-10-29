use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
};
pub struct Endpoint {
    pub listener: UnixListener,
    _lock: File,
    socket: PathBuf,
}
fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
impl Endpoint {
    pub fn bind(directory: &Path) -> io::Result<Self> {
        if !directory.is_absolute() {
            return Err(denied("socket directory must be absolute"));
        }
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(denied(
                "socket directory must be an owned private 0700 directory",
            ));
        }
        // Reject aliases through symlink parents before opening privileged files.
        if fs::canonicalize(directory)? != directory {
            return Err(denied("socket directory must use its canonical path"));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("owner.lock"))?;
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(denied("invalid owner lock"));
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another session host owns this directory",
            ));
        }
        let socket = directory.join("host.sock");
        match fs::symlink_metadata(&socket) {
            Ok(metadata) => {
                if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() }
                {
                    return Err(denied("unexpected socket path"));
                }
                fs::remove_file(&socket)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            _lock: lock,
            socket,
        })
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
    }
}
pub fn same_uid(stream: &UnixStream) -> io::Result<bool> {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let mut uid = 0;
        let mut gid = 0;
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid == unsafe { libc::geteuid() })
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid == unsafe { libc::geteuid() })
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "linux"
    )))]
    {
        let _ = stream;
        Err(denied("peer credentials unsupported on this platform"))
    }
}
