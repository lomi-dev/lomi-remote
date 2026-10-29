//! New snapshot broker. Seccomp/bootstrap code separately derives from the old spike.
use super::*;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
const MAX_ENTRIES: usize = 512;
const MAX_BYTES: u64 = 16 * 1024 * 1024;
#[repr(C)]
struct How {
    flags: u64,
    mode: u64,
    resolve: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    path: PathBuf,
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    target: Option<Vec<u8>>,
    digest: Option<[u8; 32]>,
}
pub(super) struct Entry {
    pub path: PathBuf,
    pub mode: u32,
    pub data: Option<File>,
    pub target: Option<Vec<u8>>,
}
pub(super) struct Snapshot {
    pub entries: Vec<Entry>,
    stamps: Vec<Stamp>,
    held: Vec<File>,
    root: File,
}
pub(super) fn open_at(dir: RawFd, path: &Path, flags: i32) -> Result<File> {
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Repository)?;
    let how = How {
        flags: (flags
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if flags & libc::O_PATH == 0 {
                libc::O_NONBLOCK
            } else {
                0
            }) as u64,
        mode: 0,
        resolve: 0x08 | 0x02 | 0x04,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir,
            name.as_ptr(),
            &how,
            std::mem::size_of::<How>(),
        )
    } as i32;
    if fd < 0 {
        Err(Error::Changed)
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn stamp(path: PathBuf, f: &File, target: Option<Vec<u8>>) -> Result<Stamp> {
    let m = f.metadata().map_err(|_| Error::Changed)?;
    Ok(Stamp {
        path,
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode(),
        nlink: m.nlink(),
        size: m.len(),
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
        target,
        digest: None,
    })
}
pub(super) fn sealed(
    mut source: impl Read,
    mode: u32,
    time: (i64, i64),
    bound: u64,
) -> Result<File> {
    let fd = unsafe {
        libc::memfd_create(
            c"lomi-approved-snapshot".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(Error::Setup);
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let count = std::io::copy(&mut source.by_ref().take(bound + 1), &mut file)
        .map_err(|_| Error::Changed)?;
    if count > bound {
        return Err(Error::Limit);
    }
    file.flush().map_err(|_| Error::Setup)?;
    let times = [libc::timespec {
        tv_sec: time.0,
        tv_nsec: time.1,
    }; 2];
    if unsafe { libc::fchmod(fd, mode & 0o777) } != 0
        || unsafe { libc::futimens(fd, times.as_ptr()) } != 0
        || unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
    {
        return Err(Error::Setup);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| Error::Setup)?;
    Ok(file)
}
fn names(directory: &File) -> Result<Vec<std::ffi::OsString>> {
    let fd = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(Error::Setup);
    }
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        unsafe { libc::close(fd) };
        return Err(Error::Setup);
    }
    // dup shares directory offset. Rewind on every independent validation pass.
    unsafe { libc::rewinddir(dir) };
    let mut result = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            let error = unsafe { *libc::__errno_location() };
            unsafe { libc::closedir(dir) };
            if error != 0 {
                return Err(Error::Changed);
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            result.push(std::ffi::OsStr::from_bytes(name).to_owned());
            if result.len() > MAX_ENTRIES {
                unsafe { libc::closedir(dir) };
                return Err(Error::Limit);
            }
        }
    }
    result.sort();
    Ok(result)
}
fn safe_config(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Repository)?;
    let mut section = String::new();
    // Deliberately narrow ordinary-repository grammar, not a replacement Git parser.
    // Reject escaping/continuations and unknown sections instead of normalizing them.
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.contains('\\') || line.bytes().any(|b| b < 32 || b == 127) {
            return Err(Error::Repository);
        }
        if line.starts_with('[') && line.ends_with(']') {
            let inner = &line[1..line.len() - 1];
            section = inner
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if ![
                "core", "user", "filter", "diff", "alias", "remote", "branch",
            ]
            .contains(&section.as_str())
                || !inner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b" \".-_/@:".contains(&b))
            {
                return Err(Error::Repository);
            }
        } else {
            let (key, _) = line.split_once('=').ok_or(Error::Repository)?;
            let key = key.trim().to_ascii_lowercase();
            if section.is_empty()
                || key.is_empty()
                || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || (section == "core"
                    && ![
                        "repositoryformatversion",
                        "filemode",
                        "bare",
                        "logallrefupdates",
                        "ignorecase",
                        "precomposeunicode",
                        "fsmonitor",
                        "untrackedcache",
                        "hookspath",
                        "attributesfile",
                    ]
                    .contains(&key.as_str()))
            {
                return Err(Error::Repository);
            }
        }
    }
    Ok(())
}
fn digest(file: &File) -> Result<[u8; 32]> {
    let mut reader = file.try_clone().map_err(|_| Error::Changed)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::Changed)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 8192];
    let mut total = 0;
    loop {
        let n = reader.read(&mut bytes).map_err(|_| Error::Changed)?;
        if n == 0 {
            break;
        }
        total += n;
        if total > 8 * 1024 * 1024 {
            return Err(Error::Limit);
        }
        hash.update(&bytes[..n]);
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::Changed)?;
    Ok(hash.finalize().into())
}
impl Snapshot {
    pub fn capture(root: &Path) -> Result<Self> {
        let root = open_root(root).map_err(|_| Error::Repository)?;
        Self::capture_from(root)
    }
    pub fn capture_pinned(root: &File) -> Result<Self> {
        let root = root.try_clone().map_err(|_| Error::Setup)?;
        Self::capture_from(root)
    }
    fn capture_from(root: File) -> Result<Self> {
        let mut value = Self {
            entries: Vec::new(),
            stamps: vec![stamp(PathBuf::new(), &root, None)?],
            held: Vec::new(),
            root,
        };
        let mut total = 0;
        value.walk(Path::new(""), 0, true, &mut total)?;
        if !value
            .entries
            .iter()
            .any(|e| e.path == Path::new(".git") && e.mode & libc::S_IFMT == libc::S_IFDIR)
        {
            return Err(Error::Repository);
        }
        value.validate()?;
        Ok(value)
    }
    fn walk(
        &mut self,
        path: &Path,
        depth: usize,
        copy: bool,
        total: &mut u64,
    ) -> Result<Vec<Stamp>> {
        if depth > 32 {
            return Err(Error::Limit);
        }
        let dir = if path.as_os_str().is_empty() {
            self.root.try_clone().map_err(|_| Error::Setup)?
        } else {
            open_at(
                self.root.as_raw_fd(),
                path,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?
        };
        let mut stamps = Vec::new();
        for name in names(&dir)? {
            let path = path.join(name);
            if self.entries.len() + stamps.len() > MAX_ENTRIES {
                return Err(Error::Limit);
            }
            if path == Path::new(".git/commondir")
                || path == Path::new(".git/objects/info/alternates")
                || path == Path::new(".git/objects/info/http-alternates")
            {
                return Err(Error::Repository);
            }
            let pin = open_at(self.root.as_raw_fd(), &path, libc::O_PATH)?;
            let metadata = pin.metadata().map_err(|_| Error::Changed)?;
            let initial = stamp(path.clone(), &pin, None)?;
            let kind = metadata.mode() & libc::S_IFMT;
            let mut data = None;
            let mut target = None;
            let mut content_digest = None;
            match kind {
                libc::S_IFDIR => {}
                libc::S_IFREG => {
                    if metadata.nlink() != 1 {
                        return Err(Error::Repository);
                    }
                    if copy {
                        let mut source = open_at(self.root.as_raw_fd(), &path, libc::O_RDONLY)?;
                        if stamp(path.clone(), &source, None)? != initial {
                            return Err(Error::Changed);
                        }
                        *total = total.checked_add(metadata.len()).ok_or(Error::Limit)?;
                        if *total > MAX_BYTES || metadata.len() > 8 * 1024 * 1024 {
                            return Err(Error::Limit);
                        }
                        if path == Path::new(".git/config") {
                            let mut bytes = Vec::new();
                            std::io::Read::by_ref(&mut source)
                                .take(64 * 1024 + 1)
                                .read_to_end(&mut bytes)
                                .map_err(|_| Error::Changed)?;
                            if bytes.len() > 64 * 1024 {
                                return Err(Error::Limit);
                            }
                            safe_config(&bytes)?;
                            source
                                .seek(SeekFrom::Start(0))
                                .map_err(|_| Error::Changed)?;
                        }
                        data = Some(sealed(
                            &mut source,
                            metadata.mode(),
                            (metadata.mtime(), metadata.mtime_nsec()),
                            metadata.len(),
                        )?);
                        if stamp(path.clone(), &source, None)? != initial {
                            return Err(Error::Changed);
                        }
                        self.held.push(source);
                    }
                    if let Some(file) = &data {
                        content_digest = Some(digest(file)?);
                    } else {
                        *total = total.checked_add(metadata.len()).ok_or(Error::Limit)?;
                        if *total > MAX_BYTES || metadata.len() > 8 * 1024 * 1024 {
                            return Err(Error::Limit);
                        }
                        let source = open_at(self.root.as_raw_fd(), &path, libc::O_RDONLY)?;
                        if stamp(path.clone(), &source, None)? != initial {
                            return Err(Error::Changed);
                        }
                        content_digest = Some(digest(&source)?);
                        if stamp(path.clone(), &source, None)? != initial {
                            return Err(Error::Changed);
                        }
                    }
                }
                libc::S_IFLNK => {
                    if path.starts_with(".git") {
                        return Err(Error::Repository);
                    }
                    let mut bytes = vec![0; 4097];
                    let n = unsafe {
                        libc::readlinkat(
                            pin.as_raw_fd(),
                            c"".as_ptr(),
                            bytes.as_mut_ptr().cast(),
                            bytes.len(),
                        )
                    };
                    if n < 0 || n as usize >= bytes.len() {
                        return Err(Error::Changed);
                    }
                    bytes.truncate(n as usize);
                    target = Some(bytes);
                }
                _ => return Err(Error::Repository),
            }
            let item = Stamp {
                target: target.clone(),
                digest: content_digest,
                ..initial
            };
            let mut current = stamp(path.clone(), &pin, target.clone())?;
            current.digest = content_digest;
            if current != item {
                return Err(Error::Changed);
            }
            if copy {
                self.entries.push(Entry {
                    path: path.clone(),
                    mode: metadata.mode(),
                    data,
                    target,
                });
                self.stamps.push(item.clone());
                self.held.push(pin)
            }
            stamps.push(item);
            if kind == libc::S_IFDIR {
                stamps.extend(self.walk(&path, depth + 1, copy, total)?)
            }
        }
        Ok(stamps)
    }
    pub fn validate(&mut self) -> Result<()> {
        if stamp(PathBuf::new(), &self.root, None)? != self.stamps[0] {
            return Err(Error::Changed);
        }
        let current = self
            .walk(Path::new(""), 0, false, &mut 0)
            .map_err(|_| Error::Changed)?;
        if current != self.stamps[1..] {
            return Err(Error::Changed);
        }
        // Held descriptors pin the source graph throughout this check. A rename
        // or unlink of any opened inode updates its ctime/nlink and is rejected.
        for file in &self.held {
            let m = file.metadata().map_err(|_| Error::Changed)?;
            let old = self
                .stamps
                .iter()
                .find(|s| s.dev == m.dev() && s.ino == m.ino())
                .ok_or(Error::Changed)?;
            let mut current = stamp(old.path.clone(), file, old.target.clone())?;
            current.digest = old.digest;
            if current != *old {
                return Err(Error::Changed);
            }
        }
        Ok(())
    }
}
