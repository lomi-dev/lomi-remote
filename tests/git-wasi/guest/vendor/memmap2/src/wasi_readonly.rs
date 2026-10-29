//! Lomi E0-only owned read snapshot, not an OS memory mapping.
//! Native backends and all mutable/executable mappings remain unchanged/denied.
use std::{fs::File, io, os::fd::AsRawFd};

const MAX_READ: usize = 16 * 1024 * 1024;

pub struct MmapInner {
    // No method resizes this Vec, so its allocation stays stable until Drop.
    bytes: Vec<u8>,
}

fn denied<T>() -> io::Result<T> {
    Err(io::ErrorKind::Unsupported.into())
}

impl MmapInner {
    pub fn map(len: usize, file: &File, offset: u64, _: bool, _: bool) -> io::Result<Self> {
        let end = offset.checked_add(u64::try_from(len).map_err(|_| io::ErrorKind::InvalidInput)?)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if len > MAX_READ || end > i64::MAX as u64 { return Err(io::ErrorKind::InvalidInput.into()); }
        if end > file.metadata()?.len() { return Err(io::ErrorKind::UnexpectedEof.into()); }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(io::Error::other)?;
        bytes.resize(len, 0);
        let mut read = 0;
        while read < len {
            // WASI FileExt::read_at is unstable even on the pinned toolchain.
            // libc pread lowers to core WASI fd_pread; it borrows the original
            // descriptor and never seeks, duplicates, owns or closes it.
            let n = unsafe { libc::pread(file.as_raw_fd(), bytes[read..].as_mut_ptr().cast(), len - read, (offset + read as u64) as i64) };
            if n == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
            if n < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted { continue; }
                return Err(error);
            }
            read += usize::try_from(n).map_err(io::Error::other)?;
        }
        Ok(Self { bytes })
    }
    pub fn map_copy_read_only(len: usize, file: &File, offset: u64, a: bool, b: bool) -> io::Result<Self> {
        Self::map(len, file, offset, a, b)
    }
    pub fn map_exec(_: usize, _: &File, _: u64, _: bool, _: bool) -> io::Result<Self> { denied() }
    pub fn map_mut(_: usize, _: &File, _: u64, _: bool, _: bool) -> io::Result<Self> { denied() }
    pub fn map_copy(_: usize, _: &File, _: u64, _: bool, _: bool) -> io::Result<Self> { denied() }
    pub fn map_anon(_: usize, _: bool, _: bool, _: Option<u8>, _: bool) -> io::Result<Self> { denied() }
    pub fn flush(&self, _: usize, _: usize) -> io::Result<()> { denied() }
    pub fn flush_async(&self, _: usize, _: usize) -> io::Result<()> { denied() }
    pub fn make_read_only(&mut self) -> io::Result<()> { denied() }
    pub fn make_exec(&mut self) -> io::Result<()> { denied() }
    pub fn make_mut(&mut self) -> io::Result<()> { denied() }
    pub fn ptr(&self) -> *const u8 { self.bytes.as_ptr() }
    pub fn mut_ptr(&mut self) -> *mut u8 { self.bytes.as_mut_ptr() }
    pub fn len(&self) -> usize { self.bytes.len() }
}

pub fn file_len(file: &File) -> io::Result<u64> { Ok(file.metadata()?.len()) }
