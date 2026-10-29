//! Lomi E0-only metadata access. Never invent a fallback timestamp.
use crate::FileTime;
use std::{fs, io, path::Path};
pub fn from_last_modification_time(meta: &fs::Metadata) -> FileTime {
    FileTime::from_system_time(meta.modified().expect("WASI modification time unavailable"))
}
pub fn from_last_access_time(meta: &fs::Metadata) -> FileTime {
    FileTime::from_system_time(meta.accessed().expect("WASI access time unavailable"))
}
pub fn from_creation_time(meta: &fs::Metadata) -> Option<FileTime> {
    meta.created().ok().map(FileTime::from_system_time)
}
pub fn set_symlink_file_times(_: &Path, _: FileTime, _: FileTime) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}
pub fn open(_: &Path) -> io::Result<fs::File> {
    Err(io::ErrorKind::Unsupported.into())
}
