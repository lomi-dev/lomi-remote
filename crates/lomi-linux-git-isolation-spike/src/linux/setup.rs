//! Trusted setup only: bounded sealed metadata, exact fd timestamps, readonly
//! mounts, then irrevocable privilege removal before broker fork or Git input.
use super::*;
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
#[repr(C)]
struct MountAttr {
    set: u64,
    clear: u64,
    propagation: u64,
    userns: u64,
}
fn caps() -> Result<[CapData; 2]> {
    let header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    if unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) } != 0 {
        return Err(Error::Setup);
    }
    Ok(data)
}
pub(super) fn zero_caps() -> bool {
    let Ok(data) = caps() else { return false };
    if data
        .iter()
        .any(|d| d.effective != 0 || d.permitted != 0 || d.inheritable != 0)
    {
        return false;
    }
    for bit in 0..=40 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, bit, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, bit, 0, 0) }
                != 0
        {
            return false;
        }
    }
    true
}
fn readonly(file: &File) -> Result<()> {
    let attr = MountAttr {
        set: 1 | 2 | 4,
        clear: 0,
        propagation: 0,
        userns: 0,
    };
    if unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            &attr,
            std::mem::size_of::<MountAttr>(),
        )
    } != 0
    {
        eprintln!(
            "setup-readonly-error:{}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        );
        return Err(Error::Setup);
    }
    Ok(())
}
pub(super) fn sealed_manifest(fd: RawFd) -> bool {
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    seals >= 0 && seals & required == required
}
pub(super) fn finish(metadata: RawFd) -> Result<()> {
    let allowed = (1 << 21) | (1 << 8); // SYS_ADMIN and SETPCAP only.
    let data = caps()?;
    if data[0].effective != allowed
        || data[0].permitted != allowed
        || data[1].effective != 0
        || data[1].permitted != 0
    {
        return Err(Error::Setup);
    }
    let mut manifest = unsafe { File::from_raw_fd(metadata) };
    if !sealed_manifest(metadata) {
        return Err(Error::Setup);
    }
    let mut bytes = Vec::new();
    manifest
        .by_ref()
        .take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Setup)?;
    if bytes.len() > 128 * 1024 {
        return Err(Error::Setup);
    }
    let entries: Vec<(String, u32, i64, i64)> =
        serde_json::from_slice(&bytes).map_err(|_| Error::Setup)?;
    if entries.len() > 512 {
        return Err(Error::Setup);
    }
    let root = open_root(Path::new("/repo")).map_err(|_| Error::Setup)?;
    for (path, mode, sec, nsec) in entries {
        if path.is_empty()
            || path.starts_with('/')
            || !(0..1_000_000_000).contains(&nsec)
            || mode & !0o777 != 0
        {
            return Err(Error::Setup);
        }
        let file = snapshot::open_at(root.as_raw_fd(), Path::new(&path), libc::O_RDONLY)?;
        let m = file.metadata().map_err(|_| Error::Setup)?;
        if !m.is_file() || m.mode() & 0o777 != mode || m.nlink() != 0 {
            return Err(Error::Setup);
        }
        let times = [libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        }; 2];
        if unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } != 0 {
            return Err(Error::Setup);
        }
        readonly(&file)?;
        let after = file.metadata().map_err(|_| Error::Setup)?;
        if (m.dev(), m.ino(), mode, sec, nsec)
            != (
                after.dev(),
                after.ino(),
                after.mode() & 0o777,
                after.mtime(),
                after.mtime_nsec(),
            )
        {
            return Err(Error::Setup);
        }
        let mut fs = unsafe { std::mem::zeroed::<libc::statvfs>() };
        if unsafe { libc::fstatvfs(file.as_raw_fd(), &mut fs) } != 0
            || fs.f_flag & libc::ST_RDONLY == 0
        {
            return Err(Error::Setup);
        }
    }
    readonly(&open_root(Path::new("/")).map_err(|_| Error::Setup)?)?;
    drop(root);
    drop(manifest);
    // CAP_SETPCAP is needed until the last bounding bit has been dropped.
    for bit in 0..=40 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, bit, 0, 0, 0) } != 0 {
            return Err(Error::Setup);
        }
    }
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(Error::Setup);
    }
    let header = CapHeader {
        version: 0x20080522,
        pid: 0,
    };
    let zero = [CapData::default(); 2];
    if unsafe { libc::syscall(libc::SYS_capset, &header, zero.as_ptr()) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || !zero_caps()
    {
        return Err(Error::Setup);
    }
    Ok(())
}
