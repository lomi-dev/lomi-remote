use super::{Error, Result};
use std::{
    ffi::{CStr, CString},
    os::fd::RawFd,
    path::{Component, Path, PathBuf},
};

struct Account {
    name: CString,
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: PathBuf,
}

fn account(name: &str) -> Result<Account> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(Error::Invalid);
    }
    let encoded = CString::new(name).map_err(|_| Error::Invalid)?;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut storage = vec![0u8; 16 * 1024];
    let mut found = std::ptr::null_mut();
    if unsafe {
        libc::getpwnam_r(
            encoded.as_ptr(),
            &mut entry,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut found,
        )
    } != 0
        || found.is_null()
        || entry.pw_name.is_null()
        || entry.pw_dir.is_null()
    {
        return Err(Error::Invalid);
    }
    let canonical_name = unsafe { CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(|_| Error::Invalid)?;
    let home = unsafe { CStr::from_ptr(entry.pw_dir) }
        .to_str()
        .map_err(|_| Error::Invalid)?;
    let uid = entry.pw_uid;
    let gid = entry.pw_gid;
    if canonical_name != name || uid == 0 || gid == 0 || !absolute_clean(Path::new(home)) {
        return Err(Error::Invalid);
    }
    Ok(Account {
        name: encoded,
        uid,
        gid,
        home: PathBuf::from(home),
    })
}

fn absolute_clean(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn self_bsdinfo() -> Result<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    let result = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size as libc::c_int,
        )
    };
    if result != size as libc::c_int {
        return Err(Error::Conflict);
    }
    Ok(info)
}

fn close_extra_descriptors() -> Result<()> {
    let mut capacity = 32usize;
    loop {
        let mut descriptors = Vec::<libc::proc_fdinfo>::with_capacity(capacity);
        descriptors.resize_with(capacity, || unsafe { std::mem::zeroed() });
        let bytes = capacity
            .checked_mul(std::mem::size_of::<libc::proc_fdinfo>())
            .and_then(|size| libc::c_int::try_from(size).ok())
            .ok_or(Error::Conflict)?;
        let result = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                descriptors.as_mut_ptr().cast(),
                bytes,
            )
        };
        if result <= 0 {
            return Err(Error::Conflict);
        }
        let returned = result as usize;
        let element_size = std::mem::size_of::<libc::proc_fdinfo>();
        if returned % element_size != 0 {
            return Err(Error::Conflict);
        }
        if returned == bytes as usize {
            capacity = capacity
                .checked_mul(2)
                .filter(|size| *size <= 65_536)
                .ok_or(Error::Conflict)?;
            continue;
        }
        for descriptor in descriptors.iter().take(returned / element_size) {
            let fd = descriptor.proc_fd;
            if fd > libc::STDERR_FILENO as RawFd && unsafe { libc::close(fd) } != 0 {
                return Err(Error::Conflict);
            }
        }
        return Ok(());
    }
}

fn permanently_drop_privileges(account: &Account) -> Result<()> {
    let base_group = libc::c_int::try_from(account.gid).map_err(|_| Error::Invalid)?;
    if unsafe { libc::initgroups(account.name.as_ptr(), base_group) } != 0
        || unsafe { libc::setgid(account.gid) } != 0
        || unsafe { libc::setuid(account.uid) } != 0
    {
        return Err(Error::Conflict);
    }
    let info = self_bsdinfo()?;
    if info.pbi_uid != account.uid
        || info.pbi_ruid != account.uid
        || info.pbi_svuid != account.uid
        || info.pbi_gid != account.gid
        || info.pbi_rgid != account.gid
        || info.pbi_svgid != account.gid
    {
        return Err(Error::Conflict);
    }
    close_extra_descriptors()?;
    if unsafe { libc::geteuid() } != account.uid || unsafe { libc::getegid() } != account.gid {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub(super) fn prepare_boot_profile_in_helper(
    selected_account: &str,
    profile: &Path,
) -> Result<PathBuf> {
    if unsafe { libc::geteuid() } != 0 || self_bsdinfo()?.pbi_uid != 0 {
        return Err(Error::Conflict);
    }
    let account = account(selected_account)?;
    let expected = account
        .home
        .join("Library")
        .join("Application Support")
        .join("LomiRemote");
    if !absolute_clean(profile) || profile.as_os_str() != expected.as_os_str() {
        return Err(Error::Invalid);
    }

    permanently_drop_privileges(&account)?;
    super::custody::prepare_current_user_host_profile(profile).map_err(|_| Error::Conflict)?;
    let canonical = profile.canonicalize().map_err(|_| Error::Conflict)?;
    if canonical != profile {
        return Err(Error::Conflict);
    }
    Ok(canonical)
}
