#[cfg(target_os = "linux")]
use super::AccountCreationConsent;
use super::{CurrentAccount, Error, SelectedAccount, UnixAccount};
use std::{
    ffi::{CStr, CString, OsString},
    fs, io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path},
    process::{Command, ExitStatus},
};
#[cfg(target_os = "linux")]
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::PermissionsExt,
    },
    process::Stdio,
    thread,
    time::{Duration, Instant},
};

#[path = "setup_terminal.rs"]
mod setup_terminal;

const ACCOUNT_BUFFER: usize = 16 * 1024;
const MAX_GROUPS: usize = 65_536;
const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 128 * 1024;
#[cfg(target_os = "linux")]
const MAX_HANDOFF_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MFD_EXEC_FLAG: libc::c_uint = 0x0010;

fn account_name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn home_is_clean(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && !path.starts_with("/root")
        && !path.starts_with("/var/root")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn from_passwd(entry: &libc::passwd) -> Result<UnixAccount, Error> {
    if entry.pw_name.is_null() || entry.pw_dir.is_null() {
        return Err(Error::NativeIdentityUnavailable);
    }
    let name = unsafe { CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(|_| Error::NativeIdentityUnavailable)?
        .to_owned();
    let home = unsafe { CStr::from_ptr(entry.pw_dir) }
        .to_str()
        .map_err(|_| Error::NativeIdentityUnavailable)?;
    let home = Path::new(home);
    if !account_name_is_valid(&name) || !home_is_clean(home) {
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok(UnixAccount {
        uid: entry.pw_uid,
        gid: entry.pw_gid,
        name,
        home: home.to_path_buf(),
    })
}

fn lookup_name(name: &str) -> Result<UnixAccount, Error> {
    if !account_name_is_valid(name) {
        return Err(Error::InvalidAccount);
    }
    let encoded = CString::new(name).map_err(|_| Error::InvalidAccount)?;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut storage = vec![0u8; ACCOUNT_BUFFER];
    let mut found = std::ptr::null_mut();
    let result = unsafe {
        libc::getpwnam_r(
            encoded.as_ptr(),
            &mut entry,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut found,
        )
    };
    if result == libc::ERANGE {
        return Err(Error::NativeIdentityUnavailable);
    }
    if result != 0 {
        return Err(Error::NativeIdentityUnavailable);
    }
    if found.is_null() {
        return Err(Error::AccountNotFound);
    }
    let account = from_passwd(&entry)?;
    if account.name != name {
        return Err(Error::InvalidAccount);
    }
    Ok(account)
}

fn lookup_uid(uid: libc::uid_t) -> Result<UnixAccount, Error> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut storage = vec![0u8; ACCOUNT_BUFFER];
    let mut found = std::ptr::null_mut();
    let result = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut found,
        )
    };
    if result != 0 || found.is_null() || entry.pw_uid != uid {
        return Err(Error::NativeIdentityUnavailable);
    }
    from_passwd(&entry)
}

#[cfg(target_os = "linux")]
fn group_name_exists(name: &str) -> Result<bool, Error> {
    let encoded = CString::new(name).map_err(|_| Error::InvalidAccount)?;
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut storage = vec![0u8; ACCOUNT_BUFFER];
    let mut found = std::ptr::null_mut();
    let result = unsafe {
        libc::getgrnam_r(
            encoded.as_ptr(),
            &mut entry,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut found,
        )
    };
    if result != 0 {
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok(!found.is_null())
}

#[cfg(target_os = "linux")]
fn private_primary_group_matches(name: &str, gid: libc::gid_t) -> Result<bool, Error> {
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut storage = vec![0u8; ACCOUNT_BUFFER];
    let mut found = std::ptr::null_mut();
    let result = unsafe {
        libc::getgrgid_r(
            gid,
            &mut entry,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut found,
        )
    };
    if result != 0 || found.is_null() || entry.gr_name.is_null() || entry.gr_mem.is_null() {
        return Err(Error::NativeIdentityUnavailable);
    }
    let group_name = unsafe { CStr::from_ptr(entry.gr_name) }
        .to_str()
        .map_err(|_| Error::NativeIdentityUnavailable)?;
    if group_name != name {
        return Ok(false);
    }
    for index in 0..1024usize {
        let member = unsafe { *entry.gr_mem.add(index) };
        if member.is_null() {
            return Ok(true);
        }
        let member = unsafe { CStr::from_ptr(member) }
            .to_str()
            .map_err(|_| Error::NativeIdentityUnavailable)?;
        if member != name {
            return Ok(false);
        }
    }
    Err(Error::NativeIdentityUnavailable)
}

#[cfg(target_os = "linux")]
fn unix_ids() -> Result<
    (
        libc::uid_t,
        libc::uid_t,
        libc::uid_t,
        libc::gid_t,
        libc::gid_t,
        libc::gid_t,
    ),
    Error,
> {
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
        || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
    {
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok((
        real_uid,
        effective_uid,
        saved_uid,
        real_gid,
        effective_gid,
        saved_gid,
    ))
}

#[cfg(target_os = "macos")]
fn unix_ids() -> Result<
    (
        libc::uid_t,
        libc::uid_t,
        libc::uid_t,
        libc::gid_t,
        libc::gid_t,
        libc::gid_t,
    ),
    Error,
> {
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
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok((
        info.pbi_ruid,
        info.pbi_uid,
        info.pbi_svuid,
        info.pbi_rgid,
        info.pbi_gid,
        info.pbi_svgid,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unix_ids() -> Result<
    (
        libc::uid_t,
        libc::uid_t,
        libc::uid_t,
        libc::gid_t,
        libc::gid_t,
        libc::gid_t,
    ),
    Error,
> {
    Err(Error::Unsupported)
}

fn process_ids_match(uid: libc::uid_t, gid: libc::gid_t) -> bool {
    let Ok(ids) = unix_ids() else {
        return false;
    };
    ids.0 == uid && ids.1 == uid && ids.2 == uid && ids.3 == gid && ids.4 == gid && ids.5 == gid
}

pub(super) fn current_account() -> Result<CurrentAccount, Error> {
    let (real_uid, effective_uid, saved_uid, real_gid, effective_gid, saved_gid) = unix_ids()?;
    if effective_uid == 0 {
        return Ok(CurrentAccount {
            is_root: true,
            selected: None,
        });
    }
    if real_uid != effective_uid
        || saved_uid != effective_uid
        || real_gid != effective_gid
        || saved_gid != effective_gid
    {
        return Err(Error::NativeIdentityUnavailable);
    }
    let account = lookup_uid(effective_uid)?;
    if account.gid != effective_gid {
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok(CurrentAccount {
        is_root: false,
        selected: Some(SelectedAccount::Unix(account)),
    })
}

pub(super) fn select_unix_account(name: &str) -> Result<SelectedAccount, Error> {
    let account = lookup_name(name)?;
    if account.uid == 0 {
        return Err(Error::RootCannotBeSelected);
    }
    let current = current_account()?;
    if !current.is_root
        && !current.selected.as_ref().is_some_and(
            |selected| matches!(selected, SelectedAccount::Unix(current) if current == &account),
        )
    {
        return Err(Error::DifferentAccountRequiresFreshProcess);
    }
    Ok(SelectedAccount::Unix(account))
}

fn validate_unix_record(account: &UnixAccount) -> Result<UnixAccount, Error> {
    if account.uid == 0 {
        return Err(Error::RootCannotBeSelected);
    }
    let resolved = lookup_uid(account.uid)?;
    if resolved != *account {
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok(resolved)
}

pub(super) fn validate_selection(account: &SelectedAccount) -> Result<(), Error> {
    let SelectedAccount::Unix(account) = account else {
        return Err(Error::Unsupported);
    };
    let resolved = validate_unix_record(account)?;
    let current = current_account()?;
    if current.is_root {
        return Ok(());
    }
    if current.selected.as_ref() == Some(&SelectedAccount::Unix(resolved)) {
        Ok(())
    } else {
        Err(Error::DifferentAccountRequiresFreshProcess)
    }
}

fn executable_is_absolute_regular(executable: &Path) -> bool {
    if !executable.is_absolute()
        || executable
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || executable.canonicalize().ok().as_deref() != Some(executable)
    {
        return false;
    }
    fs::symlink_metadata(executable)
        .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
}

#[cfg(target_os = "linux")]
fn trusted_root_executable(executable: &Path) -> bool {
    if !executable.is_absolute()
        || executable.canonicalize().ok().as_deref() != Some(executable)
        || executable
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return false;
    }
    let components: Vec<_> = executable.components().collect();
    let mut current = Path::new("/").to_path_buf();
    for (index, component) in components.iter().enumerate().skip(1) {
        let Component::Normal(name) = component else {
            return false;
        };
        current.push(name);
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            return false;
        };
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (index + 1 == components.len()
                && (!metadata.is_file() || metadata.mode() & 0o111 == 0))
            || (index + 1 != components.len() && !metadata.is_dir())
        {
            return false;
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn supplementary_groups(account: &UnixAccount) -> Result<Vec<libc::gid_t>, Error> {
    let name = CString::new(account.name.as_bytes()).map_err(|_| Error::InvalidAccount)?;
    let mut capacity = 16usize;
    loop {
        if capacity > MAX_GROUPS {
            return Err(Error::NativeIdentityUnavailable);
        }
        let capacity_i32 = i32::try_from(capacity).map_err(|_| Error::NativeIdentityUnavailable)?;
        let mut groups = vec![0 as libc::gid_t; capacity];
        let mut actual = capacity_i32;
        let result = unsafe {
            libc::getgrouplist(name.as_ptr(), account.gid, groups.as_mut_ptr(), &mut actual)
        };
        if result >= 0 {
            let count = usize::try_from(result).map_err(|_| Error::NativeIdentityUnavailable)?;
            if count > capacity {
                capacity = count;
                continue;
            }
            groups.truncate(count);
            if !groups.contains(&account.gid) {
                groups.push(account.gid);
            }
            groups.sort_unstable();
            groups.dedup();
            return Ok(groups);
        }
        let suggested = usize::try_from(actual).unwrap_or(0);
        capacity = if suggested > capacity {
            suggested
        } else {
            capacity.saturating_mul(2)
        };
    }
}

#[cfg(target_os = "macos")]
fn supplementary_groups(account: &UnixAccount) -> Result<Vec<libc::gid_t>, Error> {
    let name = CString::new(account.name.as_bytes()).map_err(|_| Error::InvalidAccount)?;
    let base_gid =
        libc::c_int::try_from(account.gid).map_err(|_| Error::NativeIdentityUnavailable)?;
    let mut capacity = 16usize;
    loop {
        if capacity > MAX_GROUPS {
            return Err(Error::NativeIdentityUnavailable);
        }
        let mut groups = vec![0 as libc::c_int; capacity];
        let mut actual = i32::try_from(capacity).map_err(|_| Error::NativeIdentityUnavailable)?;
        let result = unsafe {
            libc::getgrouplist(name.as_ptr(), base_gid, groups.as_mut_ptr(), &mut actual)
        };
        if result >= 0 {
            // Darwin reports success as zero and writes the populated count
            // through `actual`. Linux returns the count directly.
            let count = usize::try_from(actual).map_err(|_| Error::NativeIdentityUnavailable)?;
            if count > capacity {
                capacity = count;
                continue;
            }
            let mut groups: Vec<libc::gid_t> = groups[..count]
                .iter()
                .map(|gid| {
                    libc::gid_t::try_from(*gid).map_err(|_| Error::NativeIdentityUnavailable)
                })
                .collect::<Result<_, _>>()?;
            if !groups.contains(&account.gid) {
                groups.push(account.gid);
            }
            // XNU places the effective GID first when setgid() updates the
            // supplementary list. Preserve that primary-GID position, while
            // sorting and deduplicating only the remainder for deterministic
            // membership checks.
            if let Some(primary_index) = groups.iter().position(|gid| *gid == account.gid) {
                groups.swap(0, primary_index);
            }
            groups[1..].sort_unstable();
            if let Ok(index) = groups[1..].binary_search(&account.gid) {
                groups.remove(index + 1);
            }
            groups.dedup();
            return Ok(groups);
        }
        let suggested = usize::try_from(actual).unwrap_or(0);
        capacity = if suggested > capacity {
            suggested
        } else {
            capacity.saturating_mul(2)
        };
    }
}

fn validate_arguments(arguments: &[OsString]) -> Result<(), Error> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(Error::InvalidExecutable);
    }
    let total = arguments.iter().try_fold(0usize, |total, argument| {
        total.checked_add(argument.as_os_str().as_bytes().len())
    });
    if total.map_or(true, |total| total > MAX_ARGUMENT_BYTES)
        || arguments
            .iter()
            .any(|argument| argument.as_os_str().as_bytes().contains(&0))
    {
        return Err(Error::InvalidExecutable);
    }
    Ok(())
}

pub(super) fn reexec_as_selected(
    account: &SelectedAccount,
    executable: &Path,
    arguments: &[OsString],
) -> Result<ExitStatus, Error> {
    let SelectedAccount::Unix(account) = account else {
        return Err(Error::Unsupported);
    };
    let account = validate_unix_record(account)?;
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::AdministratorRequired);
    }
    if !executable_is_absolute_regular(executable) {
        return Err(Error::InvalidExecutable);
    }
    reexec_unix_record_as_selected(&account, executable, arguments)
}

#[cfg(target_os = "linux")]
pub(super) fn reexec_sealed_current_as_selected(
    account: &SelectedAccount,
    arguments: &[OsString],
) -> Result<ExitStatus, Error> {
    let SelectedAccount::Unix(account) = account else {
        return Err(Error::Unsupported);
    };
    let account = validate_unix_record(account)?;
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::AdministratorRequired);
    }
    validate_arguments(arguments)?;
    if arguments.len() + 3 > MAX_ARGUMENTS {
        return Err(Error::InvalidExecutable);
    }
    crate::process::require_child_ownership().map_err(|_| Error::ProcessOwnershipUnavailable)?;

    let image = sealed_current_executable()?;
    let inherited_fd = unsafe { libc::fcntl(image.as_raw_fd(), libc::F_DUPFD, 3) };
    if inherited_fd < 0 {
        return Err(Error::InvalidExecutable);
    }
    let inherited_image = unsafe { File::from_raw_fd(inherited_fd) };
    let executable = Path::new("/proc/self/fd").join(inherited_fd.to_string());
    let mut child_arguments = Vec::with_capacity(arguments.len() + 3);
    child_arguments.push(OsString::from("--internal-linux-selected-install"));
    child_arguments.push(OsString::from(inherited_fd.to_string()));
    child_arguments.push(OsString::from("--"));
    child_arguments.extend(arguments.iter().cloned());
    let result = reexec_unix_record_as_selected(&account, &executable, &child_arguments);
    drop(inherited_image);
    drop(image);
    result
}

#[cfg(target_os = "linux")]
pub(super) fn validate_sealed_selected_executable(fd: i32) -> Result<(), Error> {
    if fd < 3
        || unsafe { libc::geteuid() } == 0
        || unsafe { libc::getuid() } != unsafe { libc::geteuid() }
    {
        return Err(Error::InvalidExecutable);
    }
    let current = current_account()?;
    let selected = current.selected().ok_or(Error::NativeIdentityUnavailable)?;
    validate_selection(selected)?;
    let mut handoff: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut handoff) } != 0 {
        return Err(Error::InvalidExecutable);
    }
    let required_seals =
        libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0
        || seals & required_seals != required_seals
        || handoff.st_uid != 0
        || handoff.st_mode & 0o777 != 0o555
        || handoff.st_nlink != 0
        || handoff.st_size <= 0
        || handoff.st_size as u64 > MAX_HANDOFF_IMAGE_BYTES
    {
        return Err(Error::InvalidExecutable);
    }
    let running = fs::metadata("/proc/self/exe").map_err(|_| Error::InvalidExecutable)?;
    if !running.is_file()
        || running.dev() != handoff.st_dev
        || running.ino() != handoff.st_ino
        || running.uid() != handoff.st_uid
        || running.mode() & 0o777 != handoff.st_mode & 0o777
        || running.len() != handoff.st_size as u64
    {
        return Err(Error::InvalidExecutable);
    }
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } != 0
    {
        return Err(Error::InvalidExecutable);
    }
    Ok(())
}

fn reexec_unix_record_as_selected(
    account: &UnixAccount,
    executable: &Path,
    arguments: &[OsString],
) -> Result<ExitStatus, Error> {
    validate_arguments(arguments)?;
    crate::process::require_child_ownership().map_err(|_| Error::ProcessOwnershipUnavailable)?;
    let groups = supplementary_groups(&account)?;
    if groups.is_empty() {
        return Err(Error::NativeIdentityUnavailable);
    }
    let group_count = i32::try_from(groups.len()).map_err(|_| Error::NativeIdentityUnavailable)?;
    let mut observed_groups = vec![0 as libc::gid_t; groups.len()];
    let child_groups = groups.clone();
    let mut expected_groups = groups.clone();
    expected_groups.sort_unstable();

    let mut command = Command::new(executable);
    command
        .args(arguments)
        .current_dir("/")
        .env_clear()
        .env("HOME", &account.home)
        .env("USER", &account.name)
        .env("LOGNAME", &account.name)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .env("TERM", "xterm-256color");
    let target_uid = account.uid;
    let target_gid = account.gid;
    let child_setup = move || {
        #[cfg(target_os = "linux")]
        let set_groups_result =
            unsafe { libc::setgroups(child_groups.len(), child_groups.as_ptr()) };
        #[cfg(target_os = "macos")]
        let set_groups_result = unsafe { libc::setgroups(group_count, child_groups.as_ptr()) };
        if set_groups_result != 0
            || unsafe { libc::setgid(target_gid) } != 0
            || unsafe { libc::setuid(target_uid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if !process_ids_match(target_uid, target_gid) {
            return Err(io::Error::other("selected uid/gid verification failed"));
        }
        let count = unsafe { libc::getgroups(group_count, observed_groups.as_mut_ptr()) };
        if count != group_count {
            return Err(io::Error::other("supplementary group verification failed"));
        }
        observed_groups.sort_unstable();
        if observed_groups != expected_groups {
            return Err(io::Error::other("supplementary group verification failed"));
        }
        Ok(())
    };
    setup_terminal::run_selected(&mut command, child_setup).map_err(|error| match error {
        setup_terminal::RunError::BeforeSpawn => Error::SpawnFailed,
        setup_terminal::RunError::AfterSpawn => Error::OperationUncertain,
    })
}

#[cfg(target_os = "linux")]
fn sealed_current_executable() -> Result<File, Error> {
    use std::io::{Read, Write};

    let mut source = fs::File::open("/proc/self/exe").map_err(|_| Error::InvalidExecutable)?;
    let before = source.metadata().map_err(|_| Error::InvalidExecutable)?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_HANDOFF_IMAGE_BYTES {
        return Err(Error::InvalidExecutable);
    }
    let name = CString::new("lomi-selected-setup").map_err(|_| Error::InvalidExecutable)?;
    let flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let mut raw = unsafe { libc::memfd_create(name.as_ptr(), flags | MFD_EXEC_FLAG) };
    // MFD_EXEC is a Linux 6.3 ABI addition. Kernels predating it reject the
    // unknown flag; their memfd behavior is executable by default. Newer
    // no-exec policies require the explicit flag, and any non-EINVAL error
    // remains fail-closed.
    if raw < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        raw = unsafe { libc::memfd_create(name.as_ptr(), flags) };
    }
    if raw < 0 {
        return Err(Error::InvalidExecutable);
    }
    let mut image = unsafe { File::from_raw_fd(raw) };
    let mut copied = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| Error::InvalidExecutable)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .filter(|size| *size <= MAX_HANDOFF_IMAGE_BYTES)
            .ok_or(Error::InvalidExecutable)?;
        image
            .write_all(&buffer[..read])
            .map_err(|_| Error::InvalidExecutable)?;
    }
    let after = source.metadata().map_err(|_| Error::InvalidExecutable)?;
    if copied != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(Error::InvalidExecutable);
    }
    image.sync_all().map_err(|_| Error::InvalidExecutable)?;
    image
        .set_permissions(fs::Permissions::from_mode(0o555))
        .map_err(|_| Error::InvalidExecutable)?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(image.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(Error::InvalidExecutable);
    }
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(image.as_raw_fd(), &mut metadata) } != 0
        || metadata.st_uid != 0
        || metadata.st_mode & 0o777 != 0o555
        || metadata.st_size as u64 != copied
    {
        return Err(Error::InvalidExecutable);
    }
    Ok(image)
}

#[cfg(target_os = "linux")]
pub(super) fn create_dedicated_account(
    name: &str,
    _consent: AccountCreationConsent,
) -> Result<SelectedAccount, Error> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::AdministratorRequired);
    }
    if !account_name_is_valid(name) || name.len() > 32 {
        return Err(Error::InvalidAccount);
    }
    match lookup_name(name) {
        Ok(_) => return Err(Error::InvalidAccount),
        Err(Error::AccountNotFound) => {}
        Err(error) => return Err(error),
    }
    if group_name_exists(name)? {
        return Err(Error::InvalidAccount);
    }
    crate::process::require_child_ownership().map_err(|_| Error::ProcessOwnershipUnavailable)?;
    let useradd = Path::new("/usr/sbin/useradd");
    let nologin = Path::new("/usr/sbin/nologin");
    if !trusted_root_executable(useradd) || !trusted_root_executable(nologin) {
        return Err(Error::AccountCreationFailed);
    }
    let mut command = Command::new(useradd);
    command
        .args([
            "--system",
            "--create-home",
            "--user-group",
            "--shell",
            nologin.to_str().ok_or(Error::AccountCreationFailed)?,
            "--",
            name,
        ])
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = bounded_status(&mut command, Duration::from_secs(30))?;
    if !status.success() {
        return Err(Error::AccountCreationFailed);
    }
    let account = lookup_name(name)?;
    if account.uid == 0
        || account.gid == 0
        || !private_primary_group_matches(name, account.gid)?
        || account.home == Path::new("/root")
        || account.home.starts_with("/root/")
        || account.home.canonicalize().ok().as_deref() != Some(account.home.as_path())
    {
        return Err(Error::NativeIdentityUnavailable);
    }
    let metadata =
        fs::symlink_metadata(&account.home).map_err(|_| Error::NativeIdentityUnavailable)?;
    if !metadata.is_dir() || metadata.uid() != account.uid || metadata.mode() & 0o022 != 0 {
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok(SelectedAccount::Unix(account))
}

#[cfg(target_os = "linux")]
fn bounded_status(command: &mut Command, timeout: Duration) -> Result<ExitStatus, Error> {
    let mut child = command.spawn().map_err(|_| Error::AccountCreationFailed)?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                crate::process::require_unreaped_child(&child)
                    .map_err(|_| Error::OperationUncertain)?;
                child.kill().map_err(|_| Error::OperationUncertain)?;
                let reap_deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => return Err(Error::OperationUncertain),
                        Ok(None) if Instant::now() < reap_deadline => {
                            thread::sleep(Duration::from_millis(25));
                        }
                        _ => return Err(Error::OperationUncertain),
                    }
                }
            }
            Err(_) => return Err(Error::OperationUncertain),
        }
    }
}
