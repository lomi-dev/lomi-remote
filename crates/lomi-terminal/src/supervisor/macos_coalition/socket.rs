//! The sticky temporary parent is the sole exception to immutable ancestry.
//! Every generation creates a new private directory and never adopts a name.
use super::*;
use std::ffi::CString;

fn component(record: &Record) -> String {
    format!("lomi-pty-{}-{}", unsafe { libc::geteuid() }, record.run)
}
fn parent() -> Result<Directory> {
    let private = Directory::ancestry(Path::new("/private"))?;
    let fd = unsafe {
        libc::openat(
            private.file.as_raw_fd(),
            c"tmp".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o1777
        || unsafe { lomi_coalition_safe_acl(fd) } != 0
    {
        return Err(Error::InvalidArgument);
    }
    Ok(Directory {
        path: PathBuf::from("/private/tmp"),
        file,
    })
}
fn child(parent: &Directory, record: &Record) -> Result<Option<Directory>> {
    let name = CString::new(component(record)).map_err(|_| Error::CleanupFailed)?;
    let fd = unsafe {
        libc::openat(
            parent.file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
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
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
        || unsafe { lomi_coalition_safe_acl(fd) } != 0
    {
        return Err(Error::CleanupFailed);
    }
    Ok(Some(Directory {
        path: parent.path.join(component(record)),
        file,
    }))
}
pub(super) fn pin(directory: &Directory) -> Result<[u64; 2]> {
    let metadata = directory
        .file
        .metadata()
        .map_err(|_| Error::CleanupFailed)?;
    Ok([metadata.dev(), metadata.ino()])
}
pub(super) fn create(record: &Record) -> Result<Directory> {
    let parent = parent()?;
    let name = CString::new(component(record)).map_err(|_| Error::CleanupFailed)?;
    // Prepared intent has already been committed; even an owned collision is
    // unknown. Never adopt/retry another name for this generation.
    if unsafe { libc::mkdirat(parent.file.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(Error::CleanupFailed);
    }
    parent.sync()?;
    child(&parent, record)?.ok_or(Error::CleanupFailed)
}
pub(super) fn open(record: &Record) -> Result<Directory> {
    let parent = parent()?;
    let directory = child(&parent, record)?.ok_or(Error::CleanupFailed)?;
    if Some(pin(&directory)?) != record.runtime_pin {
        return Err(Error::CleanupFailed);
    }
    Ok(directory)
}
pub(super) fn socket_pin(directory: &Directory) -> Result<[u64; 2]> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.file.as_raw_fd(),
            c"s".as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(Error::CleanupFailed);
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_uid != unsafe { libc::geteuid() }
        || metadata.st_nlink != 1
    {
        return Err(Error::CleanupFailed);
    }
    Ok([metadata.st_dev as u64, metadata.st_ino])
}
pub(super) fn validate(directory: &Directory, record: &Record) -> Result<()> {
    let reopened = open(record)?;
    if pin(directory)? != pin(&reopened)? || Some(socket_pin(directory)?) != record.socket_pin {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}
pub(super) fn cleanup(directory: &Directory, record: &Record) -> Result<()> {
    let parent = parent()?;
    let actual = child(&parent, record)?;
    if record.runtime_removed {
        if actual.is_some() {
            return Err(Error::CleanupFailed);
        }
        return parent.sync();
    }
    let Some(runtime) = actual else {
        if record.runtime_pin.is_some() && !record.runtime_removal_started {
            return Err(Error::CleanupFailed);
        }
        parent.sync()?;
        update(directory, &record.nonce, |current| {
            current.runtime_removed = true;
            Ok(())
        })?;
        return Ok(());
    };
    if Some(pin(&runtime)?) != record.runtime_pin {
        return Err(Error::CleanupFailed);
    }
    let names = runtime.names()?;
    if names.iter().any(|name| name != "s") {
        return Err(Error::CleanupFailed);
    }
    if names.iter().any(|name| name == "s") {
        if Some(socket_pin(&runtime)?) != record.socket_pin {
            return Err(Error::CleanupFailed);
        }
    } else if record.socket_pin.is_some() && !record.runtime_removal_started {
        return Err(Error::CleanupFailed);
    }
    // Durable intent permits an absent entry only after exact owned inode checks.
    update(directory, &record.nonce, |current| {
        current.runtime_removal_started = true;
        Ok(())
    })?;
    if names.iter().any(|name| name == "s")
        && unsafe { libc::unlinkat(runtime.file.as_raw_fd(), c"s".as_ptr(), 0) } != 0
    {
        return Err(Error::CleanupFailed);
    }
    runtime.sync()?;
    // Recheck the held inode against the public name before removing the name.
    let still = child(&parent, record)?.ok_or(Error::CleanupFailed)?;
    if pin(&still)? != pin(&runtime)? {
        return Err(Error::CleanupFailed);
    }
    let name = CString::new(component(record)).map_err(|_| Error::CleanupFailed)?;
    if unsafe { libc::unlinkat(parent.file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(Error::CleanupFailed);
    }
    parent.sync()?;
    update(directory, &record.nonce, |current| {
        current.runtime_removed = true;
        Ok(())
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Directory, Record, PathBuf) {
        let root = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap()
            .join(format!(".lomi-socket-test-{}", uuid::Uuid::new_v4()));
        let profile = Directory::open(&root, true).unwrap();
        let generations = profile.child("pty-generations").unwrap();
        let run = uuid::Uuid::new_v4().to_string();
        let generation = generations.child(&run).unwrap();
        let record = Record {
            schema: 2,
            run,
            nonce: uuid::Uuid::new_v4().to_string(),
            stage: Stage::Prepared,
            executable: PathBuf::from("/usr/bin/true"),
            executable_pin: [0; 5],
            host: Identity {
                pid: 1,
                audit: [0; 8],
                resource: 1,
                jetsam: 2,
            },
            controller: None,
            custodian: None,
            lifetime: None,
            controller_lifetime: None,
            controller_reaped: false,
            disposed: false,
            leader_reaped: false,
            drained: false,
            admission_consumed: false,
            profile_pin: pin(&profile).unwrap(),
            generation_pin: pin(&generation).unwrap(),
            runtime_pin: None,
            socket_pin: None,
            runtime_removal_started: false,
            runtime_removed: false,
            host_step: "Prepared".into(),
            worker_step: "Unconnected".into(),
        };
        generation
            .write("journal.json", &record.bytes().unwrap(), None)
            .unwrap();
        (generation, record, root)
    }
    fn dispose(generation: Directory, root: PathBuf) {
        generation
            .remove(
                "journal.json",
                &generation.read("journal.json").unwrap().unwrap(),
            )
            .unwrap();
        generation.remove("journal.lock", b"").unwrap();
        std::fs::remove_dir(&generation.path).unwrap();
        std::fs::remove_dir(root.join("pty-generations")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn namespace_collision_symlink_and_inode_replacement_are_never_adopted() {
        let (generation, mut record, root) = fixture();
        let runtime = create(&record).unwrap();
        record.runtime_pin = Some(pin(&runtime).unwrap());
        update(&generation, &record.nonce, |current| {
            current.runtime_pin = record.runtime_pin;
            Ok(())
        })
        .unwrap();
        assert!(create(&record).is_err());
        let parked = runtime.path.with_extension("owned-held");
        std::fs::rename(&runtime.path, &parked).unwrap();
        std::os::unix::fs::symlink(&parked, &runtime.path).unwrap();
        assert!(open(&record).is_err());
        std::fs::remove_file(&runtime.path).unwrap();
        std::fs::create_dir(&runtime.path).unwrap();
        std::fs::set_permissions(&runtime.path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open(&record).is_err());
        assert!(cleanup(&generation, &record).is_err());
        std::fs::remove_dir(&runtime.path).unwrap();
        std::fs::rename(parked, &runtime.path).unwrap();
        cleanup(&generation, &record).unwrap();
        assert!(Record::read(&generation).unwrap().runtime_removed);
        dispose(generation, root);
    }
    #[test]
    fn missing_namespace_requires_durable_removal_intent_and_retries_idempotently() {
        let (generation, mut record, root) = fixture();
        let runtime = create(&record).unwrap();
        record.runtime_pin = Some(pin(&runtime).unwrap());
        update(&generation, &record.nonce, |current| {
            current.runtime_pin = record.runtime_pin;
            Ok(())
        })
        .unwrap();
        // Model an unlink effect before its final directory-sync/checkpoint.
        std::fs::remove_dir(&runtime.path).unwrap();
        assert!(cleanup(&generation, &record).is_err());
        record = update(&generation, &record.nonce, |current| {
            current.runtime_removal_started = true;
            Ok(())
        })
        .unwrap();
        cleanup(&generation, &record).unwrap();
        cleanup(&generation, &Record::read(&generation).unwrap()).unwrap();
        dispose(generation, root);
    }
    #[test]
    fn namespace_permissions_and_acl_grants_are_rejected() {
        let (generation, mut record, root) = fixture();
        let runtime = create(&record).unwrap();
        record.runtime_pin = Some(pin(&runtime).unwrap());
        update(&generation, &record.nonce, |current| {
            current.runtime_pin = record.runtime_pin;
            Ok(())
        })
        .unwrap();
        std::fs::set_permissions(&runtime.path, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(open(&record).is_err());
        std::fs::set_permissions(&runtime.path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let account = unsafe { libc::getpwuid(libc::geteuid()) };
        assert!(!account.is_null());
        let username = unsafe { std::ffi::CStr::from_ptr((*account).pw_name) }
            .to_str()
            .unwrap();
        let grant = format!("user:{username} allow read,write,execute");
        assert!(
            Command::new("/bin/chmod")
                .arg("+a")
                .arg(grant)
                .arg(&runtime.path)
                .status()
                .unwrap()
                .success()
        );
        assert!(open(&record).is_err());
        assert!(
            Command::new("/bin/chmod")
                .arg("-N")
                .arg(&runtime.path)
                .status()
                .unwrap()
                .success()
        );
        cleanup(&generation, &record).unwrap();
        dispose(generation, root);
    }

    #[test]
    fn socket_inode_replacement_is_not_unlinked() {
        let (generation, mut record, root) = fixture();
        let runtime = create(&record).unwrap();
        record.runtime_pin = Some(pin(&runtime).unwrap());
        let listener = UnixListener::bind(runtime.path.join("s")).unwrap();
        std::fs::set_permissions(
            runtime.path.join("s"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        record.socket_pin = Some(socket_pin(&runtime).unwrap());
        update(&generation, &record.nonce, |current| {
            current.runtime_pin = record.runtime_pin;
            current.socket_pin = record.socket_pin;
            Ok(())
        })
        .unwrap();
        std::fs::rename(runtime.path.join("s"), runtime.path.join("held")).unwrap();
        let replacement = UnixListener::bind(runtime.path.join("s")).unwrap();
        std::fs::set_permissions(
            runtime.path.join("s"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(validate(&runtime, &record).is_err());
        assert!(cleanup(&generation, &record).is_err());
        drop(replacement);
        std::fs::remove_file(runtime.path.join("s")).unwrap();
        std::fs::rename(runtime.path.join("held"), runtime.path.join("s")).unwrap();
        drop(listener);
        cleanup(&generation, &record).unwrap();
        dispose(generation, root);
    }
}
