//! Bounded cleanup of proven retired generations. A single durable parent intent
//! carries deletion authority across partial unlink/rmdir failures; no old UUID
//! can be admitted again, with or without its former journal.
use super::*;
const INTENT: &str = "gc-intent.json";
const RETAIN: usize = 64;
const BATCH: usize = 32;
pub(super) fn eligible(record: &Record) -> bool {
    let drained = record.disposed
        && record.leader_reaped
        && record.drained
        && record.controller.is_some()
        && record.lifetime.is_some()
        && (record.schema == 1
            || (record.custodian.is_some()
                && record.controller_lifetime.is_some()
                && record.controller_reaped))
        && record.runtime_pin.is_some()
        && record.socket_pin.is_some()
        && record.runtime_removal_started;
    let never_bootstrapped = !record.disposed
        && !record.leader_reaped
        && !record.drained
        && record.controller.is_none()
        && record.custodian.is_none()
        && record.lifetime.is_none()
        && !record.admission_consumed
        && record.host_step == "Prepared"
        && record.worker_step == "Unconnected";
    let unconsumed = !record.admission_consumed
        && !record.disposed
        && !record.leader_reaped
        && !record.drained
        && record.lifetime.is_some()
        && record.host_step == "UnconsumedRemovalIntent";
    record.stage == Stage::Cleaned
        && record.runtime_removed
        && (drained || never_bootstrapped || unconsumed)
}
fn file_pin(file: &File) -> Result<[u64; 2]> {
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    Ok([metadata.dev(), metadata.ino()])
}
fn held(file: &File) -> Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(Error::CleanupFailed)
    }
}
fn uuid_name(name: &str) -> Result<()> {
    if uuid::Uuid::parse_str(name)
        .map(|id| id.to_string())
        .ok()
        .as_deref()
        != Some(name)
    {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}
fn resume(
    profile: &Directory,
    absent: &mut impl FnMut(&Directory, &Record) -> Result<bool>,
) -> Result<()> {
    let Some(bytes) = profile.read(INTENT)? else {
        return Ok(());
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| Error::CleanupFailed)?;
    if value["schema"] != 1 {
        return Err(Error::CleanupFailed);
    }
    let run = value["run"].as_str().ok_or(Error::CleanupFailed)?;
    uuid_name(run)?;
    let generation_pin: [u64; 2] =
        serde_json::from_value(value["generationPin"].clone()).map_err(|_| Error::CleanupFailed)?;
    if value["record"]["run"].as_str() != Some(run)
        || value["record"]["generationPin"] != value["generationPin"]
        || value["record"]["stage"] != "Cleaned"
        || value["record"]["runtimeRemoved"] != true
        || value["record"]["uid"].as_u64() != Some(unsafe { libc::geteuid() } as u64)
        || !value["files"].is_array()
    {
        return Err(Error::CleanupFailed);
    }
    let record_bytes = serde_json::to_vec(&value["record"]).map_err(|_| Error::CleanupFailed)?;
    let record = Record::decode_retired(profile, run, &record_bytes, generation_pin)?;
    if !eligible(&record) {
        return Err(Error::CleanupFailed);
    }
    let entries = value["files"].as_array().ok_or(Error::CleanupFailed)?;
    let expected_count = 3
        + usize::from(record.lifetime.is_some())
        + usize::from(record.controller_lifetime.is_some());
    if entries.len() != expected_count {
        return Err(Error::CleanupFailed);
    }
    let mut expected = std::collections::BTreeMap::new();
    for entry in entries {
        let name = entry["name"].as_str().ok_or(Error::CleanupFailed)?;
        if !matches!(
            name,
            "journal.json" | "journal.lock" | "owner.lock" | "controller.lock" | "protocol.lock"
        ) {
            return Err(Error::CleanupFailed);
        }
        let pin: [u64; 2] =
            serde_json::from_value(entry["pin"].clone()).map_err(|_| Error::CleanupFailed)?;
        let data: Vec<u8> =
            serde_json::from_value(entry["bytes"].clone()).map_err(|_| Error::CleanupFailed)?;
        if expected.insert(name, (pin, data)).is_some() {
            return Err(Error::CleanupFailed);
        }
    }
    if !expected.contains_key("journal.json")
        || !expected.contains_key("journal.lock")
        || !expected.contains_key("owner.lock")
        || expected.contains_key("controller.lock") != record.lifetime.is_some()
        || record
            .lifetime
            .is_some_and(|pin| expected.get("controller.lock").map(|entry| entry.0) != Some(pin))
    {
        return Err(Error::CleanupFailed);
    }
    if expected.contains_key("protocol.lock") != record.controller_lifetime.is_some()
        || record
            .controller_lifetime
            .is_some_and(|pin| expected.get("protocol.lock").map(|entry| entry.0) != Some(pin))
    {
        return Err(Error::CleanupFailed);
    }
    if expected.get("journal.json").map(|entry| entry.1.as_slice())
        != Some(record.bytes()?.as_slice())
        || expected
            .iter()
            .any(|(name, (_, bytes))| *name != "journal.json" && !bytes.is_empty())
    {
        return Err(Error::CleanupFailed);
    }
    let path = profile.path.join(run);
    if let Err(error) = std::fs::symlink_metadata(&path) {
        if error.kind() != io::ErrorKind::NotFound {
            return Err(Error::CleanupFailed);
        }
        profile.sync()?;
        return profile.remove(INTENT, &bytes);
    }
    let directory = Directory::open(&path, false)?;
    if socket::pin(&directory)? != generation_pin || !absent(&directory, &record)? {
        return Err(Error::CleanupFailed);
    }
    Record::decode(&directory, &record_bytes)?;
    socket::cleanup(&directory, &record)?;
    let mut locks = Vec::new();
    // Validate every remaining entry before deleting any, including retry state.
    directory.visit_names(|name| {
        let (pin, data) = expected.get(name).ok_or(Error::CleanupFailed)?;
        let file = directory.file(name, false)?.ok_or(Error::CleanupFailed)?;
        if file_pin(&file)? != *pin || directory.read(name)?.as_ref() != Some(data) {
            return Err(Error::CleanupFailed);
        }
        if name == "owner.lock" || name == "controller.lock" || name == "protocol.lock" {
            held(&file)?;
            locks.push(file);
        }
        Ok(())
    })?;
    for (name, (_, data)) in expected {
        directory.remove(name, &data)?;
    }
    // Check the public directory name still names our pinned generation.
    let current = Directory::open(&path, false)?;
    if socket::pin(&current)? != generation_pin {
        return Err(Error::CleanupFailed);
    }
    let name = std::ffi::CString::new(run).map_err(|_| Error::CleanupFailed)?;
    if unsafe { libc::unlinkat(profile.file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(Error::CleanupFailed);
    }
    profile.sync()?;
    profile.remove(INTENT, &bytes)
}
fn prepare(
    profile: &Directory,
    name: &str,
    absent: &mut impl FnMut(&Directory, &Record) -> Result<bool>,
) -> Result<()> {
    let directory = Directory::open(&profile.path.join(name), false)?;
    let owner = directory
        .file("owner.lock", false)?
        .ok_or(Error::CleanupFailed)?;
    if held(&owner).is_err() {
        return Ok(());
    } // A live owner is never collected.
    let record = Record::read(&directory)?;
    if !eligible(&record) {
        return Ok(());
    }
    let lifetime = record
        .lifetime
        .map(|pin| lifetime(&directory, pin))
        .transpose()?;
    let controller_lifetime = record
        .controller_lifetime
        .map(|pin| controller_lifetime(&directory, pin))
        .transpose()?;
    if lifetime.as_ref().is_some_and(|file| held(file).is_err())
        || controller_lifetime
            .as_ref()
            .is_some_and(|file| held(file).is_err())
    {
        return Ok(());
    }
    if !absent(&directory, &record)? {
        return Err(Error::CleanupFailed);
    }
    socket::cleanup(&directory, &record)?;
    let mut files = Vec::new();
    directory.visit_names(|name| {
        if !matches!(name, "journal.json" | "journal.lock" | "owner.lock" | "controller.lock" | "protocol.lock") {
            return Err(Error::CleanupFailed);
        }
        let file = directory.file(name, false)?.ok_or(Error::CleanupFailed)?;
        files.push(json!({"name":name,"pin":file_pin(&file)?,"bytes":directory.read(name)?.ok_or(Error::CleanupFailed)?}));
        Ok(())
    })?;
    if files.len()
        != 3 + usize::from(record.lifetime.is_some())
            + usize::from(record.controller_lifetime.is_some())
    {
        return Err(Error::CleanupFailed);
    }
    let names: std::collections::BTreeSet<_> = files
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .collect();
    let mut wanted: std::collections::BTreeSet<_> = ["journal.json", "journal.lock", "owner.lock"]
        .into_iter()
        .collect();
    if record.lifetime.is_some() {
        wanted.insert("controller.lock");
    }
    if record.controller_lifetime.is_some() {
        wanted.insert("protocol.lock");
    }
    if names != wanted
        || files
            .iter()
            .any(|entry| entry["name"] != "journal.json" && entry["bytes"] != json!([]))
    {
        return Err(Error::CleanupFailed);
    }
    let bytes = serde_json::to_vec(&json!({"schema":1,"run":record.run,"generationPin":record.generation_pin,
        "record":serde_json::from_slice::<Value>(&record.bytes()?).map_err(|_|Error::CleanupFailed)?,"files":files}))
        .map_err(|_| Error::CleanupFailed)?;
    profile.write(INTENT, &bytes, None)?;
    drop(controller_lifetime);
    drop(lifetime);
    drop(owner); // Resume acquires the exact original lock FDs again.
    resume(profile, absent)
}
pub(super) fn collect(
    profile: &Directory,
    absent: &mut impl FnMut(&Directory, &Record) -> Result<bool>,
) -> Result<()> {
    resume(profile, absent)?;
    let mut retained = 0usize;
    let mut candidates = Vec::new();
    // Gather without mutation; then delete a bounded batch. Admission performs
    // its own fresh traversal afterwards, so GC cannot skip an unknown owner.
    profile.visit_names(|name| {
        uuid_name(name)?;
        let directory = Directory::open(&profile.path.join(name), false)?;
        if eligible(&Record::read(&directory)?) {
            if retained < RETAIN {
                retained += 1;
            } else if candidates.len() < BATCH {
                candidates.push(name.to_owned());
            }
        }
        Ok(())
    })?;
    for name in candidates {
        prepare(profile, &name, absent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Directory, Directory, PathBuf) {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(format!(".lomi-gc-test-{}", uuid::Uuid::new_v4()));
        let profile = Directory::open(&root, true).unwrap();
        let generations = profile.child("pty-generations").unwrap();
        (profile, generations, root)
    }
    fn record(profile: &Directory, generations: &Directory, stage: Stage) -> (Directory, Record) {
        let run = uuid::Uuid::new_v4().to_string();
        let directory = generations.child(&run).unwrap();
        for name in ["owner.lock", "journal.lock", "controller.lock"] {
            directory
                .file(name, true)
                .unwrap()
                .unwrap()
                .sync_all()
                .unwrap();
        }
        let controller = Identity {
            pid: 1,
            audit: [0; 8],
            resource: 1,
            jetsam: 2,
        };
        let record = Record {
            schema: 1,
            run,
            nonce: uuid::Uuid::new_v4().to_string(),
            stage,
            executable: PathBuf::from("/usr/bin/true"),
            executable_pin: [0; 5],
            host: controller,
            controller: Some(controller),
            custodian: None,
            lifetime: Some(
                file_pin(&directory.file("controller.lock", false).unwrap().unwrap()).unwrap(),
            ),
            controller_lifetime: None,
            controller_reaped: false,
            disposed: true,
            leader_reaped: true,
            drained: true,
            admission_consumed: true,
            profile_pin: socket::pin(profile).unwrap(),
            generation_pin: socket::pin(&directory).unwrap(),
            runtime_pin: Some([1, 1]),
            socket_pin: Some([1, 2]),
            runtime_removal_started: true,
            runtime_removed: true,
            host_step: "AdmissionConsumed".into(),
            worker_step: "Acquired".into(),
        };
        directory
            .write("journal.json", &record.bytes().unwrap(), None)
            .unwrap();
        (directory, record)
    }
    fn dispose(generations: Directory, root: PathBuf) {
        let mut names = Vec::new();
        generations
            .visit_names(|name| {
                names.push(name.to_owned());
                Ok(())
            })
            .unwrap();
        for name in names {
            uuid_name(&name).unwrap();
            let directory = Directory::open(&generations.path.join(name), false).unwrap();
            for name in directory.names().unwrap() {
                assert!(matches!(
                    name.as_str(),
                    "journal.json" | "journal.lock" | "owner.lock" | "controller.lock"
                ));
                directory
                    .remove(&name, &directory.read(&name).unwrap().unwrap())
                    .unwrap();
            }
            std::fs::remove_dir(&directory.path).unwrap();
        }
        std::fs::remove_dir(&generations.path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn more_than_4096_cleaned_generations_do_not_block_admission_or_hide_32_unknown_owners() {
        let (profile, generations, root) = fixture();
        for _ in 0..4097 {
            record(&profile, &generations, Stage::Cleaned);
        }
        let mut queries = 0;
        let mut absent = |_: &Directory, _: &Record| {
            queries += 1;
            Ok(true)
        };
        assert_eq!(recover_profile_with(&generations, &mut absent).unwrap(), 0);
        assert!(queries <= BATCH * 2); // Fixed command budget even with old history.
        let mut first = 0;
        generations
            .visit_names(|_| {
                first += 1;
                Ok(())
            })
            .unwrap();
        let mut second = 0;
        generations
            .visit_names(|_| {
                second += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(first, 4097 - BATCH);
        assert_eq!(first, second); // Repeated scans use independent offsets.
        let mut owners = Vec::new();
        let mut unknown_paths = Vec::new();
        for _ in 0..MAX_SESSIONS {
            let (directory, _) = record(&profile, &generations, Stage::AdmissionConsumed);
            owners.push(directory.lock("owner.lock", Duration::ZERO).unwrap());
            unknown_paths.push(directory.path.clone());
        }
        assert_eq!(
            recover_profile_with(&generations, &mut |_, _| Ok(true)).unwrap(),
            MAX_SESSIONS
        );
        assert!(
            unknown_paths
                .iter()
                .all(|path| path.join("journal.json").exists())
        );
        drop(owners);
        dispose(generations, root);
    }
    #[test]
    fn partial_gc_retry_keeps_unknown_entries_and_never_reactivates_a_removed_generation() {
        let (profile, generations, root) = fixture();
        let (directory, record) = record(&profile, &generations, Stage::Cleaned);
        let mut files = Vec::new();
        for name in directory.names().unwrap() {
            let file = directory.file(&name, false).unwrap().unwrap();
            files.push(json!({"name":name,"pin":file_pin(&file).unwrap(),"bytes":directory.read(&name).unwrap().unwrap()}));
        }
        let bytes = serde_json::to_vec(&json!({"schema":1,"run":record.run,"generationPin":record.generation_pin,
            "record":serde_json::from_slice::<Value>(&record.bytes().unwrap()).unwrap(),"files":files})).unwrap();
        generations.write(INTENT, &bytes, None).unwrap();
        // A real partial unlink after durable intent: retry must not need the
        // original journal, and cannot silently delete an unexpected file.
        directory
            .remove("journal.json", &record.bytes().unwrap())
            .unwrap();
        directory.write("foreign", b"preserve", None).unwrap();
        assert!(resume(&generations, &mut |_, _| Ok(true)).is_err());
        assert_eq!(directory.read("foreign").unwrap().unwrap(), b"preserve");
        directory.remove("foreign", b"preserve").unwrap();
        resume(&generations, &mut |_, _| Ok(true)).unwrap();
        resume(&generations, &mut |_, _| Ok(true)).unwrap();
        assert!(!directory.path.exists());
        assert!(Directory::open(&directory.path, false).is_err());
        assert!(Record::read(&directory).is_err()); // No unconsumed journal can authorize G.
        assert!(!directory.path.exists());
        dispose(generations, root);
    }
    #[test]
    fn never_bootstrapped_gc_refuses_substituted_lock_names_and_nonempty_locks() {
        let (profile, generations, root) = fixture();
        let (directory, mut record) = record(&profile, &generations, Stage::Cleaned);
        let old = record.bytes().unwrap();
        record.controller = None;
        record.lifetime = None;
        record.disposed = false;
        record.leader_reaped = false;
        record.drained = false;
        record.admission_consumed = false;
        record.host_step = "Prepared".into();
        record.worker_step = "Unconnected".into();
        directory
            .write("journal.json", &record.bytes().unwrap(), Some(&old))
            .unwrap();
        directory.remove("controller.lock", b"").unwrap();
        std::fs::rename(
            directory.path.join("journal.lock"),
            directory.path.join("controller.lock"),
        )
        .unwrap();
        assert!(prepare(&generations, &record.run, &mut |_, _| Ok(true)).is_err());
        assert!(generations.read(INTENT).unwrap().is_none());
        assert!(directory.path.join("controller.lock").exists());
        std::fs::rename(
            directory.path.join("controller.lock"),
            directory.path.join("journal.lock"),
        )
        .unwrap();
        directory
            .write("journal.lock", b"foreign", Some(b""))
            .unwrap();
        assert!(prepare(&generations, &record.run, &mut |_, _| Ok(true)).is_err());
        assert_eq!(directory.read("journal.lock").unwrap().unwrap(), b"foreign");
        directory
            .write("journal.lock", b"", Some(b"foreign"))
            .unwrap();
        prepare(&generations, &record.run, &mut |_, _| Ok(true)).unwrap();
        assert!(!directory.path.exists());
        dispose(generations, root);
    }
    #[test]
    fn malformed_gc_authority_is_preserved_even_when_its_directory_is_absent() {
        let (_profile, generations, root) = fixture();
        let run = uuid::Uuid::new_v4().to_string();
        let bytes = serde_json::to_vec(&json!({"schema":1,"run":run,"generationPin":[1,2],
            "record":{"run":run,"generationPin":[1,2],"stage":"Cleaned","runtimeRemoved":true,
            "uid":unsafe{libc::geteuid()}},"files":[]}))
        .unwrap();
        generations.write(INTENT, &bytes, None).unwrap();
        assert!(resume(&generations, &mut |_, _| Ok(true)).is_err());
        assert_eq!(generations.read(INTENT).unwrap().unwrap(), bytes);
        generations.remove(INTENT, &bytes).unwrap();
        dispose(generations, root);
    }
}
