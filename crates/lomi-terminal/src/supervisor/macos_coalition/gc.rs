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
