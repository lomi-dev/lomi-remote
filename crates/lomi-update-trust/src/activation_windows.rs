//! Windows activation uses a stable, ACL-protected `lomiremote.exe` file and
//! private pointer/journal files. It avoids symlinks and junctions entirely.

use crate::{
    MAX_TARGET, Result, invalid,
    windows_storage::{
        create_private_dir, create_private_file, ensure_private_file, lock_file, open_private_file,
        private_dir, private_file, read_bounded, sync_dir,
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};

const ACTIVE: &str = "active.ptr";
const PREVIOUS: &str = "previous.ptr";
const ACTIVE_COMPANION: &str = "active-helper.ptr";
const PREVIOUS_COMPANION: &str = "previous-helper.ptr";
const JOURNAL: &str = "activation.pending";
const EXE: &str = "lomiremote.exe";
const HELPER_EXE: &str = "lomiremote-host.exe";
const LOCK: &str = ".activation.lock";

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn move_replace(source: &Path, destination: &Path) -> Result<()> {
    if unsafe {
        MoveFileExW(
            wide(source).as_ptr(),
            wide(destination).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn move_new(source: &Path, destination: &Path) -> Result<()> {
    if unsafe {
        MoveFileExW(
            wide(source).as_ptr(),
            wide(destination).as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

pub(crate) fn validate_directory(path: &Path) -> Result<()> {
    private_dir(path)
}

fn lock(root: &Path) -> Result<fs::File> {
    let path = root.join(LOCK);
    ensure_private_file(&path)?;
    let file = open_private_file(&path, true)?;
    lock_file(&file)?;
    Ok(file)
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn target_path(value: &str) -> Result<PathBuf> {
    let digest = value
        .strip_prefix("objects/sha256/")
        .and_then(|value| value.strip_suffix(".exe"))
        .ok_or_else(|| invalid("Windows activation pointer is malformed"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("Windows activation pointer has an invalid digest"));
    }
    Ok(PathBuf::from("objects")
        .join("sha256")
        .join(format!("{digest}.exe")))
}

fn target_digest(value: &str) -> Result<String> {
    target_path(value)?;
    value
        .rsplit('/')
        .next()
        .and_then(|value| value.strip_suffix(".exe"))
        .map(str::to_owned)
        .ok_or_else(|| invalid("Windows activation object has no digest"))
}

fn verify_object(root: &Path, value: &str) -> Result<PathBuf> {
    let relative = target_path(value)?;
    private_dir(&root.join("objects"))?;
    private_dir(&root.join("objects/sha256"))?;
    let path = root.join(&relative);
    private_file(&path)?;
    let bytes = read_bounded(&path, MAX_TARGET)?;
    if digest(&bytes)
        != value
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .trim_end_matches(".exe")
    {
        return Err(invalid("Windows content object hash mismatch"));
    }
    Ok(path)
}

fn stable_executable_digest(root: &Path, name: &str) -> Result<Option<String>> {
    let path = root.join(name);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => {
            private_file(&path)?;
            let bytes = read_bounded(&path, MAX_TARGET)?;
            Ok(Some(digest(&bytes)))
        }
    }
}

fn stable_matches(
    root: &Path,
    executable: &str,
    pointer: &str,
    target: Option<&str>,
) -> Result<()> {
    let existing = stable_executable_digest(root, executable)?;
    match (target, existing.as_deref()) {
        (Some(target), Some(existing)) if target_digest(target)? == existing => Ok(()),
        (Some(target), None) => replace_executable(root, executable, pointer, Some(target), &[]),
        (None, None) => Ok(()),
        (Some(_), Some(_)) => Err(invalid(
            "Windows stable executable does not match the active pointer",
        )),
        (None, Some(_)) => Err(invalid(
            "Windows stable executable exists without an active pointer",
        )),
    }
}

fn read_pointer(root: &Path, name: &str) -> Result<Option<String>> {
    let path = root.join(name);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => {
            private_file(&path)?;
            let bytes = read_bounded(&path, 256)?;
            let value = std::str::from_utf8(&bytes)
                .map_err(|_| invalid("Windows activation pointer is not UTF-8"))?
                .strip_suffix('\n')
                .ok_or_else(|| invalid("Windows activation pointer is unterminated"))?
                .to_owned();
            verify_object(root, &value)?;
            Ok(Some(value))
        }
    }
}

fn remove_regular(root: &Path, name: &str) -> Result<()> {
    let path = root.join(name);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => {
            private_file(&path)?;
            fs::remove_file(path)?;
            sync_dir(root)?;
            Ok(())
        }
    }
}

fn replace_pointer(root: &Path, name: &str, target: Option<&str>) -> Result<()> {
    let destination = root.join(name);
    let _ = read_pointer(root, name)?;
    let Some(target) = target else {
        return remove_regular(root, name);
    };
    verify_object(root, target)?;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut staged = None;
    for _ in 0..32 {
        let candidate = root.join(format!(
            ".pointer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match create_private_file(&candidate, format!("{target}\n").as_bytes()) {
            Ok(()) => {
                staged = Some(candidate);
                break;
            }
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    let staged = staged.ok_or_else(|| invalid("could not allocate Windows pointer stage"))?;
    if let Err(error) = move_replace(&staged, &destination) {
        let _ = fs::remove_file(staged);
        return Err(error);
    }
    sync_dir(root)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct PointerState {
    active: Option<String>,
    previous: Option<String>,
    companion: Option<String>,
    previous_companion: Option<String>,
    legacy_without_companion: bool,
}
impl PointerState {
    fn encode(&self) -> Vec<u8> {
        format!(
            "lomi-activation-v2\nactive={}\nprevious={}\ncompanion={}\nprevious_companion={}\n",
            self.active.as_deref().unwrap_or("-"),
            self.previous.as_deref().unwrap_or("-"),
            self.companion.as_deref().unwrap_or("-"),
            self.previous_companion.as_deref().unwrap_or("-")
        )
        .into_bytes()
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| invalid("activation journal is not UTF-8"))?;
        let mut lines = text.lines();
        let version = lines.next();
        if !matches!(version, Some("lomi-activation-v1" | "lomi-activation-v2")) {
            return Err(invalid("activation journal has an unsupported format"));
        }
        let active = lines
            .next()
            .and_then(|line| line.strip_prefix("active="))
            .ok_or_else(|| invalid("activation journal lacks active state"))?;
        let previous = lines
            .next()
            .and_then(|line| line.strip_prefix("previous="))
            .ok_or_else(|| invalid("activation journal lacks previous state"))?;
        let parse = |value: &str| -> Result<Option<String>> {
            if value == "-" {
                Ok(None)
            } else {
                target_path(value)?;
                Ok(Some(value.to_owned()))
            }
        };
        let legacy_without_companion = version == Some("lomi-activation-v1");
        let (companion, previous_companion) = if !legacy_without_companion {
            let companion = lines
                .next()
                .and_then(|line| line.strip_prefix("companion="))
                .ok_or_else(|| invalid("activation journal lacks companion state"))?;
            let previous_companion = lines
                .next()
                .and_then(|line| line.strip_prefix("previous_companion="))
                .ok_or_else(|| invalid("activation journal lacks previous companion state"))?;
            (parse(companion)?, parse(previous_companion)?)
        } else {
            (None, None)
        };
        if lines.next().is_some() {
            return Err(invalid("activation journal has trailing data"));
        }
        Ok(Self {
            active: parse(active)?,
            previous: parse(previous)?,
            companion,
            previous_companion,
            legacy_without_companion,
        })
    }
}

fn write_journal(root: &Path, state: &PointerState) -> Result<()> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut staged = None;
    for _ in 0..32 {
        let candidate = root.join(format!(
            ".journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match create_private_file(&candidate, &state.encode()) {
            Ok(()) => {
                staged = Some(candidate);
                break;
            }
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    let staged = staged.ok_or_else(|| invalid("could not allocate Windows activation journal"))?;
    if let Err(error) = move_replace(&staged, &root.join(JOURNAL)) {
        let _ = fs::remove_file(staged);
        return Err(error);
    }
    sync_dir(root)?;
    Ok(())
}

fn read_journal(root: &Path) -> Result<Option<PointerState>> {
    let path = root.join(JOURNAL);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => {
            private_file(&path)?;
            PointerState::decode(&read_bounded(&path, 1024)?).map(Some)
        }
    }
}

fn clear_journal(root: &Path) -> Result<()> {
    remove_regular(root, JOURNAL)
}

fn replace_executable(
    root: &Path,
    executable_name: &str,
    pointer_name: &str,
    target: Option<&str>,
    permitted_existing: &[Option<String>],
) -> Result<()> {
    let executable = root.join(executable_name);
    let current = read_pointer(root, pointer_name)?;
    if let Some(existing) = stable_executable_digest(root, executable_name)? {
        let expected = [current.as_deref(), target]
            .into_iter()
            .flatten()
            .chain(
                permitted_existing
                    .iter()
                    .filter_map(|value| value.as_deref()),
            )
            .map(|candidate| target_digest(candidate))
            .collect::<Result<Vec<_>>>()?;
        if !expected.iter().any(|value| value == &existing) {
            return Err(invalid(
                "refusing to replace an unbound Windows stable executable",
            ));
        }
    }
    match target {
        Some(target) => {
            let object = verify_object(root, target)?;
            let bytes = read_bounded(&object, MAX_TARGET)?;
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let mut staged = None;
            for _ in 0..32 {
                let candidate = root.join(format!(
                    ".{executable_name}-{}-{}.stage",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match create_private_file(&candidate, &bytes) {
                    Ok(()) => {
                        staged = Some(candidate);
                        break;
                    }
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            let staged =
                staged.ok_or_else(|| invalid("could not allocate Windows executable stage"))?;
            if let Err(error) = move_replace(&staged, &executable) {
                let _ = fs::remove_file(staged);
                return Err(error);
            }
            sync_dir(root)
        }
        None => remove_regular(root, executable_name),
    }
}

fn recover(root: &Path) -> Result<()> {
    let Some(state) = read_journal(root)? else {
        let active = read_pointer(root, ACTIVE)?;
        let companion = read_pointer(root, ACTIVE_COMPANION)?;
        stable_matches(root, EXE, ACTIVE, active.as_deref())?;
        return stable_matches(root, HELPER_EXE, ACTIVE_COMPANION, companion.as_deref());
    };
    for target in [
        state.active.as_deref(),
        state.previous.as_deref(),
        state.companion.as_deref(),
        state.previous_companion.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        verify_object(root, target)?;
    }
    replace_executable(root, EXE, ACTIVE, state.active.as_deref(), &[])?;
    replace_executable(
        root,
        HELPER_EXE,
        ACTIVE_COMPANION,
        state.companion.as_deref(),
        &[],
    )?;
    replace_pointer(root, PREVIOUS, state.previous.as_deref())?;
    replace_pointer(
        root,
        PREVIOUS_COMPANION,
        state.previous_companion.as_deref(),
    )?;
    replace_pointer(root, ACTIVE, state.active.as_deref())?;
    replace_pointer(root, ACTIVE_COMPANION, state.companion.as_deref())?;
    clear_journal(root)
}

pub(crate) fn recovery_pending(root: &Path) -> Result<bool> {
    validate_directory(root)?;
    read_journal(root).map(|journal| journal.is_some())
}

pub(crate) fn recover_verified(root: &Path, platform: &str, profile_schema: u64) -> Result<()> {
    validate_directory(root)?;
    let _lock = lock(root)?;
    let Some(state) = read_journal(root)? else {
        return Err(invalid("no interrupted release activation is pending"));
    };
    if !state.legacy_without_companion
        && (state.active.is_some() != state.companion.is_some()
            || state.previous.is_some() != state.previous_companion.is_some())
    {
        return Err(invalid(
            "interrupted Windows release journal does not contain complete executable pairs",
        ));
    }

    let current_active = read_pointer(root, ACTIVE)?;
    let current_previous = read_pointer(root, PREVIOUS)?;
    let current_companion = read_pointer(root, ACTIVE_COMPANION)?;
    let current_previous_companion = read_pointer(root, PREVIOUS_COMPANION)?;
    let targets = [
        state.active.as_deref(),
        state.previous.as_deref(),
        state.companion.as_deref(),
        state.previous_companion.as_deref(),
        current_active.as_deref(),
        current_previous.as_deref(),
        current_companion.as_deref(),
        current_previous_companion.as_deref(),
    ];
    for target in targets.into_iter().flatten() {
        let custom = release_custom(root, target)?;
        crate::release_schema_range(&custom, platform)?;
    }
    for target in [
        state.active.as_deref(),
        state.companion.as_deref(),
        current_active.as_deref(),
        current_companion.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let custom = release_custom(root, target)?;
        crate::validate_release_custom(&custom, platform, profile_schema)?;
    }
    for (main, helper) in [
        (state.active.as_deref(), state.companion.as_deref()),
        (
            state.previous.as_deref(),
            state.previous_companion.as_deref(),
        ),
    ] {
        if let (Some(main), Some(helper)) = (main, helper) {
            let main_policy = release_custom(root, main)?;
            let helper_policy = release_custom(root, helper)?;
            if main_policy.get("lomiRelease") != helper_policy.get("lomiRelease") {
                return Err(invalid(
                    "interrupted Windows executable pair has mismatched release policy",
                ));
            }
        }
    }
    recover(root)
}

fn commit_pointers(
    root: &Path,
    active: Option<String>,
    previous: Option<String>,
    companion: Option<String>,
    previous_companion: Option<String>,
) -> Result<()> {
    recover(root)?;
    for target in [
        active.as_deref(),
        previous.as_deref(),
        companion.as_deref(),
        previous_companion.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        verify_object(root, target)?;
    }
    let before = PointerState {
        active: read_pointer(root, ACTIVE)?,
        previous: read_pointer(root, PREVIOUS)?,
        companion: read_pointer(root, ACTIVE_COMPANION)?,
        previous_companion: read_pointer(root, PREVIOUS_COMPANION)?,
        legacy_without_companion: false,
    };
    stable_matches(root, EXE, ACTIVE, before.active.as_deref())?;
    stable_matches(
        root,
        HELPER_EXE,
        ACTIVE_COMPANION,
        before.companion.as_deref(),
    )?;
    let after = PointerState {
        active,
        previous,
        companion,
        previous_companion,
        legacy_without_companion: false,
    };
    write_journal(root, &before)?;
    let result = (|| -> Result<()> {
        replace_pointer(root, PREVIOUS, after.previous.as_deref())?;
        replace_pointer(
            root,
            PREVIOUS_COMPANION,
            after.previous_companion.as_deref(),
        )?;
        replace_pointer(root, ACTIVE, after.active.as_deref())?;
        replace_pointer(root, ACTIVE_COMPANION, after.companion.as_deref())?;
        let permitted_executable_generations = [before.active.clone(), after.active.clone()];
        let permitted_companion_generations = [before.companion.clone(), after.companion.clone()];
        replace_executable(
            root,
            EXE,
            ACTIVE,
            after.active.as_deref(),
            &permitted_executable_generations,
        )?;
        replace_executable(
            root,
            HELPER_EXE,
            ACTIVE_COMPANION,
            after.companion.as_deref(),
            &permitted_companion_generations,
        )?;
        clear_journal(root)
    })();
    if result.is_err() {
        let _ = recover(root);
    }
    result
}

fn sidecar(root: &Path, target: &str) -> Result<PathBuf> {
    let object = target_path(target)?;
    let name = object
        .file_name()
        .ok_or_else(|| invalid("release object has no name"))?
        .to_string_lossy();
    Ok(root
        .join("objects/sha256")
        .join(format!("{name}.release.json")))
}

fn write_sidecar(root: &Path, target: &str, custom: &serde_json::Value) -> Result<()> {
    let bytes = serde_json::to_vec(custom)?;
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(invalid("release custom metadata exceeds its bound"));
    }
    let path = sidecar(root, target)?;
    publish_immutable_file(
        &path,
        &bytes,
        16 * 1024,
        "existing release metadata mismatches",
    )
}

fn release_custom(root: &Path, target: &str) -> Result<serde_json::Value> {
    verify_object(root, target)?;
    let path = sidecar(root, target)?;
    private_file(&path)?;
    Ok(serde_json::from_slice(&read_bounded(&path, 16 * 1024)?)?)
}

fn store_verified_object(root: &Path, bytes: &[u8], custom: &serde_json::Value) -> Result<String> {
    if bytes.is_empty() || bytes.len() > MAX_TARGET {
        return Err(invalid("release executable is empty or oversized"));
    }
    for directory in [root.join("objects"), root.join("objects/sha256")] {
        match fs::symlink_metadata(&directory) {
            Ok(_) => private_dir(&directory)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_dir(&directory)?
            }
            Err(error) => return Err(error.into()),
        }
    }
    let target = format!("objects/sha256/{}.exe", digest(bytes));
    let object = root.join(target_path(&target)?);
    publish_immutable_file(
        &object,
        bytes,
        MAX_TARGET,
        "existing Windows release object is corrupt",
    )?;
    write_sidecar(root, &target, custom)?;
    Ok(target)
}

/// Stage, flush, and atomically publish immutable object and sidecar files.
/// An existing final name is accepted only if it is a private regular file
/// whose complete bytes match the requested content.
fn publish_immutable_file(
    destination: &Path,
    bytes: &[u8],
    limit: usize,
    mismatch: &'static str,
) -> Result<()> {
    let verify_existing = || -> Result<()> {
        private_file(destination)?;
        if read_bounded(destination, limit)? != bytes {
            return Err(invalid(mismatch));
        }
        Ok(())
    };
    match fs::symlink_metadata(destination) {
        Ok(_) => return verify_existing(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("immutable release file has no parent"))?;
    let mut staged = None;
    for _ in 0..32 {
        let candidate = parent.join(format!(
            ".immutable-{}-{}.stage",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match create_private_file(&candidate, bytes) {
            Ok(()) => {
                staged = Some(candidate);
                break;
            }
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    let staged = staged.ok_or_else(|| invalid("could not allocate immutable release stage"))?;
    let publish = move_new(&staged, destination);
    if publish.is_err() {
        let _ = fs::remove_file(&staged);
        // A racing publisher may have won the absent-name race. Its final
        // bytes are reusable only after the same exact verification above.
        if matches!(fs::symlink_metadata(destination), Ok(_)) {
            return verify_existing();
        }
        return publish;
    }
    sync_dir(parent)?;
    verify_existing()
}

pub(crate) fn activate_verified_target(
    root: &Path,
    bytes: &[u8],
    custom: &serde_json::Value,
    platform: &str,
    profile_schema: u64,
) -> Result<PathBuf> {
    validate_directory(root)?;
    crate::validate_release_custom(custom, platform, profile_schema)?;
    if bytes.is_empty() || bytes.len() > MAX_TARGET {
        return Err(invalid("release executable is empty or oversized"));
    }
    let _lock = lock(root)?;
    recover(root)?;
    let current = read_pointer(root, ACTIVE)?;
    let _ = read_pointer(root, PREVIOUS)?;
    if read_pointer(root, ACTIVE_COMPANION)?.is_some()
        || read_pointer(root, PREVIOUS_COMPANION)?.is_some()
    {
        return Err(invalid(
            "paired Windows releases require both signed targets",
        ));
    }
    let target = store_verified_object(root, bytes, custom)?;
    let object = root.join(target_path(&target)?);
    commit_pointers(root, Some(target), current, None, None)?;
    Ok(object)
}

pub(crate) fn activate_verified_pair(
    root: &Path,
    primary_bytes: &[u8],
    companion_bytes: &[u8],
    primary_custom: &serde_json::Value,
    companion_custom: &serde_json::Value,
    platform: &str,
    profile_schema: u64,
) -> Result<(PathBuf, PathBuf)> {
    validate_directory(root)?;
    crate::validate_release_custom(primary_custom, platform, profile_schema)?;
    crate::validate_release_custom(companion_custom, platform, profile_schema)?;
    if primary_custom.get("lomiRelease") != companion_custom.get("lomiRelease") {
        return Err(invalid(
            "Windows primary and companion targets have different signed release policies",
        ));
    }
    let _lock = lock(root)?;
    recover(root)?;
    let current = read_pointer(root, ACTIVE)?;
    let current_companion = read_pointer(root, ACTIVE_COMPANION)?;
    let _ = read_pointer(root, PREVIOUS)?;
    let _ = read_pointer(root, PREVIOUS_COMPANION)?;
    let primary = store_verified_object(root, primary_bytes, primary_custom)?;
    let companion = store_verified_object(root, companion_bytes, companion_custom)?;
    let primary_path = root.join(target_path(&primary)?);
    let companion_path = root.join(target_path(&companion)?);
    commit_pointers(
        root,
        Some(primary),
        current,
        Some(companion),
        current_companion,
    )?;
    Ok((primary_path, companion_path))
}

pub(crate) struct ActiveHostPair {
    pub(crate) primary_path: PathBuf,
    pub(crate) helper_path: PathBuf,
    pub(crate) primary_custom: serde_json::Value,
    pub(crate) helper_custom: serde_json::Value,
}

/// Recover and return only a complete, hash-checked active pair from the
/// updater's protected content-addressed store.
pub(crate) fn active_host_pair(root: &Path, platform: &str) -> Result<Option<ActiveHostPair>> {
    validate_directory(root)?;
    let _lock = lock(root)?;
    recover(root)?;
    let Some(primary) = read_pointer(root, ACTIVE)? else {
        if read_pointer(root, ACTIVE_COMPANION)?.is_some() {
            return Err(invalid("active Windows release has no primary image"));
        }
        return Ok(None);
    };
    let helper = read_pointer(root, ACTIVE_COMPANION)?
        .ok_or_else(|| invalid("active Windows release lacks its signed Host companion"))?;
    let primary_custom = release_custom(root, &primary)?;
    let helper_custom = release_custom(root, &helper)?;
    crate::validate_release_custom(&primary_custom, platform, 0)?;
    crate::validate_release_custom(&helper_custom, platform, 0)?;
    if primary_custom.get("lomiRelease") != helper_custom.get("lomiRelease") {
        return Err(invalid(
            "active Windows release pair has mismatched TUF policy",
        ));
    }
    Ok(Some(ActiveHostPair {
        primary_path: verify_object(root, &primary)?,
        helper_path: verify_object(root, &helper)?,
        primary_custom,
        helper_custom,
    }))
}

/// Swap the active and previous complete Windows pairs. Both pairs must still
/// be present in the protected activation store and pass signed release policy
/// checks; this operation never copies arbitrary paths into Install.
#[cfg(feature = "release-root")]
pub(crate) fn rollback_host_pair(
    root: &Path,
    platform: &str,
    profile_schema: u64,
) -> Result<ActiveHostPair> {
    validate_directory(root)?;
    let _lock = lock(root)?;
    recover(root)?;
    let current = read_pointer(root, ACTIVE)?
        .ok_or_else(|| invalid("no active Windows release to roll back"))?;
    let previous =
        read_pointer(root, PREVIOUS)?.ok_or_else(|| invalid("no previous Windows release pair"))?;
    let current_helper = read_pointer(root, ACTIVE_COMPANION)?
        .ok_or_else(|| invalid("active Windows release lacks its Host companion"))?;
    let previous_helper = read_pointer(root, PREVIOUS_COMPANION)?
        .ok_or_else(|| invalid("previous Windows release lacks its Host companion"))?;
    let current_custom = release_custom(root, &current)?;
    let current_helper_custom = release_custom(root, &current_helper)?;
    let previous_custom = release_custom(root, &previous)?;
    let previous_helper_custom = release_custom(root, &previous_helper)?;
    for custom in [
        &current_custom,
        &current_helper_custom,
        &previous_custom,
        &previous_helper_custom,
    ] {
        crate::validate_release_custom(custom, platform, profile_schema)?;
    }
    if current_custom.get("lomiRelease") != current_helper_custom.get("lomiRelease")
        || previous_custom.get("lomiRelease") != previous_helper_custom.get("lomiRelease")
    {
        return Err(invalid("Windows rollback pair has mismatched TUF policy"));
    }
    crate::validate_windows_service_pair(
        &current_custom,
        &current_helper_custom,
        platform,
        profile_schema,
    )?;
    crate::validate_windows_service_pair(
        &previous_custom,
        &previous_helper_custom,
        platform,
        profile_schema,
    )?;
    commit_pointers(
        root,
        Some(previous.clone()),
        Some(current),
        Some(previous_helper.clone()),
        Some(current_helper),
    )?;
    Ok(ActiveHostPair {
        primary_path: verify_object(root, &previous)?,
        helper_path: verify_object(root, &previous_helper)?,
        primary_custom: previous_custom,
        helper_custom: previous_helper_custom,
    })
}

pub(crate) fn rollback(root: &Path, platform: &str, profile_schema: u64) -> Result<PathBuf> {
    validate_directory(root)?;
    let _lock = lock(root)?;
    recover(root)?;
    let current =
        read_pointer(root, ACTIVE)?.ok_or_else(|| invalid("no active release to roll back"))?;
    let previous = read_pointer(root, PREVIOUS)?.ok_or_else(|| invalid("no previous release"))?;
    let current_companion = read_pointer(root, ACTIVE_COMPANION)?
        .ok_or_else(|| invalid("active Windows release lacks its signed host companion"))?;
    let previous_companion = read_pointer(root, PREVIOUS_COMPANION)?
        .ok_or_else(|| invalid("previous Windows release lacks its signed host companion"))?;
    let current_custom = release_custom(root, &current)?;
    let previous_custom = release_custom(root, &previous)?;
    let current_companion_custom = release_custom(root, &current_companion)?;
    let previous_companion_custom = release_custom(root, &previous_companion)?;
    if current_custom.get("lomiRelease") != current_companion_custom.get("lomiRelease")
        || previous_custom.get("lomiRelease") != previous_companion_custom.get("lomiRelease")
    {
        return Err(invalid(
            "Windows active release pair has inconsistent signed policy",
        ));
    }
    crate::validate_release_custom(&previous_custom, platform, profile_schema)?;
    crate::validate_release_custom(&previous_companion_custom, platform, profile_schema)?;
    let object = verify_object(root, &previous)?;
    commit_pointers(
        root,
        Some(previous),
        Some(current),
        Some(previous_companion),
        Some(current_companion),
    )?;
    Ok(object)
}

pub(crate) fn uninstall(root: &Path) -> Result<usize> {
    validate_directory(root)?;
    let _lock = lock(root)?;
    recover(root)?;
    let _ = read_pointer(root, ACTIVE)?;
    let _ = read_pointer(root, PREVIOUS)?;
    commit_pointers(root, None, None, None, None)?;
    let hashes = root.join("objects/sha256");
    let metadata = match fs::symlink_metadata(&hashes) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    private_dir(&hashes)?;
    let _ = metadata;
    let mut removed = 0usize;
    for entry in fs::read_dir(&hashes)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(digest_name) = name.strip_suffix(".exe") else {
            continue;
        };
        if digest_name.len() != 64
            || !digest_name
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            continue;
        }
        let target = format!("objects/sha256/{name}");
        if verify_object(root, &target).is_ok() {
            let metadata = sidecar(root, &target)?;
            if fs::symlink_metadata(&metadata).is_ok() {
                private_file(&metadata)?;
                fs::remove_file(metadata)?;
            }
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    sync_dir(&hashes)?;
    Ok(removed)
}
