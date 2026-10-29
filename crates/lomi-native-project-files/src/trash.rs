use crate::{
    NativeProjectCheckPhase, NativeProjectDirectory, NativeProjectEntryKind,
    NativeProjectErrorCode as ErrorCode, NativeProjectMutationError, NativeProjectStagedTrash,
    NativeProjectTrashTicket,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

const PLAN_LIMIT: u64 = 16 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrashPlan {
    device: String,
    expected_parent_revision: String,
    expected_revision: String,
    inode: String,
    kind: NativeProjectEntryKind,
    operation_id: String,
    project_path: PathBuf,
    relative_path: String,
    version: u8,
}

fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:.".contains(&byte))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identity(file: &File) -> Result<(u64, u64), ErrorCode> {
    let metadata = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn private_directory(parent: &File, name: &str, create: bool) -> Result<File, ErrorCode> {
    use rustix::fs::{Mode, OFlags, mkdirat, openat};

    if create {
        mkdirat(parent, name, Mode::from_raw_mode(0o700))
            .map_err(|_| ErrorCode::StorageUnavailable)?;
    }
    let directory = File::from(
        openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ErrorCode::StorageUnavailable)?,
    );
    check_private_directory(&directory)?;
    Ok(directory)
}

fn check_private_directory(directory: &File) -> Result<(), ErrorCode> {
    let metadata = directory
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
        return Err(ErrorCode::StorageUnavailable);
    }
    Ok(())
}

fn durable_json(directory: &File, name: &str, value: &impl Serialize) -> Result<(), ErrorCode> {
    use rustix::fs::{Mode, OFlags, openat};

    let bytes = serde_json::to_vec(value).map_err(|_| ErrorCode::StorageUnavailable)?;
    if bytes.len() as u64 > PLAN_LIMIT {
        return Err(ErrorCode::ResourceExhausted);
    }
    let mut file = File::from(
        openat(
            directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| ErrorCode::StorageUnavailable)?,
    );
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    directory
        .sync_all()
        .map_err(|_| ErrorCode::StorageUnavailable)
}

fn read_plan(directory: &File) -> Result<TrashPlan, ErrorCode> {
    use rustix::fs::{Mode, OFlags, openat};

    let mut file = File::from(
        openat(
            directory,
            "plan.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ErrorCode::StorageUnavailable)?,
    );
    let metadata = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > PLAN_LIMIT
    {
        return Err(ErrorCode::StorageUnavailable);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > PLAN_LIMIT {
        return Err(ErrorCode::StorageUnavailable);
    }
    serde_json::from_slice(&bytes).map_err(|_| ErrorCode::StorageUnavailable)
}

fn ensure_absent(directory: &File, name: &str) -> Result<(), ErrorCode> {
    use rustix::fs::{AtFlags, statat};

    match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        _ => Err(ErrorCode::StorageUnavailable),
    }
}

fn ensure_absent_for_stage(directory: &File, name: &str) -> Result<(), ErrorCode> {
    use rustix::fs::{AtFlags, statat};

    match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        _ => Err(ErrorCode::RevisionConflict),
    }
}

fn exact_names(directory: &File, expected: &[&str]) -> Result<(), ErrorCode> {
    use rustix::fs::Dir;

    let stream = Dir::read_from(directory).map_err(|_| ErrorCode::StorageUnavailable)?;
    let mut names = Vec::with_capacity(expected.len());
    for entry in stream {
        let entry = entry.map_err(|_| ErrorCode::StorageUnavailable)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if matches!(name, "." | "..") {
            continue;
        }
        if names.len() >= expected.len() {
            return Err(ErrorCode::StorageUnavailable);
        }
        names.push(name.to_owned());
    }
    names.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    if names
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
    {
        Ok(())
    } else {
        Err(ErrorCode::StorageUnavailable)
    }
}

fn open_staged_entry(
    payload: &File,
    leaf: &std::ffi::OsStr,
    kind: &NativeProjectEntryKind,
) -> Result<File, ErrorCode> {
    use rustix::fs::{Mode, OFlags, openat};

    let flags = OFlags::RDONLY
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC
        | if *kind == NativeProjectEntryKind::Directory {
            OFlags::DIRECTORY
        } else {
            OFlags::empty()
        };
    let entry = File::from(
        openat(payload, leaf, flags, Mode::empty()).map_err(|_| ErrorCode::StorageUnavailable)?,
    );
    let metadata = entry
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    let valid_kind = match kind {
        NativeProjectEntryKind::File => metadata.is_file() && metadata.nlink() == 1,
        NativeProjectEntryKind::Directory => metadata.is_dir(),
    };
    if !valid_kind {
        return Err(ErrorCode::StorageUnavailable);
    }
    Ok(entry)
}

fn decimal(value: &str) -> Result<u64, ErrorCode> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    if parsed.to_string() != value {
        return Err(ErrorCode::StorageUnavailable);
    }
    Ok(parsed)
}

fn ticket_is_well_formed(ticket: &NativeProjectTrashTicket) -> Result<PathBuf, ErrorCode> {
    if !ticket.recovery_root.is_absolute()
        || !ticket.project_path.is_absolute()
        || !valid_operation_id(&ticket.operation_id)
        || crate::validate_relative(&ticket.relative_path).is_err()
        || !valid_hash(&ticket.expected_revision)
        || !valid_hash(&ticket.expected_parent_revision)
    {
        return Err(ErrorCode::StorageUnavailable);
    }
    let leaf = Path::new(&ticket.relative_path)
        .file_name()
        .ok_or(ErrorCode::StorageUnavailable)?;
    let expected_path = ticket
        .recovery_root
        .join(&ticket.operation_id)
        .join("entry")
        .join(leaf);
    if ticket.staged_path != expected_path {
        return Err(ErrorCode::StorageUnavailable);
    }
    let source_device = decimal(&ticket.source_entry_device)?;
    let _source_inode = decimal(&ticket.source_entry_inode)?;
    let recovery_device = decimal(&ticket.recovery_device)?;
    let _recovery_inode = decimal(&ticket.recovery_inode)?;
    let operation_device = decimal(&ticket.operation_device)?;
    let _operation_inode = decimal(&ticket.operation_inode)?;
    let payload_device = decimal(&ticket.payload_device)?;
    let _payload_inode = decimal(&ticket.payload_inode)?;
    if source_device != recovery_device
        || operation_device != recovery_device
        || payload_device != recovery_device
    {
        return Err(ErrorCode::StorageUnavailable);
    }
    Ok(expected_path)
}

fn reopen_validated(
    ticket: &NativeProjectTrashTicket,
) -> Result<NativeProjectStagedTrash, ErrorCode> {
    let expected_path = ticket_is_well_formed(ticket)?;
    let leaf = Path::new(&ticket.relative_path)
        .file_name()
        .ok_or(ErrorCode::StorageUnavailable)?;
    let leaf_c = CString::new(leaf.as_bytes()).map_err(|_| ErrorCode::StorageUnavailable)?;
    let recovery = crate::open_absolute_directory(&ticket.recovery_root)?;
    check_private_directory(&recovery)?;
    let operation = private_directory(&recovery, &ticket.operation_id, false)?;
    let payload = private_directory(&operation, "entry", false)?;
    let recovery_identity = identity(&recovery)?;
    let operation_identity = identity(&operation)?;
    let payload_identity = identity(&payload)?;
    if recovery_identity
        != (
            decimal(&ticket.recovery_device)?,
            decimal(&ticket.recovery_inode)?,
        )
        || operation_identity
            != (
                decimal(&ticket.operation_device)?,
                decimal(&ticket.operation_inode)?,
            )
        || payload_identity
            != (
                decimal(&ticket.payload_device)?,
                decimal(&ticket.payload_inode)?,
            )
        || recovery_identity.0 != decimal(&ticket.source_entry_device)?
    {
        return Err(ErrorCode::StorageUnavailable);
    }
    exact_names(&operation, &["entry", "plan.json"])?;
    exact_names(
        &payload,
        &[leaf.to_str().ok_or(ErrorCode::StorageUnavailable)?],
    )?;
    ensure_absent(&operation, "completed.json")?;
    let plan = read_plan(&operation)?;
    if plan.version != 1
        || plan.operation_id != ticket.operation_id
        || plan.project_path != ticket.project_path
        || plan.relative_path != ticket.relative_path
        || plan.kind != ticket.kind
        || plan.expected_revision != ticket.expected_revision
        || plan.expected_parent_revision != ticket.expected_parent_revision
        || plan.device != ticket.source_entry_device
        || plan.inode != ticket.source_entry_inode
    {
        return Err(ErrorCode::StorageUnavailable);
    }
    let entry = open_staged_entry(&payload, leaf, &ticket.kind)?;
    let source_identity = identity(&entry)?;
    if source_identity
        != (
            decimal(&ticket.source_entry_device)?,
            decimal(&ticket.source_entry_inode)?,
        )
        || expected_path.file_name() != Some(leaf)
    {
        return Err(ErrorCode::StorageUnavailable);
    }
    Ok(NativeProjectStagedTrash {
        ticket: ticket.clone(),
        operation_directory: operation,
        payload_directory: payload,
        leaf: leaf_c,
        source_identity,
    })
}

/// Reopen a staged trash operation using only the validated durable ticket.
/// No action is taken when the returned object is dropped.
pub fn from_ticket(
    ticket: NativeProjectTrashTicket,
) -> Result<NativeProjectStagedTrash, NativeProjectMutationError> {
    NativeProjectStagedTrash::from_ticket(ticket)
}

impl NativeProjectStagedTrash {
    pub fn from_ticket(
        ticket: NativeProjectTrashTicket,
    ) -> Result<Self, NativeProjectMutationError> {
        reopen_validated(&ticket).map_err(|_| NativeProjectMutationError::Uncertain)
    }

    pub fn ticket(&self) -> NativeProjectTrashTicket {
        self.ticket.clone()
    }

    pub fn path(&self) -> &Path {
        &self.ticket.staged_path
    }

    pub fn finish(
        self,
        trash: impl FnOnce(&Path) -> Result<(), ErrorCode>,
    ) -> Result<(), NativeProjectMutationError> {
        use rustix::fs::{AtFlags, statat};

        let staged =
            reopen_validated(&self.ticket).map_err(|_| NativeProjectMutationError::Uncertain)?;
        if staged.source_identity != self.source_identity {
            return Err(NativeProjectMutationError::Uncertain);
        }
        drop(self);
        trash(staged.path()).map_err(|_| NativeProjectMutationError::Uncertain)?;
        if !matches!(
            statat(
                &staged.payload_directory,
                &staged.leaf,
                AtFlags::SYMLINK_NOFOLLOW,
            ),
            Err(rustix::io::Errno::NOENT)
        ) {
            return Err(NativeProjectMutationError::Uncertain);
        }
        durable_json(
            &staged.operation_directory,
            "completed.json",
            &serde_json::json!({"trashed":true}),
        )
        .map_err(|_| NativeProjectMutationError::Uncertain)?;
        Ok(())
    }
}

pub(crate) fn stage(
    project: &NativeProjectDirectory,
    relative_path: &str,
    kind: NativeProjectEntryKind,
    expected_revision: &str,
    expected_parent_revision: &str,
    recovery_root: &Path,
    operation_id: &str,
    check: &mut impl FnMut(NativeProjectCheckPhase) -> Result<(), ErrorCode>,
) -> Result<NativeProjectTrashTicket, NativeProjectMutationError> {
    if !valid_operation_id(operation_id) {
        return Err(ErrorCode::ScopeDenied.into());
    }
    crate::validate_relative(relative_path)?;
    check(NativeProjectCheckPhase::Progress)?;
    let relative = Path::new(relative_path);
    let parent_name = relative
        .parent()
        .and_then(Path::to_str)
        .ok_or(ErrorCode::ScopeDenied)?;
    let leaf_name = relative.file_name().ok_or(ErrorCode::ScopeDenied)?;
    let leaf = CString::new(leaf_name.as_bytes()).map_err(|_| ErrorCode::ScopeDenied)?;
    let parent = project.open_directory(parent_name)?;
    let parent_identity = identity(&parent)?;
    if project
        .list(parent_name, || check(NativeProjectCheckPhase::Progress))?
        .revision
        != expected_parent_revision
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    let (entry, expected_stamp) = match &kind {
        NativeProjectEntryKind::File => {
            let mut entry = crate::open_file_at(&parent, &leaf)?;
            if entry
                .metadata()
                .map_err(|_| ErrorCode::StorageUnavailable)?
                .len()
                > 4 * 1024 * 1024
            {
                return Err(ErrorCode::ResourceExhausted.into());
            }
            let (revision, metadata) =
                crate::snapshot_file(&mut entry, || check(NativeProjectCheckPhase::Progress))?;
            if revision != expected_revision {
                return Err(ErrorCode::RevisionConflict.into());
            }
            (entry, Some(crate::stamp_file(&metadata)))
        }
        NativeProjectEntryKind::Directory => {
            let entry = project.open_directory(relative_path)?;
            if project
                .list(relative_path, || check(NativeProjectCheckPhase::Progress))?
                .revision
                != expected_revision
            {
                return Err(ErrorCode::RevisionConflict.into());
            }
            (entry, None)
        }
    };
    let source_identity = identity(&entry)?;
    let recovery = crate::open_absolute_directory(recovery_root)?;
    let recovery_identity = identity(&recovery)?;
    check_private_directory(&recovery)?;
    if source_identity.0 != recovery_identity.0 {
        return Err(ErrorCode::UnsupportedCapability.into());
    }

    // The host obtains a fresh authorization before each private directory
    // creation. Revalidate the parent and absence after each blocking upcall.
    check(NativeProjectCheckPhase::BeforeEffect)?;
    check(NativeProjectCheckPhase::Validation)?;
    let validated_recovery = crate::open_absolute_directory(recovery_root)?;
    check_private_directory(&validated_recovery)?;
    if identity(&validated_recovery)? != recovery_identity {
        return Err(ErrorCode::RevisionConflict.into());
    }
    ensure_absent_for_stage(&validated_recovery, operation_id)?;
    check(NativeProjectCheckPhase::Publication)?;
    let operation_directory = private_directory(&recovery, operation_id, true)?;
    let operation_identity = identity(&operation_directory)?;

    check(NativeProjectCheckPhase::BeforeEffect)?;
    check(NativeProjectCheckPhase::Validation)?;
    let validated_recovery = crate::open_absolute_directory(recovery_root)?;
    check_private_directory(&validated_recovery)?;
    let validated_operation = private_directory(&validated_recovery, operation_id, false)?;
    if identity(&validated_recovery)? != recovery_identity
        || identity(&validated_operation)? != operation_identity
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    ensure_absent_for_stage(&validated_operation, "entry")?;
    check(NativeProjectCheckPhase::Publication)?;
    let payload_directory = private_directory(&operation_directory, "entry", true)?;
    let payload_identity = identity(&payload_directory)?;
    let plan = TrashPlan {
        device: source_identity.0.to_string(),
        expected_parent_revision: expected_parent_revision.to_owned(),
        expected_revision: expected_revision.to_owned(),
        inode: source_identity.1.to_string(),
        kind: kind.clone(),
        operation_id: operation_id.to_owned(),
        project_path: project.canonical_path().to_path_buf(),
        relative_path: relative_path.to_owned(),
        version: 1,
    };
    durable_json(&operation_directory, "plan.json", &plan)?;
    recovery
        .sync_all()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    check(NativeProjectCheckPhase::Progress)?;
    project.check()?;
    if identity(&project.open_directory(parent_name)?)? != parent_identity
        || identity(&crate::open_absolute_directory(recovery_root)?)? != recovery_identity
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    match &kind {
        NativeProjectEntryKind::File => {
            let (revision, metadata) =
                crate::snapshot_file(&mut crate::open_file_at(&parent, &leaf)?, || {
                    check(NativeProjectCheckPhase::Progress)
                })?;
            if revision != expected_revision || Some(crate::stamp_file(&metadata)) != expected_stamp
            {
                return Err(ErrorCode::RevisionConflict.into());
            }
        }
        NativeProjectEntryKind::Directory => {
            if identity(&project.open_directory(relative_path)?)? != source_identity
                || project
                    .list(relative_path, || check(NativeProjectCheckPhase::Progress))?
                    .revision
                    != expected_revision
            {
                return Err(ErrorCode::RevisionConflict.into());
            }
        }
    }
    check(NativeProjectCheckPhase::Progress)?;
    project.check()?;
    if identity(&project.open_directory(parent_name)?)? != parent_identity
        || identity(&crate::open_absolute_directory(recovery_root)?)? != recovery_identity
        || identity(&private_directory(&recovery, operation_id, false)?)? != operation_identity
        || identity(&private_directory(&operation_directory, "entry", false)?)? != payload_identity
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    check(NativeProjectCheckPhase::BeforeEffect)?;
    project.check()?;
    let validated_parent = project.open_directory(parent_name)?;
    if identity(&validated_parent)? != parent_identity
        || project
            .list(parent_name, || check(NativeProjectCheckPhase::Validation))?
            .revision
            != expected_parent_revision
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    match &kind {
        NativeProjectEntryKind::File => {
            let mut current = crate::open_file_at(&validated_parent, &leaf)?;
            if current
                .metadata()
                .map_err(|_| ErrorCode::StorageUnavailable)?
                .len()
                > 4 * 1024 * 1024
            {
                return Err(ErrorCode::ResourceExhausted.into());
            }
            let (revision, metadata) =
                crate::snapshot_file(&mut current, || check(NativeProjectCheckPhase::Validation))?;
            if revision != expected_revision
                || Some(crate::stamp_file(&metadata)) != expected_stamp
                || identity(&current)? != source_identity
            {
                return Err(ErrorCode::RevisionConflict.into());
            }
            let named = crate::open_file_at(&validated_parent, &leaf)?;
            if identity(&named)? != source_identity
                || Some(crate::stamp_file(
                    &named
                        .metadata()
                        .map_err(|_| ErrorCode::StorageUnavailable)?,
                )) != expected_stamp
            {
                return Err(ErrorCode::RevisionConflict.into());
            }
        }
        NativeProjectEntryKind::Directory => {
            if project
                .list(relative_path, || check(NativeProjectCheckPhase::Validation))?
                .revision
                != expected_revision
                || identity(&project.open_directory(relative_path)?)? != source_identity
            {
                return Err(ErrorCode::RevisionConflict.into());
            }
        }
    }
    let validated_recovery = crate::open_absolute_directory(recovery_root)?;
    check_private_directory(&validated_recovery)?;
    let validated_operation = private_directory(&validated_recovery, operation_id, false)?;
    let validated_payload = private_directory(&validated_operation, "entry", false)?;
    if identity(&validated_recovery)? != recovery_identity
        || identity(&validated_operation)? != operation_identity
        || identity(&validated_payload)? != payload_identity
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    let validated_plan = read_plan(&validated_operation)?;
    if validated_plan.version != plan.version
        || validated_plan.operation_id != plan.operation_id
        || validated_plan.project_path != plan.project_path
        || validated_plan.relative_path != plan.relative_path
        || validated_plan.kind != plan.kind
        || validated_plan.expected_revision != plan.expected_revision
        || validated_plan.expected_parent_revision != plan.expected_parent_revision
        || validated_plan.device != plan.device
        || validated_plan.inode != plan.inode
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    exact_names(&validated_operation, &["entry", "plan.json"])?;
    ensure_absent(&validated_operation, "completed.json")?;
    exact_names(&validated_payload, &[])?;
    let leaf_name_str = leaf_name.to_str().ok_or(ErrorCode::ScopeDenied)?;
    ensure_absent_for_stage(&validated_payload, leaf_name_str)?;
    check(NativeProjectCheckPhase::Publication)?;
    crate::rename_exclusive(&parent, &leaf, &payload_directory, &leaf)?;
    parent
        .sync_all()
        .and_then(|_| payload_directory.sync_all())
        .map_err(|_| NativeProjectMutationError::Uncertain)?;
    Ok(NativeProjectTrashTicket {
        recovery_root: recovery_root.to_path_buf(),
        operation_id: operation_id.to_owned(),
        staged_path: recovery_root
            .join(operation_id)
            .join("entry")
            .join(leaf_name),
        project_path: project.canonical_path().to_path_buf(),
        relative_path: relative_path.to_owned(),
        kind,
        expected_revision: expected_revision.to_owned(),
        expected_parent_revision: expected_parent_revision.to_owned(),
        source_entry_device: source_identity.0.to_string(),
        source_entry_inode: source_identity.1.to_string(),
        recovery_device: recovery_identity.0.to_string(),
        recovery_inode: recovery_identity.1.to_string(),
        operation_device: operation_identity.0.to_string(),
        operation_inode: operation_identity.1.to_string(),
        payload_device: payload_identity.0.to_string(),
        payload_inode: payload_identity.1.to_string(),
    })
}
