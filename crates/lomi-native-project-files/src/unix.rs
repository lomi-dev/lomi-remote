use crate::{
    NativeArtifactCreated, NativeProjectCheckPhase, NativeProjectDirectory,
    NativeProjectDirectorySnapshot, NativeProjectEntry, NativeProjectEntryKind,
    NativeProjectErrorCode as ErrorCode, NativeProjectFile, NativeProjectMutation,
    NativeProjectMutationError, NativeProjectMutationResult, NativeProjectStamp,
};
use lomi_files::{
    LocalNativeFile, LocalNativeFileCheckPhase, LocalNativeFileError, LocalNativeFilePublishError,
    LocalNativeFileReadError,
};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString, OsStr},
    fs::{File, Metadata},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

const FILE_SNAPSHOT_LIMIT: u64 = 16 * 1024 * 1024;
const MOVED_FILE_LIMIT: u64 = 4 * 1024 * 1024;

impl From<rustix::io::Errno> for NativeProjectMutationError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Before(map_mutation_errno(error))
    }
}

fn stamp(metadata: &Metadata) -> NativeProjectStamp {
    NativeProjectStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        links: metadata.nlink(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

/// Stable file identity and version data used by other native publishers.
pub fn stamp_file(metadata: &Metadata) -> (u64, u64, u64, u64, i64, i64, i64, i64) {
    let stamp = stamp(metadata);
    (
        stamp.device,
        stamp.inode,
        stamp.bytes,
        stamp.links,
        stamp.modified.0,
        stamp.modified.1,
        stamp.changed.0,
        stamp.changed.1,
    )
}

fn open_at(directory: &File, name: &OsStr, directory_only: bool) -> Result<File, ErrorCode> {
    let name = CString::new(name.as_bytes()).map_err(|_| ErrorCode::ScopeDenied)?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory_only { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(ErrorCode::TargetNotFound);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open an absolute directory without following links in any path component.
pub fn open_absolute_directory(path: &Path) -> Result<File, ErrorCode> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(ErrorCode::ScopeDenied);
    }
    let mut directory = File::open("/").map_err(|_| ErrorCode::StorageUnavailable)?;
    for (index, component) in path.components().enumerate() {
        if index > 128 {
            return Err(ErrorCode::ResourceExhausted);
        }
        match component {
            Component::RootDir => {}
            Component::Normal(name) => directory = open_at(&directory, name, true)?,
            _ => return Err(ErrorCode::ScopeDenied),
        }
    }
    Ok(directory)
}

/// Preserve the project-file and mutation path policy used by the desktop.
pub fn validate_relative(path: &str) -> Result<(), ErrorCode> {
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\0')
        || path.contains('\\')
        || path.split('/').count() > 128
    {
        return Err(ErrorCode::ScopeDenied);
    }
    for part in path.split('/') {
        let lower = part.to_ascii_lowercase();
        if part.is_empty()
            || matches!(part, "." | "..")
            || lower.starts_with(".env")
            || lomi_fs_policy::is_private_staging_name(part.as_bytes())
            || matches!(
                lower.as_str(),
                ".git"
                    | ".ssh"
                    | ".aws"
                    | ".azure"
                    | ".gnupg"
                    | ".codex"
                    | ".netrc"
                    | ".npmrc"
                    | ".pypirc"
                    | "credentials"
                    | "credentials.json"
                    | "id_rsa"
                    | "id_ed25519"
            )
            || [".pem", ".key", ".p12", ".pfx", ".keystore", ".jks"]
                .iter()
                .any(|suffix| lower.ends_with(suffix))
        {
            return Err(ErrorCode::ScopeDenied);
        }
    }
    Ok(())
}

impl NativeProjectDirectory {
    pub fn open(path: &Path) -> Result<Self, ErrorCode> {
        Ok(Self {
            path: path.to_path_buf(),
            directory: open_absolute_directory(path)?,
        })
    }

    pub fn canonical_path(&self) -> &Path {
        &self.path
    }

    pub fn check(&self) -> Result<(), ErrorCode> {
        let current = open_absolute_directory(&self.path)?
            .metadata()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        let approved = self
            .directory
            .metadata()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if (current.dev(), current.ino()) != (approved.dev(), approved.ino()) {
            return Err(ErrorCode::RevisionConflict);
        }
        Ok(())
    }

    pub fn open_directory(&self, relative: &str) -> Result<File, ErrorCode> {
        self.check()?;
        let mut directory = self
            .directory
            .try_clone()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if !relative.is_empty() {
            validate_relative(relative)?;
            for name in relative.split('/') {
                directory = open_at(&directory, OsStr::new(name), true)?;
            }
        }
        Ok(directory)
    }

    pub fn list(
        &self,
        relative: &str,
        mut check: impl FnMut() -> Result<(), ErrorCode>,
    ) -> Result<NativeProjectDirectorySnapshot, ErrorCode> {
        use rustix::fs::{AtFlags, Dir, FileType, statat};

        check()?;
        let directory = self.open_directory(relative)?;
        let directory_stamp = stamp(
            &directory
                .metadata()
                .map_err(|_| ErrorCode::StorageUnavailable)?,
        );
        let stream = Dir::read_from(&directory).map_err(|_| ErrorCode::StorageUnavailable)?;
        let mut entries = Vec::new();
        let mut bytes = 0;
        for (visited, entry) in stream.enumerate() {
            check()?;
            if visited >= 10002 {
                return Err(ErrorCode::ResourceExhausted);
            }
            let entry = entry.map_err(|_| ErrorCode::StorageUnavailable)?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if matches!(name, "." | "..") {
                continue;
            }
            let relative_path = if relative.is_empty() {
                name.to_owned()
            } else {
                format!("{relative}/{name}")
            };
            if validate_relative(&relative_path).is_err() {
                continue;
            }
            let metadata = statat(&directory, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ErrorCode::RevisionConflict)?;
            let kind = match FileType::from_raw_mode(metadata.st_mode) {
                FileType::Directory => NativeProjectEntryKind::Directory,
                FileType::RegularFile if metadata.st_nlink == 1 && metadata.st_size >= 0 => {
                    NativeProjectEntryKind::File
                }
                _ => continue,
            };
            let item = NativeProjectEntry {
                name: name.into(),
                relative_path,
                byte_length: (kind == NativeProjectEntryKind::File)
                    .then(|| metadata.st_size.to_string()),
                kind,
            };
            bytes += serde_json::to_vec(&item)
                .map_err(|_| ErrorCode::ResourceExhausted)?
                .len();
            if bytes > 1024 * 1024 {
                return Err(ErrorCode::ResourceExhausted);
            }
            entries.push(item);
        }
        entries.sort_by(|a, b| {
            (a.kind != NativeProjectEntryKind::Directory)
                .cmp(&(b.kind != NativeProjectEntryKind::Directory))
                .then(a.name.cmp(&b.name))
        });
        if entries
            .windows(2)
            .any(|items| items[0].name == items[1].name)
        {
            return Err(ErrorCode::RevisionConflict);
        }
        check()?;
        let current = self.open_directory(relative)?;
        if stamp(
            &current
                .metadata()
                .map_err(|_| ErrorCode::StorageUnavailable)?,
        ) != directory_stamp
            || stamp(
                &directory
                    .metadata()
                    .map_err(|_| ErrorCode::StorageUnavailable)?,
            ) != directory_stamp
        {
            return Err(ErrorCode::RevisionConflict);
        }
        let mut hash = Sha256::new();
        hash.update(directory_stamp.device.to_le_bytes());
        hash.update(directory_stamp.inode.to_le_bytes());
        for value in [
            directory_stamp.modified.0,
            directory_stamp.modified.1,
            directory_stamp.changed.0,
            directory_stamp.changed.1,
        ] {
            hash.update(value.to_le_bytes());
        }
        hash.update(serde_json::to_vec(&entries).map_err(|_| ErrorCode::ResourceExhausted)?);
        check()?;
        Ok(NativeProjectDirectorySnapshot {
            entries,
            revision: format!("{:x}", hash.finalize()),
        })
    }

    pub fn open_file(
        &self,
        relative: &str,
        max_bytes: u64,
    ) -> Result<NativeProjectFile, ErrorCode> {
        validate_relative(relative)?;
        self.check()?;
        let mut directory = self
            .directory
            .try_clone()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        let components: Vec<_> = Path::new(relative).components().collect();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err(ErrorCode::ScopeDenied);
            };
            let last = index + 1 == components.len();
            let file = open_at(&directory, name, !last)?;
            if last {
                let metadata = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
                if !metadata.is_file() || metadata.nlink() != 1 {
                    return Err(ErrorCode::ScopeDenied);
                }
                if metadata.len() > max_bytes {
                    return Err(ErrorCode::ArtifactTooLarge);
                }
                return Ok(NativeProjectFile {
                    file,
                    stamp: stamp(&metadata),
                });
            }
            directory = file;
        }
        Err(ErrorCode::ScopeDenied)
    }

    /// Create a raw artifact beneath this approved project root. The parent
    /// revision is checked before the publisher creates its private sibling
    /// stage file, then the visible namespace is revalidated after the fresh
    /// authorization checkpoint without comparing the stage-altered parent
    /// timestamp to the original revision.
    pub fn create_artifact(
        &self,
        relative_path: &str,
        expected_parent_revision: &str,
        bytes: &[u8],
        mut check: impl FnMut(NativeProjectCheckPhase) -> Result<(), ErrorCode>,
    ) -> Result<NativeArtifactCreated, NativeProjectMutationError> {
        const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(ErrorCode::ArtifactTooLarge.into());
        }
        validate_relative(relative_path)?;
        let path = Path::new(relative_path);
        let parent_relative = path
            .parent()
            .and_then(Path::to_str)
            .ok_or(ErrorCode::ScopeDenied)?;
        let parent_relative = if parent_relative == "." {
            ""
        } else {
            parent_relative
        };
        let leaf = path.file_name().ok_or(ErrorCode::ScopeDenied)?;
        let leaf_name = CString::new(leaf.as_bytes()).map_err(|_| ErrorCode::ScopeDenied)?;

        check(NativeProjectCheckPhase::Progress)?;
        let parent = self.open_directory(parent_relative)?;
        let parent_before = parent
            .metadata()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        let parent_identity = (parent_before.dev(), parent_before.ino());
        let (baseline, snapshot) = capture_namespace(&parent, parent_relative, || {
            check(NativeProjectCheckPhase::Progress)
        })?;
        let parent_after = parent
            .metadata()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if (parent_after.dev(), parent_after.ino()) != parent_identity
            || stamp(&parent_before) != stamp(&parent_after)
            || snapshot.revision != expected_parent_revision
        {
            return Err(ErrorCode::RevisionConflict.into());
        }
        ensure_absent_at(&parent, &leaf_name)?;

        let destination = self.path.join(relative_path);
        let local_file =
            LocalNativeFile::open_no_follow(&destination).map_err(map_local_native_file_error)?;
        if !local_file.is_new() {
            return Err(ErrorCode::RevisionConflict.into());
        }
        let destination_parent = destination.parent().ok_or(ErrorCode::ScopeDenied)?;
        let named_parent = open_absolute_directory(destination_parent)?;
        let named_parent_metadata = named_parent
            .metadata()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if (named_parent_metadata.dev(), named_parent_metadata.ino()) != parent_identity {
            return Err(ErrorCode::RevisionConflict.into());
        }

        let mut phase_check = |phase: NativeProjectCheckPhase| -> Result<(), ErrorCode> {
            match phase {
                NativeProjectCheckPhase::Progress => check(phase),
                NativeProjectCheckPhase::BeforeEffect => check(phase),
                NativeProjectCheckPhase::Validation => {
                    check(phase)?;
                    revalidate_namespace(
                        self,
                        parent_relative,
                        parent_identity,
                        &baseline,
                        &leaf_name,
                        || check(NativeProjectCheckPhase::Validation),
                    )
                }
                // Publication must remain a fast local approval/deadline
                // check: LocalNativeFile has already revalidated its staged
                // name and identity immediately before this checkpoint.
                NativeProjectCheckPhase::Publication => check(phase),
            }
        };
        let disk_revision = match local_file.create_with_phase(bytes, &mut |phase| {
            phase_check(match phase {
                LocalNativeFileCheckPhase::Progress => NativeProjectCheckPhase::Progress,
                LocalNativeFileCheckPhase::BeforeEffect => NativeProjectCheckPhase::BeforeEffect,
                LocalNativeFileCheckPhase::Validation => NativeProjectCheckPhase::Validation,
                LocalNativeFileCheckPhase::Publication => NativeProjectCheckPhase::Publication,
            })
        }) {
            Ok(revision) => revision,
            Err(LocalNativeFilePublishError::Before(LocalNativeFileReadError::File(error))) => {
                return Err(map_local_native_file_error(error).into());
            }
            Err(LocalNativeFilePublishError::Before(LocalNativeFileReadError::Check(error))) => {
                return Err(error.into());
            }
            Err(LocalNativeFilePublishError::Uncertain) => {
                return Err(NativeProjectMutationError::Uncertain);
            }
        };
        Ok(NativeArtifactCreated {
            relative_path: relative_path.to_owned(),
            byte_length: bytes.len() as u64,
            disk_revision,
        })
    }

    pub fn apply(
        &self,
        mutation: NativeProjectMutation,
        mut check: impl FnMut() -> Result<(), ErrorCode>,
    ) -> Result<NativeProjectMutationResult, NativeProjectMutationError> {
        self.apply_with_phase(mutation, |phase| match phase {
            NativeProjectCheckPhase::Progress | NativeProjectCheckPhase::BeforeEffect => check(),
            NativeProjectCheckPhase::Validation | NativeProjectCheckPhase::Publication => Ok(()),
        })
    }

    /// Apply a filesystem mutation with separate authorization and local-only
    /// validation phases. `BeforeEffect` may perform a blocking host upcall;
    /// no filesystem validation should precede the effect without being
    /// repeated with `Validation` after that upcall.
    pub fn apply_with_phase(
        &self,
        mutation: NativeProjectMutation,
        mut check: impl FnMut(NativeProjectCheckPhase) -> Result<(), ErrorCode>,
    ) -> Result<NativeProjectMutationResult, NativeProjectMutationError> {
        match mutation {
            NativeProjectMutation::Create {
                relative_path,
                kind,
                expected_parent_revision,
            } => {
                create(
                    self,
                    &relative_path,
                    &expected_parent_revision,
                    kind,
                    &mut check,
                )?;
                Ok(NativeProjectMutationResult::Created { relative_path })
            }
            NativeProjectMutation::RenameMoveFile {
                relative_path,
                target_relative_path,
                expected_disk_revision,
                expected_parent_revision,
            } => {
                move_file(
                    self,
                    &relative_path,
                    &target_relative_path,
                    &expected_disk_revision,
                    &expected_parent_revision,
                    &mut check,
                )?;
                Ok(NativeProjectMutationResult::FileMoved {
                    relative_path,
                    target_relative_path,
                })
            }
            NativeProjectMutation::RenameMoveDirectory {
                relative_path,
                target_relative_path,
                expected_directory_revision,
                expected_parent_revision,
            } => {
                move_directory(
                    self,
                    &relative_path,
                    &target_relative_path,
                    &expected_directory_revision,
                    &expected_parent_revision,
                    &mut check,
                )?;
                Ok(NativeProjectMutationResult::DirectoryMoved {
                    relative_path,
                    target_relative_path,
                })
            }
            NativeProjectMutation::TrashStage {
                relative_path,
                kind,
                expected_revision,
                expected_parent_revision,
                recovery_root,
                operation_id,
            } => {
                let ticket = crate::trash::stage(
                    self,
                    &relative_path,
                    kind,
                    &expected_revision,
                    &expected_parent_revision,
                    &recovery_root,
                    &operation_id,
                    &mut check,
                )?;
                Ok(NativeProjectMutationResult::TrashStaged { ticket })
            }
        }
    }
}

impl NativeProjectFile {
    pub fn try_clone_file(&self) -> Result<File, ErrorCode> {
        self.file
            .try_clone()
            .map_err(|_| ErrorCode::StorageUnavailable)
    }

    pub fn len(&self) -> u64 {
        self.stamp.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.stamp.bytes == 0
    }

    pub fn check_unchanged(&self) -> Result<(), ErrorCode> {
        let metadata = self
            .file
            .metadata()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if !metadata.is_file() || stamp(&metadata) != self.stamp {
            return Err(ErrorCode::RevisionConflict);
        }
        Ok(())
    }

    pub fn read_bytes(
        mut self,
        limit: u64,
        mut check: impl FnMut() -> Result<(), ErrorCode>,
    ) -> Result<Vec<u8>, ErrorCode> {
        check()?;
        if self.len() > limit || limit > MOVED_FILE_LIMIT {
            return Err(ErrorCode::ResourceExhausted);
        }
        let mut bytes = Vec::with_capacity(self.len() as usize);
        let mut chunk = [0_u8; 65536];
        loop {
            check()?;
            let count = self
                .file
                .read(&mut chunk)
                .map_err(|_| ErrorCode::StorageUnavailable)?;
            if count == 0 {
                break;
            }
            if bytes.len() as u64 + count as u64 > limit {
                return Err(ErrorCode::ResourceExhausted);
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        self.check_unchanged()?;
        check()?;
        if bytes.len() as u64 != self.len() {
            return Err(ErrorCode::RevisionConflict);
        }
        Ok(bytes)
    }
}

/// Shared pinned-descriptor open primitive used by native atomic writers.
pub fn open_file_at(parent: &File, name: &CStr) -> Result<File, ErrorCode> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(ErrorCode::RevisionConflict);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Shared bounded content snapshot primitive for native publishers.
pub fn snapshot_file(
    file: &mut File,
    mut check: impl FnMut() -> Result<(), ErrorCode>,
) -> Result<(String, Metadata), ErrorCode> {
    let before = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(ErrorCode::ScopeDenied);
    }
    if before.len() > FILE_SNAPSHOT_LIMIT {
        return Err(ErrorCode::ResourceExhausted);
    }
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    let mut total = 0;
    loop {
        check()?;
        let count = file
            .read(&mut bytes)
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > FILE_SNAPSHOT_LIMIT {
            return Err(ErrorCode::ResourceExhausted);
        }
        hash.update(&bytes[..count]);
    }
    let after = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
    if stamp(&before) != stamp(&after) || total != before.len() {
        return Err(ErrorCode::RevisionConflict);
    }
    Ok((format!("{:x}", hash.finalize()), before))
}

fn ensure_absent_at(parent: &File, name: &CStr) -> Result<(), ErrorCode> {
    use rustix::fs::{AtFlags, statat};

    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        _ => Err(ErrorCode::RevisionConflict),
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NamespaceIdentity {
    name: Vec<u8>,
    mode: u32,
    device: u64,
    inode: u64,
    size: i64,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn capture_namespace(
    directory: &File,
    relative: &str,
    mut check: impl FnMut() -> Result<(), ErrorCode>,
) -> Result<(Vec<NamespaceIdentity>, NativeProjectDirectorySnapshot), ErrorCode> {
    use rustix::fs::{AtFlags, Dir, FileType, statat};

    let before = directory
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    let directory_stamp = stamp(&before);
    let stream = Dir::read_from(directory).map_err(|_| ErrorCode::StorageUnavailable)?;
    let mut identities = Vec::new();
    let mut visible = Vec::new();
    let mut serialized_bytes = 0;
    for (visited, entry) in stream.enumerate() {
        check()?;
        if visited >= 10002 {
            return Err(ErrorCode::ResourceExhausted);
        }
        let entry = entry.map_err(|_| ErrorCode::StorageUnavailable)?;
        let raw_name = entry.file_name();
        let name_bytes = raw_name.to_bytes();
        if matches!(name_bytes, b"." | b"..") || lomi_fs_policy::is_private_staging_name(name_bytes)
        {
            continue;
        }
        let metadata = statat(directory, raw_name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ErrorCode::RevisionConflict)?;
        identities.push(NamespaceIdentity {
            name: name_bytes.to_vec(),
            mode: metadata.st_mode as u32,
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
            size: metadata.st_size as i64,
            links: metadata.st_nlink as u64,
            modified: (metadata.st_mtime as i64, metadata.st_mtime_nsec as i64),
            changed: (metadata.st_ctime as i64, metadata.st_ctime_nsec as i64),
        });

        let Ok(name) = raw_name.to_str() else {
            continue;
        };
        let relative_path = if relative.is_empty() {
            name.to_owned()
        } else {
            format!("{relative}/{name}")
        };
        if validate_relative(&relative_path).is_err() {
            continue;
        }
        let kind = match FileType::from_raw_mode(metadata.st_mode) {
            FileType::Directory => NativeProjectEntryKind::Directory,
            FileType::RegularFile if metadata.st_nlink == 1 && metadata.st_size >= 0 => {
                NativeProjectEntryKind::File
            }
            _ => continue,
        };
        let item = NativeProjectEntry {
            name: name.to_owned(),
            relative_path,
            byte_length: (kind == NativeProjectEntryKind::File)
                .then(|| metadata.st_size.to_string()),
            kind,
        };
        serialized_bytes += serde_json::to_vec(&item)
            .map_err(|_| ErrorCode::ResourceExhausted)?
            .len();
        if serialized_bytes > 1024 * 1024 {
            return Err(ErrorCode::ResourceExhausted);
        }
        visible.push(item);
    }
    identities.sort();
    visible.sort_by(|a, b| {
        (a.kind != NativeProjectEntryKind::Directory)
            .cmp(&(b.kind != NativeProjectEntryKind::Directory))
            .then(a.name.cmp(&b.name))
    });
    if visible
        .windows(2)
        .any(|items| items[0].name == items[1].name)
    {
        return Err(ErrorCode::RevisionConflict);
    }
    check()?;
    let after = directory
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    if stamp(&before) != stamp(&after) {
        return Err(ErrorCode::RevisionConflict);
    }
    let mut hash = Sha256::new();
    hash.update(directory_stamp.device.to_le_bytes());
    hash.update(directory_stamp.inode.to_le_bytes());
    for value in [
        directory_stamp.modified.0,
        directory_stamp.modified.1,
        directory_stamp.changed.0,
        directory_stamp.changed.1,
    ] {
        hash.update(value.to_le_bytes());
    }
    hash.update(serde_json::to_vec(&visible).map_err(|_| ErrorCode::ResourceExhausted)?);
    Ok((
        identities,
        NativeProjectDirectorySnapshot {
            entries: visible,
            revision: format!("{:x}", hash.finalize()),
        },
    ))
}

fn revalidate_namespace(
    project: &NativeProjectDirectory,
    parent_relative: &str,
    expected_parent_identity: (u64, u64),
    expected: &[NamespaceIdentity],
    target_name: &CStr,
    mut check: impl FnMut() -> Result<(), ErrorCode>,
) -> Result<(), ErrorCode> {
    project.check()?;
    check()?;
    let parent = project.open_directory(parent_relative)?;
    let metadata = parent
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    if (metadata.dev(), metadata.ino()) != expected_parent_identity {
        return Err(ErrorCode::RevisionConflict);
    }
    let (current, _) = capture_namespace(&parent, parent_relative, &mut check)?;
    if current != expected {
        return Err(ErrorCode::RevisionConflict);
    }
    ensure_absent_at(&parent, target_name)?;
    let named_parent = project.open_directory(parent_relative)?;
    let named_metadata = named_parent
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    if (named_metadata.dev(), named_metadata.ino()) != expected_parent_identity {
        return Err(ErrorCode::RevisionConflict);
    }
    Ok(())
}

fn map_local_native_file_error(error: LocalNativeFileError) -> ErrorCode {
    match error {
        LocalNativeFileError::NotFound => ErrorCode::TargetNotFound,
        LocalNativeFileError::Changed | LocalNativeFileError::Exists => ErrorCode::RevisionConflict,
        LocalNativeFileError::Protected | LocalNativeFileError::Invalid => ErrorCode::ScopeDenied,
        LocalNativeFileError::Unsupported => ErrorCode::HostUnqualified,
        LocalNativeFileError::Limit => ErrorCode::ResourceExhausted,
        LocalNativeFileError::Io => ErrorCode::StorageUnavailable,
    }
}

fn create(
    project: &NativeProjectDirectory,
    relative: &str,
    expected_parent_revision: &str,
    kind: NativeProjectEntryKind,
    check: &mut impl FnMut(NativeProjectCheckPhase) -> Result<(), ErrorCode>,
) -> Result<(), NativeProjectMutationError> {
    validate_relative(relative)?;
    let path = Path::new(relative);
    let parent_name = path
        .parent()
        .and_then(Path::to_str)
        .ok_or(ErrorCode::ScopeDenied)?;
    let leaf = path.file_name().ok_or(ErrorCode::ScopeDenied)?;
    let leaf_name = CString::new(leaf.as_bytes()).map_err(|_| ErrorCode::ScopeDenied)?;
    check(NativeProjectCheckPhase::Progress)?;
    let parent = project.open_directory(parent_name)?;
    let metadata = parent
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    let same_parent = || {
        project.check()?;
        let current = project
            .open_directory(parent_name)?
            .metadata()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if (current.dev(), current.ino()) != (metadata.dev(), metadata.ino()) {
            return Err(ErrorCode::RevisionConflict);
        }
        Ok(())
    };
    if project
        .list(parent_name, || check(NativeProjectCheckPhase::Progress))?
        .revision
        != expected_parent_revision
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    check(NativeProjectCheckPhase::Progress)?;
    same_parent()?;
    check(NativeProjectCheckPhase::BeforeEffect)?;
    if project
        .list(parent_name, || check(NativeProjectCheckPhase::Validation))?
        .revision
        != expected_parent_revision
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    same_parent()?;
    ensure_absent_at(&parent, &leaf_name)?;
    check(NativeProjectCheckPhase::Publication)?;
    use rustix::fs::{Mode, OFlags, mkdirat, openat};
    let created: Option<File> = match kind {
        NativeProjectEntryKind::File => Some(
            openat(
                &parent,
                leaf,
                OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::WRONLY,
                Mode::from_raw_mode(0o600),
            )
            .map(File::from)
            .map_err(before)?,
        ),
        NativeProjectEntryKind::Directory => {
            mkdirat(&parent, &leaf_name, Mode::from_raw_mode(0o700)).map_err(before)?;
            None
        }
    };
    if let Some(file) = created {
        file.sync_all()
            .map_err(|_| NativeProjectMutationError::Uncertain)?;
    } else {
        let created: File = openat(
            &parent,
            &leaf_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| NativeProjectMutationError::Uncertain)?;
        created
            .sync_all()
            .map_err(|_| NativeProjectMutationError::Uncertain)?;
    }
    parent
        .sync_all()
        .map_err(|_| NativeProjectMutationError::Uncertain)?;
    same_parent().map_err(|_| NativeProjectMutationError::Uncertain)?;
    Ok(())
}

fn move_file(
    project: &NativeProjectDirectory,
    source: &str,
    destination: &str,
    expected_disk_revision: &str,
    expected_parent_revision: &str,
    check: &mut impl FnMut(NativeProjectCheckPhase) -> Result<(), ErrorCode>,
) -> Result<(), NativeProjectMutationError> {
    for path in [source, destination] {
        validate_relative(path)?;
    }
    if source == destination {
        return Err(ErrorCode::RevisionConflict.into());
    }
    check(NativeProjectCheckPhase::Progress)?;
    let source = Path::new(source);
    let destination = Path::new(destination);
    let source_parent_name = source
        .parent()
        .and_then(Path::to_str)
        .ok_or(ErrorCode::ScopeDenied)?;
    let destination_parent_name = destination
        .parent()
        .and_then(Path::to_str)
        .ok_or(ErrorCode::ScopeDenied)?;
    let source_name = CString::new(source.file_name().ok_or(ErrorCode::ScopeDenied)?.as_bytes())
        .map_err(|_| ErrorCode::ScopeDenied)?;
    let destination_name = CString::new(
        destination
            .file_name()
            .ok_or(ErrorCode::ScopeDenied)?
            .as_bytes(),
    )
    .map_err(|_| ErrorCode::ScopeDenied)?;
    let source_parent = project.open_directory(source_parent_name)?;
    let destination_parent = project.open_directory(destination_parent_name)?;
    let parent_identity = |file: &File| -> Result<_, ErrorCode> {
        let metadata = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
        Ok((metadata.dev(), metadata.ino()))
    };
    let source_identity = parent_identity(&source_parent)?;
    let destination_identity = parent_identity(&destination_parent)?;
    let verify_parents = || {
        project.check()?;
        if parent_identity(&project.open_directory(source_parent_name)?)? != source_identity
            || parent_identity(&project.open_directory(destination_parent_name)?)?
                != destination_identity
        {
            return Err(ErrorCode::RevisionConflict);
        }
        Ok(())
    };
    if project
        .list(destination_parent_name, || {
            check(NativeProjectCheckPhase::Progress)
        })?
        .revision
        != expected_parent_revision
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    let mut original = open_file_at(&source_parent, &source_name)?;
    if original
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?
        .len()
        > MOVED_FILE_LIMIT
    {
        return Err(ErrorCode::ResourceExhausted.into());
    }
    let (revision, metadata) =
        snapshot_file(&mut original, || check(NativeProjectCheckPhase::Progress))?;
    if revision != expected_disk_revision {
        return Err(ErrorCode::RevisionConflict.into());
    }
    let (current_revision, current_metadata) =
        snapshot_file(&mut open_file_at(&source_parent, &source_name)?, || {
            check(NativeProjectCheckPhase::Progress)
        })?;
    if current_revision != revision || stamp_file(&metadata) != stamp_file(&current_metadata) {
        return Err(ErrorCode::RevisionConflict.into());
    }
    let source_stamp = stamp_file(&metadata);
    let approved_file_identity = (metadata.dev(), metadata.ino());
    check(NativeProjectCheckPhase::Progress)?;
    verify_parents()?;
    check(NativeProjectCheckPhase::BeforeEffect)?;
    if project
        .list(destination_parent_name, || {
            check(NativeProjectCheckPhase::Validation)
        })?
        .revision
        != expected_parent_revision
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    verify_parents()?;
    let mut validated_source = open_file_at(&source_parent, &source_name)?;
    if validated_source
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?
        .len()
        > MOVED_FILE_LIMIT
    {
        return Err(ErrorCode::ResourceExhausted.into());
    }
    let (validated_revision, validated_metadata) = snapshot_file(&mut validated_source, || {
        check(NativeProjectCheckPhase::Validation)
    })?;
    if validated_revision != expected_disk_revision
        || stamp_file(&validated_metadata) != source_stamp
        || (validated_metadata.dev(), validated_metadata.ino()) != approved_file_identity
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    let named_source = open_file_at(&source_parent, &source_name)?;
    let named_metadata = named_source
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    if stamp_file(&named_metadata) != source_stamp
        || (named_metadata.dev(), named_metadata.ino()) != approved_file_identity
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    verify_parents()?;
    ensure_absent_at(&destination_parent, &destination_name)?;
    check(NativeProjectCheckPhase::Publication)?;
    rename_exclusive(
        &source_parent,
        &source_name,
        &destination_parent,
        &destination_name,
    )?;
    source_parent
        .sync_all()
        .map_err(|_| NativeProjectMutationError::Uncertain)?;
    destination_parent
        .sync_all()
        .map_err(|_| NativeProjectMutationError::Uncertain)?;
    verify_parents().map_err(|_| NativeProjectMutationError::Uncertain)?;
    let moved = open_file_at(&destination_parent, &destination_name)
        .map_err(|_| NativeProjectMutationError::Uncertain)?
        .metadata()
        .map_err(|_| NativeProjectMutationError::Uncertain)?;
    if (moved.dev(), moved.ino()) != (metadata.dev(), metadata.ino()) {
        return Err(NativeProjectMutationError::Uncertain);
    }
    Ok(())
}

fn move_directory(
    project: &NativeProjectDirectory,
    source: &str,
    destination: &str,
    expected_directory_revision: &str,
    expected_parent_revision: &str,
    check: &mut impl FnMut(NativeProjectCheckPhase) -> Result<(), ErrorCode>,
) -> Result<(), NativeProjectMutationError> {
    for path in [source, destination] {
        validate_relative(path)?;
    }
    if source == destination || destination.starts_with(&format!("{source}/")) {
        return Err(ErrorCode::ScopeDenied.into());
    }
    check(NativeProjectCheckPhase::Progress)?;
    let source_path = Path::new(source);
    let destination_path = Path::new(destination);
    let source_parent_name = source_path
        .parent()
        .and_then(Path::to_str)
        .ok_or(ErrorCode::ScopeDenied)?;
    let destination_parent_name = destination_path
        .parent()
        .and_then(Path::to_str)
        .ok_or(ErrorCode::ScopeDenied)?;
    let source_name = CString::new(
        source_path
            .file_name()
            .ok_or(ErrorCode::ScopeDenied)?
            .as_bytes(),
    )
    .map_err(|_| ErrorCode::ScopeDenied)?;
    let destination_name = CString::new(
        destination_path
            .file_name()
            .ok_or(ErrorCode::ScopeDenied)?
            .as_bytes(),
    )
    .map_err(|_| ErrorCode::ScopeDenied)?;
    let source_parent = project.open_directory(source_parent_name)?;
    let destination_parent = project.open_directory(destination_parent_name)?;
    let directory = project.open_directory(source)?;
    let identity = |file: &File| -> Result<_, ErrorCode> {
        let metadata = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
        Ok((metadata.dev(), metadata.ino()))
    };
    let source_parent_identity = identity(&source_parent)?;
    let destination_parent_identity = identity(&destination_parent)?;
    let source_identity = identity(&directory)?;
    let verify_parents = || {
        project.check()?;
        if identity(&project.open_directory(source_parent_name)?)? != source_parent_identity
            || identity(&project.open_directory(destination_parent_name)?)?
                != destination_parent_identity
        {
            return Err(ErrorCode::RevisionConflict);
        }
        Ok(())
    };
    if project
        .list(source, || check(NativeProjectCheckPhase::Progress))?
        .revision
        != expected_directory_revision
        || project
            .list(destination_parent_name, || {
                check(NativeProjectCheckPhase::Progress)
            })?
            .revision
            != expected_parent_revision
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    check(NativeProjectCheckPhase::Progress)?;
    verify_parents()?;
    if identity(&project.open_directory(source)?)? != source_identity {
        return Err(ErrorCode::RevisionConflict.into());
    }
    check(NativeProjectCheckPhase::BeforeEffect)?;
    if project
        .list(source, || check(NativeProjectCheckPhase::Validation))?
        .revision
        != expected_directory_revision
        || project
            .list(destination_parent_name, || {
                check(NativeProjectCheckPhase::Validation)
            })?
            .revision
            != expected_parent_revision
    {
        return Err(ErrorCode::RevisionConflict.into());
    }
    verify_parents()?;
    if identity(&project.open_directory(source)?)? != source_identity {
        return Err(ErrorCode::RevisionConflict.into());
    }
    ensure_absent_at(&destination_parent, &destination_name)?;
    check(NativeProjectCheckPhase::Publication)?;
    rename_exclusive(
        &source_parent,
        &source_name,
        &destination_parent,
        &destination_name,
    )?;
    source_parent
        .sync_all()
        .map_err(|_| NativeProjectMutationError::Uncertain)?;
    destination_parent
        .sync_all()
        .map_err(|_| NativeProjectMutationError::Uncertain)?;
    verify_parents().map_err(|_| NativeProjectMutationError::Uncertain)?;
    if identity(
        &project
            .open_directory(destination)
            .map_err(|_| NativeProjectMutationError::Uncertain)?,
    )
    .map_err(|_| NativeProjectMutationError::Uncertain)?
        != source_identity
    {
        return Err(NativeProjectMutationError::Uncertain);
    }
    Ok(())
}

/// Rename an entry between pinned directories without replacing a target.
pub fn rename_exclusive(
    source: &File,
    source_name: &CStr,
    destination: &File,
    destination_name: &CStr,
) -> Result<(), NativeProjectMutationError> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use rustix::fs::{RenameFlags, renameat_with};
        renameat_with(
            source,
            source_name,
            destination,
            destination_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            if matches!(
                error,
                rustix::io::Errno::XDEV | rustix::io::Errno::NOSYS | rustix::io::Errno::NOTSUP
            ) {
                NativeProjectMutationError::Before(ErrorCode::UnsupportedCapability)
            } else {
                before(error)
            }
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (source, source_name, destination, destination_name);
        Err(ErrorCode::HostUnqualified.into())
    }
}

fn before(error: rustix::io::Errno) -> NativeProjectMutationError {
    NativeProjectMutationError::Before(map_mutation_errno(error))
}

fn map_mutation_errno(error: rustix::io::Errno) -> ErrorCode {
    if error == rustix::io::Errno::EXIST {
        ErrorCode::RevisionConflict
    } else if error == rustix::io::Errno::ACCESS || error == rustix::io::Errno::PERM {
        ErrorCode::ScopeDenied
    } else {
        ErrorCode::StorageUnavailable
    }
}
