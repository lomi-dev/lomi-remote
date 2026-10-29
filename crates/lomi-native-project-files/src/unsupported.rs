use crate::{
    NativeArtifactCreated, NativeProjectCheckPhase, NativeProjectDirectory,
    NativeProjectDirectorySnapshot, NativeProjectErrorCode as ErrorCode, NativeProjectFile,
    NativeProjectMutation, NativeProjectMutationError, NativeProjectMutationResult,
    NativeProjectStagedTrash, NativeProjectTrashTicket,
};
use std::{
    ffi::CStr,
    fs::{File, Metadata},
    path::Path,
};

fn unsupported() -> ErrorCode {
    ErrorCode::HostUnqualified
}

impl NativeProjectDirectory {
    pub fn open(path: &Path) -> Result<Self, ErrorCode> {
        let _ = path;
        Err(unsupported())
    }

    pub fn canonical_path(&self) -> &Path {
        &self.path
    }

    pub fn check(&self) -> Result<(), ErrorCode> {
        Err(unsupported())
    }

    pub fn open_directory(&self, relative: &str) -> Result<File, ErrorCode> {
        let _ = relative;
        Err(unsupported())
    }

    pub fn list(
        &self,
        relative: &str,
        check: impl FnMut() -> Result<(), ErrorCode>,
    ) -> Result<NativeProjectDirectorySnapshot, ErrorCode> {
        let _ = (relative, check);
        Err(unsupported())
    }

    pub fn open_file(
        &self,
        relative: &str,
        max_bytes: u64,
    ) -> Result<NativeProjectFile, ErrorCode> {
        let _ = (relative, max_bytes);
        Err(unsupported())
    }

    pub fn create_artifact(
        &self,
        relative_path: &str,
        expected_parent_revision: &str,
        bytes: &[u8],
        check: impl FnMut(NativeProjectCheckPhase) -> Result<(), ErrorCode>,
    ) -> Result<NativeArtifactCreated, NativeProjectMutationError> {
        let _ = (relative_path, expected_parent_revision, bytes, check);
        Err(unsupported().into())
    }

    pub fn apply(
        &self,
        mutation: NativeProjectMutation,
        _check: impl FnMut() -> Result<(), ErrorCode>,
    ) -> Result<NativeProjectMutationResult, NativeProjectMutationError> {
        self.apply_with_phase(mutation, |_| Ok(()))
    }

    pub fn apply_with_phase(
        &self,
        mutation: NativeProjectMutation,
        _check: impl FnMut(NativeProjectCheckPhase) -> Result<(), ErrorCode>,
    ) -> Result<NativeProjectMutationResult, NativeProjectMutationError> {
        let _ = mutation;
        Err(unsupported().into())
    }
}

impl NativeProjectFile {
    pub fn try_clone_file(&self) -> Result<File, ErrorCode> {
        Err(unsupported())
    }

    pub fn len(&self) -> u64 {
        self.stamp.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.stamp.bytes == 0
    }

    pub fn check_unchanged(&self) -> Result<(), ErrorCode> {
        Err(unsupported())
    }

    pub fn read_bytes(
        self,
        limit: u64,
        check: impl FnMut() -> Result<(), ErrorCode>,
    ) -> Result<Vec<u8>, ErrorCode> {
        let _ = (self, limit, check);
        Err(unsupported())
    }
}

pub fn open_absolute_directory(path: &Path) -> Result<File, ErrorCode> {
    let _ = path;
    Err(unsupported())
}

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

pub fn open_file_at(parent: &File, name: &CStr) -> Result<File, ErrorCode> {
    let _ = (parent, name);
    Err(unsupported())
}

pub fn snapshot_file(
    file: &mut File,
    check: impl FnMut() -> Result<(), ErrorCode>,
) -> Result<(String, Metadata), ErrorCode> {
    let _ = (file, check);
    Err(unsupported())
}

pub fn stamp_file(metadata: &Metadata) -> (u64, u64, u64, u64, i64, i64, i64, i64) {
    (0, 0, metadata.len(), 0, 0, 0, 0, 0)
}

pub fn rename_exclusive(
    source: &File,
    source_name: &CStr,
    destination: &File,
    destination_name: &CStr,
) -> Result<(), NativeProjectMutationError> {
    let _ = (source, source_name, destination, destination_name);
    Err(unsupported().into())
}

pub fn from_ticket(
    ticket: NativeProjectTrashTicket,
) -> Result<NativeProjectStagedTrash, NativeProjectMutationError> {
    let _ = ticket;
    Err(unsupported().into())
}

impl NativeProjectStagedTrash {
    pub fn from_ticket(
        ticket: NativeProjectTrashTicket,
    ) -> Result<Self, NativeProjectMutationError> {
        from_ticket(ticket)
    }

    pub fn ticket(&self) -> NativeProjectTrashTicket {
        self.ticket.clone()
    }

    pub fn path(&self) -> &Path {
        &self.ticket.staged_path
    }

    pub fn finish(
        self,
        _trash: impl FnOnce(&Path) -> Result<(), ErrorCode>,
    ) -> Result<(), NativeProjectMutationError> {
        Err(unsupported().into())
    }
}
