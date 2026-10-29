//! Handle-relative publisher for one owner-local Git symlink restore.
//!
//! Git for Windows represents symlinks with NTFS symbolic-link reparse data.
//! The LocalSystem broker only applies that data to a new private temp object;
//! this module chooses the target kind in the ordinary owner process and does
//! all publication through the selected worktree's pinned directory handles.

use super::owner_git::DesktopGitMetadataAuthority;
use super::*;
use crate::desktop_git::GitDesktopFileTarget;
use std::path::PathBuf;
use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

const MAX_DESKTOP_GIT_LINK_BYTES: usize = 64 * 1024;

struct SymlinkTarget {
    substitute: Vec<u16>,
    print: Vec<u16>,
    relative: bool,
    directory: bool,
}

struct StagedSymlinkTemp {
    broker: BrokerSession,
    temp: BrokerSymlinkTemp,
    parent: OwnedHandle,
    name: String,
    security_handle: Option<OwnedHandle>,
    linked: bool,
}

impl StagedSymlinkTemp {
    fn new(parent: &OwnedHandle, name: &str, target: &SymlinkTarget) -> Result<Self> {
        let broker = operation_broker_session().map_err(git_native_security_error)?;
        let temp = broker
            .create_symlink_temp(
                parent,
                name,
                &target.substitute,
                &target.print,
                target.relative,
                target.directory,
            )
            .map_err(git_native_security_error)?;
        let parent = parent.try_clone().map_err(map_os)?;
        Ok(Self {
            broker,
            temp,
            parent,
            name: name.to_owned(),
            security_handle: None,
            linked: true,
        })
    }

    fn temp(&self) -> &BrokerSymlinkTemp {
        &self.temp
    }

    fn prepare_security(
        &mut self,
        directory: bool,
        source: Option<&CapturedGitLeafSecurity>,
    ) -> Result<RawHandle> {
        self.temp
            .verify_private_dacl(self.temp.file())
            .map_err(|_| Error::Changed)?;
        if let Some(source) = source {
            source
                .broker_source
                .as_ref()
                .ok_or(Error::Changed)?
                .finalize(self.temp.token())
                .map_err(git_native_security_error)?;
        }
        let options = if directory {
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC
        } else {
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC
        };
        let name = self.name.encode_utf16().collect::<Vec<_>>();
        let handle = open_relative_with_share(
            self.parent.as_raw_handle(),
            &name,
            DELETE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | FILE_READ_EA
                | FILE_WRITE_EA
                | READ_CONTROL
                | WRITE_DAC
                | WRITE_OWNER
                | SYNCHRONIZE,
            FILE_OPEN,
            options,
            0,
            FILE_SHARE_READ,
            false,
        )?;
        let info = info_of(handle.as_raw_handle())?;
        let temp_info = info_of(self.temp.file().as_raw_handle())?;
        if info.ident != temp_info.ident
            || info.nlink != 1
            || kind_of(&info) != Kind::Symlink
            || (info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        {
            return Err(Error::Changed);
        }
        if let Some(source) = source {
            apply_git_leaf_security(
                handle.as_raw_handle(),
                &source.security,
                GitPullNodeKind::Symlink,
            )?;
        }
        let checked = File::from(handle.try_clone().map_err(map_os)?);
        self.temp
            .verify_file(&checked)
            .map_err(|_| Error::Changed)?;
        self.security_handle = Some(handle);
        Ok(self.security_handle.as_ref().unwrap().as_raw_handle())
    }

    fn security_handle(&self) -> Result<RawHandle> {
        self.security_handle
            .as_ref()
            .map(|handle| handle.as_raw_handle())
            .ok_or(Error::Changed)
    }

    fn security_file(&self) -> Result<File> {
        self.security_handle
            .as_ref()
            .ok_or(Error::Changed)?
            .try_clone()
            .map(File::from)
            .map_err(map_os)
    }

    fn release_after_publish(&mut self) -> bool {
        let released = self.broker.try_release_temp(self.temp.token()).is_ok();
        // A release failure happens after the namespace rename has succeeded.
        // Never let Drop delete the published link while trying to clean up.
        self.linked = false;
        released
    }

    fn mark_published(&mut self) {
        // A post-rename failure is an uncertain published result; Drop must
        // never delete the object after its name has become public.
        self.linked = false;
    }

    fn finalize_published_security(&mut self, published: &File) -> bool {
        self.mark_published();
        self.broker
            .finalize_published_temp(self.temp.token(), published)
            .and_then(|()| self.broker.try_release_temp(self.temp.token()))
            .is_ok()
    }
}

impl Drop for StagedSymlinkTemp {
    fn drop(&mut self) {
        if self.linked {
            if let Some(handle) = self.security_handle.take() {
                let expected = info_of(self.temp.file().as_raw_handle()).ok();
                let name = self.name.encode_utf16().collect::<Vec<_>>();
                let named = open_attributes(self.parent.as_raw_handle(), &name).ok();
                if let (Some(expected), Some((named_handle, named_info))) = (expected, named)
                    && expected.ident == named_info.ident
                    && info_of(handle.as_raw_handle())
                        .is_ok_and(|held| held.ident == expected.ident && held.nlink == 1)
                {
                    let verified = handle
                        .try_clone()
                        .ok()
                        .is_some_and(|clone| self.temp.verify_file(&File::from(clone)).is_ok());
                    drop(named_handle);
                    if verified {
                        let _ = delete_entry(handle.as_raw_handle());
                        let _ = sync_git_directory(self.parent.as_raw_handle());
                    }
                }
                drop(handle);
            }
            self.broker.discard_temp(self.temp.token());
        }
    }
}

pub(super) fn publish_symlink(
    root: &FileRoot,
    target: &GitDesktopFileTarget,
    authority: &DesktopGitMetadataAuthority<'_>,
    mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    let _broker_scope = BrokerOperationScope::enter();
    let file = &target.file;
    root.validate_pull_worktree_path(file)?;
    validate_repository_path(root, target.repository, file)?;
    if file.kind != GitPullNodeKind::Symlink
        || file.executable
        || file.expected.kind == Some(GitPullNodeKind::Directory)
    {
        return Err(Error::Unsupported);
    }
    let contents = file.contents.as_deref().ok_or(Error::Invalid)?;
    if contents.is_empty() || contents.contains(&0) || contents.len() > MAX_DESKTOP_GIT_LINK_BYTES {
        return Err(Error::Invalid);
    }
    if !check(LocalNativeFileCheckPhase::Progress)
        || !check(LocalNativeFileCheckPhase::BeforeEffect)
    {
        return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
    }

    let _metadata_guards = authority.lock(root)?;
    if !check(LocalNativeFileCheckPhase::Validation) {
        return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
    }
    let mut visible = false;
    let result = (|| -> Result<GitPublishOutcome> {
        authority.check(root, target)?;
        root.validate_pull_worktree_path(file)?;
        validate_repository_path(root, target.repository, file)?;
        root.check_git_pull_precondition(&file.expected, true)?;

        let (base, base_info) = root.open_dir(file.parent)?;
        if kind_of(&base_info) != Kind::Directory {
            return Err(Error::Changed);
        }
        let mut created_dirs = Vec::new();
        let target_parent = create_git_target_parent(
            &base,
            &file.parent_suffix,
            &mut created_dirs,
            file.parent,
            &[],
            &mut || check(LocalNativeFileCheckPhase::Progress),
            |identity| root.touch(identity),
            || visible = true,
        )?;
        let parent_info = info_of(target_parent.as_raw_handle())?;
        if kind_of(&parent_info) != Kind::Directory {
            return Err(Error::Changed);
        }
        let target_name = component(&file.name)?;
        let mut source_security =
            git_named_leaf_security(target_parent.as_raw_handle(), &target_name)?;
        if source_security.is_some() != file.expected.entry.is_some()
            || source_security
                .as_ref()
                .is_some_and(|source| Some(source.security.kind) != file.expected.kind)
        {
            return Err(Error::Changed);
        }
        if !check(LocalNativeFileCheckPhase::Progress) {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }
        let link_target = prepare_symlink_target(root, file, contents)?;

        let mut stage_container = GitPrivateStageDirectory::create(&target_parent)?;
        let stage_parent = stage_container.handle()?;
        let temp_name = format!("lomi-link-{}.tmp", uuid::Uuid::new_v4());
        let mut staged = StagedSymlinkTemp::new(stage_parent, &temp_name, &link_target)?;
        let temp_info = info_of(staged.temp().file().as_raw_handle())?;
        if kind_of(&temp_info) != Kind::Symlink
            || temp_info.nlink != 1
            || (temp_info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != link_target.directory
        {
            return Err(Error::Changed);
        }
        let temp_identity = temp_info.ident;
        staged.prepare_security(link_target.directory, source_security.as_ref())?;

        if !check(LocalNativeFileCheckPhase::Progress) {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }
        authority.check(root, target)?;
        root.validate_pull_worktree_path(file)?;
        validate_repository_path(root, target.repository, file)?;
        root.check_git_pull_precondition(&file.expected, true)?;
        let (final_base, final_base_info) = root.open_dir(file.parent)?;
        if kind_of(&final_base_info) != Kind::Directory || final_base_info.ident != base_info.ident
        {
            return Err(Error::Changed);
        }
        let final_parent = if file.parent_suffix.is_empty() {
            final_base.try_clone().map_err(map_os)?
        } else {
            verify_git_target_parent(&final_base, &file.parent_suffix, &created_dirs)?
        };
        let final_parent_info = info_of(final_parent.as_raw_handle())?;
        if kind_of(&final_parent_info) != Kind::Directory
            || final_parent_info.ident != parent_info.ident
        {
            return Err(Error::Changed);
        }
        if !file.parent_suffix.is_empty() {
            match open_attributes(final_parent.as_raw_handle(), &target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Err(Error::Changed),
                Err(error) => return Err(error),
            }
        }

        let rename_handle = staged.security_handle()?;
        let rename_info = info_of(rename_handle)?;
        if rename_info.ident != temp_identity
            || kind_of(&rename_info) != Kind::Symlink
            || rename_info.nlink != 1
            || (rename_info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != link_target.directory
        {
            return Err(Error::Changed);
        }
        if staged.temp().verify_file(&staged.security_file()?).is_err() {
            return Err(Error::Changed);
        }
        if !check(LocalNativeFileCheckPhase::Publication) {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }
        check_git_named_leaf_security(
            final_parent.as_raw_handle(),
            &target_name,
            source_security.as_ref(),
        )?;
        let expected_leaf = source_security
            .as_ref()
            .map(|source| source.security.clone());

        authority.check(root, target)?;
        root.validate_pull_worktree_path(file)?;
        validate_repository_path(root, target.repository, file)?;
        root.check_git_pull_precondition(&file.expected, true)?;
        let (last_base, last_base_info) = root.open_dir(file.parent)?;
        if kind_of(&last_base_info) != Kind::Directory || last_base_info.ident != base_info.ident {
            return Err(Error::Changed);
        }
        let last_parent = if file.parent_suffix.is_empty() {
            last_base.try_clone().map_err(map_os)?
        } else {
            verify_git_target_parent(&last_base, &file.parent_suffix, &created_dirs)?
        };
        let last_parent_info = info_of(last_parent.as_raw_handle())?;
        if kind_of(&last_parent_info) != Kind::Directory
            || last_parent_info.ident != final_parent_info.ident
            || info_of(rename_handle)?.ident != temp_identity
            || staged.temp().verify_file(&staged.security_file()?).is_err()
        {
            return Err(Error::Changed);
        }
        if file.parent_suffix.is_empty() {
            root.check_git_pull_precondition(&file.expected, true)?;
        } else {
            match open_attributes(last_parent.as_raw_handle(), &target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Err(Error::Changed),
                Err(error) => return Err(error),
            }
        }

        let directory_link = expected_leaf.as_ref().is_some_and(|source| {
            source.kind == GitPullNodeKind::Symlink
                && source.info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        });
        let target_guard = if let Some(source) = expected_leaf.as_ref() {
            let (access, options, share) = if directory_link {
                (
                    DELETE | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
                    FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
                    FILE_SHARE_READ,
                )
            } else {
                (
                    FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
                    FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
                    FILE_SHARE_READ | FILE_SHARE_DELETE,
                )
            };
            let target = open_relative_with_share(
                last_parent.as_raw_handle(),
                &target_name,
                access,
                FILE_OPEN,
                options,
                0,
                share,
                false,
            )?;
            check_git_leaf_security_value(target.as_raw_handle(), source)?;
            if directory_link
                && info_of(target.as_raw_handle())?.attributes & FILE_ATTRIBUTE_READONLY != 0
            {
                return Err(Error::Unsupported);
            }
            Some(target)
        } else {
            match open_attributes(last_parent.as_raw_handle(), &target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Err(Error::Changed),
                Err(error) => return Err(error),
            }
            None
        };

        // Recheck the broker-bound security snapshot while the final target
        // handle is already open. The share mode blocks target writes; release
        // both retained source handles before deletion so classic disposition
        // semantics can remove the old name. All local final checks follow the
        // broker calls below.
        if let Some(source) = source_security.as_ref()
            && let Some(broker_source) = source.broker_source.as_ref()
        {
            broker_source.recheck().map_err(git_native_security_error)?;
        }
        if let Some(source) = source_security.as_mut()
            && let Some(broker_source) = source.broker_source.as_mut()
        {
            broker_source.release();
        }
        drop(source_security);

        // Source broker recheck/release above is the final pre-effect IPC.
        // Refresh authorization after it, then reattach every namespace and
        // staged-object check locally before the first unlink or rename.
        if !check(LocalNativeFileCheckPhase::Publication) {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }
        authority.check(root, target)?;
        root.validate_pull_worktree_path(file)?;
        validate_repository_path(root, target.repository, file)?;
        root.check_git_pull_precondition(&file.expected, true)?;
        let (last_base, last_base_info) = root.open_dir(file.parent)?;
        if kind_of(&last_base_info) != Kind::Directory || last_base_info.ident != base_info.ident {
            return Err(Error::Changed);
        }
        let last_parent = if file.parent_suffix.is_empty() {
            last_base.try_clone().map_err(map_os)?
        } else {
            verify_git_target_parent(&last_base, &file.parent_suffix, &created_dirs)?
        };
        let last_parent_info = info_of(last_parent.as_raw_handle())?;
        let expected_reparse = staged
            .temp()
            .expected_reparse()
            .map_err(|_| Error::Changed)?
            .to_vec();
        if kind_of(&last_parent_info) != Kind::Directory
            || last_parent_info.ident != final_parent_info.ident
            || info_of(rename_handle)?.ident != temp_identity
            || staged.temp().verify_file(&staged.security_file()?).is_err()
        {
            return Err(Error::Changed);
        }
        if let Some(source) = expected_leaf.as_ref() {
            let mut staged_extended = source.extended.clone();
            staged_extended.dacl_protected = true;
            check_git_leaf_metadata(
                rename_handle,
                source,
                GitPullNodeKind::Symlink,
                temp_identity,
                Some(&expected_reparse),
                &staged_extended,
            )?;
        } else if !native_query_git_eas(rename_handle)
            .map_err(git_native_security_error)?
            .is_empty()
        {
            return Err(Error::Changed);
        }
        if file.parent_suffix.is_empty() {
            root.check_git_pull_precondition(&file.expected, true)?;
        } else {
            match open_attributes(last_parent.as_raw_handle(), &target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Err(Error::Changed),
                Err(error) => return Err(error),
            }
        }
        if let Some(expected) = expected_leaf.as_ref() {
            let (_named, named_info) = open_attributes(last_parent.as_raw_handle(), &target_name)?;
            if named_info.ident != expected.info.ident {
                return Err(Error::Changed);
            }
            let guard = target_guard.as_ref().ok_or(Error::Changed)?;
            check_git_leaf_security_value(guard.as_raw_handle(), expected)?;
        }

        if directory_link {
            let target = target_guard.as_ref().ok_or(Error::Changed)?;
            delete_entry(target.as_raw_handle())?;
            visible = true;
            root.touch(last_parent_info.ident);
            drop(target_guard);
            match open_attributes(last_parent.as_raw_handle(), &target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Ok(GitPublishOutcome::UncertainAfterFinalRename),
                Err(_) => return Ok(GitPublishOutcome::UncertainAfterFinalRename),
            }
            rename_no_replace(rename_handle, last_parent.as_raw_handle(), &target_name)
                .map_err(|_| Error::Changed)?;
        } else if file.expected.entry.is_some() {
            let target_guard = target_guard.ok_or(Error::Changed)?;
            check_git_leaf_security_value(
                target_guard.as_raw_handle(),
                expected_leaf.as_ref().ok_or(Error::Changed)?,
            )?;
            rename_replace(rename_handle, last_parent.as_raw_handle(), &target_name)
                .map_err(|_| Error::Changed)?;
        } else {
            rename_no_replace(rename_handle, last_parent.as_raw_handle(), &target_name)
                .map_err(|_| Error::Changed)?;
        }
        visible = true;
        staged.mark_published();
        if let Some(source) = expected_leaf.as_ref() {
            let expected_reparse = match staged.temp().expected_reparse() {
                Ok(expected) => expected.to_vec(),
                Err(_) => return Ok(GitPublishOutcome::UncertainAfterFinalRename),
            };
            if finalize_git_leaf_security(
                rename_handle,
                source,
                GitPullNodeKind::Symlink,
                temp_identity,
                Some(&expected_reparse),
            )
            .is_err()
            {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
        }
        let (_published, published_info) =
            open_attributes(last_parent.as_raw_handle(), &target_name)?;
        if published_info.ident != temp_identity
            || kind_of(&published_info) != Kind::Symlink
            || (published_info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != link_target.directory
            || staged.temp().verify_file(&staged.security_file()?).is_err()
            || sync_git_directory(last_parent.as_raw_handle()).is_err()
        {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
        root.touch(last_parent_info.ident);
        let published_file = staged.security_file()?;
        let released = if expected_leaf.is_some() {
            staged.finalize_published_security(&published_file)
        } else {
            staged.release_after_publish()
        };
        if !released {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
        let (_confirmed, confirmed_info) =
            open_attributes(last_parent.as_raw_handle(), &target_name)?;
        if confirmed_info.ident != temp_identity
            || kind_of(&confirmed_info) != Kind::Symlink
            || (confirmed_info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != link_target.directory
            || staged.temp().verify_file(&staged.security_file()?).is_err()
            || expected_leaf.as_ref().is_some_and(|source| {
                check_git_leaf_metadata(
                    rename_handle,
                    source,
                    GitPullNodeKind::Symlink,
                    temp_identity,
                    Some(&expected_reparse),
                    &source.extended,
                )
                .is_err()
            })
            || (expected_leaf.is_none()
                && !native_query_git_eas(rename_handle)
                    .map_err(git_native_security_error)?
                    .is_empty())
            || sync_git_directory(last_parent.as_raw_handle()).is_err()
        {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
        drop(staged);
        let _ = stage_container.remove_empty();
        Ok(GitPublishOutcome::Published)
    })();
    match result {
        Err(_) if visible => Ok(GitPublishOutcome::UncertainAfterFinalRename),
        Ok(GitPublishOutcome::AbortedBeforeFinalRename) if visible => {
            Ok(GitPublishOutcome::UncertainAfterFinalRename)
        }
        other => other,
    }
}

fn validate_repository_path(
    root: &FileRoot,
    repository: EntryRef,
    file: &GitPullFile,
) -> Result<()> {
    let repository_chain = root.chain(repository)?;
    let parent_chain = root.chain(file.parent)?;
    let parent_prefix_len = file
        .path
        .len()
        .checked_sub(file.parent_suffix.len() + 1)
        .ok_or(Error::Invalid)?;
    if parent_chain.len() < repository_chain.len()
        || parent_chain[..repository_chain.len()] != repository_chain
        || parent_chain
            .iter()
            .any(|(name, _)| is_git_name(name) || is_private_staging_name(name))
        || parent_chain
            .iter()
            .map(|(name, _)| name)
            .ne(file.path[..parent_prefix_len].iter())
    {
        return Err(Error::Protected);
    }
    Ok(())
}

fn prepare_symlink_target(
    root: &FileRoot,
    file: &GitPullFile,
    contents: &[u8],
) -> Result<SymlinkTarget> {
    let text = std::str::from_utf8(contents).map_err(|_| Error::Unsupported)?;
    if text.is_empty() || text.contains('\0') {
        return Err(Error::Invalid);
    }
    let path = text.replace('/', "\\");
    if path.starts_with("\\\\.\\") || path.starts_with("\\??\\") {
        return Err(Error::Unsupported);
    }

    let extended = path
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("\\\\?\\"));
    let (substitute, print, relative, probe_path) = if extended {
        let rest = &path[4..];
        if rest
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("UNC\\"))
        {
            let unc = &rest[4..];
            if !valid_unc_prefix(unc) {
                return Err(Error::Unsupported);
            }
            (
                format!("\\??\\UNC\\{unc}"),
                format!("\\\\?\\UNC\\{unc}"),
                false,
                None,
            )
        } else if rest
            .as_bytes()
            .get(1..3)
            .is_some_and(|suffix| suffix == b":\\")
        {
            let print = rest.to_owned();
            (
                format!("\\??\\{rest}"),
                print,
                false,
                Some(PathBuf::from(rest)),
            )
        } else {
            return Err(Error::Unsupported);
        }
    } else if path.starts_with("\\\\") {
        let rest = path.trim_start_matches('\\');
        if rest.starts_with(".\\") || !valid_unc_prefix(rest) {
            return Err(Error::Unsupported);
        }
        (
            format!("\\??\\UNC\\{rest}"),
            format!("\\\\{rest}"),
            false,
            None,
        )
    } else if is_drive_absolute(&path) {
        (
            format!("\\??\\{path}"),
            path.clone(),
            false,
            Some(PathBuf::from(&path)),
        )
    } else if path.starts_with('\\') {
        let (substitute, print, probe_path) = root_relative_target(root, &path)?;
        (substitute, print, false, probe_path)
    } else if path.as_bytes().get(1) == Some(&b':') {
        return Err(Error::Unsupported);
    } else {
        let probe_path = relative_target_probe_path(root, file, &path);
        (path.clone(), path.clone(), true, probe_path)
    };
    let directory = probe_path
        .as_deref()
        .is_some_and(|path| safe_target_is_directory(root, path));
    let substitute = substitute.encode_utf16().collect::<Vec<_>>();
    let print = print.encode_utf16().collect::<Vec<_>>();
    if substitute.is_empty() || print.is_empty() {
        return Err(Error::Invalid);
    }
    Ok(SymlinkTarget {
        substitute,
        print,
        relative,
        directory,
    })
}

fn is_drive_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

fn valid_unc_prefix(path: &str) -> bool {
    let mut parts = path.split('\\');
    parts.next().is_some_and(|server| !server.is_empty())
        && parts.next().is_some_and(|share| !share.is_empty())
}

fn root_relative_target(root: &FileRoot, path: &str) -> Result<(String, String, Option<PathBuf>)> {
    let mut components = root.root_path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(Error::Unsupported);
    };
    let rest = path.trim_start_matches('\\');
    match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
            let drive = char::from(drive);
            let print = format!("{drive}:\\{rest}");
            let substitute = format!("\\??\\{print}");
            // Git for Windows avoids probing rooted targets. Keep that same
            // no-probe rule for this root-relative form.
            Ok((substitute, path.to_owned(), None))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let server = server.to_string_lossy();
            let share = share.to_string_lossy();
            let rest = format!("{server}\\{share}\\{rest}");
            Ok((format!("\\??\\UNC\\{rest}"), path.to_owned(), None))
        }
        _ => Err(Error::Unsupported),
    }
}

fn relative_target_probe_path(
    root: &FileRoot,
    file: &GitPullFile,
    target: &str,
) -> Option<PathBuf> {
    let mut result = root.root_path.clone();
    for component in file.path.iter().take(file.path.len().checked_sub(1)?) {
        let text = std::str::from_utf8(component).ok()?;
        if !valid_component(text) {
            return None;
        }
        result.push(text);
    }
    let volume_root = local_drive_root(&result)?;
    for component in target.split('\\') {
        match component {
            "" | "." => {}
            ".." => {
                if result == volume_root || !result.pop() {
                    return None;
                }
            }
            text => {
                if !valid_component(text)
                    || is_git_name(text.as_bytes())
                    || is_private_staging_name(text.as_bytes())
                {
                    return None;
                }
                result.push(text);
            }
        }
    }
    Some(result)
}

fn local_drive_root(path: &std::path::Path) -> Option<PathBuf> {
    let mut components = path.components();
    let Component::Prefix(prefix) = components.next()? else {
        return None;
    };
    let drive = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => char::from(drive),
        _ => return None,
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return None;
    }
    Some(PathBuf::from(format!("{drive}:\\")))
}

fn safe_target_is_directory(root: &FileRoot, path: &std::path::Path) -> bool {
    let Some(drive_root) = local_drive_root(path) else {
        return false;
    };
    let drive_root_wide = drive_root
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let drive_type = unsafe { GetDriveTypeW(drive_root_wide.as_ptr()) };
    if !matches!(drive_type, 2 | 3 | 6) {
        return false;
    }
    for component in path.components() {
        if let Component::Normal(name) = component
            && name.to_str().is_some_and(|name| {
                is_git_name(name.as_bytes()) || is_private_staging_name(name.as_bytes())
            })
        {
            return false;
        }
    }
    let Some(name) = path.file_name() else {
        return open_local_directory_no_follow(root, path)
            .is_ok_and(|(_, info)| kind_of(&info) == Kind::Directory);
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok((parent, parent_info)) = open_local_directory_no_follow(root, parent) else {
        return false;
    };
    if root.is_protected_ident(&parent_info.ident) {
        return false;
    }
    let Some(name) = name.to_str() else {
        return false;
    };
    let Ok(name) = component(name.as_bytes()) else {
        return false;
    };
    let Ok((_target, info)) = open_attributes(parent.as_raw_handle(), &name) else {
        return false;
    };
    kind_of(&info) == Kind::Directory
        && info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && !root.is_protected_ident(&info.ident)
}

fn open_local_directory_no_follow(
    root: &FileRoot,
    path: &std::path::Path,
) -> Result<(OwnedHandle, Info)> {
    let Some(volume_root) = local_drive_root(path) else {
        return Err(Error::Unsupported);
    };
    let (mut current, mut info) = native_open_absolute_directory_no_follow(&volume_root)
        .map_err(git_native_security_error)?;
    if kind_of(&info) != Kind::Directory || root.is_protected_ident(&info.ident) {
        return Err(Error::Protected);
    }
    let mut components = path.components();
    let _prefix = components.next().ok_or(Error::Invalid)?;
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(Error::Invalid);
    }
    for part in components {
        let Component::Normal(name) = part else {
            return Err(Error::Invalid);
        };
        let text = name.to_str().ok_or(Error::Invalid)?;
        if is_git_name(text.as_bytes()) || is_private_staging_name(text.as_bytes()) {
            return Err(Error::Protected);
        }
        let wide = component(text.as_bytes())?;
        current = open_relative(
            current.as_raw_handle(),
            &wide,
            DIRECTORY_ACCESS,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
            0,
            false,
        )?;
        info = info_of(current.as_raw_handle())?;
        if kind_of(&info) != Kind::Directory
            || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || root.is_protected_ident(&info.ident)
        {
            return Err(Error::Protected);
        }
    }
    Ok((current, info))
}
