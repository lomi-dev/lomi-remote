//! One-leaf, index-to-worktree publisher for owner-local Desktop Git discard.

use super::owner_git::DesktopGitMetadataAuthority;
use super::*;
use crate::desktop_git::{GitDesktopFilePublication, GitDesktopFileTarget};

pub(crate) fn publish_file(
    root: &FileRoot,
    publication: &GitDesktopFilePublication,
    check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    let _broker_scope = BrokerOperationScope::enter();
    let file = &publication.file;
    if file.kind == GitPullNodeKind::Symlink {
        let target: GitDesktopFileTarget = publication.target();
        let authority = DesktopGitMetadataAuthority::confined(publication);
        return super::desktop_git_symlink::publish_symlink(root, &target, &authority, check);
    }
    let target = publication.target();
    let authority = DesktopGitMetadataAuthority::confined(publication);
    publish_file_core(root, &target, &authority, check)
}

pub(super) fn publish_file_core(
    root: &FileRoot,
    target: &GitDesktopFileTarget,
    authority: &DesktopGitMetadataAuthority<'_>,
    mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    let file = &target.file;
    root.validate_pull_worktree_path(file)?;
    validate_repository_path(root, target.repository, file)?;
    if file.kind != GitPullNodeKind::File || file.expected.kind == Some(GitPullNodeKind::Directory)
    {
        return Err(Error::Unsupported);
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
        let contents = file.contents.as_deref().ok_or(Error::Invalid)?;
        let session = operation_broker_session().map_err(git_native_security_error)?;
        let stage_parent = if authority.stages_common_exclude_in_root(file, created_dirs.is_empty())
        {
            root.open_dir(root.root_entry())?.0
        } else {
            target_parent.try_clone().map_err(map_os)?
        };
        let stage_parent_info = info_of(stage_parent.as_raw_handle())?;
        if kind_of(&stage_parent_info) != Kind::Directory
            || stage_parent_info.ident.volume != parent_info.ident.volume
        {
            return Err(Error::Changed);
        }
        let mut stage_container = GitPrivateStageDirectory::create(&stage_parent)?;
        let temp_parent = stage_container.handle()?.try_clone().map_err(map_os)?;
        let mut temp =
            native_temp_from_broker(&temp_parent, &session).map_err(git_native_security_error)?;
        let temp_info = info_of(temp.handle.as_raw_handle())?;
        if kind_of(&temp_info) != Kind::File || temp_info.nlink != 1 {
            return Err(Error::Protected);
        }
        let temp_identity = temp_info.ident;
        let private_security = native_owner_only_file_security(temp.handle.as_raw_handle())?;
        let writer_handle = temp.handle.try_clone().map_err(map_os)?;
        let mut writer = File::from(writer_handle);
        if !write_git_bytes(&mut writer, contents, &mut || {
            check(LocalNativeFileCheckPhase::Progress)
        })? {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }
        writer.sync_all().map_err(map_os)?;
        let expected_digest: [u8; 32] = Sha256::digest(contents).into();
        if hash_git_file(&mut writer, contents.len())? != expected_digest {
            return Err(Error::Changed);
        }
        drop(writer);

        if let Some(source) = source_security.as_ref() {
            source
                .broker_source
                .as_ref()
                .ok_or(Error::Changed)?
                .finalize(temp.broker_token.as_ref().ok_or(Error::Changed)?)
                .map_err(git_native_security_error)?;
        }
        let publish_handle = temp
            .seal_for_git_leaf()
            .map_err(git_native_security_error)?;
        if let Some(source) = source_security.as_ref() {
            apply_git_leaf_security(publish_handle, &source.security, GitPullNodeKind::File)?;
        }
        let mut published_security = if let Some(source) = source_security.as_ref() {
            let mut staged_extended = source.security.extended.clone();
            staged_extended.dacl_protected = true;
            check_git_leaf_metadata(
                publish_handle,
                &source.security,
                GitPullNodeKind::File,
                temp_identity,
                None,
                &staged_extended,
            )?;
            let staged_info = info_of(publish_handle)?;
            let expected = GitFileSecurity {
                attributes: staged_info.attributes,
                extended: staged_extended.clone(),
            };
            let observed = git_file_security_for_expected(publish_handle, &expected)?;
            if observed.extended != staged_extended {
                return Err(Error::Changed);
            }
            observed
        } else {
            if !native_query_git_eas(publish_handle)
                .map_err(git_native_security_error)?
                .is_empty()
            {
                return Err(Error::Changed);
            }
            private_security
        };
        let mut staged_file = File::from(temp.handle.try_clone().map_err(map_os)?);
        if hash_git_file(&mut staged_file, contents.len())? != expected_digest
            || git_file_security_for_expected(publish_handle, &published_security)?
                != published_security
        {
            return Err(Error::Changed);
        }

        if !check(LocalNativeFileCheckPhase::Publication) {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }
        check_git_named_leaf_security(
            target_parent.as_raw_handle(),
            &target_name,
            source_security.as_ref(),
        )?;
        let expected_leaf = source_security
            .as_ref()
            .map(|source| source.security.clone());
        let staged_info = info_of(publish_handle)?;
        if kind_of(&staged_info) != Kind::File
            || staged_info.nlink != 1
            || staged_info.ident != temp_identity
            || git_file_security_for_expected(publish_handle, &published_security)?
                != published_security
            || hash_git_file(&mut staged_file, contents.len())? != expected_digest
        {
            return Err(Error::Changed);
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
            let guard = open_relative_with_share(
                target_parent.as_raw_handle(),
                &target_name,
                access,
                FILE_OPEN,
                options,
                0,
                share,
                false,
            )?;
            check_git_leaf_security_value(guard.as_raw_handle(), source)?;
            if directory_link
                && info_of(guard.as_raw_handle())?.attributes & FILE_ATTRIBUTE_READONLY != 0
            {
                return Err(Error::Unsupported);
            }
            Some(guard)
        } else {
            match open_attributes(target_parent.as_raw_handle(), &target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Err(Error::Changed),
                Err(error) => return Err(error),
            }
            None
        };
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

        // Source recheck/release above is the last pre-effect broker IPC.
        // Refresh publication authorization only after it, then do all path,
        // parent, leaf, and staged-object checks locally before the first
        // unlink or rename.
        if !check(LocalNativeFileCheckPhase::Publication) {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }

        if let Some(source) = expected_leaf.as_ref() {
            let mut staged_extended = source.extended.clone();
            staged_extended.dacl_protected = true;
            check_git_leaf_metadata(
                publish_handle,
                source,
                GitPullNodeKind::File,
                temp_identity,
                None,
                &staged_extended,
            )?;
        } else if !native_query_git_eas(publish_handle)
            .map_err(git_native_security_error)?
            .is_empty()
        {
            return Err(Error::Changed);
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
        if kind_of(&last_parent_info) != Kind::Directory
            || last_parent_info.ident != parent_info.ident
            || info_of(stage_container.handle()?.as_raw_handle())?.ident
                != info_of(temp_parent.as_raw_handle())?.ident
            || info_of(publish_handle)?.ident != temp_identity
            || git_file_security_for_expected(publish_handle, &published_security)?
                != published_security
            || hash_git_file(&mut staged_file, contents.len())? != expected_digest
        {
            return Err(Error::Changed);
        }
        if file.parent_suffix.is_empty() {
            root.check_git_pull_precondition(&file.expected, true)?;
        } else {
            verify_git_target_parent(&last_base, &file.parent_suffix, &created_dirs)?;
        }
        if let (Some(guard), Some(expected)) = (target_guard.as_ref(), expected_leaf.as_ref()) {
            check_git_leaf_security_value(guard.as_raw_handle(), expected)?;
            let (named, named_info) = open_attributes(last_parent.as_raw_handle(), &target_name)?;
            if named_info.ident != expected.info.ident {
                return Err(Error::Changed);
            }
            drop(named);
        } else if git_target_exists(last_parent.as_raw_handle(), &target_name)? {
            return Err(Error::Changed);
        }

        if directory_link {
            let guard = target_guard.as_ref().ok_or(Error::Changed)?;
            delete_entry(guard.as_raw_handle())?;
            visible = true;
            root.touch(last_parent_info.ident);
            drop(target_guard);
            match open_attributes(last_parent.as_raw_handle(), &target_name) {
                Err(Error::NotFound) => {}
                Ok(_) | Err(_) => return Ok(GitPublishOutcome::UncertainAfterFinalRename),
            }
            rename_no_replace(publish_handle, last_parent.as_raw_handle(), &target_name)
                .map_err(|_| Error::Changed)?;
        } else if file.expected.entry.is_some() {
            let _target_guard = target_guard.ok_or(Error::Changed)?;
            rename_replace(publish_handle, last_parent.as_raw_handle(), &target_name)
                .map_err(|_| Error::Changed)?;
        } else {
            rename_no_replace(publish_handle, last_parent.as_raw_handle(), &target_name)
                .map_err(|_| Error::Changed)?;
        }
        visible = true;
        temp.mark_published();
        if let Some(source) = expected_leaf.as_ref() {
            if finalize_git_leaf_security(
                publish_handle,
                source,
                GitPullNodeKind::File,
                temp_identity,
                None,
            )
            .is_err()
            {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            let published_info = match info_of(publish_handle) {
                Ok(info) => info,
                Err(_) => return Ok(GitPublishOutcome::UncertainAfterFinalRename),
            };
            let expected = GitFileSecurity {
                attributes: published_info.attributes,
                extended: source.extended.clone(),
            };
            published_security = match git_file_security_for_expected(publish_handle, &expected) {
                Ok(security) if security.extended == source.extended => security,
                _ => return Ok(GitPublishOutcome::UncertainAfterFinalRename),
            };
        }
        let (_published, published_info) =
            open_attributes(last_parent.as_raw_handle(), &target_name)?;
        if kind_of(&published_info) != Kind::File
            || published_info.nlink != 1
            || published_info.ident != temp_identity
            || git_file_security_for_expected(publish_handle, &published_security)?
                != published_security
            || expected_leaf.as_ref().is_some_and(|source| {
                check_git_leaf_metadata(
                    publish_handle,
                    source,
                    GitPullNodeKind::File,
                    temp_identity,
                    None,
                    &source.extended,
                )
                .is_err()
            })
            || (expected_leaf.is_none()
                && !native_query_git_eas(publish_handle)
                    .map_err(git_native_security_error)?
                    .is_empty())
            || hash_git_file(&mut staged_file, contents.len())? != expected_digest
        {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
        if sync_git_directory(last_parent.as_raw_handle()).is_err()
            || sync_git_directory(stage_parent.as_raw_handle()).is_err()
        {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
        let published_file = File::from(temp.handle.try_clone().map_err(map_os)?);
        let detached = if expected_leaf.is_some() {
            temp.finalize_published_git_leaf(&published_file)
        } else {
            temp.detach_published()
        };
        if detached.is_err() {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
        let (_confirmed, confirmed_info) =
            open_attributes(last_parent.as_raw_handle(), &target_name)?;
        if confirmed_info.ident != temp_identity
            || kind_of(&confirmed_info) != Kind::File
            || git_file_security_for_expected(publish_handle, &published_security)?
                != published_security
            || expected_leaf.as_ref().is_some_and(|source| {
                check_git_leaf_metadata(
                    publish_handle,
                    source,
                    GitPullNodeKind::File,
                    temp_identity,
                    None,
                    &source.extended,
                )
                .is_err()
            })
            || (expected_leaf.is_none()
                && !native_query_git_eas(publish_handle)
                    .map_err(git_native_security_error)?
                    .is_empty())
            || hash_git_file(&mut staged_file, contents.len())? != expected_digest
        {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
        root.touch(last_parent_info.ident);
        if stage_parent_info.ident != last_parent_info.ident {
            root.touch(stage_parent_info.ident);
        }
        drop(staged_file);
        drop(temp_parent);
        drop(temp);
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
