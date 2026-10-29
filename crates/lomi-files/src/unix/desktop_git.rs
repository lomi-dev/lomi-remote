//! One-leaf, index-to-worktree publisher for owner-local Desktop Git discard.

use super::owner_git::DesktopGitMetadataAuthority;
use super::*;
use crate::desktop_git::{GitDesktopFilePublication, GitDesktopFileTarget};

struct StagedLeaf {
    parent: OwnedFd,
    name: CString,
    identity: Option<Ident>,
    kind: Kind,
    file: Option<File>,
    identity_handle: Option<OwnedFd>,
    security: Option<GitFileSecurity>,
    active: bool,
}

struct CreatedParent {
    parent: OwnedFd,
    name: CString,
    identity: Ident,
}

impl Drop for StagedLeaf {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let Ok(named) = fstatat_nofollow(self.parent.as_raw_fd(), &self.name) else {
            return;
        };
        let identity_matches = match self.identity {
            Some(identity) => {
                ident_at(self.parent.as_raw_fd(), &self.name, &named).ok() == Some(identity)
            }
            None => self
                .file
                .as_ref()
                .map(|file| file.as_raw_fd())
                .or_else(|| self.identity_handle.as_ref().map(AsRawFd::as_raw_fd))
                .is_some_and(|held_fd| {
                    fstat(held_fd).is_ok_and(|held| {
                        held.st_dev == named.st_dev && held.st_ino == named.st_ino
                    })
                }),
        };
        if kind_of(&named) != self.kind || !identity_matches {
            return;
        }
        unsafe {
            libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
        }
    }
}

impl StagedLeaf {
    fn identity(&self) -> Result<Ident> {
        self.identity.ok_or(Error::Changed)
    }
}

pub(crate) fn publish_file(
    root: &FileRoot,
    publication: &GitDesktopFilePublication,
    check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    publication.validate()?;
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
    if file.expected.kind == Some(GitPullNodeKind::Directory) {
        return Err(Error::Protected);
    }
    if !check(LocalNativeFileCheckPhase::Progress)
        || !check(LocalNativeFileCheckPhase::BeforeEffect)
    {
        return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
    }

    if !check(LocalNativeFileCheckPhase::Validation) {
        return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
    }
    let _metadata_guards = authority.lock(root)?;

    let mut visible = false;
    let result = (|| -> Result<GitPublishOutcome> {
        authority.check(root, target)?;
        root.validate_pull_worktree_path(file)?;
        validate_repository_path(root, target.repository, file)?;
        root.check_git_pull_precondition(&file.expected, true)?;

        let (base, parent_stat) = root.open_dir(file.parent)?;
        if kind_of(&parent_stat) != Kind::Directory {
            return Err(Error::Changed);
        }
        let base_identity = ident_fd(base.as_raw_fd(), &parent_stat)?;
        let (parent, created_parents) =
            create_missing_parents(&base, &file.parent_suffix, &mut check, &mut visible)?;
        let target_parent_identity = ident_fd(parent.as_raw_fd(), &fstat(parent.as_raw_fd())?)?;
        let target_name = cstring(&file.name)?;
        let stage_parent =
            if authority.stages_common_exclude_in_root(file, created_parents.is_empty()) {
                let (parent, stat) = root.open_dir(root.root_entry())?;
                if kind_of(&stat) != Kind::Directory {
                    return Err(Error::Changed);
                }
                parent
            } else {
                dup(parent.as_raw_fd())?
            };
        let source_security = if file.parent_suffix.is_empty() {
            match file.expected.kind {
                Some(GitPullNodeKind::File) => {
                    capture_regular_security(root, file.parent, &target_name, &file.expected)?
                }
                Some(GitPullNodeKind::Symlink) | None => None,
                Some(GitPullNodeKind::Directory) => return Err(Error::Protected),
            }
        } else {
            None
        };
        let contents = file.contents.as_deref().ok_or(Error::Invalid)?;
        let mut staged = create_staged_leaf(
            &stage_parent,
            contents,
            file.kind,
            source_security.as_ref(),
            file.executable,
            &mut check,
        )?;

        if !check(LocalNativeFileCheckPhase::Publication) {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }
        // The phase callback may run local cancellation/deadline checks only.
        // All roots and exact Git/worktree conditions are repeated after it.
        authority.check(root, target)?;
        if file.parent_suffix.is_empty() {
            root.check_git_pull_precondition(&file.expected, true)?;
        } else {
            verify_created_parents(&base, &created_parents)?;
        }
        verify_staged(&mut staged, contents)?;
        if file.parent_suffix.is_empty() {
            check_target_security(
                &parent,
                &target_name,
                file.expected.kind,
                source_security.as_ref(),
            )?;
        } else {
            match fstatat_nofollow(parent.as_raw_fd(), &target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Err(Error::Changed),
                Err(error) => return Err(error),
            }
        }

        authority.check(root, target)?;
        if file.parent_suffix.is_empty() {
            root.check_git_pull_precondition(&file.expected, true)?;
        } else {
            verify_created_parents(&base, &created_parents)?;
        }
        // Reattach the original parent through the rooted FileRoot immediately
        // before publication. A held directory handle alone would still point
        // at a moved tree after an ancestor rename during staging.
        let (final_base, final_base_stat) = root.open_dir(file.parent)?;
        if kind_of(&final_base_stat) != Kind::Directory
            || ident_fd(final_base.as_raw_fd(), &final_base_stat)? != base_identity
        {
            return Err(Error::Changed);
        }
        let final_parent = if file.parent_suffix.is_empty() {
            dup(final_base.as_raw_fd())?
        } else {
            verify_created_parents(&final_base, &created_parents)?
        };
        if ident_fd(final_parent.as_raw_fd(), &fstat(final_parent.as_raw_fd())?)?
            != target_parent_identity
        {
            return Err(Error::Changed);
        }
        if file.parent_suffix.is_empty() {
            root.check_git_pull_precondition(&file.expected, true)?;
        } else {
            match fstatat_nofollow(final_parent.as_raw_fd(), &target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Err(Error::Changed),
                Err(error) => return Err(error),
            }
        }
        check_target_security(
            &final_parent,
            &target_name,
            file.expected.kind,
            source_security.as_ref(),
        )?;

        if file.expected.entry.is_some() {
            if unsafe {
                libc::renameat(
                    staged.parent.as_raw_fd(),
                    staged.name.as_ptr(),
                    final_parent.as_raw_fd(),
                    target_name.as_ptr(),
                )
            } != 0
            {
                return Err(map_errno(last_errno(), false));
            }
        } else {
            no_replace_rename(
                staged.parent.as_raw_fd(),
                &staged.name,
                final_parent.as_raw_fd(),
                &target_name,
            )?;
        }
        visible = true;
        staged.active = false;

        let published = fstatat_nofollow(final_parent.as_raw_fd(), &target_name)?;
        if kind_of(&published) != staged.kind
            || ident_at(final_parent.as_raw_fd(), &target_name, &published)? != staged.identity()?
        {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
        if let Some(expected_security) = staged.security.as_ref()
            && (git_named_file_security(final_parent.as_raw_fd(), &target_name)
                .ok()
                .flatten()
                != Some(expected_security.clone())
                || staged.file.as_mut().is_none_or(|temp| {
                    hash_git_file(temp, contents.len()).ok()
                        != Some(Sha256::digest(contents).into())
                }))
        {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
        if sync_git_directory(final_parent.as_raw_fd()).is_err()
            || sync_git_directory(stage_parent.as_raw_fd()).is_err()
        {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
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

fn create_missing_parents(
    base: &OwnedFd,
    suffix: &[Vec<u8>],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> bool,
    visible: &mut bool,
) -> Result<(OwnedFd, Vec<CreatedParent>)> {
    let mut current = dup(base.as_raw_fd())?;
    let mut created = Vec::with_capacity(suffix.len());
    for component in suffix {
        if !check(LocalNativeFileCheckPhase::Progress) {
            return Err(Error::Changed);
        }
        let name = cstring(component)?;
        if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(if last_errno() == libc::EEXIST {
                Error::Changed
            } else {
                map_errno(last_errno(), false)
            });
        }
        *visible = true;
        let parent_identity = ident_fd(current.as_raw_fd(), &fstat(current.as_raw_fd())?)?;
        let stat = fstatat_nofollow(current.as_raw_fd(), &name)?;
        if kind_of(&stat) != Kind::Directory {
            return Err(Error::Changed);
        }
        let identity = ident_at(current.as_raw_fd(), &name, &stat)?;
        created.push(CreatedParent {
            parent: dup(current.as_raw_fd())?,
            name,
            identity,
        });
        let (child, child_stat) = open_git_child_dir(&current, component)?;
        if ident_fd(child.as_raw_fd(), &child_stat)? != identity
            || ident_fd(current.as_raw_fd(), &fstat(current.as_raw_fd())?)? != parent_identity
        {
            return Err(Error::Changed);
        }
        current = child;
    }
    Ok((current, created))
}

fn verify_created_parents(base: &OwnedFd, created: &[CreatedParent]) -> Result<OwnedFd> {
    let mut current = dup(base.as_raw_fd())?;
    for item in created {
        let current_stat = fstat(current.as_raw_fd())?;
        let recorded_parent = fstat(item.parent.as_raw_fd())?;
        if ident_fd(current.as_raw_fd(), &current_stat)?
            != ident_fd(item.parent.as_raw_fd(), &recorded_parent)?
        {
            return Err(Error::Changed);
        }
        let (child, stat) = open_git_child_dir(&current, item.name.to_bytes())?;
        if ident_fd(child.as_raw_fd(), &stat)? != item.identity {
            return Err(Error::Changed);
        }
        current = child;
    }
    Ok(current)
}

fn capture_regular_security(
    root: &FileRoot,
    parent_entry: EntryRef,
    name: &CStr,
    expected: &GitPullPrecondition,
) -> Result<Option<GitFileSecurity>> {
    let Some(entry) = expected.entry else {
        return Ok(None);
    };
    let (recorded_parent, recorded_name, expected_ident) = root.node(entry)?;
    if recorded_parent != Some(parent_entry) || recorded_name != expected.name {
        return Err(Error::Changed);
    }
    let (parent, _) = root.open_dir(parent_entry)?;
    let named = fstatat_nofollow(parent.as_raw_fd(), name)?;
    if kind_of(&named) != Kind::File || named.st_nlink != 1 {
        return Err(Error::Protected);
    }
    let file = openat(
        parent.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
        false,
    )?;
    let held = fstat(file.as_raw_fd())?;
    if kind_of(&held) != Kind::File
        || held.st_nlink != 1
        || ident_fd(file.as_raw_fd(), &held)? != expected_ident
        || ident_at(parent.as_raw_fd(), name, &named)? != expected_ident
    {
        return Err(Error::Changed);
    }
    git_file_security(file.as_raw_fd()).map(Some)
}

fn create_staged_leaf(
    parent: &OwnedFd,
    contents: &[u8],
    kind: GitPullNodeKind,
    source_security: Option<&GitFileSecurity>,
    executable: bool,
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<StagedLeaf> {
    for _ in 0..64 {
        let suffix = NEXT_GIT_PULL_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = cstring(format!(".lomi-pull-{}-{suffix}.tmp", std::process::id()).as_bytes())?;
        if !check(LocalNativeFileCheckPhase::Progress) {
            return Err(Error::Changed);
        }
        match kind {
            GitPullNodeKind::File => {
                // Pin the cleanup parent before creating a public staging
                // name. Every fallible step after creation is then covered by
                // the identity-checked Drop guard below.
                let cleanup_parent = dup(parent.as_raw_fd())?;
                let fd = match openat(
                    parent.as_raw_fd(),
                    &name,
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    0o600,
                    false,
                ) {
                    Ok(fd) => fd,
                    Err(Error::Exists) => continue,
                    Err(error) => return Err(error),
                };
                let mut staged = StagedLeaf {
                    parent: cleanup_parent,
                    name,
                    identity: None,
                    kind: Kind::File,
                    file: Some(File::from(fd)),
                    identity_handle: None,
                    security: None,
                    active: true,
                };
                let file = staged.file.as_mut().ok_or(Error::Changed)?;
                let stat = fstat(file.as_raw_fd())?;
                staged.identity = Some(ident_fd(file.as_raw_fd(), &stat)?);
                if kind_of(&stat) != Kind::File || stat.st_nlink != 1 {
                    return Err(Error::Protected);
                }
                apply_git_file_security(file.as_raw_fd(), None, None)?;
                if !write_git_bytes(file, contents, &mut || {
                    check(LocalNativeFileCheckPhase::Progress)
                })? {
                    return Err(Error::Changed);
                }
                file.sync_all().map_err(map_io)?;
                let security =
                    apply_git_file_security(file.as_raw_fd(), source_security, Some(executable))?;
                file.sync_all().map_err(map_io)?;
                let expected_digest: [u8; 32] = Sha256::digest(contents).into();
                if hash_git_file(file, contents.len())? != expected_digest
                    || git_file_security(file.as_raw_fd())? != security
                {
                    return Err(Error::Changed);
                }
                staged.security = Some(security);
                return Ok(staged);
            }
            GitPullNodeKind::Symlink => {
                let target = CString::new(contents).map_err(|_| Error::Invalid)?;
                // Acquire the parent pin before publishing the temporary link,
                // so a later allocation/duplication failure cannot strand it.
                let cleanup_parent = dup(parent.as_raw_fd())?;
                if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) }
                    != 0
                {
                    if last_errno() == libc::EEXIST {
                        continue;
                    }
                    return Err(map_errno(last_errno(), false));
                }
                let mut staged = StagedLeaf {
                    parent: cleanup_parent,
                    name,
                    identity: None,
                    kind: Kind::Symlink,
                    file: None,
                    identity_handle: None,
                    security: None,
                    active: true,
                };
                // Record the named identity before opening another descriptor:
                // EMFILE must still leave Drop enough evidence to remove this
                // exact temporary link without following or replacing it.
                let named = fstatat_nofollow(parent.as_raw_fd(), &staged.name)?;
                if kind_of(&named) != Kind::Symlink {
                    return Err(Error::Changed);
                }
                staged.identity = Some(ident_at(parent.as_raw_fd(), &staged.name, &named)?);
                let symlink_handle = open_symlink_handle(parent.as_raw_fd(), &staged.name)?;
                staged.identity_handle = Some(symlink_handle);
                let handle = staged.identity_handle.as_ref().ok_or(Error::Changed)?;
                let stat = fstat(handle.as_raw_fd())?;
                if kind_of(&stat) != Kind::Symlink
                    || ident_fd(handle.as_raw_fd(), &stat)? != staged.identity()?
                {
                    return Err(Error::Changed);
                }
                let named = fstatat_nofollow(parent.as_raw_fd(), &staged.name)?;
                if kind_of(&named) != Kind::Symlink
                    || ident_at(parent.as_raw_fd(), &staged.name, &named)? != staged.identity()?
                {
                    return Err(Error::Changed);
                }
                return Ok(staged);
            }
            GitPullNodeKind::Directory => return Err(Error::Invalid),
        }
    }
    Err(Error::Exists)
}

fn verify_staged(staged: &mut StagedLeaf, contents: &[u8]) -> Result<()> {
    let stat = fstatat_nofollow(staged.parent.as_raw_fd(), &staged.name)?;
    if kind_of(&stat) != staged.kind
        || ident_at(staged.parent.as_raw_fd(), &staged.name, &stat)? != staged.identity()?
    {
        return Err(Error::Changed);
    }
    if let Some(file) = staged.file.as_mut() {
        let expected_digest: [u8; 32] = Sha256::digest(contents).into();
        if git_file_security(file.as_raw_fd())?
            != *staged.security.as_ref().ok_or(Error::Changed)?
            || hash_git_file(file, contents.len())? != expected_digest
        {
            return Err(Error::Changed);
        }
    }
    if let Some(handle) = staged.identity_handle.as_ref() {
        let held = fstat(handle.as_raw_fd())?;
        if kind_of(&held) != Kind::Symlink
            || ident_fd(handle.as_raw_fd(), &held)? != staged.identity()?
        {
            return Err(Error::Changed);
        }
        let mut target = vec![0u8; contents.len().saturating_add(1)];
        let actual = unsafe {
            libc::readlinkat(
                staged.parent.as_raw_fd(),
                staged.name.as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        if actual < 0 {
            return Err(map_errno(last_errno(), false));
        }
        target.truncate(actual as usize);
        if target != contents {
            return Err(Error::Changed);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_symlink_handle(parent: RawFd, name: &CStr) -> Result<OwnedFd> {
    openat(parent, name, libc::O_PATH | libc::O_NOFOLLOW, 0, false)
}

#[cfg(target_os = "macos")]
fn open_symlink_handle(parent: RawFd, name: &CStr) -> Result<OwnedFd> {
    openat(
        parent,
        name,
        libc::O_RDONLY | libc::O_SYMLINK | libc::O_NOFOLLOW,
        0,
        false,
    )
}

fn check_target_security(
    parent: &OwnedFd,
    target: &CStr,
    kind: Option<GitPullNodeKind>,
    expected: Option<&GitFileSecurity>,
) -> Result<()> {
    if kind == Some(GitPullNodeKind::File) {
        check_git_named_file_security(parent.as_raw_fd(), target, expected)
    } else {
        Ok(())
    }
}
