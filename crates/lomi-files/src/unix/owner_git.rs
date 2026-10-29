//! Paired owner-local Desktop Git publisher for external Git metadata roots.

use super::*;
use crate::desktop_git::{
    GitDesktopFilePublication, GitDesktopFileTarget, OwnerGitDesktopFilePublication,
};
use crate::owner_git_metadata::{
    OwnerGitMetadataCondition, OwnerGitMetadataRole, OwnerGitMetadataRoot,
};
use std::sync::MutexGuard;

pub(super) enum DesktopGitMetadataAuthority<'a> {
    Confined {
        git_dir: EntryRef,
        common_dir: EntryRef,
        metadata: &'a [GitFilePrecondition],
        repository_preconditions: &'a [GitPullPrecondition],
    },
    OwnerLocal {
        git_dir: &'a OwnerGitMetadataRoot,
        common_dir: &'a OwnerGitMetadataRoot,
        metadata: &'a [OwnerGitMetadataCondition],
    },
    OwnerCommonExclude {
        workspace: &'a FileRoot,
        worktree_target: &'a GitDesktopFileTarget,
        selected: &'a GitPullPrecondition,
        git_dir: &'a OwnerGitMetadataRoot,
        common_dir: &'a OwnerGitMetadataRoot,
        metadata: &'a [OwnerGitMetadataCondition],
    },
}

pub(super) struct MetadataWriteGuards<'a> {
    _guards: Vec<MutexGuard<'a, ()>>,
}

impl<'a> DesktopGitMetadataAuthority<'a> {
    pub(super) fn confined(publication: &'a GitDesktopFilePublication) -> Self {
        Self::Confined {
            git_dir: publication.git_dir,
            common_dir: publication.common_dir,
            metadata: &publication.metadata_preconditions,
            repository_preconditions: &publication.repository_preconditions,
        }
    }

    pub(super) fn stages_common_exclude_in_root(
        &self,
        file: &GitPullFile,
        no_new_parents: bool,
    ) -> bool {
        matches!(self, Self::OwnerCommonExclude { .. })
            && no_new_parents
            && file.parent_suffix.is_empty()
            && file.path.len() == 2
            && file.path[0] == b"info"
            && file.path[1] == b"exclude"
            && file.name == b"exclude"
    }

    pub(super) fn lock<'b>(&'b self, effect_root: &'b FileRoot) -> Result<MetadataWriteGuards<'b>> {
        let mut roots: Vec<&FileRoot> = Vec::new();
        match self {
            Self::Confined { .. } => roots.push(effect_root),
            Self::OwnerLocal {
                git_dir,
                common_dir,
                ..
            } => {
                roots.push(git_dir.file_root());
                roots.push(common_dir.file_root());
                roots.push(effect_root);
            }
            Self::OwnerCommonExclude {
                workspace,
                git_dir,
                common_dir,
                ..
            } => {
                roots.push(git_dir.file_root());
                roots.push(common_dir.file_root());
                roots.push(workspace);
                roots.push(effect_root);
            }
        }
        let mut unique_roots: Vec<&FileRoot> = Vec::with_capacity(roots.len());
        for root in roots {
            if !unique_roots
                .iter()
                .any(|existing| std::ptr::eq(*existing, root))
            {
                unique_roots.push(root);
            }
        }
        let mut guards = Vec::with_capacity(unique_roots.len());
        for root in unique_roots {
            guards.push(root.write.lock().map_err(|_| Error::Limit)?);
        }
        Ok(MetadataWriteGuards { _guards: guards })
    }

    pub(super) fn check(&self, workspace: &FileRoot, target: &GitDesktopFileTarget) -> Result<()> {
        match self {
            Self::Confined {
                git_dir,
                common_dir,
                metadata,
                repository_preconditions,
            } => {
                workspace.require_git_dir(*git_dir)?;
                workspace.require_git_dir(*common_dir)?;
                workspace.check_git_desktop_repository(
                    target.repository,
                    *git_dir,
                    *common_dir,
                    repository_preconditions,
                    None,
                )?;
                workspace.check_git_preconditions(metadata)?;
                for condition in &target.worktree_preconditions {
                    workspace.check_git_pull_precondition(condition, true)?;
                }
                Ok(())
            }
            Self::OwnerLocal {
                git_dir,
                common_dir,
                metadata,
            } => {
                if git_dir.role() != OwnerGitMetadataRole::GitDir
                    || common_dir.role() != OwnerGitMetadataRole::CommonDir
                    || target.repository_preconditions.len() != 1
                {
                    return Err(Error::Invalid);
                }
                let marker = &target.repository_preconditions[0];
                workspace.check_git_desktop_marker(marker)?;
                check_owner_metadata_pair(git_dir, common_dir, metadata)?;
                for condition in &target.worktree_preconditions {
                    workspace.check_git_pull_precondition(condition, true)?;
                }
                Ok(())
            }
            Self::OwnerCommonExclude {
                workspace,
                worktree_target,
                selected,
                git_dir,
                common_dir,
                metadata,
            } => {
                if git_dir.role() != OwnerGitMetadataRole::GitDir
                    || common_dir.role() != OwnerGitMetadataRole::CommonDir
                    || worktree_target.repository_preconditions.len() != 1
                {
                    return Err(Error::Invalid);
                }
                workspace.check_git_desktop_marker(&worktree_target.repository_preconditions[0])?;
                workspace.check_git_pull_precondition(selected, true)?;
                check_owner_metadata_pair(git_dir, common_dir, metadata)?;
                Ok(())
            }
        }
    }
}

fn check_owner_metadata_pair(
    git_dir: &OwnerGitMetadataRoot,
    common_dir: &OwnerGitMetadataRoot,
    metadata: &[OwnerGitMetadataCondition],
) -> Result<()> {
    crate::desktop_git::validate_owner_git_metadata_conditions(metadata)?;
    git_dir.revalidate_binding()?;
    common_dir.revalidate_binding()?;
    let commondir = metadata
        .iter()
        .find(|condition| {
            condition.role == OwnerGitMetadataRole::GitDir
                && condition.path.components() == [b"commondir".to_vec()]
        })
        .ok_or(Error::Invalid)?;
    if commondir.expected.is_none() && git_dir.physical_identity() != common_dir.physical_identity()
    {
        return Err(Error::Changed);
    }
    for condition in metadata {
        let root = match condition.role {
            OwnerGitMetadataRole::GitDir => git_dir,
            OwnerGitMetadataRole::CommonDir => common_dir,
        };
        root.check(condition)?;
    }
    Ok(())
}

pub(crate) fn publish_common_exclude(
    workspace: &FileRoot,
    git_dir: &OwnerGitMetadataRoot,
    common_dir: &OwnerGitMetadataRoot,
    worktree_target: &GitDesktopFileTarget,
    selected: &GitPullPrecondition,
    metadata: &[OwnerGitMetadataCondition],
    target: &GitPullFile,
    check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    let authority = DesktopGitMetadataAuthority::OwnerCommonExclude {
        workspace,
        worktree_target,
        selected,
        git_dir,
        common_dir,
        metadata,
    };
    let internal_target = GitDesktopFileTarget {
        repository: common_dir.file_root().root_entry(),
        repository_preconditions: Vec::new(),
        worktree_preconditions: Vec::new(),
        file: target.clone(),
    };
    super::desktop_git::publish_file_core(
        common_dir.file_root(),
        &internal_target,
        &authority,
        check,
    )
}

pub(crate) fn publish_file(
    workspace: &FileRoot,
    git_dir: &OwnerGitMetadataRoot,
    common_dir: &OwnerGitMetadataRoot,
    publication: &OwnerGitDesktopFilePublication,
    check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    let authority = DesktopGitMetadataAuthority::OwnerLocal {
        git_dir,
        common_dir,
        metadata: &publication.metadata_preconditions,
    };
    super::desktop_git::publish_file_core(workspace, &publication.target, &authority, check)
}
