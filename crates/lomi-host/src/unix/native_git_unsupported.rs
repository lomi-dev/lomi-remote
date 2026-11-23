//! Native Git custody depends on Unix process and file identity; Windows
//! Hosts report it as unavailable instead of running an unguarded backend.
#![allow(dead_code)]

use super::{LocalError, LocalResult, owner_domain::Operation, platform, shared_owner};
use lomi_remote_protocol::ipc::{
    self, LocalNativeGitExecute, LocalNativeGitPrepare, NativeIntentId, NativeIntentTarget,
};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub(super) struct GuardedNativeGitChallenge {
    pub(super) operation_id: NativeIntentId,
    pub(super) challenge: ipc::IpcNonce,
    pub(super) before_execution: bool,
}

/// Never constructed: `execute_guarded` always fails on this platform.
pub(super) struct GuardedNativeGitExchange {
    pub(super) operation_id: NativeIntentId,
}

impl GuardedNativeGitExchange {
    pub(super) fn cancel(&self) {}
    pub(super) fn respond(_: GuardedNativeGitChallenge, _: bool) -> Result<(), ()> {
        Err(())
    }
    pub(super) fn wait_for_completion(&self, _: Duration) -> bool {
        true
    }
    pub(super) fn try_challenge(&self) -> Option<GuardedNativeGitChallenge> {
        None
    }
}

pub(super) struct NativeGitHost;

impl NativeGitHost {
    pub(super) fn new(
        _: PathBuf,
        _: Arc<shared_owner::SharedOwner>,
        _: Arc<platform::OwnerEndpoint>,
        _: Arc<AtomicBool>,
    ) -> Self {
        Self
    }
    pub(super) fn recover_pending(&self) -> Result<(), LocalError> {
        Ok(())
    }
    pub(super) fn prepare_guarded(
        &self,
        _: &Operation<'_>,
        _: ipc::IpcNonce,
        _: LocalNativeGitPrepare,
    ) -> Result<LocalResult, LocalError> {
        Err(LocalError::Unavailable)
    }
    pub(super) fn execute_guarded(
        &self,
        _: &Operation<'_>,
        _: ipc::IpcNonce,
        _: LocalNativeGitExecute,
    ) -> Result<(LocalResult, Option<GuardedNativeGitExchange>), LocalError> {
        Err(LocalError::Unavailable)
    }
    pub(super) fn authorize_before_execution(
        &self,
        _: &Operation<'_>,
        _: NativeIntentId,
    ) -> Result<(), LocalError> {
        Err(LocalError::Unavailable)
    }
    pub(super) fn status(
        &self,
        _: &Operation<'_>,
        _: NativeIntentTarget,
    ) -> Result<LocalResult, LocalError> {
        Err(LocalError::Unavailable)
    }
    pub(super) fn cancel_prepared(
        &self,
        _: &Operation<'_>,
        _: NativeIntentTarget,
    ) -> Result<LocalResult, LocalError> {
        Err(LocalError::Unavailable)
    }
    pub(super) fn acknowledge(
        &self,
        _: &Operation<'_>,
        _: NativeIntentTarget,
    ) -> Result<LocalResult, LocalError> {
        Err(LocalError::Unavailable)
    }
    pub(super) fn reap_finished(&self) {}
    pub(super) fn shutdown_and_join(&self) {}
}
