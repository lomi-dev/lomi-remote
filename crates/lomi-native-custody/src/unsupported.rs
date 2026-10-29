use crate::{Identity, Member, NativeSpec, RetiredReceipt, Scope, Transport, unavailable};
use std::{path::Path, sync::Arc};

pub struct EffectScope;
pub struct EffectGuard;

impl EffectScope {
    pub fn enter(self: &Arc<Self>) -> Result<EffectGuard, String> {
        Err(unavailable())
    }

    pub fn cancelled(&self) -> bool {
        true
    }

    pub fn cancel(&self) {}
}

pub struct Boundary {
    root: std::path::PathBuf,
    scope: Scope,
}

impl Boundary {
    pub fn create(_: &Path, _: Scope, _: NativeSpec) -> Result<Self, String> {
        Err(unavailable())
    }

    pub fn release_with_gate(
        &mut self,
        _: impl FnOnce(&Boundary) -> Result<(), String>,
    ) -> Result<(), String> {
        Err(unavailable())
    }

    pub fn take_transport(&mut self) -> Result<Transport, String> {
        Err(unavailable())
    }

    pub fn stop(&mut self) -> Result<RetiredReceipt, String> {
        Err(unavailable())
    }

    pub fn restore(_: &Path) -> Result<Self, String> {
        Err(unavailable())
    }

    pub fn verify_binding(&self, _: &Scope, _: &NativeSpec) -> Result<(), String> {
        Err(unavailable())
    }

    pub fn resize(&self, _: u16, _: u16) -> Result<(), String> {
        Err(unavailable())
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, String> {
        Err(unavailable())
    }

    pub fn retain_retirement_resource<T: Send + Sync + 'static>(
        &self,
        _: Arc<T>,
    ) -> Result<(), String> {
        Err(unavailable())
    }

    pub fn effects(&self) -> Arc<EffectScope> {
        Arc::new(EffectScope)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn release_attempted(&self) -> bool {
        false
    }

    pub fn is_released(&self) -> bool {
        false
    }

    pub fn identity(&self) -> Result<&Identity, String> {
        Err(unavailable())
    }

    pub fn member(&self) -> Result<&Member, String> {
        Err(unavailable())
    }

    pub fn signal(&self, _: i32) -> Result<(), String> {
        Err(unavailable())
    }
}
