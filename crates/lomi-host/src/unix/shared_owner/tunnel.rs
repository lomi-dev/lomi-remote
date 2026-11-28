//! One read for the device tunnel service (P3a.9): the device's grant, the projects the
//! authorization ceilings come from, and the Host name for the directory.
use super::{Error, Operation, SharedOwner};
use lomi_host_store::{DeviceGrant, ProjectRecord};

pub(in super::super) struct TunnelView {
    pub(in super::super) grant: Option<DeviceGrant>,
    pub(in super::super) projects: Vec<ProjectRecord>,
    pub(in super::super) host_name: Option<String>,
}

impl SharedOwner {
    /// The same store the owner uses, for device consent (it writes grants itself).
    pub(in super::super) fn store_handle(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<lomi_host_store::HostStore>> {
        self.store.clone()
    }
    pub(in super::super) fn tunnel_view(
        &self,
        operation: &Operation<'_>,
        device_key: &[u8; 32],
    ) -> Result<TunnelView, Error> {
        self.read(operation, |store| {
            Ok(TunnelView {
                grant: store.get_grant(device_key)?,
                projects: store.list_projects()?,
                host_name: store
                    .host_display_name()?
                    .map(|name| name.as_str().to_owned()),
            })
        })
    }
}

#[cfg(test)]
impl SharedOwner {
    pub(in super::super) fn with_store_for_test<R>(
        &self,
        f: impl FnOnce(&mut lomi_host_store::HostStore) -> R,
    ) -> R {
        f(&mut self.store.lock().unwrap())
    }
}
