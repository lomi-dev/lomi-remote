//! Owner-local `devices.*` calls (P3a.12): list, approve, deny, revoke, mode and notices over the
//! Host's `DeviceConsent`. Circuits and fingerprints travel as lowercase hex.
use super::{
    Coordinator,
    tunnel_consent::{Approval, Kind, Notice},
};
use lomi_host_store::DeviceGrant;
use lomi_remote_crypto::Permissions;
use lomi_remote_protocol::{
    DecimalU64,
    ipc::{
        LocalCall, LocalDeviceApproval, LocalDeviceGrant, LocalDeviceLevel, LocalDeviceNotice,
        LocalDeviceNoticeKind, LocalDeviceReason, LocalDeviceText, LocalDevices, LocalError,
        LocalResult,
    },
    rpc::BoundedList,
};
use std::sync::PoisonError;

use super::tunnel_consent::DeviceConsent;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
/// Lowercase hex of exactly `N` bytes.
fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}
/// Control characters and empty names cannot cross the IPC; a device chose its own name.
fn text(s: &str) -> LocalDeviceText {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    LocalDeviceText::try_from(clean)
        .or_else(|_| LocalDeviceText::try_from("device".to_owned()))
        .expect("literal is valid")
}
fn grant(g: &DeviceGrant, now: u64) -> LocalDeviceGrant {
    LocalDeviceGrant {
        name: text(&g.device_name),
        kind: text(&g.device_kind),
        fingerprint: text(&hex(&g.device_key)),
        level: if g.ceiling == Permissions::Control && g.control_confirmed_at.is_some() {
            LocalDeviceLevel::Control
        } else {
            LocalDeviceLevel::Read
        },
        granted_at: DecimalU64(g.granted_at),
        server_confirmed_at: DecimalU64(g.server_confirmed_at),
        valid: g.is_valid(now),
    }
}
fn approval(a: &Approval) -> LocalDeviceApproval {
    LocalDeviceApproval {
        circuit: text(&hex(&a.circuit)),
        device_name: text(&a.grant.device_name),
        fingerprint: text(&hex(&a.grant.device_key)),
        code: text(&a.code),
        reason: match a.kind {
            Kind::NewDevice => LocalDeviceReason::NewDevice,
            Kind::Control => LocalDeviceReason::Control,
        },
        at: DecimalU64(a.at),
    }
}
fn notice(n: Notice) -> LocalDeviceNotice {
    use LocalDeviceNoticeKind as K;
    let (kind, name, code) = match n {
        Notice::NewDevice { device_name, .. } => (K::NewDevice, device_name, None),
        Notice::ControlRequested {
            device_name, code, ..
        } => (K::ControlRequested, device_name, Some(code)),
        Notice::GrantsFull { device_name } => (K::GrantsFull, device_name, None),
        Notice::RateLimited { device_name } => (K::RateLimited, device_name, None),
    };
    LocalDeviceNotice {
        kind,
        device_name: text(&name),
        code: code.map(|c| text(&c)),
    }
}

impl Coordinator {
    fn consent(&self) -> Result<DeviceConsent, LocalError> {
        self.consent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(LocalError::Unavailable)
    }
    fn devices(&self, consent: &DeviceConsent) -> LocalResult {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        LocalResult::Devices(LocalDevices {
            mode: consent.mode().into(),
            grants: BoundedList(consent.grants().iter().map(|g| grant(g, now)).collect()),
            pending: BoundedList(consent.pending().iter().map(approval).collect()),
        })
    }
    /// Only called for the `devices.*` variants.
    pub(super) fn devices_call(&self, call: LocalCall) -> Result<LocalResult, LocalError> {
        let consent = self.consent()?;
        let approve = matches!(call, LocalCall::DevicesApprove(_));
        match call {
            LocalCall::DevicesList {} => {}
            LocalCall::DevicesApprove(t) | LocalCall::DevicesDeny(t) => {
                let circuit = unhex::<16>(t.circuit.as_str()).ok_or(LocalError::InvalidArgument)?;
                // Nothing waits there any more (answered, closed or never asked): Conflict.
                if !(if approve {
                    consent.approve(circuit)
                } else {
                    consent.deny(circuit)
                }) {
                    return Err(LocalError::Conflict);
                }
            }
            LocalCall::DevicesRevoke(t) => {
                let key = unhex::<32>(t.fingerprint.as_str()).ok_or(LocalError::InvalidArgument)?;
                if !consent.revoke(&key) {
                    return Err(LocalError::Conflict);
                }
            }
            LocalCall::DevicesModeGet {} => {
                return Ok(LocalResult::DeviceMode(
                    lomi_remote_protocol::ipc::LocalDeviceModeState {
                        mode: consent.mode().into(),
                    },
                ));
            }
            LocalCall::DevicesModeSet(m) => {
                if !consent.set_mode(m.mode.into()) {
                    return Err(LocalError::Unavailable);
                }
                return Ok(LocalResult::DeviceMode(m));
            }
            LocalCall::DevicesNotices {} => {
                return Ok(LocalResult::DeviceNotices(BoundedList(
                    consent.take_notices().into_iter().map(notice).collect(),
                )));
            }
            _ => return Err(LocalError::InvalidArgument),
        }
        Ok(self.devices(&consent))
    }
}
