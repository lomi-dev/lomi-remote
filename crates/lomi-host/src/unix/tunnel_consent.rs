//! Device consent for the tunnel (P3a.10): which devices the Host lets in, at what level, and
//! what happens when the account revokes one. One [`DeviceConsent`] is the engine's `Policy`, the
//! uplink's `Roster` (device list, `devices.changed`, `device.revoked`, `host.revoked`) and the
//! owner-facing queue of approvals and notices.
//!
//! It lives here, not in `lomi-host-http`, because it needs the grant store and `lomi-host` is
//! where both crates meet (`lomi-host-http` stays free of the store). Not wired in yet: the call
//! site that builds the engine (P3a.9) creates it, passes `policy()` and `roster()` and gives it
//! the engine `Handle` with `set_handle`.
//!
//! Admission, in order (first match wins):
//! - no READY seen yet, other account, `expiresAt` passed (wall clock): `Refuse`;
//! - list known and the device is not on it: `Refuse`; list unknown (server flag off or unreadable
//!   list): only a device with a valid stored grant (24 h server confirmation, deadline) passes,
//!   because a new device cannot be checked against the account;
//! - `hello` auth epoch, Host access epoch or runtime generation differ: `Stale`;
//! - valid grant: refreshed (epoch, deadline), `Welcome` (`Control` only if confirmed on the Host
//!   and the ceiling allows it);
//! - new device, store full: `Refuse` plus a `GrantsFull` notice;
//! - new device, `Auto` (D5 variant 2): grant stored read-only, `Welcome(Read)`, `NewDevice` notice;
//! - new device, `Confirm`: `Pending` with the code (rate limited, else `Refuse`); approval stores
//!   the grant with control confirmed.
//!
//! Control for an `Auto` device: the service calls `request_control(circuit)` when the check says
//! `ControlNotConfirmed`; the owner `approve`s the same code, `confirm_control` is written and the
//! device's live tunnels become `Control`.
#![allow(dead_code)]
use lomi_host_http::uplink::tunnels::{
    Admission, AttestedDevice, CircuitId, Closing, Command, DeviceEntry, DeviceEvent, Handle,
    Level, Policy, Roster,
};
use lomi_host_store::{DeviceGrant, HostStore, MAX_DEVICE_GRANTS, StoreError};
use lomi_remote_crypto::Permissions;
use lomi_remote_protocol::tunnel::{DeviceKind, Hello, StaleEpoch};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

/// Open approvals per account.
pub(super) const MAX_PENDING: usize = 3;
/// Approval prompts per account and hour (the code has only 20 bits).
pub(super) const MAX_PROMPTS_PER_HOUR: usize = 10;
const HOUR_MS: u64 = 3_600_000;
const MAX_NOTICES: usize = 32;

type Id = [u8; 16];
type Key = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    /// D5 variant 2: read at once, control after the code is confirmed on the Host.
    Auto,
    /// Every new device waits for the owner.
    Confirm,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    NewDevice,
    Control,
}
/// Something the owner has to answer; the TUI lists these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Approval {
    pub(super) circuit: CircuitId,
    pub(super) kind: Kind,
    pub(super) code: String,
    pub(super) grant: DeviceGrant,
    pub(super) at: u64,
}
/// Something the owner should know; drained by the TUI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Notice {
    NewDevice {
        device_name: String,
        fingerprint: Key,
        waiting: bool,
    },
    ControlRequested {
        device_name: String,
        fingerprint: Key,
        code: String,
    },
    /// A new device was refused: all 16 grants are in use.
    GrantsFull { device_name: String },
    /// Too many prompts: the device was refused without asking.
    RateLimited { device_name: String },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ControlError {
    UnknownCircuit,
    /// The account's ceiling for this device is read-only.
    Ceiling,
    AlreadyConfirmed,
    Limited,
}

struct Inner {
    store: Arc<Mutex<HostStore>>,
    account: Id,
    mode: Mode,
    clock: Box<dyn Fn() -> u64 + Send>,
    handle: Option<Handle>,
    /// `(host access epoch, runtime generation)` of the current link; `None` before READY.
    epochs: Option<(u64, u64)>,
    list: Option<BTreeMap<Key, DeviceEntry>>,
    pending: Vec<Approval>,
    /// Welcomed tunnels: device and the code both sides display.
    live: BTreeMap<CircuitId, (Key, String)>,
    prompts: VecDeque<u64>,
    notices: VecDeque<Notice>,
}
impl Inner {
    fn store(&self) -> MutexGuard<'_, HostStore> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn notice(&mut self, n: Notice) {
        if self.notices.len() == MAX_NOTICES {
            self.notices.pop_front();
        }
        self.notices.push_back(n);
    }
    /// One outstanding approval per device, `MAX_PENDING` per account, `MAX_PROMPTS_PER_HOUR`.
    fn allow_prompt(&mut self, device: &Key, now: u64) -> bool {
        self.prompts.retain(|t| now.saturating_sub(*t) < HOUR_MS);
        if self.pending.len() >= MAX_PENDING
            || self.prompts.len() >= MAX_PROMPTS_PER_HOUR
            || self.pending.iter().any(|p| p.grant.device_key == *device)
        {
            return false;
        }
        self.prompts.push_back(now);
        true
    }
    fn revoke_where(&mut self, pick: impl Fn(&DeviceGrant) -> bool) {
        let mut store = self.store();
        for g in store
            .list_grants()
            .unwrap_or_default()
            .iter()
            .filter(|g| pick(g))
        {
            let _ = store.revoke(&g.device_key);
        }
    }

    fn admit(
        &mut self,
        circuit: CircuitId,
        d: &AttestedDevice,
        h: &Hello,
        code: &str,
    ) -> Admission {
        let now = (self.clock)();
        let Some((host_access_epoch, runtime_generation)) = self.epochs else {
            return Admission::Refuse;
        };
        let on_list = self.list.as_ref().map(|l| l.contains_key(&d.fingerprint));
        if d.account_id != self.account || d.expires_at <= now || on_list == Some(false) {
            return Admission::Refuse;
        }
        let Ok(grant) = self.store().get_grant(&d.fingerprint) else {
            return Admission::Refuse;
        };
        let grant = grant.filter(|g| g.account_id == self.account);
        if on_list.is_none() && !grant.as_ref().is_some_and(|g| g.is_valid(now)) {
            return Admission::Refuse;
        }
        if h.auth_epoch != d.auth_epoch
            || h.host_access_epoch != host_access_epoch
            || h.runtime_generation != runtime_generation
        {
            return Admission::Stale {
                epochs: StaleEpoch {
                    auth_epoch: d.auth_epoch,
                    host_access_epoch,
                    runtime_generation,
                },
            };
        }
        if let Some(mut grant) = grant {
            grant.authorization_epoch = d.auth_epoch;
            grant.authorization_expires_at = d.expires_at;
            if !grant.is_valid(now) || self.store().upsert_grant(&grant).is_err() {
                return Admission::Refuse;
            }
            self.live.insert(circuit, (d.fingerprint, code.to_owned()));
            return Admission::Welcome {
                level: level_of(&grant),
            };
        }
        let new = DeviceGrant {
            device_key: d.fingerprint,
            account_id: d.account_id,
            device_id: d.device_id,
            device_name: h.device_name.as_str().to_owned(),
            device_kind: match h.device_kind {
                DeviceKind::Web => "web",
                DeviceKind::Mobile => "mobile",
                DeviceKind::Desktop => "desktop",
            }
            .to_owned(),
            ceiling: Permissions::Control,
            granted_at: now,
            authorization_expires_at: d.expires_at,
            authorization_epoch: d.auth_epoch,
            server_confirmed_at: now,
            control_confirmed_at: None,
        };
        let full = self
            .store()
            .list_grants()
            .map_or(true, |g| g.len() >= MAX_DEVICE_GRANTS);
        if full {
            self.notice(Notice::GrantsFull {
                device_name: new.device_name,
            });
            return Admission::Refuse;
        }
        match self.mode {
            Mode::Auto => {
                if self.store().upsert_grant(&new).is_err() {
                    return Admission::Refuse;
                }
                self.notice(Notice::NewDevice {
                    device_name: new.device_name,
                    fingerprint: d.fingerprint,
                    waiting: false,
                });
                self.live.insert(circuit, (d.fingerprint, code.to_owned()));
                Admission::Welcome { level: Level::Read }
            }
            Mode::Confirm => {
                if !self.allow_prompt(&d.fingerprint, now) {
                    self.notice(Notice::RateLimited {
                        device_name: new.device_name,
                    });
                    return Admission::Refuse;
                }
                self.notice(Notice::NewDevice {
                    device_name: new.device_name.clone(),
                    fingerprint: d.fingerprint,
                    waiting: true,
                });
                self.pending.push(Approval {
                    circuit,
                    kind: Kind::NewDevice,
                    code: code.to_owned(),
                    grant: new,
                    at: now,
                });
                Admission::Pending
            }
        }
    }

    fn apply(&mut self, event: &DeviceEvent) -> Option<Closing> {
        let now = (self.clock)();
        match event {
            DeviceEvent::Ready {
                host_access_epoch,
                runtime_generation,
                devices,
            } => {
                self.epochs = Some((*host_access_epoch, *runtime_generation));
                let Some(devices) = devices else {
                    self.list = None; // unknown: nothing is wiped, only valid grants are let in
                    return None;
                };
                let keys: Vec<Key> = devices.iter().map(|e| e.fingerprint).collect();
                {
                    let mut store = self.store();
                    let _ = store.revoke_account_devices_not_in(&self.account, &keys);
                    let _ = store.mark_server_confirmed(&keys, now);
                }
                self.list = Some(devices.iter().map(|e| (e.fingerprint, e.clone())).collect());
                Some(Box::new(move |d| !keys.contains(&d.fingerprint)))
            }
            DeviceEvent::Changed(e) => {
                let (id, key) = (e.device_id, e.fingerprint);
                // The same device with another key: the old key is gone.
                self.revoke_where(|g| g.device_id == id && g.device_key != key);
                if let Some(list) = &mut self.list {
                    list.retain(|_, x| x.device_id != id);
                    list.insert(key, e.clone());
                }
                let grant = self.store().get_grant(&key).ok().flatten();
                if let Some(mut g) = grant.filter(|g| g.account_id == self.account) {
                    g.authorization_epoch = e.auth_epoch;
                    g.authorization_expires_at = e.expires_at;
                    g.server_confirmed_at = now;
                    let _ = self.store().upsert_grant(&g);
                }
                Some(Box::new(move |d| d.device_id == id && d.fingerprint != key))
            }
            DeviceEvent::Revoked {
                device_id,
                fingerprint,
            } => {
                let (id, key) = (*device_id, *fingerprint);
                self.revoke_where(|g| g.device_id == id || Some(g.device_key) == key);
                if let Some(list) = &mut self.list {
                    list.retain(|k, x| x.device_id != id && Some(*k) != key);
                }
                Some(Box::new(move |d| {
                    d.device_id == id || Some(d.fingerprint) == key
                }))
            }
            DeviceEvent::HostRevoked => {
                self.revoke_where(|_| true);
                (self.list, self.epochs) = (None, None);
                Some(Box::new(|_| true))
            }
        }
    }
}

fn level_of(g: &DeviceGrant) -> Level {
    if g.ceiling == Permissions::Control && g.control_confirmed_at.is_some() {
        Level::Control
    } else {
        Level::Read
    }
}

/// Cheap to clone; every clone is the same consent state.
#[derive(Clone)]
pub(super) struct DeviceConsent(Arc<Mutex<Inner>>);

impl DeviceConsent {
    pub(super) fn new(store: Arc<Mutex<HostStore>>, account: Id, mode: Mode) -> Self {
        Self::with_clock(store, account, mode, || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64)
        })
    }
    pub(super) fn with_clock(
        store: Arc<Mutex<HostStore>>,
        account: Id,
        mode: Mode,
        clock: impl Fn() -> u64 + Send + 'static,
    ) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            store,
            account,
            mode,
            clock: Box::new(clock),
            handle: None,
            epochs: None,
            list: None,
            pending: Vec::new(),
            live: BTreeMap::new(),
            prompts: VecDeque::new(),
            notices: VecDeque::new(),
        })))
    }
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// For `install_tunnels(.., Box::new(c.policy()), ..)`.
    pub(super) fn policy(&self) -> Box<dyn Policy> {
        Box::new(self.clone())
    }
    /// For `uplink::install_roster`.
    pub(super) fn roster(&self) -> Box<dyn Roster> {
        Box::new(self.clone())
    }
    /// The engine handle `install_tunnels` returned; approvals need it.
    pub(super) fn set_handle(&self, handle: Handle) {
        self.inner().handle = Some(handle);
    }

    /// The service asks for control on `circuit` (check said `ControlNotConfirmed`). Returns the
    /// code the owner must see on both screens. Asking again on the same circuit repeats it.
    pub(super) fn request_control(&self, circuit: CircuitId) -> Result<String, ControlError> {
        let mut g = self.inner();
        let now = (g.clock)();
        let (key, code) = g
            .live
            .get(&circuit)
            .cloned()
            .ok_or(ControlError::UnknownCircuit)?;
        if let Some(p) = g.pending.iter().find(|p| p.circuit == circuit) {
            return Ok(p.code.clone());
        }
        let grant = match g.store().get_grant(&key) {
            Ok(Some(grant)) => grant,
            _ => return Err(ControlError::UnknownCircuit),
        };
        if grant.ceiling != Permissions::Control {
            return Err(ControlError::Ceiling);
        }
        if grant.control_confirmed_at.is_some() {
            return Err(ControlError::AlreadyConfirmed);
        }
        if !g.allow_prompt(&key, now) {
            g.notice(Notice::RateLimited {
                device_name: grant.device_name,
            });
            return Err(ControlError::Limited);
        }
        g.notice(Notice::ControlRequested {
            device_name: grant.device_name.clone(),
            fingerprint: key,
            code: code.clone(),
        });
        g.pending.push(Approval {
            circuit,
            kind: Kind::Control,
            code: code.clone(),
            grant,
            at: now,
        });
        Ok(code)
    }
    /// The owner confirmed the code. False: nothing waits there any more, or it could not be
    /// stored or delivered (then it stays open).
    pub(super) fn approve(&self, circuit: CircuitId) -> bool {
        let mut g = self.inner();
        let now = (g.clock)();
        let (Some(i), Some(handle)) = (
            g.pending.iter().position(|p| p.circuit == circuit),
            g.handle.clone(),
        ) else {
            return false;
        };
        let a = g.pending[i].clone();
        let key = a.grant.device_key;
        let sent = match a.kind {
            Kind::NewDevice => {
                let grant = DeviceGrant {
                    server_confirmed_at: now,
                    control_confirmed_at: Some(now),
                    ..a.grant
                };
                let stored = g.store().upsert_grant(&grant);
                if matches!(stored, Err(StoreError::DeviceGrantsFull)) {
                    g.notice(Notice::GrantsFull {
                        device_name: grant.device_name.clone(),
                    });
                }
                stored.is_ok()
                    && handle
                        .push(Command::Approve {
                            circuit,
                            level: level_of(&grant),
                        })
                        .is_ok()
            }
            Kind::Control => {
                g.store().confirm_control(&key, now).is_ok()
                    && handle
                        .push(Command::SetLevel {
                            fingerprint: key,
                            level: Level::Control,
                        })
                        .is_ok()
            }
        };
        if sent {
            g.pending.remove(i);
            g.live.insert(circuit, (key, a.code));
        }
        sent
    }
    /// The owner said no. A new device's tunnel is closed; a control request just ends (the device
    /// stays read-only).
    pub(super) fn deny(&self, circuit: CircuitId) -> bool {
        let mut g = self.inner();
        let Some(i) = g.pending.iter().position(|p| p.circuit == circuit) else {
            return false;
        };
        if g.pending.remove(i).kind == Kind::NewDevice
            && let Some(h) = &g.handle
        {
            let _ = h.push(Command::Deny { circuit });
        }
        true
    }
    pub(super) fn pending(&self) -> Vec<Approval> {
        self.inner().pending.clone()
    }
    pub(super) fn take_notices(&self) -> Vec<Notice> {
        self.inner().notices.drain(..).collect()
    }
}

impl Policy for DeviceConsent {
    fn admit(&self, d: &AttestedDevice, h: &Hello, code: &str) -> Admission {
        self.admit_circuit([0; 16], d, h, code)
    }
    fn admit_circuit(
        &self,
        circuit: CircuitId,
        d: &AttestedDevice,
        h: &Hello,
        code: &str,
    ) -> Admission {
        self.inner().admit(circuit, d, h, code)
    }
    fn closed(&self, circuit: CircuitId) {
        let mut g = self.inner();
        g.pending.retain(|p| p.circuit != circuit);
        g.live.remove(&circuit);
    }
}
impl Roster for DeviceConsent {
    fn apply(&mut self, event: &DeviceEvent) -> Option<Closing> {
        self.inner().apply(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_host_store::Limits;
    use lomi_remote_protocol::{rpc::BoundedList, tunnel::DeviceName};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const ACCOUNT: Id = [1; 16];
    const T0: u64 = 10_000_000_000;

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct Rig {
        c: DeviceConsent,
        store: Arc<Mutex<HostStore>>,
        clock: Arc<AtomicU64>,
        inbox: Handle,
        _dir: Dir,
    }
    fn rig(mode: Mode) -> Rig {
        let path = std::env::temp_dir().join(format!("lomi-consent-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let dir = Dir(fs::canonicalize(&path).unwrap());
        let store = Arc::new(Mutex::new(
            HostStore::open(&dir.0.join("host.sqlite3"), Limits::default()).unwrap(),
        ));
        let clock = Arc::new(AtomicU64::new(T0));
        let c = {
            let clock = clock.clone();
            DeviceConsent::with_clock(store.clone(), ACCOUNT, mode, move || {
                clock.load(Ordering::SeqCst)
            })
        };
        let inbox = Handle::new(|| {});
        c.set_handle(inbox.clone());
        Rig {
            c,
            store,
            clock,
            inbox,
            _dir: dir,
        }
    }
    impl Rig {
        fn ready(&mut self, list: Option<Vec<DeviceEntry>>) -> Option<Closing> {
            self.c.apply(&DeviceEvent::Ready {
                host_access_epoch: 2,
                runtime_generation: 3,
                devices: list,
            })
        }
        fn grants(&self) -> Vec<DeviceGrant> {
            self.store.lock().unwrap().list_grants().unwrap()
        }
        fn commands(&self) -> Vec<Command> {
            self.inbox.take()
        }
    }
    fn entry(n: u8) -> DeviceEntry {
        DeviceEntry {
            device_id: [n; 16],
            fingerprint: [n; 32],
            client_class: None,
            auth_epoch: 5,
            expires_at: T0 + 3_600_000,
        }
    }
    fn device(n: u8) -> AttestedDevice {
        AttestedDevice {
            account_id: ACCOUNT,
            device_id: [n; 16],
            client_class: None,
            fingerprint: [n; 32],
            auth_epoch: 5,
            expires_at: T0 + 3_600_000,
        }
    }
    fn hello(epoch: u64) -> Hello {
        Hello {
            device_name: DeviceName::try_from("Phone".to_string()).unwrap(),
            device_kind: DeviceKind::Mobile,
            auth_epoch: epoch,
            host_access_epoch: 2,
            runtime_generation: 3,
            resume: BoundedList(vec![]),
            send_directory: false,
            device_bundle: BoundedList(vec![]),
        }
    }
    fn admit(r: &Rig, n: u8, circuit: u8) -> Admission {
        r.c.admit_circuit([circuit; 16], &device(n), &hello(5), "123456")
    }
    const READ: Admission = Admission::Welcome { level: Level::Read };

    #[test]
    fn refuses_what_the_account_does_not_vouch_for() {
        let mut r = rig(Mode::Auto);
        assert_eq!(admit(&r, 1, 1), Admission::Refuse, "no READY yet");
        r.ready(Some(vec![entry(1)]));
        let mut d = device(1);
        d.account_id = [9; 16];
        assert_eq!(
            r.c.admit_circuit([1; 16], &d, &hello(5), "1"),
            Admission::Refuse
        );
        let mut d = device(1);
        d.expires_at = T0;
        assert_eq!(
            r.c.admit_circuit([1; 16], &d, &hello(5), "1"),
            Admission::Refuse
        );
        assert_eq!(admit(&r, 2, 1), Admission::Refuse, "not on the list");
        assert_eq!(admit(&r, 1, 1), READ);
    }

    #[test]
    fn stale_epochs_carry_the_current_ones() {
        let mut r = rig(Mode::Auto);
        r.ready(Some(vec![entry(1)]));
        let Admission::Stale { epochs } = r.c.admit_circuit([1; 16], &device(1), &hello(4), "1")
        else {
            panic!()
        };
        assert_eq!(
            (
                epochs.auth_epoch,
                epochs.host_access_epoch,
                epochs.runtime_generation
            ),
            (5, 2, 3)
        );
        let mut h = hello(5);
        h.runtime_generation = 9;
        assert!(matches!(
            r.c.admit_circuit([1; 16], &device(1), &h, "1"),
            Admission::Stale { .. }
        ));
        assert!(r.grants().is_empty(), "a stale device leaves no grant");
    }

    #[test]
    fn new_device_gets_read_a_notice_and_a_refreshed_grant_next_time() {
        let mut r = rig(Mode::Auto);
        r.ready(Some(vec![entry(1)]));
        assert_eq!(admit(&r, 1, 1), READ);
        let g = &r.grants()[0];
        assert_eq!(
            (g.ceiling, g.control_confirmed_at),
            (Permissions::Control, None)
        );
        assert!(matches!(
            r.c.take_notices()[..],
            [Notice::NewDevice { waiting: false, .. }]
        ));
        let mut d = device(1);
        d.auth_epoch = 6;
        d.expires_at += 1000;
        let h = Hello {
            auth_epoch: 6,
            ..hello(5)
        };
        assert_eq!(r.c.admit_circuit([2; 16], &d, &h, "1"), READ);
        assert_eq!(r.grants()[0].authorization_epoch, 6);
        assert!(r.c.take_notices().is_empty(), "known device: no notice");
    }

    #[test]
    fn read_then_request_control_then_approve_raises_the_level() {
        let mut r = rig(Mode::Auto);
        r.ready(Some(vec![entry(1)]));
        assert_eq!(admit(&r, 1, 1), READ);
        r.c.take_notices();
        assert_eq!(r.c.request_control([1; 16]), Ok("123456".into()));
        assert_eq!(
            r.c.request_control([1; 16]),
            Ok("123456".into()),
            "same circuit repeats"
        );
        assert!(matches!(
            r.c.take_notices()[..],
            [Notice::ControlRequested { .. }]
        ));
        assert_eq!(r.c.pending().len(), 1);
        assert!(r.c.approve([1; 16]));
        assert!(r.c.pending().is_empty());
        assert_eq!(r.grants()[0].control_confirmed_at, Some(T0));
        assert!(matches!(
            r.commands()[..],
            [Command::SetLevel {
                fingerprint: [1, ..],
                level: Level::Control
            }]
        ));
        assert_eq!(
            r.c.request_control([1; 16]),
            Err(ControlError::AlreadyConfirmed)
        );
        // a later tunnel of the device starts at Control
        assert_eq!(
            admit(&r, 1, 2),
            Admission::Welcome {
                level: Level::Control
            }
        );
        assert_eq!(
            r.c.request_control([7; 16]),
            Err(ControlError::UnknownCircuit)
        );
    }

    #[test]
    fn confirm_mode_waits_for_the_owner_and_approval_grants_control() {
        let mut r = rig(Mode::Confirm);
        r.ready(Some(vec![entry(1)]));
        assert_eq!(admit(&r, 1, 1), Admission::Pending);
        assert!(r.grants().is_empty(), "nothing is stored before approval");
        assert_eq!(r.c.pending()[0].code, "123456");
        assert!(r.c.approve([1; 16]));
        assert_eq!(r.grants()[0].control_confirmed_at, Some(T0));
        assert!(matches!(
            r.commands()[..],
            [Command::Approve {
                circuit: [1, ..],
                level: Level::Control
            }]
        ));
        // deny ends the wait and closes the circuit
        r.ready(Some(vec![entry(1), entry(2)]));
        assert_eq!(admit(&r, 2, 2), Admission::Pending);
        assert!(r.c.deny([2; 16]));
        assert!(matches!(
            r.commands()[..],
            [Command::Deny { circuit: [2, ..] }]
        ));
        assert!(r.c.pending().is_empty());
        assert!(!r.c.approve([2; 16]));
    }

    #[test]
    fn approval_prompts_are_rate_limited() {
        let mut r = rig(Mode::Confirm);
        let list: Vec<_> = (1..=12).map(entry).collect();
        r.ready(Some(list));
        // one outstanding per device
        assert_eq!(admit(&r, 1, 1), Admission::Pending);
        assert_eq!(admit(&r, 1, 2), Admission::Refuse);
        // three open per account
        assert_eq!(admit(&r, 2, 3), Admission::Pending);
        assert_eq!(admit(&r, 3, 4), Admission::Pending);
        assert_eq!(admit(&r, 4, 5), Admission::Refuse);
        assert!(
            r.c.take_notices()
                .iter()
                .any(|n| matches!(n, Notice::RateLimited { .. }))
        );
        // closing the circuits frees the slots, but the hour allows 10 prompts in all
        for n in 1..=3 {
            r.c.closed([n; 16]);
        }
        r.c.closed([4; 16]);
        for (i, n) in (4..=10).enumerate() {
            assert_eq!(admit(&r, n, 10 + n), Admission::Pending, "prompt {}", 4 + i);
            r.c.closed([10 + n; 16]);
        }
        assert_eq!(
            admit(&r, 11, 30),
            Admission::Refuse,
            "11th prompt within the hour"
        );
        r.clock.fetch_add(HOUR_MS, Ordering::SeqCst);
        let mut d = device(11);
        d.expires_at += HOUR_MS; // the attestation of an hour later
        assert_eq!(
            r.c.admit_circuit([31; 16], &d, &hello(5), "1"),
            Admission::Pending
        );
    }

    #[test]
    fn a_full_store_refuses_and_says_so() {
        let mut r = rig(Mode::Auto);
        let list: Vec<_> = (1..=17).map(entry).collect();
        r.ready(Some(list));
        for n in 1..=16 {
            assert_eq!(admit(&r, n, n), READ);
        }
        r.c.take_notices();
        assert_eq!(admit(&r, 17, 17), Admission::Refuse);
        assert!(matches!(
            r.c.take_notices()[..],
            [Notice::GrantsFull { .. }]
        ));
        assert_eq!(r.grants().len(), 16);
    }

    #[test]
    fn reconciliation_removes_grants_that_vanished_while_the_host_was_off() {
        let mut r = rig(Mode::Auto);
        r.ready(Some(vec![entry(1), entry(2)]));
        admit(&r, 1, 1);
        admit(&r, 2, 2);
        // the Host restarts; device 1 was revoked meanwhile
        let mut r2 = rig(Mode::Auto);
        r2.store = r.store.clone();
        r2.c = DeviceConsent::with_clock(r.store.clone(), ACCOUNT, Mode::Auto, {
            let c = r.clock.clone();
            move || c.load(Ordering::SeqCst)
        });
        let closing = r2.ready(Some(vec![entry(2)])).unwrap();
        assert_eq!(
            r2.grants()
                .iter()
                .map(|g| g.device_id[0])
                .collect::<Vec<_>>(),
            [2]
        );
        assert!(closing(&device(1)) && !closing(&device(2)));
        assert_eq!(admit(&r2, 1, 3), Admission::Refuse);
        assert_eq!(admit(&r2, 2, 4), READ);
    }

    #[test]
    fn an_unknown_list_wipes_nothing_and_lets_in_valid_grants_only() {
        let mut r = rig(Mode::Auto);
        r.ready(Some(vec![entry(1), entry(2)]));
        admit(&r, 1, 1);
        assert!(r.ready(None).is_none());
        assert_eq!(r.grants().len(), 1);
        assert_eq!(admit(&r, 1, 2), READ, "valid grant");
        assert_eq!(
            admit(&r, 2, 3),
            Admission::Refuse,
            "new device cannot be checked"
        );
        // 24 h without server confirmation: the grant is no longer valid
        r.clock.fetch_add(24 * HOUR_MS + 1, Ordering::SeqCst);
        let mut d = device(1);
        d.expires_at += 24 * HOUR_MS + 1;
        assert_eq!(
            r.c.admit_circuit([4; 16], &d, &hello(5), "1"),
            Admission::Refuse
        );
    }

    #[test]
    fn revocation_events_drop_grants_and_name_the_tunnels_to_close() {
        let mut r = rig(Mode::Auto);
        r.ready(Some(vec![entry(1), entry(2), entry(3)]));
        for n in 1..=3 {
            admit(&r, n, n);
        }
        // by fingerprint-less deviceId
        let close =
            r.c.apply(&DeviceEvent::Revoked {
                device_id: [1; 16],
                fingerprint: None,
            })
            .unwrap();
        assert!(close(&device(1)) && !close(&device(2)));
        assert_eq!(r.grants().len(), 2);
        assert_eq!(admit(&r, 1, 9), Admission::Refuse, "also off the list");
        // by fingerprint
        let close =
            r.c.apply(&DeviceEvent::Revoked {
                device_id: [9; 16],
                fingerprint: Some([2; 32]),
            })
            .unwrap();
        assert!(close(&device(2)) && !close(&device(3)));
        // same deviceId, new key: the old grant and its tunnels go
        let mut moved = entry(3);
        moved.fingerprint = [0x33; 32];
        let close = r.c.apply(&DeviceEvent::Changed(moved)).unwrap();
        let mut old = device(3);
        old.fingerprint = [3; 32];
        assert!(close(&old));
        assert!(r.grants().is_empty());
        // host.revoked: everything goes
        admit(&r, 1, 1);
        r.ready(Some(vec![entry(1)]));
        admit(&r, 1, 1);
        let close = r.c.apply(&DeviceEvent::HostRevoked).unwrap();
        assert!(close(&device(5)) && r.grants().is_empty());
        assert_eq!(
            admit(&r, 1, 1),
            Admission::Refuse,
            "epochs forgotten until READY"
        );
    }

    #[test]
    fn devices_changed_refreshes_deadline_and_confirmation() {
        let mut r = rig(Mode::Auto);
        r.ready(Some(vec![entry(1)]));
        admit(&r, 1, 1);
        r.clock.fetch_add(HOUR_MS, Ordering::SeqCst);
        let mut e = entry(1);
        e.auth_epoch = 6;
        e.expires_at += 10 * HOUR_MS;
        r.c.apply(&DeviceEvent::Changed(e.clone()));
        let g = &r.grants()[0];
        assert_eq!(
            (
                g.authorization_epoch,
                g.authorization_expires_at,
                g.server_confirmed_at
            ),
            (6, e.expires_at, T0 + HOUR_MS)
        );
    }

    #[test]
    fn closed_circuits_leave_no_approvals_behind() {
        let mut r = rig(Mode::Confirm);
        r.ready(Some(vec![entry(1)]));
        assert_eq!(admit(&r, 1, 1), Admission::Pending);
        r.c.closed([1; 16]);
        assert!(r.c.pending().is_empty() && !r.c.approve([1; 16]));
    }

    /// The real engine and a real Noise handshake against `DeviceConsent`.
    mod engine {
        use super::*;
        use lomi_host_http::uplink::tunnels::{Config, Engine, Out, testing::Echo};
        use lomi_remote_crypto::{Identity, Role, TunnelHandshake, TunnelPath, TunnelPrologue};
        use lomi_remote_protocol::tunnel::HostGreeting;
        use serde_json::{Value, json};

        const HASH: [u8; 32] = [7; 32];
        const HOST_ID: Id = [0xb2; 16];

        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        fn dashed(id: &Id) -> String {
            let h = hex(id);
            format!(
                "{}-{}-{}-{}-{}",
                &h[..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..]
            )
        }
        struct World {
            r: Rig,
            e: Engine,
            host: lomi_remote_crypto::SignedBundle,
            log: Arc<Mutex<Vec<String>>>,
            id: Identity,
        }
        fn world(mode: Mode) -> World {
            let r = rig(mode);
            let host = Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap();
            let bundle = host.public_bundle();
            let echo = Echo::default();
            let log = echo.log.clone();
            let e = Engine::new(
                Config {
                    identity: host,
                    host_id: HOST_ID,
                    contract_hash: HASH,
                },
                r.c.policy(),
                Box::new(echo),
                r.inbox.clone(),
            )
            .unwrap();
            let id = Identity::generate(ACCOUNT, [1; 16], Role::Device, 1).unwrap();
            World {
                r,
                e,
                host: bundle,
                log,
                id,
            }
        }
        fn entry_of(id: &Identity) -> DeviceEntry {
            let b = &id.public_bundle().bundle;
            DeviceEntry {
                device_id: b.subject_id,
                fingerprint: b.fingerprint().unwrap(),
                client_class: None,
                auth_epoch: 5,
                expires_at: T0 + HOUR_MS,
            }
        }
        impl World {
            /// Relay-side `circuit.open`, then the device's three messages; returns the device
            /// side of the tunnel and what the Host sent after message 3.
            fn connect(&mut self, c: u8) -> (lomi_remote_crypto::Tunnel, String, Vec<Out>) {
                let circuit = [c; 16];
                let e = entry_of(&self.id);
                let Value::Object(ev) = json!({
                    "circuitId": hex(&circuit), "nonce": hex(&circuit),
                    "device": {"accountId": dashed(&ACCOUNT), "deviceId": dashed(&e.device_id),
                        "clientClass": "native",
                        "attestation": {"fingerprint": hex(&e.fingerprint), "authEpoch": "5",
                                        "expiresAt": e.expires_at}},
                }) else {
                    unreachable!()
                };
                self.e.on_circuit_open(&ev, 0);
                let host_fp = self.host.bundle.fingerprint().unwrap();
                let p = TunnelPrologue {
                    contract_hash: HASH,
                    path: TunnelPath::Relay,
                    circuit_id: circuit,
                    nonce: circuit,
                    host_id: HOST_ID,
                    host_fingerprint: host_fp,
                    device_fingerprint: e.fingerprint,
                    account_id: ACCOUNT,
                };
                let mut hs = TunnelHandshake::device(&self.id, &p, &self.host, &host_fp).unwrap();
                let send = |w: &mut Self, b: &[u8]| w.e.on_data(&[&circuit[..], b].concat(), 0);
                send(self, &hs.write_message(&[]).unwrap());
                let Some(Out::Data { bytes, .. }) = self.e.take_out().into_iter().next() else {
                    panic!("message 2 expected")
                };
                hs.read_message(&bytes).unwrap();
                let hello: Hello = serde_json::from_value(json!({
                    "deviceName": "T", "deviceKind": "web", "authEpoch": 5, "hostAccessEpoch": 2,
                    "runtimeGeneration": 3, "resume": [], "sendDirectory": false,
                    "deviceBundle": serde_json::to_vec(&self.id.public_bundle()).unwrap(),
                }))
                .unwrap();
                let m3 = hs.write_message(&hello.encode().unwrap()).unwrap();
                let code = hs.confirmation_code().unwrap();
                let noise = hs.into_transport().unwrap();
                send(self, &m3);
                (noise, code, self.e.take_out())
            }
            fn greeting(noise: &mut lomi_remote_crypto::Tunnel, outs: &[Out]) -> HostGreeting {
                let Some(Out::Data { bytes, .. }) = outs.first() else {
                    panic!("{outs:?}")
                };
                HostGreeting::decode(&noise.decrypt(bytes).unwrap()).unwrap()
            }
            fn revoke(&mut self, n: u8) {
                let id = [n; 16];
                let close = self
                    .r
                    .c
                    .apply(&DeviceEvent::Revoked {
                        device_id: id,
                        fingerprint: None,
                    })
                    .unwrap();
                self.e.close_where("deviceRevoked", close);
            }
        }

        #[test]
        fn confirm_mode_gives_approval_pending_and_no_data_until_approved() {
            let mut w = world(Mode::Confirm);
            w.r.ready(Some(vec![entry_of(&w.id)]));
            let (mut noise, code, outs) = w.connect(1);
            let HostGreeting::ApprovalPending(p) = World::greeting(&mut noise, &outs) else {
                panic!("approval.pending expected")
            };
            assert_eq!((format!("{:06}", p.code), outs.len()), (code.clone(), 1));
            assert_eq!(
                w.r.c.pending()[0].code,
                code,
                "the Host shows the same code"
            );
            assert!(
                w.log.lock().unwrap().is_empty(),
                "the service heard nothing"
            );
            assert!(w.r.c.approve([1; 16]));
            w.e.drain_commands();
            let outs = w.e.take_out();
            assert_eq!(
                World::greeting(&mut noise, &outs),
                HostGreeting::Welcome(lomi_remote_protocol::tunnel::Welcome { directory: false })
            );
            assert_eq!(*w.log.lock().unwrap(), ["open"]);
        }

        #[test]
        fn revocation_closes_the_live_tunnel_on_the_event_and_refuses_the_next() {
            let mut w = world(Mode::Auto);
            w.r.ready(Some(vec![entry_of(&w.id)]));
            let (mut noise, _, outs) = w.connect(1);
            assert!(matches!(
                World::greeting(&mut noise, &outs),
                HostGreeting::Welcome(_)
            ));
            w.revoke(1);
            assert_eq!(
                w.e.take_out(),
                [Out::Close { circuit: [1; 16] }],
                "no timer involved"
            );
            assert_eq!(w.log.lock().unwrap().last().unwrap(), "close deviceRevoked");
            assert!(w.r.grants().is_empty());
            // it comes back with a new circuit: not on the list any more
            let (_, _, outs) = w.connect(2);
            assert_eq!(outs, [Out::Close { circuit: [2; 16] }]);
        }

        #[test]
        fn revoked_while_the_host_was_off_is_refused_after_start() {
            let mut w = world(Mode::Auto);
            w.r.ready(Some(vec![entry_of(&w.id)]));
            let (mut noise, _, outs) = w.connect(1);
            assert!(matches!(
                World::greeting(&mut noise, &outs),
                HostGreeting::Welcome(_)
            ));
            w.e.link_down(); // the Host stops
            // restart: same store, READY without the device
            let mut w2 = world(Mode::Auto);
            w2.r.c = DeviceConsent::with_clock(w.r.store.clone(), ACCOUNT, Mode::Auto, || T0);
            w2.e = {
                let host = Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap();
                w2.host = host.public_bundle();
                Engine::new(
                    Config {
                        identity: host,
                        host_id: HOST_ID,
                        contract_hash: HASH,
                    },
                    w2.r.c.policy(),
                    Box::new(Echo::default()),
                    w2.r.inbox.clone(),
                )
                .unwrap()
            };
            w2.id = Identity::import_secret_seed_blob(
                &w.id.export_secret_seed_blob().unwrap(),
                &w.id.public_bundle(),
            )
            .unwrap();
            w2.r.ready(Some(vec![]));
            assert!(
                w2.r.grants().is_empty(),
                "the grant is gone before anyone connects"
            );
            let (_, _, outs) = w2.connect(1);
            assert_eq!(outs, [Out::Close { circuit: [1; 16] }]);
        }

        #[test]
        fn the_authorization_deadline_closes_a_live_tunnel() {
            let mut w = world(Mode::Auto);
            w.r.ready(Some(vec![entry_of(&w.id)]));
            let (mut noise, _, outs) = w.connect(1);
            assert!(matches!(
                World::greeting(&mut noise, &outs),
                HostGreeting::Welcome(_)
            ));
            w.e.expire(T0 + HOUR_MS - 1);
            assert!(w.e.take_out().is_empty());
            w.e.expire(T0 + HOUR_MS);
            assert_eq!(w.e.take_out(), [Out::Close { circuit: [1; 16] }]);
            assert_eq!(
                w.log.lock().unwrap().last().unwrap(),
                "close authorizationExpired"
            );
        }
    }
}
