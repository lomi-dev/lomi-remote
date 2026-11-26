//! On-device directory (`04-bezpieczenstwo.md`, decision D2): Hosts, workspaces and
//! their availability, kept between launches so the list shows in the first frame.
//! Names only, never content. The core does no I/O: the platform loads and stores
//! the blob, keeps the key in the OS keystore and supplies the nonce.
//!
//! Merge rules: the server is authoritative. A session response or an
//! `inventory.changed` snapshot replaces the Host list, but a Host entry never
//! moves back to an older `(accessEpoch, runtimeGeneration)`, and a revoked Host
//! cannot return below its revocation epoch. `presence` updates one known Host.
//! `revoked` / `device.revoked` wipe the directory.
//!
//! Blob format v1 (all integers big endian):
//! `"LRDR" | version u8 | key_id u32 | nonce[24] | XChaCha20-Poly1305(plaintext) + tag[16]`.
//! Associated data: header (first 9 bytes) | len u32 | account id | len u32 | device id.
//! Plaintext: strict JSON in a fixed key order with Hosts sorted by id, so equal
//! directories give equal plaintext.
//!
//! Logout, revoke and lock: the platform destroys the key, raises its stored
//! `min_key_id` and calls [`Directory::wipe`]. Without the key the blob cannot be
//! read; with `min_key_id` raised the core also refuses the old blob if a copy of
//! the old key survived somewhere.

use crate::json::{self, Object};
use crate::session::{DeviceState, HostEntry, SessionResponse, parse_host};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

pub const FORMAT_VERSION: u8 = 1;
pub const NONCE_LEN: usize = 24;
const MAGIC: &[u8; 4] = b"LRDR";
const HEADER_LEN: usize = 9;
const TAG_LEN: usize = 16;
/// Largest plaintext the core seals or opens.
pub const MAX_PLAINTEXT_BYTES: usize = 1 << 20;

/// A 256-bit key from the OS keystore, tagged with the platform's key id.
/// Wiped from memory on drop.
pub struct Key {
    pub id: u32,
    bytes: [u8; 32],
}

impl Key {
    pub fn new(id: u32, bytes: [u8; 32]) -> Self {
        Key { id, bytes }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Directory was wiped; nothing to seal.
    Wiped,
    /// Not a directory blob (short, wrong magic).
    BadFormat,
    /// Blob from another format version; discard it and refetch from the server.
    Version(u8),
    /// Key id below the platform's floor: the blob predates a logout or rotation.
    Stale,
    /// No key with the blob's id was supplied.
    NoKey,
    /// Authentication failed: tampered blob, wrong key, account or device.
    Auth,
    /// Data or plaintext is malformed or too large.
    Malformed,
    /// The response belongs to another account or device.
    Mismatch,
}

/// What a merge did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Unchanged,
    /// Store the directory again (and render it).
    Changed,
    /// Access was revoked: the directory is already wiped; destroy the key and the stored blob.
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub id: String,
    /// Known only from the Host; kept across server snapshots, which carry no names.
    pub name: Option<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub id: String,
    /// Known only from the Host; kept across server snapshots, which carry no names.
    pub name: Option<String>,
    pub online: bool,
    pub access_epoch: u64,
    pub runtime_generation: u64,
    pub workspaces: Vec<Workspace>,
}

impl Host {
    fn stamp(&self) -> (u64, u64) {
        (self.access_epoch, self.runtime_generation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    account_id: String,
    device_id: String,
    hosts: BTreeMap<String, Host>,
    /// Highest revoked epoch per Host id; entries at or below it are ignored.
    revoked: BTreeMap<String, u64>,
    wiped: bool,
}

fn dec(s: &str) -> Result<u64, Error> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Malformed);
    }
    s.parse().map_err(|_| Error::Malformed)
}

fn str_of<'a>(o: &'a Object, k: &str) -> Result<&'a str, Error> {
    o.get(k).and_then(Value::as_str).ok_or(Error::Malformed)
}

fn opt_str(o: &Object, k: &str) -> Result<Option<String>, Error> {
    o.get(k)
        .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Malformed))
        .transpose()
}

fn to_host(e: HostEntry) -> Result<Host, Error> {
    let mut ids = std::collections::BTreeSet::new();
    let workspaces = e
        .workspaces
        .into_iter()
        .map(|w| {
            if !ids.insert(w.id.clone()) {
                return Err(Error::Malformed);
            }
            Ok(Workspace {
                epoch: dec(&w.epoch)?,
                id: w.id,
                name: w.name,
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(Host {
        access_epoch: dec(&e.access_epoch)?,
        runtime_generation: dec(&e.runtime_generation)?,
        id: e.id,
        name: e.name,
        online: e.online,
        workspaces,
    })
}

impl Directory {
    pub fn new(account_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        Directory {
            account_id: account_id.into(),
            device_id: device_id.into(),
            hosts: BTreeMap::new(),
            revoked: BTreeMap::new(),
            wiped: false,
        }
    }

    /// Hosts sorted by id.
    pub fn hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts.values()
    }

    pub fn host(&self, id: &str) -> Option<&Host> {
        self.hosts.get(id)
    }

    pub fn is_wiped(&self) -> bool {
        self.wiped
    }

    /// Logout / revoke / lock: drops everything and refuses further sealing. The
    /// platform must also destroy the key and the stored blob.
    pub fn wipe(&mut self) {
        self.hosts.clear();
        self.revoked.clear();
        self.wiped = true;
    }

    fn live(&self) -> Result<(), Error> {
        if self.wiped {
            Err(Error::Wiped)
        } else {
            Ok(())
        }
    }

    fn upsert(&mut self, mut h: Host) -> bool {
        if self
            .revoked
            .get(&h.id)
            .is_some_and(|r| h.access_epoch <= *r)
        {
            return false;
        }
        let old = self.hosts.get(&h.id);
        if let Some(old) = old {
            if h.stamp() < old.stamp() {
                return false;
            }
            h.name = h.name.or_else(|| old.name.clone());
            if !h.online {
                // The server lists no workspaces for an offline Host: keep the last known ones.
                h.workspaces = old.workspaces.clone();
            } else {
                for w in &mut h.workspaces {
                    if let Some(o) = old.workspaces.iter().find(|o| o.id == w.id) {
                        w.name = w.name.take().or_else(|| o.name.clone());
                        if o.epoch > w.epoch {
                            *w = o.clone(); // older snapshot of this workspace
                        }
                    }
                }
            }
            if *old == h {
                return false;
            }
        }
        self.revoked.remove(&h.id);
        self.hosts.insert(h.id.clone(), h);
        true
    }

    /// Sets names learned from the Host (the server has none). Returns whether anything changed.
    pub fn set_host_name(&mut self, host_id: &str, name: &str) -> bool {
        self.live().is_ok()
            && self.hosts.get_mut(host_id).is_some_and(|h| {
                let c = h.name.as_deref() != Some(name);
                h.name = Some(name.to_owned());
                c
            })
    }

    pub fn set_workspace_name(&mut self, host_id: &str, workspace_id: &str, name: &str) -> bool {
        self.live().is_ok()
            && self
                .hosts
                .get_mut(host_id)
                .and_then(|h| h.workspaces.iter_mut().find(|w| w.id == workspace_id))
                .is_some_and(|w| {
                    let c = w.name.as_deref() != Some(name);
                    w.name = Some(name.to_owned());
                    c
                })
    }

    /// Server snapshot: entries are merged monotonically, Hosts missing from it are removed.
    fn merge_snapshot(&mut self, entries: Vec<HostEntry>) -> Result<Effect, Error> {
        let hosts = entries
            .into_iter()
            .map(to_host)
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen = std::collections::BTreeSet::new();
        if !hosts.iter().all(|h| seen.insert(h.id.clone())) {
            return Err(Error::Malformed);
        }
        let before = self.hosts.len();
        self.hosts.retain(|id, _| seen.contains(id));
        let mut changed = self.hosts.len() != before;
        for h in hosts {
            changed |= self.upsert(h);
        }
        Ok(if changed {
            Effect::Changed
        } else {
            Effect::Unchanged
        })
    }

    /// Merges the startup response. Nothing is changed on error.
    pub fn apply_session(&mut self, r: &SessionResponse) -> Result<Effect, Error> {
        self.live()?;
        if r.account.id != self.account_id {
            return Err(Error::Mismatch);
        }
        match &r.device {
            DeviceState::Revoked => {
                self.wipe();
                return Ok(Effect::Revoked);
            }
            DeviceState::Registered { device_id } if *device_id != self.device_id => {
                return Err(Error::Mismatch);
            }
            _ => {}
        }
        let mut next = self.clone();
        let e = next.merge_snapshot(r.hosts.clone())?;
        *self = next;
        Ok(e)
    }

    /// Merges a relay EVENT (`LinkEvent::Server`). Unknown events are ignored.
    /// Nothing is changed on error.
    pub fn apply_event(&mut self, name: &str, data: &Object) -> Result<Effect, Error> {
        self.live()?;
        let mut next = self.clone();
        let e = match name {
            "revoked" | "device.revoked" => {
                self.wipe();
                return Ok(Effect::Revoked);
            }
            "inventory.changed" => {
                let list = data
                    .get("hosts")
                    .and_then(Value::as_array)
                    .ok_or(Error::Malformed)?;
                let entries = list
                    .iter()
                    .map(|v| {
                        let o = v.as_object().ok_or(Error::Malformed)?;
                        parse_host(o).map_err(|_| Error::Malformed)
                    })
                    .collect::<Result<_, _>>()?;
                next.merge_snapshot(entries)?
            }
            "presence" => {
                let id = str_of(data, "hostId")?;
                let online = data
                    .get("online")
                    .and_then(Value::as_bool)
                    .ok_or(Error::Malformed)?;
                let stamp = (
                    dec(str_of(data, "accessEpoch")?)?,
                    dec(str_of(data, "runtimeGeneration")?)?,
                );
                match next.hosts.get_mut(id) {
                    Some(h) if stamp >= h.stamp() && (h.online, h.stamp()) != (online, stamp) => {
                        (h.online, h.access_epoch, h.runtime_generation) =
                            (online, stamp.0, stamp.1);
                        Effect::Changed
                    }
                    // Unknown Host: its name arrives with the next snapshot.
                    _ => Effect::Unchanged,
                }
            }
            "host.revoked" => {
                let id = str_of(data, "hostId")?;
                let epoch = dec(str_of(data, "accessEpoch")?)?;
                // An entry above the revocation epoch is a later enrolment: keep it.
                if next.hosts.get(id).is_some_and(|h| h.access_epoch > epoch) {
                    Effect::Unchanged
                } else {
                    let r = next.revoked.entry(id.to_owned()).or_insert(0);
                    *r = (*r).max(epoch);
                    next.hosts.remove(id);
                    Effect::Changed
                }
            }
            _ => Effect::Unchanged,
        };
        *self = next;
        Ok(e)
    }

    fn plaintext(&self) -> Vec<u8> {
        let hosts = self.hosts.values().map(|h| {
            let mut o = Map::new();
            o.insert("id".into(), h.id.clone().into());
            if let Some(n) = &h.name {
                o.insert("name".into(), n.clone().into());
            }
            o.insert("online".into(), h.online.into());
            o.insert("epoch".into(), h.access_epoch.to_string().into());
            o.insert("generation".into(), h.runtime_generation.to_string().into());
            let ws = h.workspaces.iter().map(|w| {
                let mut o = Map::new();
                o.insert("id".into(), w.id.clone().into());
                if let Some(n) = &w.name {
                    o.insert("name".into(), n.clone().into());
                }
                o.insert("epoch".into(), w.epoch.to_string().into());
                Value::Object(o)
            });
            o.insert("workspaces".into(), ws.collect::<Vec<_>>().into());
            Value::Object(o)
        });
        let revoked = self.revoked.iter().map(|(id, e)| {
            let mut o = Map::new();
            o.insert("id".into(), id.clone().into());
            o.insert("epoch".into(), e.to_string().into());
            Value::Object(o)
        });
        let mut root = Map::new();
        root.insert("hosts".into(), hosts.collect::<Vec<_>>().into());
        root.insert("revoked".into(), revoked.collect::<Vec<_>>().into());
        // Serializing strings, bools and arrays cannot fail.
        serde_json::to_vec(&Value::Object(root)).unwrap_or_default()
    }

    fn from_plaintext(account: &str, device: &str, bytes: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Malformed)?;
        let Ok(Value::Object(root)) = json::parse(text) else {
            return Err(Error::Malformed);
        };
        let list = |o: &Object, k: &str| -> Result<Vec<Object>, Error> {
            o.get(k)
                .and_then(Value::as_array)
                .ok_or(Error::Malformed)?
                .iter()
                .map(|v| v.as_object().cloned().ok_or(Error::Malformed))
                .collect()
        };
        let mut d = Directory::new(account, device);
        for h in list(&root, "hosts")? {
            let host = Host {
                id: str_of(&h, "id")?.to_owned(),
                name: opt_str(&h, "name")?,
                online: h
                    .get("online")
                    .and_then(Value::as_bool)
                    .ok_or(Error::Malformed)?,
                access_epoch: dec(str_of(&h, "epoch")?)?,
                runtime_generation: dec(str_of(&h, "generation")?)?,
                workspaces: list(&h, "workspaces")?
                    .iter()
                    .map(|w| {
                        Ok(Workspace {
                            id: str_of(w, "id")?.to_owned(),
                            name: opt_str(w, "name")?,
                            epoch: dec(str_of(w, "epoch")?)?,
                        })
                    })
                    .collect::<Result<_, Error>>()?,
            };
            if d.hosts.insert(host.id.clone(), host).is_some() {
                return Err(Error::Malformed);
            }
        }
        for r in list(&root, "revoked")? {
            let id = str_of(&r, "id")?.to_owned();
            if d.revoked.insert(id, dec(str_of(&r, "epoch")?)?).is_some() {
                return Err(Error::Malformed);
            }
        }
        Ok(d)
    }

    /// Encrypts the directory under `key` with a fresh random `nonce` from the platform
    /// (never reuse a nonce with the same key). Returns the bytes to store.
    pub fn seal(&self, key: &Key, nonce: [u8; NONCE_LEN]) -> Result<Vec<u8>, Error> {
        self.live()?;
        let plain = Zeroizing::new(self.plaintext());
        if plain.len() > MAX_PLAINTEXT_BYTES {
            return Err(Error::Malformed);
        }
        let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + plain.len() + TAG_LEN);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&key.id.to_be_bytes());
        out.extend_from_slice(&nonce);
        let aad = aad(&out[..HEADER_LEN], &self.account_id, &self.device_id);
        let ct = XChaCha20Poly1305::new((&key.bytes).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Malformed)?;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypts a stored blob for this account and device. `keys` may hold several
    /// keys during rotation (reseal with the new one afterwards); blobs whose key id
    /// is below `min_key_id` are refused. Any `Err` means: discard the blob and use
    /// the server response.
    pub fn open(
        blob: &[u8],
        account_id: &str,
        device_id: &str,
        keys: &[Key],
        min_key_id: u32,
    ) -> Result<Self, Error> {
        if blob.len() < HEADER_LEN + NONCE_LEN + TAG_LEN
            || &blob[..4] != MAGIC
            || blob.len() > MAX_PLAINTEXT_BYTES + HEADER_LEN + NONCE_LEN + TAG_LEN
        {
            return Err(Error::BadFormat);
        }
        if blob[4] != FORMAT_VERSION {
            return Err(Error::Version(blob[4]));
        }
        let key_id = u32::from_be_bytes([blob[5], blob[6], blob[7], blob[8]]);
        if key_id < min_key_id {
            return Err(Error::Stale);
        }
        let key = keys.iter().find(|k| k.id == key_id).ok_or(Error::NoKey)?;
        let aad = aad(&blob[..HEADER_LEN], account_id, device_id);
        let (nonce, ct) = blob[HEADER_LEN..].split_at(NONCE_LEN);
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new((&key.bytes).into())
                .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
                .map_err(|_| Error::Auth)?,
        );
        Self::from_plaintext(account_id, device_id, &plain)
    }
}

fn aad(header: &[u8], account: &str, device: &str) -> Vec<u8> {
    let mut a = header.to_vec();
    for s in [account, device] {
        a.extend_from_slice(&(s.len() as u32).to_be_bytes());
        a.extend_from_slice(s.as_bytes());
    }
    a
}
