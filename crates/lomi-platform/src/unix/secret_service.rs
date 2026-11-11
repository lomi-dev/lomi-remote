//! Account-scoped Linux Secret Service storage, without unlock prompts or fallback.
//!
//! The protocol uses the local authenticated session bus and its standard plain
//! transfer session; persistence and encryption at rest belong to Secret Service.
//! https://specifications.freedesktop.org/secret-service/latest/
use super::{
    Object, PrivateProfile, object, open_profile_regular, private_regular, secrets::ProtectedFile,
};
use crate::secrets::{
    Error, ProviderKind, ProviderStatus, SecretBundle, SecretStorage, Selection, StorageState,
};
use lomi_remote_protocol::ipc::IpcProfileId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    sync::mpsc,
    thread,
    time::Duration,
};
use zbus::{
    blocking::{Connection, Proxy, connection::Builder},
    zvariant::{OwnedObjectPath, OwnedValue, Type, Value},
};
use zeroize::Zeroizing;

const SERVICE: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_INTERFACE: &str = "org.freedesktop.Secret.Item";
const CONTENT_TYPE: &str = "application/vnd.lomi.host-secrets.v1";
const GNOME_KEYRING_CONTENT_TYPE: &str = "text/plain";
const MARKER: &CStr = c"host-secrets.secret-service";
const CALL_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_XDG_SCHEMA_BYTES: usize = 255;
const APPLICATION_ATTRIBUTE: &str = "dev.lomi.remote.host-secrets.v1";
const HOST_SCHEMA_VERSION: u32 = 16;
const MAX_UNMARKED_BTRFS_ITEMS: usize = 128;
const MAX_UNMARKED_BTRFS_ITEM_ATTRIBUTES: usize = 5;
const MAX_UNMARKED_BTRFS_ATTRIBUTE_KEY_BYTES: usize = 64;
const MAX_UNMARKED_BTRFS_ATTRIBUTE_VALUE_BYTES: usize = 255;

/// Checked identity of the Host profile that owns a Secret Service provider.
/// Btrfs marker writes require its durable, checkpointed schema-16 main file.
/// The root directory and database descriptors stay pinned for the provider's
/// lifetime; callers cannot construct this type without opening a private Host
/// profile.
pub struct HostProfileContext {
    root: PrivateProfile,
    database: Option<File>,
}

impl HostProfileContext {
    pub fn open(path: &std::path::Path) -> Result<Self, Error> {
        let root = PrivateProfile::open(path, false).map_err(|_| Error::InvalidStorage)?;
        Ok(Self {
            root,
            database: None,
        })
    }

    fn require_current_schema_for(&mut self, profile: &PrivateProfile) -> Result<(), Error> {
        self.root
            .check_current()
            .map_err(|_| Error::InvalidStorage)?;
        if !host_profile_owns_provider_profile(self.root.path(), profile.path()) {
            return Err(Error::InvalidStorage);
        }

        let database = open_profile_regular(&self.root, "host.sqlite3", false)
            .map_err(|_| Error::InvalidStorage)?;
        private_regular(&database).map_err(|_| Error::InvalidStorage)?;
        let metadata = database.metadata().map_err(|_| Error::InvalidStorage)?;
        if metadata.len() < 100 {
            return Err(Error::InvalidStorage);
        }
        let mut header = [0u8; 100];
        let mut reader = &database;
        reader
            .read_exact(&mut header)
            .map_err(|_| Error::InvalidStorage)?;
        if &header[..16] != b"SQLite format 3\0"
            || u32::from_be_bytes(header[60..64].try_into().unwrap()) != HOST_SCHEMA_VERSION
        {
            return Err(Error::InvalidStorage);
        }
        self.root
            .check_current()
            .map_err(|_| Error::InvalidStorage)?;
        self.database = Some(database);
        Ok(())
    }
}

fn host_profile_owns_provider_profile(root: &std::path::Path, profile: &std::path::Path) -> bool {
    if root == profile {
        return true;
    }
    let Ok(relative) = profile.strip_prefix(root) else {
        return false;
    };
    let mut components = relative.components();
    let Some(std::path::Component::Normal(directory)) = components.next() else {
        return false;
    };
    let Some(std::path::Component::Normal(slot)) = components.next() else {
        return false;
    };
    components.next().is_none()
        && directory == "git-credentials"
        && slot.len() == 64
        && slot
            .as_encoded_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[derive(Serialize, Deserialize, Type)]
struct WireSecret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}
impl Drop for WireSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
    }
}

/// The common private-profile storage lock remains held throughout every D-Bus
/// operation. Each connection pins the actual service's unique owner and UID.
pub struct SecretService<'a> {
    profile: &'a PrivateProfile,
    _host_context: HostProfileContext,
    guard: ProtectedFile<'a>,
    connection: Connection,
    deadline_socket: UnixStream,
    owner: String,
    collection: OwnedObjectPath,
    session: OwnedObjectPath,
    attributes: HashMap<String, String>,
    marker: Vec<u8>,
    marker_identity: Option<Object>,
    collection_created: u64,
}
impl<'a> SecretService<'a> {
    pub fn open(
        profile: &'a PrivateProfile,
        mut host_context: HostProfileContext,
        selection: Selection,
        account: IpcProfileId,
    ) -> Result<Self, Error> {
        match selection {
            Selection::SecretService => {}
            Selection::Unconfigured => return Err(Error::Unconfigured),
            _ => return Err(Error::Unavailable),
        }
        let metadata = profile
            .directory
            .metadata()
            .map_err(|_| Error::InvalidStorage)?;
        let account = String::from(account);
        let legacy_profile_object = format!("{}:{}", metadata.dev(), metadata.ino());
        let btrfs_identity =
            crate::btrfs_identity::read(&profile.directory).map_err(|_| Error::InvalidStorage)?;
        if btrfs_identity.is_some() {
            host_context.require_current_schema_for(profile)?;
        }
        let is_btrfs_git_slot =
            btrfs_identity.is_some() && host_context.root.path() != profile.path();
        let guard = ProtectedFile::open_secret_service_guard(profile)?;
        let uid = unsafe { libc::geteuid() };
        if uid == 0 || uid != unsafe { libc::getuid() } {
            return Err(Error::Unavailable);
        }
        let (connection, deadline_socket) = connect_bus(uid)?;
        let _deadline = OperationDeadline::start(&deadline_socket)?;
        let bus = Proxy::new(
            &connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(read_error)?;
        let owner: String = bus.call("GetNameOwner", &(SERVICE,)).map_err(read_error)?;
        if !owner.starts_with(':') || owner.len() > 255 {
            return Err(Error::InvalidStorage);
        }
        let owner_uid: u32 = bus
            .call("GetConnectionUnixUser", &(owner.as_str(),))
            .map_err(read_error)?;
        if owner_uid != uid {
            return Err(Error::InvalidStorage);
        }
        let service = proxy(&connection, &owner, SERVICE_PATH, SERVICE_INTERFACE)?;
        let collection: OwnedObjectPath = service
            .call("ReadAlias", &("default",))
            .map_err(read_error)?;
        if collection.as_str() == "/" || collection.as_str().len() > 1024 {
            return Err(Error::Unavailable);
        }
        let default = proxy(
            &connection,
            &owner,
            collection.as_str(),
            COLLECTION_INTERFACE,
        )?;
        if default.get_property::<bool>("Locked").map_err(read_error)? {
            return Err(Error::Locked);
        }
        let collection_created = collection_created_anchor(
            || default.get_property("Created").map_err(read_error),
            || default.get_property("Modified").map_err(read_error),
        )?;
        let (output, session): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::from("")))
            .map_err(read_error)?;
        if String::try_from(output).ok().as_deref() != Some("")
            || session.as_str() == "/"
            || session.as_str().len() > 1024
        {
            return Err(Error::InvalidStorage);
        }
        guard.check()?;
        let (marker, marker_identity, item_object, migration_marker) =
            if let Some(identity) = btrfs_identity {
                let stable_profile_object = btrfs_profile_object(&identity, metadata.ino());
                let existing = marker_entry(profile, MARKER)?;
                let marker_identity = existing.as_ref().map(|(_, _, identity)| *identity);
                let selected = select_btrfs_marker(
                    existing.as_ref().map(|(_, bytes, _)| bytes.as_slice()),
                    &account,
                    uid,
                    &stable_profile_object,
                    &legacy_profile_object,
                    metadata.ino(),
                    collection.as_str(),
                    collection_created,
                )?;
                if existing.is_none() {
                    let query = btrfs_orphan_search_attributes(&account, uid);
                    // Search the whole service under its already-pinned unique
                    // owner; matching items may live outside the default alias.
                    let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
                        .call("SearchItems", &(&query,))
                        .map_err(read_error)?;
                    if is_btrfs_git_slot {
                        validate_btrfs_search_results(&unlocked, &locked)?;
                        let unlocked_attributes =
                            read_search_item_attributes(&connection, &owner, &unlocked)?;
                        let locked_attributes =
                            read_search_item_attributes(&connection, &owner, &locked)?;
                        reject_unmarked_btrfs_git_items(
                            &unlocked_attributes,
                            &locked_attributes,
                            &query,
                            &stable_profile_object,
                            metadata.ino(),
                        )?;
                    } else {
                        reject_unmarked_btrfs_items(&unlocked, &locked)?;
                    }
                }
                (
                    selected.marker,
                    marker_identity,
                    selected.item_object,
                    selected.migration_marker,
                )
            } else {
                let marker = legacy_marker(
                    &account,
                    uid,
                    &legacy_profile_object,
                    collection.as_str(),
                    collection_created,
                );
                let marker_identity = read_marker_identity(profile, MARKER, &marker)?;
                (marker, marker_identity, legacy_profile_object, None)
            };
        let attributes = item_attributes(&account, uid, &item_object);
        validate_marker_anchor(marker_identity, collection_created)?;
        guard.check()?;
        drop(default);
        drop(service);
        drop(bus);
        let mut this = Self {
            profile,
            _host_context: host_context,
            guard,
            connection,
            deadline_socket,
            owner,
            collection,
            session,
            attributes,
            marker,
            marker_identity,
            collection_created,
        };
        this.check()?;
        drop(this.load()?);
        if let Some(updated) = migration_marker {
            let created = this
                .current_collection_created()
                .map_err(|_| Error::InvalidStorage)?;
            if created == 0 || created != this.collection_created {
                return Err(Error::InvalidStorage);
            }
            this.replace_marker(updated)?;
        }
        Ok(this)
    }
    fn proxy<'b>(&'b self, path: &'b str, interface: &'static str) -> Result<Proxy<'b>, Error> {
        proxy(&self.connection, &self.owner, path, interface)
    }
    fn check(&self) -> Result<bool, Error> {
        self.guard.check()?;
        let current = read_marker_identity(self.profile, MARKER, &self.marker)?;
        if current != self.marker_identity {
            return Err(Error::InvalidStorage);
        }
        self.guard.check()?;
        Ok(current.is_some())
    }
    fn collection(&self) -> Result<Proxy<'_>, Error> {
        let collection = self.proxy(self.collection.as_str(), COLLECTION_INTERFACE)?;
        if collection
            .get_property::<bool>("Locked")
            .map_err(read_error)?
        {
            return Err(Error::Locked);
        }
        Ok(collection)
    }
    fn current_collection_created(&self) -> Result<u64, Error> {
        self.guard.check()?;
        let bus = Proxy::new(
            &self.connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(read_error)?;
        let owner: String = bus.call("GetNameOwner", &(SERVICE,)).map_err(read_error)?;
        if owner != self.owner {
            return Err(Error::InvalidStorage);
        }
        let owner_uid: u32 = bus
            .call("GetConnectionUnixUser", &(owner.as_str(),))
            .map_err(read_error)?;
        if owner_uid != unsafe { libc::geteuid() } {
            return Err(Error::InvalidStorage);
        }

        let service = self.proxy(SERVICE_PATH, SERVICE_INTERFACE)?;
        let alias: OwnedObjectPath = service
            .call("ReadAlias", &("default",))
            .map_err(read_error)?;
        if alias != self.collection {
            return Err(Error::InvalidStorage);
        }
        let collection = self.collection()?;
        let created = collection_created_anchor(
            || collection.get_property("Created").map_err(read_error),
            || collection.get_property("Modified").map_err(read_error),
        )?;

        let alias_after: OwnedObjectPath = service
            .call("ReadAlias", &("default",))
            .map_err(read_error)?;
        let collection = self.collection()?;
        let created_after = collection_created_anchor(
            || collection.get_property("Created").map_err(read_error),
            || collection.get_property("Modified").map_err(read_error),
        )?;
        let owner_after: String = bus.call("GetNameOwner", &(SERVICE,)).map_err(read_error)?;
        if alias_after != self.collection || created_after != created || owner_after != self.owner {
            return Err(Error::InvalidStorage);
        }
        self.guard.check()?;
        Ok(created)
    }
    fn item(&self) -> Result<Option<OwnedObjectPath>, Error> {
        let collection = self.collection()?;
        let items: Vec<OwnedObjectPath> = collection
            .call("SearchItems", &(&self.attributes,))
            .map_err(read_error)?;
        if items.len() > 1 {
            return Err(Error::InvalidStorage);
        }
        let Some(item) = items.into_iter().next() else {
            return Ok(None);
        };
        if item.as_str() == "/" || item.as_str().len() > 1024 {
            return Err(Error::InvalidStorage);
        }
        let proxy = self.proxy(item.as_str(), ITEM_INTERFACE)?;
        if proxy.get_property::<bool>("Locked").map_err(read_error)? {
            return Err(Error::Locked);
        }
        let attributes = proxy
            .get_property::<HashMap<String, String>>("Attributes")
            .map_err(read_error)?;
        if !item_attributes_match(&self.attributes, &attributes) {
            return Err(Error::InvalidStorage);
        }
        drop(proxy);
        Ok(Some(item))
    }
    fn publish_marker(&mut self) -> Result<(), Error> {
        if self.check()? {
            return Ok(());
        }
        let name = CString::new(format!(".host-secret-service-{}.tmp", uuid::Uuid::new_v4()))
            .map_err(|_| Error::Io)?;
        let mut file = open_at(
            self.profile,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?
        .ok_or(Error::Io)?;
        let result = (|| {
            private_regular(&file).map_err(|_| Error::InvalidStorage)?;
            file.write_all(&self.marker).map_err(|_| Error::Io)?;
            file.sync_all().map_err(|_| Error::Io)?;
            self.guard.check()?;
            let named =
                open_at(self.profile, &name, libc::O_RDONLY)?.ok_or(Error::InvalidStorage)?;
            if object(&named.metadata().map_err(|_| Error::InvalidStorage)?)
                != object(&file.metadata().map_err(|_| Error::InvalidStorage)?)
            {
                return Err(Error::InvalidStorage);
            }
            if unsafe {
                libc::renameat2(
                    self.profile.directory.as_raw_fd(),
                    name.as_ptr(),
                    self.profile.directory.as_raw_fd(),
                    MARKER.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(Error::CommitUncertain);
            }
            self.marker_identity =
                Some(object(&file.metadata().map_err(|_| Error::InvalidStorage)?));
            self.profile
                .directory
                .sync_all()
                .map_err(|_| Error::CommitUncertain)
        })();
        // Only our freshly created, exact temporary inode can be removed.
        if let Ok(Some(named)) = open_at(self.profile, &name, libc::O_RDONLY)
            && let (Ok(named_metadata), Ok(opened_metadata)) = (named.metadata(), file.metadata())
            && object(&named_metadata) == object(&opened_metadata)
        {
            unsafe {
                libc::unlinkat(self.profile.directory.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        result?;
        self.check()?.then_some(()).ok_or(Error::CommitUncertain)
    }
    fn promote_marker(&mut self, created: u64) -> Result<(), Error> {
        if self.collection_created != 0 || created == 0 {
            return Err(Error::CommitUncertain);
        }
        let updated = marker_with_created(&self.marker, self.collection_created, created)
            .map_err(|_| Error::CommitUncertain)?;
        self.replace_marker(updated)?;
        self.collection_created = created;
        Ok(())
    }
    fn replace_marker(&mut self, updated: Vec<u8>) -> Result<(), Error> {
        let expected_identity = self.marker_identity.ok_or(Error::CommitUncertain)?;
        let identity = replace_marker_cas(
            self.profile,
            &self.guard,
            expected_identity,
            &self.marker,
            &updated,
            |_| Ok(()),
            |directory| directory.sync_all(),
        )
        .map_err(|_| Error::CommitUncertain)?;
        self.marker = updated;
        self.marker_identity = Some(identity);
        if self.check().map_err(|_| Error::CommitUncertain)? {
            Ok(())
        } else {
            Err(Error::CommitUncertain)
        }
    }
}
impl SecretStorage for SecretService<'_> {
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            kind: Some(ProviderKind::SecretService),
            state: self
                .load()
                .map_or_else(Error::state, |_| StorageState::Available),
        }
    }
    fn load(&self) -> Result<Option<SecretBundle>, Error> {
        let _deadline = OperationDeadline::start(&self.deadline_socket)?;
        let has_marker = self.check()?;
        let Some(item) = self.item()? else {
            return Ok(None);
        };
        if !has_marker {
            return Err(Error::InvalidStorage);
        }
        let item = self.proxy(item.as_str(), ITEM_INTERFACE)?;
        let mut secret: WireSecret = item
            .call("GetSecret", &(&self.session,))
            .map_err(read_error)?;
        if secret.session != self.session
            || !secret.parameters.is_empty()
            || !supported_content_type(&secret.content_type)
        {
            return Err(Error::InvalidBundle);
        }
        let value = Zeroizing::new(std::mem::take(&mut secret.value));
        self.check()?;
        if value.is_empty() || value.len() > crate::secrets::MAX_BUNDLE_BYTES {
            return Err(Error::InvalidBundle);
        }
        Ok(Some(SecretBundle::from_zeroizing(value)))
    }
    fn replace(&mut self, bundle: &SecretBundle) -> Result<(), Error> {
        let _deadline = OperationDeadline::start(&self.deadline_socket)?;
        self.check()?;
        let existing = self.item()?;
        self.publish_marker()?;
        let secret = WireSecret {
            session: self.session.clone(),
            parameters: Vec::new(),
            value: bundle.expose().to_vec(),
            content_type: CONTENT_TYPE.into(),
        };
        if let Some(path) = existing {
            let item = self.proxy(path.as_str(), ITEM_INTERFACE)?;
            item.call::<_, _, ()>("SetSecret", &(secret,))
                .map_err(write_error)?;
        } else {
            let attributes: HashMap<&str, &str> = self
                .attributes
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            let properties = HashMap::from([
                (
                    "org.freedesktop.Secret.Item.Label",
                    Value::from("Lomi Remote host credentials"),
                ),
                (
                    "org.freedesktop.Secret.Item.Attributes",
                    Value::from(attributes),
                ),
            ]);
            let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = self
                .collection()?
                .call("CreateItem", &(properties, secret, true))
                .map_err(write_error)?;
            if prompt.as_str() != "/" {
                return Err(Error::Locked);
            }
            if item.as_str() == "/" {
                return Err(Error::CommitUncertain);
            }
        }
        // Never replay a write after transport loss; a verified read is the
        // only acknowledgement of the exact atomic bundle replacement.
        let observed = self
            .load()
            .map_err(|_| Error::CommitUncertain)?
            .ok_or(Error::CommitUncertain)?;
        if observed.expose() != bundle.expose() {
            return Err(Error::CommitUncertain);
        }
        let current_created = self
            .current_collection_created()
            .map_err(|_| Error::CommitUncertain)?;
        if let Some(created) = created_after_write(self.collection_created, current_created)? {
            self.promote_marker(created)?;
        }
        Ok(())
    }
    fn clear(&mut self) -> Result<(), Error> {
        let _deadline = OperationDeadline::start(&self.deadline_socket)?;
        self.check()?;
        let Some(path) = self.item()? else {
            return Ok(());
        };
        drop(self.load()?);
        let prompt: OwnedObjectPath = self
            .proxy(path.as_str(), ITEM_INTERFACE)?
            .call("Delete", &())
            .map_err(write_error)?;
        if prompt.as_str() != "/" {
            return Err(Error::Locked);
        }
        self.check().map_err(|_| Error::CommitUncertain)?;
        if self.item().map_err(|_| Error::CommitUncertain)?.is_some() {
            return Err(Error::CommitUncertain);
        }
        // Keep the public provider binding and common lock; this never deletes
        // a collection, another application item, or installation identity.
        Ok(())
    }
}
fn proxy<'a>(
    connection: &'a Connection,
    owner: &'a str,
    path: &'a str,
    interface: &'static str,
) -> Result<Proxy<'a>, Error> {
    zbus::blocking::proxy::Builder::<Proxy<'a>>::new(connection)
        .destination(owner)
        .map_err(read_error)?
        .path(path)
        .map_err(read_error)?
        .interface(interface)
        .map_err(read_error)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .map_err(read_error)
}
fn read_error(error: zbus::Error) -> Error {
    match error {
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.Secret.Error.IsLocked" =>
        {
            Error::Locked
        }
        _ => Error::Unavailable,
    }
}
fn write_error(error: zbus::Error) -> Error {
    match error {
        zbus::Error::MethodError(name, _, _)
            if name.as_str() == "org.freedesktop.Secret.Error.IsLocked" =>
        {
            Error::Locked
        }
        _ => Error::CommitUncertain,
    }
}
fn open_at(profile: &PrivateProfile, name: &CStr, flags: i32) -> Result<Option<File>, Error> {
    profile.check_current().map_err(|_| Error::InvalidStorage)?;
    let fd = unsafe {
        libc::openat(
            profile.directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd >= 0 {
        Ok(Some(unsafe { File::from_raw_fd(fd) }))
    } else if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(Error::InvalidStorage)
    }
}

fn item_attributes(account: &str, uid: u32, profile_object: &str) -> HashMap<String, String> {
    HashMap::from([
        ("application".into(), APPLICATION_ATTRIBUTE.into()),
        ("account".into(), account.into()),
        ("native-uid".into(), uid.to_string()),
        ("profile-object".into(), profile_object.into()),
    ])
}

fn legacy_marker(
    account: &str,
    uid: u32,
    profile_object: &str,
    collection: &str,
    created: u64,
) -> Vec<u8> {
    format!("LMSS0001\n{account}\n{uid}\n{profile_object}\n{collection}\n{created}\n").into_bytes()
}

fn btrfs_marker(
    account: &str,
    uid: u32,
    stable_profile_object: &str,
    item_object: &str,
    collection: &str,
    created: u64,
) -> Vec<u8> {
    format!(
        "LMSS0002\n{account}\n{uid}\n{stable_profile_object}\n{item_object}\n{collection}\n{created}\n"
    )
    .into_bytes()
}

fn btrfs_profile_object(identity: &crate::btrfs_identity::Identity, inode: u64) -> String {
    format!(
        "btrfs:{}:{}:{inode}",
        identity.filesystem_uuid, identity.subvolume_uuid
    )
}

fn btrfs_orphan_search_attributes(account: &str, uid: u32) -> HashMap<String, String> {
    HashMap::from([
        ("application".into(), APPLICATION_ATTRIBUTE.into()),
        ("account".into(), account.into()),
        ("native-uid".into(), uid.to_string()),
    ])
}

fn reject_unmarked_btrfs_items(
    unlocked: &[OwnedObjectPath],
    locked: &[OwnedObjectPath],
) -> Result<(), Error> {
    validate_btrfs_search_results(unlocked, locked)?;
    if unlocked.is_empty() && locked.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidStorage)
    }
}

fn validate_btrfs_search_results(
    unlocked: &[OwnedObjectPath],
    locked: &[OwnedObjectPath],
) -> Result<(), Error> {
    if unlocked.len().saturating_add(locked.len()) > MAX_UNMARKED_BTRFS_ITEMS {
        return Err(Error::InvalidStorage);
    }
    let mut paths = HashSet::with_capacity(unlocked.len() + locked.len());
    for item in unlocked.iter().chain(locked) {
        if item.as_str() == "/" || item.as_str().len() > 1024 || !paths.insert(item.as_str()) {
            return Err(Error::InvalidStorage);
        }
    }
    Ok(())
}

fn read_search_item_attributes(
    connection: &Connection,
    owner: &str,
    items: &[OwnedObjectPath],
) -> Result<Vec<HashMap<String, String>>, Error> {
    // Item attributes are public metadata, so this remains valid for locked
    // results and never unlocks or reads a secret.
    items
        .iter()
        .map(|item| {
            let item = proxy(connection, owner, item.as_str(), ITEM_INTERFACE)?;
            let attributes = item
                .get_property::<HashMap<String, String>>("Attributes")
                .map_err(read_error)?;
            if !bounded_btrfs_item_attributes(&attributes) {
                return Err(Error::InvalidStorage);
            }
            Ok(attributes)
        })
        .collect()
}

fn bounded_btrfs_item_attributes(attributes: &HashMap<String, String>) -> bool {
    attributes.len() <= MAX_UNMARKED_BTRFS_ITEM_ATTRIBUTES
        && attributes.iter().all(|(key, value)| {
            !key.is_empty()
                && key.len() <= MAX_UNMARKED_BTRFS_ATTRIBUTE_KEY_BYTES
                && value.len() <= MAX_UNMARKED_BTRFS_ATTRIBUTE_VALUE_BYTES
        })
}

fn reject_unmarked_btrfs_git_items(
    unlocked: &[HashMap<String, String>],
    locked: &[HashMap<String, String>],
    query: &HashMap<String, String>,
    current_profile_object: &str,
    current_inode: u64,
) -> Result<(), Error> {
    if unlocked.len().saturating_add(locked.len()) > MAX_UNMARKED_BTRFS_ITEMS {
        return Err(Error::InvalidStorage);
    }
    for attributes in unlocked.iter().chain(locked) {
        if !bounded_btrfs_item_attributes(attributes) {
            return Err(Error::InvalidStorage);
        }
        let Some(profile_object) = attributes.get("profile-object") else {
            return Err(Error::InvalidStorage);
        };
        let mut expected = query.clone();
        expected.insert("profile-object".into(), profile_object.clone());
        if !item_attributes_match(&expected, attributes)
            || !canonical_foreign_btrfs_profile_object(
                profile_object,
                current_profile_object,
                current_inode,
            )
        {
            return Err(Error::InvalidStorage);
        }
    }
    Ok(())
}

fn canonical_foreign_btrfs_profile_object(
    value: &str,
    current_profile_object: &str,
    current_inode: u64,
) -> bool {
    if value == current_profile_object {
        return false;
    }
    if canonical_btrfs_profile_object(value) {
        return true;
    }
    if !canonical_positive_legacy_profile_object(value) {
        return false;
    }
    value
        .split_once(':')
        .and_then(|(_, inode)| inode.parse::<u64>().ok())
        .is_some_and(|inode| inode != current_inode)
}

fn canonical_btrfs_profile_object(value: &str) -> bool {
    let Some(value) = value.strip_prefix("btrfs:") else {
        return false;
    };
    let mut fields = value.split(':');
    let Some(filesystem_text) = fields.next() else {
        return false;
    };
    let Some(subvolume_text) = fields.next() else {
        return false;
    };
    let Some(inode_text) = fields.next() else {
        return false;
    };
    if fields.next().is_some() {
        return false;
    }
    let (Ok(filesystem), Ok(subvolume), Ok(inode)) = (
        uuid::Uuid::parse_str(filesystem_text),
        uuid::Uuid::parse_str(subvolume_text),
        inode_text.parse::<u64>(),
    ) else {
        return false;
    };
    !filesystem.is_nil()
        && !subvolume.is_nil()
        && filesystem.hyphenated().to_string() == filesystem_text
        && subvolume.hyphenated().to_string() == subvolume_text
        && inode > 0
        && inode.to_string() == inode_text
}

struct BtrfsMarkerSelection {
    marker: Vec<u8>,
    item_object: String,
    migration_marker: Option<Vec<u8>>,
}

fn select_btrfs_marker(
    existing: Option<&[u8]>,
    account: &str,
    uid: u32,
    stable_profile_object: &str,
    legacy_profile_object: &str,
    inode: u64,
    collection: &str,
    created: u64,
) -> Result<BtrfsMarkerSelection, Error> {
    let new_marker = btrfs_marker(
        account,
        uid,
        stable_profile_object,
        stable_profile_object,
        collection,
        created,
    );
    match existing {
        None => Ok(BtrfsMarkerSelection {
            marker: new_marker,
            item_object: stable_profile_object.into(),
            migration_marker: None,
        }),
        Some(bytes) if bytes == new_marker => Ok(BtrfsMarkerSelection {
            marker: bytes.into(),
            item_object: stable_profile_object.into(),
            migration_marker: None,
        }),
        Some(bytes)
            if let Some(item_object) = btrfs_legacy_item_object(
                bytes,
                account,
                uid,
                stable_profile_object,
                inode,
                collection,
                created,
            ) =>
        {
            Ok(BtrfsMarkerSelection {
                marker: bytes.into(),
                item_object,
                migration_marker: None,
            })
        }
        Some(bytes)
            if bytes == legacy_marker(account, uid, legacy_profile_object, collection, created) =>
        {
            if !canonical_positive_legacy_profile_object(legacy_profile_object) {
                return Err(Error::InvalidStorage);
            }
            let migration_marker = btrfs_marker(
                account,
                uid,
                stable_profile_object,
                legacy_profile_object,
                collection,
                created,
            );
            Ok(BtrfsMarkerSelection {
                marker: bytes.into(),
                item_object: legacy_profile_object.into(),
                migration_marker: Some(migration_marker),
            })
        }
        Some(_) => Err(Error::InvalidStorage),
    }
}

fn btrfs_legacy_item_object(
    marker: &[u8],
    account: &str,
    uid: u32,
    stable_profile_object: &str,
    inode: u64,
    collection: &str,
    created: u64,
) -> Option<String> {
    let text = std::str::from_utf8(marker).ok()?;
    let fields: Vec<_> = text.split('\n').collect();
    if fields.len() != 8
        || fields[0] != "LMSS0002"
        || fields[1] != account
        || fields[2] != uid.to_string()
        || fields[3] != stable_profile_object
        || fields[5] != collection
        || fields[6] != created.to_string()
        || !fields[7].is_empty()
        || !canonical_legacy_item_object(fields[4], inode)
    {
        return None;
    }
    (btrfs_marker(
        account,
        uid,
        stable_profile_object,
        fields[4],
        collection,
        created,
    ) == marker)
        .then(|| fields[4].into())
}

fn canonical_legacy_item_object(value: &str, inode: u64) -> bool {
    let Some((device, stored_inode)) = value.split_once(':') else {
        return false;
    };
    let Ok(device) = device.parse::<u64>() else {
        return false;
    };
    device > 0 && stored_inode == inode.to_string() && format!("{device}:{stored_inode}") == value
}

fn canonical_positive_legacy_profile_object(value: &str) -> bool {
    let Some((device, inode)) = value.split_once(':') else {
        return false;
    };
    let (Ok(device), Ok(inode)) = (device.parse::<u64>(), inode.parse::<u64>()) else {
        return false;
    };
    device > 0 && inode > 0 && format!("{device}:{inode}") == value
}

fn read_marker_identity(
    profile: &PrivateProfile,
    name: &CStr,
    expected: &[u8],
) -> Result<Option<Object>, Error> {
    let Some((_, bytes, identity)) = marker_entry(profile, name)? else {
        return Ok(None);
    };
    if bytes != expected {
        return Err(Error::InvalidStorage);
    }
    Ok(Some(identity))
}

fn marker_entry(
    profile: &PrivateProfile,
    name: &CStr,
) -> Result<Option<(File, Vec<u8>, Object)>, Error> {
    let Some(mut file) = open_at(profile, name, libc::O_RDONLY)? else {
        return Ok(None);
    };
    private_regular(&file).map_err(|_| Error::InvalidStorage)?;
    let length = file.metadata().map_err(|_| Error::InvalidStorage)?.len();
    if length == 0 || length > 4096 {
        return Err(Error::InvalidStorage);
    }
    let mut bytes = vec![0; length as usize];
    file.read_exact(&mut bytes)
        .map_err(|_| Error::InvalidStorage)?;
    let mut extra = [0; 1];
    if file.read(&mut extra).map_err(|_| Error::InvalidStorage)? != 0 {
        return Err(Error::InvalidStorage);
    }
    let identity = object(&file.metadata().map_err(|_| Error::InvalidStorage)?);
    let named = open_at(profile, name, libc::O_RDONLY)?.ok_or(Error::InvalidStorage)?;
    if object(&named.metadata().map_err(|_| Error::InvalidStorage)?) != identity {
        return Err(Error::InvalidStorage);
    }
    Ok(Some((file, bytes, identity)))
}

fn marker_with_created(marker: &[u8], old: u64, new: u64) -> Result<Vec<u8>, Error> {
    let marker = std::str::from_utf8(marker).map_err(|_| Error::InvalidStorage)?;
    let suffix = format!("{old}\n");
    let prefix = marker.strip_suffix(&suffix).ok_or(Error::InvalidStorage)?;
    Ok(format!("{prefix}{new}\n").into_bytes())
}

fn created_after_write(pinned: u64, observed: u64) -> Result<Option<u64>, Error> {
    match (pinned, observed) {
        (0, 0) => Err(Error::CommitUncertain),
        (0, created) => Ok(Some(created)),
        (created, observed) if created == observed => Ok(None),
        _ => Err(Error::CommitUncertain),
    }
}

fn collection_created_anchor(
    read_created: impl FnOnce() -> Result<u64, Error>,
    read_modified: impl FnOnce() -> Result<u64, Error>,
) -> Result<u64, Error> {
    let created = read_created()?;
    if created != 0 {
        return Ok(created);
    }
    // GNOME Keyring can swap these timestamps after a save.
    read_modified()
}

fn validate_marker_anchor(
    marker_identity: Option<Object>,
    collection_created: u64,
) -> Result<(), Error> {
    if marker_identity.is_some() && collection_created == 0 {
        return Err(Error::InvalidStorage);
    }
    Ok(())
}

fn replace_marker_cas(
    profile: &PrivateProfile,
    guard: &ProtectedFile<'_>,
    expected_identity: Object,
    expected_marker: &[u8],
    updated_marker: &[u8],
    before_exchange: impl FnOnce(&PrivateProfile) -> io::Result<()>,
    sync_directory: impl FnOnce(&File) -> io::Result<()>,
) -> Result<Object, Error> {
    if expected_marker == updated_marker || updated_marker.len() > 4096 {
        return Err(Error::CommitUncertain);
    }
    guard.check().map_err(|_| Error::CommitUncertain)?;
    let Some((old_file, old_bytes, old_identity)) = marker_entry(profile, MARKER)? else {
        return Err(Error::CommitUncertain);
    };
    if old_identity != expected_identity || old_bytes != expected_marker {
        return Err(Error::CommitUncertain);
    }

    let name = CString::new(format!(".host-secret-service-{}.tmp", uuid::Uuid::new_v4()))
        .map_err(|_| Error::CommitUncertain)?;
    let mut new_file = open_at(
        profile,
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?
    .ok_or(Error::CommitUncertain)?;
    let new_identity = object(&new_file.metadata().map_err(|_| Error::CommitUncertain)?);

    let result = (|| {
        private_regular(&new_file).map_err(|_| Error::CommitUncertain)?;
        new_file
            .write_all(updated_marker)
            .map_err(|_| Error::CommitUncertain)?;
        new_file.sync_all().map_err(|_| Error::CommitUncertain)?;
        guard.check().map_err(|_| Error::CommitUncertain)?;
        let Some((current, bytes, identity)) = marker_entry(profile, MARKER)? else {
            return Err(Error::CommitUncertain);
        };
        if identity != expected_identity || bytes != expected_marker {
            return Err(Error::CommitUncertain);
        }
        let Some((named_temp, bytes, identity)) = marker_entry(profile, &name)? else {
            return Err(Error::CommitUncertain);
        };
        if identity != new_identity || bytes != updated_marker {
            return Err(Error::CommitUncertain);
        }
        drop((current, named_temp));
        before_exchange(profile).map_err(|_| Error::CommitUncertain)?;

        if unsafe {
            libc::renameat2(
                profile.directory.as_raw_fd(),
                name.as_ptr(),
                profile.directory.as_raw_fd(),
                MARKER.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        } != 0
        {
            return Err(Error::CommitUncertain);
        }

        let Some((installed, installed_bytes, installed_identity)) = marker_entry(profile, MARKER)?
        else {
            return Err(Error::CommitUncertain);
        };
        let Some((displaced, displaced_bytes, displaced_identity)) = marker_entry(profile, &name)?
        else {
            return Err(Error::CommitUncertain);
        };
        if installed_identity != new_identity
            || installed_bytes != updated_marker
            || displaced_identity != expected_identity
            || displaced_bytes != expected_marker
        {
            // Preserve both exchanged entries when the compare fails. The
            // temporary name may now hold an unexpected replacement.
            return Err(Error::CommitUncertain);
        }
        drop((installed, displaced, old_file));

        let Some((old_named, old_named_bytes, old_named_identity)) = marker_entry(profile, &name)?
        else {
            return Err(Error::CommitUncertain);
        };
        if old_named_identity != expected_identity || old_named_bytes != expected_marker {
            return Err(Error::CommitUncertain);
        }
        drop(old_named);
        if unsafe { libc::unlinkat(profile.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(Error::CommitUncertain);
        }
        guard.check().map_err(|_| Error::CommitUncertain)?;
        sync_directory(&profile.directory).map_err(|_| Error::CommitUncertain)?;
        Ok(new_identity)
    })();

    match result {
        Ok(identity) => Ok(identity),
        Err(error) => {
            if let Ok(Some(file)) = open_at(profile, &name, libc::O_RDONLY)
                && let Ok(metadata) = file.metadata()
                && object(&metadata) == new_identity
            {
                unsafe {
                    libc::unlinkat(profile.directory.as_raw_fd(), name.as_ptr(), 0);
                }
            }
            Err(error)
        }
    }
}
/// The reply timeout starts after writing a message. Also bound blocked socket
/// writes and authentication, and join the one timer thread on every exit.
struct OperationDeadline {
    done: Option<mpsc::Sender<()>>,
    timer: Option<thread::JoinHandle<()>>,
}
impl OperationDeadline {
    fn start(socket: &UnixStream) -> Result<Self, Error> {
        let socket = socket.try_clone().map_err(|_| Error::Unavailable)?;
        let (done, wait) = mpsc::channel();
        let timer = thread::Builder::new()
            .name("lomi-keyring-deadline".into())
            .spawn(move || {
                if wait.recv_timeout(Duration::from_secs(3)).is_err() {
                    let _ = socket.shutdown(Shutdown::Both);
                }
            })
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            done: Some(done),
            timer: Some(timer),
        })
    }
}
impl Drop for OperationDeadline {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        if let Some(timer) = self.timer.take() {
            let _ = timer.join();
        }
    }
}
fn connect_bus(uid: u32) -> Result<(Connection, UnixStream), Error> {
    let directory = format!("/run/user/{uid}");
    let metadata = std::fs::symlink_metadata(&directory).map_err(|_| Error::Unavailable)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o777 != 0o700 {
        return Err(Error::InvalidStorage);
    }
    let path = format!("{directory}/bus");
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| Error::Unavailable)?;
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(Error::InvalidStorage);
    }
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        .map_err(|_| Error::Unavailable)?;
    socket
        .set_nonblocking(true)
        .map_err(|_| Error::Unavailable)?;
    let address = socket2::SockAddr::unix(path).map_err(|_| Error::Unavailable)?;
    if let Err(error) = socket.connect(&address) {
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
        ) {
            return Err(Error::Unavailable);
        }
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 1000) } <= 0
            || socket
                .take_error()
                .map_err(|_| Error::Unavailable)?
                .is_some()
        {
            return Err(Error::Unavailable);
        }
    }
    socket
        .set_nonblocking(false)
        .map_err(|_| Error::Unavailable)?;
    let descriptor: std::os::fd::OwnedFd = socket.into();
    let stream = UnixStream::from(descriptor);
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || peer.uid != uid
    {
        return Err(Error::InvalidStorage);
    }
    let deadline_socket = stream.try_clone().map_err(|_| Error::Unavailable)?;
    let _deadline = OperationDeadline::start(&deadline_socket)?;
    let result = Builder::async_io_unix_stream(stream)
        .auth_mechanism(zbus::AuthMechanism::External)
        .max_queued(8)
        .method_timeout(CALL_TIMEOUT)
        .build()
        .map_err(read_error);
    result.map(|connection| (connection, deadline_socket))
}

fn item_attributes_match(
    expected: &HashMap<String, String>,
    actual: &HashMap<String, String>,
) -> bool {
    expected
        .iter()
        .all(|(key, value)| actual.get(key) == Some(value))
        && actual.iter().all(|(key, value)| {
            expected.contains_key(key) || (key == "xdg:schema" && valid_xdg_schema(value))
        })
}

fn valid_xdg_schema(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_XDG_SCHEMA_BYTES
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn supported_content_type(content_type: &str) -> bool {
    content_type == CONTENT_TYPE || content_type == GNOME_KEYRING_CONTENT_TYPE
}

#[cfg(test)]
mod tests {
    use super::super::Object;
    use super::super::{PrivateProfile, object, secrets::ProtectedFile};
    use super::{
        CONTENT_TYPE, Error, GNOME_KEYRING_CONTENT_TYPE, HOST_SCHEMA_VERSION, HostProfileContext,
        MARKER, MAX_XDG_SCHEMA_BYTES, btrfs_marker, btrfs_orphan_search_attributes,
        btrfs_profile_object, canonical_btrfs_profile_object,
        canonical_foreign_btrfs_profile_object, canonical_positive_legacy_profile_object,
        collection_created_anchor, created_after_write, host_profile_owns_provider_profile,
        item_attributes, item_attributes_match, legacy_marker, marker_entry, marker_with_created,
        read_marker_identity, reject_unmarked_btrfs_git_items, reject_unmarked_btrfs_items,
        replace_marker_cas, select_btrfs_marker, supported_content_type, validate_marker_anchor,
    };
    use std::{
        collections::HashMap,
        fs,
        io::{self, Write},
        os::{
            fd::AsRawFd,
            unix::fs::{OpenOptionsExt, PermissionsExt},
        },
    };

    fn expected_attributes() -> HashMap<String, String> {
        HashMap::from([
            (
                "application".into(),
                "dev.lomi.remote.host-secrets.v1".into(),
            ),
            ("account".into(), "profile-id".into()),
            ("native-uid".into(), "1001".into()),
            ("profile-object".into(), "device:inode".into()),
        ])
    }

    fn marker(created: u64) -> Vec<u8> {
        legacy_marker(
            "profile-id",
            1001,
            "1:2",
            "/org/freedesktop/secrets/collection/login",
            created,
        )
    }

    fn select_btrfs(
        existing: Option<&[u8]>,
        stable: &str,
        legacy: &str,
        created: u64,
    ) -> Result<super::BtrfsMarkerSelection, Error> {
        let inode = stable.rsplit(':').next().unwrap().parse().unwrap();
        select_btrfs_marker(
            existing,
            "profile-id",
            1001,
            stable,
            legacy,
            inode,
            "/org/freedesktop/secrets/collection/login",
            created,
        )
    }

    #[test]
    fn btrfs_profile_object_uses_stable_uuids_and_inode() {
        let identity = crate::btrfs_identity::Identity {
            filesystem_uuid: "01010101-0101-0101-0101-010101010101".into(),
            subvolume_uuid: "02020202-0202-0202-0202-020202020202".into(),
        };
        assert_eq!(
            btrfs_profile_object(&identity, 77),
            "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77"
        );
        assert_ne!(
            btrfs_profile_object(&identity, 77),
            btrfs_profile_object(&identity, 78)
        );
    }

    #[test]
    fn btrfs_markers_select_stable_items_and_exact_v1_migration() {
        let stable =
            "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77";
        let legacy = "8:77";
        let collection = "/org/freedesktop/secrets/collection/login";
        let fresh = select_btrfs(None, stable, legacy, 123).unwrap();
        assert_eq!(fresh.item_object, stable);
        assert_eq!(
            fresh.marker,
            btrfs_marker("profile-id", 1001, stable, stable, collection, 123)
        );
        assert!(fresh.migration_marker.is_none());

        let migrated_item = select_btrfs(
            Some(&btrfs_marker(
                "profile-id",
                1001,
                stable,
                legacy,
                collection,
                123,
            )),
            stable,
            legacy,
            123,
        )
        .unwrap();
        assert_eq!(migrated_item.item_object, legacy);
        assert!(migrated_item.migration_marker.is_none());

        let old_legacy = "47:77";
        let old = legacy_marker("profile-id", 1001, old_legacy, collection, 123);
        let migration = select_btrfs(Some(&old), stable, old_legacy, 123).unwrap();
        assert_eq!(migration.marker, old);
        assert_eq!(migration.item_object, old_legacy);
        assert_eq!(
            migration.migration_marker,
            Some(btrfs_marker(
                "profile-id",
                1001,
                stable,
                old_legacy,
                collection,
                123
            ))
        );
        assert_eq!(
            item_attributes("profile-id", 1001, &migration.item_object)["profile-object"],
            old_legacy
        );
        let reopened =
            select_btrfs(migration.migration_marker.as_deref(), stable, legacy, 123).unwrap();
        assert_eq!(reopened.item_object, old_legacy);

        let moved_device_marker = legacy_marker("profile-id", 1001, "7:77", collection, 123);
        assert_eq!(
            select_btrfs(Some(&moved_device_marker), stable, legacy, 123).map(|_| ()),
            Err(Error::InvalidStorage)
        );
    }

    #[test]
    fn btrfs_marker_rejects_changed_context_and_noncanonical_fields() {
        let stable =
            "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77";
        let legacy = "8:77";
        let collection = "/org/freedesktop/secrets/collection/login";
        let current = btrfs_marker("profile-id", 1001, stable, stable, collection, 123);
        let mut unknown_version = current.clone();
        unknown_version[7] = b'9';
        let mut non_utf8 = current.clone();
        non_utf8[9] = 0xff;
        let invalid = [
            unknown_version,
            non_utf8,
            btrfs_marker("other-profile", 1001, stable, stable, collection, 123),
            btrfs_marker("profile-id", 1002, stable, stable, collection, 123),
            btrfs_marker(
                "profile-id",
                1001,
                "btrfs:03030303-0303-0303-0303-030303030303:02020202-0202-0202-0202-020202020202:77",
                stable,
                collection,
                123,
            ),
            btrfs_marker(
                "profile-id",
                1001,
                "btrfs:01010101-0101-0101-0101-010101010101:03030303-0303-0303-0303-030303030303:77",
                stable,
                collection,
                123,
            ),
            btrfs_marker(
                "profile-id",
                1001,
                "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:78",
                stable,
                collection,
                123,
            ),
            btrfs_marker("profile-id", 1001, stable, stable, "/other/collection", 123),
            btrfs_marker("profile-id", 1001, stable, stable, collection, 124),
            b"LMSS0002\nprofile-id\n1001\nbtrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77\nbtrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77\n/org/freedesktop/secrets/collection/login\n123\nextra\n".to_vec(),
            btrfs_marker("profile-id", 1001, stable, "08:77", collection, 123),
            btrfs_marker("profile-id", 1001, stable, "8:077", collection, 123),
            btrfs_marker("profile-id", 1001, stable, "8:78", collection, 123),
            btrfs_marker("profile-id", 1001, stable, "18446744073709551616:77", collection, 123),
        ];
        for marker in invalid {
            assert_eq!(
                select_btrfs(Some(&marker), stable, legacy, 123).map(|_| ()),
                Err(Error::InvalidStorage)
            );
        }
        assert_eq!(
            select_btrfs(Some(&current), stable, legacy, 123)
                .unwrap()
                .item_object,
            stable
        );
        assert!(canonical_positive_legacy_profile_object(legacy));
        for noncanonical in ["0:77", "8:0", "08:77", "8:077", "8:77:1", "-8:77"] {
            assert!(!canonical_positive_legacy_profile_object(noncanonical));
        }
        assert_eq!(
            validate_marker_anchor(
                Some(Object {
                    device: 1,
                    inode: 2
                }),
                0
            ),
            Err(Error::InvalidStorage)
        );
    }

    #[test]
    fn btrfs_markerless_search_catches_all_item_object_variants() {
        let query = btrfs_orphan_search_attributes("profile-id", 1001);
        assert_eq!(query.len(), 3);
        assert!(!query.contains_key("profile-object"));

        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        for (index, profile_object) in ["7:77", "8:77", "btrfs:stable:77"].into_iter().enumerate() {
            let mut item = query.clone();
            item.insert("profile-object".into(), profile_object.into());
            assert!(
                query
                    .iter()
                    .all(|(key, value)| item.get(key) == Some(value))
            );
            let path =
                super::OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/item_{index}"))
                    .unwrap();
            if index % 2 == 0 {
                unlocked.push(path);
            } else {
                locked.push(path);
            }
        }
        assert_eq!(
            reject_unmarked_btrfs_items(&unlocked, &locked),
            Err(Error::InvalidStorage)
        );
        assert_eq!(reject_unmarked_btrfs_items(&[], &[]), Ok(()));
    }

    fn orphan_attributes(profile_object: &str) -> HashMap<String, String> {
        let mut attributes = btrfs_orphan_search_attributes("profile-id", 1001);
        attributes.insert("profile-object".into(), profile_object.into());
        attributes
    }

    #[test]
    fn git_markerless_search_allows_canonical_distinct_profiles_in_both_lock_sets() {
        let current =
            "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77";
        let other_subvolume =
            "btrfs:01010101-0101-0101-0101-010101010101:03030303-0303-0303-0303-030303030303:77";
        let query = btrfs_orphan_search_attributes("profile-id", 1001);
        assert!(canonical_btrfs_profile_object(other_subvolume));

        let mut unlocked_item = orphan_attributes(other_subvolume);
        unlocked_item.insert("xdg:schema".into(), "org.gnome.Keyring.Item".into());
        let unlocked = vec![unlocked_item];
        let locked = vec![orphan_attributes("8:78")];
        assert_eq!(
            reject_unmarked_btrfs_git_items(&unlocked, &locked, &query, current, 77),
            Ok(()),
            "distinct stable tuples and legacy items with another inode are allowed"
        );

        for profile_object in [current, "999:77"] {
            let unlocked = vec![orphan_attributes(profile_object)];
            assert_eq!(
                reject_unmarked_btrfs_git_items(&unlocked, &[], &query, current, 77),
                Err(Error::InvalidStorage),
                "the current stable tuple and any legacy device with the current inode are fenced"
            );
        }

        let locked = vec![orphan_attributes(current)];
        assert_eq!(
            reject_unmarked_btrfs_git_items(&[], &locked, &query, current, 77),
            Err(Error::InvalidStorage),
            "locked items receive the same ownership check"
        );
    }

    #[test]
    fn git_markerless_search_rejects_foreign_or_malformed_item_metadata() {
        let current =
            "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77";
        let query = btrfs_orphan_search_attributes("profile-id", 1001);
        for profile_object in [
            "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:077",
            "btrfs:AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA:03030303-0303-0303-0303-030303030303:78",
            "btrfs:03030303-0303-0303-0303-030303030303:04040404-0404-0404-0404-040404040404:0",
            "8:078",
            "unknown:profile:78",
        ] {
            assert!(!canonical_foreign_btrfs_profile_object(
                profile_object,
                current,
                77
            ));
            assert_eq!(
                reject_unmarked_btrfs_git_items(
                    &[orphan_attributes(profile_object)],
                    &[],
                    &query,
                    current,
                    77
                ),
                Err(Error::InvalidStorage)
            );
        }

        let other =
            "btrfs:01010101-0101-0101-0101-010101010101:03030303-0303-0303-0303-030303030303:78";
        for (key, value) in [
            ("application", "dev.other.application"),
            ("account", "other-profile"),
            ("native-uid", "1002"),
        ] {
            let mut attributes = orphan_attributes(other);
            attributes.insert(key.into(), value.into());
            assert_eq!(
                reject_unmarked_btrfs_git_items(&[attributes], &[], &query, current, 77),
                Err(Error::InvalidStorage)
            );
        }

        let mut unknown_attribute = orphan_attributes(other);
        unknown_attribute.insert("unknown".into(), "value".into());
        assert_eq!(
            reject_unmarked_btrfs_git_items(&[unknown_attribute], &[], &query, current, 77),
            Err(Error::InvalidStorage)
        );

        let mut malformed_schema = orphan_attributes(other);
        malformed_schema.insert("xdg:schema".into(), "not allowed schema".into());
        assert_eq!(
            reject_unmarked_btrfs_git_items(&[malformed_schema], &[], &query, current, 77),
            Err(Error::InvalidStorage)
        );
    }

    #[test]
    fn git_markerless_search_bounds_results_and_attribute_sizes() {
        let current =
            "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77";
        let query = btrfs_orphan_search_attributes("profile-id", 1001);
        let path = || super::OwnedObjectPath::try_from("/org/freedesktop/secrets/item_1").unwrap();
        let too_many: Vec<_> = (0..=super::MAX_UNMARKED_BTRFS_ITEMS)
            .map(|_| path())
            .collect();
        assert_eq!(
            super::validate_btrfs_search_results(&too_many, &[]),
            Err(Error::InvalidStorage)
        );
        assert_eq!(
            super::validate_btrfs_search_results(&[path()], &[path()]),
            Err(Error::InvalidStorage),
            "duplicate paths across locked and unlocked lists fail closed"
        );

        let mut too_large = orphan_attributes("8:78");
        too_large.insert("xdg:schema".into(), "x".repeat(MAX_XDG_SCHEMA_BYTES + 1));
        assert_eq!(
            reject_unmarked_btrfs_git_items(&[too_large], &[], &query, current, 77),
            Err(Error::InvalidStorage)
        );
    }

    fn private_profile() -> (tempfile::TempDir, PrivateProfile) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let canonical_path = directory.path().canonicalize().unwrap();
        let profile = PrivateProfile::open(&canonical_path, false).unwrap();
        (directory, profile)
    }

    fn write_host_header(profile: &PrivateProfile, version: u32, valid_magic: bool) -> Vec<u8> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut header = vec![0u8; 100];
        if valid_magic {
            header[..16].copy_from_slice(b"SQLite format 3\0");
        }
        header[60..64].copy_from_slice(&version.to_be_bytes());
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(profile.path().join("host.sqlite3"))
            .unwrap()
            .write_all(&header)
            .unwrap();
        header
    }

    #[test]
    fn btrfs_host_context_requires_exact_durable_main_header_schema_16() {
        let (_directory, profile) = private_profile();
        write_host_header(&profile, HOST_SCHEMA_VERSION, true);
        let mut context = HostProfileContext::open(profile.path()).unwrap();
        assert_eq!(context.require_current_schema_for(&profile), Ok(()));

        for version in [15, 17, u32::MAX] {
            let (_directory, profile) = private_profile();
            let original = write_host_header(&profile, version, true);
            let mut wal = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(profile.path().join("host.sqlite3-wal"))
                .unwrap();
            wal.write_all(b"uncheckpointed wal version 16").unwrap();
            wal.sync_all().unwrap();
            let mut context = HostProfileContext::open(profile.path()).unwrap();
            assert_eq!(
                context.require_current_schema_for(&profile),
                Err(Error::InvalidStorage),
                "main schema {version} must not be accepted with a WAL"
            );
            assert_eq!(
                fs::read(profile.path().join("host.sqlite3")).unwrap(),
                original
            );
            assert_eq!(
                fs::read_dir(profile.path()).unwrap().count(),
                2,
                "rejection must not create or replace provider marker files"
            );
        }

        let (_directory, profile) = private_profile();
        write_host_header(&profile, HOST_SCHEMA_VERSION, false);
        let mut context = HostProfileContext::open(profile.path()).unwrap();
        assert_eq!(
            context.require_current_schema_for(&profile),
            Err(Error::InvalidStorage)
        );

        let (_directory, profile) = private_profile();
        write_host_header(&profile, HOST_SCHEMA_VERSION, true);
        fs::set_permissions(
            profile.path().join("host.sqlite3"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let mut context = HostProfileContext::open(profile.path()).unwrap();
        assert_eq!(
            context.require_current_schema_for(&profile),
            Err(Error::InvalidStorage),
            "the main database must be an owner-private regular file"
        );

        let (_directory, profile) = private_profile();
        let target_directory = tempfile::tempdir().unwrap();
        let target = target_directory.path().join("host.sqlite3");
        fs::write(&target, {
            let mut header = vec![0u8; 100];
            header[..16].copy_from_slice(b"SQLite format 3\0");
            header[60..64].copy_from_slice(&HOST_SCHEMA_VERSION.to_be_bytes());
            header
        })
        .unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(target, profile.path().join("host.sqlite3")).unwrap();
        let mut context = HostProfileContext::open(profile.path()).unwrap();
        assert_eq!(
            context.require_current_schema_for(&profile),
            Err(Error::InvalidStorage),
            "the main database must be opened without following links"
        );

        let (_directory, profile) = private_profile();
        let mut context = HostProfileContext::open(profile.path()).unwrap();
        assert_eq!(
            context.require_current_schema_for(&profile),
            Err(Error::InvalidStorage),
            "missing main database must remain missing"
        );
        assert_eq!(fs::read_dir(profile.path()).unwrap().count(), 0);
    }

    #[test]
    fn btrfs_host_context_limits_provider_paths_to_root_or_canonical_git_slot() {
        let (_root_directory, root) = private_profile();
        write_host_header(&root, HOST_SCHEMA_VERSION, true);

        let slot_path = root.path().join("git-credentials").join("a".repeat(64));
        fs::create_dir_all(&slot_path).unwrap();
        fs::set_permissions(
            slot_path.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&slot_path, fs::Permissions::from_mode(0o700)).unwrap();
        let slot = PrivateProfile::open(&slot_path, false).unwrap();
        let mut context = HostProfileContext::open(root.path()).unwrap();
        assert_eq!(context.require_current_schema_for(&slot), Ok(()));

        let (_other_directory, other_root) = private_profile();
        write_host_header(&other_root, HOST_SCHEMA_VERSION, true);
        let mut wrong_parent = HostProfileContext::open(other_root.path()).unwrap();
        assert_eq!(
            wrong_parent.require_current_schema_for(&root),
            Err(Error::InvalidStorage)
        );

        assert!(!host_profile_owns_provider_profile(
            root.path(),
            &root.path().join("git-credentials").join("A".repeat(64))
        ));
        assert!(!host_profile_owns_provider_profile(
            root.path(),
            &root.path().join("git-credentials").join("a".repeat(63))
        ));
        assert!(!host_profile_owns_provider_profile(
            root.path(),
            &root.path().join("other").join("a".repeat(64))
        ));
    }

    fn write_marker(
        profile: &PrivateProfile,
        bytes: &[u8],
    ) -> (std::fs::File, super::super::Object) {
        let mut file = super::open_at(
            profile,
            MARKER,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .unwrap()
        .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        let identity = object(&file.metadata().unwrap());
        profile.directory.sync_all().unwrap();
        (file, identity)
    }

    #[test]
    fn accepts_exact_attributes_with_optional_xdg_schema() {
        let expected = expected_attributes();
        assert!(item_attributes_match(&expected, &expected));

        let mut actual = expected.clone();
        actual.insert("xdg:schema".into(), "org.freedesktop.Secret.Generic".into());
        assert!(item_attributes_match(&expected, &actual));
    }

    #[test]
    fn rejects_missing_or_mismatched_expected_attributes() {
        let expected = expected_attributes();

        let mut missing = expected.clone();
        missing.remove("profile-object");
        assert!(!item_attributes_match(&expected, &missing));

        let mut mismatched = expected.clone();
        mismatched.insert("account".into(), "other-profile".into());
        mismatched.insert("xdg:schema".into(), "org.example.Schema".into());
        assert!(!item_attributes_match(&expected, &mismatched));
    }

    #[test]
    fn rejects_unexpected_attributes_and_invalid_schema_metadata() {
        let expected = expected_attributes();

        let mut unexpected = expected.clone();
        unexpected.insert("unrecognized".into(), "value".into());
        assert!(!item_attributes_match(&expected, &unexpected));

        for schema in [
            "".to_owned(),
            "org.example.\nschema".to_owned(),
            "x".repeat(MAX_XDG_SCHEMA_BYTES + 1),
        ] {
            let mut invalid_schema = expected.clone();
            invalid_schema.insert("xdg:schema".into(), schema);
            assert!(!item_attributes_match(&expected, &invalid_schema));
        }
    }

    #[test]
    fn accepts_only_lomi_and_gnome_keyring_content_types() {
        assert!(supported_content_type(CONTENT_TYPE));
        assert!(supported_content_type(GNOME_KEYRING_CONTENT_TYPE));
        assert!(!supported_content_type("text/html"));
        assert!(!supported_content_type(
            "application/vnd.lomi.host-secrets.v2"
        ));
    }

    #[test]
    fn promotes_only_a_verified_zero_to_positive_created_transition() {
        assert_eq!(
            marker(123),
            b"LMSS0001\nprofile-id\n1001\n1:2\n/org/freedesktop/secrets/collection/login\n123\n"
        );
        assert_eq!(created_after_write(0, 123), Ok(Some(123)));
        assert_eq!(created_after_write(0, 0), Err(Error::CommitUncertain));
        assert_eq!(created_after_write(123, 123), Ok(None));
        assert_eq!(created_after_write(123, 124), Err(Error::CommitUncertain));
        assert_eq!(created_after_write(123, 0), Err(Error::CommitUncertain));

        let updated = marker_with_created(&marker(0), 0, 123).unwrap();
        assert_eq!(updated, marker(123));
    }

    #[test]
    fn collection_anchor_uses_modified_only_when_created_is_zero() {
        assert_eq!(collection_created_anchor(|| Ok(0), || Ok(123)), Ok(123));
        assert_eq!(collection_created_anchor(|| Ok(123), || Ok(0)), Ok(123));
        assert_eq!(collection_created_anchor(|| Ok(0), || Ok(0)), Ok(0));

        let modified_was_read = std::cell::Cell::new(false);
        assert_eq!(
            collection_created_anchor(
                || Ok(123),
                || {
                    modified_was_read.set(true);
                    Ok(456)
                }
            ),
            Ok(123)
        );
        assert!(!modified_was_read.get());
        assert_eq!(
            collection_created_anchor(|| Err(Error::Locked), || panic!("unexpected fallback")),
            Err(Error::Locked)
        );
        assert_eq!(
            collection_created_anchor(|| Ok(0), || Err(Error::Unavailable)),
            Err(Error::Unavailable)
        );
    }

    #[test]
    fn positive_marker_remains_exact_when_zero_timestamp_fields_swap() {
        let (_directory, profile) = private_profile();
        let (_file, original) = write_marker(&profile, &marker(123));
        for (created, modified) in [(0, 123), (123, 0)] {
            let observed = collection_created_anchor(|| Ok(created), || Ok(modified)).unwrap();
            let identity = read_marker_identity(&profile, MARKER, &marker(observed)).unwrap();
            assert_eq!(identity, Some(original));
            assert_eq!(validate_marker_anchor(identity, observed), Ok(()));
        }
    }

    #[test]
    fn rejects_legacy_zero_marker_on_positive_created_reopen() {
        let (_directory, profile) = private_profile();
        let (_file, _) = write_marker(&profile, &marker(0));
        for (created, modified) in [(123, 0), (0, 123)] {
            let observed = collection_created_anchor(|| Ok(created), || Ok(modified)).unwrap();
            assert_eq!(
                read_marker_identity(&profile, MARKER, &marker(observed)),
                Err(Error::InvalidStorage)
            );
        }
    }

    #[test]
    fn rejects_existing_marker_when_collection_anchor_is_zero() {
        let (_directory, profile) = private_profile();
        let (_file, _) = write_marker(&profile, &marker(0));
        let identity = read_marker_identity(&profile, MARKER, &marker(0)).unwrap();

        assert!(identity.is_some());
        assert_eq!(
            validate_marker_anchor(identity, 0),
            Err(Error::InvalidStorage)
        );
    }

    #[test]
    fn allows_absent_marker_when_collection_anchor_is_zero() {
        let (_directory, profile) = private_profile();
        let identity = read_marker_identity(&profile, MARKER, &marker(0)).unwrap();

        assert_eq!(identity, None);
        assert_eq!(validate_marker_anchor(identity, 0), Ok(()));
    }

    #[test]
    fn rejects_changed_positive_created_even_when_modified_matches_marker() {
        let (_directory, profile) = private_profile();
        let (_file, _) = write_marker(&profile, &marker(123));
        let observed = collection_created_anchor(|| Ok(456), || Ok(123)).unwrap();

        assert_eq!(
            read_marker_identity(&profile, MARKER, &marker(observed)),
            Err(Error::InvalidStorage)
        );
    }

    #[test]
    fn marker_cas_promotes_exact_inode_and_bytes() {
        let (_directory, profile) = private_profile();
        let guard = ProtectedFile::open_secret_service_guard(&profile).unwrap();
        let old = marker(0);
        let new = marker(123);
        let (_file, identity) = write_marker(&profile, &old);

        let updated_identity = replace_marker_cas(
            &profile,
            &guard,
            identity,
            &old,
            &new,
            |_| Ok(()),
            |directory| directory.sync_all(),
        )
        .unwrap();
        assert_ne!(updated_identity, identity);
        let (_, bytes, installed_identity) = marker_entry(&profile, MARKER).unwrap().unwrap();
        assert_eq!(bytes, new);
        assert_eq!(installed_identity, updated_identity);
    }

    #[test]
    fn btrfs_marker_cas_promotes_zero_created_and_reopens_exact_v2() {
        let (_directory, profile) = private_profile();
        let guard = ProtectedFile::open_secret_service_guard(&profile).unwrap();
        let stable =
            "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77";
        let old = btrfs_marker(
            "profile-id",
            1001,
            stable,
            stable,
            "/org/freedesktop/secrets/collection/login",
            0,
        );
        let new = marker_with_created(&old, 0, 123).unwrap();
        let (_file, identity) = write_marker(&profile, &old);

        let updated_identity = replace_marker_cas(
            &profile,
            &guard,
            identity,
            &old,
            &new,
            |_| Ok(()),
            |directory| directory.sync_all(),
        )
        .unwrap();
        assert_ne!(updated_identity, identity);
        let (_, bytes, installed_identity) = marker_entry(&profile, MARKER).unwrap().unwrap();
        assert_eq!(bytes, new);
        assert_eq!(installed_identity, updated_identity);
        assert_eq!(
            select_btrfs(Some(&bytes), stable, "8:77", 123)
                .unwrap()
                .item_object,
            stable
        );
    }

    #[test]
    fn btrfs_marker_sync_uncertainty_keeps_reopenable_v2() {
        let (_directory, profile) = private_profile();
        let guard = ProtectedFile::open_secret_service_guard(&profile).unwrap();
        let stable =
            "btrfs:01010101-0101-0101-0101-010101010101:02020202-0202-0202-0202-020202020202:77";
        let old = btrfs_marker(
            "profile-id",
            1001,
            stable,
            stable,
            "/org/freedesktop/secrets/collection/login",
            0,
        );
        let new = marker_with_created(&old, 0, 123).unwrap();
        let (_file, identity) = write_marker(&profile, &old);

        assert_eq!(
            replace_marker_cas(
                &profile,
                &guard,
                identity,
                &old,
                &new,
                |_| Ok(()),
                |_| Err(io::Error::other("injected sync failure")),
            ),
            Err(Error::CommitUncertain)
        );
        let (_, bytes, _) = marker_entry(&profile, MARKER).unwrap().unwrap();
        assert_eq!(bytes, new);
        assert_eq!(
            select_btrfs(Some(&bytes), stable, "8:77", 123)
                .unwrap()
                .item_object,
            stable
        );
    }

    #[test]
    fn marker_cas_rejects_inode_replacement_before_exchange() {
        let (_directory, profile) = private_profile();
        let guard = ProtectedFile::open_secret_service_guard(&profile).unwrap();
        let old = marker(0);
        let new = marker(123);
        let (_original, original_identity) = write_marker(&profile, &old);
        assert_eq!(
            unsafe { libc::unlinkat(profile.directory.as_raw_fd(), MARKER.as_ptr(), 0,) },
            0
        );
        let (_replacement, replacement_identity) = write_marker(&profile, &old);
        assert_ne!(replacement_identity, original_identity);

        assert_eq!(
            replace_marker_cas(
                &profile,
                &guard,
                original_identity,
                &old,
                &new,
                |_| Ok(()),
                |directory| directory.sync_all(),
            ),
            Err(Error::CommitUncertain)
        );
        let (_, bytes, identity) = marker_entry(&profile, MARKER).unwrap().unwrap();
        assert_eq!(bytes, old);
        assert_eq!(identity, replacement_identity);
    }

    #[test]
    fn marker_cas_preserves_displaced_replacement_without_rollback() {
        let (_directory, profile) = private_profile();
        let guard = ProtectedFile::open_secret_service_guard(&profile).unwrap();
        let old = marker(0);
        let new = marker(123);
        let unexpected = marker(456);
        let (_original, identity) = write_marker(&profile, &old);

        assert_eq!(
            replace_marker_cas(
                &profile,
                &guard,
                identity,
                &old,
                &new,
                |profile| {
                    assert_eq!(
                        unsafe {
                            libc::unlinkat(profile.directory.as_raw_fd(), MARKER.as_ptr(), 0)
                        },
                        0
                    );
                    let _ = write_marker(profile, &unexpected);
                    Ok(())
                },
                |directory| directory.sync_all(),
            ),
            Err(Error::CommitUncertain)
        );

        let (_, installed, _) = marker_entry(&profile, MARKER).unwrap().unwrap();
        assert_eq!(installed, new);
        let displaced: Vec<_> = std::fs::read_dir(profile.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with(".host-secret-service-") && name.ends_with(".tmp")
                    })
            })
            .collect();
        assert_eq!(displaced.len(), 1);
        assert_eq!(std::fs::read(&displaced[0]).unwrap(), unexpected);
    }

    #[test]
    fn marker_directory_sync_failure_returns_uncertain_after_exchange() {
        let (_directory, profile) = private_profile();
        let guard = ProtectedFile::open_secret_service_guard(&profile).unwrap();
        let old = marker(0);
        let new = marker(123);
        let (_file, identity) = write_marker(&profile, &old);

        assert_eq!(
            replace_marker_cas(
                &profile,
                &guard,
                identity,
                &old,
                &new,
                |_| Ok(()),
                |_| Err(io::Error::other("injected sync failure")),
            ),
            Err(Error::CommitUncertain)
        );
        let (_, bytes, _) = marker_entry(&profile, MARKER).unwrap().unwrap();
        assert_eq!(bytes, new);
    }
}
