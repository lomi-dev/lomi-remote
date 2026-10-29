//! Account-scoped Linux Secret Service storage, without unlock prompts or fallback.
//!
//! The protocol uses the local authenticated session bus and its standard plain
//! transfer session; persistence and encryption at rest belong to Secret Service.
//! https://specifications.freedesktop.org/secret-service/latest/
use super::{PrivateProfile, object, private_regular, secrets::ProtectedFile};
use crate::secrets::{
    Error, ProviderKind, ProviderStatus, SecretBundle, SecretStorage, Selection, StorageState,
};
use lomi_remote_protocol::ipc::IpcProfileId;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
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
const MARKER: &CStr = c"host-secrets.secret-service";
const CALL_TIMEOUT: Duration = Duration::from_secs(2);

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
    guard: ProtectedFile<'a>,
    connection: Connection,
    deadline_socket: UnixStream,
    owner: String,
    collection: OwnedObjectPath,
    session: OwnedObjectPath,
    attributes: HashMap<String, String>,
    marker: Vec<u8>,
}
impl<'a> SecretService<'a> {
    pub fn open(
        profile: &'a PrivateProfile,
        selection: Selection,
        account: IpcProfileId,
    ) -> Result<Self, Error> {
        match selection {
            Selection::SecretService => {}
            Selection::Unconfigured => return Err(Error::Unconfigured),
            _ => return Err(Error::Unavailable),
        }
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
        let collection_created: u64 = default.get_property("Created").map_err(read_error)?;
        let (output, session): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::from("")))
            .map_err(read_error)?;
        if String::try_from(output).ok().as_deref() != Some("")
            || session.as_str() == "/"
            || session.as_str().len() > 1024
        {
            return Err(Error::InvalidStorage);
        }
        let metadata = profile
            .directory
            .metadata()
            .map_err(|_| Error::InvalidStorage)?;
        let account = String::from(account);
        let profile_object = format!("{}:{}", metadata.dev(), metadata.ino());
        let attributes = HashMap::from([
            (
                "application".into(),
                "dev.lomi.remote.host-secrets.v1".into(),
            ),
            ("account".into(), account.clone()),
            ("native-uid".into(), uid.to_string()),
            ("profile-object".into(), profile_object.clone()),
        ]);
        // An alias change cannot make credentials in the old keyring appear
        // absent. Bind the persistent collection and its creation observation.
        let marker = format!(
            "LMSS0001\n{account}\n{uid}\n{profile_object}\n{}\n{collection_created}\n",
            collection.as_str()
        )
        .into_bytes();
        drop(default);
        drop(service);
        drop(bus);
        let this = Self {
            profile,
            guard,
            connection,
            deadline_socket,
            owner,
            collection,
            session,
            attributes,
            marker,
        };
        this.check()?;
        drop(this.load()?);
        Ok(this)
    }
    fn proxy<'b>(&'b self, path: &'b str, interface: &'static str) -> Result<Proxy<'b>, Error> {
        proxy(&self.connection, &self.owner, path, interface)
    }
    fn check(&self) -> Result<bool, Error> {
        self.guard.check()?;
        let Some(mut file) = open_at(self.profile, MARKER, libc::O_RDONLY)? else {
            return Ok(false);
        };
        private_regular(&file).map_err(|_| Error::InvalidStorage)?;
        if file.metadata().map_err(|_| Error::InvalidStorage)?.len() != self.marker.len() as u64 {
            return Err(Error::InvalidStorage);
        }
        let mut bytes = vec![0; self.marker.len()];
        file.read_exact(&mut bytes)
            .map_err(|_| Error::InvalidStorage)?;
        let named = open_at(self.profile, MARKER, libc::O_RDONLY)?.ok_or(Error::InvalidStorage)?;
        if bytes != self.marker
            || object(&named.metadata().map_err(|_| Error::InvalidStorage)?)
                != object(&file.metadata().map_err(|_| Error::InvalidStorage)?)
        {
            return Err(Error::InvalidStorage);
        }
        self.guard.check()?;
        Ok(true)
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
        if proxy
            .get_property::<HashMap<String, String>>("Attributes")
            .map_err(read_error)?
            != self.attributes
        {
            return Err(Error::InvalidStorage);
        }
        drop(proxy);
        Ok(Some(item))
    }
    fn publish_marker(&self) -> Result<(), Error> {
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
            || secret.content_type != CONTENT_TYPE
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
