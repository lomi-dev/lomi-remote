//! Independent Local IPC 1.0 contract. E1 must supply real OS authentication,
//! endpoint ownership/ACL checks, deadlines, durable admission and publication
//! fencing before cloud share/unshare. No OS transport or liveness is implemented.
use crate::rpc::{BoundedList, Confirmed, SubscriptionId, WorkspaceState};
use crate::streams::{
    FileWatchAck, FileWatchFrame, TerminalStreamFrame, WorkspaceStreamAck, WorkspaceStreamFrame,
};
use crate::*;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::Path,
};

pub const LOCAL_IPC_FRAME_BYTES: usize = CONTROL_MESSAGE_BYTES as usize;
/// Proposed E0 lease budget; expiry quarantines, never releases a writer.
pub const NATIVE_LEASE_MAX_MS: u64 = 120_000;
/// Owner-local recursive Explorer effects may authorize each namespace change.
/// Other editor and Git exchanges retain their existing 8,192 challenge cap.
pub const DESKTOP_FILE_CHALLENGE_LIMIT: usize = 262_144;

macro_rules! ipc_id {
    ($($name:ident),+) => {$(
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(HostId);
        impl $name {
            pub fn from_bytes(bytes: [u8;16]) -> Result<Self, &'static str> { HostId::from_bytes(bytes).map(Self) }
            pub fn to_bytes(self) -> [u8;16] { self.0.to_bytes() }
        }
        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(value: String) -> Result<Self, Self::Error> { HostId::try_from(value).map(Self) }
        }
        impl From<$name> for String { fn from(value: $name) -> Self { value.0.into() } }
    )+};
}
ipc_id!(IpcProfileId, IpcNonce, NativeIntentId);

macro_rules! local_text {
    ($name:ident, $limit:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from="String", into="String")]
        pub struct $name(String);
        impl $name { pub fn as_str(&self) -> &str { &self.0 } }
        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                if value.is_empty() || value.len() > $limit || value.chars().any(char::is_control) {
                    Err("invalid bounded local text")
                } else { Ok(Self(value)) }
            }
        }
        impl From<$name> for String { fn from(value: $name) -> Self { value.0 } }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static,str> { stringify!($name).into() }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({"type":"string","minLength":1,"maxLength":$limit,"x-lomi-maxUtf8Bytes":$limit,"not":{"pattern":r"[\u0000-\u001F\u007F-\u009F]"}})
            }
        }
    };
}
local_text!(LocalProjectName, 255);
/// Bounded local-only label for the Host. It is never a remote RPC identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LocalHostName(String);
impl LocalHostName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for LocalHostName {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 255
            || value.trim() != value
            || value.chars().any(|character| {
                let code = character as u32;
                character.is_control()
                    || matches!(character, '\u{2028}' | '\u{2029}')
                    || (0x202a..=0x202e).contains(&code)
                    || (0x2066..=0x2069).contains(&code)
            })
        {
            Err("invalid bounded local Host name")
        } else {
            Ok(Self(value))
        }
    }
}
impl From<LocalHostName> for String {
    fn from(value: LocalHostName) -> Self {
        value.0
    }
}
impl JsonSchema for LocalHostName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "LocalHostName".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type":"string","minLength":1,"maxLength":255,
            "x-lomi-maxUtf8Bytes":255,
            "not":{"pattern":r"[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]"}})
    }
}
// UTF-8 local configuration only; remote RPC never accepts a root path.
local_text!(LocalRootPath, 4096);
local_text!(LocalWorkspaceWebUrl, 4096);
local_text!(LocalNativeRelativePath, 4096);
local_text!(LocalNativeParentOperationId, 256);
local_text!(LocalNativeResultJson, 131072);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LocalProcessArgument(String);
impl TryFrom<String> for LocalProcessArgument {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() > 4096 || value.contains('\0') {
            Err("invalid local process argument")
        } else {
            Ok(Self(value))
        }
    }
}
impl From<LocalProcessArgument> for String {
    fn from(value: LocalProcessArgument) -> Self {
        value.0
    }
}
impl JsonSchema for LocalProcessArgument {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "LocalProcessArgument".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type":"string","maxLength":4096,
            "x-lomi-maxUtf8Bytes":4096,"not":{"pattern":"\u{0000}"}})
    }
}
local_text!(LocalShellEnvironmentName, 32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LocalShellKind {
    Bash,
    Zsh,
    Fish,
    Sh,
    PowerShell,
    Cmd,
    /// A bounded generic WSL shell whose exact absolute path is carried in
    /// the adjacent descriptor. Native profiles keep unknown executables on
    /// the legacy launch path instead.
    Other,
}

/// Typed description of an ordinary discovered shell. Its fields are local
/// configuration only; remote RPC still selects a registered profile ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "platform", rename_all = "camelCase", deny_unknown_fields)]
pub enum LocalShellIntegration {
    NativeV1 {
        shell: LocalShellKind,
        home: LocalRootPath,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_zdotdir: Option<LocalRootPath>,
    },
    WslV1 {
        distro: LocalProjectName,
        shell: LocalShellKind,
        shell_executable: LocalRootPath,
        home: LocalRootPath,
    },
}

impl LocalShellIntegration {
    pub fn validate_launch(
        &self,
        executable: &LocalRootPath,
        args: &BoundedList<LocalProcessArgument, 32>,
    ) -> Result<(), &'static str> {
        if !args.0.is_empty() || !Path::new(executable.as_str()).is_absolute() {
            return Err("invalid ordinary shell launch");
        }
        match self {
            Self::NativeV1 { shell, home, .. } => {
                if !Path::new(home.as_str()).is_absolute()
                    || *shell == LocalShellKind::Other
                    || !shell.matches_executable(executable.as_str())
                {
                    return Err("invalid native shell integration");
                }
                if original_zdotdir_invalid(self) {
                    return Err("invalid native zsh integration directory");
                }
            }
            Self::WslV1 {
                distro,
                shell,
                shell_executable,
                home,
            } => {
                if cfg!(not(windows))
                    || !valid_wsl_distro(distro.as_str())
                    || !shell.is_wsl_shell()
                    || !shell_executable.as_str().starts_with('/')
                    || (*shell != LocalShellKind::Other
                        && !shell.matches_executable(shell_executable.as_str()))
                    || !home.as_str().starts_with('/')
                    || !is_wsl_launcher(executable.as_str())
                {
                    return Err("invalid WSL shell integration");
                }
            }
        }
        Ok(())
    }
}

fn original_zdotdir_invalid(integration: &LocalShellIntegration) -> bool {
    match integration {
        LocalShellIntegration::NativeV1 {
            shell: LocalShellKind::Zsh,
            original_zdotdir: Some(path),
            ..
        } => !Path::new(path.as_str()).is_absolute(),
        LocalShellIntegration::NativeV1 {
            original_zdotdir: Some(_),
            ..
        } => true,
        _ => false,
    }
}

impl LocalShellKind {
    fn is_wsl_shell(self) -> bool {
        matches!(
            self,
            Self::Bash
                | Self::Zsh
                | Self::Fish
                | Self::Sh
                | Self::PowerShell
                | Self::Cmd
                | Self::Other
        )
    }

    fn matches_executable(self, executable: &str) -> bool {
        let path = Path::new(executable);
        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        match self {
            Self::Bash => name == "bash",
            Self::Zsh => name == "zsh",
            Self::Fish => name == "fish",
            Self::Sh => name == "sh",
            Self::PowerShell => name == "pwsh" || name == "powershell",
            Self::Cmd => name == "cmd",
            Self::Other => false,
        }
    }
}

fn valid_wsl_distro(distro: &str) -> bool {
    !distro.is_empty()
        && !distro.starts_with('-')
        && distro
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b' '))
}

fn is_wsl_launcher(executable: &str) -> bool {
    Path::new(executable)
        .file_stem()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("wsl"))
}

macro_rules! dto {
    ($name:ident {$($field:ident: $ty:ty),* $(,)?}) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all="camelCase", deny_unknown_fields)]
        pub struct $name {$(pub $field: $ty),*}
    };
}
// Authentication envelopes require maps, including nested configuration values.
// Keep Wire-only decoding attributes separate from public serialization attributes.
macro_rules! auth_dto {
    ($name:ident { $($(#[$field_attr:meta])* $(@serialize($serialize_attr:meta))* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name { $($(#[$serialize_attr])* pub $field: $ty),* }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase", deny_unknown_fields)]
                struct Wire { $($(#[$field_attr])* $field: $ty),* }
                struct Object;
                impl<'de> serde::de::Visitor<'de> for Object {
                    type Value = $name;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("an IPC object") }
                    fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                        let Wire { $($field),* } = Wire::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                        Ok($name { $($field),* })
                    }
                }
                decoder.deserialize_map(Object)
            }
        }
    }
}
local_text!(LocalAuthOrigin, 180);
/// Separately trusted relay pin: a canonical WSS origin (at most180bytes)
/// followed by the fixed9byte path. No runtime transport or discovery is implied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LocalRelayEndpoint(String);
impl LocalRelayEndpoint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for LocalRelayEndpoint {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        const INVALID: &str = "invalid canonical relay endpoint";
        let authority = value
            .strip_prefix("wss://")
            .and_then(|v| v.strip_suffix("/v2/relay"))
            .ok_or(INVALID)?;
        let (hostname, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        // Same narrow authority policy as Host HTTP's Remote API origin. Kept
        // local to this protocol type to avoid a protocol->HTTP dependency and
        // changing the independently qualified HTTP origin implementation.
        if value.len() > 189
            || hostname.is_empty()
            || hostname.len() > 253
            || hostname.starts_with('.')
            || hostname.ends_with('.')
            || hostname.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            || port.is_some_and(|p| {
                p.is_empty()
                    || p.starts_with('0')
                    || p == "443"
                    || p.parse::<u16>().is_err()
                    || !p.bytes().all(|b| b.is_ascii_digit())
            })
        {
            return Err(INVALID);
        }
        let last = hostname.rsplit('.').next().ok_or(INVALID)?;
        let numeric = last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|v| v.bytes().all(|b| b.is_ascii_hexdigit()));
        if numeric
            && !hostname
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.to_string() == hostname)
        {
            return Err(INVALID);
        }
        Ok(Self(value))
    }
}
impl From<LocalRelayEndpoint> for String {
    fn from(value: LocalRelayEndpoint) -> Self {
        value.0
    }
}
impl JsonSchema for LocalRelayEndpoint {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "LocalRelayEndpoint".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let label = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
        let port = "(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])";
        let octet = "(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])";
        json_schema!({"type":"string","minLength":16,"maxLength":189,"x-lomi-maxUtf8Bytes":189,
            "pattern":format!("^wss://{label}(?:\\.{label})*(?::{port})?/v2/relay$"),
            "not":{"anyOf":[{"pattern":":443/v2/relay$"},{"pattern":r"[^\u0021-\u007e]"}]},
            "if":{"pattern":"^wss://(?:[a-z0-9-]+\\.)*(?:[0-9]+|0x[0-9a-f]*)(?::[0-9]+)?/v2/relay$"},
            "then":{"pattern":format!("^wss://{octet}(?:\\.{octet}){{3}}(?::{port})?/v2/relay$")}
        })
    }
}
local_text!(LocalAuthClientId, 128);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalAuthProvider {
    ProtectedFile,
    MacOsKeychain,
    WindowsDpapi,
    LinuxSecretService,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalFileAcknowledgement {
    OsPermissionsOnly,
}
auth_dto!(LocalAuthConfiguration {
    version: u32,
    origin: LocalAuthOrigin,
    @serialize(serde(skip_serializing_if = "Option::is_none"))
    remote_api_origin: Option<LocalAuthOrigin>,
    @serialize(serde(skip_serializing_if = "Option::is_none"))
    relay_endpoint: Option<LocalRelayEndpoint>,
    client_id: LocalAuthClientId,
    provider: LocalAuthProvider,
    keychain_path: Option<LocalRootPath>,
    protected_file_acknowledgement: Option<LocalFileAcknowledgement>
});
impl LocalAuthConfiguration {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1 {
            return Err("AUTH_CONFIG_VERSION");
        }
        match self.provider {
            LocalAuthProvider::ProtectedFile
                if self.keychain_path.is_none()
                    && self.protected_file_acknowledgement
                        == Some(LocalFileAcknowledgement::OsPermissionsOnly) =>
            {
                Ok(())
            }
            LocalAuthProvider::MacOsKeychain
                if self.keychain_path.is_some()
                    && self.protected_file_acknowledgement.is_none() =>
            {
                Ok(())
            }
            LocalAuthProvider::WindowsDpapi | LocalAuthProvider::LinuxSecretService
                if self.keychain_path.is_none()
                    && self.protected_file_acknowledgement.is_none() =>
            {
                Ok(())
            }
            _ => Err("AUTH_CONFIG_PROVIDER"),
        }
    }
}
auth_dto!(LocalAuthConfigure {
    configuration: LocalAuthConfiguration,
    operator_intent: Confirmed
});
auth_dto!(LocalLoginStart {
    operation_id: OperationId
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalAuthPhase {
    Unconfigured,
    Idle,
    Initializing,
    AwaitingApproval,
    Exchanging,
    Registering,
    Ready,
    Refreshing,
    Locked,
    PendingRevoke,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalAuthStorage {
    Unconfigured,
    Available,
    Locked,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalAuthNetwork {
    Idle,
    Working,
    Available,
    Unavailable,
}
auth_dto!(LocalLoginStatus {
    phase: LocalAuthPhase,
    storage: LocalAuthStorage,
    network: LocalAuthNetwork,
    generation: DecimalU64,
    locked: bool,
    pending_cloud_revoke: bool,
    operation_id: Option<OperationId>,
    access_expires_at: Option<DecimalU64>,
    refresh_at: Option<DecimalU64>
});
auth_dto!(LocalLoginPresentation {
    user_code: UserCode,
    verification_url: LocalRootPath,
    expires_at: DecimalU64,
    next_poll_at: DecimalU64
});
auth_dto!(LocalLoginAccepted {
    operation_id: OperationId,
    generation: DecimalU64
});
dto!(LocalClientHello {
    version: LocalIpcVersion,
    profile_id: IpcProfileId,
    nonce: IpcNonce
});
dto!(LocalServerHello {
    version: LocalIpcVersion,
    profile_id: IpcProfileId,
    host_id: HostId,
    runtime_id: RuntimeId,
    nonce: IpcNonce
});

/// Non-wire OS identity. Adapters must derive this from the connected socket or
/// pipe token, never from JSON, environment, client class, or a caller bool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalOsOwner {
    UnixUid(u32),
    WindowsSid(String),
}
/// Implement only in the trusted native OS adapter. Unix verifies peer UID and
/// endpoint owner; Windows verifies restrictive ACL, peer SID and server PID.
pub trait TrustedLocalPeerAdapter {
    fn connected_owner(&self) -> Result<LocalOsOwner, &'static str>;
}
#[derive(Debug)]
pub struct AuthenticatedLocalPeer {
    owner: LocalOsOwner,
}
impl AuthenticatedLocalPeer {
    pub fn from_os_adapter(
        adapter: &impl TrustedLocalPeerAdapter,
        expected: &LocalOsOwner,
    ) -> Result<Self, &'static str> {
        let owner = adapter.connected_owner()?;
        if &owner != expected {
            return Err("LOCAL_OWNER_MISMATCH");
        }
        Ok(Self { owner })
    }
}
/// One probe per connection. A failed or repeated reply permanently consumes it.
#[derive(Debug)]
pub struct LocalHelloProbe {
    hello: LocalClientHello,
    expected_host: HostId,
    expected_runtime: RuntimeId,
    expected_owner: LocalOsOwner,
    consumed: bool,
}
impl LocalHelloProbe {
    pub fn new(
        hello: LocalClientHello,
        expected_host: HostId,
        expected_runtime: RuntimeId,
        expected_owner: LocalOsOwner,
    ) -> Self {
        Self {
            hello,
            expected_host,
            expected_runtime,
            expected_owner,
            consumed: false,
        }
    }
    pub fn verify(
        &mut self,
        reply: &LocalServerHello,
        peer: &AuthenticatedLocalPeer,
    ) -> Result<LocalIpcVersion, &'static str> {
        if std::mem::replace(&mut self.consumed, true) {
            return Err("PROBE_CONSUMED");
        }
        if reply.profile_id != self.hello.profile_id
            || reply.host_id != self.expected_host
            || reply.runtime_id != self.expected_runtime
            || reply.nonce != self.hello.nonce
            || peer.owner != self.expected_owner
        {
            return Err("LOCAL_BINDING_MISMATCH");
        }
        let selected = self.hello.version.negotiate(&LocalIpcVersion::CURRENT);
        if reply.version != selected {
            return Err("UPDATE_REQUIRED");
        }
        Ok(selected)
    }
}
pub fn answer_local_hello(
    hello: &LocalClientHello,
    peer: &AuthenticatedLocalPeer,
    owner: &LocalOsOwner,
    profile_id: IpcProfileId,
    host_id: HostId,
    runtime_id: RuntimeId,
) -> Result<LocalServerHello, &'static str> {
    if hello.profile_id != profile_id || &peer.owner != owner {
        return Err("LOCAL_BINDING_MISMATCH");
    }
    Ok(LocalServerHello {
        version: LocalIpcVersion::CURRENT.negotiate(&hello.version),
        profile_id,
        host_id,
        runtime_id,
        nonce: hello.nonce,
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalSharing {
    #[default]
    Disabled,
    Enabled,
}
/// Saved local preference only. It does not install or start an OS service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalStartMode {
    #[default]
    Manual,
    Login,
    Boot,
}
dto!(LocalStartModePreference {
    start_mode: LocalStartMode
});
dto!(LocalWorkspaceAdd {
    name: LocalProjectName,
    root_path: LocalRootPath,
    operator_intent: Confirmed
});
// Idempotent import of an existing local desktop workspace. The stable ID is
// selected by the trusted native application before its first IPC attempt.
// Repeating the import never changes sharing policy or starts a terminal.
dto!(LocalWorkspaceImport {
    workspace_id: WorkspaceId,
    name: LocalProjectName,
    root_path: LocalRootPath,
    operator_intent: Confirmed
});
/// Owner-local resolution of stable import IDs. `Missing` is distinct from
/// `Retired`: an import may not have been committed yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "camelCase", deny_unknown_fields)]
pub enum WorkspaceBinding {
    Missing {
        import_id: WorkspaceId,
    },
    Active {
        import_id: WorkspaceId,
        workspace_id: WorkspaceId,
        root_path: LocalRootPath,
    },
    Pending {
        import_id: WorkspaceId,
        workspace_id: WorkspaceId,
    },
    Retired {
        import_id: WorkspaceId,
        workspace_id: WorkspaceId,
    },
}
dto!(WorkspaceBindingsRead {
    import_ids: BoundedList<WorkspaceId, 256>
});
dto!(WorkspaceBindingsSnapshot {
    host_id: HostId,
    runtime_id: RuntimeId,
    bindings: BoundedList<WorkspaceBinding, 256>
});
auth_dto!(LocalShellEnvironment {
    name: LocalShellEnvironmentName,
    value: LocalProcessArgument
});
auth_dto!(LocalShellProfileRegister {
    workspace_id: WorkspaceId,
    profile_id: crate::rpc::HostProfileId,
    name: LocalProjectName,
    executable: LocalRootPath,
    args: BoundedList<LocalProcessArgument, 32>,
    cwd: LocalRootPath,
    environment: BoundedList<LocalShellEnvironment, 8>,
    #[serde(default)] @serialize(serde(skip_serializing_if = "Option::is_none")) integration: Option<LocalShellIntegration>,
    operator_intent: Confirmed
});
impl LocalShellProfileRegister {
    pub fn new(
        workspace_id: WorkspaceId,
        name: LocalProjectName,
        executable: LocalRootPath,
        args: BoundedList<LocalProcessArgument, 32>,
        cwd: LocalRootPath,
        environment: BoundedList<LocalShellEnvironment, 8>,
    ) -> Result<Self, &'static str> {
        let mut value = Self {
            workspace_id,
            profile_id: "default".to_owned().try_into()?,
            name,
            executable,
            args,
            cwd,
            environment,
            integration: None,
            operator_intent: Confirmed::Confirmed,
        };
        value.profile_id = value.derived_profile_id()?;
        Ok(value)
    }

    pub fn with_integration(
        mut self,
        integration: LocalShellIntegration,
    ) -> Result<Self, &'static str> {
        integration.validate_launch(&self.executable, &self.args)?;
        self.integration = Some(integration);
        self.profile_id = self.derived_profile_id()?;
        Ok(self)
    }

    /// One canonical native implementation binds every immutable launch field,
    /// including the workspace and nonsecret environment. Remote RPC carries
    /// only the resulting ID; it cannot supply executable paths or arguments.
    pub fn derived_profile_id(&self) -> Result<crate::rpc::HostProfileId, &'static str> {
        use sha2::{Digest, Sha256};
        let mut environment = std::collections::BTreeMap::new();
        for entry in &self.environment.0 {
            if !matches!(
                entry.name.as_str(),
                "TERM" | "COLORTERM" | "TERM_PROGRAM" | "ZDOTDIR" | "LOMI_ZDOTDIR" | "PROMPT"
            ) || environment
                .insert(entry.name.as_str(), &entry.value)
                .is_some()
            {
                return Err("invalid local shell environment");
            }
        }
        let bytes = if let Some(integration) = &self.integration {
            serde_json::to_vec(&(
                "lomi-shell-profile-v2",
                self.workspace_id,
                &self.name,
                &self.executable,
                &self.args,
                &self.cwd,
                environment,
                integration,
            ))
        } else {
            // Preserve the v1 profile ID for existing stored and registered
            // profiles whose descriptor is absent.
            serde_json::to_vec(&(
                "lomi-shell-profile-v1",
                self.workspace_id,
                &self.name,
                &self.executable,
                &self.args,
                &self.cwd,
                environment,
            ))
        }
        .map_err(|_| "invalid local shell profile")?;
        format!("shell_{:x}", Sha256::digest(bytes)).try_into()
    }
}
// Read-only lookup. The server supplies current epochs, runtime and domain CAS.
dto!(LocalWorkspaceRead {
    workspace_id: WorkspaceId
});
dto!(LocalWorkspaceTarget {
    workspace_id: WorkspaceId,
    operator_intent: Confirmed
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalWorkspaceRemovalPhase {
    NotStarted,
    Stopping,
    Uncertain,
    Complete,
}
dto!(LocalWorkspaceRemovalStatus {
    workspace_id: WorkspaceId,
    attempt_id: Option<OperationId>,
    phase: LocalWorkspaceRemovalPhase,
    total_sessions: DecimalU64,
    confirmed_sessions: DecimalU64
});
impl LocalWorkspaceRemovalStatus {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.total_sessions.0 > 32 || self.confirmed_sessions > self.total_sessions {
            return Err("IPC_INVALID_REMOVAL_STATUS");
        }
        match self.phase {
            LocalWorkspaceRemovalPhase::NotStarted => {
                if self.attempt_id.is_some() || self.total_sessions.0 != 0 {
                    return Err("IPC_INVALID_REMOVAL_STATUS");
                }
            }
            LocalWorkspaceRemovalPhase::Uncertain if self.attempt_id.is_none() => {
                // The begin may have committed without a recoverable reply.
                // Stable workspace identity still permits a status-only query.
                if self.total_sessions.0 != 0 {
                    return Err("IPC_INVALID_REMOVAL_STATUS");
                }
            }
            _ if self.attempt_id.is_none() => return Err("IPC_INVALID_REMOVAL_STATUS"),
            _ => {}
        }
        if self.phase == LocalWorkspaceRemovalPhase::Complete
            && self.confirmed_sessions != self.total_sessions
        {
            return Err("IPC_INVALID_REMOVAL_STATUS");
        }
        Ok(())
    }
}
dto!(LocalWorkspaceRename {
    workspace_id: WorkspaceId,
    expected_name: LocalProjectName,
    name: LocalProjectName,
    operator_intent: Confirmed
});
dto!(LocalWorkspaceConsentAuthorized {
    workspace_id: WorkspaceId,
    expected_host_id: HostId,
    expected_authorization_generation: DecimalU64,
    expected_context: WorkspaceContext,
    expected_import_id: WorkspaceId,
    expected_root_path: LocalRootPath,
    operator_intent: Confirmed
});
// Owner-local paths never enter Remote RPC or Cloud publication.
dto!(LocalWorkspaceDetails {
    workspace: LocalWorkspaceSummary,
    root_path: LocalRootPath,
    remote_web_url: Option<LocalWorkspaceWebUrl>
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalPublicationState {
    Pending,
    Acknowledged,
    Unknown,
}
dto!(LocalWorkspacePublication {
    host_id: HostId,
    workspace_id: WorkspaceId,
    auth_generation: DecimalU64,
    consent: LocalSharing,
    publication: LocalPublicationState
});
auth_dto!(LocalOperatorIntent {
    operator_intent: Confirmed
});
dto!(LocalWorkspaceSummary {
    workspace_id: WorkspaceId,
    name: LocalProjectName,
    sharing: LocalSharing
});
auth_dto!(LocalWorkspaceImportReceipt {
    import_id: WorkspaceId,
    workspace: LocalWorkspaceSummary
});
dto!(LocalProfileSummary {
    profile_id: IpcProfileId,
    name: LocalProjectName
});
dto!(LocalStatus {
    host_name: LocalHostName,
    host_id: HostId,
    runtime_id: RuntimeId,
    sharing: LocalSharing
});
dto!(LocalHostNameSet {
    expected_name: Option<LocalHostName>,
    name: LocalHostName
});
auth_dto!(LocalMaintenanceStatus {
    host_id: HostId,
    runtime_id: RuntimeId,
    profile_schema: DecimalU64,
    active_terminals: DecimalU64
});
auth_dto!(LocalOperatorSnapshot {
    status: LocalStatus,
    login: LocalLoginStatus,
    uptime_seconds: DecimalU64,
    active_terminals: DecimalU64,
    connected_clients: Option<u32>
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticComponent {
    Host,
    Ipc,
    Profile,
    Service,
    Authentication,
    Network,
    Storage,
    Shell,
    Git,
    Updater,
    Terminal,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticCode {
    HostStarted,
    HostStartRejected,
    IpcRequestRejected,
    IpcVersionMismatch,
    ProfileInvalid,
    ServiceUnavailable,
    ServiceRegistrationMissing,
    AuthenticationConfigurationMissing,
    AuthenticationRejected,
    NetworkUnavailable,
    NetworkConfigurationInvalid,
    DnsUnavailable,
    TlsUnavailable,
    NetworkTimeout,
    StorageUnavailable,
    ShellConfigurationMissing,
    ShellExecutableUnavailable,
    BuiltInGitUnavailable,
    NativeGitUnavailable,
    ActivationPending,
    ResourceLimitReached,
}
dto!(DiagnosticLogEntry {
    sequence: DecimalU64,
    unix_time_ms: Option<DecimalU64>,
    severity: DiagnosticSeverity,
    component: DiagnosticComponent,
    code: DiagnosticCode
});
dto!(LocalDiagnosticLogsRead {
    after_sequence: Option<DecimalU64>,
    limit: u8
});
dto!(DiagnosticLogSnapshot {
    entries: BoundedList<DiagnosticLogEntry, 128>,
    next_cursor: DecimalU64,
    truncated: bool,
    available: bool
});
/// Closed diagnostics vocabulary: no arbitrary error text, env, paths, terminal
/// transcripts, account credentials or file payloads can enter this export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DoctorCheck {
    IpcVersion,
    ProfileOwner,
    Service,
    Autostart,
    Clock,
    Network,
    Dns,
    Tls,
    Proxy,
    Authorization,
    Storage,
    Shell,
    Git,
    RootPermissions,
    Limits,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DoctorHealth {
    Healthy,
    Unavailable,
    PermissionDenied,
    Incompatible,
    Unknown,
    ConfigurationInvalid,
    TransportUnavailable,
    AuthorizationRejected,
    DisabledByPolicy,
}
dto!(DoctorDiagnostic {
    check: DoctorCheck,
    health: DoctorHealth
});
dto!(LocalDoctorReport {
    checks: BoundedList<DoctorDiagnostic, 32>,
    last_error: Option<DiagnosticCode>,
    logs_available: bool
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "scope", rename_all = "camelCase", deny_unknown_fields)]
pub enum NativeIntentScope {
    Workspace {
        #[serde(rename = "workspaceId")]
        workspace_id: WorkspaceId,
    },
    Unscoped {},
}
dto!(NativeIntentRequest {
    intent_id: NativeIntentId,
    scope: NativeIntentScope
});
dto!(NativeBindJobRequest {
    intent_id: NativeIntentId,
    store_root: LocalRootPath,
    parent_operation_id: LocalNativeParentOperationId
});
dto!(NativeIntentTarget {
    intent_id: NativeIntentId
});
dto!(NativeLease {
    intent_id: NativeIntentId,
    fence: DecimalU64,
    expires_at_ms: DecimalU64,
    state: NativeWriterState
});

// Local owner-only file effects. Content is staged as bounded bytes in an
// owner-private file; editor and project-mutation effects validate UTF-8 while
// ArtifactCreate preserves raw bytes. Content never enters Remote RPC or the
// 1 MiB IPC frame.
auth_dto!(LocalNativeFileBlob {
    operation_id: NativeIntentId,
    byte_length: DecimalU64,
    content_sha256: HostKeyCommitmentHex
});
auth_dto!(LocalNativeFileStage {
    operation_id: NativeIntentId,
    path: LocalRootPath
});
auth_dto!(LocalNativeFileLocation {
    root: LocalRootPath,
    relative: LocalNativeRelativePath
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "effect", rename_all = "camelCase", deny_unknown_fields)]
pub enum LocalNativeEditorEffect {
    Save {
        root: LocalRootPath,
        relative: LocalNativeRelativePath,
        #[serde(rename = "expectedRevision")]
        expected_revision: HostKeyCommitmentHex,
    },
    SaveNew {
        #[serde(rename = "absolutePath")]
        absolute_path: LocalRootPath,
        #[serde(rename = "openFiles")]
        open_files: BoundedList<LocalNativeFileLocation, 256>,
    },
    SaveNewChecked {
        #[serde(rename = "absolutePath")]
        absolute_path: LocalRootPath,
        #[serde(rename = "openFiles")]
        open_files: BoundedList<LocalNativeFileLocation, 256>,
        #[serde(rename = "expectedRevision")]
        expected_revision: Option<HostKeyCommitmentHex>,
    },
    ProjectFiles {
        root: LocalRootPath,
    },
    DesktopFiles {
        root: LocalRootPath,
        #[serde(rename = "timeoutMs")]
        timeout_ms: TimeoutMs,
    },
    ArtifactCreate {
        root: LocalRootPath,
        relative: LocalNativeRelativePath,
        #[serde(rename = "expectedParentRevision")]
        expected_parent_revision: HostKeyCommitmentHex,
    },
}
auth_dto!(LocalNativeEditorExecute {
    blob: LocalNativeFileBlob,
    effect: LocalNativeEditorEffect
});
auth_dto!(LocalNativeEffectChallenge {
    operation_id: NativeIntentId,
    challenge: IpcNonce
});
auth_dto!(LocalNativeEffectDecision {
    operation_id: NativeIntentId,
    challenge: IpcNonce,
    allowed: bool
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalNativeEffectState {
    Running,
    Succeeded,
    Failed,
    OutcomeUnknown,
}
auth_dto!(LocalNativeEditorResult {
    operation_id: NativeIntentId,
    state: LocalNativeEffectState,
    result_json: Option<LocalNativeResultJson>
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum NativeEditorRetirement {
    Unresolved,
    Joined,
    NotStarted,
    Recovered,
}
dto!(NativeEditorDisposition {
    operation_id: NativeIntentId,
    state: LocalNativeEffectState,
    retirement: NativeEditorRetirement
});
auth_dto!(LocalNativeGitInput {
    workspace_id: WorkspaceId,
    root: LocalRootPath,
    control_roots: BoundedList<LocalRootPath, 8>,
    request_json: LocalNativeResultJson
});
auth_dto!(LocalNativeGitPrepare {
    operation_id: NativeIntentId,
    input: LocalNativeGitInput,
    timeout_ms: TimeoutMs
});
auth_dto!(LocalNativeGitExecute {
    operation_id: NativeIntentId,
    request_hash: HostKeyCommitmentHex,
    plan_hash: HostKeyCommitmentHex,
    timeout_ms: TimeoutMs
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalNativeGitState {
    Preparing,
    Prepared,
    Running,
    Succeeded,
    Failed,
    OutcomeUnknown,
}
auth_dto!(LocalNativeGitResult {
    operation_id: NativeIntentId,
    request_hash: HostKeyCommitmentHex,
    state: LocalNativeGitState,
    plan_hash: Option<HostKeyCommitmentHex>,
    preview_json: Option<LocalNativeResultJson>,
    result_json: Option<LocalNativeResultJson>,
    custody_settled: bool
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", content = "params", deny_unknown_fields)]
pub enum LocalCall {
    #[serde(rename = "native.files.stage")]
    NativeFileStage(LocalNativeFileBlob),
    #[serde(rename = "native.files.execute")]
    NativeEditorExecute(LocalNativeEditorExecute),
    #[serde(rename = "native.files.executeGuarded")]
    NativeEditorExecuteGuarded(LocalNativeEditorExecute),
    #[serde(rename = "native.effect.decision")]
    NativeEffectDecision(LocalNativeEffectDecision),
    #[serde(rename = "native.files.status")]
    NativeEditorStatus(NativeIntentTarget),
    #[serde(rename = "native.files.disposition")]
    NativeEditorDispositionRead(NativeIntentTarget),
    #[serde(rename = "native.files.acknowledge")]
    NativeEditorAcknowledge(NativeIntentTarget),
    #[serde(rename = "native.acknowledge")]
    NativeAcknowledge(NativeIntentTarget),
    #[serde(rename = "native.git.prepareGuarded")]
    NativeGitPrepareGuarded(LocalNativeGitPrepare),
    #[serde(rename = "native.git.executeGuarded")]
    NativeGitExecuteGuarded(LocalNativeGitExecute),
    #[serde(rename = "native.git.status")]
    NativeGitStatus(NativeIntentTarget),
    #[serde(rename = "native.git.cancelPrepared")]
    NativeGitCancelPrepared(NativeIntentTarget),
    #[serde(rename = "native.git.acknowledge")]
    NativeGitAcknowledge(NativeIntentTarget),
    #[serde(rename = "auth.configure")]
    AuthConfigure(LocalAuthConfigure),
    #[serde(rename = "login.start")]
    LoginStart(LocalLoginStart),
    #[serde(rename = "login.status")]
    LoginStatus {},
    #[serde(rename = "login.presentation")]
    LoginPresentation {},
    #[serde(rename = "logout")]
    Logout(LocalOperatorIntent),
    #[serde(rename = "daemon.stop")]
    DaemonStop(LocalOperatorIntent),
    #[serde(rename = "status")]
    Status {},
    #[serde(rename = "host.name.set")]
    HostNameSet(LocalHostNameSet),
    #[serde(rename = "maintenance.prepare")]
    MaintenancePrepare(LocalOperatorIntent),
    #[serde(rename = "setup.startMode.read")]
    SetupStartModeRead {},
    #[serde(rename = "setup.startMode.save")]
    SetupStartModeSave(LocalStartModePreference),
    #[serde(rename = "doctor")]
    Doctor {},
    #[serde(rename = "doctor.report")]
    DoctorReport {},
    #[serde(rename = "operator.snapshot")]
    OperatorSnapshot {},
    #[serde(rename = "diagnostics.logs")]
    DiagnosticLogs(LocalDiagnosticLogsRead),
    #[serde(rename = "workspaces")]
    Workspaces {},
    #[serde(rename = "workspace.inspect")]
    WorkspaceInspect(LocalWorkspaceRead),
    #[serde(rename = "workspace.details")]
    WorkspaceDetails(LocalWorkspaceRead),
    #[serde(rename = "workspace.removal.status")]
    WorkspaceRemovalStatus(LocalWorkspaceRead),
    #[serde(rename = "workspace.publication")]
    WorkspacePublication(LocalWorkspaceRead),
    #[serde(rename = "workspace.rename")]
    WorkspaceRename(LocalWorkspaceRename),
    #[serde(rename = "profiles")]
    Profiles {},
    #[serde(rename = "localWorkspaceAdd")]
    WorkspaceAdd(LocalWorkspaceAdd),
    #[serde(rename = "workspace.import")]
    WorkspaceImport(LocalWorkspaceImport),
    #[serde(rename = "workspace.bindings.read")]
    WorkspaceBindingsRead(WorkspaceBindingsRead),
    #[serde(rename = "shellProfile.register")]
    ShellProfileRegister(LocalShellProfileRegister),
    #[serde(rename = "localWorkspaceRemove")]
    WorkspaceRemove(LocalWorkspaceTarget),
    #[serde(rename = "share")]
    Share(LocalWorkspaceTarget),
    #[serde(rename = "share.authorized")]
    ShareAuthorized(LocalWorkspaceConsentAuthorized),
    #[serde(rename = "unshare.authorized")]
    UnshareAuthorized(LocalWorkspaceConsentAuthorized),
    #[serde(rename = "unshare")]
    Unshare(LocalWorkspaceTarget),
    #[serde(rename = "rpc")]
    Rpc(Box<RpcRequest>),
    #[serde(rename = "stream.ack")]
    StreamAck(#[serde(deserialize_with = "deserialize_map_only")] LocalStreamAck),
    #[serde(rename = "native.intent")]
    NativeIntent(NativeIntentRequest),
    #[serde(rename = "native.bindJob")]
    NativeBindJob(NativeBindJobRequest),
    #[serde(rename = "native.acquire")]
    NativeAcquire(NativeIntentTarget),
    #[serde(rename = "native.check")]
    NativeCheck(NativeIntentTarget),
    #[serde(rename = "native.renew")]
    NativeRenew(NativeIntentTarget),
    #[serde(rename = "native.requestFinish")]
    NativeRequestFinish(NativeIntentTarget),
    #[serde(rename = "native.reconcile")]
    NativeReconcile(NativeIntentTarget),
}
auth_dto!(LocalRequest {
    version: LocalIpcVersion,
    request_id: RequestId,
    #[serde(deserialize_with = "deserialize_map_only")]
    call: LocalCall
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum LocalResult {
    NativeFileStage(LocalNativeFileStage),
    NativeEditor(LocalNativeEditorResult),
    NativeEditorDisposition(NativeEditorDisposition),
    NativeGit(LocalNativeGitResult),
    NativeEffectChallenge(LocalNativeEffectChallenge),
    AuthConfigured {},
    LoginAccepted(LocalLoginAccepted),
    LoginStatus(LocalLoginStatus),
    LoginPresentation(LocalLoginPresentation),
    Stopping {},
    Status(LocalStatus),
    HostNameSet(LocalHostName),
    MaintenanceStatus(LocalMaintenanceStatus),
    SetupStartMode(LocalStartModePreference),
    Doctor(BoundedList<DoctorDiagnostic, 32>),
    DoctorReport(LocalDoctorReport),
    OperatorSnapshot(LocalOperatorSnapshot),
    DiagnosticLogs(DiagnosticLogSnapshot),
    WorkspaceDetails(LocalWorkspaceDetails),
    WorkspaceRemovalStatus(LocalWorkspaceRemovalStatus),
    WorkspacePublication(LocalWorkspacePublication),
    Workspaces(BoundedList<LocalWorkspaceSummary, 200>),
    Profiles(BoundedList<LocalProfileSummary, 200>),
    Workspace(LocalWorkspaceSummary),
    WorkspaceImported(LocalWorkspaceImportReceipt),
    WorkspaceBindings(WorkspaceBindingsSnapshot),
    ShellProfileRegistered {
        #[serde(rename = "profileId")]
        profile_id: crate::rpc::HostProfileId,
    },
    WorkspaceState(Box<WorkspaceState>),
    Removed(WorkspaceId),
    Rpc(Box<RpcResponse>),
    StreamAcknowledged(SubscriptionId),
    NativeLease(NativeLease),
    NativeIntent(NativeIntentId),
    NativeEditorAcknowledged(NativeIntentId),
    NativeAcknowledged(NativeIntentId),
}
auth_dto!(LocalResponse {
    version: LocalIpcVersion,
    request_id: RequestId,
    #[serde(deserialize_with = "deserialize_local_result")]
    result: Result<LocalResult, LocalError>
});
// Enforce map-only adjacent enums at the typed IPC envelope boundary while
// preserving the existing enum catalog and legitimate RPC list payloads.
struct MapOnly<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Object<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
            type Value = MapOnly<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an IPC object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(MapOnly)
            }
        }
        decoder.deserialize_map(Object(std::marker::PhantomData))
    }
}
fn deserialize_map_only<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<T, D::Error> {
    MapOnly::deserialize(decoder).map(|value| value.0)
}
fn deserialize_local_result<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Result<LocalResult, LocalError>, D::Error> {
    let value: MapOnly<Result<MapOnly<LocalResult>, LocalError>> = MapOnly::deserialize(decoder)?;
    Ok(value.0.map(|inner| inner.0))
}
/// Data-plane frames are distinguishable from the existing versioned response
/// envelope, allowing bounded client demultiplexing without changing replies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "stream",
    content = "frame",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum LocalStreamEvent {
    Terminal(TerminalStreamFrame),
    Workspace(WorkspaceStreamFrame),
    Files(FileWatchFrame),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "stream",
    content = "frame",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum LocalStreamAck {
    Workspace(WorkspaceStreamAck),
    Files(FileWatchAck),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalError {
    InvalidArgument,
    PermissionDenied,
    VersionMismatch,
    Conflict,
    /// The host atomically discarded a Registered native intent before any
    /// native writer lease could be activated.
    NativeBindRejected,
    Quarantine,
    Unavailable,
}

/// Check prefix before allocating payload. A zero or oversized frame is fatal;
/// transport must close on any framing/parse error and impose absolute deadlines.
pub fn local_frame_length(prefix: [u8; 4]) -> Result<usize, &'static str> {
    let size = u32::from_be_bytes(prefix) as usize;
    if size == 0 || size > LOCAL_IPC_FRAME_BYTES {
        Err("IPC_FRAME_LIMIT")
    } else {
        Ok(size)
    }
}
pub fn decode_local_frame<T: DeserializeOwned>(frame: &[u8]) -> Result<T, String> {
    let prefix: [u8; 4] = frame.get(..4).ok_or("IPC_TRUNCATED")?.try_into().unwrap();
    let length = local_frame_length(prefix)?;
    if frame.len() != length + 4 {
        return Err("IPC_FRAME_LENGTH".into());
    }
    serde_json::from_slice(&frame[4..]).map_err(|_| "IPC_INVALID_JSON".into())
}
pub fn read_local_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, String> {
    let mut prefix = [0; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| "IPC_TRUNCATED")?;
    let length = local_frame_length(prefix)?;
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .map_err(|_| "IPC_TRUNCATED")?;
    serde_json::from_slice(&payload).map_err(|_| "IPC_INVALID_JSON".into())
}
pub fn encode_local_frame(value: &impl Serialize) -> Result<Vec<u8>, String> {
    struct BoundedWriter(Vec<u8>);
    impl Write for BoundedWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if data.len() > LOCAL_IPC_FRAME_BYTES - self.0.len() {
                return Err(std::io::Error::other("IPC_FRAME_LIMIT"));
            }
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = BoundedWriter(Vec::new());
    serde_json::to_writer(&mut out, value).map_err(|_| "IPC_ENCODE_FAILED")?;
    let mut frame = Vec::with_capacity(out.0.len() + 4);
    frame.extend_from_slice(&(out.0.len() as u32).to_be_bytes());
    frame.extend_from_slice(&out.0);
    Ok(frame)
}
pub fn decode_local_request(frame: &[u8]) -> Result<LocalRequest, String> {
    let request: LocalRequest = decode_local_frame(frame)?;
    if let LocalCall::Rpc(rpc) = &request.call {
        rpc.call.validate()?;
    }
    Ok(request)
}
pub fn decode_local_response(frame: &[u8]) -> Result<LocalResponse, String> {
    let response: LocalResponse = decode_local_frame(frame)?;
    if let Ok(LocalResult::WorkspaceRemovalStatus(status)) = &response.result {
        status.validate()?;
    }
    if let Ok(LocalResult::WorkspaceState(state)) = &response.result {
        state.validate()?;
    }
    if let Ok(LocalResult::Rpc(rpc)) = &response.result {
        crate::decode_response(&serde_json::to_vec(rpc).map_err(|_| "IPC_INVALID_JSON")?)?;
    }
    Ok(response)
}

/// Validate the local frame and its inner checked stream semantics. Subscription
/// queues, authorization, deadlines and actual state installation remain callers' duties.
pub fn decode_local_stream_event(frame: &[u8]) -> Result<LocalStreamEvent, String> {
    let event: LocalStreamEvent = decode_local_frame(frame)?;
    match &event {
        LocalStreamEvent::Terminal(value) => {
            crate::decode_terminal_frame(
                &serde_json::to_vec(value).map_err(|_| "IPC_INVALID_JSON")?,
            )?;
        }
        LocalStreamEvent::Workspace(value) => {
            crate::decode_workspace_frame(
                &serde_json::to_vec(value).map_err(|_| "IPC_INVALID_JSON")?,
            )?;
        }
        LocalStreamEvent::Files(value) => {
            crate::decode_watch_frame(&serde_json::to_vec(value).map_err(|_| "IPC_INVALID_JSON")?)?;
        }
    }
    Ok(event)
}

/// Server-resolved physical project, shared Git common-dir and worktree keys.
/// No wire caller can select writer class or fabricate these identities. Empty
/// resolution is unscoped and must conflict with every writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalWriteScope(BTreeSet<String>);
impl PhysicalWriteScope {
    pub fn from_server_identities(identities: BTreeSet<String>) -> Self {
        Self(identities)
    }
    pub fn conflicts(&self, other: &Self) -> bool {
        self.0.is_empty() || other.0.is_empty() || !self.0.is_disjoint(&other.0)
    }
}
pub trait TrustedNativeIntentResolver {
    fn resolve(&self, scope: &NativeIntentScope) -> Result<PhysicalWriteScope, &'static str>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum NativeWriterState {
    Registered,
    Active,
    Quarantine,
    Finished,
}
/// Server callback must independently verify writer termination and reconcile
/// effects. Returning Unknown never releases safety. No request contains proof.
pub enum NativeCompletion {
    VerifiedStopped,
    Unknown,
}
pub trait TrustedNativeCompletionVerifier {
    fn verify_stopped(&mut self, intent_id: NativeIntentId) -> NativeCompletion;
}
#[derive(Debug)]
pub struct StoredNativeIntent {
    id: NativeIntentId,
    connection: IpcNonce,
    scope: PhysicalWriteScope,
    state: NativeWriterState,
    fence: u64,
    expires_at_ms: u64,
}
impl StoredNativeIntent {
    pub fn register(
        request: &NativeIntentRequest,
        connection: IpcNonce,
        _peer: &AuthenticatedLocalPeer,
        resolver: &impl TrustedNativeIntentResolver,
    ) -> Result<Self, &'static str> {
        let scope = match request.scope {
            NativeIntentScope::Unscoped {} => PhysicalWriteScope(BTreeSet::new()),
            _ => resolver.resolve(&request.scope)?,
        };
        Ok(Self {
            id: request.intent_id,
            connection,
            scope,
            state: NativeWriterState::Registered,
            fence: 0,
            expires_at_ms: 0,
        })
    }
    pub fn state(&self) -> NativeWriterState {
        self.state
    }
    pub fn blocks(&self, remote_scope: &PhysicalWriteScope) -> bool {
        matches!(
            self.state,
            NativeWriterState::Active | NativeWriterState::Quarantine
        ) && self.scope.conflicts(remote_scope)
    }
    /// Host coordinator must check all stored native and remote admissions in the
    /// same transaction before acquire; this guard does not implement that store.
    pub fn acquire(
        &mut self,
        connection: IpcNonce,
        now_ms: u64,
        expires_at_ms: u64,
        fence: u64,
    ) -> Result<NativeLease, &'static str> {
        if self.connection != connection
            || self.state != NativeWriterState::Registered
            || expires_at_ms <= now_ms
            || expires_at_ms - now_ms > NATIVE_LEASE_MAX_MS
            || fence <= self.fence
        {
            return Err("ADMISSION_DENIED");
        }
        self.fence = fence;
        self.expires_at_ms = expires_at_ms;
        self.state = NativeWriterState::Active;
        Ok(self.lease())
    }
    pub fn check(
        &mut self,
        connection: IpcNonce,
        now_ms: u64,
    ) -> Result<NativeLease, &'static str> {
        self.observe_expiry(now_ms);
        if connection != self.connection || self.state != NativeWriterState::Active {
            return Err("ADMISSION_DENIED");
        }
        Ok(self.lease())
    }
    pub fn renew(
        &mut self,
        connection: IpcNonce,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<NativeLease, &'static str> {
        self.check(connection, now_ms)?;
        if expires_at_ms <= now_ms
            || expires_at_ms - now_ms > NATIVE_LEASE_MAX_MS
            || expires_at_ms <= self.expires_at_ms
        {
            return Err("ADMISSION_DENIED");
        }
        self.expires_at_ms = expires_at_ms;
        Ok(self.lease())
    }
    pub fn observe_expiry(&mut self, now_ms: u64) {
        if self.state == NativeWriterState::Active && now_ms >= self.expires_at_ms {
            self.state = NativeWriterState::Quarantine;
        }
    }
    pub fn connection_lost(&mut self) {
        if self.state == NativeWriterState::Active {
            self.state = NativeWriterState::Quarantine;
        }
    }
    pub fn host_restarted(&mut self) {
        self.connection_lost();
    }
    pub fn request_finish(
        &mut self,
        verifier: &mut impl TrustedNativeCompletionVerifier,
    ) -> NativeWriterState {
        if matches!(
            self.state,
            NativeWriterState::Active | NativeWriterState::Quarantine
        ) {
            self.state = match verifier.verify_stopped(self.id) {
                NativeCompletion::VerifiedStopped => NativeWriterState::Finished,
                NativeCompletion::Unknown => NativeWriterState::Quarantine,
            };
        }
        self.state
    }
    fn lease(&self) -> NativeLease {
        NativeLease {
            intent_id: self.id,
            fence: DecimalU64(self.fence),
            expires_at_ms: DecimalU64(self.expires_at_ms),
            state: self.state,
        }
    }
}
