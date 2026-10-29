//! E0 foundation and draft scaffolding only: no signatures, admission, transport, or frozen OpenAPI.
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub mod admission;
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
mod browser_codec;
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
mod browser_framing;
mod errors;
pub mod http;
pub mod ipc;
mod json_wire;
mod limits;
pub mod message_framing;
mod operations;
mod primitives;
pub mod rpc;
pub mod streams;
pub use admission::*;
pub use errors::*;
pub use http::*;
pub use limits::*;
pub use operations::*;
pub use primitives::*;
pub use rpc::{
    RpcCall, RpcRequest, RpcResponse, RpcResult, decode_request, decode_response,
    decode_response_for,
};
pub use streams::{
    FileWatchFrame, TerminalStreamFrame, WorkspaceStreamFrame, decode_terminal_frame,
    decode_watch_frame, decode_workspace_frame,
};

macro_rules! fixed_version {
    ($name:ident, $value:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "u8", into = "u8")]
        pub struct $name;
        impl TryFrom<u8> for $name {
            type Error = &'static str;
            fn try_from(value: u8) -> Result<Self, Self::Error> {
                if value == $value { Ok(Self) } else { Err("UPDATE_REQUIRED") }
            }
        }
        impl From<$name> for u8 { fn from(_: $name) -> u8 { $value } }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> { stringify!($name).into() }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({"type": "integer", "const": $value})
            }
        }
    };
}
fixed_version!(RemoteApiMajor, 2);
fixed_version!(ApplicationMajor, 2);
fixed_version!(GrantContextVersion, 3);
fixed_version!(LocalIpcMajor, 1);

/// Canonical decimal string; numbers, leading zeroes, signs and overflow fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DecimalU64(pub u64);
impl TryFrom<String> for DecimalU64 {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty()
            || !s.bytes().all(|b| b.is_ascii_digit())
            || (s.len() > 1 && s.starts_with('0'))
        {
            return Err("expected canonical decimal u64 string");
        }
        s.parse::<u64>().map(Self).map_err(|_| "u64 overflow")
    }
}
impl From<DecimalU64> for String {
    fn from(n: DecimalU64) -> String {
        n.0.to_string()
    }
}
impl JsonSchema for DecimalU64 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DecimalU64".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        // Enumerate each prefix smaller than u64::MAX, plus the exact maximum.
        let maximum = u64::MAX.to_string();
        let mut alternatives = vec!["0".to_owned(), "[1-9][0-9]{0,18}".to_owned()];
        for (i, digit) in maximum.bytes().enumerate() {
            let low = if i == 0 { b'1' } else { b'0' };
            if digit > low {
                alternatives.push(format!(
                    "{}[{}-{}][0-9]{{{}}}",
                    &maximum[..i],
                    low as char,
                    (digit - 1) as char,
                    19 - i
                ));
            }
        }
        alternatives.push(maximum);
        let pattern = format!("^({})$", alternatives.join("|"));
        json_schema!({"type": "string", "pattern": pattern, "not": {"pattern": "[^0-9]"}, "maxLength": 20})
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Capability {
    #[serde(rename = "workspace.read")]
    WorkspaceRead,
    #[serde(rename = "terminal.observe")]
    TerminalObserve,
    #[serde(rename = "terminal.control")]
    TerminalControl,
    #[serde(rename = "terminal.manage")]
    TerminalManage,
    #[serde(rename = "files.read")]
    FilesRead,
    #[serde(rename = "files.write")]
    FilesWrite,
    #[serde(rename = "git.read")]
    GitRead,
    #[serde(rename = "git.write")]
    GitWrite,
    #[serde(rename = "git.network")]
    GitNetwork,
    #[serde(rename = "git.execute")]
    GitExecute,
}
impl Capability {
    pub const ALL: [Self; 10] = [
        Self::WorkspaceRead,
        Self::TerminalObserve,
        Self::TerminalControl,
        Self::TerminalManage,
        Self::FilesRead,
        Self::FilesWrite,
        Self::GitRead,
        Self::GitWrite,
        Self::GitNetwork,
        Self::GitExecute,
    ];
    pub fn dependencies(self) -> &'static [Self] {
        use Capability::*;
        match self {
            WorkspaceRead => &[],
            TerminalControl | TerminalManage => &[WorkspaceRead, TerminalObserve],
            FilesWrite => &[WorkspaceRead, FilesRead],
            GitWrite | GitNetwork | GitExecute => &[WorkspaceRead, GitRead],
            _ => &[WorkspaceRead],
        }
    }
    pub fn allows_shell_execution(self) -> bool {
        matches!(
            self,
            Self::TerminalControl | Self::TerminalManage | Self::GitExecute
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "Vec<Capability>", into = "Vec<Capability>")]
pub struct CapabilitySet(BTreeSet<Capability>);
impl TryFrom<Vec<Capability>> for CapabilitySet {
    type Error = &'static str;
    fn try_from(values: Vec<Capability>) -> Result<Self, Self::Error> {
        let set: BTreeSet<_> = values.iter().copied().collect();
        if set.len() != values.len() {
            return Err("duplicate capability");
        }
        if set
            .iter()
            .any(|c| c.dependencies().iter().any(|d| !set.contains(d)))
        {
            return Err("incomplete capability closure");
        }
        Ok(Self(set))
    }
}
impl From<CapabilitySet> for Vec<Capability> {
    fn from(set: CapabilitySet) -> Self {
        set.0.into_iter().collect()
    }
}
impl CapabilitySet {
    pub fn contains(&self, cap: Capability) -> bool {
        self.0.contains(&cap)
    }
    pub fn control_with_workspace_tools() -> Self {
        Self::try_from(
            Capability::ALL
                .into_iter()
                .filter(|c| *c != Capability::GitExecute)
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }
    /// Capability check only; caller must separately check freshness, membership,
    /// signatures, epochs and repository execution consent/binding.
    pub fn authorize(&self, method: &str, repository_execution: bool) -> Result<(), &'static str> {
        let required = required_capabilities(method).ok_or("UNSUPPORTED_CAPABILITY")?;
        if required.iter().any(|c| !self.contains(*c)) {
            return Err("SCOPE_DENIED");
        }
        if repository_execution {
            if !is_git_mutation(method) {
                return Err("INVALID_ARGUMENT");
            }
            if !self.contains(Capability::GitExecute) {
                return Err("REPOSITORY_EXECUTION_REQUIRED");
            }
        }
        Ok(())
    }
}
/// Rights source for a logical method; operation lookup never has static fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodRights {
    Static(&'static [Capability]),
    StoredOperationRights,
}
macro_rules! methods {
    ($($variant:ident => $wire:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        pub enum Method { $(#[serde(rename = $wire)] $variant),+ }
        pub const METHODS: &[&str] = &[$($wire),+];
        impl Method {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $wire),+ } }
            pub fn parse(name: &str) -> Option<Self> { match name { $($wire => Some(Self::$variant),)+ _ => None } }

        }
    }
}
methods! {
    WorkspaceGet => "workspace.get",
    WorkspaceCapabilities => "workspace.capabilities",
    WorkspaceSubscribe => "workspace.subscribe",
    TerminalCreate => "terminal.create",
    TerminalSplit => "terminal.split",
    TerminalRename => "terminal.rename",
    TerminalMove => "terminal.move",
    TerminalClose => "terminal.close",
    TerminalRestart => "terminal.restart",
    TerminalAttach => "terminal.attach",
    TerminalSnapshot => "terminal.snapshot",
    TerminalAck => "terminal.ack",
    TerminalClaim => "terminal.claim",
    TerminalRenew => "terminal.renew",
    TerminalRelease => "terminal.release",
    TerminalInput => "terminal.input",
    TerminalResize => "terminal.resize",
    FilesList => "files.list",
    FilesStat => "files.stat",
    FilesRead => "files.read",
    FilesSearchNames => "files.searchNames",
    FilesWatch => "files.watch",
    FilesCreate => "files.create",
    FilesMkdir => "files.mkdir",
    FilesRename => "files.rename",
    FilesRemove => "files.remove",
    GitRepositories => "git.repositories",
    GitStatus => "git.status",
    GitDiff => "git.diff",
    GitLog => "git.log",
    GitShow => "git.show",
    GitStage => "git.stage",
    GitUnstage => "git.unstage",
    GitCommit => "git.commit",
    GitFetch => "git.fetch",
    GitPush => "git.push",
    GitPull => "git.pull",
    OperationStatus => "operation.status",
    OperationCancel => "operation.cancel",
}

pub fn is_git_mutation(method: &str) -> bool {
    matches!(
        method,
        "git.stage" | "git.unstage" | "git.commit" | "git.fetch" | "git.push" | "git.pull"
    )
}
pub fn required_capabilities(method: &str) -> Option<&'static [Capability]> {
    match Method::parse(method)?.rights() {
        MethodRights::Static(rights) => Some(rights),
        MethodRights::StoredOperationRights => None,
    }
}
impl Method {
    pub fn rights(self) -> MethodRights {
        use Capability::*;
        MethodRights::Static(match self {
            Method::WorkspaceGet | Method::WorkspaceCapabilities | Method::WorkspaceSubscribe => {
                &[WorkspaceRead]
            }
            Method::TerminalCreate
            | Method::TerminalSplit
            | Method::TerminalRename
            | Method::TerminalMove
            | Method::TerminalClose
            | Method::TerminalRestart => &[WorkspaceRead, TerminalObserve, TerminalManage],
            Method::TerminalAttach | Method::TerminalSnapshot | Method::TerminalAck => {
                &[WorkspaceRead, TerminalObserve]
            }
            Method::TerminalClaim
            | Method::TerminalRenew
            | Method::TerminalRelease
            | Method::TerminalInput
            | Method::TerminalResize => &[WorkspaceRead, TerminalObserve, TerminalControl],
            Method::FilesList
            | Method::FilesStat
            | Method::FilesRead
            | Method::FilesSearchNames
            | Method::FilesWatch => &[WorkspaceRead, FilesRead],
            Method::FilesCreate
            | Method::FilesMkdir
            | Method::FilesRename
            | Method::FilesRemove => &[WorkspaceRead, FilesRead, FilesWrite],
            Method::GitRepositories
            | Method::GitStatus
            | Method::GitDiff
            | Method::GitLog
            | Method::GitShow => &[WorkspaceRead, GitRead],
            Method::GitStage | Method::GitUnstage | Method::GitCommit => {
                &[WorkspaceRead, GitRead, GitWrite]
            }
            Method::GitFetch | Method::GitPush => &[WorkspaceRead, GitRead, GitNetwork],
            Method::GitPull => &[WorkspaceRead, GitRead, GitWrite, GitNetwork],
            Method::OperationStatus | Method::OperationCancel => {
                return MethodRights::StoredOperationRights;
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalIpcVersion {
    pub major: LocalIpcMajor,
    pub minor: u16,
}
impl LocalIpcVersion {
    pub const CURRENT: Self = Self {
        major: LocalIpcMajor,
        minor: 0,
    };
    /// Both peers support major 1; agree on the smaller supported minor.
    pub fn negotiate(&self, peer: &Self) -> Self {
        Self {
            major: LocalIpcMajor,
            minor: self.minor.min(peer.minor),
        }
    }
    /// Validate untrusted version numbers before exchanging application data.
    pub fn negotiate_wire(&self, major: u8, minor: u16) -> Result<Self, &'static str> {
        Ok(self.negotiate(&Self {
            major: LocalIpcMajor::try_from(major)?,
            minor,
        }))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionAxes {
    pub remote_api_major: RemoteApiMajor,
    pub application_major: ApplicationMajor,
    pub grant_context_version: GrantContextVersion,
    pub local_ipc: LocalIpcVersion,
    pub terminal_profile: TerminalProfile,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TerminalProfile {
    #[serde(rename = "lomi-rust-grid-v1-experimental")]
    ExperimentalRustGridV1,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ChannelPurpose {
    Workspace,
    Terminal,
}
rpc::dto!(WorkspaceContext {
    workspace_id: WorkspaceId,
    workspace_epoch: WorkspaceEpoch,
    runtime_id: RuntimeId,
    runtime_generation: DecimalU64,
    host_access_epoch: DecimalU64,
    grant_revision: DecimalU64,
});
rpc::dto!(MutationContext {
    operation_id: OperationId,
    context: WorkspaceContext,
    expected_revision: DecimalU64,
});
rpc::dto!(TerminalContext {
    workspace: WorkspaceContext,
    pane_id: PaneId,
    session_id: TerminalSessionId,
    session_epoch: SessionEpoch,
    profile: TerminalProfile,
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileCreate {
    pub parent_entry_id: EntryId,
    pub parent_revision: FileRevision,
    pub name: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileRemove {
    pub entry_id: EntryId,
    pub file_revision: FileRevision,
    pub parent_revision: FileRevision,
    pub confirmed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalCreate {
    pub tab_name: String,
    pub profile_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", content = "params", deny_unknown_fields)]
pub enum DraftCommand {
    #[serde(rename = "files.create")]
    FileCreate(FileCreate),
    #[serde(rename = "files.remove")]
    FileRemove(FileRemove),
    #[serde(rename = "terminal.create")]
    TerminalCreate(TerminalCreate),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DraftContract {
    pub versions: VersionAxes,
    pub capabilities: CapabilitySet,
    pub purpose: ChannelPurpose,
    pub mutation: MutationContext,
    pub terminal: Option<TerminalContext>,
    pub command: DraftCommand,
}
