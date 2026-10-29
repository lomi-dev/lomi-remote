//! Application v2 DTOs for E2EE payloads only; never cloud inventory.
//! E0 choices: the typed `call` contains method/params; timeouts are 1..=120000 ms,
//! pages 1..=200, names 255 UTF-8 bytes, display text 4096 bytes. Host-selected
//! profile/remote/ref IDs are opaque tokens, never commands, executable paths or URLs.
//! File paths use opaque IDs and an encoded host path token, preserving non-UTF8 names.
//! Decode through the checked entrypoints. This validates shape/budgets, not host
//! membership, freshness, physical identity, admission, or atomic external effects.
use crate::streams::*;
use crate::*;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

/// Deserialize a value only after confirming its JSON representation is an object.
/// This keeps DTO and adjacent RPC enum decoding aligned with the object schemas.
pub(crate) fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object")
        }

        fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

macro_rules! text_type {
    ($name:ident, $max:literal, $token:literal) => {
        text_type!(@impl $name, $max, $token, [Debug]);
    };
    (@impl $name:ident, $max:literal, $token:literal, [$($debug:ident),*]) => {
        #[derive($($debug,)* Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from="String", into="String")]
        pub struct $name(String);
        impl $name { pub fn as_str(&self)->&str { &self.0 } }
        impl TryFrom<String> for $name {
            type Error=&'static str;
            fn try_from(s:String)->Result<Self,Self::Error> {
                if s.is_empty() || s.len()>$max || s.chars().any(|c| c=='\0' || (c.is_control() && c!='\n' && c!='\t')) || ($token && !s.bytes().all(|b| b.is_ascii_alphanumeric() || b==b'_' || b==b'-')) { return Err("invalid bounded text/token"); }
                Ok(Self(s))
            }
        }
        impl From<$name> for String { fn from(s:$name)->Self {s.0} }
        impl JsonSchema for $name {
            fn schema_name()->std::borrow::Cow<'static,str>{stringify!($name).into()}
            fn json_schema(_: &mut SchemaGenerator)->Schema {
                if $token {
                    json_schema!({"type":"string","minLength":1,"maxLength":$max,"pattern":"^[A-Za-z0-9_-]+$","not":{"pattern":"[^A-Za-z0-9_-]"},"x-lomi-maxUtf8Bytes":$max})
                } else {
                    json_schema!({"type":"string","minLength":1,"maxLength":$max,"not":{"pattern":r"[\u0000-\u0008\u000B-\u001F\u007F-\u009F]"},"x-lomi-maxUtf8Bytes":$max})
                }
            }
        }
    }
}
text_type!(DisplayText, 4096, false);
text_type!(CommitMessage, 16384, false);
text_type!(SearchText, 256, false);
text_type!(HostProfileId, 128, true);
text_type!(RemoteId, 128, true);
text_type!(RefId, 256, true);
text_type!(SubscriptionId, 128, true);
// A lease token is a bearer credential; derived Debug would expose it in
// every containing request/lease DTO's derived Debug output.
text_type!(@impl LeaseToken, 256, true, []);
impl std::fmt::Debug for LeaseToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LeaseToken([REDACTED])")
    }
}
text_type!(InputId, 128, true);
text_type!(EncodedPathId, 4096, true);
text_type!(ObjectId, 128, true);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EntryName(String);
impl EntryName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for EntryName {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty()
            || s.len() > 255
            || s == "."
            || s == ".."
            || s.chars().any(|c| c == '/' || c == '\\' || c.is_control())
        {
            Err("invalid single entry name")
        } else {
            Ok(Self(s))
        }
    }
}
impl From<EntryName> for String {
    fn from(s: EntryName) -> Self {
        s.0
    }
}
impl JsonSchema for EntryName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EntryName".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type":"string","minLength":1,"maxLength":255,"x-lomi-maxUtf8Bytes":255,"not":{"anyOf":[{"pattern":r"[/\\\u0000-\u001F\u007F-\u009F]"},{"enum":[".",".."]}]}})
    }
}

/// One diff line without its line terminator. Empty text represents a blank
/// context/added/removed line; horizontal tabs are preserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DiffLineText(String);
impl DiffLineText {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for DiffLineText {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.len() > 4096 || s.chars().any(|c| c.is_control() && c != '\t') {
            Err("invalid bounded diff line")
        } else {
            Ok(Self(s))
        }
    }
}
impl From<DiffLineText> for String {
    fn from(s: DiffLineText) -> Self {
        s.0
    }
}
impl JsonSchema for DiffLineText {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DiffLineText".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type":"string","maxLength":4096,"x-lomi-maxUtf8Bytes":4096,"not":{"pattern":r"[\u0000-\u0008\u000A-\u001F\u007F-\u009F]"}})
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct BoundedList<T, const N: usize>(#[schemars(length(max=N))] pub Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedList<T, N> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ListVisitor<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for ListVisitor<T, N> {
            type Value = BoundedList<T, N>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "array of at most {N} items")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element()? {
                    if values.len() == N {
                        return Err(serde::de::Error::custom("list exceeds bound"));
                    }
                    values.push(value);
                }
                Ok(BoundedList(values))
            }
        }
        d.deserialize_seq(ListVisitor::<T, N>(std::marker::PhantomData))
    }
}
macro_rules! bounded_number {
    ($name:ident,$min:literal,$max:literal)=>{
        #[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
        #[serde(try_from="u32",into="u32")]
        pub struct $name(pub u32);
        impl TryFrom<u32> for $name {type Error=&'static str;fn try_from(v:u32)->Result<Self,Self::Error>{if ($min..=$max).contains(&v){Ok(Self(v))}else{Err("number outside bound")}}}
        impl From<$name> for u32 {fn from(v:$name)->Self{v.0}}
        impl JsonSchema for $name {
            fn schema_name()->std::borrow::Cow<'static,str>{stringify!($name).into()}
            fn json_schema(_: &mut SchemaGenerator)->Schema{json_schema!({"type":"integer","minimum":$min,"maximum":$max})}
        }
    }
}

bounded_number!(PageLimit, 1, 200);
bounded_number!(PreviewLimit, 1, 1048576);
bounded_number!(TerminalDimension, 1, 1000);
bounded_number!(ChunkCount, 1, 1024);
bounded_number!(ChunkIndex, 0, 1023);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Confirmed {
    #[serde(rename = "confirmed")]
    Confirmed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DestinationState {
    #[serde(rename = "absent")]
    Absent,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PullMode {
    #[serde(rename = "ff-only")]
    FastForwardOnly,
}
macro_rules! dto {($name:ident { $($(#[$field_attr:meta])* $field:ident: $ty:ty),* $(,)? })=>{
    #[derive(Debug,Clone,PartialEq,Eq,Serialize,JsonSchema)]
    #[serde(rename_all="camelCase",deny_unknown_fields)]
    pub struct $name {$(pub $field:$ty),*}

    impl<'de> Deserialize<'de> for $name {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            #[derive(Deserialize)]
            #[serde(rename_all="camelCase",deny_unknown_fields)]
            struct Wire { $($(#[$field_attr])* $field:$ty),* }
            let Wire { $($field),* } = crate::rpc::deserialize_object(deserializer)?;
            Ok($name { $($field),* })
        }
    }
}}
pub(crate) use dto;
dto!(WorkspaceReadParams {
    context: WorkspaceContext
});
dto!(WorkspaceSubscribeParams {context:WorkspaceContext,cursor:Option<EventCursor>});
dto!(FileMutationContext {
    operation_id: OperationId,
    context: WorkspaceContext
});
dto!(GitMutationContext {
    operation_id: OperationId,
    context: WorkspaceContext
});
dto!(TerminalCreateParams {
    mutation: MutationContext,
    tab_name: DisplayText,
    profile_id: HostProfileId
});
dto!(TerminalSplitParams {
    mutation: MutationContext,
    tab_id: TabId,
    pane_id: PaneId,
    axis: SplitAxis,
    profile_id: HostProfileId
});
dto!(TerminalRenameParams {
    mutation: MutationContext,
    tab_id: TabId,
    name: DisplayText
});
dto!(TerminalMoveParams {
    mutation: MutationContext,
    pane_id: PaneId,
    source_tab_id: TabId,
    target_tab_id: TabId,
    target_pane_id: PaneId,
    placement: MovePlacement
});
// Descriptor CAS supports stopped/lost panes without inventing live session IDs.
// None requires the persistent descriptor to have no current session.
dto!(TerminalCloseParams {
    mutation: MutationContext,
    pane_id: PaneId,
    expected_session: Option<TerminalContext>
});
dto!(TerminalRestartParams {
    mutation: MutationContext,
    pane_id: PaneId,
    expected_session: Option<TerminalContext>,
    profile_id: HostProfileId
});
dto!(TerminalReadParams {
    terminal: TerminalContext
});
dto!(TerminalAckParams {
    terminal: TerminalContext,
    subscription_id: SubscriptionId,
    through_seq: TerminalSeq
});
dto!(TerminalClaimParams {
    terminal: TerminalContext,
    subscription_id: SubscriptionId,
    rendered_through_seq: TerminalSeq
});
dto!(LeaseBinding {
    token: LeaseToken,
    version: DecimalU64
});
dto!(TerminalLeaseParams {
    terminal: TerminalContext,
    lease: LeaseBinding
});
dto!(TerminalInputParams {terminal:TerminalContext,lease:LeaseBinding,input_id:DecimalU64,input_seq:InputSeq,bytes:BoundedList<u8,16384>});
dto!(TerminalResizeParams {
    terminal: TerminalContext,
    lease: LeaseBinding,
    resize_seq: ResizeSeq,
    columns: TerminalDimension,
    rows: TerminalDimension
});
dto!(FilesListParams {context:WorkspaceContext,parent_entry_id:EntryId,cursor:Option<EventCursor>,limit:PageLimit});
dto!(FilesStatParams {context:WorkspaceContext,entry_id:EntryId,file_revision:Option<FileRevision>});
dto!(FilesReadParams {context:WorkspaceContext,entry_id:EntryId,file_revision:Option<FileRevision>,offset:DecimalU64,max_bytes:PreviewLimit});
dto!(FilesSearchNamesParams {context:WorkspaceContext,parent_entry_id:EntryId,query:SearchText,cursor:Option<EventCursor>,limit:PageLimit});
dto!(FilesWatchParams {context:WorkspaceContext,entry_id:EntryId,cursor:Option<EventCursor>});
dto!(FilesCreateParams {
    mutation: FileMutationContext,
    parent_entry_id: EntryId,
    parent_revision: FileRevision,
    name: EntryName,
    destination: DestinationState
});
dto!(FilesRenameParams {
    mutation: FileMutationContext,
    entry_id: EntryId,
    file_revision: FileRevision,
    source_parent_id: EntryId,
    source_parent_revision: FileRevision,
    target_parent_id: EntryId,
    target_parent_revision: FileRevision,
    name: EntryName,
    destination: DestinationState
});
dto!(FilesRemoveParams {
    mutation: FileMutationContext,
    entry_id: EntryId,
    file_revision: FileRevision,
    parent_entry_id: EntryId,
    parent_revision: FileRevision,
    confirmation: Confirmed
});
dto!(GitRepositoryParams {
    context: WorkspaceContext,
    repository_id: RepositoryId
});
dto!(GitStatusParams {context:WorkspaceContext,repository_id:RepositoryId,state_token:Option<RepoStateToken>,cursor:Option<EventCursor>,limit:PageLimit});
dto!(GitDiffParams {context:WorkspaceContext,repository_id:RepositoryId,state_token:RepoStateToken,entry_id:Option<EntryId>,view:DiffView,cursor:Option<EventCursor>,limit:PageLimit});
dto!(GitLogParams {context:WorkspaceContext,repository_id:RepositoryId,state_token:RepoStateToken,cursor:Option<EventCursor>,limit:PageLimit});
dto!(GitShowParams {context:WorkspaceContext,repository_id:RepositoryId,state_token:RepoStateToken,object_id:ObjectId,cursor:Option<EventCursor>,limit:PageLimit});
dto!(GitPreconditions {
    head: RepoStateToken,
    index: RepoStateToken
});
dto!(GitStagePath {
    entry_id: EntryId,
    file_revision: FileRevision
});
dto!(GitStageParams {mutation:GitMutationContext,repository_id:RepositoryId,expected:GitPreconditions,paths:BoundedList<GitStagePath,200>});
dto!(GitUnstageParams {mutation:GitMutationContext,repository_id:RepositoryId,expected:GitPreconditions,paths:BoundedList<EntryId,200>});
dto!(GitCommitParams {
    mutation: GitMutationContext,
    repository_id: RepositoryId,
    expected: GitPreconditions,
    message: CommitMessage
});
dto!(GitNetworkParams {
    mutation: GitMutationContext,
    repository_id: RepositoryId,
    remote_id: RemoteId,
    ref_id: RefId,
    expected_refs: RepoStateToken
});
dto!(GitPullParams {
    mutation: GitMutationContext,
    repository_id: RepositoryId,
    remote_id: RemoteId,
    ref_id: RefId,
    expected_refs: RepoStateToken,
    expected: GitPreconditions,
    expected_worktree: RepoStateToken,
    mode: PullMode
});
dto!(WorkspaceState {context:WorkspaceContext,domain_revision:DecimalU64,name:DisplayText,tabs:BoundedList<TerminalTab,32>});
dto!(TerminalTab {
    tab_id: TabId,
    name: DisplayText,
    layout: TerminalLayout
});
/// The shared terminal projection contains no private desktop view descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum TerminalLayout {
    Pane {
        pane: TerminalPane,
    },
    Split {
        axis: SplitAxis,
        first: Box<TerminalLayout>,
        second: Box<TerminalLayout>,
    },
}
impl WorkspaceState {
    pub fn validate(&self) -> Result<(), &'static str> {
        let mut tabs = std::collections::BTreeSet::new();
        let mut panes = std::collections::BTreeSet::new();
        let mut sessions = std::collections::BTreeSet::new();
        for tab in &self.tabs.0 {
            if !tabs.insert(tab.tab_id) {
                return Err("duplicate tab identity");
            }
            let mut pending = vec![(&tab.layout, 0)];
            while let Some((node, depth)) = pending.pop() {
                if depth > 32 {
                    return Err("terminal layout exceeds depth bound");
                }
                match node {
                    TerminalLayout::Pane { pane } => {
                        if matches!(pane.state, PaneState::Stopped | PaneState::Lost)
                            && pane.session.is_some()
                        {
                            return Err("stopped/lost pane cannot claim a current session");
                        }
                        if !panes.insert(pane.pane_id) || panes.len() > 32 {
                            return Err("duplicate/excess terminal panes");
                        }
                        if pane.session.as_ref().is_some_and(|terminal| {
                            terminal.workspace != self.context
                                || terminal.pane_id != pane.pane_id
                                || !sessions.insert(terminal.session_id)
                        }) {
                            return Err("terminal layout session binding mismatch");
                        }
                    }
                    TerminalLayout::Split { first, second, .. } => {
                        pending.push((first, depth + 1));
                        pending.push((second, depth + 1));
                    }
                }
            }
        }
        Ok(())
    }
}

dto!(TerminalPane {pane_id:PaneId,session:Option<TerminalContext>,state:PaneState});
dto!(WorkspaceCapabilitiesResult {capabilities:CapabilitySet,profiles:BoundedList<HostProfile,32>});
dto!(HostProfile {
    profile_id: HostProfileId,
    name: DisplayText
});
dto!(TerminalLeaseResult {
    terminal: TerminalContext,
    lease: LeaseBinding,
    expires_in_ms: TimeoutMs,
    next_input_id: DecimalU64,
    next_input_seq: InputSeq,
    next_resize_seq: ResizeSeq
});
dto!(TerminalResizeResult {
    terminal: TerminalContext,
    resize_seq: ResizeSeq,
    columns: TerminalDimension,
    rows: TerminalDimension
});
dto!(TerminalAckResult {
    subscription_id: SubscriptionId,
    through_seq: TerminalSeq
});
dto!(TerminalReleaseResult {
    terminal: TerminalContext,
    released: bool
});
dto!(FileMetadata {
    entry_id: EntryId,
    path_id: EncodedPathId,
    display_name: DisplayText,
    kind: EntryKind,
    file_revision: FileRevision,
    size: DecimalU64
});
dto!(FilesListResult {entries:BoundedList<FileMetadata,200>,next_cursor:Option<EventCursor>,truncated:bool});
dto!(FilesReadResult {metadata:FileMetadata,encoding:FileEncoding,line_endings:LineEndings,offset:DecimalU64,bytes:BoundedList<u8,1048576>,truncated:bool});
dto!(FilesWatchResult {
    subscription_id: SubscriptionId,
    cursor: EventCursor,
    through_seq: WatchSeq
});
dto!(GitRepository {repository_id:RepositoryId,display_name:DisplayText,remotes:BoundedList<GitRemote,32>});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum GitRemoteSelectorKind {
    Head,
    Fetch,
    Push,
}

dto!(GitRemoteSelector {
    kind: GitRemoteSelectorKind,
    ref_id: RefId,
    display_name: DisplayText,
    fetch: bool,
    pull: bool,
    push: bool
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitRemote {
    pub remote_id: RemoteId,
    pub display_name: DisplayText,
    pub refs_state_token: RepoStateToken,
    pub refs: BoundedList<RefId, 200>,
    #[serde(
        default = "empty_git_remote_selectors",
        skip_serializing_if = "git_remote_selectors_empty"
    )]
    pub selectors: BoundedList<GitRemoteSelector, 200>,
}

fn empty_git_remote_selectors() -> BoundedList<GitRemoteSelector, 200> {
    BoundedList(Vec::new())
}

fn git_remote_selectors_empty(selectors: &BoundedList<GitRemoteSelector, 200>) -> bool {
    selectors.0.is_empty()
}

impl<'de> Deserialize<'de> for GitRemote {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            remote_id: RemoteId,
            display_name: DisplayText,
            refs_state_token: RepoStateToken,
            refs: BoundedList<RefId, 200>,
            #[serde(default = "empty_git_remote_selectors")]
            selectors: BoundedList<GitRemoteSelector, 200>,
        }

        let Wire {
            remote_id,
            display_name,
            refs_state_token,
            refs,
            selectors,
        } = deserialize_object(deserializer)?;
        if !selectors.0.is_empty() {
            let ref_ids = refs
                .0
                .iter()
                .map(RefId::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            let selector_ids = selectors
                .0
                .iter()
                .map(|selector| selector.ref_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if ref_ids.len() != refs.0.len()
                || selector_ids.len() != selectors.0.len()
                || ref_ids != selector_ids
            {
                return Err(serde::de::Error::custom(
                    "Git selector IDs must uniquely match the advertised refs",
                ));
            }
            if selectors.0.iter().any(|selector| match selector.kind {
                GitRemoteSelectorKind::Head => !selector.fetch || selector.pull || selector.push,
                GitRemoteSelectorKind::Fetch => !selector.fetch || selector.push,
                GitRemoteSelectorKind::Push => selector.fetch || selector.pull || !selector.push,
            }) {
                return Err(serde::de::Error::custom(
                    "Git selector capabilities do not match their kind",
                ));
            }
        }
        Ok(Self {
            remote_id,
            display_name,
            refs_state_token,
            refs,
            selectors,
        })
    }
}
dto!(GitRepositoriesResult {repositories:BoundedList<GitRepository,32>});
dto!(GitStatusEntry {
    entry_id: EntryId,
    path_id: EncodedPathId,
    display_name: DisplayText,
    index: GitChange,
    worktree: GitChange,
    file_revision: FileRevision
});
dto!(GitStatusResult {state_token:RepoStateToken,head:RepoStateToken,index:RepoStateToken,entries:BoundedList<GitStatusEntry,200>,next_cursor:Option<EventCursor>,truncated:bool});
dto!(GitDiffLine {
    kind: DiffLineKind,
    text: DiffLineText
});
dto!(GitDiffHunk {old_start:DecimalU64,new_start:DecimalU64,lines:BoundedList<GitDiffLine,200>});
dto!(GitDiffFile {entry_id:EntryId,display_name:DisplayText,binary:bool,hunks:BoundedList<GitDiffHunk,200>,truncated:bool});
dto!(GitDiffResult {state_token:RepoStateToken,files:BoundedList<GitDiffFile,200>,next_cursor:Option<EventCursor>,truncated:bool});
dto!(GitCommitSummary {
    object_id: ObjectId,
    subject: DisplayText,
    author: DisplayText,
    timestamp_seconds: DecimalU64
});
dto!(GitLogResult {state_token:RepoStateToken,commits:BoundedList<GitCommitSummary,200>,next_cursor:Option<EventCursor>,truncated:bool});
dto!(GitShowResult {
    commit: GitCommitSummary,
    diff: GitDiffResult
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SplitAxis {
    Horizontal,
    Vertical,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MovePlacement {
    Before,
    After,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum PaneState {
    Starting,
    Publishing,
    Running,
    Exited,
    Stopped,
    Lost,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DiffView {
    Index,
    Worktree,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Other,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum FileEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Binary,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LineEndings {
    Lf,
    CrLf,
    Cr,
    Mixed,
    None,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum GitChange {
    Unchanged,
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
    Unmerged,
    Untracked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DiffLineKind {
    Context,
    Added,
    Removed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", content = "params", deny_unknown_fields)]
pub enum RpcCall {
    #[serde(rename = "workspace.get")]
    WorkspaceGet(WorkspaceReadParams),
    #[serde(rename = "workspace.capabilities")]
    WorkspaceCapabilities(WorkspaceReadParams),
    #[serde(rename = "workspace.subscribe")]
    WorkspaceSubscribe(WorkspaceSubscribeParams),
    #[serde(rename = "terminal.create")]
    TerminalCreate(TerminalCreateParams),
    #[serde(rename = "terminal.split")]
    TerminalSplit(TerminalSplitParams),
    #[serde(rename = "terminal.rename")]
    TerminalRename(TerminalRenameParams),
    #[serde(rename = "terminal.move")]
    TerminalMove(TerminalMoveParams),
    #[serde(rename = "terminal.close")]
    TerminalClose(TerminalCloseParams),
    #[serde(rename = "terminal.restart")]
    TerminalRestart(TerminalRestartParams),
    #[serde(rename = "terminal.attach")]
    TerminalAttach(TerminalReadParams),
    #[serde(rename = "terminal.snapshot")]
    TerminalSnapshot(TerminalReadParams),
    #[serde(rename = "terminal.ack")]
    TerminalAck(TerminalAckParams),
    #[serde(rename = "terminal.claim")]
    TerminalClaim(TerminalClaimParams),
    #[serde(rename = "terminal.renew")]
    TerminalRenew(TerminalLeaseParams),
    #[serde(rename = "terminal.release")]
    TerminalRelease(TerminalLeaseParams),
    #[serde(rename = "terminal.input")]
    TerminalInput(TerminalInputParams),
    #[serde(rename = "terminal.resize")]
    TerminalResize(TerminalResizeParams),
    #[serde(rename = "files.list")]
    FilesList(FilesListParams),
    #[serde(rename = "files.stat")]
    FilesStat(FilesStatParams),
    #[serde(rename = "files.read")]
    FilesRead(FilesReadParams),
    #[serde(rename = "files.searchNames")]
    FilesSearchNames(FilesSearchNamesParams),
    #[serde(rename = "files.watch")]
    FilesWatch(FilesWatchParams),
    #[serde(rename = "files.create")]
    FilesCreate(FilesCreateParams),
    #[serde(rename = "files.mkdir")]
    FilesMkdir(FilesCreateParams),
    #[serde(rename = "files.rename")]
    FilesRename(FilesRenameParams),
    #[serde(rename = "files.remove")]
    FilesRemove(FilesRemoveParams),
    #[serde(rename = "git.repositories")]
    GitRepositories(WorkspaceReadParams),
    #[serde(rename = "git.status")]
    GitStatus(GitStatusParams),
    #[serde(rename = "git.diff")]
    GitDiff(GitDiffParams),
    #[serde(rename = "git.log")]
    GitLog(GitLogParams),
    #[serde(rename = "git.show")]
    GitShow(GitShowParams),
    #[serde(rename = "git.stage")]
    GitStage(GitStageParams),
    #[serde(rename = "git.unstage")]
    GitUnstage(GitUnstageParams),
    #[serde(rename = "git.commit")]
    GitCommit(GitCommitParams),
    #[serde(rename = "git.fetch")]
    GitFetch(GitNetworkParams),
    #[serde(rename = "git.push")]
    GitPush(GitNetworkParams),
    #[serde(rename = "git.pull")]
    GitPull(GitPullParams),
    #[serde(rename = "operation.status")]
    OperationStatus(OperationStatusParams),
    #[serde(rename = "operation.cancel")]
    OperationCancel(OperationCancelParams),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", content = "params", deny_unknown_fields)]
pub enum RpcResult {
    #[serde(rename = "workspace.get")]
    WorkspaceGet(WorkspaceState),
    #[serde(rename = "workspace.capabilities")]
    WorkspaceCapabilities(WorkspaceCapabilitiesResult),
    #[serde(rename = "workspace.subscribe")]
    WorkspaceSubscribe(WorkspaceSnapshotMetadata),
    #[serde(rename = "terminal.create")]
    TerminalCreate(OperationReceipt),
    #[serde(rename = "terminal.split")]
    TerminalSplit(OperationReceipt),
    #[serde(rename = "terminal.rename")]
    TerminalRename(OperationReceipt),
    #[serde(rename = "terminal.move")]
    TerminalMove(OperationReceipt),
    #[serde(rename = "terminal.close")]
    TerminalClose(OperationReceipt),
    #[serde(rename = "terminal.restart")]
    TerminalRestart(OperationReceipt),
    #[serde(rename = "terminal.attach")]
    TerminalAttach(TerminalSnapshotMetadata),
    #[serde(rename = "terminal.snapshot")]
    TerminalSnapshot(TerminalSnapshotMetadata),
    #[serde(rename = "terminal.ack")]
    TerminalAck(TerminalAckResult),
    #[serde(rename = "terminal.claim")]
    TerminalClaim(TerminalLeaseResult),
    #[serde(rename = "terminal.renew")]
    TerminalRenew(TerminalLeaseResult),
    #[serde(rename = "terminal.release")]
    TerminalRelease(TerminalReleaseResult),
    #[serde(rename = "terminal.input")]
    TerminalInput(InputReceipt),
    #[serde(rename = "terminal.resize")]
    TerminalResize(TerminalResizeResult),
    #[serde(rename = "files.list")]
    FilesList(FilesListResult),
    #[serde(rename = "files.stat")]
    FilesStat(FileMetadata),
    #[serde(rename = "files.read")]
    FilesRead(FilesReadResult),
    #[serde(rename = "files.searchNames")]
    FilesSearchNames(FilesListResult),
    #[serde(rename = "files.watch")]
    FilesWatch(FilesWatchResult),
    #[serde(rename = "files.create")]
    FilesCreate(OperationReceipt),
    #[serde(rename = "files.mkdir")]
    FilesMkdir(OperationReceipt),
    #[serde(rename = "files.rename")]
    FilesRename(OperationReceipt),
    #[serde(rename = "files.remove")]
    FilesRemove(OperationReceipt),
    #[serde(rename = "git.repositories")]
    GitRepositories(GitRepositoriesResult),
    #[serde(rename = "git.status")]
    GitStatus(GitStatusResult),
    #[serde(rename = "git.diff")]
    GitDiff(GitDiffResult),
    #[serde(rename = "git.log")]
    GitLog(GitLogResult),
    #[serde(rename = "git.show")]
    GitShow(GitShowResult),
    #[serde(rename = "git.stage")]
    GitStage(OperationReceipt),
    #[serde(rename = "git.unstage")]
    GitUnstage(OperationReceipt),
    #[serde(rename = "git.commit")]
    GitCommit(OperationReceipt),
    #[serde(rename = "git.fetch")]
    GitFetch(OperationReceipt),
    #[serde(rename = "git.push")]
    GitPush(OperationReceipt),
    #[serde(rename = "git.pull")]
    GitPull(OperationReceipt),
    #[serde(rename = "operation.status")]
    OperationStatus(OperationReceipt),
    #[serde(rename = "operation.cancel")]
    OperationCancel(OperationReceipt),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum RequestKind {
    #[serde(rename = "request")]
    Request,
}
dto!(RpcRequest {
    v: ApplicationMajor,
    r#type: RequestKind,
    request_id: RequestId,
    timeout_ms: TimeoutMs,
    #[serde(deserialize_with = "crate::rpc::deserialize_object")]
    call: RpcCall
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum RpcResponse {
    Result {
        v: ApplicationMajor,
        #[serde(rename = "requestId")]
        request_id: RequestId,
        result: RpcResult,
    },
    Error {
        v: ApplicationMajor,
        #[serde(rename = "requestId")]
        request_id: RequestId,
        #[serde(rename = "operationId")]
        operation_id: Option<OperationId>,
        error: RemoteError,
    },
}
impl RpcCall {
    pub fn method(&self) -> Method {
        match self {
            Self::WorkspaceGet(_) => Method::WorkspaceGet,
            Self::WorkspaceCapabilities(_) => Method::WorkspaceCapabilities,
            Self::WorkspaceSubscribe(_) => Method::WorkspaceSubscribe,
            Self::TerminalCreate(_) => Method::TerminalCreate,
            Self::TerminalSplit(_) => Method::TerminalSplit,
            Self::TerminalRename(_) => Method::TerminalRename,
            Self::TerminalMove(_) => Method::TerminalMove,
            Self::TerminalClose(_) => Method::TerminalClose,
            Self::TerminalRestart(_) => Method::TerminalRestart,
            Self::TerminalAttach(_) => Method::TerminalAttach,
            Self::TerminalSnapshot(_) => Method::TerminalSnapshot,
            Self::TerminalAck(_) => Method::TerminalAck,
            Self::TerminalClaim(_) => Method::TerminalClaim,
            Self::TerminalRenew(_) => Method::TerminalRenew,
            Self::TerminalRelease(_) => Method::TerminalRelease,
            Self::TerminalInput(_) => Method::TerminalInput,
            Self::TerminalResize(_) => Method::TerminalResize,
            Self::FilesList(_) => Method::FilesList,
            Self::FilesStat(_) => Method::FilesStat,
            Self::FilesRead(_) => Method::FilesRead,
            Self::FilesSearchNames(_) => Method::FilesSearchNames,
            Self::FilesWatch(_) => Method::FilesWatch,
            Self::FilesCreate(_) => Method::FilesCreate,
            Self::FilesMkdir(_) => Method::FilesMkdir,
            Self::FilesRename(_) => Method::FilesRename,
            Self::FilesRemove(_) => Method::FilesRemove,
            Self::GitRepositories(_) => Method::GitRepositories,
            Self::GitStatus(_) => Method::GitStatus,
            Self::GitDiff(_) => Method::GitDiff,
            Self::GitLog(_) => Method::GitLog,
            Self::GitShow(_) => Method::GitShow,
            Self::GitStage(_) => Method::GitStage,
            Self::GitUnstage(_) => Method::GitUnstage,
            Self::GitCommit(_) => Method::GitCommit,
            Self::GitFetch(_) => Method::GitFetch,
            Self::GitPush(_) => Method::GitPush,
            Self::GitPull(_) => Method::GitPull,
            Self::OperationStatus(_) => Method::OperationStatus,
            Self::OperationCancel(_) => Method::OperationCancel,
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::TerminalClose(p)
                if p.expected_session.as_ref().is_some_and(|session| {
                    session.workspace != p.mutation.context || session.pane_id != p.pane_id
                }) =>
            {
                return Err("terminal workspace mismatch");
            }
            Self::TerminalRestart(p)
                if p.expected_session.as_ref().is_some_and(|session| {
                    session.workspace != p.mutation.context || session.pane_id != p.pane_id
                }) =>
            {
                return Err("terminal workspace mismatch");
            }
            Self::TerminalInput(p) if p.bytes.0.is_empty() => return Err("empty input"),
            Self::GitStage(p) if p.paths.0.is_empty() => return Err("empty stage paths"),
            Self::GitUnstage(p) if p.paths.0.is_empty() => return Err("empty unstage paths"),
            _ => {}
        }
        Ok(())
    }
}
pub fn decode_request(bytes: &[u8]) -> Result<RpcRequest, String> {
    crate::json_wire::check_raw_bytes(bytes).map_err(str::to_owned)?;
    let request: RpcRequest = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    request.call.validate().map_err(str::to_owned)?;
    Ok(request)
}
pub fn decode_response(bytes: &[u8]) -> Result<RpcResponse, String> {
    if bytes.len() > CONTROL_MESSAGE_BYTES as usize {
        return Err("response exceeds 1 MiB control message budget".into());
    }
    let response: RpcResponse = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if let RpcResponse::Result {
        result: RpcResult::WorkspaceGet(state),
        ..
    } = &response
    {
        state.validate().map_err(str::to_owned)?;
    }
    if let RpcResponse::Error {
        operation_id,
        error,
        ..
    } = &response
    {
        // Effects requiring status must always carry their durable operation identity.
        if !matches!(error.effect(), Effect::None)
            && operation_id.is_none()
            && !(error.code() == ErrorCode::OutcomeUnknown
                && error.effect() == Effect::Unknown
                && error.operation().is_none())
        {
            return Err("effect requires operationId".into());
        }
    }
    Ok(response)
}

impl RpcResult {
    pub fn method(&self) -> Method {
        match self {
            Self::WorkspaceGet(_) => Method::WorkspaceGet,
            Self::WorkspaceCapabilities(_) => Method::WorkspaceCapabilities,
            Self::WorkspaceSubscribe(_) => Method::WorkspaceSubscribe,
            Self::TerminalCreate(_) => Method::TerminalCreate,
            Self::TerminalSplit(_) => Method::TerminalSplit,
            Self::TerminalRename(_) => Method::TerminalRename,
            Self::TerminalMove(_) => Method::TerminalMove,
            Self::TerminalClose(_) => Method::TerminalClose,
            Self::TerminalRestart(_) => Method::TerminalRestart,
            Self::TerminalAttach(_) => Method::TerminalAttach,
            Self::TerminalSnapshot(_) => Method::TerminalSnapshot,
            Self::TerminalAck(_) => Method::TerminalAck,
            Self::TerminalClaim(_) => Method::TerminalClaim,
            Self::TerminalRenew(_) => Method::TerminalRenew,
            Self::TerminalRelease(_) => Method::TerminalRelease,
            Self::TerminalInput(_) => Method::TerminalInput,
            Self::TerminalResize(_) => Method::TerminalResize,
            Self::FilesList(_) => Method::FilesList,
            Self::FilesStat(_) => Method::FilesStat,
            Self::FilesRead(_) => Method::FilesRead,
            Self::FilesSearchNames(_) => Method::FilesSearchNames,
            Self::FilesWatch(_) => Method::FilesWatch,
            Self::FilesCreate(_) => Method::FilesCreate,
            Self::FilesMkdir(_) => Method::FilesMkdir,
            Self::FilesRename(_) => Method::FilesRename,
            Self::FilesRemove(_) => Method::FilesRemove,
            Self::GitRepositories(_) => Method::GitRepositories,
            Self::GitStatus(_) => Method::GitStatus,
            Self::GitDiff(_) => Method::GitDiff,
            Self::GitLog(_) => Method::GitLog,
            Self::GitShow(_) => Method::GitShow,
            Self::GitStage(_) => Method::GitStage,
            Self::GitUnstage(_) => Method::GitUnstage,
            Self::GitCommit(_) => Method::GitCommit,
            Self::GitFetch(_) => Method::GitFetch,
            Self::GitPush(_) => Method::GitPush,
            Self::GitPull(_) => Method::GitPull,
            Self::OperationStatus(_) => Method::OperationStatus,
            Self::OperationCancel(_) => Method::OperationCancel,
        }
    }
    pub fn receipt(&self) -> Option<&OperationReceipt> {
        match self {
            Self::TerminalCreate(receipt) => Some(receipt),
            Self::TerminalSplit(receipt) => Some(receipt),
            Self::TerminalRename(receipt) => Some(receipt),
            Self::TerminalMove(receipt) => Some(receipt),
            Self::TerminalClose(receipt) => Some(receipt),
            Self::TerminalRestart(receipt) => Some(receipt),
            Self::FilesCreate(receipt) => Some(receipt),
            Self::FilesMkdir(receipt) => Some(receipt),
            Self::FilesRename(receipt) => Some(receipt),
            Self::FilesRemove(receipt) => Some(receipt),
            Self::GitStage(receipt) => Some(receipt),
            Self::GitUnstage(receipt) => Some(receipt),
            Self::GitCommit(receipt) => Some(receipt),
            Self::GitFetch(receipt) => Some(receipt),
            Self::GitPush(receipt) => Some(receipt),
            Self::GitPull(receipt) => Some(receipt),
            Self::OperationStatus(receipt) => Some(receipt),
            Self::OperationCancel(receipt) => Some(receipt),
            _ => None,
        }
    }
}
impl RpcCall {
    pub fn operation_binding(&self) -> Option<OperationLookup> {
        match self {
            Self::TerminalCreate(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::TerminalSplit(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::TerminalRename(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::TerminalMove(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::TerminalClose(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::TerminalRestart(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::FilesCreate(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::FilesMkdir(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::FilesRename(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::FilesRemove(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::GitStage(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::GitUnstage(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::GitCommit(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::GitFetch(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::GitPush(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::GitPull(p) => Some(OperationLookup {
                workspace_id: p.mutation.context.workspace_id,
                operation_id: p.mutation.operation_id,
            }),
            Self::OperationStatus(p) => Some(OperationLookup {
                workspace_id: p.context.workspace_id,
                operation_id: p.operation_id,
            }),
            Self::OperationCancel(p) => Some(OperationLookup {
                workspace_id: p.context.workspace_id,
                operation_id: p.operation_id,
            }),
            _ => None,
        }
    }
}

/// Correlate an untrusted response with the original request before dispatch/apply.
/// The context-free decoder accepts wire shape without method-specific context.
pub fn decode_response_for(bytes: &[u8], request: &RpcRequest) -> Result<RpcResponse, String> {
    let response = decode_response(bytes)?;
    response.validate_for(request).map_err(str::to_owned)?;
    Ok(response)
}
impl RpcResponse {
    pub fn validate_for(&self, request: &RpcRequest) -> Result<(), &'static str> {
        match self {
            Self::Error {
                request_id,
                operation_id,
                error,
                ..
            } => {
                if request_id != &request.request_id {
                    return Err("requestId mismatch");
                }
                error.validate_for_method(request.call.method())?;
                let binding = request.call.operation_binding();
                if operation_id.is_some()
                    && operation_id.as_ref() != binding.as_ref().map(|b| &b.operation_id)
                {
                    return Err("error operation binding mismatch");
                }
                if error
                    .operation()
                    .is_some_and(|lookup| Some(lookup) != binding.as_ref())
                {
                    return Err("error status lookup mismatch");
                }
            }
            Self::Result {
                request_id, result, ..
            } => {
                if request_id != &request.request_id || result.method() != request.call.method() {
                    return Err("result request/method mismatch");
                }
                if let Some(receipt) = result.receipt() {
                    let binding = request
                        .call
                        .operation_binding()
                        .ok_or("unexpected receipt")?;
                    if receipt.operation_id() != binding.operation_id
                        || receipt.stored_rights().workspace() != binding.workspace_id
                    {
                        return Err("receipt operation/workspace mismatch");
                    }
                    if is_durable_mutation(request.call.method())
                        && receipt.stored_rights().original_method() != request.call.method()
                    {
                        return Err("receipt original method mismatch");
                    }
                }
                match (&request.call, result) {
                    (RpcCall::WorkspaceGet(p), RpcResult::WorkspaceGet(r))
                        if p.context != r.context =>
                    {
                        return Err("workspace result context mismatch");
                    }
                    (RpcCall::WorkspaceSubscribe(p), RpcResult::WorkspaceSubscribe(r)) => {
                        if p.context != r.context {
                            return Err("snapshot context mismatch");
                        }
                        crate::streams::validate_snapshot_budget(r.chunk_count, r.total_bytes)?;
                    }
                    (RpcCall::TerminalAttach(p), RpcResult::TerminalAttach(r))
                    | (RpcCall::TerminalSnapshot(p), RpcResult::TerminalSnapshot(r)) => {
                        if p.terminal != r.terminal {
                            return Err("terminal snapshot binding mismatch");
                        }
                        crate::streams::validate_snapshot_budget(r.chunk_count, r.total_bytes)?;
                    }
                    (RpcCall::TerminalInput(p), RpcResult::TerminalInput(r)) => r
                        .validate_binding(
                            p.terminal.session_id,
                            p.terminal.session_epoch,
                            p.input_id,
                            p.input_seq.0,
                            InputBytes::new(p.bytes.0.len() as u64)?,
                        )?,
                    (RpcCall::TerminalResize(p), RpcResult::TerminalResize(r))
                        if p.terminal != r.terminal
                            || p.resize_seq != r.resize_seq
                            || p.columns != r.columns
                            || p.rows != r.rows =>
                    {
                        return Err("resize result mismatch");
                    }
                    (RpcCall::TerminalClaim(p), RpcResult::TerminalClaim(r))
                        if p.terminal != r.terminal =>
                    {
                        return Err("lease terminal mismatch");
                    }
                    (RpcCall::TerminalRenew(p), RpcResult::TerminalRenew(r))
                        if p.terminal != r.terminal =>
                    {
                        return Err("lease terminal mismatch");
                    }
                    (RpcCall::TerminalRelease(p), RpcResult::TerminalRelease(r))
                        if p.terminal != r.terminal =>
                    {
                        return Err("release terminal mismatch");
                    }
                    (RpcCall::TerminalAck(p), RpcResult::TerminalAck(r))
                        if p.subscription_id != r.subscription_id
                            || p.through_seq != r.through_seq =>
                    {
                        return Err("ack result mismatch");
                    }
                    (RpcCall::FilesRead(p), RpcResult::FilesRead(r)) => {
                        if p.entry_id != r.metadata.entry_id
                            || p.offset != r.offset
                            || r.bytes.0.len() > p.max_bytes.0 as usize
                            || p.file_revision
                                .as_ref()
                                .is_some_and(|v| v != &r.metadata.file_revision)
                        {
                            return Err("file preview binding/budget mismatch");
                        }
                        if matches!(r.encoding, FileEncoding::Binary | FileEncoding::Unknown)
                            && !r.bytes.0.is_empty()
                        {
                            return Err("binary/unknown preview must contain metadata only");
                        }
                    }
                    (RpcCall::FilesStat(p), RpcResult::FilesStat(r))
                        if p.entry_id != r.entry_id
                            || p.file_revision
                                .as_ref()
                                .is_some_and(|v| v != &r.file_revision) =>
                    {
                        return Err("file metadata binding mismatch");
                    }
                    (RpcCall::FilesList(p), RpcResult::FilesList(r))
                        if r.entries.0.len() > p.limit.0 as usize =>
                    {
                        return Err("list exceeds requested page");
                    }
                    (RpcCall::FilesSearchNames(p), RpcResult::FilesSearchNames(r))
                        if r.entries.0.len() > p.limit.0 as usize =>
                    {
                        return Err("search exceeds requested page");
                    }
                    (RpcCall::GitStatus(p), RpcResult::GitStatus(r))
                        if p.state_token.as_ref().is_some_and(|v| v != &r.state_token)
                            || r.entries.0.len() > p.limit.0 as usize =>
                    {
                        return Err("git status state/page mismatch");
                    }
                    (RpcCall::GitDiff(p), RpcResult::GitDiff(r))
                        if p.state_token != r.state_token
                            || r.files.0.len() > p.limit.0 as usize =>
                    {
                        return Err("git diff state/page mismatch");
                    }
                    (RpcCall::GitLog(p), RpcResult::GitLog(r))
                        if p.state_token != r.state_token
                            || r.commits.0.len() > p.limit.0 as usize =>
                    {
                        return Err("git log state/page mismatch");
                    }
                    (RpcCall::GitShow(p), RpcResult::GitShow(r))
                        if p.object_id != r.commit.object_id
                            || p.state_token != r.diff.state_token
                            || r.diff.files.0.len() > p.limit.0 as usize =>
                    {
                        return Err("git show state/object/page mismatch");
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}
