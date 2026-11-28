//! One authorization check for every tunnel request and stream (P3a.8). Pure and
//! not wired in yet (P3a.9); `GateCore::request_allowed` still guards the old path.
//! Order: grant validity, workspace sharing, workspace ceiling, device control
//! level, local consent. Unknown and unshared workspaces are indistinguishable.
#![allow(dead_code)]
use lomi_host_store::{DeviceGrant, ProjectRecord};
use lomi_remote_crypto::Permissions;
use lomi_remote_protocol::{
    Capability, CapabilitySet, ChatPermissions, ErrorCode, Method, MethodRights, RpcCall,
    WorkspaceId, tunnel::OpenParams,
};
use std::collections::BTreeMap;

/// What a device may do: its grant plus the ceiling of every shared workspace.
pub(super) struct DeviceAccess {
    grant: DeviceGrant,
    /// Shared workspaces only; the chat level is already part of the capabilities.
    sharing: BTreeMap<WorkspaceId, CapabilitySet>,
}

impl DeviceAccess {
    pub(super) fn new(grant: DeviceGrant, sharing: BTreeMap<WorkspaceId, CapabilitySet>) -> Self {
        Self { grant, sharing }
    }
    /// Ceilings as the Host publishes them: consented projects, chat level included.
    pub(super) fn from_projects(grant: DeviceGrant, projects: &[ProjectRecord]) -> Self {
        let sharing = projects
            .iter()
            .filter(|p| p.consent)
            .map(|p| {
                let ceiling = p
                    .chat_level
                    .ceiling()
                    .unwrap_or_else(CapabilitySet::control_with_workspace_tools);
                (p.state.context.workspace_id, ceiling)
            })
            .collect();
        Self::new(grant, sharing)
    }
    /// What this device may do in `workspace`: the ceiling, without the control-only
    /// capabilities until the grant controls (the set stays dependency-closed).
    pub(super) fn capabilities(&self, workspace: &WorkspaceId) -> Option<CapabilitySet> {
        let ceiling = self.sharing.get(workspace)?;
        if self.controls() {
            return Some(ceiling.clone());
        }
        const CONTROL_ONLY: [Capability; 8] = [
            Capability::TerminalControl,
            Capability::TerminalManage,
            Capability::FilesWrite,
            Capability::GitWrite,
            Capability::GitNetwork,
            Capability::ChatSend,
            Capability::ChatPermissionsEdit,
            Capability::ChatPermissionsFull,
        ];
        let kept: Vec<Capability> = Capability::ALL
            .into_iter()
            .filter(|c| ceiling.contains(*c) && !CONTROL_ONLY.contains(c))
            .collect();
        CapabilitySet::try_from(kept).ok()
    }
    /// Control needs both the account ceiling and the code confirmation on this Host.
    fn controls(&self) -> bool {
        self.grant.ceiling == Permissions::Control && self.grant.control_confirmed_at.is_some()
    }
}

pub(super) struct Target<'a> {
    /// `None`: device-scoped (directory, transfer); only the grant is checked.
    workspace: Option<&'a WorkspaceId>,
    method: Option<Method>,
    chat_mode: Option<ChatPermissions>,
    repository_execution: bool,
}

impl<'a> Target<'a> {
    /// `workspace` is the request envelope's workspace. A call that carries its own
    /// workspace context for another workspace is denied as unshared. Chat calls carry none.
    pub(super) fn rpc(workspace: &'a WorkspaceId, call: &RpcCall) -> Result<Self, Denied> {
        if call_workspace(call).is_some_and(|w| w != workspace) {
            return Err(Denied::WorkspaceUnshared);
        }
        Ok(Self {
            workspace: Some(workspace),
            method: Some(call.method()),
            chat_mode: match call {
                RpcCall::ChatThreadCreate(p) => Some(p.permissions),
                _ => None,
            },
            repository_execution: false,
        })
    }
    /// A control message inside an open stream, e.g. `terminal.input`.
    pub(super) fn message(workspace: &'a WorkspaceId, method: Method) -> Self {
        Self {
            workspace: Some(workspace),
            method: Some(method),
            chat_mode: None,
            repository_execution: false,
        }
    }
    pub(super) fn open(params: &'a OpenParams) -> Self {
        let (workspace, method) = match params {
            OpenParams::Terminal(p) => (&p.workspace_id, Method::TerminalAttach),
            OpenParams::Chat(p) => (&p.workspace_id, Method::ChatSubscribe),
            OpenParams::FilesWatch(p) => (&p.workspace_id, Method::FilesWatch),
            // The directory lists only what the device may see; a transfer follows an
            // already authorized request.
            OpenParams::Directory | OpenParams::Transfer(_) => {
                return Self {
                    workspace: None,
                    method: None,
                    chat_mode: None,
                    repository_execution: false,
                };
            }
        };
        Self::message(workspace, method)
    }
    /// The caller knows what the operation will execute (hooks) or the thread's mode.
    pub(super) fn with_repository_execution(mut self) -> Self {
        self.repository_execution = true;
        self
    }
    pub(super) fn with_chat_mode(mut self, mode: ChatPermissions) -> Self {
        self.chat_mode = Some(mode);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Granted;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Consent {
    GitExecute,
    ChatMode(ChatPermissions),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Denied {
    /// Grant revoked, expired or not confirmed by the server recently enough.
    Revoked,
    WorkspaceUnshared,
    Scope,
    /// The device is read-only until the code is confirmed (P3a.10 asks for it).
    ControlNotConfirmed,
    NeedsLocalConsent(Consent),
}

impl Denied {
    pub(super) fn code(self) -> ErrorCode {
        match self {
            Self::Revoked => ErrorCode::AuthRequired,
            Self::WorkspaceUnshared => ErrorCode::WorkspaceUnshared,
            Self::NeedsLocalConsent(Consent::GitExecute) => ErrorCode::RepositoryExecutionRequired,
            Self::Scope | Self::ControlNotConfirmed | Self::NeedsLocalConsent(_) => {
                ErrorCode::ScopeDenied
            }
        }
    }
}

pub(super) fn authorize(
    device: &DeviceAccess,
    target: &Target<'_>,
    now: u64,
) -> Result<Granted, Denied> {
    if !device.grant.is_valid(now) {
        return Err(Denied::Revoked);
    }
    let (Some(workspace), Some(method)) = (target.workspace, target.method) else {
        return Ok(Granted);
    };
    let ceiling = device
        .sharing
        .get(workspace)
        .ok_or(Denied::WorkspaceUnshared)?;
    // Stored-operation methods have no static rights; like today they are never allowed here.
    let MethodRights::Static(rights) = method.rights() else {
        return Err(Denied::Scope);
    };
    if rights.iter().any(|c| !ceiling.contains(*c)) {
        return Err(Denied::Scope);
    }
    if needs_control(method) && !device.controls() {
        return Err(Denied::ControlNotConfirmed);
    }
    if let Some(mode) = target.chat_mode
        && !ceiling.contains(match mode {
            ChatPermissions::ReadOnly => Capability::ChatSend,
            ChatPermissions::Edit => Capability::ChatPermissionsEdit,
            ChatPermissions::Full => Capability::ChatPermissionsFull,
        })
    {
        return Err(Denied::NeedsLocalConsent(Consent::ChatMode(mode)));
    }
    if target.repository_execution && !ceiling.contains(Capability::GitExecute) {
        return Err(Denied::NeedsLocalConsent(Consent::GitExecute));
    }
    Ok(Granted)
}

/// Methods that change state or take terminal control. Exhaustive on purpose: a new
/// catalog method does not compile until it is classified here.
pub(super) fn needs_control(method: Method) -> bool {
    match method {
        Method::WorkspaceGet
        | Method::WorkspaceCapabilities
        | Method::WorkspaceSubscribe
        | Method::TerminalAttach
        | Method::TerminalSnapshot
        | Method::TerminalAck
        | Method::FilesList
        | Method::FilesStat
        | Method::FilesRead
        | Method::FilesSearchNames
        | Method::FilesWatch
        | Method::GitRepositories
        | Method::GitStatus
        | Method::GitDiff
        | Method::GitLog
        | Method::GitShow
        | Method::ChatProviders
        | Method::ChatThreadsList
        | Method::ChatThreadGet
        | Method::ChatSubscribe
        | Method::OperationStatus => false,
        Method::TerminalCreate
        | Method::TerminalSplit
        | Method::TerminalRename
        | Method::TerminalMove
        | Method::TerminalClose
        | Method::TerminalRestart
        | Method::TerminalClaim
        | Method::TerminalRenew
        | Method::TerminalRelease
        | Method::TerminalInput
        | Method::TerminalResize
        | Method::FilesCreate
        | Method::FilesMkdir
        | Method::FilesRename
        | Method::FilesRemove
        | Method::GitStage
        | Method::GitUnstage
        | Method::GitCommit
        | Method::GitFetch
        | Method::GitPush
        | Method::GitPull
        | Method::ChatThreadCreate
        | Method::ChatThreadUpdate
        | Method::ChatThreadDelete
        | Method::ChatSend
        | Method::ChatStop
        | Method::OperationCancel => true,
    }
}

/// Workspace embedded in the call; `None` for chat and operation calls.
pub(super) fn call_workspace(call: &RpcCall) -> Option<&WorkspaceId> {
    use RpcCall::*;
    Some(match call {
        WorkspaceGet(p) | WorkspaceCapabilities(p) | GitRepositories(p) => &p.context.workspace_id,
        WorkspaceSubscribe(p) => &p.context.workspace_id,
        FilesList(p) => &p.context.workspace_id,
        FilesStat(p) => &p.context.workspace_id,
        FilesRead(p) => &p.context.workspace_id,
        FilesSearchNames(p) => &p.context.workspace_id,
        FilesWatch(p) => &p.context.workspace_id,
        GitStatus(p) => &p.context.workspace_id,
        GitDiff(p) => &p.context.workspace_id,
        GitLog(p) => &p.context.workspace_id,
        GitShow(p) => &p.context.workspace_id,
        GitStage(p) => &p.mutation.context.workspace_id,
        GitUnstage(p) => &p.mutation.context.workspace_id,
        GitCommit(p) => &p.mutation.context.workspace_id,
        GitFetch(p) | GitPush(p) => &p.mutation.context.workspace_id,
        GitPull(p) => &p.mutation.context.workspace_id,
        FilesCreate(p) | FilesMkdir(p) => &p.mutation.context.workspace_id,
        FilesRename(p) => &p.mutation.context.workspace_id,
        FilesRemove(p) => &p.mutation.context.workspace_id,
        TerminalCreate(p) => &p.mutation.context.workspace_id,
        TerminalSplit(p) => &p.mutation.context.workspace_id,
        TerminalRename(p) => &p.mutation.context.workspace_id,
        TerminalMove(p) => &p.mutation.context.workspace_id,
        TerminalClose(p) => &p.mutation.context.workspace_id,
        TerminalRestart(p) => &p.mutation.context.workspace_id,
        TerminalAttach(p) | TerminalSnapshot(p) => &p.terminal.workspace.workspace_id,
        TerminalAck(p) => &p.terminal.workspace.workspace_id,
        TerminalClaim(p) => &p.terminal.workspace.workspace_id,
        TerminalRenew(p) | TerminalRelease(p) => &p.terminal.workspace.workspace_id,
        TerminalInput(p) => &p.terminal.workspace.workspace_id,
        TerminalResize(p) => &p.terminal.workspace.workspace_id,
        ChatProviders(_) | ChatThreadsList(_) | ChatThreadGet(_) | ChatSubscribe(_)
        | ChatThreadCreate(_) | ChatThreadUpdate(_) | ChatThreadDelete(_) | ChatSend(_)
        | ChatStop(_) | OperationStatus(_) | OperationCancel(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_protocol::{
        ChatThreadId, PaneId, SessionEpoch,
        ipc::ChatLevel,
        rpc::{EncodedPathId, TerminalDimension},
        tunnel::{ChatOpen, FilesWatchOpen, StreamKind, TerminalOpen, TransferOpen},
    };

    const NOW: u64 = 10 * 24 * 60 * 60 * 1000;
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    fn ws(id: &str) -> WorkspaceId {
        WorkspaceId::try_from(id.to_string()).unwrap()
    }
    fn full() -> CapabilitySet {
        ChatLevel::Full.ceiling().unwrap()
    }
    fn grant(ceiling: Permissions, confirmed: bool) -> DeviceGrant {
        DeviceGrant {
            device_key: [1; 32],
            account_id: [2; 16],
            device_id: [3; 16],
            device_name: "d".into(),
            device_kind: "k".into(),
            ceiling,
            granted_at: 0,
            authorization_expires_at: NOW + 1000,
            authorization_epoch: 1,
            server_confirmed_at: NOW,
            control_confirmed_at: confirmed.then_some(NOW),
        }
    }
    fn access(g: DeviceGrant, ceiling: CapabilitySet) -> DeviceAccess {
        DeviceAccess::new(g, BTreeMap::from([(ws(A), ceiling)]))
    }
    fn control() -> DeviceGrant {
        grant(Permissions::Control, true)
    }
    fn rights(m: Method) -> &'static [Capability] {
        match m.rights() {
            MethodRights::Static(r) => r,
            MethodRights::StoredOperationRights => &[],
        }
    }
    fn methods() -> impl Iterator<Item = Method> {
        Method::ALL
            .iter()
            .copied()
            .filter(|m| !matches!(m, Method::OperationStatus | Method::OperationCancel))
    }
    fn opens() -> Vec<OpenParams> {
        vec![
            OpenParams::Directory,
            OpenParams::Terminal(TerminalOpen {
                workspace_id: ws(A),
                pane_id: PaneId::try_from(A.to_string()).unwrap(),
                session_epoch: SessionEpoch::try_from(A.to_string()).unwrap(),
                cols: TerminalDimension::try_from(80).unwrap(),
                rows: TerminalDimension::try_from(24).unwrap(),
                after_seq: None,
            }),
            OpenParams::Chat(ChatOpen {
                workspace_id: ws(A),
                thread_id: ChatThreadId::try_from("a".repeat(32)).unwrap(),
                after: None,
            }),
            OpenParams::FilesWatch(FilesWatchOpen {
                workspace_id: ws(A),
                path: EncodedPathId::try_from("abc_-1".to_string()).unwrap(),
            }),
            OpenParams::Transfer(TransferOpen {
                request_id: lomi_remote_protocol::RequestId::try_from(A.to_string()).unwrap(),
            }),
        ]
    }
    /// Unshared workspace B, and the same params re-pointed at it.
    fn other(open: &OpenParams) -> OpenParams {
        match open.clone() {
            OpenParams::Terminal(mut p) => {
                p.workspace_id = ws(B);
                OpenParams::Terminal(p)
            }
            OpenParams::Chat(mut p) => {
                p.workspace_id = ws(B);
                OpenParams::Chat(p)
            }
            OpenParams::FilesWatch(mut p) => {
                p.workspace_id = ws(B);
                OpenParams::FilesWatch(p)
            }
            o => o,
        }
    }
    fn at(device: &DeviceAccess, target: &Target<'_>) -> Result<Granted, Denied> {
        authorize(device, target, NOW)
    }
    fn revoked_grants() -> [DeviceGrant; 2] {
        let mut stale = control();
        stale.server_confirmed_at = 0;
        stale.authorization_expires_at = u64::MAX;
        let mut expired = control();
        expired.authorization_expires_at = NOW;
        [stale, expired]
    }

    #[test]
    fn method_matrix() {
        let a = ws(A);
        let b = ws(B);
        let mut cells = 0;
        for m in methods() {
            let t = Target::message(&a, m);
            // (a) full control in a shared workspace
            assert_eq!(at(&access(control(), full()), &t), Ok(Granted), "{m:?}");
            // (b) every method needs rights; drop the last (a leaf of the dependency closure)
            let r = rights(m);
            let missing = CapabilitySet::try_from(r[..r.len() - 1].to_vec()).unwrap();
            assert_eq!(
                at(&access(control(), missing), &t),
                Err(Denied::Scope),
                "{m:?}"
            );
            // (c) another workspace
            let t_other = Target::message(&b, m);
            assert_eq!(
                at(&access(control(), full()), &t_other),
                Err(Denied::WorkspaceUnshared),
                "{m:?}"
            );
            // (d) read level: observe ceiling, or control ceiling without the code
            for g in [
                grant(Permissions::Observe, true),
                grant(Permissions::Control, false),
            ] {
                let got = at(&access(g, full()), &t);
                if needs_control(m) {
                    assert_eq!(got, Err(Denied::ControlNotConfirmed), "{m:?}");
                } else {
                    assert_eq!(got, Ok(Granted), "{m:?}");
                }
            }
            // (e) revoked or expired
            for g in revoked_grants() {
                assert_eq!(at(&access(g, full()), &t), Err(Denied::Revoked), "{m:?}");
            }
            cells += 1;
        }
        assert_eq!(cells, Method::ALL.len() - 2);
    }

    #[test]
    fn classification_covers_catalog() {
        for m in Method::ALL.iter().copied() {
            let writes = rights(m).iter().any(|c| {
                matches!(
                    c,
                    Capability::TerminalControl
                        | Capability::TerminalManage
                        | Capability::FilesWrite
                        | Capability::GitWrite
                        | Capability::GitNetwork
                        | Capability::ChatSend
                )
            });
            let mutating = lomi_remote_protocol::is_durable_mutation(m)
                || lomi_remote_protocol::is_chat_mutation(m);
            assert!(!(writes || mutating) || needs_control(m), "{m:?}");
        }
        // Operation lookup is read-only; cancel is not.
        assert!(!needs_control(Method::OperationStatus) && needs_control(Method::OperationCancel));
    }

    #[test]
    fn operation_methods_have_no_static_rights() {
        let a = ws(A);
        for m in [Method::OperationStatus, Method::OperationCancel] {
            let t = Target::message(&a, m);
            assert_eq!(at(&access(control(), full()), &t), Err(Denied::Scope));
        }
    }

    #[test]
    fn chat_off_denies_chat_methods() {
        let a = ws(A);
        let off = ChatLevel::Off
            .ceiling()
            .unwrap_or_else(CapabilitySet::control_with_workspace_tools);
        for m in Method::ALL
            .iter()
            .copied()
            .filter(|m| rights(*m).contains(&Capability::ChatRead))
        {
            assert_eq!(
                at(&access(control(), off.clone()), &Target::message(&a, m)),
                Err(Denied::Scope),
                "{m:?}"
            );
        }
    }

    #[test]
    fn local_consent_is_reported() {
        let a = ws(A);
        let send_only = ChatLevel::Send.ceiling().unwrap();
        let device = access(control(), send_only);
        let create = |mode| Target::message(&a, Method::ChatThreadCreate).with_chat_mode(mode);
        assert_eq!(at(&device, &create(ChatPermissions::ReadOnly)), Ok(Granted));
        for mode in [ChatPermissions::Edit, ChatPermissions::Full] {
            assert_eq!(
                at(&device, &create(mode)),
                Err(Denied::NeedsLocalConsent(Consent::ChatMode(mode)))
            );
        }
        let git = Target::message(&a, Method::GitPull).with_repository_execution();
        assert_eq!(
            at(&device, &git),
            Err(Denied::NeedsLocalConsent(Consent::GitExecute))
        );
        let mut with_exec = Vec::from(CapabilitySet::control_with_workspace_tools());
        with_exec.push(Capability::GitExecute);
        let device = access(control(), CapabilitySet::try_from(with_exec).unwrap());
        assert_eq!(at(&device, &git), Ok(Granted));
    }

    #[test]
    fn stream_matrix() {
        let opens = opens();
        // Every kind a device may open is in the matrix (rpc and media never are).
        let kinds: Vec<_> = opens.iter().map(OpenParams::kind).collect();
        for k in [
            StreamKind::Directory,
            StreamKind::Terminal,
            StreamKind::Chat,
            StreamKind::FilesWatch,
            StreamKind::Transfer,
        ] {
            assert!(kinds.contains(&k), "{k:?}");
        }
        for open in &opens {
            let t = Target::open(open);
            let scoped = !matches!(open, OpenParams::Directory | OpenParams::Transfer(_));
            assert_eq!(at(&access(control(), full()), &t), Ok(Granted));
            // Opening observes only, so read level is enough.
            assert_eq!(
                at(&access(grant(Permissions::Observe, false), full()), &t),
                Ok(Granted)
            );
            let empty = CapabilitySet::try_from(vec![Capability::WorkspaceRead]).unwrap();
            let denied = at(&access(control(), empty), &t);
            let unshared = other(open);
            let got = at(&access(control(), full()), &Target::open(&unshared));
            if scoped {
                assert_eq!(denied, Err(Denied::Scope), "{:?}", open.kind());
                assert_eq!(got, Err(Denied::WorkspaceUnshared), "{:?}", open.kind());
            } else {
                assert_eq!((denied, got), (Ok(Granted), Ok(Granted)));
            }
            for g in revoked_grants() {
                assert_eq!(at(&access(g, full()), &t), Err(Denied::Revoked));
            }
        }
    }

    #[test]
    fn error_codes() {
        assert_eq!(
            Denied::WorkspaceUnshared.code(),
            ErrorCode::WorkspaceUnshared
        );
        assert_eq!(Denied::ControlNotConfirmed.code(), ErrorCode::ScopeDenied);
        assert_eq!(
            Denied::NeedsLocalConsent(Consent::GitExecute).code(),
            ErrorCode::RepositoryExecutionRequired
        );
    }
}
