#![cfg(unix)]
use lomi_platform::unix::LocalClient;
use lomi_remote_protocol::{ipc::*, rpc::*, streams::*, *};
use lomi_terminal_state::{GridPatch, Snapshot};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static IDS: AtomicU64 = AtomicU64::new(1);
fn id<T: TryFrom<String>>() -> T
where
    T::Error: std::fmt::Debug,
{
    format!(
        "11111111-1111-4111-8111-{:012x}",
        IDS.fetch_add(1, Ordering::Relaxed)
    )
    .try_into()
    .unwrap()
}
struct Host {
    base: PathBuf,
    profile: PathBuf,
    shell: PathBuf,
    child: Option<Child>,
}
impl Host {
    fn new() -> Self {
        Self::with_spawn_counter(false)
    }
    fn with_spawn_counter(count_spawns: bool) -> Self {
        // Two tests of this process can start within one clock tick, so the
        // timestamp alone is not unique; a process-wide counter is.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = fs::canonicalize("/tmp").unwrap().join(format!(
            "lr-ipc-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(base.join("home"))
            .unwrap();
        fs::create_dir(base.join("project")).unwrap();
        let shell = if count_spawns {
            let script = base.join("counted-shell");
            fs::write(
                &script,
                b"#!/bin/sh\nprintf 'spawn\\n' >> \"$HOME/shell-starts\"\nexec /bin/sh\n",
            )
            .unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
            script
        } else {
            PathBuf::from("/bin/sh")
        };
        let mut host = Self {
            profile: base.join("p"),
            shell,
            base,
            child: None,
        };
        host.start();
        host
    }
    fn start(&mut self) {
        self.child = Some(
            Command::new(env!("CARGO_BIN_EXE_lomiremote"))
                .arg("--profile-dir")
                .arg(&self.profile)
                .args(["daemon", "run"])
                .env("SHELL", &self.shell)
                .env("HOME", self.base.join("home"))
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if LocalClient::connect_with_timeout(&self.profile, Duration::from_millis(100)).is_ok()
            {
                break;
            }
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "host startup exited"
            );
            assert!(Instant::now() < deadline, "host startup deadline");
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn stop(&mut self) {
        lomi_host::stop(&self.profile).expect("controlled host shutdown");
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                assert!(status.success());
                self.child = None;
                break;
            }
            assert!(Instant::now() < deadline, "owned host reap deadline");
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn client(&self) -> LocalClient {
        LocalClient::connect(&self.profile).unwrap()
    }
    fn crash(&mut self) {
        let mut child = self.child.take().unwrap();
        // The retained Child owns the target identity; no PID-file signalling.
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = lomi_host::stop(&self.profile);
        }
        if let Some(child) = &mut self.child {
            let deadline = Instant::now() + Duration::from_secs(3);
            while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if child.try_wait().ok().flatten().is_none() {
                return;
            } // Preserve an uncertain runtime/store.
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn result(client: &mut LocalClient, call: RpcCall) -> RpcResult {
    let method = call.method();
    match rpc(client, call) {
        RpcResponse::Result { result, .. } => result,
        RpcResponse::Error { error, .. } => {
            panic!("{} rejected: {:?}", method.as_str(), error.code())
        }
    }
}
fn rpc(client: &mut LocalClient, call: RpcCall) -> RpcResponse {
    let method = call.method();
    let request = RpcRequest {
        v: ApplicationMajor::try_from(2).unwrap(),
        r#type: RequestKind::Request,
        request_id: format!("rpc-{}", IDS.fetch_add(1, Ordering::Relaxed))
            .try_into()
            .unwrap(),
        timeout_ms: TimeoutMs::new(10000).unwrap(),
        call,
    };
    match client
        .request(LocalCall::Rpc(Box::new(request)))
        .unwrap_or_else(|error| panic!("{} transport rejected: {}", method.as_str(), error))
        .result
        .unwrap()
    {
        LocalResult::Rpc(response) => *response,
        _ => panic!("wrong local RPC response"),
    }
}
fn inspect(client: &mut LocalClient, workspace_id: WorkspaceId) -> WorkspaceState {
    match client
        .request(LocalCall::WorkspaceInspect(LocalWorkspaceRead {
            workspace_id,
        }))
        .unwrap()
        .result
        .unwrap()
    {
        LocalResult::WorkspaceState(state) => *state,
        _ => panic!("wrong workspace inspection response"),
    }
}
fn terminal(state: &WorkspaceState) -> TerminalContext {
    match &state.tabs.0[0].layout {
        TerminalLayout::Pane { pane } => pane.session.clone().unwrap(),
        _ => panic!("expected single terminal"),
    }
}
struct View {
    metadata: TerminalSnapshotMetadata,
    through: TerminalSeq,
    model: Snapshot,
    assembly: Option<DeltaAssembly>,
}
impl View {
    fn attach(client: &mut LocalClient, terminal: &TerminalContext) -> Self {
        let RpcResult::TerminalAttach(metadata) = result(
            client,
            RpcCall::TerminalAttach(TerminalReadParams {
                terminal: terminal.clone(),
            }),
        ) else {
            panic!("attach result")
        };
        let mut assembly = SnapshotAssembly::new(
            metadata.subscription_id.clone(),
            metadata.chunk_count,
            metadata.total_bytes,
        )
        .unwrap();
        let mut bytes = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            assert!(Instant::now() < deadline, "initial snapshot deadline");
            match client.next_event(Duration::from_secs(2)).unwrap() {
                Some(LocalStreamEvent::Terminal(TerminalStreamFrame::SnapshotChunk(chunk))) => {
                    assembly
                        .push(&chunk.subscription_id, chunk.index, &chunk.bytes.0)
                        .unwrap();
                    bytes.extend(chunk.bytes.0);
                }
                Some(LocalStreamEvent::Terminal(TerminalStreamFrame::SnapshotComplete(done))) => {
                    assert_eq!(done.terminal, *terminal);
                    assert_eq!(done.through_seq, metadata.through_seq);
                    assembly.complete(&done.subscription_id).unwrap();
                    break;
                }
                None => {}
                _ => panic!("unexpected initial snapshot frame"),
            }
        }
        let model: Snapshot = serde_json::from_slice(&bytes).unwrap();
        model.validate().unwrap();
        assert_eq!(
            model.session_epoch.to_string(),
            String::from(terminal.session_epoch)
        );
        Self {
            through: metadata.through_seq,
            metadata,
            model,
            assembly: None,
        }
    }
    fn acknowledge(&mut self, client: &mut LocalClient) {
        assert!(matches!(
            self.result(
                client,
                RpcCall::TerminalAck(TerminalAckParams {
                    terminal: self.metadata.terminal.clone(),
                    subscription_id: self.metadata.subscription_id.clone(),
                    through_seq: self.through
                })
            ),
            RpcResult::TerminalAck(_)
        ));
    }
    fn text(&self) -> String {
        self.model
            .normal
            .lines
            .iter()
            .flat_map(|row| &row.cells)
            .map(|cell| cell.text.as_str())
            .collect()
    }
    fn advance(&mut self, client: &mut LocalClient) {
        let Some(event) = client.next_event(Duration::from_millis(300)).unwrap() else {
            return;
        };
        self.apply(event);
    }
    fn apply(&mut self, event: LocalStreamEvent) {
        let LocalStreamEvent::Terminal(event) = event else {
            panic!("unexpected workspace frame")
        };
        match event {
            TerminalStreamFrame::DeltaMetadata(metadata) => {
                assert!(self.assembly.is_none());
                self.assembly = Some(DeltaAssembly::new(metadata, self.through).unwrap());
            }
            TerminalStreamFrame::DeltaChunk(chunk) => {
                self.assembly.as_mut().unwrap().push(&chunk).unwrap()
            }
            TerminalStreamFrame::DeltaComplete(complete) => {
                let mut assembly = self.assembly.take().unwrap();
                let bytes = assembly.complete(&complete).unwrap();
                let delta = GridPatch::from_json(&bytes).unwrap();
                assert_eq!(delta.previous_sequence(), self.through.0);
                assert_eq!(
                    delta.session_epoch().to_string(),
                    String::from(self.metadata.terminal.session_epoch)
                );
                self.model = delta.apply(&self.model).unwrap();
                self.through = complete.through_seq;
            }
            TerminalStreamFrame::Delta(delta) => {
                assert_eq!(delta.seq.0.0, self.through.0.0 + 1);
                assert!(matches!(delta.change, TerminalChange::ControlChanged(_)));
                self.model.sequence = delta.seq.0;
                self.through = delta.seq;
            }
            TerminalStreamFrame::ResyncRequired(_) => {
                panic!("unexpected subscriber overflow during bounded interaction")
            }
            _ => panic!("unexpected terminal stream frame"),
        }
    }
    fn request(&mut self, client: &mut LocalClient, call: RpcCall) -> RpcResponse {
        let request = RpcRequest {
            v: ApplicationMajor::try_from(2).unwrap(),
            r#type: RequestKind::Request,
            request_id: format!("rpc-{}", IDS.fetch_add(1, Ordering::Relaxed))
                .try_into()
                .unwrap(),
            timeout_ms: TimeoutMs::new(10000).unwrap(),
            call,
        };
        let response = client
            .request_with_events(LocalCall::Rpc(Box::new(request)), &mut |event| {
                self.apply(event);
                Ok(())
            })
            .unwrap();
        let Ok(LocalResult::Rpc(response)) = response.result else {
            panic!("RPC response")
        };
        *response
    }
    fn result(&mut self, client: &mut LocalClient, call: RpcCall) -> RpcResult {
        let method = call.method();
        match self.request(client, call) {
            RpcResponse::Result { result, .. } => result,
            RpcResponse::Error { error, .. } => {
                panic!("{} rejected: {:?}", method.as_str(), error.code())
            }
        }
    }
    fn until(&mut self, client: &mut LocalClient, marker: &str) {
        let deadline = Instant::now() + Duration::from_secs(8);
        while !self.text().contains(marker) {
            assert!(
                Instant::now() < deadline,
                "terminal projection observation deadline"
            );
            self.advance(client);
        }
    }
}

#[test]
fn two_actual_ipc_views_share_one_shell_control_and_durable_descriptors() {
    let mut host = Host::new();
    let mut first = host.client();
    let added = first
        .request(LocalCall::WorkspaceAdd(LocalWorkspaceAdd {
            name: "IPC fixture".to_owned().try_into().unwrap(),
            root_path: host
                .base
                .join("project")
                .to_str()
                .unwrap()
                .to_owned()
                .try_into()
                .unwrap(),
            operator_intent: Confirmed::Confirmed,
        }))
        .unwrap()
        .result
        .unwrap();
    let LocalResult::Workspace(added) = added else {
        panic!("workspace add result")
    };
    let state = inspect(&mut first, added.workspace_id);
    let create = RpcCall::TerminalCreate(TerminalCreateParams {
        mutation: MutationContext {
            context: state.context.clone(),
            operation_id: id(),
            expected_revision: state.domain_revision,
        },
        tab_name: "Shell".to_owned().try_into().unwrap(),
        profile_id: "default".to_owned().try_into().unwrap(),
    });
    let created = result(&mut first, create.clone());
    assert!(
        matches!(created, RpcResult::TerminalCreate(ref receipt) if receipt.state() == OperationState::Succeeded)
    );
    assert_eq!(
        result(&mut first, create),
        created,
        "duplicate create must return receipt without spawning"
    );
    let current = inspect(&mut first, added.workspace_id);
    assert_eq!(current.tabs.0.len(), 1);
    let terminal = terminal(&current);
    let mut a = View::attach(&mut first, &terminal);
    a.acknowledge(&mut first);
    let mut second = host.client();
    let mut b = View::attach(&mut second, &terminal);
    b.acknowledge(&mut second);
    let RpcResult::TerminalClaim(lease) = a.result(
        &mut first,
        RpcCall::TerminalClaim(TerminalClaimParams {
            terminal: terminal.clone(),
            subscription_id: a.metadata.subscription_id.clone(),
            rendered_through_seq: a.through,
        }),
    ) else {
        panic!("claim result")
    };
    assert!(
        matches!(b.request(&mut second, RpcCall::TerminalClaim(TerminalClaimParams { terminal: terminal.clone(),
        subscription_id: b.metadata.subscription_id.clone(), rendered_through_seq: b.through })), RpcResponse::Error {error,..} if error.code() == ErrorCode::ControlRequired)
    );
    let input = RpcCall::TerminalInput(TerminalInputParams {
        terminal: terminal.clone(),
        lease: lease.lease.clone(),
        input_id: lease.next_input_id,
        input_seq: lease.next_input_seq,
        bytes: BoundedList(b"n=$(( ${n:-0} + 1 )); printf 'LMCOUNT_%s\\n' \"$n\"\n".to_vec()),
    });
    let receipt = a.result(&mut first, input.clone());
    assert_eq!(
        a.result(&mut first, input),
        receipt,
        "duplicate input may not write twice"
    );
    a.until(&mut first, "LMCOUNT_1");
    b.until(&mut second, "LMCOUNT_1");
    assert!(!a.text().contains("LMCOUNT_2"));
    drop(first); // Closing a controlling view releases its lease, not the shell.
    thread::sleep(Duration::from_millis(80));
    let mut third = host.client();
    let c = View::attach(&mut third, &terminal);
    assert!(c.text().contains("LMCOUNT_1"));
    assert_eq!(
        terminal.session_id,
        crate_terminal_id(&inspect(&mut third, added.workspace_id))
    );
    drop(third);
    drop(second);
    host.stop();
    host.start();
    let mut restarted = host.client();
    let stopped = inspect(&mut restarted, added.workspace_id);
    let TerminalLayout::Pane { pane } = &stopped.tabs.0[0].layout else {
        panic!("retained pane")
    };
    assert_eq!(pane.state, PaneState::Stopped);
    assert!(pane.session.is_none());
    assert!(
        matches!(result(&mut restarted, RpcCall::TerminalRestart(TerminalRestartParams { mutation: MutationContext {
        context: stopped.context.clone(), operation_id: id(), expected_revision: stopped.domain_revision }, pane_id: pane.pane_id,
        expected_session: None, profile_id: "default".to_owned().try_into().unwrap() })), RpcResult::TerminalRestart(ref receipt) if receipt.state() == OperationState::Succeeded)
    );
    let fresh = inspect(&mut restarted, added.workspace_id);
    let new_terminal = terminal_from_state(&fresh);
    assert_ne!(new_terminal.session_epoch, terminal.session_epoch);
    let fresh_view = View::attach(&mut restarted, &new_terminal);
    assert!(
        !fresh_view.text().contains("LMCOUNT_1"),
        "restart must not replay old commands"
    );
    drop(restarted);
    host.stop();
}
fn crate_terminal_id(state: &WorkspaceState) -> TerminalSessionId {
    terminal_from_state(state).session_id
}
fn terminal_from_state(state: &WorkspaceState) -> TerminalContext {
    terminal(state)
}

#[test]
fn actual_owner_crash_recovers_lost_without_observer_spawn_or_input_replay() {
    let mut host = Host::with_spawn_counter(true);
    let mut client = host.client();
    let LocalResult::Workspace(workspace) = client
        .request(LocalCall::WorkspaceAdd(LocalWorkspaceAdd {
            name: "Crash fixture".to_owned().try_into().unwrap(),
            root_path: host
                .base
                .join("project")
                .to_str()
                .unwrap()
                .to_owned()
                .try_into()
                .unwrap(),
            operator_intent: Confirmed::Confirmed,
        }))
        .unwrap()
        .result
        .unwrap()
    else {
        panic!("workspace add")
    };
    let initial = inspect(&mut client, workspace.workspace_id);
    assert!(
        matches!(result(&mut client, RpcCall::TerminalCreate(TerminalCreateParams {
        mutation: MutationContext { context: initial.context, operation_id: id(), expected_revision: initial.domain_revision },
        tab_name: "Crash shell".to_owned().try_into().unwrap(),
        profile_id: "default".to_owned().try_into().unwrap(),
    })), RpcResult::TerminalCreate(ref receipt) if receipt.state() == OperationState::Succeeded)
    );
    let running = inspect(&mut client, workspace.workspace_id);
    let old_terminal = terminal(&running);
    let mut view = View::attach(&mut client, &old_terminal);
    view.acknowledge(&mut client);
    let RpcResult::TerminalClaim(lease) = view.result(
        &mut client,
        RpcCall::TerminalClaim(TerminalClaimParams {
            terminal: old_terminal.clone(),
            subscription_id: view.metadata.subscription_id.clone(),
            rendered_through_seq: view.through,
        }),
    ) else {
        panic!("claim")
    };
    view.result(
        &mut client,
        RpcCall::TerminalInput(TerminalInputParams {
            terminal: old_terminal.clone(),
            lease: lease.lease,
            input_id: lease.next_input_id,
            input_seq: lease.next_input_seq,
            bytes: BoundedList(b"printf 'OLD_%s\\n' 'PROCESS_ONLY'\n".to_vec()),
        }),
    );
    view.until(&mut client, "OLD_PROCESS_ONLY");
    let starts = host.base.join("home/shell-starts");
    assert_eq!(fs::read_to_string(&starts).unwrap(), "spawn\n");
    host.crash();
    drop(client);
    host.start();
    let mut observer = host.client();
    let lost = inspect(&mut observer, workspace.workspace_id);
    let TerminalLayout::Pane { pane } = &lost.tabs.0[0].layout else {
        panic!("lost pane")
    };
    assert_eq!(pane.state, PaneState::Lost);
    assert!(pane.session.is_none());
    assert_ne!(lost.context.runtime_id, running.context.runtime_id);
    assert!(matches!(
        rpc(
            &mut observer,
            RpcCall::TerminalAttach(TerminalReadParams {
                terminal: old_terminal.clone(),
            })
        ),
        RpcResponse::Error { .. }
    ));
    // Allow an owner tick after the rejected observer request. Inspection and
    // attachment must not silently restore a shell from the retained layout.
    thread::sleep(Duration::from_millis(150));
    assert_eq!(fs::read_to_string(&starts).unwrap(), "spawn\n");
    assert_eq!(inspect(&mut observer, workspace.workspace_id), lost);
    assert!(
        matches!(result(&mut observer, RpcCall::TerminalRestart(TerminalRestartParams {
        mutation: MutationContext { context: lost.context.clone(), operation_id: id(), expected_revision: lost.domain_revision },
        pane_id: pane.pane_id, expected_session: None,
        profile_id: "default".to_owned().try_into().unwrap(),
    })), RpcResult::TerminalRestart(ref receipt) if receipt.state() == OperationState::Succeeded)
    );
    let fresh = terminal(&inspect(&mut observer, workspace.workspace_id));
    assert_ne!(fresh.session_epoch, old_terminal.session_epoch);
    let mut fresh_view = View::attach(&mut observer, &fresh);
    let deadline = Instant::now() + Duration::from_secs(3);
    while fs::read_to_string(&starts).unwrap().lines().count() != 2 {
        assert!(Instant::now() < deadline, "explicit restart did not spawn");
        fresh_view.advance(&mut observer);
    }
    assert!(!fresh_view.text().contains("OLD_PROCESS_ONLY"));
    drop(observer);
    host.stop();
}
