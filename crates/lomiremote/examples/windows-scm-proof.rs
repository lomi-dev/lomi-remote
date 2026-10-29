//! Native SCM fixture: production dispatcher/host, plus same-account IPC observers.
#[cfg(not(windows))]
fn main() {}
#[cfg(windows)]
fn main() {
    use std::path::PathBuf;
    let mut args = std::env::args_os().skip(1);
    let (Some(name), Some(root), None) = (args.next(), args.next(), args.next()) else {
        std::process::exit(2);
    };
    let root = PathBuf::from(root);
    let profile = root.join("profile");
    let observer_root = root.clone();
    std::thread::spawn(move || {
        if observer::run(&observer_root).is_err() {
            let _ = std::fs::write(
                observer_root.join("observer-failed.json"),
                b"{\"passed\":false}",
            );
        }
    });
    if lomi_host::windows_service::dispatch(name, profile).is_err() {
        std::process::exit(1);
    }
}
#[cfg(windows)]
mod observer {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetConsoleWindow() -> isize;
    }
    use lomi_platform::windows::LocalClient;
    use lomi_remote_protocol::{ipc::*, rpc::*, streams::*, *};
    use lomi_terminal_state::{GridPatch, Snapshot};
    use std::{
        ffi::OsString,
        io::Read,
        os::windows::process::CommandExt,
        path::Path,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use uuid::Uuid;
    type Result<T> = std::result::Result<T, &'static str>;
    fn check(ok: bool) -> Result<()> {
        if ok {
            Ok(())
        } else {
            Err("synthetic assertion")
        }
    }
    fn fresh<T: TryFrom<String>>() -> T
    where
        T::Error: std::fmt::Debug,
    {
        Uuid::new_v4()
            .to_string()
            .try_into()
            .expect("synthetic UUID")
    }
    fn bounded(executable: &Path, args: &[OsString]) -> Result<Vec<u8>> {
        let mut child = Command::new(executable)
            .creation_flags(0x08000000)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "owned child spawn")?;
        let out = child.stdout.take().ok_or("owned stdout")?;
        let err = child.stderr.take().ok_or("owned stderr")?;
        let (out_tx, out_rx) = std::sync::mpsc::sync_channel(1);
        let (err_tx, err_rx) = std::sync::mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = out.take(131073).read_to_end(&mut bytes).map(|_| bytes);
            let _ = out_tx.send(result);
        });
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = err.take(131073).read_to_end(&mut bytes).map(|_| bytes);
            let _ = err_tx.send(result);
        });
        let deadline = Instant::now() + Duration::from_secs(22);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|_| "owned child wait")? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("owned child deadline");
            }
            thread::sleep(Duration::from_millis(5));
        };
        let output = out_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "owned output completion")?
            .map_err(|_| "owned output")?;
        let error = err_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "owned error completion")?
            .map_err(|_| "owned error")?;
        check(status.success() && output.len() <= 131072 && error.len() <= 131072)?;
        Ok(output)
    }
    fn cli(exe: &Path, profile: &Path, args: &[&str]) -> Result<Vec<u8>> {
        let mut all = vec![
            OsString::from("--profile-dir"),
            profile.as_os_str().to_owned(),
        ];
        all.extend(args.iter().map(OsString::from));
        bounded(exe, &all)
    }
    fn connect(profile: &Path) -> Result<LocalClient> {
        LocalClient::connect(profile).map_err(|_| "authenticated IPC")
    }
    fn local(client: &mut LocalClient, call: LocalCall) -> Result<LocalResult> {
        client
            .request(call)
            .map_err(|_| "local request")?
            .result
            .map_err(|_| "local rejection")
    }
    fn request(call: RpcCall) -> RpcRequest {
        RpcRequest {
            v: ApplicationMajor,
            r#type: RequestKind::Request,
            request_id: fresh(),
            timeout_ms: TimeoutMs::new(10000).unwrap(),
            call,
        }
    }
    fn rpc_response(client: &mut LocalClient, call: RpcCall) -> Result<RpcResponse> {
        let request = request(call);
        let LocalResult::Rpc(response) = local(client, LocalCall::Rpc(Box::new(request.clone())))?
        else {
            return Err("RPC envelope");
        };
        response
            .validate_for(&request)
            .map_err(|_| "RPC response binding")?;
        Ok(*response)
    }
    fn rpc(client: &mut LocalClient, call: RpcCall) -> Result<RpcResult> {
        match rpc_response(client, call)? {
            RpcResponse::Result { result, .. } => Ok(result),
            _ => Err("RPC rejected"),
        }
    }
    fn workspace(client: &mut LocalClient, id: WorkspaceId) -> Result<WorkspaceState> {
        match local(
            client,
            LocalCall::WorkspaceInspect(LocalWorkspaceRead { workspace_id: id }),
        )? {
            LocalResult::WorkspaceState(state) => Ok(*state),
            _ => Err("workspace response"),
        }
    }
    fn pane(state: &WorkspaceState) -> Result<TerminalPane> {
        fn first(node: &TerminalLayout) -> TerminalPane {
            match node {
                TerminalLayout::Pane { pane } => pane.clone(),
                TerminalLayout::Split { first: node, .. } => first(node),
            }
        }
        state
            .tabs
            .0
            .first()
            .map(|tab| first(&tab.layout))
            .ok_or("pane missing")
    }
    struct View {
        client: LocalClient,
        state: ViewState,
    }
    struct ViewState {
        terminal: TerminalContext,
        metadata: TerminalSnapshotMetadata,
        snapshot: Snapshot,
        delta: Option<DeltaAssembly>,
    }
    impl View {
        fn attach(profile: &Path, terminal: &TerminalContext) -> Result<Self> {
            let mut client = connect(profile)?;
            let RpcResult::TerminalAttach(metadata) = rpc(
                &mut client,
                RpcCall::TerminalAttach(TerminalReadParams {
                    terminal: terminal.clone(),
                }),
            )?
            else {
                return Err("attach metadata");
            };
            let mut assembly = SnapshotAssembly::new(
                metadata.subscription_id.clone(),
                metadata.chunk_count,
                metadata.total_bytes,
            )
            .map_err(|_| "snapshot metadata")?;
            let mut bytes = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                check(Instant::now() < deadline)?;
                match client
                    .next_event(Duration::from_millis(500))
                    .map_err(|_| "snapshot transport")?
                {
                    Some(LocalStreamEvent::Terminal(TerminalStreamFrame::SnapshotChunk(chunk))) => {
                        check(chunk.terminal == *terminal)?;
                        assembly
                            .push(&chunk.subscription_id, chunk.index, &chunk.bytes.0)
                            .map_err(|_| "snapshot chunk")?;
                        bytes.extend(chunk.bytes.0);
                    }
                    Some(LocalStreamEvent::Terminal(TerminalStreamFrame::SnapshotComplete(
                        done,
                    ))) => {
                        check(
                            done.terminal == *terminal && done.through_seq == metadata.through_seq,
                        )?;
                        assembly
                            .complete(&done.subscription_id)
                            .map_err(|_| "snapshot completion")?;
                        break;
                    }
                    None => (),
                    _ => return Err("unexpected snapshot event"),
                }
            }
            let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| "snapshot JSON")?;
            snapshot.validate().map_err(|_| "snapshot validation")?;
            check(
                snapshot.session_epoch.as_bytes() == &terminal.session_epoch.to_bytes()
                    && snapshot.sequence.0 == metadata.through_seq.0.0,
            )?;
            Ok(Self {
                client,
                state: ViewState {
                    terminal: terminal.clone(),
                    metadata,
                    snapshot,
                    delta: None,
                },
            })
        }
        fn wait_marker(&mut self, marker: &str) -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let text: String = self
                    .snapshot
                    .normal
                    .lines
                    .iter()
                    .flat_map(|row| row.cells.iter().map(|cell| cell.text.as_str()))
                    .collect();
                if text.contains(marker) {
                    return Ok(());
                }
                check(Instant::now() < deadline)?;
                if let Some(event) = self
                    .client
                    .next_event(Duration::from_millis(100))
                    .map_err(|_| "live transport")?
                {
                    self.event(event)?;
                }
            }
        }
        fn claim(&mut self) -> Result<TerminalLeaseResult> {
            match self.rpc(RpcCall::TerminalClaim(TerminalClaimParams {
                terminal: self.terminal.clone(),
                subscription_id: self.metadata.subscription_id.clone(),
                rendered_through_seq: TerminalSeq(self.snapshot.sequence),
            }))? {
                RpcResult::TerminalClaim(lease) => Ok(lease),
                _ => Err("claim result"),
            }
        }
    }
    impl std::ops::Deref for View {
        type Target = ViewState;
        fn deref(&self) -> &ViewState {
            &self.state
        }
    }
    impl std::ops::DerefMut for View {
        fn deref_mut(&mut self) -> &mut ViewState {
            &mut self.state
        }
    }
    impl ViewState {
        fn event(&mut self, event: LocalStreamEvent) -> Result<()> {
            let LocalStreamEvent::Terminal(frame) = event else {
                return Err("wrong stream");
            };
            match frame {
                TerminalStreamFrame::DeltaMetadata(meta) => {
                    check(
                        meta.terminal == self.terminal
                            && meta.subscription_id == self.metadata.subscription_id,
                    )?;
                    self.delta = Some(
                        DeltaAssembly::new(meta, TerminalSeq(self.snapshot.sequence))
                            .map_err(|_| "delta metadata")?,
                    );
                }
                TerminalStreamFrame::DeltaChunk(chunk) => self
                    .delta
                    .as_mut()
                    .ok_or("delta missing")?
                    .push(&chunk)
                    .map_err(|_| "delta chunk")?,
                TerminalStreamFrame::DeltaComplete(done) => {
                    let bytes = self
                        .delta
                        .take()
                        .ok_or("delta missing")?
                        .complete(&done)
                        .map_err(|_| "delta completion")?;
                    let patch: GridPatch =
                        serde_json::from_slice(&bytes).map_err(|_| "patch JSON")?;
                    self.snapshot = patch.apply(&self.snapshot).map_err(|_| "patch apply")?;
                }
                TerminalStreamFrame::Delta(delta) => {
                    check(
                        delta.terminal == self.terminal
                            && delta.subscription_id == self.metadata.subscription_id,
                    )?;
                    match delta.change {
                        TerminalChange::Grid(bytes) => {
                            let patch: GridPatch =
                                serde_json::from_slice(&bytes.0).map_err(|_| "inline JSON")?;
                            self.snapshot =
                                patch.apply(&self.snapshot).map_err(|_| "inline apply")?;
                        }
                        TerminalChange::ControlChanged(_) | TerminalChange::Exit(_) => {
                            check(delta.seq.0.0 == self.snapshot.sequence.0 + 1)?;
                            self.snapshot.sequence = delta.seq.0;
                        }
                        TerminalChange::Resize(_) => return Err("unexpected resize frame"),
                    }
                }
                TerminalStreamFrame::ResyncRequired(_) => return Err("observer resync required"),
                _ => return Err("unexpected live event"),
            }
            Ok(())
        }
    }
    impl View {
        fn rpc_response(&mut self, call: RpcCall) -> Result<RpcResponse> {
            let request = request(call);
            let (client, state) = (&mut self.client, &mut self.state);
            let response = client
                .request_with_events(LocalCall::Rpc(Box::new(request.clone())), &mut |event| {
                    state
                        .event(event)
                        .map_err(|_| lomi_platform::windows::Error::InvalidFrame)
                })
                .map_err(|_| "streaming local request")?;
            let LocalResult::Rpc(response) = response.result.map_err(|_| "local rejection")? else {
                return Err("RPC envelope");
            };
            response
                .validate_for(&request)
                .map_err(|_| "RPC response binding")?;
            Ok(*response)
        }
        fn rpc(&mut self, call: RpcCall) -> Result<RpcResult> {
            match self.rpc_response(call)? {
                RpcResponse::Result { result, .. } => Ok(result),
                _ => Err("RPC rejected"),
            }
        }
    }

    pub fn run(root: &Path) -> Result<()> {
        check(unsafe { GetConsoleWindow() } == 0)?;
        use lomi_platform::{
            secrets::{SecretBundle, SecretStorage, Selection},
            windows::{OwnerLock, secrets::WindowsDpapi},
        };
        // Synthetic bytes only, protected by the real provider under precisely
        // the account in which SCM launched this process. No impersonation.
        let dpapi_owner =
            OwnerLock::acquire(&root.join("dpapi-profile")).map_err(|_| "DPAPI profile")?;
        {
            let mut provider = WindowsDpapi::open(dpapi_owner.profile(), Selection::WindowsDpapi)
                .map_err(|_| "DPAPI provider")?;
            let synthetic =
                SecretBundle::new(b"scm-synthetic-v1".to_vec()).map_err(|_| "synthetic bundle")?;
            provider.replace(&synthetic).map_err(|_| "DPAPI protect")?;
        }
        {
            let provider = WindowsDpapi::open(dpapi_owner.profile(), Selection::WindowsDpapi)
                .map_err(|_| "DPAPI reopen")?;
            check(
                provider
                    .load()
                    .map_err(|_| "DPAPI decrypt")?
                    .ok_or("DPAPI missing")?
                    .expose()
                    == b"scm-synthetic-v1",
            )?;
        }
        drop(dpapi_owner);
        let profile = root.join("profile");
        let exe = root.join("lomiremote.exe");
        let deadline = Instant::now() + Duration::from_secs(25);
        let mut control = loop {
            if let Ok(client) =
                LocalClient::connect_with_timeout(&profile, Duration::from_millis(200))
            {
                break client;
            }
            check(Instant::now() < deadline)?;
            thread::sleep(Duration::from_millis(50));
        };
        let LocalResult::Status(status) = local(&mut control, LocalCall::Status {})? else {
            return Err("status");
        };
        let LocalResult::Workspaces(items) = local(&mut control, LocalCall::Workspaces {})? else {
            return Err("workspaces");
        };
        if let Some(item) = items.0.first() {
            let state = workspace(&mut control, item.workspace_id)?;
            let old = pane(&state)?;
            check(old.session.is_none())?;
            if old.state == PaneState::Lost {
                let value = serde_json::json!({"passed":true,"runtimeId":String::from(status.runtime_id),"oldSessionLost":true,"automaticShell":false,"inputReplayed":false});
                std::fs::write(
                    root.join("restart-proof.json"),
                    serde_json::to_vec(&value).unwrap(),
                )
                .map_err(|_| "restart evidence")?;
                return Ok(());
            }
            check(old.state == PaneState::Stopped)?;
            cli(
                &exe,
                &profile,
                &[
                    "terminal",
                    "restart",
                    "--workspace",
                    &String::from(item.workspace_id),
                    "--pane",
                    &String::from(old.pane_id),
                    "--confirm",
                    "--json",
                ],
            )?;
        } else {
            let project = root.join("workspace");
            std::fs::create_dir(&project).map_err(|_| "workspace")?;
            cli(
                &exe,
                &profile,
                &[
                    "workspace",
                    "add",
                    "--name",
                    "SCM synthetic",
                    "--path",
                    project.to_str().ok_or("path")?,
                ],
            )?;
            let LocalResult::Workspaces(items) = local(&mut control, LocalCall::Workspaces {})?
            else {
                return Err("workspace");
            };
            check(items.0.len() == 1)?;
            cli(
                &exe,
                &profile,
                &[
                    "terminal",
                    "create",
                    "--workspace",
                    &String::from(items.0[0].workspace_id),
                    "--name",
                    "SCM synthetic",
                    "--json",
                ],
            )?;
        }
        let LocalResult::Workspaces(items) = local(&mut control, LocalCall::Workspaces {})? else {
            return Err("workspace");
        };
        check(items.0.len() == 1)?;
        let id = items.0[0].workspace_id;
        let terminal = pane(&workspace(&mut control, id)?)?
            .session
            .ok_or("session")?;
        let mut owner = View::attach(&profile, &terminal)?;
        let mut observer = View::attach(&profile, &terminal)?;
        let lease = owner.claim()?;
        let send = |owner: &mut View, sequence, bytes: &[u8]| -> Result<()> {
            check(
                matches!(owner.rpc(RpcCall::TerminalInput(TerminalInputParams {
                terminal:terminal.clone(),lease:lease.lease.clone(), input_id:DecimalU64(sequence),input_seq:InputSeq(DecimalU64(sequence)),bytes:BoundedList(bytes.to_vec())
            }))?,RpcResult::TerminalInput(receipt) if receipt.accepted_bytes().get() as usize == bytes.len()),
            )
        };
        send(&mut owner, 1, b"echo SCM_PRODUCT_READY\r\n")?;
        owner.wait_marker("SCM_PRODUCT_READY")?;
        observer.wait_marker("SCM_PRODUCT_READY")?;
        owner.rpc(RpcCall::TerminalResize(TerminalResizeParams {
            terminal: terminal.clone(),
            lease: lease.lease.clone(),
            resize_seq: lease.next_resize_seq,
            columns: TerminalDimension(70),
            rows: TerminalDimension(20),
        }))?;
        let resized = View::attach(&profile, &terminal)?;
        check(resized.snapshot.rows == 20 && resized.snapshot.cols == 70)?;
        drop(resized);
        send(&mut owner, 2, b"for /l %i in (1,1,2147483647) do @rem\r\n")?;
        thread::sleep(Duration::from_millis(100));
        send(&mut owner, 3, &[3])?;
        send(&mut owner, 4, b"echo SCM_PRODUCT_CTRL_^C\r\n")?;
        owner.wait_marker("SCM_PRODUCT_CTRL_C")?;
        // Keep the ordinary shell alive for the independent SCM stop/crash test.
        drop(owner);
        drop(observer);
        let value = serde_json::json!({"passed":true,"runtimeId":String::from(status.runtime_id),"twoClients":true,"ptyInput":true,"ptyResize":true,"ptyCtrlC":true,"shellLeftAlive":true,"oldSessionLost":false,"dpapiSameAccountRoundtrip":true,"consoleAttached":false});
        std::fs::write(
            root.join("observer-proof.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .map_err(|_| "evidence")?;
        #[cfg(feature = "scm-fixture")]
        if root.join("arm-timeout").is_file() {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !root.join("trigger-timeout").is_file() {
                check(Instant::now() < deadline)?;
                thread::sleep(Duration::from_millis(20));
            }
            lomi_host::windows_service::fixture_expire_stop_deadline();
            std::fs::write(root.join("timeout-armed.json"), b"{\"passed\":true}")
                .map_err(|_| "timeout acknowledgment")?;
        }
        Ok(())
    }
}
