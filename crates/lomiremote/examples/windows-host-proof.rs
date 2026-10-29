#[cfg(not(windows))]
fn main() {}
#[cfg(windows)]
fn main() {
    if let Err(reason) = proof::run() {
        eprintln!("PRODUCT_WINDOWS_HOST_FAILURE:{}:{reason}", proof::phase());
        std::process::exit(1);
    }
}
#[cfg(windows)]
mod proof {
    use lomi_platform::windows::LocalClient;
    use lomi_remote_protocol::{ipc::*, rpc::*, streams::*, *};
    use lomi_terminal_state::{GridPatch, Snapshot};
    use std::{
        ffi::OsString,
        io::Read,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::atomic::{AtomicBool, AtomicU32, Ordering},
        thread,
        time::{Duration, Instant},
    };
    use uuid::Uuid;
    type Result<T> = std::result::Result<T, &'static str>;
    static OWNED_DIRECTORY: AtomicBool = AtomicBool::new(false);
    static PHASE: AtomicU32 = AtomicU32::new(0);
    pub fn phase() -> u32 {
        PHASE.load(Ordering::SeqCst)
    }
    fn phase_set(n: u32) {
        PHASE.store(n, Ordering::SeqCst);
        if OWNED_DIRECTORY.load(Ordering::SeqCst) {
            let _ = std::fs::write("proof-phase.txt", n.to_string());
        }
    }
    fn check(ok: bool) -> Result<()> {
        if ok {
            Ok(())
        } else {
            Err("synthetic assertion")
        }
    }
    fn safe_child_error_code(output: &[u8]) -> Option<String> {
        let value: serde_json::Value = serde_json::from_slice(output).ok()?;
        let code = value.get("error")?.get("code")?.as_str()?;
        if code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return None;
        }
        Some(code.to_owned())
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
        check(output.len() <= 131072 && error.len() <= 131072)?;
        if !status.success() {
            let exit = status
                .code()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "signal".to_owned());
            let code = safe_child_error_code(&output).unwrap_or_else(|| "UNKNOWN".to_owned());
            eprintln!(
                "PRODUCT_WINDOWS_CHILD_FAILURE:phase={}:exit={exit}:code={code}",
                phase()
            );
            return Err("owned child failure");
        }
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
    struct Guard {
        exe: PathBuf,
        profile: PathBuf,
        stopped: bool,
    }
    impl Guard {
        fn stop(&mut self) -> Result<()> {
            cli(&self.exe, &self.profile, &["daemon", "stop", "--confirm"])?;
            self.stopped = true;
            Ok(())
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if !self.stopped {
                let _ = self.stop();
            }
        }
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
    fn profile_acl(profile: &Path) -> Result<()> {
        let shell = PathBuf::from(std::env::var_os("SystemRoot").ok_or("system root")?)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let path = profile
            .to_str()
            .ok_or("synthetic profile path")?
            .replace('\'', "''");
        let script = format!(
            "$ErrorActionPreference='Stop';$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$p='{path}';$checks=@();foreach($pair in @(@('profile',''),@('db','host.sqlite3'),@('wal','host.sqlite3-wal'),@('shm','host.sqlite3-shm'))){{$n=$pair[1];$f=if($n){{Join-Path $p $n}}else{{$p}};if(!(Test-Path -LiteralPath $f)){{$checks+=@{{kind=$pair[0];exists=$false;readable=$true;owner=$true;grants=$true;protected=$false}};continue}};try{{$a=Get-Acl -LiteralPath $f;$safe=$true;foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){{if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -cne $sid){{$safe=$false}}}};$checks+=@{{kind=$pair[0];exists=$true;readable=$true;owner=($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $sid);grants=$safe;protected=$a.AreAccessRulesProtected}}}}catch{{$checks+=@{{kind=$pair[0];readable=$false;owner=$false;grants=$false;protected=$false}}}}}};@{{checks=$checks}}|ConvertTo-Json -Compress"
        );
        let output = bounded(
            &shell,
            &[
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                script.into(),
            ],
        )?;
        let value: serde_json::Value =
            serde_json::from_slice(&output).map_err(|_| "ACL metadata")?;
        let checks = value
            .get("checks")
            .and_then(|v| v.as_array())
            .ok_or("ACL metadata")?;
        let safe = checks.len() == 4
            && checks.iter().all(|v| {
                v["readable"] == true
                    && v["owner"] == true
                    && v["grants"] == true
                    && (v["exists"] == true || v["kind"] == "shm")
            })
            && (checks[0]["protected"] == true);
        if !safe {
            println!("PRODUCT_WINDOWS_ACL_CHECKS:{value}");
            return Err("profile ACL");
        }
        Ok(())
    }

    pub fn run() -> Result<()> {
        phase_set(1);
        let run = std::env::args().nth(1).ok_or("run UUID")?;
        check(Uuid::parse_str(&run).map_err(|_| "run UUID")?.to_string() == run)?;
        let root = std::env::current_dir().map_err(|_| "owned root")?;
        check(
            root.file_name().and_then(|s| s.to_str()) == Some(&format!("lomi-windows-host-{run}")),
        )?;
        OWNED_DIRECTORY.store(true, Ordering::SeqCst);
        let profile = PathBuf::from(std::env::var_os("USERPROFILE").ok_or("profile parent")?)
            .join(format!(".lomiRemote-proof-{run}"));
        let exe = root.join("target/debug/lomiremote.exe");
        match std::env::args().nth(2).as_deref() {
            Some("continuity-start") => {
                phase_set(101);
                check(profile.is_dir())?;
                cli(&exe, &profile, &["daemon", "start"])?;
                let mut client = connect(&profile)?;
                let LocalResult::Status(status) = local(&mut client, LocalCall::Status {})? else {
                    return Err("continuity status");
                };
                println!(
                    "{}",
                    serde_json::json!({"hostId":String::from(status.host_id),"runtimeId":String::from(status.runtime_id),"continuityStarted":true})
                );
                return Ok(());
            }
            Some("continuity-stop") => {
                phase_set(102);
                let expected =
                    RuntimeId::try_from(std::env::args().nth(3).ok_or("expected runtime")?)
                        .map_err(|_| "expected runtime")?;
                let mut client = connect(&profile)?;
                let LocalResult::Status(status) = local(&mut client, LocalCall::Status {})? else {
                    return Err("continuity status");
                };
                check(status.runtime_id == expected)?;
                let LocalResult::Workspaces(items) = local(&mut client, LocalCall::Workspaces {})?
                else {
                    return Err("continuity workspaces");
                };
                check(items.0.len() == 1)?;
                drop(client);
                cli(&exe, &profile, &["daemon", "stop", "--confirm"])?;
                check(connect(&profile).is_err())?;
                println!(
                    "{}",
                    serde_json::json!({"hostId":String::from(status.host_id),"runtimeId":String::from(status.runtime_id),"continuityStopped":true})
                );
                return Ok(());
            }
            Some(_) => return Err("unexpected proof mode"),
            None => (),
        }
        check(!profile.exists())?;
        let project = root.join("synthetic-workspace");
        std::fs::create_dir(&project).map_err(|_| "owned workspace")?;
        let mut guard = Guard {
            exe: exe.clone(),
            profile: profile.clone(),
            stopped: false,
        };
        phase_set(2);
        cli(&exe, &profile, &["daemon", "start"])?;
        phase_set(3);
        cli(&exe, &profile, &["status", "--json"])?;
        cli(&exe, &profile, &["doctor", "--json"])?;
        cli(
            &exe,
            &profile,
            &[
                "workspace",
                "add",
                "--name",
                "Synthetic Windows proof",
                "--path",
                project.to_str().ok_or("workspace path")?,
            ],
        )?;
        cli(&exe, &profile, &["workspace", "list", "--json"])?;
        let mut control = connect(&profile)?;
        let LocalResult::Status(status) = local(&mut control, LocalCall::Status {})? else {
            return Err("status");
        };
        let LocalResult::Workspaces(workspaces) = local(&mut control, LocalCall::Workspaces {})?
        else {
            return Err("workspaces");
        };
        check(workspaces.0.len() == 1)?;
        let id = workspaces.0[0].workspace_id;
        phase_set(4);
        cli(
            &exe,
            &profile,
            &[
                "terminal",
                "create",
                "--workspace",
                &String::from(id),
                "--name",
                "Synthetic terminal",
                "--json",
            ],
        )?;
        cli(
            &exe,
            &profile,
            &[
                "terminal",
                "list",
                "--workspace",
                &String::from(id),
                "--json",
            ],
        )?;
        let state = workspace(&mut control, id)?;
        let first = pane(&state)?;
        let terminal = first.session.clone().ok_or("current session")?;
        phase_set(5);
        profile_acl(&profile)?;
        phase_set(6);
        let mut owner = View::attach(&profile, &terminal)?;
        let mut observer = View::attach(&profile, &terminal)?;
        let lease = owner.claim()?;
        phase_set(7);
        check(matches!(
            observer.rpc_response(
                RpcCall::TerminalClaim(TerminalClaimParams {
                    terminal: terminal.clone(),
                    subscription_id: observer.metadata.subscription_id.clone(),
                    rendered_through_seq: observer.metadata.through_seq
                })
            )?,
            RpcResponse::Error {error,..} if error.code()==ErrorCode::ControlRequired
        ))?;
        let input = RpcCall::TerminalInput(TerminalInputParams {
            terminal: terminal.clone(),
            lease: lease.lease.clone(),
            input_id: lease.next_input_id,
            input_seq: lease.next_input_seq,
            bytes: BoundedList(b"set /a LOMI_PROOF_COUNTER+=1\r\necho PRODUCT_WINDOWS_COUNTER_%LOMI_PROOF_COUNTER%\r\n".to_vec()),
        });
        let submitted = match &input {
            RpcCall::TerminalInput(params) => params.bytes.0.len(),
            _ => unreachable!(),
        };
        let first = owner.rpc(input.clone())?;
        check(
            matches!(&first,RpcResult::TerminalInput(receipt) if receipt.accepted_bytes().get() as usize==submitted),
        )?;
        check(owner.rpc(input)? == first)?;
        phase_set(8);
        owner.wait_marker("PRODUCT_WINDOWS_COUNTER_1")?;
        observer.wait_marker("PRODUCT_WINDOWS_COUNTER_1")?;
        phase_set(9);
        owner.rpc(RpcCall::TerminalResize(TerminalResizeParams {
            terminal: terminal.clone(),
            lease: lease.lease.clone(),
            resize_seq: lease.next_resize_seq,
            columns: TerminalDimension(70),
            rows: TerminalDimension(20),
        }))?;
        // Read-only reconnection proves the host model retains the native resize.
        let resized = View::attach(&profile, &terminal)?;
        check(resized.snapshot.rows == 20 && resized.snapshot.cols == 70)?;
        let text: String = resized
            .snapshot
            .normal
            .lines
            .iter()
            .flat_map(|row| row.cells.iter().map(|cell| cell.text.as_str()))
            .collect();
        check(!text.contains("PRODUCT_WINDOWS_COUNTER_2"))?;
        drop(resized);
        phase_set(10);
        let lease = match owner.rpc(RpcCall::TerminalRenew(TerminalLeaseParams {
            terminal: terminal.clone(),
            lease: lease.lease,
        }))? {
            RpcResult::TerminalRenew(lease) => lease,
            _ => return Err("lease renewal"),
        };
        let mut send = |sequence: u64, bytes: &[u8]| -> Result<()> {
            let result = owner.rpc(RpcCall::TerminalInput(TerminalInputParams {
                terminal: terminal.clone(),
                lease: lease.lease.clone(),
                input_id: DecimalU64(sequence),
                input_seq: InputSeq(DecimalU64(sequence)),
                bytes: BoundedList(bytes.to_vec()),
            }))?;
            match result {
                RpcResult::TerminalInput(receipt) => {
                    check(receipt.accepted_bytes().get() as usize == bytes.len())
                }
                _ => Err("input receipt"),
            }
        };
        send(2, b"for /l %i in (1,1,2147483647) do @rem\r\n")?;
        thread::sleep(Duration::from_millis(100));
        send(3, &[3])?;
        send(4, b"echo PRODUCT_WINDOWS_CTRL_^C\r\n")?;
        owner.wait_marker("PRODUCT_WINDOWS_CTRL_C")?;
        owner.rpc(RpcCall::TerminalInput(TerminalInputParams {
            terminal: terminal.clone(),
            lease: lease.lease,
            input_id: DecimalU64(5),
            input_seq: InputSeq(DecimalU64(5)),
            bytes: BoundedList(b"exit\r\n".to_vec()),
        }))?;
        drop(owner);
        drop(observer);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = workspace(&mut control, id)?;
            if pane(&state)?.state == PaneState::Exited {
                break;
            }
            check(Instant::now() < deadline)?;
            thread::sleep(Duration::from_millis(20));
        }
        phase_set(11);
        cli(
            &exe,
            &profile,
            &[
                "terminal",
                "restart",
                "--workspace",
                &String::from(id),
                "--pane",
                &String::from(terminal.pane_id),
                "--confirm",
                "--json",
            ],
        )?;
        let restarted = pane(&workspace(&mut control, id)?)?
            .session
            .ok_or("restarted session")?;
        check(
            restarted.session_id != terminal.session_id
                && restarted.session_epoch != terminal.session_epoch,
        )?;
        let view = View::attach(&profile, &restarted)?;
        drop(view);
        phase_set(12);
        cli(
            &exe,
            &profile,
            &[
                "terminal",
                "close",
                "--workspace",
                &String::from(id),
                "--pane",
                &String::from(terminal.pane_id),
                "--confirm",
                "--json",
            ],
        )?;
        phase_set(13);
        drop(control);
        guard.stop()?;
        phase_set(14);
        cli(&exe, &profile, &["daemon", "start"])?;
        guard.stopped = false;
        let mut client = connect(&profile)?;
        let LocalResult::Status(after) = local(&mut client, LocalCall::Status {})? else {
            return Err("restart status");
        };
        check(after.host_id == status.host_id && after.runtime_id != status.runtime_id)?;
        check(workspace(&mut client, id)?.tabs.0.is_empty())?;
        drop(client);
        profile_acl(&profile)?;
        phase_set(15);
        guard.stop()?;
        println!("PRODUCT_WINDOWS_PROFILE_ACL_PASS\nPRODUCT_WINDOWS_HOST_PASS");
        Ok(())
    }
}
