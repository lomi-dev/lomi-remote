//! Explicit local terminal actions. Reads never create sessions; mutations are
//! sent once with a fresh operation identity and the inspected domain CAS.
use clap::ArgMatches;
#[cfg(unix)]
pub use lomi_platform::unix::{Error as TransportError, LocalClient};
#[cfg(windows)]
pub use lomi_platform::windows::{Error as TransportError, LocalClient};
use lomi_remote_protocol::{ipc::*, rpc::*, *};
use std::{io, path::Path};
use uuid::Uuid;

#[cfg(target_os = "macos")]
pub fn connect_installed_macos_host(profile: &Path) -> Result<LocalClient, &'static str> {
    lomi_platform::service_macos::custody::prepare_current_user_host_profile(profile)
        .map_err(|_| "MACOS_ADMIN_INSTALL_REQUIRED")?;
    let executable =
        lomi_platform::service_macos::custody::installed_privileged_host_executable(profile)
            .map_err(|_| "MACOS_ADMIN_INSTALL_REQUIRED")?;
    let client = LocalClient::connect(profile).map_err(|error| match error {
        TransportError::PermissionDenied => "LOCAL_PERMISSION_DENIED",
        TransportError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            "LOCAL_PERMISSION_DENIED"
        }
        TransportError::Incompatible => "UPDATE_REQUIRED",
        TransportError::InvalidProfile
        | TransportError::InvalidEndpoint
        | TransportError::InvalidFrame => "INVALID_LOCAL_PROFILE",
        _ => "DAEMON_UNAVAILABLE",
    })?;
    client
        .verify_macos_host_executable(profile, &executable)
        .map_err(|_| "UPDATE_REQUIRED")?;
    Ok(client)
}

#[derive(Debug)]
pub struct Failure {
    pub code: String,
    pub exit: u8,
    pub operation: Option<OperationId>,
}
impl Failure {
    pub fn new(code: &str, exit: u8) -> Self {
        Self {
            code: code.to_owned(),
            exit,
            operation: None,
        }
    }
    pub fn invalid() -> Self {
        Self::new("INVALID_ARGUMENT", 2)
    }
    pub fn connect(error: TransportError) -> Self {
        match error {
            TransportError::PermissionDenied => Self::new("LOCAL_PERMISSION_DENIED", 5),
            TransportError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                Self::new("LOCAL_PERMISSION_DENIED", 5)
            }
            TransportError::Incompatible => Self::new("UPDATE_REQUIRED", 6),
            TransportError::InvalidProfile
            | TransportError::InvalidEndpoint
            | TransportError::InvalidFrame => Self::new("INVALID_LOCAL_PROFILE", 5),
            _ => Self::transport(None),
        }
    }
    pub fn transport(operation: Option<OperationId>) -> Self {
        Self {
            code: if operation.is_some() {
                "OUTCOME_UNKNOWN"
            } else {
                "DAEMON_UNAVAILABLE"
            }
            .to_owned(),
            exit: if operation.is_some() { 7 } else { 4 },
            operation,
        }
    }
}
pub fn request(call: RpcCall) -> RpcRequest {
    RpcRequest {
        v: ApplicationMajor,
        r#type: RequestKind::Request,
        request_id: Uuid::new_v4()
            .simple()
            .to_string()
            .try_into()
            .expect("generated request ID"),
        timeout_ms: TimeoutMs::new(10000).expect("fixed budget"),
        call,
    }
}
pub fn result(
    response: LocalResponse,
    operation: Option<OperationId>,
) -> Result<RpcResult, Failure> {
    match response.result {
        Ok(LocalResult::Rpc(reply)) => match *reply {
            RpcResponse::Result { result, .. } => Ok(result),
            RpcResponse::Error { error, .. } => {
                let code = serde_json::to_value(error.code())
                    .expect("closed code")
                    .as_str()
                    .expect("string code")
                    .to_owned();
                let exit = if error.effect() != Effect::None {
                    7
                } else {
                    match error.http_status() {
                        400 | 409 => 2,
                        401 => 3,
                        403 => 5,
                        426 => 6,
                        _ => 4,
                    }
                };
                Err(Failure {
                    code,
                    exit,
                    operation,
                })
            }
        },
        _ => Err(Failure::transport(operation)),
    }
}
pub fn rpc(client: &mut LocalClient, call: RpcCall) -> Result<RpcResult, Failure> {
    call.validate().map_err(|_| Failure::invalid())?;
    let operation = call.operation_binding().map(|binding| binding.operation_id);
    let response = client
        .request(LocalCall::Rpc(Box::new(request(call))))
        .map_err(|_| Failure::transport(operation))?;
    result(response, operation)
}
pub fn inspect(client: &mut LocalClient, id: WorkspaceId) -> Result<WorkspaceState, Failure> {
    match client
        .request(LocalCall::WorkspaceInspect(LocalWorkspaceRead {
            workspace_id: id,
        }))
        .map_err(|_| Failure::transport(None))?
        .result
    {
        Ok(LocalResult::WorkspaceState(state)) => Ok(*state),
        _ => Err(Failure::new("WORKSPACE_UNAVAILABLE", 4)),
    }
}
pub fn pane(state: &WorkspaceState, id: PaneId) -> Option<(TabId, &TerminalPane)> {
    fn find(node: &TerminalLayout, id: PaneId) -> Option<&TerminalPane> {
        match node {
            TerminalLayout::Pane { pane } if pane.pane_id == id => Some(pane),
            TerminalLayout::Pane { .. } => None,
            TerminalLayout::Split { first, second, .. } => {
                find(first, id).or_else(|| find(second, id))
            }
        }
    }
    state
        .tabs
        .0
        .iter()
        .find_map(|tab| find(&tab.layout, id).map(|pane| (tab.tab_id, pane)))
}
fn argument<T: TryFrom<String>>(args: &ArgMatches, name: &str) -> Result<T, Failure> {
    args.get_one::<String>(name)
        .ok_or_else(Failure::invalid)?
        .clone()
        .try_into()
        .map_err(|_| Failure::invalid())
}
fn build(state: &WorkspaceState, action: &str, args: &ArgMatches) -> Result<RpcCall, Failure> {
    if matches!(action, "close" | "restart") && !args.get_flag("confirm") {
        return Err(Failure::new("CONFIRMATION_REQUIRED", 2));
    }
    let mutation = MutationContext {
        operation_id: OperationId::from_bytes(*Uuid::new_v4().as_bytes()).expect("UUID"),
        context: state.context.clone(),
        expected_revision: state.domain_revision,
    };
    Ok(match action {
        "create" => RpcCall::TerminalCreate(TerminalCreateParams {
            mutation,
            tab_name: argument(args, "name")?,
            profile_id: argument(args, "profile")?,
        }),
        "split" => {
            let id = argument(args, "pane")?;
            let (tab_id, _) = pane(state, id).ok_or_else(Failure::invalid)?;
            RpcCall::TerminalSplit(TerminalSplitParams {
                mutation,
                tab_id,
                pane_id: id,
                profile_id: argument(args, "profile")?,
                axis: if args.get_one::<String>("axis").map(String::as_str) == Some("vertical") {
                    SplitAxis::Vertical
                } else {
                    SplitAxis::Horizontal
                },
            })
        }
        "rename" => {
            let tab_id = argument(args, "tab")?;
            if !state.tabs.0.iter().any(|tab| tab.tab_id == tab_id) {
                return Err(Failure::invalid());
            }
            RpcCall::TerminalRename(TerminalRenameParams {
                mutation,
                tab_id,
                name: argument(args, "name")?,
            })
        }
        "move" => {
            let pane_id = argument(args, "pane")?;
            let target_pane_id = argument(args, "target-pane")?;
            let (source_tab_id, _) = pane(state, pane_id).ok_or_else(Failure::invalid)?;
            let (target_tab_id, _) = pane(state, target_pane_id).ok_or_else(Failure::invalid)?;
            RpcCall::TerminalMove(TerminalMoveParams {
                mutation,
                pane_id,
                source_tab_id,
                target_tab_id,
                target_pane_id,
                placement: if args.get_one::<String>("placement").map(String::as_str)
                    == Some("before")
                {
                    MovePlacement::Before
                } else {
                    MovePlacement::After
                },
            })
        }
        "close" => {
            let pane_id = argument(args, "pane")?;
            let expected_session = pane(state, pane_id)
                .ok_or_else(Failure::invalid)?
                .1
                .session
                .clone();
            RpcCall::TerminalClose(TerminalCloseParams {
                mutation,
                pane_id,
                expected_session,
            })
        }
        "restart" => {
            let pane_id = argument(args, "pane")?;
            let expected_session = pane(state, pane_id)
                .ok_or_else(Failure::invalid)?
                .1
                .session
                .clone();
            RpcCall::TerminalRestart(TerminalRestartParams {
                mutation,
                pane_id,
                expected_session,
                profile_id: argument(args, "profile")?,
            })
        }
        _ => return Err(Failure::invalid()),
    })
}
fn execute(profile: &Path, args: &ArgMatches) -> Result<(serde_json::Value, u8), Failure> {
    let (action, args) = args.subcommand().ok_or_else(Failure::invalid)?;
    if action == "attach" {
        return crate::attach::run(
            profile,
            argument(args, "workspace")?,
            argument(args, "pane")?,
            args.get_flag("control"),
        )
        .map(|()| (serde_json::Value::Null, 0));
    }
    if matches!(action, "close" | "restart") && !args.get_flag("confirm") {
        return Err(Failure::new("CONFIRMATION_REQUIRED", 2));
    }
    #[cfg(target_os = "macos")]
    let mut client = connect_installed_macos_host(profile)
        .map_err(|code| Failure::new(code, host_failure_exit(code)))?;
    #[cfg(not(target_os = "macos"))]
    let mut client = LocalClient::connect(profile).map_err(Failure::connect)?;
    let state = inspect(&mut client, argument(args, "workspace")?)?;
    if action == "list" {
        return Ok((serde_json::json!({"v":2,"state":state}), 0));
    }
    let call = build(&state, action, args)?;
    let operation = call.operation_binding().map(|binding| binding.operation_id);
    let result = rpc(&mut client, call)?;
    let exit = match result.receipt() {
        Some(receipt)
            if receipt.state() == OperationState::OutcomeUnknown
                || receipt.effect() == Effect::Partial =>
        {
            7
        }
        Some(receipt)
            if matches!(
                receipt.state(),
                OperationState::Failed | OperationState::Cancelled
            ) =>
        {
            4
        }
        _ => 0,
    };
    Ok((
        serde_json::json!({"v":2,"operationId":operation,"result":result}),
        exit,
    ))
}

#[cfg(target_os = "macos")]
pub(super) fn host_failure_exit(code: &str) -> u8 {
    match code {
        "UPDATE_REQUIRED" => 6,
        "LOCAL_PERMISSION_DENIED" | "INVALID_LOCAL_PROFILE" => 5,
        _ => 4,
    }
}
pub fn run(profile: &Path, args: &ArgMatches) -> u8 {
    let json = args
        .subcommand()
        .is_some_and(|(action, args)| action != "attach" && args.get_flag("json"));
    match execute(profile, args) {
        Ok((value, exit)) => {
            if value.is_null() {
                return exit;
            }
            if json {
                if serde_json::to_writer(io::stdout().lock(), &value).is_err() {
                    return 4;
                }
                println!();
            } else if let Some(state) = value.get("state") {
                let state: WorkspaceState =
                    serde_json::from_value(state.clone()).expect("typed state");
                for tab in state.tabs.0 {
                    let mut pending = vec![&tab.layout];
                    while let Some(node) = pending.pop() {
                        match node {
                            TerminalLayout::Pane { pane } => println!(
                                "{}  {}  {:?}  {}",
                                String::from(tab.tab_id),
                                String::from(pane.pane_id),
                                pane.state,
                                crate::ui::safe_label(tab.name.as_str())
                            ),
                            TerminalLayout::Split { first, second, .. } => {
                                pending.push(second);
                                pending.push(first);
                            }
                        }
                    }
                }
            } else {
                println!(
                    "Operation {}: {}",
                    value["operationId"].as_str().unwrap_or("unknown"),
                    value["result"]["params"]["state"]
                        .as_str()
                        .unwrap_or("accepted")
                );
            }
            exit
        }
        Err(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"v":2,"error":{"code":error.code},"operationId":error.operation})
                );
            } else {
                match error.code.as_str() {
                    "MACOS_ADMIN_INSTALL_REQUIRED" => eprintln!(
                        "{}: install the signed Lomi Remote administrator Host for this account",
                        error.code
                    ),
                    "UPDATE_REQUIRED" => eprintln!(
                        "{}: run `daemon stop --confirm` with the installed CLI, then retry; this ends Host terminal sessions while private editor drafts remain on this device",
                        error.code
                    ),
                    _ => eprintln!("{}", error.code),
                }
                if let Some(id) = error.operation {
                    eprintln!("Operation ID: {}", String::from(id));
                }
            }
            error.exit
        }
    }
}
