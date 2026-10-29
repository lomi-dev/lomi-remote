use lomi_remote_protocol::ipc::*;
use lomi_remote_protocol::*;
use schemars::JsonSchema;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

// Schema catalog only: this aggregate is not an application message or API DTO.
#[allow(dead_code)]
#[derive(JsonSchema)]
struct FoundationTypes {
    account_id: AccountId,
    host_id: HostId,
    host_authorization_id: HostAuthorizationId,
    consumer_authorization_id: ConsumerAuthorizationId,
    window_identity_id: WindowIdentityId,
    grant_id: GrantId,
    workspace_id: WorkspaceId,
    workspace_epoch: WorkspaceEpoch,
    runtime_id: RuntimeId,
    operation_id: OperationId,
    channel_id: ChannelId,
    pane_id: PaneId,
    terminal_session_id: TerminalSessionId,
    session_epoch: SessionEpoch,
    tab_id: TabId,
    entry_id: EntryId,
    repository_id: RepositoryId,
    pairing_id: PairingId,
    enrollment_id: EnrollmentId,
    request_id: RequestId,
    account_session_id: AccountSessionId,
    event_cursor: EventCursor,
    file_revision: FileRevision,
    repo_state_token: RepoStateToken,
    versions: VersionAxes,
    method: Method,
    decimal_u64: DecimalU64,
}
fn pretty(value: &impl serde::Serialize) -> Result<String, serde_json::Error> {
    Ok(format!("{}\n", serde_json::to_string_pretty(value)?))
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn codec_fixtures() -> Result<String, Box<dyn std::error::Error>> {
    use serde_json::Value;
    const ID: &str = "11111111-1111-4111-8111-111111111111";
    fn context() -> Value {
        json!({"workspaceId":ID,"workspaceEpoch":ID,"runtimeId":ID,"runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"})
    }
    fn mutation() -> Value {
        json!({"operationId":ID,"context":context(),"expectedRevision":"1"})
    }
    fn file_mutation() -> Value {
        json!({"operationId":ID,"context":context()})
    }
    fn terminal() -> Value {
        json!({"workspace":context(),"paneId":ID,"sessionId":ID,"sessionEpoch":ID,"profile":"lomi-rust-grid-v1-experimental"})
    }
    fn lease() -> Value {
        json!({"token":"lease-token","version":"1"})
    }
    fn request(method: &str, params: Value) -> Value {
        json!({"v":2,"type":"request","requestId":"req-1","timeoutMs":10000,"call":{"method":method,"params":params}})
    }
    fn create() -> Value {
        json!({"mutation":file_mutation(),"parentEntryId":ID,"parentRevision":"revision","name":"new.txt","destination":"absent"})
    }
    fn network() -> Value {
        json!({"mutation":file_mutation(),"repositoryId":ID,"remoteId":"remote-main","refId":"ref-main","expectedRefs":"refs"})
    }
    let expected = json!({"head":"head","index":"index"});
    let mut cases = vec![
        ("workspace.get", json!({"context":context()})),
        ("workspace.capabilities", json!({"context":context()})),
        (
            "workspace.subscribe",
            json!({"context":context(),"cursor":null}),
        ),
        (
            "terminal.create",
            json!({"mutation":mutation(),"tabName":"Build","profileId":"default"}),
        ),
        (
            "terminal.split",
            json!({"mutation":mutation(),"tabId":ID,"paneId":ID,"axis":"horizontal","profileId":"default"}),
        ),
        (
            "terminal.rename",
            json!({"mutation":mutation(),"tabId":ID,"name":"Build"}),
        ),
        (
            "terminal.move",
            json!({"mutation":mutation(),"paneId":ID,"sourceTabId":ID,"targetTabId":ID,"targetPaneId":ID,"placement":"after"}),
        ),
        (
            "terminal.close",
            json!({"mutation":mutation(),"paneId":ID,"expectedSession":terminal()}),
        ),
        (
            "terminal.restart",
            json!({"mutation":mutation(),"paneId":ID,"expectedSession":terminal(),"profileId":"default"}),
        ),
        ("terminal.attach", json!({"terminal":terminal()})),
        ("terminal.snapshot", json!({"terminal":terminal()})),
        (
            "terminal.ack",
            json!({"terminal":terminal(),"subscriptionId":"sub","throughSeq":"3"}),
        ),
        (
            "terminal.claim",
            json!({"terminal":terminal(),"subscriptionId":"sub","renderedThroughSeq":"3"}),
        ),
        (
            "terminal.renew",
            json!({"terminal":terminal(),"lease":lease()}),
        ),
        (
            "terminal.release",
            json!({"terminal":terminal(),"lease":lease()}),
        ),
        (
            "terminal.input",
            json!({"terminal":terminal(),"lease":lease(),"inputId":"1","inputSeq":"1","bytes":[65]}),
        ),
        (
            "terminal.resize",
            json!({"terminal":terminal(),"lease":lease(),"resizeSeq":"1","columns":80,"rows":24}),
        ),
        (
            "files.list",
            json!({"context":context(),"parentEntryId":ID,"cursor":null,"limit":200}),
        ),
        (
            "files.stat",
            json!({"context":context(),"entryId":ID,"fileRevision":null}),
        ),
        (
            "files.read",
            json!({"context":context(),"entryId":ID,"fileRevision":"rev","offset":"0","maxBytes":1048576}),
        ),
        (
            "files.searchNames",
            json!({"context":context(),"parentEntryId":ID,"query":"test","cursor":null,"limit":20}),
        ),
        (
            "files.watch",
            json!({"context":context(),"entryId":ID,"cursor":null}),
        ),
        ("files.create", create()),
        ("files.mkdir", create()),
        (
            "files.rename",
            json!({"mutation":file_mutation(),"entryId":ID,"fileRevision":"rev","sourceParentId":ID,"sourceParentRevision":"rev","targetParentId":ID,"targetParentRevision":"rev","name":"new","destination":"absent"}),
        ),
        (
            "files.remove",
            json!({"mutation":file_mutation(),"entryId":ID,"fileRevision":"rev","parentEntryId":ID,"parentRevision":"rev","confirmation":"confirmed"}),
        ),
        ("git.repositories", json!({"context":context()})),
        (
            "git.status",
            json!({"context":context(),"repositoryId":ID,"stateToken":null,"cursor":null,"limit":10}),
        ),
        (
            "git.diff",
            json!({"context":context(),"repositoryId":ID,"stateToken":"state","entryId":null,"view":"worktree","cursor":null,"limit":10}),
        ),
        (
            "git.log",
            json!({"context":context(),"repositoryId":ID,"stateToken":"state","cursor":null,"limit":10}),
        ),
        (
            "git.show",
            json!({"context":context(),"repositoryId":ID,"stateToken":"state","objectId":"object","cursor":null,"limit":10}),
        ),
        (
            "git.stage",
            json!({"mutation":file_mutation(),"repositoryId":ID,"expected":expected,"paths":[{"entryId":ID,"fileRevision":"rev"}]}),
        ),
        (
            "git.unstage",
            json!({"mutation":file_mutation(),"repositoryId":ID,"expected":expected,"paths":[ID]}),
        ),
        (
            "git.commit",
            json!({"mutation":file_mutation(),"repositoryId":ID,"expected":expected,"message":"Add feature"}),
        ),
        ("git.fetch", network()),
        ("git.push", network()),
        (
            "operation.status",
            json!({"context":context(),"operationId":ID}),
        ),
        (
            "operation.cancel",
            json!({"context":context(),"operationId":ID}),
        ),
    ];
    let mut pull = network();
    pull["expected"] = expected;
    pull["expectedWorktree"] = json!("worktree");
    pull["mode"] = json!("ff-only");
    cases.push(("git.pull", pull));

    let mut fixtures = Vec::new();
    for (method, params) in cases {
        let positive = request(method, params);
        let mut unknown = positive.clone();
        unknown["call"]["params"]["forbiddenExtra"] = json!(true);
        for (suffix, value, accepted) in
            [("valid", positive, true), ("unknown-field", unknown, false)]
        {
            let actual = decode_request(&serde_json::to_vec(&value)?).is_ok();
            if actual != accepted {
                return Err(format!("Rust fixture expectation failed: {method}/{suffix}").into());
            }
            fixtures.push(json!({"name":format!("{method}/{suffix}"),"schema":"rpc-request","value":value,"accepted":accepted}));
        }
    }
    let mut trailing = request("workspace.get", json!({"context":context()}));
    trailing["call"]["params"]["context"]["runtimeGeneration"] = json!("1\n");
    if decode_request(&serde_json::to_vec(&trailing)?).is_ok() {
        return Err("u64 trailing newline accepted".into());
    }
    fixtures.push(json!({"name":"decimal-u64-trailing-newline","schema":"rpc-request","value":trailing,"accepted":false}));
    let base = request("files.create", create());
    for (key, value) in [
        ("content", json!("private")),
        ("url", json!("https://example.invalid")),
        ("command", json!("execute")),
        ("recursive", json!(true)),
    ] {
        let mut negative = base.clone();
        negative["call"]["params"][key] = value;
        if decode_request(&serde_json::to_vec(&negative)?).is_ok() {
            return Err("forbidden file fixture accepted".into());
        }
        fixtures.push(json!({"name":format!("files.create/forbid-{key}"),"schema":"rpc-request","value":negative,"accepted":false}));
    }
    let mut numeric = request("workspace.get", json!({"context":context()}));
    numeric["call"]["params"]["context"]["runtimeGeneration"] = json!(1);
    if decode_request(&serde_json::to_vec(&numeric)?).is_ok() {
        return Err("numeric u64 fixture accepted".into());
    }
    fixtures.push(
        json!({"name":"numeric-u64","schema":"rpc-request","value":numeric,"accepted":false}),
    );
    for (name, value) in [(
        "workspace-stream-frame",
        json!({"type":"event","data":{"context":context(),"subscriptionId":"sub","eventSeq":"1","cursor":"cursor","data":{"kind":"cursor.advance","data":{}}}}),
    )] {
        for (suffix, mut value, accepted) in
            [("valid", value.clone(), true), ("unknown", value, false)]
        {
            if !accepted {
                value["data"]["forbidden"] = json!(true);
            }
            if decode_workspace_frame(&serde_json::to_vec(&value)?).is_ok() != accepted {
                return Err("workspace frame fixture mismatch".into());
            }
            fixtures.push(json!({"name":format!("{name}/{suffix}"),"schema":name,"value":value,"accepted":accepted}));
        }
    }
    fn terminal_checked(bytes: &[u8]) -> bool {
        decode_terminal_frame(bytes).is_ok()
    }
    fn watch_checked(bytes: &[u8]) -> bool {
        decode_watch_frame(bytes).is_ok()
    }
    for (name, positive, checked) in [
        (
            "terminal-stream-frame",
            json!({"type":"delta","data":{"terminal":terminal(),"subscriptionId":"sub","seq":"1","change":{"kind":"grid","data":[1]}}}),
            terminal_checked as fn(&[u8]) -> bool,
        ),
        (
            "file-watch-frame",
            json!({"type":"invalidated","data":{"context":context(),"subscriptionId":"sub","watchSeq":"1","cursor":"cursor","invalidation":{"entries":[],"overflow":false}}}),
            watch_checked as fn(&[u8]) -> bool,
        ),
    ] {
        for (suffix, mut value, accepted) in [
            ("valid", positive.clone(), true),
            ("unknown", positive.clone(), false),
            ("zero-sequence", positive, false),
        ] {
            if suffix == "unknown" {
                value["data"]["forbidden"] = json!(true);
            }
            if suffix == "zero-sequence" {
                let field = if name == "file-watch-frame" {
                    "watchSeq"
                } else {
                    "seq"
                };
                value["data"][field] = json!("0");
            }
            if checked(&serde_json::to_vec(&value)?) != accepted {
                return Err("stream fixture mismatch".into());
            }
            fixtures.push(json!({"name":format!("{name}/{suffix}"),"schema":name,"value":value,"schemaAccepted":suffix!="unknown","accepted":accepted}));
        }
    }
    let file_request = request(
        "files.read",
        json!({"context":context(),"entryId":ID,"fileRevision":"rev","offset":"0","maxBytes":1}),
    );
    let metadata = json!({"entryId":ID,"pathId":"encoded-path","displayName":"safe","kind":"file","fileRevision":"rev","size":"2"});
    let file_response = json!({"type":"result","v":2,"requestId":"req-1","result":{"method":"files.read","params":{"metadata":metadata,"encoding":"utf8","lineEndings":"lf","offset":"0","bytes":[65],"truncated":true}}});
    for (suffix, mut response, accepted) in [
        ("valid", file_response.clone(), true),
        ("wrong-id", file_response.clone(), false),
        ("page-budget", file_response.clone(), false),
        ("wrong-revision", file_response.clone(), false),
        ("binary-content", file_response, false),
    ] {
        match suffix {
            "wrong-id" => response["requestId"] = json!("other"),
            "page-budget" => response["result"]["params"]["bytes"] = json!([65, 66]),
            "wrong-revision" => {
                response["result"]["params"]["metadata"]["fileRevision"] = json!("other")
            }
            "binary-content" => response["result"]["params"]["encoding"] = json!("binary"),
            _ => {}
        }
        let req = decode_request(&serde_json::to_vec(&file_request)?)?;
        if rpc::decode_response_for(&serde_json::to_vec(&response)?, &req).is_ok() != accepted {
            return Err("response correlation fixture mismatch".into());
        }
        fixtures.push(json!({"name":format!("files.read/correlate-{suffix}"),"schema":"rpc-response","request":file_request,"value":response,"schemaAccepted":true,"accepted":accepted}));
    }
    let safe_error = serde_json::to_value(RemoteError::new(
        ErrorCode::InvalidArgument,
        false,
        Effect::None,
        ErrorDetails::empty(),
        None,
    )?)?;
    fixtures.push(json!({"name":"remote-error/valid","schema":"remote-error","value":safe_error,"accepted":true}));
    for (field, value) in [
        ("message", json!("untrusted private message")),
        (
            "details",
            json!({"expectedRevision":"1","actualRevision":"2"}),
        ),
        ("effect", json!("unknown")),
        ("retryable", json!(true)),
    ] {
        let mut negative = safe_error.clone();
        negative[field] = value;
        if serde_json::from_value::<RemoteError>(negative.clone()).is_ok() {
            return Err("canonical error fixture accepted".into());
        }
        fixtures.push(json!({"name":format!("remote-error/semantic-{field}"),"schema":"remote-error","value":negative,"schemaAccepted":true,"accepted":false}));
    }
    let rights = StoredOperationRights::new(
        OperationId::from_bytes([1; 16])?,
        ConsumerAuthorizationId::from_bytes([2; 16])?,
        WorkspaceId::from_bytes([3; 16])?,
        Method::FilesCreate,
        CapabilitySet::control_with_workspace_tools(),
        false,
    )?;
    let receipt = serde_json::to_value(OperationReceipt::new(
        &rights,
        "a".repeat(64).try_into()?,
        OperationState::Succeeded,
        false,
        Effect::Committed,
        Some(OperationResult::File {
            entry_id: EntryId::from_bytes([4; 16])?,
            file_revision: "revision".to_owned().try_into()?,
        }),
    )?)?;
    fixtures.push(json!({"name":"operation-receipt/valid","schema":"operation-receipt","value":receipt,"accepted":true}));
    for (field, value) in [
        ("state", json!("cancelled")),
        ("effect", json!("none")),
        ("originalMethod", json!("files.read")),
        ("repositoryExecution", json!(true)),
    ] {
        let mut negative = receipt.clone();
        negative[field] = value;
        if serde_json::from_value::<OperationReceipt>(negative.clone()).is_ok() {
            return Err("canonical receipt fixture accepted".into());
        }
        fixtures.push(json!({"name":format!("operation-receipt/semantic-{field}"),"schema":"operation-receipt","value":negative,"schemaAccepted":true,"accepted":false}));
    }
    // Required E1 claim/renew counters share exact fixtures with Rust and clients.
    let lease_fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/rpc-streams/lease-watermarks.json"
    ))?;
    for fixture in lease_fixtures {
        let request = decode_request(&serde_json::to_vec(&fixture["request"])?)?;
        let accepted =
            rpc::decode_response_for(&serde_json::to_vec(&fixture["value"])?, &request).is_ok();
        if Some(accepted) != fixture["accepted"].as_bool() {
            return Err("lease fixture expectation failed".into());
        }
        fixtures.push(fixture);
    }
    // E1 wire cases are one source for native, WASM, SDK and real-browser parity.
    let e1_fixtures: Vec<Value> =
        serde_json::from_str(include_str!("../../../../contracts/fixtures/e1/wire.json"))?;
    for fixture in e1_fixtures {
        let value = &fixture["value"];
        let bytes = serde_json::to_vec(value)?;
        let accepted = match fixture["schema"]
            .as_str()
            .ok_or("missing E1 fixture kind")?
        {
            "rpc-request" => decode_request(&bytes).is_ok(),
            "rpc-response" => {
                let request = decode_request(&serde_json::to_vec(&fixture["request"])?)?;
                decode_response_for(&bytes, &request).is_ok()
            }
            "terminal-stream-frame" => decode_terminal_frame(&bytes).is_ok(),
            "local-request" => decode_local_request(&encode_local_frame(value)?).is_ok(),
            "local-response" => decode_local_response(&encode_local_frame(value)?).is_ok(),
            "local-stream-event" => decode_local_stream_event(&encode_local_frame(value)?).is_ok(),
            _ => return Err("unknown E1 fixture kind".into()),
        };
        if Some(accepted) != fixture["accepted"].as_bool() {
            return Err("E1 wire fixture expectation failed".into());
        }
        fixtures.push(fixture);
    }
    // Separately pinned local relay configuration: one source for native/WASM/SDK.
    let relay: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/local-relay/wire.json"
    ))?;
    for fixture in relay {
        let accepted = decode_local_request(&encode_local_frame(&fixture["value"])?).is_ok();
        if Some(accepted) != fixture["accepted"].as_bool() {
            return Err("local relay fixture expectation failed".into());
        }
        fixtures.push(fixture);
    }
    let enrollment: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/enrollment/wire.json"
    ))?;
    let token_context: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/enrollment/token-context.json"
    ))?;
    for fixture in enrollment.into_iter().chain(token_context) {
        let accepted = match fixture["schema"].as_str() {
            Some("EnrollmentInitiateParams") => {
                serde_json::from_value::<EnrollmentInitiateParams>(fixture["value"].clone()).is_ok()
            }
            Some("HostEnrollmentTokenContext") => {
                serde_json::from_value::<HostEnrollmentTokenContext>(fixture["value"].clone())
                    .is_ok()
            }
            _ => return Err("unknown enrollment fixture schema".into()),
        };
        if Some(accepted) != fixture["accepted"].as_bool() {
            return Err("enrollment init fixture expectation failed".into());
        }
        fixtures.push(fixture);
    }
    // These are transport-shape vectors. Crypto verification runs separately.
    let authority: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/authority-v2/wire.json"
    ))?;
    let runtime_get: Vec<Value> = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/authority-v2/runtime-get.json"
    ))?;
    for fixture in authority.into_iter().chain(runtime_get) {
        let kind = fixture["schema"]
            .as_str()
            .ok_or("missing authority fixture kind")?;
        let accepted = validate_http_wire(kind, &serde_json::to_string(&fixture["value"])?).is_ok();
        if Some(accepted) != fixture["accepted"].as_bool() {
            return Err("authority HTTP wire fixture expectation failed".into());
        }
        fixtures.push(fixture);
    }
    pretty(&fixtures).map_err(Into::into)
}

type Artifact = (String, String);
fn artifact_path(name: &str) -> String {
    name.strip_prefix("../")
        .map(str::to_owned)
        .unwrap_or_else(|| format!("contracts/{name}"))
}
fn schema<T: JsonSchema>() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(schemars::schema_for!(T))?)
}
fn render(root: &std::path::Path) -> Result<Vec<Artifact>, Box<dyn std::error::Error>> {
    let mut artifacts = Vec::new();
    let mut schemas = serde_json::Map::new();
    macro_rules! add {
        ($name:expr, $ty:ty) => {{
            let value = schema::<$ty>()?;
            artifacts.push((format!("{}.schema.json", $name), pretty(&value)?));
            schemas.insert(stringify!($ty).into(), value);
        }};
    }
    add!("draft-contract", DraftContract);
    add!("foundation-types", FoundationTypes);
    add!("rpc-request", RpcRequest);
    add!("rpc-response", RpcResponse);
    add!("workspace-stream-frame", WorkspaceStreamFrame);
    add!("terminal-stream-frame", TerminalStreamFrame);
    add!("file-watch-frame", FileWatchFrame);
    add!("remote-error", RemoteError);
    add!("operation-receipt", OperationReceipt);
    add!("operation-tombstone", OperationTombstone);
    add!("input-receipt", InputReceipt);
    add!("workspace-context", WorkspaceContext);
    add!("terminal-context", TerminalContext);
    add!("mutation-context", MutationContext);
    add!("wss-admission-frame", WssAdmissionFrame);
    add!("local-client-hello", LocalClientHello);
    add!("local-server-hello", LocalServerHello);
    add!("local-request", LocalRequest);
    add!("local-response", LocalResponse);
    add!("local-stream-event", LocalStreamEvent);
    add!("native-lease", NativeLease);
    add!("native-intent-scope", NativeIntentScope);
    macro_rules! http_schemas { ($($ty:ident),+ $(,)?) => { $(add!(stringify!($ty), $ty);)+ }; }
    http_schemas!(
        EnrollmentInitiateParams,
        EnrollmentInitiateResult,
        HostEnrollmentTokenContext,
        HostAuthorizationExchangeParams,
        HostAuthorizationRefreshParams,
        HostAuthorizationResult,
        HostRegisterParams,
        HostRegisterResult,
        ConsumerAuthorizationIssueParams,
        ConsumerAuthorizationContext,
        ConsumerAuthorizationRevokeParams,
        ConsumerAuthorizationRevokeResult,
        ConsumerWindowChallengeParams,
        ConsumerWindowChallengeResult,
        ConsumerWindowRegisterParams,
        ConsumerWindowRegisterResult,
        ConsumerWindowGetResult,
        ConsumerWindowRevokeParams,
        ConsumerWindowRevokeResult,
        HostRuntimeGetResult,
        RuntimeClaimParams,
        RuntimeClaimResult,
        HeartbeatParams,
        HeartbeatResult,
        PublicationParams,
        PublicationResult,
        InventoryResult,
        PairingCreateParams,
        PairingResult,
        PairingPendingResult,
        PairingDecisionParams,
        ChannelCreateParams,
        ChannelCreateResult,
        ChannelResult,
        ChannelPendingResult,
        ChannelAdmissionParams,
        ChannelTicketParams,
        ChannelTicketResult,
        GrantRevokeParams,
        GrantRevokeResult,
        HostRevokeParams,
        HostRevokeResult,
        HostRevocationAckParams,
        HostEnrollmentRevocationAckParams,
        HostEnrollmentRevocationAckResult
    );
    let mut paths = serde_json::Map::new();
    for route in HTTP_ROUTES {
        let (request, response) = match route.route {
            HttpRoute::EnrollmentInitiate => {
                (Some("EnrollmentInitiateParams"), "EnrollmentInitiateResult")
            }
            HttpRoute::HostAuthorizationExchange => (
                Some("HostAuthorizationExchangeParams"),
                "HostAuthorizationResult",
            ),
            HttpRoute::HostAuthorizationRefresh => (
                Some("HostAuthorizationRefreshParams"),
                "HostAuthorizationResult",
            ),
            HttpRoute::HostRegister => (Some("HostRegisterParams"), "HostRegisterResult"),
            HttpRoute::ConsumerAuthorizationIssue => (
                Some("ConsumerAuthorizationIssueParams"),
                "ConsumerAuthorizationContext",
            ),
            HttpRoute::ConsumerAuthorizationRevoke => (
                Some("ConsumerAuthorizationRevokeParams"),
                "ConsumerAuthorizationRevokeResult",
            ),
            HttpRoute::ConsumerWindowChallenge => (
                Some("ConsumerWindowChallengeParams"),
                "ConsumerWindowChallengeResult",
            ),
            HttpRoute::ConsumerWindowRegister => (
                Some("ConsumerWindowRegisterParams"),
                "ConsumerWindowRegisterResult",
            ),
            HttpRoute::ConsumerWindowRevoke => (None, "ConsumerWindowRevokeResult"),
            HttpRoute::ConsumerWindowGet => (None, "ConsumerWindowGetResult"),
            HttpRoute::RuntimeGet => (None, "HostRuntimeGetResult"),
            HttpRoute::RuntimeClaim => (Some("RuntimeClaimParams"), "RuntimeClaimResult"),
            HttpRoute::Heartbeat => (Some("HeartbeatParams"), "HeartbeatResult"),
            HttpRoute::Publication => (Some("PublicationParams"), "PublicationResult"),
            HttpRoute::Inventory => (None, "InventoryResult"),
            HttpRoute::PairingCreate => (Some("PairingCreateParams"), "PairingResult"),
            HttpRoute::PairingGet => (None, "PairingResult"),
            HttpRoute::PairingPending => (None, "PairingPendingResult"),
            HttpRoute::PairingDecision => (Some("PairingDecisionParams"), "PairingResult"),
            HttpRoute::ChannelCreate => (Some("ChannelCreateParams"), "ChannelCreateResult"),
            HttpRoute::ChannelGet => (None, "ChannelResult"),
            HttpRoute::ChannelPending => (None, "ChannelPendingResult"),
            HttpRoute::ChannelAdmission => (Some("ChannelAdmissionParams"), "ChannelResult"),
            HttpRoute::ChannelTicket => (Some("ChannelTicketParams"), "ChannelTicketResult"),
            HttpRoute::GrantRevoke => (Some("GrantRevokeParams"), "GrantRevokeResult"),
            HttpRoute::HostRevoke => (Some("HostRevokeParams"), "HostRevokeResult"),
            HttpRoute::HostRevocationAck => (Some("HostRevocationAckParams"), "HostRevokeResult"),
            HttpRoute::HostEnrollmentRevocationAck => (
                Some("HostEnrollmentRevocationAckParams"),
                "HostEnrollmentRevocationAckResult",
            ),
        };
        let reference = |name: &str| json!({"$ref":format!("#/components/schemas/{name}")});
        let mut responses = json!({"200":{"description":"Draft success DTO; endpoint implementation is outside this contract.","content":{"application/json":{"schema":reference(response)}}}});
        for status in [400, 401, 403, 404, 409, 410, 426, 429, 503, 504] {
            responses[status.to_string()] = json!({"description":"Safe Remote error; code determines HTTP status.","content":{"application/json":{"schema":reference("RemoteError")}}});
        }
        let mut operation = json!({"operationId":format!("{:?}",route.route),"x-lomi-server-owned-class":format!("{:?}",route.surface),"description":"Draft E0 logical route. H/C/E class and ownership come from trusted server storage, independent of credential transport. Credentials use body, header or cookie; never URL/query/fragment. Authentication, atomic admission and ownership checks are external obligations.","responses":responses});
        if route.route == HttpRoute::RuntimeGet {
            operation["description"] = json!(
                "Host-only current-runtime lookup for the exact authenticated host; no request body. Unclaimed generation zero has runtime null and no fabricated UUID. Retain the current monotonic runtimeGeneration for CAS even if its previous binding is unusable; hostAccessEpoch independently reports the current host epoch. runtime is present only for the current host epoch and current credential family. An expired lease may retain that binding for CAS, with leaseMs and freshnessMs zero. Revoked or stale-epoch bindings yield runtime null and zero effective publicationSeq, leaseMs and freshnessMs. Remaining durations are server assertions, never client authority. The DTO validates wire structure only; the server enforces these state rules."
            );
        }
        if route.route == HttpRoute::HostRevocationAck {
            operation["description"] = json!(
                "Proof-only acknowledgement for one already-revoked host authorization family. The submitted refresh secret must match a retained secret hash for the requested family, and the path host, family host/account binding, family epoch and current host epoch must match the trusted snapshot. Retained expired or consumed refresh secrets are accepted only for an already-revoked family; wrong, missing or live-family proofs are denied. This route performs no authority DML and returns only HostRevokeResult; it grants no reusable authority."
            );
        }
        if route.route == HttpRoute::HostEnrollmentRevocationAck {
            operation["description"] = json!(
                "Proof-only acknowledgement for one exact historical enrollment. The trusted adapter verifies the submitted proof against that enrollment's retained key commitment and DB challenge, and binds the path host, enrollment, operation and account. Current enrollment TTL does not grant authority. A revoked-family outcome is returned only for that enrollment's exact already-revoked family with matching host/account and valid monotonic epochs; exchange consumption or enrollment revocation is not required for this outcome. A no-family outcome requires an approved, revoked, unconsumed enrollment and an exhaustive no-family lookup for that enrollment; a family for a newer enrollment does not change that outcome. Missing, wrong, live or inconsistent proofs are denied. This route performs no authority DML and returns no reusable authority."
            );
        }
        if let Some(request) = request {
            operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":reference(request)}}});
        }
        let mut parameters = Vec::new();
        for (name, ty) in [
            ("hostId", "HostId"),
            ("pairingId", "PairingId"),
            ("channelId", "ChannelId"),
            ("grantId", "GrantId"),
            ("consumerAuthorizationId", "ConsumerAuthorizationId"),
        ] {
            if route.path.contains(&format!("{{{name}}}")) {
                parameters.push(json!({"name":name,"in":"path","required":true,"schema":schemas["FoundationTypes"]["$defs"][ty]}));
            }
        }
        if route.window_identity_header {
            parameters.push(json!({"name":"x-lomi-window-identity","in":"header","required":false,
                "description":"Required for cookie authentication; omitted for Bearer authentication. Identifies the registered window bound to the approved consumer grant.",
                "schema":schemas["FoundationTypes"]["$defs"]["WindowIdentityId"]}));
        }
        if !parameters.is_empty() {
            operation["parameters"] = json!(parameters);
        }
        let method = match route.method {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
        };
        paths
            .entry(format!("{REMOTE_HTTP_PREFIX}{}", route.path))
            .or_insert_with(|| json!({}))[method] = operation;
    }
    fn relocate(value: &mut serde_json::Value, name: &str) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::String(reference)) = map.get_mut("$ref")
                    && reference.starts_with("#/")
                {
                    *reference = format!("#/components/schemas/{name}/{}", &reference[2..]);
                }
                for child in map.values_mut() {
                    relocate(child, name);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    relocate(item, name);
                }
            }
            _ => {}
        }
    }
    let mut components = schemas.clone();
    for (name, value) in &mut components {
        relocate(value, name);
    }
    let codes = schemas["RemoteError"]["$defs"]["ErrorCode"]["enum"]
        .as_array()
        .ok_or("missing error enum")?;
    let mut statuses = serde_json::Map::new();
    for code in codes {
        let typed: ErrorCode = serde_json::from_value(code.clone())?;
        statuses.insert(
            code.as_str().ok_or("invalid error code")?.into(),
            json!(typed.http_status()),
        );
    }
    artifacts.push(("openapi.json".into(), pretty(&json!({"openapi":"3.1.0","jsonSchemaDialect":"https://json-schema.org/draft/2020-12/schema","info":{"title":"Lomi Remote E0 draft contract","version":"2.0.0-draft","description":"Generated logical contract; not frozen S0.5 or a declaration of deployed endpoints. No production server is specified."},"paths":paths,"components":{"schemas":components},"x-lomi-error-statuses":statuses,"x-lomi-wss-admission":{"schema":"wss-admission-frame.schema.json","transport":"first WSS frame before payload routing; no URL credentials","maxBytes":WSS_ADMISSION_MAX_BYTES,"timeoutMs":WSS_ADMISSION_TIMEOUT_MS}}))?));
    let capabilities: Vec<_> = Capability::ALL.into_iter().map(|c| json!({
        "name": c, "requires": c.dependencies(), "allowsShellExecution": c.allows_shell_execution(),
        "defaultControlWithWorkspaceTools": c != Capability::GitExecute,
    })).collect();
    let methods: Vec<_> = Method::ALL.iter().map(|method| {
        let rights = match method.rights() {
            MethodRights::Static(required) => json!({"source":"static", "requires":required}),
            MethodRights::StoredOperationRights => json!({"source":"storedOperationRights", "requiresWorkspaceRead":true,
                "binding":["principalAuthorization", "workspaceId", "operationId", "originalMethod", "actualRights"]}),
        };
        json!({"method":method, "authorization":rights,
            "requiresExecuteWhenRepositoryControlledCodeRuns":match method.rights() {
                MethodRights::Static(_) => Some(is_git_mutation(method.as_str())),
                MethodRights::StoredOperationRights => None,
            }})
    }).collect();
    artifacts.push((
        "../packages/remote-contracts/fixtures/rust-codec.json".into(),
        codec_fixtures()?,
    ));
    let mut hashes = serde_json::Map::new();
    for (name, contents) in &artifacts {
        hashes.insert(artifact_path(name), json!(digest(contents.as_bytes())));
    }
    for name in [
        "contracts/terminal-profile-experimental.json",
        "tests/grant-v3/vectors.json",
        "tests/crypto-v3-browser/native-vectors.json",
        "tests/crypto-provenance/source.json",
        "crates/lomi-remote-crypto/tests/fixtures/legacy-v1.json",
        "crates/lomi-remote-crypto/tests/fixtures/workspace-v2.json",
        "crates/lomi-remote-crypto/tests/fixtures/host-key-commitment-v1.json",
        "crates/lomi-remote-crypto/tests/fixtures/enrollment-wire-v1.json",
    ] {
        hashes.insert(
            name.into(),
            json!(digest(&fs::read(root.join("..").join(name))?)),
        );
    }
    fn hash_fixture_tree(
        directory: &std::path::Path,
        root: &std::path::Path,
        hashes: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                hash_fixture_tree(&path, root, hashes)?;
            } else if path.extension().is_some_and(|e| e == "json") {
                hashes.insert(
                    format!(
                        "contracts/{}",
                        path.strip_prefix(root)?
                            .to_str()
                            .ok_or("non-UTF8 fixture path")?
                    ),
                    json!(digest(&fs::read(&path)?)),
                );
            }
        }
        Ok(())
    }
    hash_fixture_tree(&root.join("fixtures"), root, &mut hashes)?;
    for package in [
        "remote-contracts",
        "protocol-codec-wasm",
        "authority-crypto-wasm",
    ] {
        let package_generated = root.join(format!("../packages/{package}/generated"));
        let mut package_files = fs::read_dir(&package_generated)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, _>>()?;
        package_files.sort();
        for path in package_files {
            if path.is_file() {
                let name = path
                    .file_name()
                    .ok_or("missing package artifact name")?
                    .to_str()
                    .ok_or("invalid package artifact name")?;
                hashes.insert(
                    format!("packages/{package}/generated/{name}"),
                    json!(digest(&fs::read(&path)?)),
                );
            }
        }
    }
    artifacts.push(("compatibility-manifest.json".into(), pretty(&json!({
        "status":"draft-e0", "productTarget":"v1", "remoteApiMajor":2,
        "remoteApiPrefix":REMOTE_HTTP_PREFIX, "applicationMajor":2, "grantContextVersion":3,
        "localIpc":{"major":1,"minor":0,"independentVersionAxis":true,"negotiation":"equal major; minimum supported minor","framing":"4-byte big-endian payload length, then JSON; maximum 1 MiB","authentication":"OS peer identity plus endpoint owner/ACL; profile/host/runtime/nonce binding, not caller JSON"},
        "terminalProfile":{"id":"lomi-rust-grid-v1-experimental","qualified":false,"path":"contracts/terminal-profile-experimental.json"},
        "artifacts":hashes,"pathBase":"repository","hashAlgorithm":"sha256","manifestSelfHash":false,
        "capabilities":capabilities,"methods":methods,
        "validationBoundary":"JSON schemas enforce wire shape and annotated byte bounds. Checked codecs additionally enforce canonical and cross-field semantics. Authentication, cryptography, correlation, admission and stream state require their trusted checks.",
        "excluded":["production-admission","s0.5-freeze","platform-qualification"],
        "cryptoBoundary":"Canonical CBOR and signatures remain owned by lomi-remote-crypto; hex wire schemas do not verify canonical CBOR or signatures. See hashed existing vectors and provenance."
    }))?));
    Ok(artifacts)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.iter().any(|a| a != "--check") || args.len() > 1 {
        return Err("usage: generate-contracts [--check]".into());
    }
    let check = args.first().is_some_and(|a| a == "--check");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
    for (name, contents) in render(&root)? {
        let path = root.join(name);
        if check {
            if fs::read_to_string(&path).ok().as_deref() != Some(&contents) {
                return Err(format!("contract drift: {}", path.display()).into());
            }
        } else {
            fs::create_dir_all(path.parent().ok_or("artifact parent missing")?)?;
            fs::write(path, contents)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn e1_source_cases_are_all_embedded_once_for_every_consumer() {
        let source: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../../../../contracts/fixtures/e1/wire.json"))
                .unwrap();
        let generated: Vec<serde_json::Value> =
            serde_json::from_str(&codec_fixtures().unwrap()).unwrap();
        assert_eq!(source.len(), 26);
        assert_eq!(
            generated
                .iter()
                .filter(|case| case["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("e1/")))
                .count(),
            source.len()
        );
        for case in &source {
            let matching: Vec<_> = generated
                .iter()
                .filter(|generated| generated["name"] == case["name"])
                .collect();
            assert_eq!(matching.len(), 1, "{}", case["name"]);
            assert_eq!(matching[0], case, "{}", case["name"]);
        }
    }

    #[test]
    fn runtime_lookup_fixtures_are_additive_and_embedded_exactly_once() {
        let original: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../../contracts/fixtures/authority-v2/wire.json"
        ))
        .unwrap();
        let lookup: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../../contracts/fixtures/authority-v2/runtime-get.json"
        ))
        .unwrap();
        let generated: Vec<serde_json::Value> =
            serde_json::from_str(&codec_fixtures().unwrap()).unwrap();
        assert_eq!(original.len(), 77);
        for case in original.into_iter().chain(lookup) {
            let matching: Vec<_> = generated
                .iter()
                .filter(|g| g["name"] == case["name"])
                .collect();
            assert_eq!(matching.len(), 1, "{}", case["name"]);
            assert_eq!(matching[0], &case);
        }
    }

    #[test]
    fn generation_is_deterministic_and_hashes_all_exact_inputs() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
        let first = render(&root).unwrap();
        assert_eq!(first, render(&root).unwrap());
        let manifest: serde_json::Value = serde_json::from_str(&first.last().unwrap().1).unwrap();
        for (name, contents) in &first[..first.len() - 1] {
            assert_eq!(
                manifest["artifacts"][artifact_path(name)],
                digest(contents.as_bytes())
            );
        }
        assert_eq!(manifest["terminalProfile"]["qualified"], false);
        assert_eq!(manifest["methods"].as_array().unwrap().len(), 39);
        let api: serde_json::Value =
            serde_json::from_str(&first.iter().find(|(n, _)| n == "openapi.json").unwrap().1)
                .unwrap();
        assert_eq!(api["paths"].as_object().unwrap().len(), 26);
        let lookup = &api["paths"]["/v2/remote/hosts/{hostId}/runtime"]["get"];
        assert_eq!(lookup["x-lomi-server-owned-class"], "HostAccess");
        assert!(lookup.get("requestBody").is_none());
        assert_eq!(
            lookup["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/HostRuntimeGetResult"
        );
        assert!(api.get("servers").is_none());
        let revocation_ack = &api["paths"]["/v2/remote/hosts/{hostId}/revocation-ack"]["post"];
        assert_eq!(
            revocation_ack["x-lomi-server-owned-class"],
            "HostRevocationProof"
        );
        assert_eq!(
            revocation_ack["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/HostRevocationAckParams"
        );
        assert_eq!(
            revocation_ack["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/HostRevokeResult"
        );
        let enrollment_revocation_ack =
            &api["paths"]["/v2/remote/hosts/{hostId}/enrollment-revocation-ack"]["post"];
        assert_eq!(
            enrollment_revocation_ack["x-lomi-server-owned-class"],
            "HostEnrollmentRevocationProof"
        );
        assert_eq!(
            enrollment_revocation_ack["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/HostEnrollmentRevocationAckParams"
        );
        assert_eq!(
            enrollment_revocation_ack["responses"]["200"]["content"]["application/json"]["schema"]
                ["$ref"],
            "#/components/schemas/HostEnrollmentRevocationAckResult"
        );
        let channel_get = &api["paths"]["/v2/remote/channels/{channelId}"]["get"];
        let window_header = channel_get["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "x-lomi-window-identity")
            .unwrap();
        assert_eq!(window_header["in"], "header");
        assert_eq!(window_header["required"], false);
        assert!(
            window_header["description"]
                .as_str()
                .unwrap()
                .contains("Required for cookie authentication")
        );
    }
}
