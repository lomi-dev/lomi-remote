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
    let mut hashes = serde_json::Map::new();
    for (name, contents) in &artifacts {
        hashes.insert(artifact_path(name), json!(digest(contents.as_bytes())));
    }
    let name = "contracts/terminal-profile-experimental.json";
    hashes.insert(
        name.into(),
        json!(digest(&fs::read(root.join("..").join(name))?)),
    );
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
        "cryptoBoundary":"Canonical CBOR and signatures remain owned by lomi-remote-crypto; hex wire schemas do not verify canonical CBOR or signatures. See the canonical lomi-remote-crypto source and build provenance."
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
