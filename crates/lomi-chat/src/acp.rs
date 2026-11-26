//! One long-lived Agent Client Protocol agent per thread (`agy acp`, `kimi acp`:
//! JSON-RPC 2.0, newline-delimited over stdio). Turns go in as `session/prompt`,
//! tool permissions arrive as `session/request_permission` and are answered
//! through [`AcpSession::respond`]. The turn loop lives in the engine; this
//! module owns the message builders, the update mapping and the session.
//! Nothing here is agent specific: the launch command and the mode table are
//! the only per-CLI facts.
use crate::{
    attachments,
    cli::{self, Ev},
    session::{Answer, Key, NOT_PENDING, Rx, Wire, line, next_generation},
    settings::Permissions,
    store::{
        self, Activity, ActivityDiff, ActivityKind, ActivityStatus, Decision, ThreadCommand, Usage,
    },
};
use base64::Engine as _;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{
    Mutex as AsyncMutex,
    mpsc::{UnboundedSender, unbounded_channel},
};

/// How long the handshake requests may wait for an answer.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Reasoning text is re-emitted after it grew by this many bytes.
const REASONING_STEP: usize = 256;

/// Everything one turn needs; the process-wide part is [`Params::key_args`].
pub struct Params {
    pub cwd: String,
    /// None for the CLI's own default model.
    pub model: Option<String>,
    pub permissions: Permissions,
    pub prompt: String,
    /// Absolute paths of attached images.
    pub images: Vec<String>,
    /// Attachments folder; offered to agents that support extra directories.
    pub attach_dir: String,
}

/// Mode ids to try, best first, per Lomi permission. The descriptions the CLIs
/// report (Antigravity 1.5.16, Kimi Code 2.7.2): `plan` is read-only planning,
/// `default` asks before edits and commands, `yolo` (Kimi) approves everything,
/// `auto` approves safe operations (Antigravity's most permissive mode).
fn mode_preference(p: Permissions) -> &'static [&'static str] {
    match p {
        Permissions::ReadOnly => &["plan"],
        Permissions::Edit => &["default"],
        Permissions::Full => &["yolo", "auto"],
    }
}

/// The mode to set; `available` is None when the agent did not list its modes.
pub fn pick_mode(p: Permissions, available: Option<&[String]>) -> Option<&'static str> {
    let prefs = mode_preference(p);
    match available {
        None => prefs.first().copied(),
        Some(a) => prefs.iter().copied().find(|m| a.iter().any(|x| x == m)),
    }
}

impl Params {
    /// Settings fixed when the thread starts; a change needs a new process.
    pub fn key_args(&self) -> Vec<String> {
        vec![
            self.model.clone().unwrap_or_default(),
            format!("{:?}", self.permissions),
        ]
    }

    /// `session/new`, or the resume/load request of a native session.
    pub fn session_params(&self, native: Option<&str>, extra_dirs: bool) -> Value {
        let mut p = json!({"cwd": self.cwd, "mcpServers": []});
        if let Some(id) = native {
            p["sessionId"] = json!(id);
        }
        if extra_dirs {
            p["additionalDirectories"] = json!([self.attach_dir]);
        }
        p
    }

    /// `images` are ready-made content blocks (see [`image_blocks`]).
    pub fn prompt_params(&self, session_id: &str, images: Vec<Value>) -> Value {
        let mut prompt = vec![json!({"type": "text", "text": self.prompt})];
        prompt.extend(images);
        json!({"sessionId": session_id, "prompt": prompt})
    }
}

/// Inline image blocks for the attached images that fit the attachment limit;
/// any other file stays a path in the prompt text.
pub async fn image_blocks(paths: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    for path in paths {
        let mime = match path
            .rsplit('.')
            .next()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("webp") => "image/webp",
            _ => continue,
        };
        let fits = tokio::fs::metadata(path)
            .await
            .is_ok_and(|m| m.len() <= attachments::MAX_IMAGE as u64);
        if let (true, Ok(data)) = (fits, tokio::fs::read(path).await) {
            let data = base64::engine::general_purpose::STANDARD.encode(data);
            out.push(json!({"type": "image", "mimeType": mime, "data": data}));
        }
    }
    out
}

fn rpc(mut v: Value) -> String {
    v["jsonrpc"] = json!("2.0");
    line(v)
}

pub fn request_line(id: u64, method: &str, params: Value) -> String {
    rpc(json!({"id": id, "method": method, "params": params}))
}

pub fn notification_line(method: &str, params: Value) -> String {
    rpc(json!({"method": method, "params": params}))
}

/// Refusal of an agent request Lomi has no UI for (we advertise no fs/terminal).
pub fn unsupported_line(id: &Value) -> String {
    rpc(json!({"id": id, "error": {"code": -32601, "message": "Unsupported by Lomi."}}))
}

/// The answer to a permission request: the chosen option, or "cancelled".
pub fn reply_line(id: &Value, option: Option<&str>) -> String {
    let outcome = match option {
        Some(o) => json!({"outcome": "selected", "optionId": o}),
        None => json!({"outcome": "cancelled"}),
    };
    rpc(json!({"id": id, "result": {"outcome": outcome}}))
}

/// One offered answer of a permission request.
#[derive(Debug, PartialEq, Clone)]
pub struct Opt {
    pub id: String,
    pub kind: String,
}

/// The option for `decision`: allow, allow-for-session and deny each fall back
/// to the other persistence of the same polarity; None when the agent offered none.
pub fn choose(options: &[Opt], decision: Decision) -> Option<&str> {
    let find = |kinds: [&str; 2]| {
        kinds
            .iter()
            .find_map(|k| options.iter().find(|o| o.kind == *k))
            .map(|o| o.id.as_str())
    };
    match decision {
        Decision::Allow => find(["allow_once", "allow_always"]),
        Decision::AllowSession => find(["allow_always", "allow_once"]),
        Decision::Deny => find(["reject_once", "reject_always"]),
    }
}

/// A `session/request_permission` kept until the user answers.
#[derive(Debug, PartialEq)]
pub struct Prompt {
    /// The JSON-RPC id, echoed in the answer.
    pub id: Value,
    /// Stringified [`Prompt::id`]: the approval's `request_id`.
    pub request_id: String,
    pub tool_id: String,
    /// The `toolCall` object (a partial tool update).
    pub tool: Value,
    pub options: Vec<Opt>,
    /// Whether an "always allow" option was offered.
    pub remember: bool,
}

/// Parses a permission request; None for any other message.
pub fn parse_prompt(v: &Value) -> Option<Prompt> {
    if v["method"] != "session/request_permission" {
        return None;
    }
    let id = v
        .get("id")
        .filter(|i| i.is_string() || i.is_number())?
        .clone();
    let p = &v["params"];
    let options: Vec<Opt> = p["options"]
        .as_array()?
        .iter()
        .filter_map(|o| {
            Some(Opt {
                id: cli::str_at(o, &["optionId"])?.into(),
                kind: cli::str_at(o, &["kind"])?.into(),
            })
        })
        .collect();
    Some(Prompt {
        request_id: id.as_str().map_or_else(|| id.to_string(), String::from),
        tool_id: cli::str_at(p, &["toolCall", "toolCallId"])?.into(),
        tool: p["toolCall"].clone(),
        remember: options.iter().any(|o| o.kind == "allow_always"),
        options,
        id,
    })
}

/// Read-only threads may not run tools that change anything; unknown kinds count as changing.
pub fn mutating(kind: ActivityKind) -> bool {
    !matches!(
        kind,
        ActivityKind::Read | ActivityKind::Search | ActivityKind::Fetch | ActivityKind::Reasoning
    )
}

/// How a turn ended.
#[derive(Debug, PartialEq)]
pub enum End {
    /// Finished; carries the stored stop reason.
    Done(&'static str),
    Cancelled,
    Failed(String),
}

/// Maps the `session/prompt` result's `stopReason`.
pub fn turn_end(result: &Value) -> End {
    match result["stopReason"].as_str() {
        Some("cancelled") => End::Cancelled,
        Some("refusal") => End::Failed("The agent declined to answer.".into()),
        Some("max_tokens") => End::Done("max_tokens"),
        Some("max_turn_requests") => End::Done("max_turn_requests"),
        _ => End::Done("stop"),
    }
}

/// Token figures of a `session/prompt` result.
pub fn usage(result: &Value) -> Option<Usage> {
    let u = result.get("usage").filter(|u| u.is_object())?;
    let n = |k: &str| u[k].as_u64().unwrap_or(0);
    Some(Usage {
        input_tokens: n("inputTokens"),
        output_tokens: n("outputTokens"),
        cached_input_tokens: n("cachedReadTokens"),
        cost_usd: None,
    })
}

fn kind(k: &str) -> ActivityKind {
    match k {
        "read" => ActivityKind::Read,
        "edit" | "delete" | "move" => ActivityKind::Edit,
        "search" => ActivityKind::Search,
        "execute" => ActivityKind::Execute,
        "fetch" => ActivityKind::Fetch,
        "think" => ActivityKind::Reasoning,
        _ => ActivityKind::Other,
    }
}

/// Maps the updates of one turn onto the engine's events.
#[derive(Default)]
pub struct Mapper {
    had_text: bool,
    /// Text since the last tool or reasoning event must start a new paragraph.
    gap: bool,
    ends_ws: bool,
    /// Open reasoning run: (activity id, text, length last emitted).
    thought: Option<(String, String, usize)>,
    runs: u32,
    /// Latest merged state of each tool call.
    acts: HashMap<String, Activity>,
}

impl Mapper {
    fn thought_activity(&self, done: bool) -> Option<Ev> {
        let (id, text, _) = self.thought.as_ref()?;
        let status = if done {
            ActivityStatus::Completed
        } else {
            ActivityStatus::Running
        };
        let mut a = cli::activity(id, ActivityKind::Reasoning, "Reasoning", status);
        a.detail = Some(text.clone());
        Some(Ev::Activity(a))
    }

    /// Ends the open reasoning run, if any.
    fn close_thought(&mut self, out: &mut Vec<Ev>) {
        out.extend(self.thought_activity(true));
        self.thought = None;
    }

    /// Flushes what is still open when the turn ends.
    pub fn finish(&mut self) -> Vec<Ev> {
        let mut out = Vec::new();
        self.close_thought(&mut out);
        out
    }

    /// Merges a tool call or a partial update into the call's state.
    pub fn tool(&mut self, v: &Value) -> Option<Activity> {
        let id = cli::str_at(v, &["toolCallId"])?;
        let mut a = self
            .acts
            .remove(id)
            .unwrap_or_else(|| cli::activity(id, ActivityKind::Other, "", ActivityStatus::Running));
        if let Some(k) = cli::str_at(v, &["kind"]) {
            a.kind = kind(k);
        }
        // A finished call stays finished when a late update repeats an earlier status.
        if a.status == ActivityStatus::Running {
            match cli::str_at(v, &["status"]) {
                Some("completed") => a.status = ActivityStatus::Completed,
                Some("failed") => a.status = ActivityStatus::Failed,
                _ => {}
            }
        }
        if let Some(t) = cli::str_at(v, &["title"]).filter(|t| !t.is_empty()) {
            a.title = t.into();
        }
        if a.title.is_empty() {
            a.title = cli::str_at(&v["locations"][0], &["path"])
                .or(cli::str_at(v, &["name"]))
                .unwrap_or("Tool")
                .into();
        }
        let content = v["content"].as_array().map_or(&[][..], Vec::as_slice);
        let texts: Vec<&str> = content
            .iter()
            .filter_map(|c| cli::str_at(c, &["content", "text"]))
            .filter(|t| !t.is_empty())
            .collect();
        if !texts.is_empty() {
            a.detail = Some(texts.join("\n"));
        }
        if let Some(d) = content.iter().find(|c| c["type"] == "diff") {
            a.diff = cli::str_at(d, &["path"]).map(|path| ActivityDiff {
                path: path.into(),
                before: cli::str_at(d, &["oldText"]).map(String::from),
                after: cli::str_at(d, &["newText"]).unwrap_or("").into(),
            });
        }
        self.acts.insert(id.into(), a.clone());
        Some(a)
    }

    /// Maps one `session/update` notification; other messages and update kinds are ignored.
    pub fn update(&mut self, v: &Value) -> Vec<Ev> {
        let mut out = Vec::new();
        if v["method"] != "session/update" {
            return out;
        }
        let u = &v["params"]["update"];
        let text = cli::str_at(u, &["content", "text"]).filter(|t| !t.is_empty());
        match (u["sessionUpdate"].as_str(), text) {
            (Some("agent_message_chunk"), Some(t)) => {
                self.close_thought(&mut out);
                if self.had_text && self.gap && !self.ends_ws {
                    out.push(Ev::Text("\n\n".into()));
                }
                (self.had_text, self.gap) = (true, false);
                self.ends_ws = t.ends_with(char::is_whitespace);
                out.push(Ev::Text(t.into()));
            }
            (Some("agent_thought_chunk"), Some(t)) => {
                self.gap = true;
                if self.thought.is_none() {
                    self.runs += 1;
                    self.thought = Some((format!("thought-{}", self.runs), String::new(), 0));
                }
                let mut emit = false;
                if let Some((_, text, sent)) = &mut self.thought {
                    let first = text.is_empty();
                    if text.len() < store::DETAIL_CAP {
                        text.push_str(t);
                    }
                    if first || text.len() >= *sent + REASONING_STEP {
                        (*sent, emit) = (text.len(), true);
                    }
                }
                if emit {
                    out.extend(self.thought_activity(false));
                }
            }
            (Some("tool_call" | "tool_call_update"), _) => {
                self.close_thought(&mut out);
                self.gap = true;
                out.extend(self.tool(u).map(Ev::Activity));
            }
            _ => {}
        }
        out
    }
}

/// The commands of an `available_commands_update` notification.
pub fn parse_commands(v: &Value) -> Option<Vec<ThreadCommand>> {
    let u = &v["params"]["update"];
    if v["method"] != "session/update" || u["sessionUpdate"] != "available_commands_update" {
        return None;
    }
    let text = |c: &Value, k: &str| c[k].as_str().unwrap_or_default().to_string();
    Some(
        u["availableCommands"]
            .as_array()?
            .iter()
            .filter(|c| c["name"].as_str().is_some_and(|n| !n.is_empty()))
            .map(|c| ThreadCommand {
                name: text(c, "name"),
                description: text(c, "description"),
                argument_hint: cli::str_at(c, &["input", "hint"])
                    .unwrap_or_default()
                    .into(),
            })
            .collect(),
    )
}

struct Pending {
    id: Value,
    options: Vec<Opt>,
}

/// One warm ACP agent, bound to one native session once started.
pub struct AcpSession {
    pub key: Key,
    pub permissions: Permissions,
    wire: Wire,
    answers: UnboundedSender<Answer>,
    rx: AsyncMutex<Rx>,
    pending: Mutex<HashMap<String, Pending>>,
    next: AtomicU64,
    native: Mutex<Option<String>>,
    /// The agent accepts image content blocks.
    images: AtomicBool,
    /// Slash commands from the agent's last `available_commands_update`.
    commands: Mutex<Vec<ThreadCommand>>,
    /// Prefix of the request ids shown to the UI: a stale answer cannot hit a later process.
    generation: u64,
}

impl std::ops::Deref for AcpSession {
    type Target = Wire;

    fn deref(&self) -> &Wire {
        &self.wire
    }
}

impl AcpSession {
    /// Starts `spec` (`<cli> acp`); [`start`] performs the handshake.
    /// Must run inside a Tokio runtime.
    pub fn spawn<G: Send + 'static>(
        spec: &cli::Spec,
        p: &Params,
        track: impl FnOnce(Option<u32>) -> G,
    ) -> Result<Arc<Self>, String> {
        let (wire, lines) = Wire::start(spec, spec.args.clone(), None, track)?;
        let (answers, answers_rx) = unbounded_channel();
        Ok(Arc::new(Self {
            key: Key::with(spec, p.key_args()),
            permissions: p.permissions,
            wire,
            answers,
            rx: AsyncMutex::new(Rx {
                lines,
                answers: answers_rx,
            }),
            pending: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            native: Mutex::new(None),
            images: AtomicBool::new(false),
            commands: Mutex::new(Vec::new()),
            generation: next_generation(),
        }))
    }

    pub async fn rx(&self) -> tokio::sync::MutexGuard<'_, Rx> {
        self.rx.lock().await
    }

    /// Sends a request and returns its id; the response arrives on the line channel.
    pub fn request(&self, method: &str, params: Value) -> Result<u64, String> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.write(request_line(id, method, params))?;
        Ok(id)
    }

    /// The native session id once the handshake succeeded.
    pub fn native(&self) -> Option<String> {
        self.native.lock().ok().and_then(|t| t.clone())
    }

    pub fn commands(&self) -> Vec<ThreadCommand> {
        self.commands.lock().map(|c| c.clone()).unwrap_or_default()
    }

    pub fn accepts_images(&self) -> bool {
        self.images.load(Ordering::Relaxed)
    }

    pub fn cancel(&self, session_id: &str) {
        let _ = self.write(notification_line(
            "session/cancel",
            json!({"sessionId": session_id}),
        ));
    }

    /// The approval's `request_id` as the UI sees it.
    pub fn scoped(&self, p: &Prompt) -> String {
        format!("{}:{}", self.generation, p.request_id)
    }

    /// Registers the prompt and returns its scoped id; call before showing it.
    pub fn add_pending(&self, p: &Prompt) -> String {
        let key = self.scoped(p);
        if let Ok(mut m) = self.pending.lock() {
            m.insert(
                key.clone(),
                Pending {
                    id: p.id.clone(),
                    options: p.options.clone(),
                },
            );
        }
        key
    }

    /// Rejects a request on Lomi's own authority (read-only threads).
    pub fn reject(&self, p: &Prompt) {
        let _ = self.write(reply_line(&p.id, choose(&p.options, Decision::Deny)));
    }

    /// Answers a pending prompt on behalf of the user.
    pub fn respond(&self, request_id: &str, decision: Decision) -> Result<(), String> {
        let p = self
            .pending
            .lock()
            .map_err(|_| NOT_PENDING.to_string())?
            .remove(request_id)
            .ok_or(NOT_PENDING)?;
        let option = choose(&p.options, decision);
        self.write(reply_line(&p.id, option))?;
        let _ = self.answers.send(Answer {
            request_id: request_id.into(),
            allowed: decision != Decision::Deny && option.is_some(),
            answers: None,
        });
        Ok(())
    }

    /// Cancels every unanswered prompt; the turn is over or being stopped.
    pub fn cancel_pending(&self) {
        let all: Vec<Pending> = self
            .pending
            .lock()
            .map(|mut m| m.drain().map(|(_, p)| p).collect())
            .unwrap_or_default();
        for p in all {
            let _ = self.write(reply_line(&p.id, None));
        }
    }
}

/// Sends a request and waits for its response; other messages are dropped
/// (agent requests are refused, replayed `session/load` updates vanish).
/// Only for the handshake, before a turn runs.
async fn call(s: &AcpSession, rx: &mut Rx, method: &str, params: Value) -> Result<Value, String> {
    let id = s.request(method, params)?;
    let wait = async {
        loop {
            let line = rx.lines.recv().await.ok_or_else(|| s.exit_detail())?;
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if v.get("method").is_some() {
                if let Some(i) = v.get("id") {
                    let _ = s.write(unsupported_line(i));
                } else if let (Some(c), Ok(mut slot)) = (parse_commands(&v), s.commands.lock()) {
                    *slot = c;
                }
            } else if v["id"] == id {
                return match v.get("error") {
                    Some(e) => Err(e["message"]
                        .as_str()
                        .unwrap_or("The CLI refused the request.")
                        .into()),
                    None => Ok(v["result"].clone()),
                };
            }
        }
    };
    tokio::time::timeout(CALL_TIMEOUT, wait)
        .await
        .map_err(|_| "The CLI did not answer in time.".to_string())?
}

/// Handshake of a fresh process: `initialize`, then the session. A native
/// session is resumed (or loaded); when that fails (whatever the reason, usually an
/// unknown session) a new one replaces it. Model and mode are applied. Returns the
/// native session id and, when the resume failed, its error so the caller can tell
/// the user the context was reset.
pub async fn start(
    s: &AcpSession,
    rx: &mut Rx,
    p: &Params,
    native: Option<&str>,
) -> Result<(String, Option<String>), String> {
    let init = json!({
        "protocolVersion": 1,
        "clientCapabilities": {"fs": {"readTextFile": false, "writeTextFile": false}, "terminal": false},
    });
    let caps = call(s, rx, "initialize", init).await?["agentCapabilities"].clone();
    let sessions = &caps["sessionCapabilities"];
    s.images.store(
        caps["promptCapabilities"]["image"] == true,
        Ordering::Relaxed,
    );
    let dirs = sessions["additionalDirectories"].is_object();
    let method = if sessions["resume"].is_object() {
        Some("session/resume")
    } else if caps["loadSession"] == true || sessions["load"].is_object() {
        Some("session/load")
    } else {
        None
    };
    let mut started = None;
    let mut reset = None;
    if let Some(id) = native {
        match method {
            Some(m) => match call(s, rx, m, p.session_params(Some(id), dirs)).await {
                Ok(r) => started = Some((id.to_string(), r)),
                Err(e) => reset = Some(e),
            },
            None => reset = Some("The CLI cannot resume sessions.".into()),
        }
    }
    let (id, info) = match started {
        Some(x) => x,
        None => {
            let r = call(s, rx, "session/new", p.session_params(None, dirs)).await?;
            let id = cli::str_at(&r, &["sessionId"]).ok_or("The CLI returned no session.")?;
            (id.to_string(), r)
        }
    };
    if let Some(m) = &p.model {
        let models = &info["models"];
        if cli::str_at(models, &["currentModelId"]) != Some(m) {
            let listed = models["availableModels"].as_array();
            if listed.is_some_and(|l| !l.iter().any(|x| x["modelId"] == m.as_str())) {
                return Err(format!("The CLI does not offer the model {m}."));
            }
            let set = json!({"sessionId": id, "modelId": m});
            call(s, rx, "session/set_model", set).await?;
        }
    }
    let modes = &info["modes"];
    let listed = modes["availableModes"].as_array().map(|l| {
        l.iter()
            .filter_map(|m| cli::str_at(m, &["id"]).map(String::from))
            .collect::<Vec<_>>()
    });
    // Read-only and edit rely on the agent's own mode, so a refusal fails the start;
    // full access may run in whatever mode the agent is in.
    let refused = || match p.permissions {
        Permissions::ReadOnly => Some("read-only"),
        Permissions::Edit => Some("edit"),
        Permissions::Full => None,
    };
    match pick_mode(p.permissions, listed.as_deref()) {
        Some(mode) if cli::str_at(modes, &["currentModeId"]) == Some(mode) => {}
        Some(mode) => {
            let set = json!({"sessionId": id, "modeId": mode});
            if let (Err(_), Some(name)) = (call(s, rx, "session/set_mode", set).await, refused()) {
                return Err(format!("This agent did not accept the {name} mode."));
            }
        }
        None => {
            if let Some(name) = refused() {
                return Err(format!("This agent did not accept the {name} mode."));
            }
        }
    }
    if let Ok(mut n) = s.native.lock() {
        *n = Some(id.clone());
    }
    Ok((id, reset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(permissions: Permissions) -> Params {
        Params {
            cwd: "/w".into(),
            model: Some("m-1".into()),
            permissions,
            prompt: "hi".into(),
            images: vec![],
            attach_dir: "/a".into(),
        }
    }

    fn v(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    fn opts(kinds: &[&str]) -> Vec<Opt> {
        kinds
            .iter()
            .map(|k| Opt {
                id: format!("id-{k}"),
                kind: (*k).into(),
            })
            .collect()
    }

    #[test]
    fn builders_match_the_protocol() {
        let p = params(Permissions::Edit);
        assert_eq!(
            p.session_params(None, false),
            json!({"cwd":"/w","mcpServers":[]})
        );
        assert_eq!(
            p.session_params(Some("S"), true),
            json!({"cwd":"/w","mcpServers":[],"sessionId":"S","additionalDirectories":["/a"]})
        );
        let img = json!({"type":"image","mimeType":"image/png","data":"AA=="});
        assert_eq!(
            p.prompt_params("S", vec![img.clone()]),
            json!({"sessionId":"S","prompt":[{"type":"text","text":"hi"},img]})
        );
        assert_eq!(
            v(&request_line(3, "session/set_mode", json!({"a":1}))),
            json!({"jsonrpc":"2.0","id":3,"method":"session/set_mode","params":{"a":1}})
        );
        assert_eq!(
            v(&notification_line(
                "session/cancel",
                json!({"sessionId":"S"})
            )),
            json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"S"}})
        );
        assert_eq!(
            v(&unsupported_line(&json!("x"))),
            json!({"jsonrpc":"2.0","id":"x","error":{"code":-32601,"message":"Unsupported by Lomi."}})
        );
        assert_eq!(
            v(&reply_line(&json!(4), Some("allow")))["result"],
            json!({"outcome":{"outcome":"selected","optionId":"allow"}})
        );
        assert_eq!(
            v(&reply_line(&json!(4), None))["result"],
            json!({"outcome":{"outcome":"cancelled"}})
        );
        assert!(reply_line(&json!(4), None).ends_with('\n'));
        assert_ne!(p.key_args(), params(Permissions::Full).key_args());
    }

    #[test]
    fn modes_follow_the_reported_tables() {
        let ids = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let agy = ids(&["default", "accept-edits", "auto", "plan"]);
        let kimi = ids(&["default", "plan", "auto", "yolo"]);
        let pick = |p, l: &[String]| pick_mode(p, Some(l));
        assert_eq!(pick(Permissions::ReadOnly, &agy), Some("plan"));
        assert_eq!(pick(Permissions::Edit, &agy), Some("default"));
        assert_eq!(pick(Permissions::Full, &agy), Some("auto"));
        assert_eq!(pick(Permissions::ReadOnly, &kimi), Some("plan"));
        assert_eq!(pick(Permissions::Edit, &kimi), Some("default"));
        assert_eq!(pick(Permissions::Full, &kimi), Some("yolo"));
        assert_eq!(pick(Permissions::ReadOnly, &ids(&["default"])), None);
        assert_eq!(pick_mode(Permissions::Full, None), Some("yolo"));
    }

    #[test]
    fn options_follow_the_decision() {
        let all = opts(&["allow_once", "allow_always", "reject_once", "reject_always"]);
        assert_eq!(choose(&all, Decision::Allow), Some("id-allow_once"));
        assert_eq!(
            choose(&all, Decision::AllowSession),
            Some("id-allow_always")
        );
        assert_eq!(choose(&all, Decision::Deny), Some("id-reject_once"));
        let once = opts(&["allow_once", "reject_always"]);
        assert_eq!(choose(&once, Decision::AllowSession), Some("id-allow_once"));
        assert_eq!(choose(&once, Decision::Deny), Some("id-reject_always"));
        assert_eq!(
            choose(&opts(&["allow_always"]), Decision::Allow),
            Some("id-allow_always")
        );
        assert_eq!(choose(&opts(&["allow_once"]), Decision::Deny), None);
    }

    #[test]
    fn read_only_rejects_everything_that_may_change_things() {
        for k in ["edit", "delete", "move", "execute", "other", "mystery"] {
            assert!(mutating(kind(k)), "{k}");
        }
        for k in ["read", "search", "fetch", "think"] {
            assert!(!mutating(kind(k)), "{k}");
        }
    }

    #[test]
    fn ends_and_usage() {
        let end = |s: &str| turn_end(&v(s));
        assert_eq!(end(r#"{"stopReason":"end_turn"}"#), End::Done("stop"));
        assert_eq!(
            end(r#"{"stopReason":"max_tokens"}"#),
            End::Done("max_tokens")
        );
        assert_eq!(end(r#"{"stopReason":"cancelled"}"#), End::Cancelled);
        assert!(matches!(end(r#"{"stopReason":"refusal"}"#), End::Failed(_)));
        assert_eq!(
            usage(&v(
                r#"{"usage":{"inputTokens":5,"outputTokens":2,"cachedReadTokens":3}}"#
            )),
            Some(Usage {
                input_tokens: 5,
                output_tokens: 2,
                cached_input_tokens: 3,
                cost_usd: None
            })
        );
        assert_eq!(usage(&v(r#"{"stopReason":"end_turn"}"#)), None);
    }

    /// Agent messages of a real `agy acp` session (Antigravity 1.5.16).
    fn fixture() -> Vec<Value> {
        include_str!("fixtures/agy-acp.jsonl")
            .lines()
            .map(v)
            .collect()
    }

    #[test]
    fn recorded_transcript_maps_to_events() {
        let (mut mapper, mut text, mut acts) = (Mapper::default(), String::new(), vec![]);
        let (mut prompt, mut result) = (None, None);
        for m in fixture() {
            if m.get("method").is_some() && m.get("id").is_some() {
                let p = parse_prompt(&m).unwrap();
                acts.push(mapper.tool(&p.tool).unwrap());
                prompt = Some(p);
                continue;
            }
            if m["id"] == 4 {
                result = Some(m["result"].clone());
            }
            for ev in mapper.update(&m) {
                match ev {
                    Ev::Text(t) => text.push_str(&t),
                    Ev::Activity(a) => acts.push(a),
                    _ => {}
                }
            }
        }
        for ev in mapper.finish() {
            if let Ev::Activity(a) = ev {
                acts.push(a);
            }
        }
        assert_eq!(text, "DONE");
        let last = |id: &str| acts.iter().rfind(|a| a.id == id).unwrap();
        let write = last("call_2545151993844110975");
        assert_eq!(
            (write.kind, write.title.as_str(), write.status),
            (
                ActivityKind::Edit,
                "File /work/a.txt",
                ActivityStatus::Completed
            )
        );
        // The permission request carried the diff; later updates refine it.
        let d = write.diff.as_ref().unwrap();
        assert_eq!(
            (d.path.as_str(), d.before.as_deref(), d.after.as_str()),
            ("/work/a.txt", Some("hello"), "bye")
        );
        let read = last("call_1171175624092027183");
        assert_eq!(
            (read.kind, read.status),
            (ActivityKind::Read, ActivityStatus::Completed)
        );
        // One reasoning activity per contiguous run of thought chunks, both finished.
        let thoughts: Vec<_> = acts
            .iter()
            .filter(|a| a.id.starts_with("thought-"))
            .collect();
        assert!(
            thoughts
                .iter()
                .any(|a| a.id == "thought-1" && a.status == ActivityStatus::Completed)
        );
        assert!(
            thoughts
                .iter()
                .any(|a| a.id == "thought-2" && a.status == ActivityStatus::Completed)
        );
        assert!(
            thoughts
                .iter()
                .all(|a| a.kind == ActivityKind::Reasoning && a.detail.is_some())
        );
        assert!(acts.iter().all(|a| a.approval.is_none()));
        let p = prompt.unwrap();
        assert_eq!((p.request_id.as_str(), p.id.clone()), ("1", json!("1")));
        assert_eq!(p.tool_id, "call_2545151993844110975");
        assert_eq!(choose(&p.options, Decision::Allow), Some("allow"));
        assert_eq!(choose(&p.options, Decision::Deny), Some("deny"));
        assert!(!p.remember);
        let result = result.unwrap();
        assert_eq!(turn_end(&result), End::Done("stop"));
        let u = usage(&result).unwrap();
        assert_eq!(
            (u.input_tokens, u.output_tokens, u.cached_input_tokens),
            (17541, 779, 26314)
        );
    }

    #[test]
    fn updates_merge_and_text_gets_paragraphs() {
        let mut m = Mapper::default();
        let up = |m: &mut Mapper, s: &str| m.update(&v(s));
        let text = |evs: Vec<Ev>| -> String {
            evs.into_iter()
                .filter_map(|e| match e {
                    Ev::Text(t) => Some(t),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            text(up(
                &mut m,
                r#"{"method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Looking."}}}}"#
            )),
            "Looking."
        );
        let evs = up(
            &mut m,
            r#"{"method":"session/update","params":{"update":{"sessionUpdate":"tool_call","toolCallId":"t","title":"ls","kind":"execute","status":"in_progress"}}}"#,
        );
        let Ev::Activity(a) = &evs[0] else { panic!() };
        assert_eq!((a.kind, a.title.as_str()), (ActivityKind::Execute, "ls"));
        // A partial update keeps title and kind and adds output.
        let evs = up(
            &mut m,
            r#"{"method":"session/update","params":{"update":{"sessionUpdate":"tool_call_update","toolCallId":"t","status":"failed","content":[{"type":"content","content":{"type":"text","text":"boom"}}]}}}"#,
        );
        let Ev::Activity(a) = &evs[0] else { panic!() };
        assert_eq!(
            (a.title.as_str(), a.status, a.detail.as_deref()),
            ("ls", ActivityStatus::Failed, Some("boom"))
        );
        // A late "pending" does not reopen a finished call.
        let evs = up(
            &mut m,
            r#"{"method":"session/update","params":{"update":{"sessionUpdate":"tool_call_update","toolCallId":"t","status":"in_progress"}}}"#,
        );
        let Ev::Activity(a) = &evs[0] else { panic!() };
        assert_eq!(a.status, ActivityStatus::Failed);
        assert_eq!(
            text(up(
                &mut m,
                r#"{"method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Done."}}}}"#
            )),
            "\n\nDone."
        );
        // Title falls back to the first location, then the tool name.
        let evs = up(
            &mut m,
            r#"{"method":"session/update","params":{"update":{"sessionUpdate":"tool_call","toolCallId":"u","kind":"delete","locations":[{"path":"/w/x"}]}}}"#,
        );
        let Ev::Activity(a) = &evs[0] else { panic!() };
        assert_eq!((a.kind, a.title.as_str()), (ActivityKind::Edit, "/w/x"));
        assert!(up(&mut m, r#"{"method":"session/update","params":{"update":{"sessionUpdate":"usage_update","used":1}}}"#).is_empty());
        assert!(up(&mut m, r#"{"method":"other"}"#).is_empty());
        assert!(parse_prompt(&v(r#"{"id":1,"method":"fs/read_text_file","params":{}}"#)).is_none());
    }

    #[test]
    fn available_commands_are_parsed() {
        let list = parse_commands(&v(
            r#"{"method":"session/update","params":{"update":{"sessionUpdate":"available_commands_update","availableCommands":[{"name":"compact","description":"Compact the conversation."},{"name":"plan","description":"Plan","input":{"hint":"<goal>"}}]}}}"#,
        ))
        .unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(
            (list[0].name.as_str(), list[0].argument_hint.as_str()),
            ("compact", "")
        );
        assert_eq!(list[1].argument_hint, "<goal>");
        assert!(parse_commands(&v(
            r#"{"method":"session/update","params":{"update":{"sessionUpdate":"usage_update"}}}"#
        ))
        .is_none());
    }
}
