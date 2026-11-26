//! One long-lived `codex app-server` per thread (JSON-RPC 2.0 without the
//! `jsonrpc` field, newline-delimited over stdio). Turns go in as `turn/start`,
//! command and file-change approvals arrive as server requests and are answered
//! through [`CodexSession::respond`]. The turn loop lives in the engine; this
//! module owns the message builders, the notification mapping and the session.
use crate::{
    cli::{self, Ev},
    session::{Answer, Key, NOT_PENDING, Rx, Wire, line, next_generation},
    settings::Permissions,
    store::{
        self, Activity, ActivityDiff, ActivityKind, ActivityStatus, Decision, Question,
        QuestionItem, QuestionOption, QuestionState, ThreadCommand, Usage,
    },
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
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
    pub effort: Option<String>,
    pub permissions: Permissions,
    pub system: String,
    pub prompt: String,
    /// Absolute paths of attached images.
    pub images: Vec<String>,
    /// The message was `/compact`: compact the thread instead of starting a turn.
    pub compact: bool,
}

impl Params {
    /// Settings fixed when the thread starts; a change needs a new process.
    pub fn key_args(&self) -> Vec<String> {
        vec![
            self.model.clone().unwrap_or_default(),
            self.effort.clone().unwrap_or_default(),
            format!("{:?}", self.permissions),
            self.system.clone(),
        ]
    }

    /// `thread/start`, or `thread/resume` when `resume` names a native thread.
    pub fn thread_params(&self, resume: Option<&str>) -> Value {
        // Read-only never asks: on-request would offer to escalate writes.
        let (approval, sandbox) = match self.permissions {
            Permissions::ReadOnly => ("never", "read-only"),
            Permissions::Edit => ("on-request", "workspace-write"),
            Permissions::Full => ("never", "danger-full-access"),
        };
        let mut p = json!({"cwd": self.cwd, "approvalPolicy": approval, "sandbox": sandbox});
        if let Some(id) = resume {
            p["threadId"] = json!(id);
        }
        if let Some(m) = &self.model {
            p["model"] = json!(m);
        }
        if !self.system.is_empty() {
            p["developerInstructions"] = json!(self.system);
        }
        p
    }

    /// `turn/start`. Read-only turns run in plan mode, the only mode in which Codex asks the
    /// user questions (`requestUserInput`); plan mode needs a model, `model` is the thread's.
    pub fn turn_params(&self, thread_id: &str, model: Option<&str>) -> Value {
        let mut input = vec![json!({"type": "text", "text": self.prompt})];
        input.extend(
            self.images
                .iter()
                .map(|path| json!({"type": "localImage", "path": path})),
        );
        let mut p = json!({"threadId": thread_id, "input": input});
        if let Some(e) = &self.effort {
            p["effort"] = json!(e);
        }
        let model = self.model.as_deref().or(model);
        if let (Permissions::ReadOnly, Some(m)) = (self.permissions, model) {
            // `developer_instructions: null` keeps the built-in plan-mode instructions.
            p["collaborationMode"] = json!({"mode": "plan", "settings": {
                "model": m, "reasoning_effort": self.effort, "developer_instructions": null,
            }});
        }
        p
    }
}

pub fn request_line(id: u64, method: &str, params: Value) -> String {
    line(json!({"id": id, "method": method, "params": params}))
}

pub fn notification_line(method: &str) -> String {
    line(json!({"method": method}))
}

/// Refusal of a server request Lomi has no UI for.
pub fn unsupported_line(id: &Value) -> String {
    line(json!({"id": id, "error": {"code": -32601, "message": "Unsupported by Lomi."}}))
}

/// `turn/steer`: adds `text` to the running turn `turn_id`.
pub fn steer_params(thread_id: &str, turn_id: &str, text: &str) -> Value {
    json!({"threadId": thread_id, "expectedTurnId": turn_id, "input": [{"type": "text", "text": text}]})
}

/// Commands Codex offers without listing them.
pub fn commands() -> Vec<ThreadCommand> {
    vec![ThreadCommand {
        name: "compact".into(),
        description: "Summarize the conversation to free up the context window.".into(),
        argument_hint: String::new(),
    }]
}

/// Whether `v` completes a `thread/compact/start` (the compaction runs as a turn item).
pub fn compaction_done(v: &Value) -> bool {
    v["method"] == "item/completed" && v["params"]["item"]["type"] == "contextCompaction"
}

/// A `requestUserInput` server request kept until the user answers.
#[derive(Debug, PartialEq)]
pub struct QuestionPrompt {
    pub id: Value,
    pub request_id: String,
    pub item_id: String,
    pub items: Vec<QuestionItem>,
    /// Ids of the secret questions; their answers are never stored.
    pub secret: Vec<String>,
}

/// Parses an `item/tool/requestUserInput` request; None for any other message.
pub fn parse_question(v: &Value) -> Option<QuestionPrompt> {
    if v["method"] != "item/tool/requestUserInput" {
        return None;
    }
    let id = v
        .get("id")
        .filter(|i| i.is_string() || i.is_number())?
        .clone();
    let p = &v["params"];
    let text = |q: &Value, k: &str| q[k].as_str().unwrap_or_default().to_string();
    let asked: Vec<&Value> = p["questions"]
        .as_array()?
        .iter()
        .filter(|q| q["id"].as_str().is_some_and(|i| !i.is_empty()))
        .take(store::MAX_QUESTIONS)
        .collect();
    if asked.is_empty() {
        return None;
    }
    Some(QuestionPrompt {
        request_id: id.as_str().map_or_else(|| id.to_string(), String::from),
        item_id: cli::str_at(p, &["itemId"])
            .filter(|s| !s.is_empty())?
            .into(),
        secret: asked
            .iter()
            .filter(|q| q["isSecret"] == true)
            .map(|q| text(q, "id"))
            .collect(),
        items: asked
            .iter()
            .map(|q| {
                let options: Vec<QuestionOption> = q["options"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|o| QuestionOption {
                        label: text(o, "label"),
                        description: text(o, "description"),
                    })
                    .collect();
                QuestionItem {
                    id: text(q, "id"),
                    header: text(q, "header"),
                    question: text(q, "question"),
                    // Without options, free text is the only way to answer.
                    allow_other: q["isOther"] == true || options.is_empty(),
                    options,
                    multi_select: false,
                    secret: q["isSecret"] == true,
                }
            })
            .collect(),
        id,
    })
}

impl QuestionPrompt {
    /// The activity of a question; its item may not have been announced before.
    pub fn activity(&self, scoped: &str) -> Activity {
        let title = self.items.first().map_or("", |i| i.header.as_str());
        let mut a = cli::activity(
            &self.item_id,
            ActivityKind::Question,
            title,
            ActivityStatus::Running,
        );
        a.question = Some(Box::new(Question {
            request_id: scoped.into(),
            items: self.items.clone(),
            state: QuestionState::Pending,
            answers: None,
        }));
        a
    }
}

/// The result of `requestUserInput`; a declined question is a refusal.
pub fn answers_line(id: &Value, answers: Option<&HashMap<String, Vec<String>>>) -> String {
    match answers {
        Some(a) => {
            let by_id: serde_json::Map<String, Value> = a
                .iter()
                .map(|(k, v)| (k.clone(), json!({"answers": v})))
                .collect();
            line(json!({"id": id, "result": {"answers": by_id}}))
        }
        None => line(
            json!({"id": id, "error": {"code": -32000, "message": "The user declined to answer."}}),
        ),
    }
}

/// The wire spelling of an answer; "for session" degrades to a plain accept
/// when the server did not offer it.
pub fn decision_line(id: &Value, decision: Decision, remember: bool) -> String {
    let d = match decision {
        Decision::Allow => "accept",
        Decision::AllowSession if remember => "acceptForSession",
        Decision::AllowSession => "accept",
        Decision::Deny => "decline",
    };
    line(json!({"id": id, "result": {"decision": d}}))
}

/// A command or file-change approval request kept until the user answers.
#[derive(Debug, PartialEq)]
pub struct Prompt {
    /// The JSON-RPC id, echoed in the answer.
    pub id: Value,
    /// Stringified [`Prompt::id`]: the approval's `request_id`.
    pub request_id: String,
    pub item_id: String,
    /// Command approval (else file change) and its command text, if sent.
    pub is_command: bool,
    pub command: Option<String>,
    pub reason: Option<String>,
    /// Whether "accept for session" was offered.
    pub remember: bool,
}

/// Parses an approval server request; None for any other message.
pub fn parse_prompt(v: &Value) -> Option<Prompt> {
    let is_command = match v["method"].as_str()? {
        "item/commandExecution/requestApproval" => true,
        "item/fileChange/requestApproval" => false,
        _ => return None,
    };
    let id = v
        .get("id")
        .filter(|i| i.is_string() || i.is_number())?
        .clone();
    let p = &v["params"];
    let text = |k: &str| {
        cli::str_at(p, &[k])
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    Some(Prompt {
        request_id: id.as_str().map_or_else(|| id.to_string(), String::from),
        item_id: text("itemId")?,
        is_command,
        command: text("command"),
        reason: text("reason"),
        // Without a decision list the server accepts every spelling.
        remember: p["availableDecisions"]
            .as_array()
            .is_none_or(|d| d.iter().any(|d| d == "acceptForSession")),
        id,
    })
}

impl Prompt {
    /// The activity of a prompt whose item was not announced before.
    pub fn activity(&self) -> Activity {
        let (kind, title) = match (&self.command, self.is_command) {
            (Some(c), _) => (ActivityKind::Execute, cli::codex_command(c).to_string()),
            (None, true) => (ActivityKind::Execute, "Command".into()),
            (None, false) => (ActivityKind::Edit, "File changes".into()),
        };
        let mut a = cli::activity(&self.item_id, kind, &title, ActivityStatus::Running);
        a.detail = self.reason.clone();
        a
    }
}

/// How a turn ended.
#[derive(Debug, PartialEq)]
pub enum End {
    Completed,
    Interrupted,
    Failed(String),
}

/// `turn/completed` as (turn id, end); None for any other message.
pub fn turn_end(v: &Value) -> Option<(String, End)> {
    if v["method"] != "turn/completed" {
        return None;
    }
    let t = &v["params"]["turn"];
    let end = match t["status"].as_str() {
        Some("completed") => End::Completed,
        Some("interrupted") => End::Interrupted,
        _ => End::Failed(
            cli::str_at(t, &["error", "message"])
                .unwrap_or("The turn failed.")
                .into(),
        ),
    };
    Some((t["id"].as_str().unwrap_or_default().into(), end))
}

/// Turn id of a `turn/started` notification or a `turn/start` result.
pub fn started_turn(v: &Value) -> Option<&str> {
    cli::str_at(&v["params"], &["turn", "id"])
        .or_else(|| cli::str_at(&v["result"], &["turn", "id"]))
}

fn texts(v: &Value) -> Option<String> {
    let all: Vec<&str> = v
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    (!all.is_empty()).then(|| all.join("\n\n"))
}

/// Maps notifications of one thread onto the engine's events.
#[derive(Default)]
pub struct Mapper {
    had_text: bool,
    /// Agent message whose text is being streamed.
    message: String,
    /// Reasoning text by item id, with the length last emitted.
    reasoning: HashMap<String, (String, usize)>,
    /// Sum of the per-request figures of this turn.
    usage: Option<Usage>,
}

impl Mapper {
    /// Text of a new agent message starts a paragraph.
    fn text(&mut self, id: &str, text: &str, out: &mut Vec<Ev>) {
        if text.is_empty() {
            return;
        }
        if self.message != id {
            self.message = id.into();
            if self.had_text {
                out.push(Ev::Text("\n\n".into()));
            }
        }
        self.had_text = true;
        out.push(Ev::Text(text.into()));
    }

    fn reasoning(&mut self, p: &Value, out: &mut Vec<Ev>) {
        let (Some(id), Some(delta)) = (cli::str_at(p, &["itemId"]), cli::str_at(p, &["delta"]))
        else {
            return;
        };
        let (text, sent) = self.reasoning.entry(id.into()).or_default();
        if text.len() < store::DETAIL_CAP {
            text.push_str(delta);
        }
        if text.len() >= *sent + REASONING_STEP {
            *sent = text.len();
            let mut a = cli::activity(
                id,
                ActivityKind::Reasoning,
                "Reasoning",
                ActivityStatus::Running,
            );
            a.detail = Some(text.clone());
            out.push(Ev::Activity(a));
        }
    }

    fn item(&mut self, started: bool, item: &Value, out: &mut Vec<Ev>) {
        let (Some(id), Some(ty)) = (cli::str_at(item, &["id"]), cli::str_at(item, &["type"]))
        else {
            return;
        };
        let (mut detail, mut diff) = (None, None);
        let (kind, title) = match ty {
            "agentMessage" => {
                if !started && self.message != id {
                    self.text(id, cli::str_at(item, &["text"]).unwrap_or(""), out);
                }
                return;
            }
            "commandExecution" => {
                let Some(command) = cli::str_at(item, &["command"]) else {
                    return;
                };
                detail = cli::str_at(item, &["aggregatedOutput"])
                    .filter(|o| !o.is_empty())
                    .map(String::from);
                (
                    ActivityKind::Execute,
                    cli::codex_command(command).to_string(),
                )
            }
            "fileChange" => {
                let changes = item["changes"].as_array().map_or(&[][..], Vec::as_slice);
                let path = |c: &Value| cli::str_at(c, &["path"]).map(String::from);
                let paths: Vec<String> = changes.iter().filter_map(path).collect();
                if let [c] = changes {
                    // An added file's diff is its content; an update carries a unified diff.
                    let text = cli::str_at(c, &["diff"]).filter(|d| !d.is_empty());
                    match (cli::str_at(c, &["kind", "type"]), text, path(c)) {
                        (Some("add"), Some(d), Some(path)) => {
                            diff = Some(ActivityDiff {
                                path,
                                before: None,
                                after: d.into(),
                            });
                        }
                        (_, Some(d), _) => detail = Some(d.into()),
                        _ => {}
                    }
                }
                (ActivityKind::Edit, paths.join(", "))
            }
            "reasoning" => {
                let streamed = self.reasoning.remove(id).map(|(t, _)| t);
                detail = texts(&item["summary"])
                    .or_else(|| texts(&item["content"]))
                    .or(streamed.filter(|t| !t.is_empty()));
                (ActivityKind::Reasoning, "Reasoning".into())
            }
            "mcpToolCall" => {
                let name = |k| cli::str_at(item, &[k]).unwrap_or("");
                (
                    ActivityKind::Other,
                    format!("{}.{}", name("server"), name("tool")),
                )
            }
            "webSearch" => (
                ActivityKind::Fetch,
                cli::str_at(item, &["query"]).unwrap_or("").into(),
            ),
            _ => return,
        };
        let ok = cli::str_at(item, &["status"]) == Some("completed")
            && item["exitCode"].as_i64().is_none_or(|c| c == 0);
        let status = match (started, ok) {
            (true, _) => ActivityStatus::Running,
            (false, true) => ActivityStatus::Completed,
            (false, false) => ActivityStatus::Failed,
        };
        let mut a = cli::activity(id, kind, &title, status);
        a.detail = detail;
        a.diff = diff;
        out.push(Ev::Activity(a));
    }

    /// Maps one notification; unknown methods are ignored.
    pub fn notification(&mut self, v: &Value) -> Vec<Ev> {
        let mut out = Vec::new();
        let p = &v["params"];
        match v["method"].as_str() {
            Some("item/agentMessage/delta") => {
                if let (Some(id), Some(d)) =
                    (cli::str_at(p, &["itemId"]), cli::str_at(p, &["delta"]))
                {
                    self.text(id, d, &mut out);
                }
            }
            Some("item/reasoning/summaryTextDelta" | "item/reasoning/textDelta") => {
                self.reasoning(p, &mut out);
            }
            Some(m @ ("item/started" | "item/completed")) => {
                self.item(m == "item/started", &p["item"], &mut out);
            }
            Some("thread/tokenUsage/updated") => {
                // `total` spans the whole thread; `last` is one model request.
                let last = &p["tokenUsage"]["last"];
                let n = |k: &str| last[k].as_u64().unwrap_or(0);
                let u = self.usage.get_or_insert(Usage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cached_input_tokens: 0,
                    cost_usd: None,
                });
                u.input_tokens += n("inputTokens");
                u.output_tokens += n("outputTokens");
                u.cached_input_tokens += n("cachedInputTokens");
                out.push(Ev::Usage(u.clone()));
            }
            _ => {}
        }
        out
    }
}

struct Pending {
    id: Value,
    remember: bool,
    /// For a question: its item ids with whether each is secret.
    question: Option<HashMap<String, bool>>,
}

/// One warm `codex app-server`, bound to one native Codex thread once started.
pub struct CodexSession {
    pub key: Key,
    wire: Wire,
    answers: UnboundedSender<Answer>,
    rx: AsyncMutex<Rx>,
    pending: Mutex<HashMap<String, Pending>>,
    next: AtomicU64,
    thread: Mutex<Option<String>>,
    /// The model the thread runs, as `thread/start` or `thread/resume` reported it.
    model: Mutex<Option<String>>,
    /// Prefix of the request ids shown to the UI: a stale answer cannot hit a later process.
    generation: u64,
}

impl std::ops::Deref for CodexSession {
    type Target = Wire;

    fn deref(&self) -> &Wire {
        &self.wire
    }
}

impl CodexSession {
    /// Starts `spec` (`codex app-server`); [`start`] performs the handshake.
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
            wire,
            answers,
            rx: AsyncMutex::new(Rx {
                lines,
                answers: answers_rx,
            }),
            pending: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            thread: Mutex::new(None),
            model: Mutex::new(None),
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

    /// The native thread id once the handshake succeeded.
    pub fn thread(&self) -> Option<String> {
        self.thread.lock().ok().and_then(|t| t.clone())
    }

    /// The thread's model once the handshake succeeded.
    pub fn model(&self) -> Option<String> {
        self.model.lock().ok().and_then(|m| m.clone())
    }

    pub fn interrupt(&self, thread_id: &str, turn_id: &str) {
        let _ = self.request(
            "turn/interrupt",
            json!({"threadId": thread_id, "turnId": turn_id}),
        );
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
                    remember: p.remember,
                    question: None,
                },
            );
        }
        key
    }

    /// Answers a pending prompt on behalf of the user.
    pub fn respond(&self, request_id: &str, decision: Decision) -> Result<(), String> {
        let p = self.take(request_id, false)?;
        self.write(decision_line(&p.id, decision, p.remember))?;
        let _ = self.answers.send(Answer {
            request_id: request_id.into(),
            allowed: decision != Decision::Deny,
            answers: None,
        });
        Ok(())
    }

    /// Registers a question and returns its scoped id; call before showing it.
    pub fn add_question(&self, q: &QuestionPrompt) -> String {
        let key = format!("{}:{}", self.generation, q.request_id);
        if let Ok(mut m) = self.pending.lock() {
            let ids = q
                .items
                .iter()
                .map(|i| (i.id.clone(), q.secret.contains(&i.id)))
                .collect();
            m.insert(
                key.clone(),
                Pending {
                    id: q.id.clone(),
                    remember: false,
                    question: Some(ids),
                },
            );
        }
        key
    }

    /// Removes a pending prompt; `question` selects `requestUserInput` over approvals.
    fn take(&self, request_id: &str, question: bool) -> Result<Pending, String> {
        let mut m = self.pending.lock().map_err(|_| NOT_PENDING.to_string())?;
        if m.get(request_id)
            .is_none_or(|p| p.question.is_some() != question)
        {
            return Err(NOT_PENDING.into());
        }
        Ok(m.remove(request_id).expect("checked above"))
    }

    /// Answers a pending question; `None` declines it.
    pub fn answer(
        &self,
        request_id: &str,
        answers: Option<HashMap<String, Vec<String>>>,
    ) -> Result<(), String> {
        if let Some(a) = &answers {
            let m = self.pending.lock().map_err(|_| NOT_PENDING.to_string())?;
            let ids = m
                .get(request_id)
                .and_then(|p| p.question.as_ref())
                .ok_or(NOT_PENDING)?;
            crate::session::valid_answers(&ids.keys().map(String::as_str).collect::<Vec<_>>(), a)?;
        }
        let p = self.take(request_id, true)?;
        self.write(answers_line(&p.id, answers.as_ref()))?;
        // The UI copy of a secret answer is never stored.
        let shown = answers.map(|mut a| {
            a.retain(|k, _| {
                p.question
                    .as_ref()
                    .is_some_and(|q| q.get(k) == Some(&false))
            });
            a
        });
        let _ = self.answers.send(Answer {
            request_id: request_id.into(),
            allowed: shown.is_some(),
            answers: shown,
        });
        Ok(())
    }

    /// Declines every unanswered prompt; the turn is over or being stopped.
    pub fn decline_pending(&self) {
        let all: Vec<Pending> = self
            .pending
            .lock()
            .map(|mut m| m.drain().map(|(_, p)| p).collect())
            .unwrap_or_default();
        for p in all {
            let _ = self.write(if p.question.is_some() {
                answers_line(&p.id, None)
            } else {
                decision_line(&p.id, Decision::Deny, false)
            });
        }
    }
}

/// Sends a request and waits for its response; other messages are dropped
/// (server requests are refused). Only for the handshake, before a turn runs.
async fn call(s: &CodexSession, rx: &mut Rx, method: &str, params: Value) -> Result<Value, String> {
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
                }
            } else if v["id"] == id {
                return match v.get("error") {
                    Some(e) => Err(e["message"]
                        .as_str()
                        .unwrap_or("Codex refused the request.")
                        .into()),
                    None => Ok(v["result"].clone()),
                };
            }
        }
    };
    tokio::time::timeout(CALL_TIMEOUT, wait)
        .await
        .map_err(|_| "Codex did not answer in time.".to_string())?
}

/// Handshake of a fresh process: `initialize`, `initialized`, then the thread.
/// A native thread is resumed; when that fails (whatever the reason, usually an
/// unknown thread) a new one replaces it. `revert_before` then drops that turn
/// and every later one from the resumed history (`thread/revert`); a failed
/// revert also replaces the thread. Returns the native thread id and, when the
/// resume or revert failed, its error so the caller can tell the user the context was reset.
pub async fn start(
    s: &CodexSession,
    rx: &mut Rx,
    p: &Params,
    native: Option<&str>,
    revert_before: Option<&str>,
) -> Result<(String, Option<String>), String> {
    // `experimentalApi` enables plan mode (`collaborationMode`) and its questions.
    let info = json!({
        "clientInfo": {"name": "lomi", "title": "Lomi", "version": env!("CARGO_PKG_VERSION")},
        "capabilities": {"experimentalApi": true},
    });
    call(s, rx, "initialize", info).await?;
    s.write(notification_line("initialized"))?;
    let mut reset = None;
    let resumed = match native {
        Some(id) => match call(s, rx, "thread/resume", p.thread_params(Some(id))).await {
            Ok(r) => match revert_before {
                Some(turn) => {
                    let params = json!({"threadId": id, "beforeTurnId": turn});
                    match call(s, rx, "thread/revert", params).await {
                        // The resume result carries the model; the revert result does not.
                        Ok(_) => Some(r),
                        Err(e) => {
                            reset = Some(e);
                            None
                        }
                    }
                }
                None => Some(r),
            },
            Err(e) => {
                reset = Some(e);
                None
            }
        },
        None => None,
    };
    let result = match resumed {
        Some(r) => r,
        None => call(s, rx, "thread/start", p.thread_params(None)).await?,
    };
    let id = cli::str_at(&result, &["thread", "id"]).ok_or("Codex returned no thread.")?;
    if let Ok(mut t) = s.thread.lock() {
        *t = Some(id.into());
    }
    if let (Ok(mut m), Some(model)) = (s.model.lock(), cli::str_at(&result, &["model"])) {
        *m = Some(model.into());
    }
    Ok((id.into(), reset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(permissions: Permissions) -> Params {
        Params {
            cwd: "/w".into(),
            model: Some("gpt-x".into()),
            effort: Some("high".into()),
            permissions,
            system: "Be brief.".into(),
            prompt: "hi".into(),
            images: vec!["/a/p.png".into()],
            compact: false,
        }
    }

    fn v(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn builders_match_the_protocol() {
        let edit = params(Permissions::Edit);
        assert_eq!(
            edit.thread_params(None),
            json!({"cwd":"/w","approvalPolicy":"on-request","sandbox":"workspace-write","model":"gpt-x","developerInstructions":"Be brief."})
        );
        let read = params(Permissions::ReadOnly).thread_params(Some("T"));
        assert_eq!(
            (
                read["approvalPolicy"].as_str(),
                read["sandbox"].as_str(),
                read["threadId"].as_str()
            ),
            (Some("never"), Some("read-only"), Some("T"))
        );
        let full = Params {
            model: None,
            system: String::new(),
            ..params(Permissions::Full)
        }
        .thread_params(None);
        assert_eq!(
            full,
            json!({"cwd":"/w","approvalPolicy":"never","sandbox":"danger-full-access"})
        );
        assert_eq!(
            edit.turn_params("T", Some("gpt-y")),
            json!({"threadId":"T","input":[{"type":"text","text":"hi"},{"type":"localImage","path":"/a/p.png"}],"effort":"high"})
        );
        // Read-only runs in plan mode, with the thread's model when none was chosen.
        let read = Params {
            model: None,
            images: vec![],
            ..params(Permissions::ReadOnly)
        };
        assert_eq!(
            read.turn_params("T", Some("gpt-y"))["collaborationMode"],
            json!({"mode":"plan","settings":{"model":"gpt-y","reasoning_effort":"high","developer_instructions":null}})
        );
        assert!(
            read.turn_params("T", None)
                .get("collaborationMode")
                .is_none()
        );
        assert_eq!(
            v(&request_line(3, "turn/interrupt", json!({"a":1}))),
            json!({"id":3,"method":"turn/interrupt","params":{"a":1}})
        );
        assert_eq!(
            v(&notification_line("initialized")),
            json!({"method":"initialized"})
        );
        assert_eq!(
            v(&unsupported_line(&json!("x"))),
            json!({"id":"x","error":{"code":-32601,"message":"Unsupported by Lomi."}})
        );
        let d = |d, r| v(&decision_line(&json!(0), d, r))["result"]["decision"].clone();
        assert_eq!(d(Decision::Allow, true), "accept");
        assert_eq!(d(Decision::AllowSession, true), "acceptForSession");
        assert_eq!(d(Decision::AllowSession, false), "accept");
        assert_eq!(d(Decision::Deny, true), "decline");
        assert!(decision_line(&json!(0), Decision::Allow, true).ends_with('\n'));
        assert_ne!(edit.key_args(), params(Permissions::Full).key_args());
    }

    /// Server messages of a real `codex app-server` session (codex-cli 0.171.0).
    fn fixture() -> Vec<Value> {
        include_str!("fixtures/codex-app-server.jsonl")
            .lines()
            .map(v)
            .collect()
    }

    #[test]
    fn recorded_transcript_maps_to_events() {
        let (mut mapper, mut text, mut acts, mut usage) =
            (Mapper::default(), String::new(), vec![], None);
        let (mut end, mut prompt, mut turn) = (None, None, None);
        for m in fixture() {
            if m.get("method").is_some() && m.get("id").is_some() {
                prompt = parse_prompt(&m);
                continue;
            }
            turn = turn.or(started_turn(&m).map(String::from));
            end = end.or(turn_end(&m));
            for ev in mapper.notification(&m) {
                match ev {
                    Ev::Text(t) => text.push_str(&t),
                    Ev::Activity(a) => acts.push(a),
                    Ev::Usage(u) => usage = Some(u),
                    _ => {}
                }
            }
        }
        assert_eq!(
            text,
            "I’ll write `bye` to `a.txt`, then request the home-directory write through the shell.\n\nDONE"
        );
        assert!(turn.is_some());
        assert_eq!(end.map(|e| e.1), Some(End::Completed));
        // Started, then completed, for each of the two commands.
        let last = |id: &str| acts.iter().rfind(|a| a.id.starts_with(id)).unwrap();
        let first = last("exec-6088");
        assert_eq!(
            (first.kind, first.title.as_str(), first.status),
            (
                ActivityKind::Execute,
                "printf %s bye > a.txt",
                ActivityStatus::Completed
            )
        );
        assert_eq!(acts.iter().filter(|a| a.id.starts_with("exec-")).count(), 4);
        assert!(acts.iter().all(|a| a.approval.is_none()));
        let u = usage.unwrap();
        assert_eq!(
            (u.input_tokens, u.output_tokens, u.cached_input_tokens),
            (52844, 127, 34944)
        );
        let p = prompt.unwrap();
        assert_eq!((p.request_id.as_str(), p.id.clone()), ("0", json!(0)));
        assert!(p.item_id.starts_with("exec-8d84"));
        assert!(
            p.reason
                .as_deref()
                .unwrap()
                .contains("outside the writable workspace")
        );
        // The server did not offer "for session".
        assert!(!p.remember);
        assert_eq!(p.activity().title, "printf %s x > ~/.lomi-rec-outside.txt");
    }

    #[test]
    fn file_changes_reasoning_and_failures() {
        let mut m = Mapper::default();
        let ev = |m: &mut Mapper, s: &str| m.notification(&v(s));
        let acts = |evs: Vec<Ev>| -> Vec<Activity> {
            evs.into_iter()
                .filter_map(|e| match e {
                    Ev::Activity(a) => Some(a),
                    _ => None,
                })
                .collect()
        };
        let a = &acts(ev(
            &mut m,
            r#"{"method":"item/completed","params":{"item":{"type":"fileChange","id":"f1","status":"completed","changes":[{"path":"/w/n.txt","kind":{"type":"add"},"diff":"hello"}]}}}"#,
        ))[0];
        assert_eq!(
            (a.kind, a.title.as_str(), a.status),
            (ActivityKind::Edit, "/w/n.txt", ActivityStatus::Completed)
        );
        assert_eq!(a.diff.as_ref().unwrap().after, "hello");
        let a = &acts(ev(
            &mut m,
            r#"{"method":"item/completed","params":{"item":{"type":"fileChange","id":"f2","status":"declined","changes":[{"path":"a","kind":{"type":"update","move_path":null},"diff":"@@ -1 +1 @@"},{"path":"b","kind":{"type":"delete"},"diff":""}]}}}"#,
        ))[0];
        assert_eq!(
            (a.title.as_str(), a.status, a.diff.is_none()),
            ("a, b", ActivityStatus::Failed, true)
        );
        let a = &acts(ev(
            &mut m,
            r#"{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"c","command":"/bin/zsh -lc 'false'","status":"completed","exitCode":1,"aggregatedOutput":"boom"}}}"#,
        ))[0];
        assert_eq!(
            (a.status, a.detail.as_deref()),
            (ActivityStatus::Failed, Some("boom"))
        );
        // Streamed reasoning is the fallback when the item carries no summary.
        let big = "x".repeat(300);
        let mid = acts(ev(
            &mut m,
            &format!(
                r#"{{"method":"item/reasoning/summaryTextDelta","params":{{"itemId":"r","delta":"{big}"}}}}"#
            ),
        ));
        assert_eq!(mid[0].status, ActivityStatus::Running);
        let done = acts(ev(
            &mut m,
            r#"{"method":"item/completed","params":{"item":{"type":"reasoning","id":"r","summary":[],"content":[]}}}"#,
        ));
        assert_eq!(
            (done[0].kind, done[0].detail.as_deref()),
            (ActivityKind::Reasoning, Some(big.as_str()))
        );
        assert!(
            ev(
                &mut m,
                r#"{"method":"mcpServer/startupStatus/updated","params":{}}"#
            )
            .is_empty()
        );
        let end = |s: &str| turn_end(&v(s)).unwrap().1;
        assert_eq!(
            end(
                r#"{"method":"turn/completed","params":{"turn":{"id":"t","status":"failed","error":{"message":"nope"}}}}"#
            ),
            End::Failed("nope".into())
        );
        assert_eq!(
            end(
                r#"{"method":"turn/completed","params":{"turn":{"id":"t","status":"interrupted"}}}"#
            ),
            End::Interrupted
        );
        assert!(turn_end(&v(r#"{"method":"turn/started","params":{}}"#)).is_none());
        assert!(
            parse_prompt(&v(
                r#"{"id":1,"method":"item/tool/requestUserInput","params":{}}"#
            ))
            .is_none()
        );
        let p = parse_prompt(&v(
            r#"{"id":"s-1","method":"item/fileChange/requestApproval","params":{"itemId":"f","availableDecisions":["accept","acceptForSession","cancel"]}}"#,
        ))
        .unwrap();
        assert_eq!(
            (p.request_id.as_str(), p.remember, p.activity().kind),
            ("s-1", true, ActivityKind::Edit)
        );
    }

    #[test]
    fn user_input_requests_parse_and_reply() {
        // Sanitized capture of `item/tool/requestUserInput`.
        let req = v(
            r#"{"method":"item/tool/requestUserInput","id":0,"params":{"threadId":"t","turnId":"u","itemId":"call_1","questions":[{"id":"color","header":"Color","question":"Which color do you prefer?","isOther":true,"isSecret":false,"options":[{"label":"Red","description":"Choose Red."}]},{"id":"pin","header":"PIN","question":"?","isOther":false,"isSecret":true,"options":null}],"isBlocking":true}}"#,
        );
        let q = parse_question(&req).unwrap();
        assert_eq!((q.request_id.as_str(), q.item_id.as_str()), ("0", "call_1"));
        assert_eq!(q.secret, ["pin"]);
        assert_eq!(q.items[0].options[0].label, "Red");
        assert!(q.items[0].allow_other && q.items[1].options.is_empty());
        // No options: free text is the only answer; `isSecret` reaches the item.
        assert!(q.items[1].allow_other && q.items[1].secret && !q.items[0].secret);
        assert_eq!(q.activity("7:0").question.unwrap().request_id, "7:0");
        assert!(
            parse_question(&v(
                r#"{"method":"item/tool/requestUserInput","id":1,"params":{}}"#
            ))
            .is_none()
        );
        assert!(
            parse_question(&v(
                r#"{"method":"item/commandExecution/requestApproval","id":1}"#
            ))
            .is_none()
        );
        let answers = HashMap::from([("color".to_string(), vec!["Green".to_string()])]);
        assert_eq!(
            v(&answers_line(&q.id, Some(&answers))),
            json!({"id":0,"result":{"answers":{"color":{"answers":["Green"]}}}})
        );
        assert_eq!(v(&answers_line(&q.id, None))["error"]["code"], -32000);
        assert_eq!(
            steer_params("T", "U", "go"),
            json!({"threadId":"T","expectedTurnId":"U","input":[{"type":"text","text":"go"}]})
        );
        assert!(compaction_done(&v(
            r#"{"method":"item/completed","params":{"item":{"type":"contextCompaction","id":"c"}}}"#
        )));
        assert!(!compaction_done(&v(
            r#"{"method":"item/completed","params":{"item":{"type":"agentMessage","id":"c"}}}"#
        )));
    }
}
