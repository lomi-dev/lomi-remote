//! One long-lived Claude Code process per thread, driven over bidirectional
//! stream-json: user turns go to stdin, tool-permission prompts arrive as
//! `control_request` lines and are answered through [`ClaudeSession::respond`].
//! The turn loop itself lives in the engine; this module owns the process
//! plumbing ([`Wire`], shared with the Codex app-server), the control-message
//! builders and the pending-approval table.
use crate::{
    cli,
    store::{self, Decision, QuestionItem, QuestionOption, ThreadCommand},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{
        Mutex as AsyncMutex,
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    },
};

pub const NOT_PENDING: &str = "This request is no longer pending.";
/// How long the pipes may stay open after the CLI exited (a grandchild outside its group may hold them).
pub const DRAIN: Duration = Duration::from_secs(2);
const DENY_MESSAGE: &str = "The user declined this action.";

/// Identifies a process: sessions are reused only when binary, cwd and argv
/// (model, effort, permissions, system prompt; never `--resume`) are equal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    bin: PathBuf,
    cwd: PathBuf,
    args: Vec<String>,
}

impl Key {
    pub fn new(spec: &cli::Spec) -> Self {
        Self {
            bin: spec.bin.clone(),
            cwd: spec.cwd.clone(),
            args: spec.args.clone(),
        }
    }

    /// Like [`Key::new`], with `extra` settings that also identify the process.
    pub fn with(spec: &cli::Spec, extra: Vec<String>) -> Self {
        let mut key = Self::new(spec);
        key.args.extend(extra);
        key
    }
}

/// A `can_use_tool` request kept until the user answers.
#[derive(Debug, PartialEq)]
pub struct ToolRequest {
    pub request_id: String,
    pub tool_use_id: String,
    pub tool_name: String,
    pub input: Value,
    /// `permission_suggestions` exactly as the CLI sent them.
    pub suggestions: Option<Value>,
}

/// Parses a `can_use_tool` control request; None for any other line.
pub fn parse_tool_request(v: &Value) -> Option<ToolRequest> {
    let r = &v["request"];
    if v["type"] != "control_request" || r["subtype"] != "can_use_tool" {
        return None;
    }
    let request_id = v["request_id"].as_str()?.to_string();
    Some(ToolRequest {
        tool_use_id: r["tool_use_id"].as_str().unwrap_or(&request_id).to_string(),
        tool_name: r["tool_name"].as_str()?.to_string(),
        input: r["input"].clone(),
        suggestions: r["permission_suggestions"]
            .as_array()
            .filter(|a| !a.is_empty())
            .map(|_| r["permission_suggestions"].clone()),
        request_id,
    })
}

/// The tool through which Claude asks the user questions.
pub const ASK_TOOL: &str = "AskUserQuestion";
/// Largest answer text and number of values per question that reach the CLI.
const ANSWER_CAP: usize = 4000;
const ANSWER_VALUES: usize = 16;

/// Tools that cannot change anything; every other tool is denied on a read-only thread.
pub fn read_only_tool(name: &str) -> bool {
    matches!(
        name,
        "Read" | "Grep" | "Glob" | "LS" | "WebFetch" | "WebSearch" | "TodoWrite" | ASK_TOOL
    )
}

/// The questions of an `AskUserQuestion` input; the question text is the answer key.
pub fn question_items(input: &Value) -> Vec<QuestionItem> {
    let text = |v: &Value, k: &str| v[k].as_str().unwrap_or_default().to_string();
    input["questions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|q| q["question"].as_str().is_some_and(|t| !t.is_empty()))
        .take(store::MAX_QUESTIONS)
        .map(|q| QuestionItem {
            id: text(q, "question"),
            header: text(q, "header"),
            question: text(q, "question"),
            options: q["options"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|o| QuestionOption {
                    label: text(o, "label"),
                    description: text(o, "description"),
                })
                .collect(),
            multi_select: q["multiSelect"] == true,
            allow_other: true,
            secret: false,
        })
        .collect()
}

/// Checks that `answers` only names asked items and stays small.
pub fn valid_answers(ids: &[&str], answers: &HashMap<String, Vec<String>>) -> Result<(), String> {
    let ok = answers.iter().all(|(k, v)| {
        ids.contains(&k.as_str())
            && v.len() <= ANSWER_VALUES
            && v.iter().all(|a| a.len() <= ANSWER_CAP)
    });
    ok.then_some(())
        .ok_or_else(|| "Invalid answer.".to_string())
}

/// The `control_response` answering `AskUserQuestion`: the input plus `answers`
/// by question text (several choices joined with ", "), or a denial when declined.
pub fn answer_line(r: &ToolRequest, answers: Option<&HashMap<String, Vec<String>>>) -> String {
    let Some(answers) = answers else {
        return reply_line(r, Decision::Deny, false);
    };
    let joined: serde_json::Map<String, Value> = answers
        .iter()
        .map(|(k, v)| (k.clone(), json!(v.join(", "))))
        .collect();
    let mut input = r.input.clone();
    input["answers"] = Value::Object(joined);
    line(
        json!({"type":"control_response","response":{"subtype":"success","request_id":r.request_id,"response":{"behavior":"allow","updatedInput":input}}}),
    )
}

/// The commands of an `initialize` response or a `commands_changed` message.
pub fn parse_commands(v: &Value) -> Option<Vec<ThreadCommand>> {
    let list = match v["type"].as_str()? {
        "control_response" => &v["response"]["response"]["commands"],
        "system" if v["subtype"] == "commands_changed" => &v["commands"],
        _ => return None,
    };
    let text = |c: &Value, k: &str| c[k].as_str().unwrap_or_default().to_string();
    Some(
        list.as_array()?
            .iter()
            .filter(|c| c["name"].as_str().is_some_and(|n| !n.is_empty()))
            .map(|c| ThreadCommand {
                name: text(c, "name"),
                description: text(c, "description"),
                argument_hint: text(c, "argumentHint"),
            })
            .collect(),
    )
}

pub fn line(v: Value) -> String {
    format!("{v}\n")
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_GEN: AtomicU64 = AtomicU64::new(1);

/// A number unique to one process of this app run; scopes JSON-RPC ids shown to the UI.
pub fn next_generation() -> u64 {
    NEXT_GEN.fetch_add(1, Ordering::Relaxed)
}

fn request(subtype: &str) -> String {
    let id = format!("lomi-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    line(json!({"type":"control_request","request_id":id,"request":{"subtype":subtype}}))
}

pub fn user_line(text: &str) -> String {
    line(json!({"type":"user","message":{"role":"user","content":text}}))
}

pub fn unsupported_line(request_id: &str) -> String {
    line(
        json!({"type":"control_response","response":{"subtype":"error","request_id":request_id,"error":"Unsupported request."}}),
    )
}

/// The `control_response` answering a permission prompt.
pub fn reply_line(r: &ToolRequest, decision: Decision, interrupt: bool) -> String {
    let mut body = match decision {
        Decision::Deny => json!({"behavior":"deny","message":DENY_MESSAGE}),
        _ => json!({"behavior":"allow","updatedInput":r.input}),
    };
    if decision == Decision::AllowSession
        && let Some(s) = &r.suggestions
    {
        // Suggestions may target settings files; "allow for session" must never persist.
        let mut s = s.clone();
        for item in s.as_array_mut().into_iter().flatten() {
            if let Some(o) = item.as_object_mut() {
                o.insert("destination".into(), json!("session"));
            }
        }
        body["updatedPermissions"] = s;
    }
    if interrupt && decision == Decision::Deny {
        body["interrupt"] = json!(true);
    }
    line(
        json!({"type":"control_response","response":{"subtype":"success","request_id":r.request_id,"response":body}}),
    )
}

/// The user's answer, forwarded to the turn loop so it can update the activity.
pub struct Answer {
    pub request_id: String,
    pub allowed: bool,
    /// The chosen values of a question; `None` for a permission prompt or a declined question.
    pub answers: Option<HashMap<String, Vec<String>>>,
}

/// Receivers owned by the running turn (one turn per session at a time).
pub struct Rx {
    pub lines: UnboundedReceiver<String>,
    pub answers: UnboundedReceiver<Answer>,
}

impl Rx {
    /// Drops whatever arrived between turns (initialize ack, late events).
    pub fn drain(&mut self) {
        self.drain_with(|_| {});
    }

    /// Like [`Rx::drain`], showing each dropped line to `f`.
    pub fn drain_with(&mut self, mut f: impl FnMut(&str)) {
        while let Ok(l) = self.lines.try_recv() {
            f(&l);
        }
        while self.answers.try_recv().is_ok() {}
    }
}

/// Process plumbing shared by the persistent Claude and Codex sessions: the
/// child in its own process group, a line reader, a writer queue, exit detail
/// and idle time. Dropping it kills the process group.
pub struct Wire {
    pgid: Option<u32>,
    out: UnboundedSender<String>,
    /// "The CLI exited ..." text, set by the reader task before the line channel closes.
    exit: Arc<Mutex<Option<String>>>,
    dead: Arc<AtomicBool>,
    used: Mutex<Instant>,
}

impl Wire {
    /// Starts the process with `args` (stdin stays open), queues `init` as the first
    /// line and returns the receiver of its stdout lines.
    /// `track` registers the process group for exit cleanup; its result lives as long as the process.
    /// Must run inside a Tokio runtime.
    pub fn start<G: Send + 'static>(
        spec: &cli::Spec,
        args: Vec<String>,
        init: Option<String>,
        track: impl FnOnce(Option<u32>) -> G,
    ) -> Result<(Self, UnboundedReceiver<String>), String> {
        let mut proc = cli::Proc::spawn(&cli::Spec {
            bin: spec.bin.clone(),
            args,
            stdin: None,
            interactive: true,
            cwd: spec.cwd.clone(),
        })?;
        let guard = track(proc.pgid());
        let mut stdin = proc.stdin.take().ok_or("Cannot write to the CLI.")?;
        let pgid = proc.pgid();
        let (out, mut out_rx) = unbounded_channel::<String>();
        let (tx, lines) = unbounded_channel();
        let exit = Arc::new(Mutex::new(None));
        let dead = Arc::new(AtomicBool::new(false));
        if let Some(l) = init {
            let _ = out.send(l);
        }
        tokio::spawn(async move {
            while let Some(l) = out_rx.recv().await {
                if stdin.write_all(l.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let (exit_w, dead_w) = (exit.clone(), dead.clone());
        tokio::spawn(async move {
            let _guard = guard;
            let (mut split, mut buf) = (cli::LineSplitter::default(), [0u8; 8192]);
            let mut drain_until: Option<tokio::time::Instant> = None;
            let mut oversize = false;
            loop {
                let n = tokio::select! {
                    r = proc.stdout.read(&mut buf) => r.unwrap_or(0),
                    _ = proc.child.wait(), if drain_until.is_none() => {
                        // Dead first: once reaped, the pgid may be reused and must never be signalled again.
                        dead_w.store(true, Ordering::Release);
                        // Grandchildren (MCP servers) may hold the pipe open; kill them so EOF arrives.
                        cli::kill_group(pgid);
                        drain_until = Some(tokio::time::Instant::now() + DRAIN);
                        continue;
                    }
                    // A grandchild that left the group can still hold the pipe; stop waiting for EOF.
                    _ = tokio::time::sleep_until(drain_until.unwrap_or_else(tokio::time::Instant::now)), if drain_until.is_some() => break,
                };
                let ls = if n == 0 {
                    split.finish()
                } else {
                    split.push(&buf[..n])
                };
                for l in ls {
                    let _ = tx.send(l);
                }
                if split.take_dropped() && !oversize {
                    // A lost line may carry a permission prompt or the result; fail the turn
                    // by ending the process instead of waiting for it forever.
                    oversize = true;
                    dead_w.store(true, Ordering::Release);
                    cli::kill_group(pgid);
                }
                if n == 0 {
                    break;
                }
            }
            let (_, status, stderr) = proc.finish().await;
            let detail = if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            };
            *exit_w.lock().unwrap_or_else(|e| e.into_inner()) = Some(if oversize {
                "The CLI sent a message that is too large; the reply was stopped.".to_string()
            } else {
                format!("The CLI exited ({status}){detail}")
            });
            dead_w.store(true, Ordering::Release);
        });
        let wire = Self {
            pgid,
            out,
            exit,
            dead,
            used: Mutex::new(Instant::now()),
        };
        Ok((wire, lines))
    }

    pub fn alive(&self) -> bool {
        !self.dead.load(Ordering::Acquire) && !self.out.is_closed()
    }

    pub fn exit_detail(&self) -> String {
        self.exit
            .lock()
            .ok()
            .and_then(|e| e.clone())
            .unwrap_or_else(|| "The CLI exited unexpectedly.".into())
    }

    pub fn kill(&self) {
        if !self.dead.load(Ordering::Acquire) {
            cli::kill_group(self.pgid);
        }
    }

    pub fn write(&self, line: String) -> Result<(), String> {
        self.out
            .send(line)
            .map_err(|_| "The CLI session ended.".to_string())
    }

    pub fn touch(&self) {
        if let Ok(mut u) = self.used.lock() {
            *u = Instant::now();
        }
    }

    pub fn idle(&self) -> Duration {
        self.used.lock().map(|u| u.elapsed()).unwrap_or_default()
    }
}

impl Drop for Wire {
    fn drop(&mut self) {
        self.kill();
    }
}

pub struct ClaudeSession {
    pub key: Key,
    wire: Wire,
    answers: UnboundedSender<Answer>,
    rx: AsyncMutex<Rx>,
    pending: Mutex<HashMap<String, ToolRequest>>,
}

impl std::ops::Deref for ClaudeSession {
    type Target = Wire;

    fn deref(&self) -> &Wire {
        &self.wire
    }
}

impl ClaudeSession {
    /// Starts the process (`spec.args` plus `--resume`) and its reader/writer tasks.
    /// `at` truncates the resumed conversation after that assistant message (a rewind).
    /// Must run inside a Tokio runtime.
    pub fn spawn<G: Send + 'static>(
        spec: &cli::Spec,
        resume: Option<&str>,
        at: Option<&str>,
        track: impl FnOnce(Option<u32>) -> G,
    ) -> Result<Arc<Self>, String> {
        let mut args = spec.args.clone();
        if let Some(s) = resume {
            args.extend(["--resume".into(), s.into()]);
            if let Some(at) = at {
                args.extend(["--resume-session-at".into(), at.into()]);
            }
        }
        let (wire, lines) = Wire::start(spec, args, Some(request("initialize")), track)?;
        let (answers, answers_rx) = unbounded_channel();
        Ok(Arc::new(Self {
            key: Key::new(spec),
            wire,
            answers,
            rx: AsyncMutex::new(Rx {
                lines,
                answers: answers_rx,
            }),
            pending: Mutex::new(HashMap::new()),
        }))
    }

    pub async fn rx(&self) -> tokio::sync::MutexGuard<'_, Rx> {
        self.rx.lock().await
    }

    pub fn send_user(&self, text: &str) -> Result<(), String> {
        self.write(user_line(text))
    }

    pub fn interrupt(&self) {
        let _ = self.write(request("interrupt"));
    }

    pub fn add_pending(&self, r: ToolRequest) {
        if let Ok(mut p) = self.pending.lock() {
            p.insert(r.request_id.clone(), r);
        }
    }

    /// Forgets a prompt the CLI cancelled (`control_cancel_request`).
    pub fn cancel_pending(&self, request_id: &str) {
        if let Ok(mut p) = self.pending.lock() {
            p.remove(request_id);
        }
    }

    /// Answers a pending prompt on behalf of the user.
    pub fn respond(&self, request_id: &str, decision: Decision) -> Result<(), String> {
        let r = self.take(request_id, false)?;
        self.write(reply_line(&r, decision, false))?;
        let _ = self.answers.send(Answer {
            request_id: r.request_id,
            allowed: decision != Decision::Deny,
            answers: None,
        });
        Ok(())
    }

    /// Removes a pending prompt; `question` selects `AskUserQuestion` over permission prompts.
    fn take(&self, request_id: &str, question: bool) -> Result<ToolRequest, String> {
        let mut p = self.pending.lock().map_err(|_| NOT_PENDING.to_string())?;
        if p.get(request_id)
            .is_none_or(|r| (r.tool_name == ASK_TOOL) != question)
        {
            return Err(NOT_PENDING.into());
        }
        Ok(p.remove(request_id).expect("checked above"))
    }

    /// Answers a pending question; `None` declines it.
    pub fn answer(
        &self,
        request_id: &str,
        answers: Option<HashMap<String, Vec<String>>>,
    ) -> Result<(), String> {
        if let Some(a) = &answers {
            let p = self.pending.lock().map_err(|_| NOT_PENDING.to_string())?;
            let r = p.get(request_id).ok_or(NOT_PENDING)?;
            let items = question_items(&r.input);
            valid_answers(&items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), a)?;
        }
        let r = self.take(request_id, true)?;
        self.write(answer_line(&r, answers.as_ref()))?;
        let _ = self.answers.send(Answer {
            request_id: r.request_id,
            allowed: answers.is_some(),
            answers,
        });
        Ok(())
    }

    /// Denies (with interrupt) every unanswered prompt; the turn is over or being stopped.
    pub fn deny_pending(&self) {
        let all: Vec<ToolRequest> = self
            .pending
            .lock()
            .map(|mut p| p.drain().map(|(_, r)| r).collect())
            .unwrap_or_default();
        for r in all {
            let _ = self.write(reply_line(&r, Decision::Deny, true));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    fn tool() -> ToolRequest {
        parse_tool_request(&v(
            r#"{"type":"control_request","request_id":"R","request":{"subtype":"can_use_tool","tool_name":"Write","display_name":"Write","input":{"file_path":"b.txt","content":"x"},"description":"b.txt","permission_suggestions":[{"type":"setMode","mode":"acceptEdits","destination":"session"}],"tool_use_id":"toolu_1"}}"#,
        ))
        .unwrap()
    }

    #[test]
    fn parses_can_use_tool_only() {
        let t = tool();
        assert_eq!(
            (t.request_id.as_str(), t.tool_use_id.as_str()),
            ("R", "toolu_1")
        );
        assert_eq!(t.tool_name, "Write");
        assert_eq!(t.input["file_path"], "b.txt");
        assert!(t.suggestions.is_some());
        assert!(
            parse_tool_request(&v(
                r#"{"type":"control_request","request_id":"R","request":{"subtype":"interrupt"}}"#
            ))
            .is_none()
        );
        assert!(parse_tool_request(&v(r#"{"type":"result"}"#)).is_none());
    }

    #[test]
    fn replies_match_the_protocol() {
        let t = tool();
        let reply = |d, i| v(&reply_line(&t, d, i));
        let allow = reply(Decision::Allow, false);
        assert_eq!(
            allow,
            json!({"type":"control_response","response":{"subtype":"success","request_id":"R","response":{"behavior":"allow","updatedInput":{"file_path":"b.txt","content":"x"}}}})
        );
        let session = reply(Decision::AllowSession, false);
        assert_eq!(
            session["response"]["response"]["updatedPermissions"],
            json!([{"type":"setMode","mode":"acceptEdits","destination":"session"}])
        );
        // Persistent destinations are rewritten to the session.
        let persistent = ToolRequest {
            suggestions: Some(
                json!([{"type":"addRules","destination":"userSettings"},{"type":"setMode","mode":"acceptEdits","destination":"localSettings"}]),
            ),
            ..tool()
        };
        assert_eq!(
            v(&reply_line(&persistent, Decision::AllowSession, false))["response"]["response"]["updatedPermissions"],
            json!([{"type":"addRules","destination":"session"},{"type":"setMode","mode":"acceptEdits","destination":"session"}])
        );
        let deny = reply(Decision::Deny, false);
        assert_eq!(
            deny["response"]["response"],
            json!({"behavior":"deny","message":"The user declined this action."})
        );
        assert_eq!(
            reply(Decision::Deny, true)["response"]["response"]["interrupt"],
            true
        );
        // No suggestions: "allow for session" degrades to a plain allow.
        let plain = ToolRequest {
            suggestions: None,
            ..tool()
        };
        assert_eq!(v(&reply_line(&plain, Decision::AllowSession, false)), allow);
        assert!(reply_line(&t, Decision::Allow, false).ends_with('\n'));
    }

    #[test]
    fn other_control_lines() {
        assert_eq!(
            v(&unsupported_line("Q")),
            json!({"type":"control_response","response":{"subtype":"error","request_id":"Q","error":"Unsupported request."}})
        );
        let i = v(&request("interrupt"));
        assert_eq!(i["request"], json!({"subtype":"interrupt"}));
        assert!(i["request_id"].as_str().unwrap().starts_with("lomi-"));
        assert_eq!(
            v(&user_line("hi")),
            json!({"type":"user","message":{"role":"user","content":"hi"}})
        );
    }

    #[cfg(unix)] // drives /bin/sh
    #[tokio::test]
    async fn lines_close_when_a_grandchild_outside_the_group_holds_stdout() {
        // `set -m` puts the background sleep in its own process group, out of reach of kill_group.
        let spec = cli::Spec {
            bin: "/bin/sh".into(),
            args: vec!["-c".into(), "set -m; sleep 6 2>/dev/null & echo hi".into()],
            stdin: None,
            interactive: true,
            cwd: "/tmp".into(),
        };
        let (wire, mut lines) = Wire::start(&spec, spec.args.clone(), None, |_| ()).unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            let mut got = vec![];
            while let Some(l) = lines.recv().await {
                got.push(l);
            }
            got
        })
        .await
        .expect("line channel must close within the drain window");
        assert_eq!(closed, vec!["hi".to_string()]);
        assert!(!wire.alive());
        assert!(wire.exit_detail().starts_with("The CLI exited"));
    }

    #[cfg(unix)] // drives /bin/sh
    #[tokio::test]
    async fn an_oversized_line_ends_the_session_with_a_clear_error() {
        let spec = cli::Spec {
            bin: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "head -c 2000000 /dev/zero | tr '\\0' x; echo; sleep 30".into(),
            ],
            stdin: None,
            interactive: true,
            cwd: "/tmp".into(),
        };
        let (wire, mut lines) = Wire::start(&spec, spec.args.clone(), None, |_| ()).unwrap();
        let end = tokio::time::timeout(Duration::from_secs(10), async {
            while lines.recv().await.is_some() {}
        })
        .await;
        assert!(end.is_ok(), "the session must end, not hang");
        assert!(wire.exit_detail().contains("too large"));
    }

    #[test]
    fn key_ignores_resume_but_not_settings() {
        let spec = |model: &str| cli::Spec {
            bin: "claude".into(),
            args: vec!["-p".into(), "--model".into(), model.into()],
            stdin: None,
            interactive: true,
            cwd: "/w".into(),
        };
        assert_eq!(Key::new(&spec("a")), Key::new(&spec("a")));
        assert_ne!(Key::new(&spec("a")), Key::new(&spec("b")));
    }

    /// Sanitized capture of an `AskUserQuestion` permission request.
    fn ask() -> ToolRequest {
        parse_tool_request(&v(
            r#"{"type":"control_request","request_id":"Q","request":{"subtype":"can_use_tool","tool_name":"AskUserQuestion","input":{"questions":[{"question":"Which color do you prefer?","header":"Color","options":[{"label":"Red","description":"Pick red"},{"label":"Green","description":"Pick green"}],"multiSelect":true}]},"tool_use_id":"toolu_Q","requires_user_interaction":true}}"#,
        ))
        .unwrap()
    }

    #[test]
    fn questions_parse_and_answers_follow_the_protocol() {
        let r = ask();
        let items = question_items(&r.input);
        assert_eq!(items.len(), 1);
        let q = &items[0];
        assert_eq!(
            (
                q.id.as_str(),
                q.header.as_str(),
                q.multi_select,
                q.allow_other
            ),
            ("Which color do you prefer?", "Color", true, true)
        );
        assert_eq!(q.options[0].label, "Red");
        assert!(read_only_tool(ASK_TOOL));
        let answers = HashMap::from([(q.id.clone(), vec!["Red".to_string(), "Green".to_string()])]);
        let reply = v(&answer_line(&r, Some(&answers)));
        assert_eq!(reply["response"]["request_id"], "Q");
        let body = &reply["response"]["response"];
        assert_eq!(body["behavior"], "allow");
        // Several choices are joined; the rest of the input is echoed back.
        assert_eq!(
            body["updatedInput"]["answers"],
            json!({"Which color do you prefer?": "Red, Green"})
        );
        assert_eq!(body["updatedInput"]["questions"], r.input["questions"]);
        assert_eq!(
            v(&answer_line(&r, None))["response"]["response"]["behavior"],
            "deny"
        );
        let ids = [q.id.as_str()];
        assert!(valid_answers(&ids, &answers).is_ok());
        let other = HashMap::from([("nope".to_string(), vec![])]);
        assert!(valid_answers(&ids, &other).is_err());
        let long = HashMap::from([(q.id.clone(), vec!["x".repeat(ANSWER_CAP + 1)])]);
        assert!(valid_answers(&ids, &long).is_err());
    }

    #[test]
    fn commands_come_from_initialize_and_commands_changed() {
        // Sanitized: the real response also carries account data, which is never read.
        let init = v(
            r#"{"type":"control_response","response":{"subtype":"success","request_id":"lomi-1","response":{"commands":[{"name":"hello","description":"Say hello (project)","argumentHint":"<name>"},{"name":"deep-research","description":"Research","argumentHint":"","builtin":true},{"name":""}],"account":{"email":"x"}}}}"#,
        );
        let list = parse_commands(&init).unwrap();
        assert_eq!(
            list.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            ["hello", "deep-research"]
        );
        assert_eq!(list[0].argument_hint, "<name>");
        assert_eq!(list[1].argument_hint, "");
        let changed = v(
            r#"{"type":"system","subtype":"commands_changed","commands":[{"name":"a","description":"A"}]}"#,
        );
        assert_eq!(parse_commands(&changed).unwrap()[0].description, "A");
        // Other responses and system messages carry no list.
        assert!(
            parse_commands(&v(
                r#"{"type":"control_response","response":{"response":{}}}"#
            ))
            .is_none()
        );
        assert!(parse_commands(&v(r#"{"type":"system","subtype":"init"}"#)).is_none());
    }
}
