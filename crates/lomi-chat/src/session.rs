//! One long-lived Claude Code process per thread, driven over bidirectional
//! stream-json: user turns go to stdin, tool-permission prompts arrive as
//! `control_request` lines and are answered through [`ClaudeSession::respond`].
//! The turn loop itself lives in the engine; this module owns the process
//! plumbing ([`Wire`], shared with the Codex app-server), the control-message
//! builders and the pending-approval table.
use crate::{cli, store::Decision};
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

/// Tools that cannot change anything; every other tool is denied on a read-only thread.
pub fn read_only_tool(name: &str) -> bool {
    matches!(
        name,
        "Read" | "Grep" | "Glob" | "LS" | "WebFetch" | "WebSearch" | "TodoWrite"
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
        body["updatedPermissions"] = s.clone();
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
}

/// Receivers owned by the running turn (one turn per session at a time).
pub struct Rx {
    pub lines: UnboundedReceiver<String>,
    pub answers: UnboundedReceiver<Answer>,
}

impl Rx {
    /// Drops whatever arrived between turns (initialize ack, late events).
    pub fn drain(&mut self) {
        while self.lines.try_recv().is_ok() {}
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
            *exit_w.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(format!("The CLI exited ({status}){detail}"));
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
    /// Must run inside a Tokio runtime.
    pub fn spawn<G: Send + 'static>(
        spec: &cli::Spec,
        resume: Option<&str>,
        track: impl FnOnce(Option<u32>) -> G,
    ) -> Result<Arc<Self>, String> {
        let mut args = spec.args.clone();
        if let Some(s) = resume {
            args.extend(["--resume".into(), s.into()]);
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

    /// Answers a pending prompt on behalf of the user.
    pub fn respond(&self, request_id: &str, decision: Decision) -> Result<(), String> {
        let r = self
            .pending
            .lock()
            .map_err(|_| NOT_PENDING.to_string())?
            .remove(request_id)
            .ok_or(NOT_PENDING)?;
        self.write(reply_line(&r, decision, false))?;
        let _ = self.answers.send(Answer {
            request_id: r.request_id,
            allowed: decision != Decision::Deny,
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
}
