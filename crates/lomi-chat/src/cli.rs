//! Chat through system CLIs: argv, JSONL stream parsers, status and model
//! probes, and the child process wrapper. Never starts a login flow.
use crate::settings::Permissions;
use crate::store::{Activity, ActivityDiff, ActivityKind, ActivityStatus, DETAIL_CAP, Usage};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    task::JoinHandle,
};

pub const CLIS: [&str; 4] = ["claude", "codex", "kimi", "agy"];
/// Longest accepted stdout line; longer lines are dropped whole.
const LINE_CAP: usize = 1024 * 1024;
const STDERR_CAP: usize = 64 * 1024;
const STDERR_SHOWN: usize = 2000;
const MAX_MODELS: usize = 500;
/// kimi and agy take the prompt as an argument; bound it well below the OS argv limit.
const ARG_PROMPT_CAP: usize = 100 * 1024;

/// Binary lookup only; never spawns.
pub fn installed_clis() -> Vec<String> {
    CLIS.into_iter()
        .filter(|id| crate::cli_bin::resolve(id).is_some())
        .map(String::from)
        .collect()
}

pub fn supported(cli: &str) -> bool {
    CLIS.contains(&cli)
}

pub fn display_name(cli: &str) -> &'static str {
    match cli {
        "claude" => "Claude Code",
        "codex" => "Codex",
        "kimi" => "Kimi Code",
        _ => "Antigravity",
    }
}

/// Model and session IDs become argv values: reject anything an option parser could read as a flag.
pub fn valid_arg_id(id: &str, max: usize) -> bool {
    !id.is_empty()
        && id.chars().count() <= max
        && !id.starts_with('-')
        && !id.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Fallback model id meaning "omit the model flag"; real model ids are never this bare word.
pub const DEFAULT_MODEL: &str = "default";

/// Codex, Kimi and agy may list nothing yet (e.g. right after login); offer the CLI default.
fn with_default_model(mut list: Vec<CliModel>) -> Vec<CliModel> {
    if list.is_empty() {
        list.push(CliModel {
            id: DEFAULT_MODEL.into(),
            label: "CLI default".into(),
            efforts: vec![],
        });
    }
    list
}

pub fn valid_model(id: &str) -> Result<(), String> {
    if valid_arg_id(id, 256) {
        Ok(())
    } else {
        Err("Invalid CLI model ID.".into())
    }
}

pub fn valid_session(id: &str) -> bool {
    valid_arg_id(id, 128)
}

pub fn check_prompt(cli: &str, text: &str) -> Result<(), String> {
    if matches!(cli, "kimi" | "agy") && text.len() > ARG_PROMPT_CAP {
        return Err(format!(
            "This message is too long for {}.",
            display_name(cli)
        ));
    }
    Ok(())
}

// ---- argv ------------------------------------------------------------

pub struct Invocation<'a> {
    pub cli: &'a str,
    pub model: &'a str,
    pub cwd: &'a str,
    pub session: Option<&'a str>,
    pub system: &'a str,
    pub prompt: &'a str,
    /// Kimi read-only agent definition, bound when a session is created.
    pub agent_file: Option<&'a str>,
    pub permissions: Permissions,
    /// Reasoning effort; Kimi has no such option.
    pub effort: Option<&'a str>,
    /// Attachments folder to grant the CLI access to; set when files are attached.
    pub attach_dir: Option<&'a str>,
    /// Absolute paths of attached images (Codex `--image`).
    pub images: &'a [String],
    /// Host-only hardening: read-only threads also drop user/project config and
    /// tools that run code. The desktop always passes false.
    pub restricted: bool,
}

/// Appends the attachment list to the prompt; `files` holds (absolute path, display name).
pub fn attach_prompt(text: &str, files: &[(String, String)]) -> String {
    if files.is_empty() {
        return text.to_string();
    }
    let sep = if text.is_empty() { "" } else { "\n\n" };
    let list: String = files
        .iter()
        .map(|(path, name)| format!("\n- {path} ({name})"))
        .collect();
    format!("{text}{sep}Attached files:{list}")
}

/// Returns the argument list and the stdin payload (when the CLI reads the prompt there).
pub fn argv(i: &Invocation) -> (Vec<String>, Option<String>) {
    let mut a: Vec<String> = Vec::new();
    let mut add = |items: &[&str]| a.extend(items.iter().map(|s| s.to_string()));
    let stdin = match i.cli {
        "claude" => {
            add(&["-p", "--output-format", "stream-json", "--verbose"]);
            add(&["--include-partial-messages", "--model", i.model]);
            if let Some(d) = i.attach_dir {
                add(&[&format!("--add-dir={d}")]);
            }
            if let Some(sid) = i.session {
                add(&["--resume", sid]);
            }
            match i.permissions {
                Permissions::ReadOnly => {
                    // Plan mode keeps Claude from changing the project; the deny rule wins over any allow rule in the user's settings.
                    add(&["--permission-mode", "plan"]);
                    add(&["--disallowedTools", "Bash,Edit,Write,NotebookEdit"]);
                    if i.restricted {
                        add(&["--restricted", "--strict-mcp-config"]);
                    }
                }
                Permissions::Edit => add(&["--permission-mode", "acceptEdits"]),
                Permissions::Full => add(&["--permission-mode", "bypassPermissions"]),
            }
            if let Some(e) = i.effort {
                add(&["--effort", e]);
            }
            if !i.system.is_empty() {
                add(&["--append-system-prompt", i.system]);
            }
            Some(i.prompt.to_string())
        }
        "codex" => {
            let mode = match i.permissions {
                Permissions::ReadOnly => Some("read-only"),
                Permissions::Edit => Some("workspace-write"),
                Permissions::Full => None,
            };
            match i.session {
                // `exec resume` has no `-s` or `-C`; the sandbox goes through config and the cwd through the process.
                Some(sid) => {
                    // `exec resume` has no `--add-dir`; the read-only sandbox still reads the files.
                    add(&["exec", "resume", sid, "--json", "--skip-git-repo-check"]);
                    if let Some(mode) = mode {
                        add(&["-c", &format!("sandbox_mode=\"{mode}\"")]);
                    }
                }
                None => {
                    add(&["exec", "--json", "--skip-git-repo-check"]);
                    if let Some(mode) = mode {
                        add(&["-s", mode]);
                    }
                    add(&[&format!("--cd={}", i.cwd)]);
                    if let Some(d) = i.attach_dir {
                        add(&[&format!("--add-dir={d}")]);
                    }
                }
            }
            for path in i.images {
                add(&[&format!("--image={path}")]);
            }
            if mode.is_none() {
                add(&["--dangerously-bypass-approvals-and-sandbox"]);
            }
            if let Some(e) = i.effort {
                add(&["-c", &format!("model_reasoning_effort=\"{e}\"")]);
            }
            if i.restricted && i.permissions == Permissions::ReadOnly {
                // Skips the user's config.toml (MCP servers, hooks) and exec-policy rules.
                add(&["--ignore-user-config", "--ignore-rules"]);
            }
            if i.model != DEFAULT_MODEL {
                add(&["-m", i.model]);
            }
            add(&["-"]);
            Some(i.prompt.to_string())
        }
        "kimi" => {
            // `--prompt=` keeps a leading dash in the text from reading as a flag. Prompt mode
            // approves tools automatically and rejects `--plan`, so a new session binds a
            // read-only agent; resumed sessions restore that agent themselves.
            add(&[&format!("--prompt={}", i.prompt)]);
            add(&["--output-format", "stream-json"]);
            if i.model != DEFAULT_MODEL {
                add(&["-m", i.model]);
            }
            if let Some(d) = i.attach_dir {
                add(&[&format!("--add-dir={d}")]);
            }
            match (i.session, i.agent_file) {
                (Some(sid), _) => add(&["-S", sid]),
                (None, Some(file)) => add(&[&format!("--agent-file={file}")]),
                (None, None) => {}
            }
            // Prompt mode already approves tools and rejects `--auto` (Kimi Code 2.7).
            None
        }
        _ => {
            // A leading space keeps the text from reading as a flag.
            let prompt = if i.prompt.starts_with('-') {
                format!(" {}", i.prompt)
            } else {
                i.prompt.to_string()
            };
            add(&["-p", &prompt, "--output-format", "stream-json"]);
            if i.model != DEFAULT_MODEL {
                add(&["--model", i.model]);
            }
            if let Some(d) = i.attach_dir {
                add(&[&format!("--add-dir={d}")]);
            }
            if let Some(sid) = i.session {
                add(&["--conversation", sid]);
            }
            match i.permissions {
                Permissions::ReadOnly if i.restricted => add(&["--mode", "plan", "--sandbox"]),
                Permissions::ReadOnly => add(&["--mode", "plan"]),
                Permissions::Edit => add(&["--mode", "accept-edits"]),
                Permissions::Full => add(&["--mode", "auto", "--dangerously-skip-permissions"]),
            }
            if let Some(e) = i.effort {
                add(&["--effort", e]);
            }
            None
        }
    };
    (a, stdin)
}

// ---- stream parsing --------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Ev {
    Text(String),
    /// Full current state of a tool call or reasoning block; `at` is set by the engine.
    Activity(Activity),
    Usage(Usage),
    Session(String),
    /// Complete answer; used only when no text streamed.
    Final(String),
    Error(String),
}

pub struct Parser {
    cli: String,
    had_text: bool,
    /// Claude: id of the assistant message being streamed.
    message: String,
    /// Claude: last state of each activity, to complete it on a later event.
    acts: HashMap<String, Activity>,
    /// Claude: open thinking blocks by content index.
    thinking: HashMap<u64, String>,
}

pub(crate) fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

fn u64_at(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap_or(0)
}

pub(crate) fn activity(
    id: &str,
    kind: ActivityKind,
    title: &str,
    status: ActivityStatus,
) -> Activity {
    Activity {
        id: id.into(),
        kind,
        title: title.into(),
        status,
        at: 0,
        detail: None,
        diff: None,
        approval: None,
        question: None,
    }
}

fn claude_kind(tool: &str) -> ActivityKind {
    match tool {
        "Read" => ActivityKind::Read,
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => ActivityKind::Edit,
        "Bash" => ActivityKind::Execute,
        "Grep" | "Glob" | "LS" => ActivityKind::Search,
        "WebFetch" | "WebSearch" => ActivityKind::Fetch,
        "Task" | "Agent" => ActivityKind::Agent,
        _ => ActivityKind::Other,
    }
}

fn claude_title(tool: &str, input: &Value) -> String {
    let key = match tool {
        "Bash" => "command",
        "Read" | "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => "file_path",
        "Grep" | "Glob" => "pattern",
        "WebFetch" => "url",
        "WebSearch" => "query",
        "Task" | "Agent" => "description",
        _ => "",
    };
    str_at(input, &[key]).unwrap_or(tool).into()
}

fn claude_diff(tool: &str, input: &Value) -> Option<ActivityDiff> {
    let path = str_at(input, &["file_path"])?.to_string();
    match tool {
        "Edit" => Some(ActivityDiff {
            path,
            before: str_at(input, &["old_string"]).map(Into::into),
            after: str_at(input, &["new_string"])?.into(),
        }),
        "Write" => Some(ActivityDiff {
            path,
            before: None,
            after: str_at(input, &["content"])?.into(),
        }),
        _ => None,
    }
}

/// Activity of a Claude tool call that is not yet known from the stream (permission prompts).
pub fn claude_activity(id: &str, tool: &str, input: &Value) -> Activity {
    let mut a = activity(id, claude_kind(tool), tool, ActivityStatus::Running);
    a.title = claude_title(tool, input);
    a.diff = claude_diff(tool, input);
    a
}

/// Argv of a persistent Claude process: today's argv (without `--resume`, so the
/// result identifies the process) plus bidirectional stream-json and stdio permission prompts.
pub fn claude_session_argv(i: &Invocation) -> Vec<String> {
    let (mut args, _) = argv(&Invocation {
        session: None,
        ..*i
    });
    let extra = [
        "--input-format",
        "stream-json",
        "--permission-prompt-tool",
        "stdio",
    ];
    args.splice(1..1, extra.map(String::from));
    args
}

/// Text of a tool_result `content`: a string or an array of text blocks.
fn result_text(content: &Value) -> Option<String> {
    let text = match content {
        Value::String(t) => t.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => return None,
    };
    (!text.is_empty()).then_some(text)
}

/// Drops a `/bin/zsh -lc ` or `/bin/bash -lc ` wrapper and its single quotes.
pub(crate) fn codex_command(command: &str) -> &str {
    let c = ["/bin/zsh -lc ", "/bin/bash -lc "]
        .iter()
        .find_map(|p| command.strip_prefix(p))
        .unwrap_or(command);
    c.strip_prefix('\'')
        .and_then(|c| c.strip_suffix('\''))
        .unwrap_or(c)
}

fn agy_kind(tool: &str) -> ActivityKind {
    match tool {
        "read_file" | "view_file" => ActivityKind::Read,
        "write_file" | "edit_file" | "replace_file_content" | "create_file" => ActivityKind::Edit,
        "run_command" => ActivityKind::Execute,
        t if ["search", "grep", "find", "list_dir"]
            .iter()
            .any(|k| t.contains(k)) =>
        {
            ActivityKind::Search
        }
        t if t.starts_with("browser_") || t.starts_with("read_url") => ActivityKind::Fetch,
        _ => ActivityKind::Other,
    }
}

impl Parser {
    pub fn new(cli: &str) -> Self {
        Self {
            cli: cli.into(),
            had_text: false,
            message: String::new(),
            acts: HashMap::new(),
            thinking: HashMap::new(),
        }
    }

    /// Remembers and emits the full state of an activity.
    fn emit(&mut self, mut a: Activity, out: &mut Vec<Ev>) {
        a.clamp();
        self.acts.insert(a.id.clone(), a.clone());
        out.push(Ev::Activity(a));
    }

    fn claude_stream_event(&mut self, e: &Value, out: &mut Vec<Ev>) {
        let index = e["index"].as_u64().unwrap_or(0);
        match (str_at(e, &["type"]), str_at(e, &["delta", "type"])) {
            (Some("message_start"), _) => {
                self.message = str_at(e, &["message", "id"]).unwrap_or("").into();
            }
            (Some("content_block_start"), _) => {
                let b = &e["content_block"];
                match str_at(b, &["type"]) {
                    Some("text") if self.had_text => {
                        out.push(Ev::Text("\n\n".into()));
                        self.had_text = false; // one separator per block
                    }
                    Some("tool_use") => {
                        let (id, name) = (
                            str_at(b, &["id"]).unwrap_or(""),
                            str_at(b, &["name"]).unwrap_or("tool"),
                        );
                        if !id.is_empty() {
                            let a = activity(id, claude_kind(name), name, ActivityStatus::Running);
                            self.emit(a, out);
                        }
                    }
                    Some("thinking") => {
                        let id = format!("{}:{index}", self.message);
                        let a = activity(
                            &id,
                            ActivityKind::Reasoning,
                            "Thinking",
                            ActivityStatus::Running,
                        );
                        self.thinking.insert(index, id);
                        self.emit(a, out);
                    }
                    _ => {}
                }
            }
            (Some("content_block_delta"), Some("text_delta")) => {
                let t = str_at(e, &["delta", "text"]).unwrap_or("");
                self.text(t, false, out);
            }
            (Some("content_block_delta"), Some("thinking_delta")) => {
                let t = str_at(e, &["delta", "thinking"]).unwrap_or("");
                let open = self.thinking.get(&index).and_then(|id| self.acts.get(id));
                if let (false, Some(mut a)) = (t.is_empty(), open.cloned()) {
                    let d = a.detail.get_or_insert_with(String::new);
                    if d.len() < DETAIL_CAP {
                        d.push_str(t);
                        self.emit(a, out);
                    }
                }
            }
            (Some("content_block_stop"), _) => {
                if let Some(mut a) = self
                    .thinking
                    .remove(&index)
                    .and_then(|id| self.acts.get(&id).cloned())
                {
                    a.status = ActivityStatus::Completed;
                    self.emit(a, out);
                }
            }
            _ => {}
        }
    }

    /// Complete assistant message: tool inputs are known now.
    fn claude_assistant(&mut self, blocks: &Value, out: &mut Vec<Ev>) {
        for b in blocks.as_array().into_iter().flatten() {
            let (Some("tool_use"), Some(id)) = (str_at(b, &["type"]), str_at(b, &["id"])) else {
                continue;
            };
            let name = str_at(b, &["name"]).unwrap_or("tool");
            let mut a =
                self.acts.get(id).cloned().unwrap_or_else(|| {
                    activity(id, claude_kind(name), name, ActivityStatus::Running)
                });
            a.title = claude_title(name, &b["input"]);
            a.diff = claude_diff(name, &b["input"]);
            self.emit(a, out);
        }
    }

    fn claude_results(&mut self, blocks: &Value, out: &mut Vec<Ev>) {
        for b in blocks.as_array().into_iter().flatten() {
            if str_at(b, &["type"]) != Some("tool_result") {
                continue;
            }
            let Some(mut a) = str_at(b, &["tool_use_id"]).and_then(|id| self.acts.get(id).cloned())
            else {
                continue;
            };
            a.status = if b["is_error"] == true {
                ActivityStatus::Failed
            } else {
                ActivityStatus::Completed
            };
            a.detail = result_text(&b["content"]);
            self.emit(a, out);
        }
    }

    fn codex_item(&mut self, started: bool, item: &Value, out: &mut Vec<Ev>) {
        let Some(id) = str_at(item, &["id"]) else {
            return;
        };
        let (kind, title, detail) = match str_at(item, &["type"]) {
            Some("command_execution") => {
                let Some(command) = str_at(item, &["command"]) else {
                    return;
                };
                let output = str_at(item, &["aggregated_output"]).filter(|o| !o.is_empty());
                (
                    ActivityKind::Execute,
                    codex_command(command).to_string(),
                    output,
                )
            }
            Some("file_change") => {
                let paths: Vec<&str> = item["changes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c["path"].as_str())
                    .collect();
                (ActivityKind::Edit, paths.join(", "), None)
            }
            Some("reasoning") => (
                ActivityKind::Reasoning,
                "Reasoning".into(),
                str_at(item, &["text"]),
            ),
            Some("mcp_tool_call") => {
                let name = |k| str_at(item, &[k]).unwrap_or("");
                (
                    ActivityKind::Other,
                    format!("{}.{}", name("server"), name("tool")),
                    None,
                )
            }
            Some("web_search") => (
                ActivityKind::Fetch,
                str_at(item, &["query"]).unwrap_or("").into(),
                None,
            ),
            _ => return,
        };
        let ok = if str_at(item, &["type"]) == Some("command_execution") {
            item["exit_code"] == 0
        } else {
            str_at(item, &["status"]) != Some("failed")
        };
        let status = match (started, ok) {
            (true, _) => ActivityStatus::Running,
            (false, true) => ActivityStatus::Completed,
            (false, false) => ActivityStatus::Failed,
        };
        let mut a = activity(id, kind, &title, status);
        a.detail = detail.map(Into::into);
        self.emit(a, out);
    }

    fn agy_tool(&mut self, u: &Value, out: &mut Vec<Ev>) {
        let tool = str_at(u, &["tool_name"]).unwrap_or("tool");
        let info = &u["tool_info"];
        let title = ["Path", "CommandLine", "Query", "Url"]
            .iter()
            .find_map(|k| str_at(info, &["parameters", k]))
            .unwrap_or(tool);
        let status = match str_at(u, &["state"]) {
            Some("DONE") => ActivityStatus::Completed,
            Some("ERROR") => ActivityStatus::Failed,
            _ => ActivityStatus::Running,
        };
        let mut a = activity(
            &format!("s{}", u64_at(u, "step_index")),
            agy_kind(tool),
            title,
            status,
        );
        a.detail = match status {
            ActivityStatus::Failed => str_at(info, &["error", "message"]),
            _ => str_at(info, &["output"]),
        }
        .map(Into::into);
        self.emit(a, out);
    }

    /// Text separated from earlier text (new message or content block) starts a paragraph.
    fn text(&mut self, text: &str, separate: bool, out: &mut Vec<Ev>) {
        if text.is_empty() {
            return;
        }
        if separate && self.had_text {
            out.push(Ev::Text("\n\n".into()));
        }
        self.had_text = true;
        out.push(Ev::Text(text.into()));
    }

    /// Maps one stdout line; non-JSON and unknown lines are ignored.
    pub fn line(&mut self, line: &str) -> Vec<Ev> {
        let mut out = Vec::new();
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            return out;
        };
        let kind = str_at(&v, &["type"]).unwrap_or("");
        match self.cli.as_str() {
            "claude" => match kind {
                "system" if str_at(&v, &["subtype"]) == Some("init") => {
                    out.extend(str_at(&v, &["session_id"]).map(|s| Ev::Session(s.into())));
                }
                // Sub-agent output is not part of the answer.
                "stream_event" if v["parent_tool_use_id"].is_null() => {
                    self.claude_stream_event(&v["event"], &mut out);
                }
                "assistant" if v["parent_tool_use_id"].is_null() => {
                    self.claude_assistant(&v["message"]["content"], &mut out);
                }
                "user" if v["parent_tool_use_id"].is_null() => {
                    self.claude_results(&v["message"]["content"], &mut out);
                }
                "result" => {
                    out.extend(str_at(&v, &["session_id"]).map(|s| Ev::Session(s.into())));
                    let text = str_at(&v, &["result"]).unwrap_or("");
                    let u = &v["usage"];
                    if u.is_object() {
                        out.push(Ev::Usage(Usage {
                            input_tokens: u64_at(u, "input_tokens")
                                + u64_at(u, "cache_creation_input_tokens"),
                            output_tokens: u64_at(u, "output_tokens"),
                            cached_input_tokens: u64_at(u, "cache_read_input_tokens"),
                            cost_usd: v["total_cost_usd"].as_f64(),
                        }));
                    }
                    if v["is_error"] == true {
                        let detail = if text.is_empty() {
                            str_at(&v, &["subtype"]).unwrap_or("error")
                        } else {
                            text
                        };
                        out.push(Ev::Error(detail.into()));
                    } else {
                        out.push(Ev::Final(text.into()));
                    }
                }
                _ => {}
            },
            "codex" => match kind {
                "thread.started" => {
                    out.extend(str_at(&v, &["thread_id"]).map(|s| Ev::Session(s.into())));
                }
                "item.completed" if str_at(&v, &["item", "type"]) == Some("agent_message") => {
                    let t = str_at(&v, &["item", "text"]).unwrap_or("");
                    self.text(t, true, &mut out);
                }
                "item.started" | "item.completed" => {
                    self.codex_item(kind == "item.started", &v["item"], &mut out);
                }
                // Terminal event: the caller stops waiting for pipe EOF.
                "turn.completed" => {
                    let u = &v["usage"];
                    if u.as_object().is_some_and(|o| !o.is_empty()) {
                        out.push(Ev::Usage(Usage {
                            input_tokens: u64_at(u, "input_tokens"),
                            output_tokens: u64_at(u, "output_tokens"),
                            cached_input_tokens: u64_at(u, "cached_input_tokens"),
                            cost_usd: None,
                        }));
                    }
                    out.push(Ev::Final(String::new()));
                }
                "turn.failed" => out.push(Ev::Error(
                    str_at(&v, &["error", "message"])
                        .unwrap_or("The turn failed.")
                        .into(),
                )),
                "error" => out.push(Ev::Error(
                    str_at(&v, &["message"])
                        .unwrap_or("The CLI reported an error.")
                        .into(),
                )),
                _ => {}
            },
            "kimi" => {
                if str_at(&v, &["role"]) == Some("assistant") {
                    let t = str_at(&v, &["content"]).unwrap_or("");
                    self.text(t, true, &mut out);
                } else if str_at(&v, &["type"]) == Some("session.resume_hint") {
                    out.extend(str_at(&v, &["session_id"]).map(|s| Ev::Session(s.into())));
                }
            }
            _ => match str_at(&v, &["event"]) {
                Some("init") => {
                    out.extend(str_at(&v, &["conversation_id"]).map(|s| Ev::Session(s.into())));
                }
                Some("step_update")
                    if str_at(&v, &["step_update", "step_type"]) == Some("agent_response") =>
                {
                    let t = str_at(&v, &["step_update", "text_delta"]).unwrap_or("");
                    self.text(t, false, &mut out);
                }
                Some("step_update")
                    if str_at(&v, &["step_update", "step_type"]) == Some("tool") =>
                {
                    self.agy_tool(&v["step_update"], &mut out);
                }
                Some("result") => {
                    let r = &v["result"];
                    out.extend(str_at(r, &["conversation_id"]).map(|s| Ev::Session(s.into())));
                    let u = &r["usage"];
                    if u.is_object() {
                        out.push(Ev::Usage(Usage {
                            input_tokens: u64_at(u, "input_tokens"),
                            output_tokens: u64_at(u, "output_tokens"),
                            cached_input_tokens: u64_at(u, "cache_read_tokens"),
                            cost_usd: None,
                        }));
                    }
                    match str_at(r, &["status"]) {
                        Some("SUCCESS") => {
                            out.push(Ev::Final(str_at(r, &["response"]).unwrap_or("").into()));
                        }
                        other => out.push(Ev::Error(format!(
                            "The CLI finished with status {}.",
                            other.unwrap_or("unknown")
                        ))),
                    }
                }
                _ => {}
            },
        }
        out
    }
}

/// Splits a byte stream into lines, dropping lines longer than `LINE_CAP`.
#[derive(Default)]
pub struct LineSplitter {
    buf: Vec<u8>,
    skipping: bool,
    dropped: bool,
}

impl LineSplitter {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        for part in bytes.split_inclusive(|b| *b == b'\n') {
            let ends = part.last() == Some(&b'\n');
            if !self.skipping {
                self.buf.extend_from_slice(part);
                if self.buf.len() > LINE_CAP + 1 {
                    self.buf.clear();
                    self.dropped = true;
                    self.skipping = !ends;
                    continue;
                }
            } else if !ends {
                continue;
            }
            if ends {
                if !self.skipping {
                    lines.push(self.take());
                }
                self.skipping = false;
            }
        }
        lines
    }

    /// Whether a line was dropped since the last call.
    pub fn take_dropped(&mut self) -> bool {
        std::mem::take(&mut self.dropped)
    }

    pub fn finish(&mut self) -> Vec<String> {
        let rest = (!self.skipping && !self.buf.is_empty()).then(|| self.take());
        self.skipping = false;
        rest.into_iter().collect()
    }

    fn take(&mut self) -> String {
        let line = String::from_utf8_lossy(&self.buf).trim_end().to_string();
        self.buf.clear();
        line
    }
}

// ---- process ---------------------------------------------------------

pub struct Spec {
    pub bin: PathBuf,
    pub args: Vec<String>,
    pub stdin: Option<String>,
    /// Keep stdin open for the caller (see [`Proc::stdin`]) when there is no payload.
    pub interactive: bool,
    pub cwd: PathBuf,
}

/// A running CLI in its own process group; dropping it kills the group.
pub struct Proc {
    pub child: Child,
    pub stdout: ChildStdout,
    /// Open stdin of an interactive spec; the caller owns closing it.
    pub stdin: Option<ChildStdin>,
    stderr: JoinHandle<Vec<u8>>,
    /// Group id; kept after reaping because grandchildren can outlive the CLI.
    pgid: Option<u32>,
    reaped: bool,
}

/// GUI launches carry a minimal PATH; CLIs implemented as scripts need their runtime.
fn path_env(bin: &Path) -> Option<std::ffi::OsString> {
    let mut dirs: Vec<PathBuf> = bin.parent().map(Path::to_path_buf).into_iter().collect();
    dirs.extend(["/opt/homebrew/bin", "/usr/local/bin"].map(PathBuf::from));
    dirs.extend(std::env::split_paths(&std::env::var_os("PATH")?));
    std::env::join_paths(dirs).ok()
}

pub fn kill_group(pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid.and_then(|p| i32::try_from(p).ok()).filter(|p| *p > 1) {
        // SAFETY: killpg only signals the group this process created with process_group(0).
        unsafe { libc::killpg(pid, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    let _ = pid;
}

impl Proc {
    pub fn spawn(spec: &Spec) -> Result<Self, String> {
        let mut cmd = Command::new(&spec.bin);
        cmd.args(&spec.args)
            .current_dir(&spec.cwd)
            .stdin(if spec.stdin.is_some() || spec.interactive {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(path) = path_env(&spec.bin) {
            cmd.env("PATH", path);
        }
        #[cfg(unix)]
        cmd.process_group(0);
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "Cannot start the CLI. Check that it is installed.".to_string()
            } else {
                format!("Cannot start the CLI: {e}")
            }
        })?;
        let pgid = child.id();
        let mut stdin = child.stdin.take();
        if let (Some(mut w), Some(text)) =
            (stdin.take_if(|_| spec.stdin.is_some()), spec.stdin.clone())
        {
            // Written concurrently so a CLI that answers before reading everything cannot deadlock us.
            tokio::spawn(async move {
                let _ = w.write_all(text.as_bytes()).await;
            });
        }
        let stdout = child.stdout.take().ok_or("Cannot read the CLI output.")?;
        let mut err = child.stderr.take().ok_or("Cannot read the CLI output.")?;
        let stderr = tokio::spawn(async move {
            let (mut tail, mut buf) = (Vec::new(), [0u8; 4096]);
            while let Ok(n) = err.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                tail.extend_from_slice(&buf[..n]);
                if tail.len() > STDERR_CAP {
                    tail.drain(..tail.len() - STDERR_CAP);
                }
            }
            tail
        });
        Ok(Self {
            child,
            stdout,
            stdin,
            stderr,
            pgid,
            reaped: false,
        })
    }

    pub fn pgid(&self) -> Option<u32> {
        self.pgid
    }

    pub fn kill(&mut self) {
        kill_group(self.pgid);
        let _ = self.child.start_kill();
    }

    /// Waits for exit; returns the success flag, the exit description and a redacted stderr tail.
    pub async fn finish(&mut self) -> (bool, String, String) {
        let status = self.child.wait().await;
        self.reaped = true;
        // A grandchild (MCP server, hook) may hold the pipes open after the CLI exits.
        kill_group(self.pgid);
        let tail = tokio::time::timeout(Duration::from_secs(2), &mut self.stderr)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        let from = tail.len().saturating_sub(STDERR_SHOWN);
        let text = crate::http::redact(&String::from_utf8_lossy(&tail[from..]), None);
        match status {
            Ok(s) => (s.success(), s.to_string(), text),
            Err(_) => (false, "unknown exit status".into(), text),
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill();
        }
    }
}

// ---- status and models -----------------------------------------------

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CliStatus {
    pub cli: String,
    pub binary_path: Option<String>,
    pub version: Option<String>,
    pub signed_in: Option<bool>,
    /// Subscription plan name, e.g. "Max 5x" or "ChatGPT Plus".
    pub plan: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CliModel {
    pub id: String,
    pub label: String,
    /// Reasoning efforts the model accepts; empty when it has none.
    pub efforts: Vec<String>,
}

/// Efforts shared by every Claude Code and Antigravity model.
const EFFORTS: [&str; 5] = ["low", "medium", "high", "xhigh", "max"];

/// Runs a short read-only probe; `None` on spawn failure or timeout. Returns (success, stdout+stderr).
async fn probe(bin: &Path, args: &[&str], secs: u64) -> Option<(bool, String)> {
    let mut cmd = Command::new(bin);
    cmd.args(args).stdin(Stdio::null()).kill_on_drop(true);
    if let Some(path) = path_env(bin) {
        cmd.env("PATH", path);
    }
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let out = tokio::time::timeout(Duration::from_secs(secs), cmd.output())
        .await
        .ok()?
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    text.truncate(text.floor_char_boundary(STDERR_CAP));
    Some((out.status.success(), text))
}

pub fn parse_version(text: &str) -> Option<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"\d+\.\d+\.\d+\S*").expect("valid pattern"));
    re.find(text).map(|m| m.as_str().to_string())
}

/// `claude auth status` prints JSON on stdout.
pub fn parse_claude_status(text: &str) -> (Option<bool>, Option<String>) {
    let Ok(v) = serde_json::from_str::<Value>(text.trim()) else {
        return (None, None);
    };
    let plan = str_at(&v, &["planTier"])
        .or_else(|| str_at(&v, &["subscriptionType"]))
        .and_then(plan_label);
    (v["loggedIn"].as_bool(), plan)
}

/// `codex login status` exits 0 and prints "Logged in ..." when signed in.
pub fn parse_codex_status(success: bool, text: &str) -> Option<bool> {
    if success && text.contains("Logged in") {
        Some(true)
    } else if text.contains("Not logged in") {
        Some(false)
    } else {
        None
    }
}

/// `agy models` lines are `<id>\t<label>`; other lines are progress output.
pub fn parse_agy_models(text: &str) -> Vec<CliModel> {
    text.lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(id, label)| (id.trim(), label.trim()))
        .filter(|(id, _)| valid_arg_id(id, 256))
        .take(MAX_MODELS)
        .map(|(id, label)| CliModel {
            id: id.into(),
            label: if label.is_empty() { id } else { label }.into(),
            efforts: vec![],
        })
        .collect()
}

/// Reads `models[]` of Codex's `models_cache.json`, keeping user-visible entries.
pub fn parse_codex_models(json: &str) -> Vec<CliModel> {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return vec![];
    };
    v["models"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["visibility"] == "list")
        .filter_map(|m| {
            let id = m["slug"].as_str().filter(|id| valid_arg_id(id, 256))?;
            let label = m["display_name"].as_str().filter(|l| !l.is_empty());
            Some(CliModel {
                id: id.into(),
                label: label.unwrap_or(id).into(),
                efforts: m["supported_reasoning_levels"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|l| l["effort"].as_str())
                    .filter(|e| crate::settings::valid_effort(e).is_ok())
                    .map(String::from)
                    .collect(),
            })
        })
        .take(MAX_MODELS)
        .collect()
}

/// Kimi lists model aliases as `[models."<alias>"]` tables with an optional `display_name`.
pub fn parse_kimi_models(toml: &str) -> Vec<CliModel> {
    let Ok(doc) = toml.parse::<toml_edit::DocumentMut>() else {
        return vec![];
    };
    let Some(models) = doc.get("models").and_then(|m| m.as_table_like()) else {
        return vec![];
    };
    models
        .iter()
        .filter(|(id, _)| valid_arg_id(id, 256))
        .take(MAX_MODELS)
        .map(|(id, item)| CliModel {
            id: id.into(),
            label: item
                .get("display_name")
                .and_then(|l| l.as_str())
                .filter(|l| !l.is_empty())
                .unwrap_or(id)
                .into(),
            efforts: vec![],
        })
        .collect()
}

fn read_capped(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::Read::take(file, 4 * 1024 * 1024), &mut text)
        .ok()?;
    Some(text)
}

fn codex_home() -> PathBuf {
    std::env::var_os("CODEX_HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(|| crate::home().join(".codex"), PathBuf::from)
}

/// The ChatGPT plan from the unverified `id_token` payload in Codex's `auth.json`.
/// Only the plan claim is read; tokens never leave this function.
fn codex_plan(auth: &str) -> Option<String> {
    use base64::Engine;
    let v: Value = serde_json::from_str(auth).ok()?;
    let payload = v["tokens"]["id_token"].as_str()?.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    let plan = plan_label(claims["https://api.openai.com/auth"]["chatgpt_plan_type"].as_str()?)?;
    Some(format!("ChatGPT {plan}"))
}

/// Turns a plan id such as `max_5x` or `plus` into "Max 5x" / "Plus".
fn plan_label(id: &str) -> Option<String> {
    let id = id.trim();
    if id.is_empty()
        || id.len() > 40
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    let words: Vec<String> = id
        .split(['_', '-'])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            c.next().map_or_else(String::new, |f| {
                f.to_ascii_uppercase().to_string() + c.as_str()
            })
        })
        .collect();
    Some(words.join(" ").replace(" X", "x")).filter(|s| !s.is_empty())
}

fn kimi_home() -> PathBuf {
    crate::home().join(".kimi-code")
}

/// Kimi keeps its OAuth login in `credentials/*.json`; absence proves nothing (API keys, env).
fn kimi_has_credentials() -> bool {
    std::fs::read_dir(kimi_home().join("credentials")).is_ok_and(|mut d| {
        d.any(|e| e.is_ok_and(|e| e.path().extension().is_some_and(|x| x == "json")))
    })
}

pub async fn status(cli: &str) -> CliStatus {
    let mut out = CliStatus {
        cli: cli.into(),
        binary_path: None,
        version: None,
        signed_in: None,
        plan: None,
        error: None,
    };
    let Some(bin) = crate::cli_bin::resolve(cli) else {
        return out;
    };
    out.binary_path = Some(bin.to_string_lossy().into_owned());
    match probe(&bin, &["--version"], 5).await {
        Some((_, text)) => out.version = parse_version(&text),
        None => out.error = Some("The CLI did not report its version in time.".into()),
    }
    match cli {
        "claude" => {
            if let Some((_, text)) = probe(&bin, &["auth", "status"], 10).await {
                (out.signed_in, out.plan) = parse_claude_status(&text);
            }
        }
        "codex" => {
            if let Some((ok, text)) = probe(&bin, &["login", "status"], 10).await {
                out.signed_in = parse_codex_status(ok, &text);
            }
            if out.signed_in == Some(true) {
                let path = codex_home().join("auth.json");
                out.plan = tokio::task::spawn_blocking(move || read_capped(&path))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|text| codex_plan(&text));
            }
        }
        "kimi" => out.signed_in = kimi_has_credentials().then_some(true),
        // No status command: a successful model listing needs a valid session.
        _ => {
            if let Some((true, text)) = probe(&bin, &["models"], 10).await {
                out.signed_in = (!parse_agy_models(&text).is_empty()).then_some(true);
            }
        }
    }
    out
}

/// Models available to the signed-in Claude Code account, read with its OAuth login.
async fn claude_account_models(access_token: AccessToken) -> Vec<CliModel> {
    let Ok(Some(token)) = tokio::task::spawn_blocking(access_token).await else {
        return Vec::new();
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    else {
        return Vec::new();
    };
    let response = client
        .get("https://api.anthropic.com/v1/models?limit=1000")
        .bearer_auth(token.as_str())
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("anthropic-version", "2023-06-01")
        .send()
        .await;
    match response {
        Ok(r) if r.status().is_success() => match r.bytes().await {
            Ok(body) if body.len() <= 1 << 20 => parse_claude_models(&body),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Parses an Anthropic `/v1/models` page into `{id, label}` entries.
fn parse_claude_models(body: &[u8]) -> Vec<CliModel> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let mut out: Vec<CliModel> = Vec::new();
    for m in value["data"].as_array().into_iter().flatten() {
        let Some(id) = m["id"].as_str().filter(|id| valid_arg_id(id, 256)) else {
            continue;
        };
        if out.iter().any(|o| o.id == id) {
            continue;
        }
        out.push(CliModel {
            id: id.into(),
            label: m["display_name"].as_str().unwrap_or(id).into(),
            efforts: vec![],
        });
    }
    out.truncate(500);
    out
}

/// Reads the Claude Code OAuth access token; supplied by the host application.
pub type AccessToken = fn() -> Option<zeroize::Zeroizing<String>>;

pub async fn models(cli: &str, access_token: AccessToken) -> Vec<CliModel> {
    let mut list = listed_models(cli, access_token).await;
    if matches!(cli, "claude" | "agy") {
        for m in &mut list {
            m.efforts = EFFORTS.map(String::from).into();
        }
    }
    list
}

async fn listed_models(cli: &str, access_token: AccessToken) -> Vec<CliModel> {
    let list = match cli {
        "claude" => {
            let listed = claude_account_models(access_token).await;
            if listed.is_empty() {
                // Aliases always resolve to the latest models when the account list is unavailable.
                [
                    ("opus", "Claude Opus"),
                    ("sonnet", "Claude Sonnet"),
                    ("haiku", "Claude Haiku"),
                ]
                .map(|(id, label)| CliModel {
                    id: id.into(),
                    label: label.into(),
                    efforts: vec![],
                })
                .into()
            } else {
                listed
            }
        }
        "codex" => {
            let path = codex_home().join("models_cache.json");
            tokio::task::spawn_blocking(move || read_capped(&path))
                .await
                .ok()
                .flatten()
                .map(|t| parse_codex_models(&t))
                .unwrap_or_default()
        }
        "kimi" => {
            let path = kimi_home().join("config.toml");
            tokio::task::spawn_blocking(move || read_capped(&path))
                .await
                .ok()
                .flatten()
                .map(|t| parse_kimi_models(&t))
                .unwrap_or_default()
        }
        _ => match crate::cli_bin::resolve(cli) {
            Some(bin) => match probe(&bin, &["models"], 10).await {
                Some((true, text)) => parse_agy_models(&text),
                _ => vec![],
            },
            None => vec![],
        },
    };
    if cli == "claude" {
        list
    } else {
        with_default_model(list)
    }
}

/// Read-only Kimi agent: prompt mode would otherwise run edits and commands unasked.
pub const KIMI_AGENT: &str = "---\nname: lomi-chat\ndescription: Read-only chat assistant for Lomi\ntools:\n  - Read\n  - Grep\n  - Glob\n---\nYou are a helpful assistant. You never modify files or run commands.\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    fn run(cli: &str, jsonl: &str) -> Vec<Ev> {
        let mut p = Parser::new(cli);
        jsonl.lines().flat_map(|l| p.line(l)).collect()
    }

    // Trimmed real captures from the installed CLIs.
    const CLAUDE: &str = r#"{"type":"system","subtype":"hook_started","session_id":"x"}
{"type":"system","subtype":"init","cwd":"/w","session_id":"c825f374"}
{"type":"stream_event","event":{"type":"message_start","message":{}},"session_id":"c825f374","parent_tool_use_id":null}
{"type":"stream_event","event":{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}},"session_id":"c825f374","parent_tool_use_id":null}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"O"}},"session_id":"c825f374","parent_tool_use_id":null}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"K"}},"session_id":"c825f374","parent_tool_use_id":null}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"sub"}},"session_id":"c825f374","parent_tool_use_id":"toolu_1"}
{"type":"assistant","message":{"content":[{"type":"text","text":"OK"}]}}
{"type":"stream_event","event":{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}},"session_id":"c825f374","parent_tool_use_id":null}
{"type":"stream_event","event":{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"!"}},"session_id":"c825f374","parent_tool_use_id":null}
{"type":"rate_limit_event"}
{"type":"result","subtype":"success","is_error":false,"result":"OK!","session_id":"c825f374"}"#;

    fn text(evs: &[Ev]) -> String {
        evs.iter()
            .filter_map(|e| match e {
                Ev::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn claude_stream() {
        let evs = run("claude", CLAUDE);
        assert_eq!(text(&evs), "OK\n\n!");
        assert_eq!(evs.first(), Some(&Ev::Session("c825f374".into())));
        assert_eq!(evs.last(), Some(&Ev::Final("OK!".into())));
        let err = run(
            "claude",
            r#"{"type":"result","subtype":"error_during_execution","is_error":true,"result":"Not logged in","session_id":"s"}"#,
        );
        assert_eq!(err.last(), Some(&Ev::Error("Not logged in".into())));
    }

    #[test]
    fn codex_stream() {
        let evs = run(
            "codex",
            r#"{"type":"thread.started","thread_id":"01a1"}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"OK"}}
{"type":"item.completed","item":{"id":"item_1","type":"command_execution","text":"ls"}}
{"type":"item.completed","item":{"id":"item_2","type":"agent_message","text":"Done"}}
{"type":"turn.completed","usage":{}}"#,
        );
        assert_eq!(
            evs,
            vec![
                Ev::Session("01a1".into()),
                Ev::Text("OK".into()),
                Ev::Text("\n\n".into()),
                Ev::Text("Done".into()),
                Ev::Final(String::new())
            ]
        );
        let failed = run(
            "codex",
            r#"{"type":"turn.failed","error":{"message":"quota"}}
{"type":"error","message":"boom"}
not json"#,
        );
        assert_eq!(
            failed,
            vec![Ev::Error("quota".into()), Ev::Error("boom".into())]
        );
    }

    #[test]
    fn kimi_stream() {
        let evs = run(
            "kimi",
            r#"{"role":"meta","type":"system.version","version":"2.7.0"}
{"role":"assistant","content":"OK"}
{"role":"tool","content":"ignored"}
{"role":"assistant","content":"More"}
{"role":"meta","type":"session.resume_hint","session_id":"session_2354","command":"kimi -r x"}"#,
        );
        assert_eq!(
            evs,
            vec![
                Ev::Text("OK".into()),
                Ev::Text("\n\n".into()),
                Ev::Text("More".into()),
                Ev::Session("session_2354".into())
            ]
        );
    }

    #[test]
    fn agy_stream() {
        let evs = run(
            "agy",
            r#"{"event":"init","conversation_id":"16b9","init":{}}
{"event":"step_update","step_update":{"step_index":0,"step_type":"user_input"}}
{"event":"step_update","step_update":{"step_index":1,"step_type":"agent_response","text_delta":"OK"}}
{"event":"step_update","step_update":{"step_index":1,"step_type":"agent_response","text_delta":"\n"}}
{"event":"result","result":{"conversation_id":"16b9","status":"SUCCESS","response":"OK\n"}}"#,
        );
        assert_eq!(text(&evs), "OK\n");
        assert_eq!(evs[0], Ev::Session("16b9".into()));
        assert_eq!(evs.last(), Some(&Ev::Final("OK\n".into())));
        let bad = run("agy", r#"{"event":"result","result":{"status":"ERROR"}}"#);
        assert!(matches!(bad.last(), Some(Ev::Error(_))));
    }

    /// Last state of every activity, in order of first appearance.
    fn acts(evs: &[Ev]) -> Vec<Activity> {
        let mut out: Vec<Activity> = Vec::new();
        for e in evs {
            if let Ev::Activity(a) = e {
                match out.iter_mut().find(|o| o.id == a.id) {
                    Some(o) => *o = a.clone(),
                    None => out.push(a.clone()),
                }
            }
        }
        out
    }

    fn usage(evs: &[Ev]) -> Option<&Usage> {
        evs.iter().find_map(|e| match e {
            Ev::Usage(u) => Some(u),
            _ => None,
        })
    }

    fn summary(a: &[Activity]) -> Vec<(ActivityKind, &str, ActivityStatus)> {
        a.iter()
            .map(|a| (a.kind, a.title.as_str(), a.status))
            .collect()
    }

    #[test]
    fn claude_fixture_has_tools_and_usage() {
        let evs = run("claude", include_str!("fixtures/claude-tools.jsonl"));
        assert_eq!(text(&evs), "DONE");
        assert_eq!(evs.last(), Some(&Ev::Final("DONE".into())));
        let all = acts(&evs);
        let tools: Vec<_> = all
            .iter()
            .filter(|a| a.kind != ActivityKind::Reasoning)
            .cloned()
            .collect();
        use {ActivityKind::*, ActivityStatus::Completed};
        assert_eq!(
            summary(&tools),
            [
                (Read, "/work/a.txt", Completed),
                (Edit, "/work/a.txt", Completed),
                (Execute, "ls", Completed)
            ]
        );
        assert_eq!(tools[0].detail.as_deref(), Some("1\thello\n2\t"));
        let diff = tools[1].diff.as_ref().unwrap();
        assert_eq!((diff.before.as_deref(), diff.after.as_str()), (None, "bye"));
        assert_eq!(tools[2].detail.as_deref(), Some("a.txt"));
        // Thinking blocks are keyed by message id and block index and end completed.
        assert!(all.len() > tools.len());
        assert!(all.iter().filter(|a| a.kind == Reasoning).all(|a| {
            a.status == Completed && a.id.starts_with("msg_") && a.id.ends_with(":0")
        }));
        assert_eq!(
            usage(&evs),
            Some(&Usage {
                input_tokens: 6 + 26166,
                output_tokens: 643,
                cached_input_tokens: 75955,
                cost_usd: Some(0.00631485)
            })
        );
    }

    #[test]
    fn claude_edit_failure_and_thinking_text() {
        let evs = run(
            "claude",
            r#"{"type":"stream_event","event":{"type":"message_start","message":{"id":"m1"}},"parent_tool_use_id":null}
{"type":"stream_event","event":{"type":"content_block_start","index":0,"content_block":{"type":"thinking"}},"parent_tool_use_id":null}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"a"}},"parent_tool_use_id":null}
{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"b"}},"parent_tool_use_id":null}
{"type":"stream_event","event":{"type":"content_block_stop","index":0},"parent_tool_use_id":null}
{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"/f","old_string":"x","new_string":"y"}}]},"parent_tool_use_id":null}
{"type":"assistant","message":{"content":[{"type":"tool_use","id":"sub","name":"Bash","input":{"command":"rm"}}]},"parent_tool_use_id":"t0"}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","is_error":true,"content":[{"type":"text","text":"no"},{"type":"text","text":"match"}]}]},"parent_tool_use_id":null}"#,
        );
        let a = acts(&evs);
        assert_eq!(a.len(), 2, "sub-agent tools are ignored");
        assert_eq!(a[0].id, "m1:0");
        assert_eq!(a[0].detail.as_deref(), Some("ab"));
        assert_eq!(a[0].status, ActivityStatus::Completed);
        assert_eq!(a[1].status, ActivityStatus::Failed);
        assert_eq!(a[1].detail.as_deref(), Some("no\nmatch"));
        let d = a[1].diff.as_ref().unwrap();
        assert_eq!((d.before.as_deref(), d.after.as_str()), (Some("x"), "y"));
    }

    #[test]
    fn codex_fixture_has_commands_and_usage() {
        let evs = run("codex", include_str!("fixtures/codex-tools.jsonl"));
        assert_eq!(
            text(&evs),
            "I\u{2019}ll read `a.txt`, replace its contents with `bye`, then run `ls`.\n\nDONE"
        );
        let a = acts(&evs);
        use {ActivityKind::Execute, ActivityStatus::Completed};
        assert_eq!(
            summary(&a),
            [
                (Execute, "cat a.txt", Completed),
                (Execute, "printf %s bye > a.txt", Completed),
                (Execute, "ls", Completed)
            ]
        );
        assert_eq!(a[0].detail.as_deref(), Some("hello\n"));
        assert_eq!(
            usage(&evs),
            Some(&Usage {
                input_tokens: 90941,
                output_tokens: 102,
                cached_input_tokens: 67968,
                cost_usd: None
            })
        );
        assert_eq!(evs.last(), Some(&Ev::Final(String::new())));
    }

    #[test]
    fn codex_other_items() {
        let a = acts(&run(
            "codex",
            r#"{"type":"item.started","item":{"id":"1","type":"file_change","changes":[{"path":"a"},{"path":"b"}],"status":"in_progress"}}
{"type":"item.completed","item":{"id":"2","type":"command_execution","command":"/bin/bash -lc 'false'","aggregated_output":"","exit_code":1,"status":"failed"}}
{"type":"item.completed","item":{"id":"3","type":"reasoning","text":"hm"}}
{"type":"item.completed","item":{"id":"4","type":"mcp_tool_call","server":"s","tool":"t","status":"completed"}}
{"type":"item.completed","item":{"id":"5","type":"web_search","query":"q"}}"#,
        ));
        use {ActivityKind::*, ActivityStatus::*};
        assert_eq!(
            summary(&a),
            [
                (Edit, "a, b", Running),
                (Execute, "false", Failed),
                (Reasoning, "Reasoning", Completed),
                (Other, "s.t", Completed),
                (Fetch, "q", Completed)
            ]
        );
        assert_eq!(a[2].detail.as_deref(), Some("hm"));
    }

    #[test]
    fn agy_fixture_has_tools_and_usage() {
        let evs = run("agy", include_str!("fixtures/agy-tools.jsonl"));
        // The recorded turn ends with an empty response and no error.
        assert_eq!(text(&evs), "");
        assert_eq!(evs.last(), Some(&Ev::Final(String::new())));
        assert!(!evs.iter().any(|e| matches!(e, Ev::Error(_))));
        let a = acts(&evs);
        use {ActivityKind::*, ActivityStatus::*};
        assert_eq!(
            summary(&a),
            [
                (Read, "/work/a.txt", Completed),
                (Edit, "/work/a.txt", Completed),
                (Execute, "ls", Failed)
            ]
        );
        assert_eq!(a[0].detail.as_deref(), Some("1 lines, 6 bytes"));
        assert!(
            a[2].detail
                .as_deref()
                .unwrap()
                .contains("permission check failed")
        );
        assert_eq!(
            usage(&evs),
            Some(&Usage {
                input_tokens: 14568,
                output_tokens: 1924,
                cached_input_tokens: 17222,
                cost_usd: None
            })
        );
        assert_eq!(agy_kind("grep_search"), ActivityKind::Search);
        assert_eq!(agy_kind("browser_click"), ActivityKind::Fetch);
        assert_eq!(agy_kind("other"), ActivityKind::Other);
    }

    #[test]
    fn line_splitter_bounds_and_joins() {
        let mut s = LineSplitter::default();
        assert_eq!(s.push(b"ab"), Vec::<String>::new());
        assert_eq!(s.push(b"c\r\nd\ne"), vec!["abc", "d"]);
        assert_eq!(s.finish(), vec!["e"]);
        let mut s = LineSplitter::default();
        let huge = vec![b'x'; LINE_CAP + 10];
        assert!(s.push(&huge).is_empty());
        assert!(s.take_dropped() && !s.take_dropped());
        assert!(s.push(b"more").is_empty());
        assert_eq!(s.push(b"tail\nok\n"), vec!["ok"]);
        assert!(s.finish().is_empty());
    }

    fn inv<'a>(cli: &'a str, session: Option<&'a str>, system: &'a str) -> Invocation<'a> {
        Invocation {
            cli,
            model: "m1",
            cwd: "/w",
            session,
            system,
            prompt: "hi",
            agent_file: None,
            permissions: Permissions::ReadOnly,
            effort: None,
            attach_dir: None,
            images: &[],
            restricted: false,
        }
    }

    #[test]
    fn argv_restricted_only_hardens_read_only() {
        let r = |cli, session, permissions, restricted| {
            argv(&Invocation {
                permissions,
                restricted,
                ..inv(cli, session, "")
            })
            .0
        };
        let has = |a: &[String], items: &[&str]| a.windows(items.len()).any(|w| w == strs(items));
        use Permissions::*;
        for session in [None, Some("s1")] {
            let a = r("claude", session, ReadOnly, true);
            assert!(has(&a, &["--restricted", "--strict-mcp-config"]));
            let a = r("codex", session, ReadOnly, true);
            assert!(
                has(&a, &["--ignore-user-config", "--ignore-rules"]) && a.last().unwrap() == "-"
            );
            assert!(has(
                &r("agy", session, ReadOnly, true),
                &["--mode", "plan", "--sandbox"]
            ));
        }
        assert!(has(&r("codex", None, ReadOnly, true), &["-s", "read-only"]));
        // Kimi keeps its read-only agent file: `--plan` cannot be combined with `--prompt`.
        assert_eq!(
            r("kimi", None, ReadOnly, true),
            r("kimi", None, ReadOnly, false)
        );
        // Unrestricted (desktop) and writable threads keep the old argv.
        for cli in ["claude", "codex", "agy"] {
            let plain = r(cli, None, ReadOnly, false);
            assert!(
                !plain
                    .iter()
                    .any(|v| v.contains("restricted") || v.contains("ignore") || v == "--sandbox")
            );
            for p in [Edit, Full] {
                assert_eq!(r(cli, None, p, true), r(cli, None, p, false), "{cli}");
            }
        }
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn argv_fresh_and_resume() {
        let (a, stdin) = argv(&inv("claude", None, ""));
        assert_eq!(
            a,
            strs(&[
                "-p",
                "--output-format",
                "stream-json",
                "--verbose",
                "--include-partial-messages",
                "--model",
                "m1",
                "--permission-mode",
                "plan",
                "--disallowedTools",
                "Bash,Edit,Write,NotebookEdit"
            ])
        );
        assert_eq!(stdin.as_deref(), Some("hi"));
        let (a, _) = argv(&inv("claude", Some("s1"), "be brief"));
        assert_eq!(
            a[7..],
            strs(&[
                "--resume",
                "s1",
                "--permission-mode",
                "plan",
                "--disallowedTools",
                "Bash,Edit,Write,NotebookEdit",
                "--append-system-prompt",
                "be brief"
            ])
        );

        let (a, stdin) = argv(&inv("codex", None, "ignored"));
        assert_eq!(
            a,
            strs(&[
                "exec",
                "--json",
                "--skip-git-repo-check",
                "-s",
                "read-only",
                "--cd=/w",
                "-m",
                "m1",
                "-"
            ])
        );
        assert_eq!(stdin.as_deref(), Some("hi"));
        let (a, _) = argv(&inv("codex", Some("t1"), ""));
        assert_eq!(
            a,
            strs(&[
                "exec",
                "resume",
                "t1",
                "--json",
                "--skip-git-repo-check",
                "-c",
                "sandbox_mode=\"read-only\"",
                "-m",
                "m1",
                "-"
            ])
        );

        let (a, stdin) = argv(&inv("kimi", Some("k1"), "ignored"));
        assert_eq!(
            a,
            strs(&[
                "--prompt=hi",
                "--output-format",
                "stream-json",
                "-m",
                "m1",
                "-S",
                "k1"
            ])
        );
        assert!(stdin.is_none());
        let fresh = Invocation {
            agent_file: Some("/d/kimi.md"),
            ..inv("kimi", None, "")
        };
        let (a, _) = argv(&fresh);
        assert!(!a.contains(&"-S".to_string()));
        assert_eq!(a.last().unwrap(), "--agent-file=/d/kimi.md");

        let (a, stdin) = argv(&inv("agy", None, ""));
        assert_eq!(
            a,
            strs(&[
                "-p",
                "hi",
                "--output-format",
                "stream-json",
                "--model",
                "m1",
                "--mode",
                "plan"
            ])
        );
        assert!(stdin.is_none());
        let (a, _) = argv(&inv("agy", Some("c1"), ""));
        assert_eq!(a[6..8], strs(&["--conversation", "c1"]));

        let dash = Invocation {
            prompt: "-x --plan",
            ..inv("kimi", None, "")
        };
        assert_eq!(argv(&dash).0[0], "--prompt=-x --plan");
        let dash = Invocation { cli: "agy", ..dash };
        assert_eq!(argv(&dash).0[1], " -x --plan");
    }

    #[test]
    fn argv_and_prompt_with_attachments() {
        let files = vec![
            ("/d/attachments/a1".to_string(), "pic.png".to_string()),
            ("/d/attachments/b2".to_string(), "n.txt".to_string()),
        ];
        assert_eq!(
            attach_prompt("hi", &files),
            "hi\n\nAttached files:\n- /d/attachments/a1 (pic.png)\n- /d/attachments/b2 (n.txt)"
        );
        assert_eq!(
            attach_prompt("", &files[..1]),
            "Attached files:\n- /d/attachments/a1 (pic.png)"
        );
        assert_eq!(attach_prompt("hi", &[]), "hi");
        let images = vec!["/d/attachments/a1".to_string()];
        let with = |cli, session| {
            argv(&Invocation {
                attach_dir: Some("/d/attachments"),
                images: &images,
                ..inv(cli, session, "")
            })
            .0
        };
        let has = |a: &[String], item: &str| a.iter().any(|v| v == item);
        for cli in ["claude", "kimi", "agy"] {
            assert!(has(&with(cli, None), "--add-dir=/d/attachments"), "{cli}");
            assert!(!has(&with(cli, None), "--image=/d/attachments/a1"), "{cli}");
        }
        let fresh = with("codex", None);
        assert!(
            has(&fresh, "--add-dir=/d/attachments") && has(&fresh, "--image=/d/attachments/a1")
        );
        let resumed = with("codex", Some("t1"));
        assert!(
            !has(&resumed, "--add-dir=/d/attachments")
                && has(&resumed, "--image=/d/attachments/a1")
        );
        // The stdin sentinel stays last so it cannot read as an image value.
        assert_eq!(fresh.last().unwrap(), "-");
        assert!(!has(
            &argv(&inv("claude", None, "")).0,
            "--add-dir=/d/attachments"
        ));
    }

    #[test]
    fn argv_permissions_and_effort() {
        let with = |cli, session, permissions, effort| {
            argv(&Invocation {
                permissions,
                effort,
                ..inv(cli, session, "")
            })
            .0
        };
        let has = |a: &[String], items: &[&str]| a.windows(items.len()).any(|w| w == strs(items));
        use Permissions::*;
        // claude
        let a = with("claude", None, Edit, Some("high"));
        assert!(has(&a, &["--permission-mode", "acceptEdits"]) && has(&a, &["--effort", "high"]));
        assert!(has(
            &with("claude", Some("s"), Full, None),
            &["--permission-mode", "bypassPermissions"]
        ));
        let a = with("claude", None, ReadOnly, None);
        assert!(
            has(&a, &["--permission-mode", "plan"])
                && has(&a, &["--disallowedTools", "Bash,Edit,Write,NotebookEdit"])
        );
        // codex, fresh and resume
        let a = with("codex", None, Edit, Some("max"));
        assert!(
            has(&a, &["-s", "workspace-write"])
                && has(&a, &["-c", "model_reasoning_effort=\"max\""])
        );
        let a = with("codex", Some("t"), Edit, None);
        assert!(has(&a, &["-c", "sandbox_mode=\"workspace-write\""]) && !a.contains(&"-s".into()));
        for session in [None, Some("t")] {
            let a = with("codex", session, Full, None);
            assert!(a.contains(&"--dangerously-bypass-approvals-and-sandbox".into()));
            assert!(!a.contains(&"-s".into()) && !a.iter().any(|v| v.starts_with("sandbox_mode")));
            assert_eq!(a.last().unwrap(), "-");
        }
        assert!(has(
            &with("codex", Some("t"), ReadOnly, None),
            &["-c", "sandbox_mode=\"read-only\""]
        ));
        // agy
        assert!(has(
            &with("agy", None, Edit, None),
            &["--mode", "accept-edits"]
        ));
        let a = with("agy", Some("c"), Full, Some("xhigh"));
        assert!(
            has(&a, &["--mode", "auto", "--dangerously-skip-permissions"])
                && has(&a, &["--effort", "xhigh"])
        );
        assert!(has(&with("agy", None, ReadOnly, None), &["--mode", "plan"]));
        // kimi ignores effort and never passes --auto, which prompt mode rejects
        for p in [Edit, Full] {
            let a = with("kimi", Some("k"), p, Some("high"));
            assert!(
                !a.contains(&"--auto".into())
                    && !a.iter().any(|v| v.contains("effort") || v == "high")
            );
        }
    }

    #[test]
    fn argument_prompts_are_capped() {
        let long = "x".repeat(ARG_PROMPT_CAP + 1);
        assert_eq!(
            check_prompt("kimi", &long),
            Err("This message is too long for Kimi Code.".into())
        );
        assert!(check_prompt("agy", &long).is_err());
        assert!(check_prompt("claude", &long).is_ok());
        assert!(check_prompt("kimi", &long[1..]).is_ok());
    }

    #[test]
    fn spawn_errors_are_distinguished() {
        block_on(async {
            let mut spec = Spec {
                bin: "/nonexistent/lomi-cli".into(),
                args: vec![],
                stdin: None,
                interactive: false,
                cwd: std::env::temp_dir(),
            };
            let e = Proc::spawn(&spec).err().unwrap();
            assert!(e.contains("installed"), "{e}");
            spec.bin = std::env::temp_dir(); // a directory cannot be executed
            let e = Proc::spawn(&spec).err().unwrap();
            assert!(e.starts_with("Cannot start the CLI: "), "{e}");
        });
    }

    #[test]
    fn default_model_omits_flag_and_fills_empty_lists() {
        for cli in ["codex", "kimi", "agy"] {
            let mut i = inv(cli, None, "s");
            i.model = DEFAULT_MODEL;
            let (a, _) = argv(&i);
            assert!(
                !a.iter().any(|x| x == "-m" || x == "--model"),
                "{cli}: {a:?}"
            );
            assert!(!a.iter().any(|x| x == DEFAULT_MODEL), "{cli}: {a:?}");
        }
        assert!(valid_model(DEFAULT_MODEL).is_ok());
        let l = with_default_model(vec![]);
        assert_eq!((l.len(), l[0].id.as_str()), (1, "default"));
        assert_eq!(with_default_model(parse_agy_models("")).len(), 1);
    }

    #[test]
    fn argument_ids_cannot_be_flags() {
        assert!(valid_model("gpt-5.2-codex").is_ok());
        assert!(valid_model("kimi-code/kimi-for-coding").is_ok());
        for bad in ["", "-m", "a b", "a\nb"] {
            assert!(valid_model(bad).is_err(), "{bad:?}");
        }
        assert!(valid_session("session_23542794-d101"));
        assert!(!valid_session("--resume"));
    }

    #[test]
    fn status_parsing() {
        assert_eq!(
            parse_version("2.1.133 (Claude Code)"),
            Some("2.1.133".into())
        );
        assert_eq!(
            parse_version("codex-cli 0.130.0-alpha.1\n"),
            Some("0.130.0-alpha.1".into())
        );
        assert_eq!(parse_version("none"), None);
        assert_eq!(
            parse_claude_status(
                r#"{"loggedIn":true,"email":"a@b.c","subscriptionType":"max","planTier":"max_5x"}"#
            ),
            (Some(true), Some("Max 5x".into()))
        );
        assert_eq!(
            parse_claude_status(r#"{"loggedIn":false}"#),
            (Some(false), None)
        );
        assert_eq!(parse_claude_status("garbage"), (None, None));
        assert_eq!(
            parse_codex_status(true, "Logged in using ChatGPT\n"),
            Some(true)
        );
        assert_eq!(parse_codex_status(false, "Not logged in\n"), Some(false));
        assert_eq!(parse_codex_status(false, "crashed"), None);
    }

    #[test]
    fn model_parsing() {
        let json = r#"{"fetched_at":"x","models":[
            {"slug":"gpt-6.2-sol","display_name":"GPT-6.2-Sol","visibility":"list",
             "supported_reasoning_levels":[{"effort":"low","description":"x"},{"effort":"ultra","description":"y"},{"effort":"-x"}]},
            {"slug":"hidden","display_name":"Hidden","visibility":"hide"},
            {"slug":"-bad","display_name":"Bad","visibility":"list"},
            {"slug":"nolabel","visibility":"list"}]}"#;
        assert_eq!(
            parse_codex_models(json),
            vec![
                CliModel {
                    id: "gpt-6.2-sol".into(),
                    label: "GPT-6.2-Sol".into(),
                    efforts: vec!["low".into(), "ultra".into()]
                },
                CliModel {
                    id: "nolabel".into(),
                    label: "nolabel".into(),
                    efforts: vec![]
                },
            ]
        );
        assert!(parse_codex_models("nope").is_empty());
        let toml = "default_model = \"a\"\n[models.\"kimi-code/k3\"]\nprovider = \"p\"\ndisplay_name = \"K3\"\n[models.plain]\nprovider = \"p\"\n";
        assert_eq!(
            parse_kimi_models(toml),
            vec![
                CliModel {
                    id: "kimi-code/k3".into(),
                    label: "K3".into(),
                    efforts: vec![]
                },
                CliModel {
                    id: "plain".into(),
                    label: "plain".into(),
                    efforts: vec![]
                },
            ]
        );
        assert_eq!(
            parse_agy_models("Fetching available models...\ngemini-x\tGemini X\n"),
            vec![CliModel {
                id: "gemini-x".into(),
                label: "Gemini X".into(),
                efforts: vec![]
            }]
        );
    }

    #[cfg(unix)]
    fn sh(script: &str, stdin: Option<&str>) -> Spec {
        Spec {
            bin: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            stdin: stdin.map(Into::into),
            interactive: false,
            cwd: std::env::temp_dir(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn process_streams_stdout_stdin_and_stderr_tail() {
        block_on(async {
            let mut p = Proc::spawn(&sh(
                "read line; echo \"got $line\"; echo oops >&2; exit 3",
                Some("hello\n"),
            ))
            .unwrap();
            let mut out = String::new();
            p.stdout.read_to_string(&mut out).await.unwrap();
            assert_eq!(out, "got hello\n");
            let (ok, status, stderr) = p.finish().await;
            assert!(!ok);
            assert!(status.contains('3'), "{status}");
            assert_eq!(stderr, "oops");
        });
    }

    #[cfg(unix)]
    #[test]
    fn finish_kills_grandchildren_holding_the_pipes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("sleep 60 & echo $! > {}; exit 0", pid_file.display());
        let started = std::time::Instant::now();
        block_on(async {
            let mut p = Proc::spawn(&sh(&script, None)).unwrap();
            let (ok, _, _) = p.finish().await;
            assert!(ok);
        });
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        for _ in 0..100 {
            // SAFETY: signal 0 only probes for existence.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("grandchild {pid} survived");
    }

    #[cfg(unix)]
    #[test]
    fn dropping_the_process_kills_its_group() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("sleep 60 & echo $! > {}; wait", pid_file.display());
        block_on(async {
            let p = Proc::spawn(&sh(&script, None)).unwrap();
            for _ in 0..100 {
                if std::fs::read_to_string(&pid_file).is_ok_and(|t| t.ends_with('\n')) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            drop(p);
        });
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        for _ in 0..100 {
            // SAFETY: signal 0 only probes for existence.
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("grandchild {pid} survived");
    }

    #[test]
    fn claude_models_parse() {
        let body = br#"{"data":[{"id":"claude-opus-5-5","display_name":"Claude Opus 5.5"},{"id":"claude-opus-5-5"},{"id":"-bad"},{"id":"claude-haiku-5-5"}]}"#;
        let m = parse_claude_models(body);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].label, "Claude Opus 5.5");
        assert_eq!(m[1].label, "claude-haiku-5-5");
        assert!(parse_claude_models(b"nope").is_empty());
    }

    #[test]
    fn plan_names() {
        use base64::Engine;
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"email":"a@b.co","https://api.openai.com/auth":{"chatgpt_plan_type":"plus"}}"#,
        );
        let auth = format!(r#"{{"tokens":{{"id_token":"h.{claims}.s"}}}}"#);
        assert_eq!(codex_plan(&auth).as_deref(), Some("ChatGPT Plus"));
        assert_eq!(codex_plan("{}"), None);
        assert_eq!(plan_label("max_20x").as_deref(), Some("Max 20x"));
        assert_eq!(plan_label("pro").as_deref(), Some("Pro"));
        assert_eq!(plan_label("bad plan!"), None);
    }
}
