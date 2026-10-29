#![cfg(unix)]
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Profile {
    base: PathBuf,
    path: PathBuf,
}
impl Profile {
    fn new() -> Self {
        let unique = uuid::Uuid::new_v4().simple();
        let base = fs::canonicalize("/tmp")
            .unwrap()
            .join(format!("lomi-cli-{}-{unique}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        Self {
            path: base.join("p"),
            base,
        }
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        // Retain the private synthetic profile if coordinator shutdown is
        // unconfirmed; never erase a possibly running host's store.
        if !self.path.join("discovery.json").exists() || lomi_host::stop(&self.path).is_ok() {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
}
fn call(profile: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lomiremote"))
        .arg("--profile-dir")
        .arg(profile)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("bounded CLI fixture deadline: {args:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn success(profile: &Path, args: &[&str]) -> Output {
    let output = call(profile, args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn json(profile: &Path, args: &[&str]) -> Value {
    serde_json::from_slice(&success(profile, args).stdout).unwrap()
}
fn workspace_list(profile: &Path) -> Value {
    json(profile, &["workspace", "list", "--json"])["result"]["Ok"]["value"].clone()
}
#[test]
fn actual_cli_clients_share_one_persistent_host_and_preserve_project_files() {
    let profile = Profile::new();
    let project = profile.base.join("project");
    fs::create_dir(&project).unwrap();
    fs::write(project.join("keep.txt"), "synthetic preserved project file").unwrap();
    success(&profile.path, &["daemon", "start"]);
    let first = json(&profile.path, &["status", "--json"]);
    let original_host = first["result"]["Ok"]["value"]["hostId"].clone();
    let original_runtime = first["result"]["Ok"]["value"]["runtimeId"].clone();
    assert!(original_host.as_str().is_some());
    assert!(original_runtime.as_str().is_some());
    assert_eq!(workspace_list(&profile.path), serde_json::json!([]));
    success(
        &profile.path,
        &[
            "workspace",
            "add",
            "--name",
            "Build",
            "--path",
            project.to_str().unwrap(),
        ],
    );
    let list = workspace_list(&profile.path);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let id = list[0]["workspaceId"].as_str().unwrap().to_owned();
    assert_eq!(list[0]["name"], "Build");
    let other_profile = profile.path.clone();
    let second_client = thread::spawn(move || json(&other_profile, &["status", "--json"]));
    assert_eq!(workspace_list(&profile.path)[0]["workspaceId"], id);
    assert_eq!(
        second_client.join().unwrap()["result"]["Ok"]["value"]["hostId"],
        original_host
    );
    success(&profile.path, &["workspace", "share", &id, "--confirm"]);
    assert_eq!(workspace_list(&profile.path)[0]["sharing"], "enabled");
    let second_owner = call(&profile.path, &["daemon", "run"]);
    assert!(!second_owner.status.success());
    assert!(String::from_utf8_lossy(&second_owner.stderr).contains("HOST_BUSY"));
    success(&profile.path, &["daemon", "stop", "--confirm"]);
    success(&profile.path, &["daemon", "start"]);
    let restarted = json(&profile.path, &["status", "--json"]);
    assert_eq!(restarted["result"]["Ok"]["value"]["hostId"], original_host);
    assert_ne!(
        restarted["result"]["Ok"]["value"]["runtimeId"],
        original_runtime
    );
    assert_eq!(workspace_list(&profile.path)[0]["sharing"], "enabled");
    success(&profile.path, &["workspace", "unshare", &id, "--confirm"]);
    success(&profile.path, &["daemon", "stop", "--confirm"]);
    success(&profile.path, &["daemon", "start"]);
    assert_eq!(workspace_list(&profile.path)[0]["sharing"], "disabled");
    success(&profile.path, &["workspace", "remove", &id, "--confirm"]);
    assert_eq!(workspace_list(&profile.path), serde_json::json!([]));
    assert_eq!(
        fs::read_to_string(project.join("keep.txt")).unwrap(),
        "synthetic preserved project file"
    );
    success(&profile.path, &["daemon", "stop", "--confirm"]);
}

fn terminal_state(profile: &Path, id: &str) -> Value {
    json(profile, &["terminal", "list", "--workspace", id, "--json"])["state"].clone()
}
fn terminal_action(profile: &Path, id: &str, args: &[&str]) -> Value {
    let mut full = vec!["terminal"];
    full.extend_from_slice(args);
    full.extend_from_slice(&["--workspace", id, "--json"]);
    let reply = json(profile, &full);
    assert_eq!(reply["result"]["params"]["state"], "succeeded");
    assert!(reply["operationId"].as_str().is_some());
    reply
}
fn panes(state: &Value) -> Vec<Value> {
    fn visit(node: &Value, result: &mut Vec<Value>) {
        if let Some(pane) = node.get("pane") {
            result.push(pane.clone());
        } else {
            visit(&node["first"], result);
            visit(&node["second"], result);
        }
    }
    let mut result = vec![];
    for tab in state["tabs"].as_array().unwrap() {
        visit(&tab["layout"], &mut result);
    }
    result
}
#[test]
fn real_terminal_commands_use_current_descriptors_and_do_not_spawn_on_reads() {
    let profile = Profile::new();
    let project = profile.base.join("project");
    fs::create_dir(&project).unwrap();
    success(&profile.path, &["daemon", "start"]);
    success(
        &profile.path,
        &[
            "workspace",
            "add",
            "--name",
            "Terminals",
            "--path",
            project.to_str().unwrap(),
        ],
    );
    let id = workspace_list(&profile.path)[0]["workspaceId"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(panes(&terminal_state(&profile.path, &id)).is_empty());
    let created = terminal_action(&profile.path, &id, &["create", "--name", "First"]);
    let initial = terminal_state(&profile.path, &id);
    let first = panes(&initial)[0].clone();
    let pane = first["paneId"].as_str().unwrap();
    let tab = initial["tabs"][0]["tabId"].as_str().unwrap();
    assert!(first["session"].is_object());
    for _ in 0..3 {
        assert_eq!(
            panes(&terminal_state(&profile.path, &id))[0]["session"],
            first["session"]
        );
    }
    let renamed = terminal_action(
        &profile.path,
        &id,
        &["rename", "--tab", tab, "--name", "Renamed"],
    );
    assert_ne!(created["operationId"], renamed["operationId"]);
    assert_eq!(
        terminal_state(&profile.path, &id)["tabs"][0]["name"],
        "Renamed"
    );
    terminal_action(
        &profile.path,
        &id,
        &["split", "--pane", pane, "--axis", "vertical"],
    );
    let split = panes(&terminal_state(&profile.path, &id));
    assert_eq!(split.len(), 2);
    let other = split.iter().find(|p| p["paneId"] != pane).unwrap()["paneId"]
        .as_str()
        .unwrap();
    terminal_action(
        &profile.path,
        &id,
        &[
            "move",
            "--pane",
            other,
            "--target-pane",
            pane,
            "--placement",
            "before",
        ],
    );
    terminal_action(&profile.path, &id, &["close", "--pane", other, "--confirm"]);
    assert_eq!(panes(&terminal_state(&profile.path, &id)).len(), 1);
    success(&profile.path, &["daemon", "stop", "--confirm"]);
    success(&profile.path, &["daemon", "start"]);
    let stopped = panes(&terminal_state(&profile.path, &id))[0].clone();
    assert_eq!(stopped["paneId"], pane);
    assert_eq!(stopped["state"], "stopped");
    assert!(stopped["session"].is_null());
    let refused = call(
        &profile.path,
        &["terminal", "attach", "--workspace", &id, "--pane", pane],
    );
    assert_eq!(refused.status.code(), Some(2));
    assert!(!refused.stderr.contains(&27));
    assert!(panes(&terminal_state(&profile.path, &id))[0]["session"].is_null());
    terminal_action(
        &profile.path,
        &id,
        &["restart", "--pane", pane, "--confirm"],
    );
    let restarted = panes(&terminal_state(&profile.path, &id))[0].clone();
    assert_ne!(
        restarted["session"]["sessionEpoch"],
        first["session"]["sessionEpoch"]
    );
    terminal_action(&profile.path, &id, &["close", "--pane", pane, "--confirm"]);
    assert!(panes(&terminal_state(&profile.path, &id)).is_empty());
    success(&profile.path, &["daemon", "stop", "--confirm"]);
}
