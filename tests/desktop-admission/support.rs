//! Actual native command and guard fixture; deliberately bypasses normal startup.
use crate::{
    files::editor::{EditorFiles, SaveFile},
    project_write_guard,
};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    process::{Child, Command},
    time::Duration,
};
use tauri::Manager;

pub(crate) fn run(mut context: tauri::Context<tauri::Wry>) {
    let directory = PathBuf::from(
        std::env::var_os("LOMI_E0_PROBE_DIRECTORY").expect("private fixture required"),
    );
    let identifier = std::env::var("LOMI_E0_IDENTIFIER").expect("private identity required");
    assert!(identifier.starts_with("dev.lomi.e0-admission-") && identifier.len() == 54);
    context.config_mut().identifier = identifier;
    // Rust-only fixture: create a real native Window, with no webview or
    // frontend at all. The normal development URL and dist assets are unused.
    context.config_mut().build.dev_url = None;
    context.config_mut().app.windows.clear();
    tauri::Builder::default()
        .manage(EditorFiles::default())
        .setup(move |app| {
            tauri::window::WindowBuilder::new(app, "main")
                .visible(false)
                .build()?;
            let app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut lease = None;
                let mut child: Option<Child> = None;
                let project = directory.join("project");
                let mut sequence = 0;
                loop {
                    let input = directory.join(format!("request-{sequence}.json"));
                    if let Ok(bytes) = std::fs::read(&input) {
                        let request: Value = serde_json::from_slice(&bytes).unwrap();
                        let result: Result<Value, String> = async {
                            match request["op"].as_str().ok_or("invalid probe operation")? {
                                "page" => {
                                    if app.get_window("main").is_none() || app.get_webview("main").is_some() {
                                        return Err("fixture must have a native window without any frontend".into());
                                    }
                                    Ok(json!({"frontend": "none"}))
                                },
                                "native" => {
                                    let held = project_write_guard::activate(
                                        &project,
                                        "e0-owned-child",
                                        1,
                                    )?;
                                    let owned = Command::new(directory.join("controlled-child"))
                                        .env_clear()
                                        .env("HOME", directory.join("child-home"))
                                        .stdin(std::process::Stdio::piped())
                                        .stdout(std::process::Stdio::null())
                                        .stderr(std::process::Stdio::null())
                                        .spawn()
                                        .map_err(|_| "controlled child spawn failed")?;
                                    let token = held.probe_token().to_owned();
                                    child = Some(owned);
                                    lease = Some(held);
                                    Ok(json!({"token": token, "childAlive": true}))
                                }
                                "check" => {
                                    lease
                                        .as_ref()
                                        .ok_or("no native lease")?
                                        .check("e0-owned-child", 1)?;
                                    Ok(json!(true))
                                }
                                "managed_check" => {
                                    project_write_guard::check_native(&project)?;
                                    Ok(json!(true))
                                }
                                "unscoped" => {
                                    let _guard =
                                        project_write_guard::admit_unscoped()?.known_in_process();
                                    Ok(json!(true))
                                }
                                "drop" => {
                                    lease.take();
                                    let alive = child
                                        .as_mut()
                                        .ok_or("no owned child")?
                                        .try_wait()
                                        .map_err(|_| "child wait failed")?
                                        .is_none();
                                    if !alive {
                                        return Err("child was not alive on disconnect".into());
                                    }
                                    Ok(json!({"childAlive": true}))
                                }
                                "terminate_wait" => {
                                    let mut owned = child.take().ok_or("no owned child")?;
                                    owned.kill().map_err(|_| "child kill failed")?;
                                    let status = owned.wait().map_err(|_| "child wait failed")?;
                                    Ok(json!({"waited": true, "success": status.success()}))
                                }
                                "save" => {
                                    let request: SaveFile =
                                        serde_json::from_value(request["request"].clone())
                                            .map_err(|_| "invalid save fixture")?;
                                    let window =
                                        app.get_window("main").ok_or("no real main window")?;
                                    let result = crate::files::editor::save_editor_file(
                                        window,
                                        app.clone(),
                                        request,
                                    )
                                    .await;
                                    result
                                        .map(|_| json!(true))
                                        .map_err(|_| "actual save_editor_file rejected".into())
                                }
                                "exit" => Ok(json!(true)),
                                _ => Err("unsupported probe operation".into()),
                            }
                        }
                        .await;
                        let output = match result {
                            Ok(value) => json!({"ok":true,"value":value}),
                            Err(error) => json!({"ok":false,"error":error}),
                        };
                        std::fs::write(
                            directory.join(format!("reply-{sequence}.json")),
                            output.to_string(),
                        )
                        .unwrap();
                        sequence += 1;
                        if request["op"] == "exit" {
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                // Never leave a controlled writer alive, even on the fixture shutdown path.
                if let Some(mut owned) = child {
                    let _ = owned.kill();
                    let _ = owned.wait();
                }
                drop(lease);
                app.exit(0);
            });
            Ok(())
        })
        .run(context)
        .expect("isolated E0 Tauri run failed");
}
