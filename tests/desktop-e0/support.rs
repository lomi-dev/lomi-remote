//! Opt-in isolated GUI fixture. Never compiled into a normal application.
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use tauri::{Manager, Webview, WebviewUrl, WebviewWindowBuilder};
static WATCHDOG_EXPIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// This pinned macOS runtime maps RequestExit to ControlFlow::Exit (status 0).
// Preserve the fixture watchdog's failure status after ordinary owned cleanup.
pub(crate) fn finish_exit() {
    if WATCHDOG_EXPIRED.load(std::sync::atomic::Ordering::SeqCst) {
        std::process::exit(2);
    }
}
fn directory(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = PathBuf::from(std::env::var_os("LOMI_E0_DIRECTORY").ok_or("E0 fixture missing")?);
    let meta = std::fs::symlink_metadata(&root).map_err(|_| "E0 fixture missing")?;
    if !root.is_absolute()
        || !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o777 != 0o700
        || !app.config().identifier.starts_with("dev.lomi.e0-")
    {
        return Err("E0 fixture isolation rejected".into());
    }
    let expected = std::env::var_os("LOMI_E0_APPDATA").ok_or("E0 appdata missing")?;
    if app
        .path()
        .app_data_dir()
        .map_err(|_| "E0 appdata unavailable")?
        != PathBuf::from(expected)
    {
        return Err("E0 appdata mismatch".into());
    }
    Ok(root)
}
#[tauri::command]
pub(crate) fn e0_desktop_mode(app: tauri::AppHandle, webview: Webview) -> Result<String, String> {
    directory(&app)?;
    match webview.label() {
        "main" => Ok("main".into()),
        "e0-observer" => Ok("observer".into()),
        _ => Err("Fixture caller denied".into()),
    }
}
#[tauri::command]
pub(crate) fn e0_desktop_projection(
    app: tauri::AppHandle,
    webview: Webview,
) -> Result<Value, String> {
    if webview.label() != "e0-observer" {
        return Err("Fixture caller denied".into());
    }
    let bytes = std::fs::read(directory(&app)?.join("snapshot.json"))
        .map_err(|_| "Projection unavailable")?;
    if bytes.len() > 16384 {
        return Err("Projection limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Projection invalid".into())
}
fn write(root: &Path, value: Value) {
    let path = root.join("reply.next");
    let bytes = serde_json::to_vec(&value).unwrap();
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
    {
        if f.write_all(&bytes).is_ok() {
            let _ = std::fs::rename(path, root.join("reply.json"));
        }
    }
}
async fn evaluate(view: &Webview, script: &str) -> Result<Value, String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    let send = Mutex::new(Some(send));
    view.eval_with_callback(script, move |s| {
        if let Some(send) = send.lock().unwrap().take() {
            let result = if s.len() > 65536 {
                Err("Evaluation limit".into())
            } else {
                serde_json::from_str(&s).map_err(|_| "Invalid evaluation JSON".into())
            };
            let _ = send.send(result);
        }
    })
    .map_err(|_| "Evaluation failed")?;
    tokio::time::timeout(Duration::from_secs(5), receive)
        .await
        .map_err(|_| "Evaluation timeout")?
        .map_err(|_| "Evaluation dropped")?
}
pub(crate) async fn screenshot(view: &Webview, path: PathBuf) -> Result<Value, String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    let send = std::sync::Arc::new(Mutex::new(Some(send)));
    view.with_webview(move |platform| {
        use objc2_app_kit::NSImage;
        use objc2_foundation::NSError;
        use objc2_web_kit::WKWebView;
        // The handle is retained by Tauri and is accessed on its GUI thread.
        let native = unsafe { &*platform.inner().cast::<WKWebView>() };
        let callback = block2::RcBlock::new(move |image: *mut NSImage, error: *mut NSError| {
            let result = if !error.is_null() || image.is_null() {
                Err("WKWebView snapshot failed".into())
            } else {
                let image = unsafe { &*image };
                image
                    .TIFFRepresentation()
                    .ok_or("Missing native image data".to_string())
                    .and_then(|data| {
                        let bytes = unsafe { data.as_bytes_unchecked() };
                        if bytes.len() > 32 * 1024 * 1024 {
                            return Err("Snapshot too large".into());
                        }
                        let image =
                            image::load_from_memory_with_format(bytes, image::ImageFormat::Tiff)
                                .map_err(|e| e.to_string())?;
                        let dimensions = json!({"width": image.width(), "height": image.height()});
                        image.save(&path).map_err(|e| e.to_string())?;
                        Ok(dimensions)
                    })
            };
            if let Some(send) = send.lock().unwrap().take() {
                let _ = send.send(result);
            }
        });
        unsafe {
            native.takeSnapshotWithConfiguration_completionHandler(None, &callback);
        }
    })
    .map_err(|e| e.to_string())?;
    tokio::time::timeout(Duration::from_secs(5), receive)
        .await
        .map_err(|_| "Snapshot timeout")?
        .map_err(|_| "Snapshot callback dropped")?
}

async fn run_command(app: &tauri::AppHandle, c: &Value) -> Result<Value, String> {
    match c["op"].as_str().ok_or("Command missing")?{
        "screenshot"=>{
            let label=c["view"].as_str().unwrap_or("main");
            if !["main","e0-observer"].contains(&label){return Err("View denied".into());}
            screenshot(&app.get_webview(label).ok_or("View unavailable")?,directory(app)?.join(format!("{label}.png"))).await
        },
        "observer"=>{
            let url=app.config().build.dev_url.clone().ok_or("Fixture requires dev server")?;
            let mut url=url;url.set_query(Some("e0=observer"));
            WebviewWindowBuilder::new(app,"e0-observer",WebviewUrl::External(url)).title("Lomi E0 projection fixture").inner_size(700.,420.).build().map_err(|_|"Observer creation failed")?;
            Ok(json!({"created":true,"nativePtys":app.state::<crate::terminal::Terminals>().e0_count()?}))
        },
        "diagnostic"=>{
            evaluate(&app.get_webview("main").ok_or("Main unavailable")?,"({url:location.href,ready:document.readyState,fixtureMode:window.e0FixtureMode||null,command:!!window.e0Command,workbench:!!window.e0Workbench,content:!!document.querySelector('.cm-content')})").await
        },
        "count"=>Ok(json!({"nativePtys":app.state::<crate::terminal::Terminals>().e0_count()?,"pids":app.state::<crate::terminal::Terminals>().e0_pids()?})),
        "eval"=>{
            let label=c["view"].as_str().unwrap_or("main");
            if !["main","e0-observer"].contains(&label){return Err("View denied".into());}
            let view=app.get_webview(label).ok_or("View unavailable")?;
            for _ in 0..200 {
                if evaluate(&view,"Boolean(window.e0Command)").await.unwrap_or(Value::Null) == true { break; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let data=serde_json::to_string(&c["command"]).map_err(|_|"Command invalid")?;
            evaluate(&view,&format!("(()=>{{window.e0Result=null; if(!window.e0Command)return false;window.e0Command({data}).then(result=>window.e0Result={{ok:true,result}},()=>window.e0Result={{ok:false}});return true;}})()")).await?;
            for _ in 0..200{let r=evaluate(&view,"window.e0Result || null").await?;if !r.is_null(){return Ok(r);}tokio::time::sleep(Duration::from_millis(50)).await;}
            Err("Renderer operation deadline".into())
        },
        "exit"=>{app.exit(0);Ok(json!({"exit":true}))},
        _=>Err("Unsupported fixture command".into())
    }
}
pub(crate) fn start(app: tauri::AppHandle) {
    let Ok(root) = directory(&app) else { return };
    tauri::async_runtime::spawn(async move {
        let mut last = 0;
        // Feature-only shortened watchdog is exercised by a separate negative run.
        let ticks = std::env::var("LOMI_E0_WATCHDOG_TICKS").ok()
            .and_then(|v| v.parse::<usize>().ok()).filter(|n| *n > 0 && *n <= 12000)
            .unwrap_or(12000);
        for _ in 0..ticks {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let Some(c) = std::fs::read(root.join("command.json"))
                .ok()
                .filter(|b| b.len() <= 32768)
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            else {
                continue;
            };
            let Some(seq) = c["seq"].as_u64().filter(|s| *s > last) else {
                continue;
            };
            last = seq;
            let result = run_command(&app, &c).await;
            write(
                &root,
                json!({"seq":seq,"ok":result.is_ok(),"result":result.as_ref().ok(),"error":result.err()}),
            );
        }
        WATCHDOG_EXPIRED.store(true, std::sync::atomic::Ordering::SeqCst);
        app.exit(2);
    });
}
