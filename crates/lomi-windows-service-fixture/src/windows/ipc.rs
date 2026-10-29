use super::{native::*, state::Config};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::Pipes::*};

pub struct Endpoint(pub Handle);
impl Endpoint {
    pub fn new(config: &Config) -> Result<Self> {
        let security = config.pipe_security()?;
        let handle = Handle::new(unsafe {
            CreateNamedPipeW(
                wide(config.pipe()).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                &security.attributes,
            )
        })?;
        Ok(Self(handle))
    }
    pub fn connect(&self) -> Result<bool> {
        if unsafe { ConnectNamedPipe(self.0.0, ptr::null_mut()) } != 0 {
            return Ok(true);
        }
        match unsafe { GetLastError() } {
            ERROR_PIPE_CONNECTED => Ok(true),
            ERROR_PIPE_LISTENING => Ok(false),
            ERROR_NO_DATA => {
                self.disconnect();
                Ok(false)
            }
            error => Err(std::io::Error::from_raw_os_error(error as i32)),
        }
    }
    pub fn disconnect(&self) {
        unsafe {
            DisconnectNamedPipe(self.0.0);
        }
    }
    pub fn request(&self, stop: &AtomicBool) -> Result<String> {
        self.frame(stop, Duration::from_millis(250))
    }
    fn frame(&self, stop: &AtomicBool, budget: Duration) -> Result<String> {
        let deadline = Instant::now() + budget;
        let mut bytes = Vec::new();
        loop {
            if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
                return Err(denied("request deadline"));
            }
            let mut chunk = [0u8; 65];
            let mut read = 0;
            let ok = unsafe {
                ReadFile(
                    self.0.0,
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    &mut read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                if error != ERROR_NO_DATA {
                    return Err(std::io::Error::from_raw_os_error(error as i32));
                }
            } else {
                bytes.extend_from_slice(&chunk[..read as usize]);
                if bytes.len() > 64 {
                    return Err(denied("request bound"));
                }
                if bytes.contains(&b'\n') {
                    if bytes.last() != Some(&b'\n')
                        || bytes.iter().filter(|&&b| b == b'\n').count() != 1
                    {
                        return Err(denied("invalid request frame"));
                    }
                    bytes.pop();
                    return String::from_utf8(bytes).map_err(|_| denied("invalid request"));
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn respond(&self, bytes: &[u8], stop: &AtomicBool) -> Result<()> {
        if bytes.len() > 2048 {
            return Err(denied("response bound"));
        }
        let mut written = 0;
        unsafe {
            check(WriteFile(
                self.0.0,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                ptr::null_mut(),
            ))?;
        }
        if written as usize != bytes.len() {
            return Err(denied("incomplete response"));
        }
        if self.frame(stop, Duration::from_secs(2))? != "ACK" {
            return Err(denied("response consumption not acknowledged"));
        }
        Ok(())
    }
}
fn open_identification_pipe(config: &Config) -> Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(config.pipe())
}
fn verify_server(config: &Config, file: &std::fs::File) -> Result<Handle> {
    use windows_service::{
        service::{ServiceAccess, ServiceState, ServiceType},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| denied("SCM connection"))?;
    let service = manager
        .open_service(
            config.name(),
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| denied("SCM service query"))?;
    let settings = service
        .query_config()
        .map_err(|_| denied("SCM config query"))?;
    let expected = format!(
        "\"{}\" service {} {}",
        config
            .directory
            .join("lomi-windows-service-fixture.exe")
            .display(),
        config.run,
        config.operator
    );
    if settings.executable_path.as_os_str() != std::ffi::OsStr::new(&expected)
        || settings.service_type != ServiceType::OWN_PROCESS
        || !settings.account_name.as_ref().is_some_and(|s| {
            s.to_string_lossy()
                .eq_ignore_ascii_case(r"NT AUTHORITY\LocalService")
        })
    {
        return Err(denied("unexpected SCM identity"));
    }
    let status = service
        .query_status()
        .map_err(|_| denied("SCM status query"))?;
    let mut server = 0;
    unsafe {
        check(GetNamedPipeServerProcessId(
            file.as_raw_handle(),
            &mut server,
        ))?;
    }
    let process = Handle::new(unsafe {
        windows_sys::Win32::System::Threading::OpenProcess(
            windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            server,
        )
    })?;
    if unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(process.0, 0) }
        != WAIT_TIMEOUT
    {
        return Err(denied("pipe server is not alive"));
    }
    if status.current_state != ServiceState::Running
        || status.process_id != Some(server)
        || server == 0
    {
        return Err(denied("named pipe server is not current SCM owner"));
    }
    Ok(process)
}
pub fn client(config: &Config, command: &str, delay: Duration, hold: bool) -> Result<()> {
    if !matches!(
        command,
        "status" | "start" | "resize" | "after-detach" | "ctrl-c" | "exit"
    ) && !(cfg!(feature = "fixture-test-hooks") && command == "close-fault")
    {
        return Err(denied("invalid client command"));
    }
    config.validate_directory()?;
    let mut file = open_identification_pipe(config)?;
    let _server_lifetime = verify_server(config, &file)?;
    file.write_all(format!("{command}\n").as_bytes())?;
    if hold {
        println!("{{\"requestWritten\":true}}");
        thread::sleep(Duration::from_millis(2500));
        return Ok(());
    }
    thread::sleep(delay);
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut bytes = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err(denied("client deadline"));
        }
        let mut available = 0;
        unsafe {
            check(PeekNamedPipe(
                file.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            ))?;
        }
        if available != 0 {
            let mut chunk = [0; 2048];
            let read = file.read(&mut chunk[..(available as usize).min(2048)])?;
            if read == 0 {
                return Err(denied("closed response"));
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > 2048 {
                return Err(denied("response bound"));
            }
            if bytes.last() == Some(&b'\n') {
                let value: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|_| denied("invalid response"))?;
                file.write_all(b"ACK\n")?;
                println!(
                    "{}",
                    serde_json::to_string(&value).map_err(|_| denied("response encode"))?
                );
                if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                    return Err(denied("fixture command rejected"));
                }
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(feature = "fixture-test-hooks")]
pub fn squatted_server_probe(config: &Config) -> Result<()> {
    use std::sync::mpsc;
    use windows_sys::Win32::{Security::*, System::Threading::*};
    let endpoint = Endpoint::new(config)?;
    let clone = config.clone();
    let (release, held) = mpsc::channel();
    let (outcome, received) = mpsc::channel();
    thread::Builder::new()
        .name("synthetic-sqos-client".into())
        .spawn(move || {
            let result = (|| {
                let mut client = open_identification_pipe(&clone)?;
                let identity_rejected = verify_server(&clone, &client).is_err();
                if !identity_rejected {
                    return Err(denied("squatted server accepted"));
                }
                // Test only: bypass rejected SCM identity to inspect the actual
                // token ceiling on the exact same restricted pipe-opening helper.
                client.write_all(b"probe\n")?;
                let _ = outcome.send(identity_rejected);
                held.recv_timeout(Duration::from_secs(3))
                    .map_err(|_| denied("probe lifetime"))?;
                Ok(())
            })();
            if result.is_err() {
                let _ = outcome.send(false);
            }
        })?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !endpoint.connect()? {
        if Instant::now() >= deadline {
            return Err(denied("squatted connection deadline"));
        }
        thread::sleep(Duration::from_millis(5));
    }
    if endpoint.request(&AtomicBool::new(false))? != "probe" {
        return Err(denied("probe frame"));
    }
    unsafe {
        check(ImpersonateNamedPipeClient(endpoint.0.0))?;
    }
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            unsafe {
                RevertToSelf();
            }
        }
    }
    let revert = Revert;
    let mut token = ptr::null_mut();
    unsafe {
        check(OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY,
            1,
            &mut token,
        ))?;
    }
    let token = Handle::new(token)?;
    let mut level = 99i32;
    let mut length = 0;
    unsafe {
        check(GetTokenInformation(
            token.0,
            TokenImpersonationLevel,
            (&mut level as *mut i32).cast(),
            std::mem::size_of::<i32>() as u32,
            &mut length,
        ))?;
    }
    drop(revert);
    let _ = release.send(());
    if level > SecurityIdentification
        || received.recv_timeout(Duration::from_secs(1)).ok() != Some(true)
    {
        return Err(denied("elevated operator impersonation authority exposed"));
    }
    println!(
        "{{\"squattedServerRejected\":true,\"tokenAtMostIdentification\":true,\"qualified\":false}}"
    );
    Ok(())
}
