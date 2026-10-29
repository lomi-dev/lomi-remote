#[cfg(not(windows))]
fn main() {}
#[cfg(windows)]
fn main() {
    if let Err(error) = proof::run() {
        eprintln!("{error}");
        std::process::exit(1)
    }
}
#[cfg(windows)]
mod proof {
    use lomi_windows_pty::{Pty, TrustedSpawnProfile};
    use std::{
        io::{self, BufRead},
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::Console::*;
    static CTRL: AtomicBool = AtomicBool::new(false);
    unsafe extern "system" fn handler(event: u32) -> i32 {
        if event == CTRL_C_EVENT {
            CTRL.store(true, Ordering::SeqCst);
            1
        } else {
            0
        }
    }
    fn require(ok: bool) -> Result<(), Box<dyn std::error::Error>> {
        if ok {
            Ok(())
        } else {
            Err("synthetic proof assertion".into())
        }
    }
    fn profile() -> Result<TrustedSpawnProfile, Box<dyn std::error::Error>> {
        Ok(TrustedSpawnProfile {
            executable: std::env::current_exe()?,
            args: vec!["child".into()],
            cwd: std::env::current_dir()?,
            environment: vec![],
            rows: 24,
            cols: 80,
        })
    }
    fn observe(pty: &mut Pty, marker: &str) -> Result<(), Box<dyn std::error::Error>> {
        let until = Instant::now() + Duration::from_secs(8);
        let mut tail = Vec::new();
        while Instant::now() < until {
            match pty.read() {
                Ok(bytes) => {
                    tail.extend(bytes);
                    if tail.windows(marker.len()).any(|b| b == marker.as_bytes()) {
                        return Ok(());
                    }
                    if tail.len() > 65536 {
                        return Err("synthetic output bound".into());
                    }
                }
                Err(lomi_windows_pty::Error::Deadline) => (),
                Err(e) => return Err(e.into()),
            }
        }
        Err(format!("synthetic marker deadline: {marker}").into())
    }
    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let mut session = u32::MAX;
        require(
            unsafe {
                windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                    windows_sys::Win32::System::Threading::GetCurrentProcessId(),
                    &mut session,
                )
            } != 0,
        )?;
        require(session == 0)?;
        match std::env::args().nth(1).as_deref() {
            Some("worker") => {
                std::thread::sleep(Duration::from_secs(120));
                return Ok(());
            }
            Some("startup-marker") => {
                std::fs::write("synthetic-child-started", b"owned synthetic marker")?;
                return Ok(());
            }
            Some("pressure-child") => {
                use std::io::Write;
                println!("PRODUCT_PRESSURE_READY");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                require(line.trim() == "pressure")?;
                let block = vec![b'P'; 4096];
                for _ in 0..128 {
                    std::io::stdout().write_all(&block)?;
                }
                std::thread::sleep(Duration::from_secs(120));
                return Ok(());
            }
            Some("final-child") => {
                use std::io::Write;
                println!("PRODUCT_FINAL_READY");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                require(line.trim() == "final")?;
                let deadline = Instant::now() + Duration::from_secs(5);
                while !std::path::Path::new("synthetic-read-timeout-paused").exists() {
                    require(Instant::now() < deadline)?;
                    std::thread::sleep(Duration::from_millis(5));
                }
                let mut output = std::io::stdout().lock();
                let data: String = (0..6000)
                    .map(|n| char::from_u32(0x1e00 + (n % 16)).unwrap())
                    .collect();
                output.write_all(data.as_bytes())?;
                output.write_all(b"\r\nPRODUCT_FINAL_END\r\n")?;
                output.flush()?;
                return Ok(());
            }
            Some("child") => return child(),
            Some("crash-owner") => {
                let mut pty = Pty::spawn(profile()?, || true)?;
                observe(&mut pty, "PRODUCT_READY")?;
                require(pty.active_processes()? == 2)?;
                // ExitProcess bypasses Rust destructors: only Job handle closure
                // may clean up this owner's child and inherited descendant.
                std::process::exit(0);
            }
            _ => (),
        }
        // A host owns its process control policy; normalize inherited launcher
        // ignore state before creating children. The child never repairs it.
        require(unsafe { SetConsoleCtrlHandler(None, 0) } != 0)?;
        require(
            Pty::spawn(profile()?, || false).err() == Some(lomi_windows_pty::Error::SpawnFailed),
        )?;
        #[cfg(feature = "proof-hooks")]
        {
            let marker = std::env::current_dir()?.join("synthetic-child-started");
            require(!marker.exists())?;
            let mut deferred = profile()?;
            deferred.args = vec!["startup-marker".into()];
            let count = lomi_windows_pty::proof_hooks::created_suspended_count();
            let result = Pty::spawn(deferred, || {
                assert!(lomi_windows_pty::proof_hooks::created_suspended_count() > count);
                false
            });
            require(result.err() == Some(lomi_windows_pty::Error::SpawnFailed))?;
            require(
                lomi_windows_pty::proof_hooks::rejected_cleanup_confirmed() && !marker.exists(),
            )?;
        }
        let mut invalid = profile()?;
        invalid.executable.push("missing-synthetic.exe");
        require(Pty::spawn(invalid, || true).err() == Some(lomi_windows_pty::Error::SpawnFailed))?;
        #[cfg(feature = "proof-hooks")]
        {
            lomi_windows_pty::proof_hooks::fail_next_suspended_setup();
            require(
                Pty::spawn(profile()?, || true).err() == Some(lomi_windows_pty::Error::SpawnFailed),
            )?;
        }
        let mut pty = Pty::spawn(profile()?, || true)?;
        observe(&mut pty, "PRODUCT_READY")?;
        require(pty.active_processes()? == 2)?;
        pty.write(b"ping\r\n")?;
        observe(&mut pty, "PRODUCT_PONG")?;
        pty.resize(37, 101)?;
        pty.write(b"size\r\n")?;
        observe(&mut pty, "PRODUCT_SIZE")?;
        require(pty.write(&vec![0; 16385]).is_err())?;
        pty.write(b"exit\r\n")?;
        let until = Instant::now() + Duration::from_secs(3);
        while pty.exit()?.is_none() && Instant::now() < until {
            let _ = pty.read();
        }
        require(pty.exit()?.is_some())?;
        pty.shutdown()?;
        require(pty.active_processes()? == 0)?;
        let mut pty = Pty::spawn(profile()?, || true)?;
        observe(&mut pty, "PRODUCT_READY")?;
        pty.write(&[3])?;
        observe(&mut pty, "PRODUCT_CTRL")?;
        pty.shutdown()?;
        require(pty.active_processes()? == 0)?;
        #[cfg(feature = "proof-hooks")]
        {
            let mut pty = Pty::spawn(profile()?, || true)?;
            observe(&mut pty, "PRODUCT_READY")?;
            lomi_windows_pty::proof_hooks::fail_next_close_thread();
            require(pty.shutdown() == Err(lomi_windows_pty::Error::Cleanup))?;
            require(lomi_windows_pty::proof_hooks::console_retained(&pty))?;
            require(pty.active_processes()? == 0)?;
            pty.shutdown()?;
        }
        // Leave output undrained to exert actual native ConPTY backpressure.
        {
            let mut pressure = profile()?;
            pressure.args = vec!["pressure-child".into()];
            let mut pty = Pty::spawn(pressure, || true)?;
            observe(&mut pty, "PRODUCT_PRESSURE_READY")?;
            pty.write(b"pressure\r\n")?;
            std::thread::sleep(Duration::from_millis(100));
            for n in 0..256 {
                let start = Instant::now();
                let result = pty.resize(24, 80 + n % 2);
                require(start.elapsed() < Duration::from_millis(500))?;
                if result.is_err() {
                    break;
                }
            }
            pty.shutdown()?;
            require(pty.active_processes()? == 0)?;
        }
        #[cfg(feature = "proof-hooks")]
        {
            let mut pty = Pty::spawn(profile()?, || true)?;
            observe(&mut pty, "PRODUCT_READY")?;
            lomi_windows_pty::proof_hooks::delay_next_resize(250);
            let start = Instant::now();
            require(pty.resize(25, 81) == Err(lomi_windows_pty::Error::Deadline))?;
            require(start.elapsed() < Duration::from_millis(500))?;
            require(
                lomi_windows_pty::proof_hooks::resize_in_flight(&pty)
                    && lomi_windows_pty::proof_hooks::console_retained(&pty),
            )?;
            require(pty.write(b"size\r\n") == Err(lomi_windows_pty::Error::Closed))?;
            pty.shutdown()?;
            require(pty.active_processes()? == 0)?;
        }
        // A persistently stuck native call consumes a global ownership charge
        // even after the ordinary session owner is dropped. Admission is bounded.
        #[cfg(feature = "proof-hooks")]
        {
            let before = lomi_windows_pty::proof_hooks::charged_slots();
            let mut pty = Pty::spawn(profile()?, || true)?;
            observe(&mut pty, "PRODUCT_READY")?;
            lomi_windows_pty::proof_hooks::delay_next_resize(20000);
            require(pty.resize(25, 81) == Err(lomi_windows_pty::Error::Deadline))?;
            require(pty.shutdown() == Err(lomi_windows_pty::Error::Cleanup))?;
            require(pty.active_processes()? == 0)?;
            drop(pty);
            require(lomi_windows_pty::proof_hooks::charged_slots() > before)?;
            let blocked_profile = profile()?;
            require(lomi_windows_pty::proof_hooks::probe_admission_bound(|| {
                Pty::spawn(blocked_profile, || panic!("admission bypassed")).err()
                    == Some(lomi_windows_pty::Error::ResourceExhausted)
            }))?;
            println!("PRODUCT_QUARANTINE_BOUND_PASS");
        }
        // This independently owned child shares the account and executable but
        // belongs to no PTY Job; cleanup must leave it running.
        let mut unrelated = std::process::Command::new(std::env::current_exe()?)
            .arg("worker")
            .env_clear()
            .spawn()?;
        let crash_status = std::process::Command::new(std::env::current_exe()?)
            .arg("crash-owner")
            .env_clear()
            .status();
        let unrelated_alive = unrelated.try_wait()?.is_none();
        unrelated.kill()?;
        unrelated.wait()?;
        require(crash_status?.success() && unrelated_alive)?;
        println!("PRODUCT_PTY_SESSION_0\nPRODUCT_PTY_SMOKE_PASS");
        Ok(())
    }
    fn child() -> Result<(), Box<dyn std::error::Error>> {
        if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 {
            return Err("synthetic control handler".into());
        }
        if unsafe {
            SetConsoleMode(
                GetStdHandle(STD_INPUT_HANDLE),
                ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT,
            )
        } == 0
        {
            return Err("synthetic input console mode".into());
        }
        let mut worker = std::process::Command::new(std::env::current_exe()?)
            .arg("worker")
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        std::thread::spawn(move || {
            for line in io::stdin().lock().lines() {
                if let Ok(line) = line {
                    if line.len() > 16 || tx.send(line).is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
        });
        println!("PRODUCT_READY");
        loop {
            if CTRL.swap(false, Ordering::SeqCst) {
                println!("PRODUCT_CTRL")
            }
            match rx.recv_timeout(Duration::from_millis(20)) {
                Ok(line) => match line.trim() {
                    "ping" => println!("PRODUCT_PONG"),
                    "size" => {
                        let mut info = unsafe { std::mem::zeroed() };
                        require(
                            unsafe {
                                GetConsoleScreenBufferInfo(
                                    GetStdHandle(STD_OUTPUT_HANDLE),
                                    &mut info,
                                )
                            } != 0,
                        )?;
                        require(info.dwSize.X == 101 && info.dwSize.Y == 37)?;
                        println!("PRODUCT_SIZE")
                    }
                    "exit" => break,
                    _ => (),
                },
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        worker.kill()?;
        worker.wait()?;
        Ok(())
    }
}
