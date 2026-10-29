use super::native::*;
use std::{
    io::{self, BufRead},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};
use windows_sys::Win32::System::Console::*;
static CTRL_C: AtomicBool = AtomicBool::new(false);
unsafe extern "system" fn control(event: u32) -> i32 {
    if event == CTRL_C_EVENT {
        CTRL_C.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}
pub fn child() -> Result<()> {
    unsafe {
        check(SetConsoleCtrlHandler(Some(control), 1))?;
        check(SetConsoleMode(
            GetStdHandle(STD_INPUT_HANDLE),
            ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT,
        ))?;
    }
    // Job inheritance applies automatically: parent was assigned while suspended.
    // The worker cannot be created before the service has resumed this child.
    let mut worker = Command::new(std::env::current_exe()?)
        .arg("synthetic-worker")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    println!("FIXTURE_WORKER:{}\nFIXTURE_READY", worker.id());
    let (tx, rx) = mpsc::sync_channel(8);
    thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            match line {
                Ok(line) if line.len() <= 32 => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    });
    let mut ctrl_seen = false;
    loop {
        if CTRL_C.swap(false, Ordering::SeqCst) {
            println!("FIXTURE_CTRL_C");
            ctrl_seen = true;
        }
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(line) => match line.trim() {
                "size" => {
                    let mut info = unsafe { std::mem::zeroed() };
                    unsafe {
                        check(GetConsoleScreenBufferInfo(
                            GetStdHandle(STD_OUTPUT_HANDLE),
                            &mut info,
                        ))?;
                    }
                    let info: CONSOLE_SCREEN_BUFFER_INFO = info;
                    if info.dwSize.X == 101 && info.dwSize.Y == 37 {
                        println!("FIXTURE_SIZE_37_101");
                    }
                }
                "after_detach" => println!("FIXTURE_AFTER_DETACH"),
                "exit" => break,
                "" => (),
                _ => return Err(denied("unexpected synthetic input")),
            },
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            // ReadConsole may abort a pending read on Ctrl+C. Keep the child
            // alive for cleanup proof; explicit exit may then be unavailable.
            Err(mpsc::RecvTimeoutError::Disconnected) if ctrl_seen => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(_) => break,
        }
    }
    let _ = worker.kill();
    let _ = worker.wait();
    Ok(())
}
pub fn worker() -> Result<()> {
    // No user commands, external programs, network, files, or inherited input.
    thread::sleep(Duration::from_secs(300));
    Ok(())
}
