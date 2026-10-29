#![cfg(unix)]
use lomi_platform::process::*;
use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[test]
fn inherited_auto_reap_is_reset_only_at_standalone_entry() {
    for mode in ["ignored", "no-child-wait"] {
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "isolated_ownership_probe"])
            .env("LOMI_TEST_CHILD_DISPOSITION", mode)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
#[ignore = "subprocess-only ownership fixture"]
fn isolated_ownership_probe() {
    let mode = std::env::var("LOMI_TEST_CHILD_DISPOSITION").unwrap();
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = if mode == "ignored" {
        libc::SIG_IGN
    } else {
        libc::SIG_DFL
    };
    action.sa_flags = if mode == "no-child-wait" {
        libc::SA_NOCLDWAIT
    } else {
        0
    };
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()),
            0
        );
    }
    assert!(require_child_ownership().is_err());
    initialize_child_ownership().unwrap();
    require_child_ownership().unwrap();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.id(),
                    &mut status,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0
        );
        #[cfg(target_os = "macos")]
        let exited = status.si_pid != 0;
        #[cfg(not(target_os = "macos"))]
        let exited = unsafe { status.si_pid() } != 0;
        if exited {
            break;
        }
        assert!(Instant::now() < deadline, "child exit observation deadline");
        thread::sleep(Duration::from_millis(2));
    }
    require_unreaped_child(&child).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(
        require_unreaped_child(&child).is_err(),
        "reaped PID is not signal authority"
    );
}
