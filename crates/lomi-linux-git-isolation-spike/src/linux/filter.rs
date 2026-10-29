use super::{Error, Result};
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::net::UnixStream,
};
const ALLOW: u32 = 0x7fff0000;
const ERRNO: u32 = 0x00050000 | libc::EPERM as u32;
const NOTIFY: u32 = 0x7fc00000;
const ARCH: u32 = 0xc00000b7;
fn ins(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
fn load(offset: u32) -> libc::sock_filter {
    ins(0x20, 0, 0, offset)
}
fn equal(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    ins(0x15, jt, jf, k)
}
fn ret(k: u32) -> libc::sock_filter {
    ins(0x06, 0, 0, k)
}
pub(super) fn program(socket: i32) -> Vec<libc::sock_filter> {
    let mut p = vec![
        load(4),
        equal(ARCH, 1, 0),
        ret(0x80000000),
        load(0),
        equal(libc::SYS_execveat as u32, 0, 1),
        ret(NOTIFY),
    ];
    // Read-only opens; private mount namespace confines resolved content/metadata.
    let write_flags = libc::O_WRONLY
        | libc::O_CREAT
        | libc::O_TRUNC
        | libc::O_APPEND
        | (libc::O_TMPFILE & !libc::O_DIRECTORY);
    p.extend([
        equal(libc::SYS_openat as u32, 0, 4),
        load(32),
        ins(0x45, 0, 1, write_flags as u32),
        ret(ERRNO),
        ret(ALLOW),
    ]);
    p.extend([
        equal(libc::SYS_sendmsg as u32, 0, 4),
        load(16),
        equal(socket as u32, 0, 1),
        ret(ALLOW),
        ret(ERRNO),
    ]);
    p.extend([
        equal(libc::SYS_write as u32, 0, 5),
        load(16),
        equal(1, 2, 0),
        equal(2, 1, 0),
        ret(ERRNO),
        ret(ALLOW),
    ]);
    p.extend([
        equal(libc::SYS_writev as u32, 0, 5),
        load(16),
        equal(1, 2, 0),
        equal(2, 1, 0),
        ret(ERRNO),
        ret(ALLOW),
    ]);
    p.extend([
        equal(libc::SYS_fcntl as u32, 0, 6),
        load(24),
        equal(libc::F_GETFD as u32, 3, 0),
        equal(libc::F_GETFL as u32, 2, 0),
        equal(libc::F_SETFD as u32, 1, 0),
        ret(ERRNO),
        ret(ALLOW),
    ]);
    p.extend([
        equal(libc::SYS_prlimit64 as u32, 0, 6),
        load(16),
        equal(0, 0, 2),
        load(32),
        equal(0, 1, 0),
        ret(ERRNO),
        ret(ALLOW),
    ]);
    for call in [
        libc::SYS_read,
        libc::SYS_readv,
        libc::SYS_pread64,
        libc::SYS_close,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_statx,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_uname,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_futex,
        libc::SYS_getrlimit,
        libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        libc::SYS_times,
        libc::SYS_sched_getaffinity,
        libc::SYS_getrandom,
        libc::SYS_ppoll,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        p.extend([equal(call as u32, 0, 1), ret(ALLOW)]);
    }
    p.push(ret(ERRNO));
    p
}
#[repr(C)]
struct Data {
    nr: i32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}
#[repr(C)]
struct Notification {
    id: u64,
    pid: u32,
    flags: u32,
    data: Data,
}
#[repr(C)]
struct Response {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}
#[repr(C)]
struct Sizes {
    notification: u16,
    response: u16,
    data: u16,
}
const RECV: libc::c_ulong = 0xc0502100;
const SEND: libc::c_ulong = 0xc0182101;
const VALID: libc::c_ulong = 0x40082102;
// No allocation, locks, formatting, or repository inspection in the fork child.
pub(super) unsafe fn send_fd(socket: i32, fd: i32) -> bool {
    unsafe {
        let mut byte = 0x47u8;
        let mut iov = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0u64; 3];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = 24;
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_len = 20;
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        *libc::CMSG_DATA(hdr).cast::<i32>() = fd;
        libc::syscall(libc::SYS_sendmsg, socket, &msg, libc::MSG_NOSIGNAL) == 1
    }
}
fn poll(fd: i32) -> Result<()> {
    let mut item = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut item, 1, 4000) } != 1 || item.revents & libc::POLLIN == 0 {
        return Err(Error::Setup);
    }
    Ok(())
}
pub(super) fn approve(
    socket: &UnixStream,
    pid: i32,
    git: i32,
    path: u64,
    argv: u64,
    env: u64,
    close_before: bool,
) -> Result<()> {
    poll(socket.as_raw_fd())?;
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0u64; 3];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = 24;
    if unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) } != 1
        || byte != 0x47
        || msg.msg_flags & libc::MSG_CTRUNC != 0
    {
        return Err(Error::Setup);
    }
    let hdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if hdr.is_null()
        || unsafe {
            (*hdr).cmsg_len != 20
                || (*hdr).cmsg_level != libc::SOL_SOCKET
                || (*hdr).cmsg_type != libc::SCM_RIGHTS
                || !libc::CMSG_NXTHDR(&msg, hdr).is_null()
        }
    {
        return Err(Error::Setup);
    }
    let listener = unsafe { File::from_raw_fd(*libc::CMSG_DATA(hdr).cast::<i32>()) };
    if close_before {
        return Ok(());
    }
    let mut sizes = Sizes {
        notification: 0,
        response: 0,
        data: 0,
    };
    if unsafe { libc::syscall(libc::SYS_seccomp, 3, 0, &mut sizes) } != 0
        || sizes.notification != 80
        || sizes.response != 24
        || sizes.data != 64
    {
        return Err(Error::Setup);
    }
    poll(listener.as_raw_fd())?;
    // The outer owned-process supervisor bounds this ioctl as well as the Git
    // process. Poll alone cannot eliminate notification invalidation races.
    let mut request: Notification = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(listener.as_raw_fd(), RECV, &mut request) } != 0 {
        return Err(Error::Setup);
    }
    if request.pid != pid as u32
        || request.flags != 0
        || request.data.nr != libc::SYS_execveat as i32
        || request.data.arch != ARCH
        || request.data.args[..5] != [git as u64, path, argv, env, libc::AT_EMPTY_PATH as u64]
    {
        return Err(Error::Setup);
    }
    if unsafe { libc::ioctl(listener.as_raw_fd(), VALID, &request.id) } != 0 {
        return Err(Error::Setup);
    }
    let response = Response {
        id: request.id,
        val: 0,
        error: 0,
        flags: 1,
    };
    if unsafe { libc::ioctl(listener.as_raw_fd(), SEND, &response) } != 0 {
        return Err(Error::Setup);
    }
    // Last listener closes now. Only the replied trusted bootstrap exec continues;
    // any subsequent execveat notification fails ENOSYS in the kernel.
    drop(listener);
    Ok(())
}
pub(super) unsafe fn syscall_probe() -> bool {
    unsafe {
        let denied = |result: i64| result == -1 && *libc::__errno_location() == libc::EPERM;
        let args = [c"/repo/helper-static".as_ptr(), std::ptr::null()];
        let env = [std::ptr::null::<libc::c_char>()];
        if !denied(libc::syscall(
            libc::SYS_execve,
            c"/repo/helper-static".as_ptr(),
            args.as_ptr(),
            env.as_ptr(),
        )) {
            return false;
        }
        for domain in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX] {
            for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
                if !denied(libc::syscall(libc::SYS_socket, domain, kind, 0)) {
                    return false;
                }
            }
        }
        for syscall in [
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
            libc::SYS_ioctl,
            libc::SYS_connect,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_io_uring_setup,
            libc::SYS_unshare,
            libc::SYS_mount,
            libc::SYS_mount_setattr,
            libc::SYS_capset,
            libc::SYS_prctl,
            libc::SYS_fchmodat,
            libc::SYS_fchownat,
            libc::SYS_utimensat,
            libc::SYS_unlinkat,
            libc::SYS_mkdirat,
            libc::SYS_linkat,
            libc::SYS_renameat2,
            libc::SYS_setxattr,
        ] {
            if !denied(libc::syscall(syscall, 0, 0, 0, 0, 0, 0)) {
                return false;
            }
        }
        if !denied(libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            c"write-denied".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT,
            0o600,
        )) {
            return false;
        }
        for path in [
            c"../private",
            c"/etc/passwd",
            c"/home/lomi-e0",
            c"/proc/self/status",
            c"outside-link",
        ] {
            let absent = |r: i64| r == -1 && *libc::__errno_location() == libc::ENOENT;
            if !absent(libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::O_RDONLY,
                0,
            )) {
                return false;
            }
            let mut stat: libc::stat = std::mem::zeroed();
            if !absent(libc::syscall(
                libc::SYS_newfstatat,
                libc::AT_FDCWD,
                path.as_ptr(),
                &mut stat,
                0,
            )) {
                return false;
            }
            let mut sx: libc::statx = std::mem::zeroed();
            if !absent(libc::syscall(
                libc::SYS_statx,
                libc::AT_FDCWD,
                path.as_ptr(),
                0,
                libc::STATX_BASIC_STATS,
                &mut sx,
            )) {
                return false;
            }
            if !absent(libc::syscall(
                libc::SYS_faccessat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::F_OK,
                0,
            )) {
                return false;
            }
            if path != c"outside-link" {
                let mut target = [0u8; 128];
                if !absent(libc::syscall(
                    libc::SYS_readlinkat,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    target.as_mut_ptr(),
                    target.len(),
                )) {
                    return false;
                }
            }
        }
        true
    }
}
pub(super) unsafe fn close_unneeded(git: i32, socket: i32) -> bool {
    unsafe {
        let (low, high) = if git < socket {
            (git, socket)
        } else {
            (socket, git)
        };
        for (start, end) in [(3, low - 1), (low + 1, high - 1), (high + 1, i32::MAX)] {
            if start <= end
                && libc::syscall(libc::SYS_close_range, start as u32, end as u32, 0) != 0
            {
                return false;
            }
        }
        true
    }
}
