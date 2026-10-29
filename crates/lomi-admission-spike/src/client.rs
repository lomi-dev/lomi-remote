use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    time::{Duration, Instant},
};
const FRAME: usize = 16 * 1024;
const LEASE_MS: u64 = 2000;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Request {
    Acquire {
        path: PathBuf,
        kind: Kind,
    },
    AcquireUnscoped {},
    Renew {
        token: String,
    },
    Finish {
        token: String,
    },
    /// Local operator assertion, never a PID/lease liveness inference.
    Reconcile {
        token: String,
        confirmed_terminated: bool,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Native,
    File,
    Git,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub token: Option<String>,
    pub error: Option<String>,
}
pub fn send(stream: &mut UnixStream, request: &Request) -> Result<Reply> {
    let deadline = Instant::now() + Duration::from_millis(LEASE_MS);
    let result = (|| {
        write_until(stream, request, deadline)?;
        read_until(stream, deadline)
    })();
    if result.is_err() {
        // A timed-out frame must never be accepted as a later request reply.
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    result
}
#[cfg(feature = "host")]
pub(crate) fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    read_until(stream, Instant::now() + Duration::from_millis(LEASE_MS))
}
fn read_until<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<T> {
    let mut read = |mut out: &mut [u8]| -> Result<()> {
        while !out.is_empty() {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or("frame deadline")?;
            stream.set_read_timeout(Some(remaining))?;
            let n = stream.read(out)?;
            if n == 0 {
                return Err("connection closed".into());
            }
            out = &mut out[n..];
        }
        Ok(())
    };
    let mut n = [0; 4];
    read(&mut n)?;
    let n = u32::from_be_bytes(n) as usize;
    if n == 0 || n > FRAME {
        return Err("frame limit".into());
    }
    let mut b = vec![0; n];
    read(&mut b)?;
    Ok(serde_json::from_slice(&b)?)
}
#[cfg(feature = "host")]
pub(crate) fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    write_until(stream, value, Instant::now() + Duration::from_millis(500))
}
fn write_until<T: Serialize>(stream: &mut UnixStream, value: &T, deadline: Instant) -> Result<()> {
    let b = serde_json::to_vec(value)?;
    if b.len() > FRAME {
        return Err("frame limit".into());
    }
    let mut frame = Vec::with_capacity(4 + b.len());
    frame.extend_from_slice(&(b.len() as u32).to_be_bytes());
    frame.extend_from_slice(&b);
    let mut pending = frame.as_slice();
    while !pending.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("frame deadline")?;
        stream.set_write_timeout(Some(remaining))?;
        let n = stream.write(pending)?;
        if n == 0 {
            return Err("connection closed".into());
        }
        pending = &pending[n..];
    }
    Ok(())
}

/// Connect to the private experimental host socket.
pub fn connect(directory: &std::path::Path) -> Result<UnixStream> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };
    let path = directory.join("host.sock");
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err("invalid socket path".into());
    }
    address.sun_family = libc::AF_UNIX as _;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as _;
    }
    let length = std::mem::size_of::<libc::sockaddr_un>();
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        address.sun_len = length as _;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.set_nonblocking(true)?;
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    if unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            length as _,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error.into());
        }
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("connect deadline")?;
            let mut poll = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1) as i32) };
            if result == 0 {
                return Err("connect deadline".into());
            }
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if let Some(error) = stream.take_error()? {
                return Err(error.into());
            }
            break;
        }
    }
    stream.set_nonblocking(false)?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stalled_reply_has_absolute_deadline_and_poisoned_connection() {
        let (mut client, _held_peer) = UnixStream::pair().unwrap();
        let start = Instant::now();
        assert!(send(&mut client, &Request::AcquireUnscoped {}).is_err());
        assert!(start.elapsed() < Duration::from_secs(4));
        let retry = Instant::now();
        assert!(send(&mut client, &Request::AcquireUnscoped {}).is_err());
        assert!(retry.elapsed() < Duration::from_millis(500));
    }
    #[test]
    fn original_acquire_wire_shape_remains_compatible() {
        let request: Request =
            serde_json::from_str(r#"{"op":"Acquire","path":"/fixture","kind":"native"}"#).unwrap();
        assert!(matches!(
            request,
            Request::Acquire {
                kind: Kind::Native,
                ..
            }
        ));
    }
}
