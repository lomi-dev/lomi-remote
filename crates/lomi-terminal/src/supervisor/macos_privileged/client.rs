//! Account-side PTY client. The privileged endpoint receives a resolved shell
//! profile but only the Host's final fresh gate can release the child's exec.
use super::{Error, wire};
use crate::{SpawnProfile, unix};
use lomi_platform::service_macos::custody;
use std::{
    fs::File,
    io::{self, Read, Write},
    net::Shutdown,
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

const SPAWN_WINDOW: Duration = Duration::from_secs(10);
const CLEANUP_WINDOW: Duration = Duration::from_secs(8);
const ADMIN_WINDOW: Duration = Duration::from_secs(55);

pub(super) fn absolute_deadline(deadline: Instant) -> Result<u64, Error> {
    // Query continuous time first. Subtracting elapsed host scheduling time
    // from the remaining Instant budget can shorten, never extend, expiry.
    let now = wire::mach_now_ns()?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    now.checked_add(u64::try_from(remaining.as_nanos()).map_err(|_| Error::SpawnFailed)?)
        .ok_or(Error::SpawnFailed)
}

fn after(duration: Duration) -> Result<u64, Error> {
    wire::mach_now_ns()?
        .checked_add(u64::try_from(duration.as_nanos()).map_err(|_| Error::SpawnFailed)?)
        .ok_or(Error::SpawnFailed)
}

pub(in crate::supervisor) struct Worker {
    stream: UnixStream,
    stopped: bool,
    _slot: super::super::Slot,
}
impl Worker {
    pub(in crate::supervisor) fn finished(&self) -> Result<bool, Error> {
        if self.stopped {
            return Ok(true);
        }
        super::super::peek_cleanup(&self.stream)
    }
    pub(in crate::supervisor) fn stop(&mut self) -> Result<(), Error> {
        if self.stopped {
            return Ok(());
        }
        let _ = self.stream.shutdown(Shutdown::Write);
        match wire::read_byte(&self.stream, after(CLEANUP_WINDOW)?) {
            Ok(Some(b'A')) => {
                self.stopped = true;
                Ok(())
            }
            _ => Err(Error::CleanupFailed),
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Closure attenuates authority and triggers broker/controller cleanup.
        // It is not itself a cleanup acknowledgement or an empty-tree proof.
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

pub(crate) fn spawn(
    executable: &Path,
    profile_directory: &Path,
    profile: &SpawnProfile,
    mut before_spawn: impl FnMut() -> bool,
    deadline: Instant,
) -> Result<(unix::Pty, Box<dyn Read + Send>), Error> {
    let deadline_ns = absolute_deadline(deadline.min(Instant::now() + SPAWN_WINDOW))?;
    if !before_spawn() {
        return Err(Error::FenceRejected);
    }
    let count = super::super::WORKERS.fetch_add(1, Ordering::AcqRel);
    let slot = super::super::Slot;
    if count >= 128 {
        return Err(Error::SpawnFailed);
    }
    let binding = custody::privileged_custodian_client_binding(profile_directory, executable)
        .map_err(|_| Error::SpawnFailed)?;
    let stream = wire::connect(binding.socket_path(), deadline_ns)?;
    custody::capture_privileged_custodian_server_proof(&binding, &stream)
        .map_err(|_| Error::SpawnFailed)?;
    if wire::mach_now_ns()? >= deadline_ns || !before_spawn() {
        return Err(Error::FenceRejected);
    }
    let request_id = uuid::Uuid::new_v4().to_string();
    let header = serde_json::json!({
        "version": 1, "operation": "spawn", "registrationKey": binding.registration_key(),
        "requestId": request_id, "deadlineNs": deadline_ns,
    });
    wire::send_json(&stream, &header, deadline_ns)?;
    let start = wire::StartRequest {
        generation_nonce: request_id,
        deadline_ns,
        profile: profile.clone(),
    };
    // Any ambiguous exchange from here retains its original outcome; another
    // connection must never replay this profile/exec intent automatically.
    let result = (|| {
        wire::write_start(&stream, &start)?;
        let master = match wire::receive_ready(&stream, deadline_ns)? {
            wire::ReadyReply::Master(master) => master,
            wire::ReadyReply::Refused => return refusal_ack(&stream),
        };
        if unsafe { libc::isatty(master.as_raw_fd()) } != 1 {
            return Err(Error::SpawnOutcomeUnknown);
        }
        wire::write_start_intent(&stream, deadline_ns)?;
        match wire::read_byte(&stream, deadline_ns)? {
            Some(b'F') => {}
            Some(b'N') => return refusal_ack(&stream),
            Some(b'A') => return Err(Error::FenceRejected),
            _ => return Err(Error::SpawnOutcomeUnknown),
        }
        loop {
            wait_writable(&stream, deadline_ns)?;
            if wire::mach_now_ns()? >= deadline_ns || !before_spawn() {
                // No final E has been sent. Only the broker's positive cleanup
                // ACK can retire the already-created controller/PTY obligation.
                let _ = stream.shutdown(Shutdown::Write);
                return match wire::read_byte(&stream, after(CLEANUP_WINDOW)?) {
                    Ok(Some(b'A')) => Err(Error::FenceRejected),
                    _ => Err(Error::SpawnOutcomeUnknown),
                };
            }
            // No provider, Store, manager, file I/O or blocking write occurs
            // between this fresh Host predicate and its one-byte exec release.
            match wire::try_send_byte_once(&stream, b'E') {
                Ok(true) => break,
                Ok(false) => continue,
                Err(_) => return Err(Error::SpawnOutcomeUnknown),
            }
        }
        match wire::read_spawn_outcome(&stream, deadline_ns)? {
            wire::SpawnOutcome::Started => Ok(Some(master)),
            wire::SpawnOutcome::Refused => refusal_ack(&stream),
        }
    })();
    let master = match result {
        Ok(Some(master)) => master,
        Ok(None) => return Err(Error::SpawnFailed),
        Err(Error::FenceRejected) => return Err(Error::FenceRejected),
        Err(_) => {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(Error::SpawnOutcomeUnknown);
        }
    };
    let worker = super::super::Worker::Privileged(Box::new(Worker {
        stream,
        stopped: false,
        _slot: slot,
    }));
    unix::Pty::from_worker(File::from(master), worker)
}

fn refusal_ack(stream: &UnixStream) -> Result<Option<std::os::fd::OwnedFd>, Error> {
    // N is trusted only together with the broker's joined-cleanup proof. This
    // fresh budget attenuates/settles authority; it cannot start another exec.
    match wire::read_byte(stream, after(CLEANUP_WINDOW)?) {
        Ok(Some(b'A')) => Ok(None),
        _ => Err(Error::SpawnOutcomeUnknown),
    }
}

fn wait_writable(stream: &UnixStream, deadline_ns: u64) -> Result<(), Error> {
    loop {
        let remaining = deadline_ns
            .checked_sub(wire::mach_now_ns()?)
            .ok_or(Error::SpawnFailed)?;
        if remaining == 0 {
            return Err(Error::SpawnFailed);
        }
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN | libc::POLLOUT,
            revents: 0,
        };
        let count = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                remaining.div_ceil(1_000_000).min(10) as i32,
            )
        };
        if count < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::SpawnFailed);
        }
        if descriptor.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
        {
            return Err(Error::SpawnFailed);
        }
        if descriptor.revents & libc::POLLOUT != 0 {
            return Ok(());
        }
    }
}

pub(super) fn admin(registration_path: &Path, drain: bool) -> i32 {
    let result = admin_request(registration_path, drain);
    match result {
        Ok(value) => {
            let mut bytes = match serde_json::to_vec(&value) {
                Ok(bytes) => bytes,
                Err(_) => return 1,
            };
            bytes.push(b'\n');
            if std::io::stdout().lock().write_all(&bytes).is_ok() {
                0
            } else {
                1
            }
        }
        Err(_) => {
            eprintln!("PRIVILEGED_PTY_SERVICE_UNAVAILABLE");
            1
        }
    }
}

fn admin_request(registration_path: &Path, drain: bool) -> Result<serde_json::Value, Error> {
    let registration =
        custody::load_privileged_custodian(registration_path).map_err(|_| Error::CleanupFailed)?;
    let deadline = after(ADMIN_WINDOW)?;
    let stream = wire::connect(registration.socket_path(), deadline)?;
    custody::capture_privileged_custodian_root_peer_proof(&registration, &stream)
        .map_err(|_| Error::CleanupFailed)?;
    let request_id = uuid::Uuid::new_v4().to_string();
    wire::send_json(
        &stream,
        &serde_json::json!({
            "version": 1, "operation": if drain { "adminDrain" } else { "adminStatus" },
            "registrationKey": registration.registration_key(), "requestId": request_id,
        }),
        deadline,
    )?;
    let value = wire::read_canonical_json(&stream, deadline)?;
    let object = value.as_object().ok_or(Error::CleanupFailed)?;
    let expected_keys: &[&str] = if drain {
        &[
            "version",
            "state",
            "registrationKey",
            "requestId",
            "runtimeId",
            "drainedGenerationCount",
            "drainedSetSha256",
        ]
    } else {
        &[
            "version",
            "state",
            "registrationKey",
            "requestId",
            "runtimeId",
        ]
    };
    if object.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !object.contains_key(*key))
        || value["version"].as_u64() != Some(1)
        || value["state"].as_str() != Some(if drain { "drained" } else { "ready" })
        || value["registrationKey"].as_str() != Some(registration.registration_key())
        || value["requestId"].as_str() != Some(request_id.as_str())
        || !value["runtimeId"].as_str().is_some_and(|runtime| {
            uuid::Uuid::parse_str(runtime)
                .is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == runtime)
        })
    {
        return Err(Error::CleanupFailed);
    }
    if drain {
        let hash = value["drainedSetSha256"]
            .as_str()
            .ok_or(Error::CleanupFailed)?;
        if value["drainedGenerationCount"]
            .as_u64()
            .is_none_or(|count| count > 64)
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::CleanupFailed);
        }
        let proof = custody::verify_privileged_custodian_drained(&registration)
            .map_err(|_| Error::CleanupFailed)?;
        if proof.runtime_id() != value["runtimeId"].as_str().ok_or(Error::CleanupFailed)?
            || proof.request_id() != request_id
            || proof.drained_set_sha256() != hash
            || Some(u64::from(proof.drained_generation_count()))
                != value["drainedGenerationCount"].as_u64()
        {
            return Err(Error::CleanupFailed);
        }
    }
    Ok(value)
}
