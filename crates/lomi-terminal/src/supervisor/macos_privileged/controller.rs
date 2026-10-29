//! Per-generation root controller. Only the registered executable is started
//! with root credentials; shell configuration is sent over a private channel
//! to that executable's child entry point, which drops permanently to the
//! selected account before it reads or executes the shell profile.

use super::{Error, capability, journal, wire};
use lomi_platform::service_macos::custody::{self, PrivilegedCustodianRegistration};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CHILD_ENTRY_ARGUMENT: &str = "--internal-privileged-pty-child";
const CHILD_CONTROL_FD: RawFd = 3;
const CLEANUP_WINDOW: Duration = Duration::from_secs(5);
const TERM_WINDOW: Duration = Duration::from_millis(350);
const RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Default)]
struct SessionResources {
    broker: Option<UnixStream>,
    child_control: Option<UnixStream>,
    master: Option<OwnedFd>,
    child: Option<Child>,
    child_control_closed: bool,
    refused: bool,
}

/// Entry called only from the fixed internal root-controller CLI dispatch.
/// The LaunchDaemon passes its fixed registration path and one canonical
/// `<state>/generations/<uuid>` directory; user paths and shell arguments are
/// never accepted on this command line.
pub(super) fn run_controller(registration_path: &Path, generation_directory: &Path) -> i32 {
    match run_inner(registration_path, generation_directory) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn run_inner(registration_path: &Path, generation_directory: &Path) -> Result<(), Error> {
    require_root_credentials()?;
    let registration =
        custody::load_privileged_custodian(registration_path).map_err(|_| Error::CleanupFailed)?;
    let mut journal = journal::claim_controller(&registration, generation_directory)?;
    let identity = match validate_controller_cohort() {
        Ok(identity) => identity,
        Err(error) => {
            let _ = journal.mark_not_started();
            return Err(error);
        }
    };

    let mut resources = SessionResources::default();
    let session = run_session(&registration, &mut journal, &identity, &mut resources);
    if session.is_err() {
        if journal.record().state() == journal::GenerationState::Prepared {
            if journal.mark_not_started().is_ok() {
                if let Some(broker) = resources.broker.as_ref() {
                    if let Ok(deadline_ns) = cleanup_io_deadline() {
                        if wire::write_spawn_outcome(
                            broker,
                            wire::SpawnOutcome::Refused,
                            deadline_ns,
                        )
                        .is_ok()
                        {
                            let _ = wire::write_ack_cleaned(broker);
                        }
                    }
                }
            }
        } else if journal.record().state() != journal::GenerationState::Cleaned {
            let cleaned = cleanup_generation(&mut journal, &identity, &mut resources);
            if cleaned.is_err() {
                hold_unknown_until_empty(&mut journal, &identity, &mut resources);
            }
        }
    }
    session
}

fn run_session(
    registration: &PrivilegedCustodianRegistration,
    journal: &mut journal::GenerationJournal,
    identity: &capability::Identity,
    resources: &mut SessionResources,
) -> Result<(), Error> {
    let generation_nonce = journal.record().generation_nonce().to_owned();
    let deadline_ns = journal.record().deadline_ns();
    let broker = wire::connect(registration.socket_path(), deadline_ns)?;
    let peer = custody::capture_privileged_custodian_root_peer_proof(registration, &broker)
        .map_err(|_| Error::SpawnFailed)?;
    if peer.registration_key() != registration.registration_key()
        || peer.peer_uid() != 0
        || peer.peer_pid() <= 0
    {
        return Err(Error::SpawnFailed);
    }
    let broker_identity = capability::identity_from_audit(&peer.audit_token())?;
    if broker_identity.pid() != peer.peer_pid()
        || broker_identity.audit()[1] != 0
        || broker_identity.resource() == identity.resource()
    {
        return Err(Error::SpawnFailed);
    }
    resources.broker = Some(broker);
    wire::write_hello(
        resources.broker.as_ref().ok_or(Error::SpawnFailed)?,
        &generation_nonce,
        registration.registration_key(),
        identity,
        deadline_ns,
    )?;

    // The broker is authenticated before it can submit the profile. The same
    // absolute deadline gates Start, user-credential readiness, and the E gate.
    let start = wire::read_start(
        resources.broker.as_ref().ok_or(Error::SpawnFailed)?,
        &generation_nonce,
        deadline_ns,
    )?;
    let (master, slave) = create_pty(
        registration.owner_uid(),
        registration.owner_gid(),
        start.profile.rows,
        start.profile.cols,
    )?;
    resources.master = Some(master);
    let (controller_control, child_control) = UnixStream::pair().map_err(|_| Error::SpawnFailed)?;
    wire::configure_sigpipe_suppression(&controller_control)?;
    journal.mark_controller_ready(identity)?;
    let child = spawn_trusted_child(registration, &slave, child_control.as_raw_fd())?;
    drop(child_control);
    resources.child_control = Some(controller_control);
    resources.child = Some(child);

    let bootstrap = child_bootstrap(registration, identity, start.deadline_ns);
    wire::send_json(
        resources.child_control.as_ref().ok_or(Error::SpawnFailed)?,
        &bootstrap,
        deadline_ns,
    )?;
    let profile = wire::profile_value(&start.profile)?;
    wire::send_json(
        resources.child_control.as_ref().ok_or(Error::SpawnFailed)?,
        &profile,
        deadline_ns,
    )?;

    match await_child_ready(resources, registration, identity, deadline_ns)? {
        ReadyOutcome::Ready => {}
        ReadyOutcome::Cancelled => return cleanup_generation(journal, identity, resources),
        ReadyOutcome::Refused => {
            resources.refused = true;
            return cleanup_generation(journal, identity, resources);
        }
    }
    wire::send_d_with_master(
        resources.broker.as_ref().ok_or(Error::SpawnFailed)?,
        resources
            .master
            .as_ref()
            .ok_or(Error::SpawnFailed)?
            .as_raw_fd(),
        deadline_ns,
    )?;

    match await_host_intent(resources, registration, identity, deadline_ns)? {
        DecisionOutcome::Commit => {}
        DecisionOutcome::Cancelled => return cleanup_generation(journal, identity, resources),
        DecisionOutcome::Refused => {
            resources.refused = true;
            return cleanup_generation(journal, identity, resources);
        }
    }

    // I records intent only. The durable transition must precede F, which
    // asks the Host for a fresh authorization decision after the fsync.
    journal.mark_start_committed()?;
    wire::write_final_authorization_request(
        resources.broker.as_ref().ok_or(Error::SpawnFailed)?,
        deadline_ns,
    )?;

    match await_host_decision(resources, registration, identity, deadline_ns)? {
        DecisionOutcome::Commit => {}
        DecisionOutcome::Cancelled => return cleanup_generation(journal, identity, resources),
        DecisionOutcome::Refused => {
            resources.refused = true;
            return cleanup_generation(journal, identity, resources);
        }
    }

    let broker = resources.broker.as_ref().ok_or(Error::SpawnFailed)?;
    let child_control = resources.child_control.as_ref().ok_or(Error::SpawnFailed)?;
    if resources.child.as_ref().is_none_or(direct_child_exited) {
        return Err(Error::SpawnFailed);
    }
    wire::require_final_commit_window(broker, child_control, deadline_ns)?;
    if !wire::try_send_byte_once(child_control, b'E')? {
        return Err(Error::SpawnFailed);
    }

    match await_child_spawn_outcome(resources, registration, identity, deadline_ns)? {
        wire::SpawnOutcome::Started => {
            wire::write_spawn_outcome(
                resources.broker.as_ref().ok_or(Error::SpawnFailed)?,
                wire::SpawnOutcome::Started,
                deadline_ns,
            )?;
        }
        wire::SpawnOutcome::Refused => {
            resources.refused = true;
            return cleanup_generation(journal, identity, resources);
        }
    }
    await_session_end(resources)?;
    cleanup_generation(journal, identity, resources)
}

fn validate_controller_cohort() -> Result<capability::Identity, Error> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 || !capability::available()
    {
        return Err(Error::CleanupFailed);
    }
    lomi_platform::process::require_child_ownership().map_err(|_| Error::CleanupFailed)?;
    capability::require_nonprivileged_current()?;
    let first = capability::current_cohorts()?;
    capability::require_nonprivileged_current()?;
    let second = capability::current_cohorts()?;
    if !first.same_task_and_cohorts(second) || capability::count(&second)? != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(second)
}

enum ReadyOutcome {
    Ready,
    Refused,
    Cancelled,
}

fn await_child_ready(
    resources: &SessionResources,
    registration: &PrivilegedCustodianRegistration,
    controller: &capability::Identity,
    deadline_ns: u64,
) -> Result<ReadyOutcome, Error> {
    loop {
        let broker = resources.broker.as_ref().ok_or(Error::SpawnFailed)?;
        let child_control = resources.child_control.as_ref().ok_or(Error::SpawnFailed)?;
        let (broker_ready, child_ready) = wire::poll_streams(
            broker.as_raw_fd(),
            Some(child_control.as_raw_fd()),
            Some(deadline_ns),
        )?;
        if broker_ready {
            match wire::read_byte(broker, deadline_ns)? {
                Some(b'X') | None => return Ok(ReadyOutcome::Cancelled),
                _ => return Err(Error::SpawnFailed),
            }
        }
        if child_ready {
            match wire::read_child_ready(child_control, deadline_ns)? {
                wire::ChildReady::Dropped => {
                    validate_child_peer(
                        child_control,
                        resources.child.as_ref().ok_or(Error::SpawnFailed)?.id(),
                        registration,
                        controller,
                    )?;
                    return Ok(ReadyOutcome::Ready);
                }
                wire::ChildReady::Refused => {
                    validate_child_refusal_peer(
                        child_control,
                        resources.child.as_ref().ok_or(Error::SpawnFailed)?.id(),
                        registration,
                        controller,
                    )?;
                    return Ok(ReadyOutcome::Refused);
                }
            }
        }
        if resources.child.as_ref().is_some_and(direct_child_exited) {
            return Err(Error::SpawnFailed);
        }
    }
}

fn await_child_spawn_outcome(
    resources: &SessionResources,
    registration: &PrivilegedCustodianRegistration,
    controller: &capability::Identity,
    deadline_ns: u64,
) -> Result<wire::SpawnOutcome, Error> {
    loop {
        let broker = resources.broker.as_ref().ok_or(Error::SpawnFailed)?;
        let child_control = resources.child_control.as_ref().ok_or(Error::SpawnFailed)?;
        let (broker_ready, child_ready) = wire::poll_streams(
            broker.as_raw_fd(),
            Some(child_control.as_raw_fd()),
            Some(deadline_ns),
        )?;
        if broker_ready {
            let _ = wire::read_byte(broker, deadline_ns)?;
            return Err(Error::SpawnFailed);
        }
        if child_ready {
            let outcome = wire::read_spawn_outcome(child_control, deadline_ns)?;
            if outcome == wire::SpawnOutcome::Refused {
                validate_child_refusal_peer(
                    child_control,
                    resources.child.as_ref().ok_or(Error::SpawnFailed)?.id(),
                    registration,
                    controller,
                )?;
            }
            return Ok(outcome);
        }
        if resources.child.as_ref().is_some_and(direct_child_exited) {
            return Err(Error::SpawnFailed);
        }
    }
}

enum DecisionOutcome {
    Commit,
    Cancelled,
    Refused,
}

fn await_host_intent(
    resources: &SessionResources,
    registration: &PrivilegedCustodianRegistration,
    controller: &capability::Identity,
    deadline_ns: u64,
) -> Result<DecisionOutcome, Error> {
    loop {
        let broker = resources.broker.as_ref().ok_or(Error::SpawnFailed)?;
        let child_control = resources.child_control.as_ref().ok_or(Error::SpawnFailed)?;
        let (broker_ready, child_ready) = wire::poll_streams(
            broker.as_raw_fd(),
            Some(child_control.as_raw_fd()),
            Some(deadline_ns),
        )?;
        if child_ready {
            return match read_helper_spawn_outcome(
                child_control,
                resources,
                registration,
                controller,
                deadline_ns,
            )? {
                wire::SpawnOutcome::Refused => Ok(DecisionOutcome::Refused),
                wire::SpawnOutcome::Started => Err(Error::SpawnFailed),
            };
        }
        if broker_ready {
            match wire::read_start_intent(broker, deadline_ns)? {
                wire::StartIntent::Start => return Ok(DecisionOutcome::Commit),
                wire::StartIntent::Cancel => return Ok(DecisionOutcome::Cancelled),
            }
        }
        if resources.child.as_ref().is_some_and(direct_child_exited) {
            return Err(Error::SpawnFailed);
        }
    }
}

fn await_host_decision(
    resources: &SessionResources,
    registration: &PrivilegedCustodianRegistration,
    controller: &capability::Identity,
    deadline_ns: u64,
) -> Result<DecisionOutcome, Error> {
    loop {
        let broker = resources.broker.as_ref().ok_or(Error::SpawnFailed)?;
        let child_control = resources.child_control.as_ref().ok_or(Error::SpawnFailed)?;
        let (broker_ready, child_ready) = wire::poll_streams(
            broker.as_raw_fd(),
            Some(child_control.as_raw_fd()),
            Some(deadline_ns),
        )?;
        if child_ready {
            return match read_helper_spawn_outcome(
                child_control,
                resources,
                registration,
                controller,
                deadline_ns,
            )? {
                wire::SpawnOutcome::Refused => Ok(DecisionOutcome::Refused),
                wire::SpawnOutcome::Started => Err(Error::SpawnFailed),
            };
        }
        if broker_ready {
            return match wire::read_decision(broker, deadline_ns)? {
                wire::Decision::Commit => Ok(DecisionOutcome::Commit),
                wire::Decision::Cancel => Ok(DecisionOutcome::Cancelled),
            };
        }
        if resources.child.as_ref().is_some_and(direct_child_exited) {
            return Err(Error::SpawnFailed);
        }
    }
}

fn read_helper_spawn_outcome(
    stream: &UnixStream,
    resources: &SessionResources,
    registration: &PrivilegedCustodianRegistration,
    controller: &capability::Identity,
    deadline_ns: u64,
) -> Result<wire::SpawnOutcome, Error> {
    let outcome = wire::read_spawn_outcome(stream, deadline_ns)?;
    if outcome == wire::SpawnOutcome::Refused {
        validate_child_refusal_peer(
            stream,
            resources.child.as_ref().ok_or(Error::SpawnFailed)?.id(),
            registration,
            controller,
        )?;
    }
    Ok(outcome)
}

fn await_session_end(resources: &mut SessionResources) -> Result<(), Error> {
    loop {
        let broker = resources.broker.as_ref().ok_or(Error::SpawnFailed)?;
        let child_fd = if resources.child_control_closed {
            None
        } else {
            resources.child_control.as_ref().map(AsRawFd::as_raw_fd)
        };
        let (broker_ready, child_ready) = wire::poll_streams(broker.as_raw_fd(), child_fd, None)?;
        if broker_ready {
            match wire::read_byte(broker, nonblocking_read_deadline()?)? {
                Some(b'X') | None => return Ok(()),
                _ => return Err(Error::SpawnFailed),
            }
        }
        if child_ready {
            let child_control = resources.child_control.as_ref().ok_or(Error::SpawnFailed)?;
            match wire::read_byte(child_control, nonblocking_read_deadline()?)? {
                None => resources.child_control_closed = true,
                Some(_) => return Err(Error::SpawnFailed),
            }
        }
        if resources.child.as_ref().is_some_and(direct_child_exited) {
            return Ok(());
        }
    }
}

fn child_bootstrap(
    registration: &PrivilegedCustodianRegistration,
    controller: &capability::Identity,
    deadline_ns: u64,
) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "accountName": registration.account_name(),
        "uid": registration.owner_uid(),
        "gid": registration.owner_gid(),
        "parentPid": controller.pid(),
        "parentPidVersion": controller.pidversion(),
        "parentAudit": controller.audit(),
        "parentResource": controller.resource(),
        "parentJetsam": controller.jetsam(),
        "deadlineNs": deadline_ns,
    })
}

fn spawn_trusted_child(
    registration: &PrivilegedCustodianRegistration,
    slave: &File,
    child_control_fd: RawFd,
) -> Result<Child, Error> {
    let stdin = slave.try_clone().map_err(|_| Error::SpawnFailed)?;
    let stdout = slave.try_clone().map_err(|_| Error::SpawnFailed)?;
    let stderr = slave.try_clone().map_err(|_| Error::SpawnFailed)?;
    let mut command = Command::new(registration.executable_path());
    command
        .arg(CHILD_ENTRY_ARGUMENT)
        .arg(CHILD_CONTROL_FD.to_string())
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let child_control_fd = child_control_fd;
    unsafe {
        command.pre_exec(move || {
            if child_control_fd != CHILD_CONTROL_FD
                && libc::dup2(child_control_fd, CHILD_CONTROL_FD) != CHILD_CONTROL_FD
            {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(CHILD_CONTROL_FD, libc::F_SETFD, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().map_err(|_| Error::SpawnFailed)
}

fn validate_child_peer(
    stream: &UnixStream,
    expected_pid: u32,
    registration: &PrivilegedCustodianRegistration,
    controller: &capability::Identity,
) -> Result<(), Error> {
    let mut peer_uid = 0;
    let mut peer_gid = 0;
    // LOCAL_PEERCRED retains the root socketpair creator's credentials.
    // The live peer audit token below proves the helper's credential drop.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut peer_uid, &mut peer_gid) } != 0
        || peer_uid != 0
        || peer_gid != 0
    {
        return Err(Error::SpawnFailed);
    }
    let mut audit = [0u32; 8];
    let mut length = std::mem::size_of_val(&audit) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            audit.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of_val(&audit)
        || audit[1] != registration.owner_uid()
        || audit[2] != registration.owner_gid()
        || audit[3] != registration.owner_uid()
        || audit[4] != registration.owner_gid()
        || audit[5] != expected_pid
        || audit[7] == 0
    {
        return Err(Error::SpawnFailed);
    }
    let child = capability::identity_from_audit(&audit)?;
    if child.pid() != expected_pid as i32
        || !child.same_cohorts(*controller)
        || child.resource() != controller.resource()
        || child.jetsam() != controller.jetsam()
    {
        return Err(Error::SpawnFailed);
    }
    Ok(())
}

/// A refusal can arrive before permanent credential drop has completed. The
/// direct helper may therefore still be root or may have only its group IDs
/// changed. It remains the known direct child on this private socket, and its
/// audit token must still pin it to the controller's exact cohorts.
fn validate_child_refusal_peer(
    stream: &UnixStream,
    expected_pid: u32,
    registration: &PrivilegedCustodianRegistration,
    controller: &capability::Identity,
) -> Result<(), Error> {
    let mut peer_uid = 0;
    let mut peer_gid = 0;
    // Socketpair credentials remain root even if the refusing helper has
    // already changed its group IDs or permanently dropped to the account.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut peer_uid, &mut peer_gid) } != 0
        || peer_uid != 0
        || peer_gid != 0
    {
        return Err(Error::SpawnFailed);
    }
    let mut audit = [0u32; 8];
    let mut length = std::mem::size_of_val(&audit) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            audit.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of_val(&audit)
        || ![0, registration.owner_uid()].contains(&audit[1])
        || ![0, registration.owner_uid()].contains(&audit[3])
        || ![0, registration.owner_gid()].contains(&audit[2])
        || ![0, registration.owner_gid()].contains(&audit[4])
        || audit[5] != expected_pid
        || audit[7] == 0
    {
        return Err(Error::SpawnFailed);
    }
    let child = capability::identity_from_audit(&audit)?;
    if child.pid() != expected_pid as i32
        || !child.same_cohorts(*controller)
        || child.resource() != controller.resource()
        || child.jetsam() != controller.jetsam()
    {
        return Err(Error::SpawnFailed);
    }
    Ok(())
}

fn create_pty(
    owner_uid: u32,
    owner_gid: u32,
    rows: u16,
    cols: u16,
) -> Result<(OwnedFd, File), Error> {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if master < 0 {
        return Err(Error::SpawnFailed);
    }
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    if unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0
        || unsafe { libc::grantpt(master.as_raw_fd()) } != 0
        || unsafe { libc::unlockpt(master.as_raw_fd()) } != 0
    {
        return Err(Error::SpawnFailed);
    }
    let name = unsafe { libc::ptsname(master.as_raw_fd()) };
    if name.is_null() {
        return Err(Error::SpawnFailed);
    }
    let name = unsafe { CStr::from_ptr(name) };
    if !name.to_bytes().starts_with(b"/dev/") {
        return Err(Error::SpawnFailed);
    }
    let path = CString::new(name.to_bytes()).map_err(|_| Error::SpawnFailed)?;
    let slave = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if slave < 0 {
        return Err(Error::SpawnFailed);
    }
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    if unsafe { libc::fchown(slave.as_raw_fd(), owner_uid, owner_gid) } != 0
        || unsafe { libc::fchmod(slave.as_raw_fd(), 0o600) } != 0
    {
        return Err(Error::SpawnFailed);
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(slave.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        return Err(Error::SpawnFailed);
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFCHR
        || metadata.st_uid != owner_uid
        || metadata.st_gid != owner_gid
        || metadata.st_mode & 0o777 != 0o600
    {
        return Err(Error::SpawnFailed);
    }
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ as libc::c_ulong, &size) } != 0 {
        return Err(Error::SpawnFailed);
    }
    Ok((master, File::from(slave)))
}

fn cleanup_generation(
    journal: &mut journal::GenerationJournal,
    identity: &capability::Identity,
    resources: &mut SessionResources,
) -> Result<(), Error> {
    if journal.record().state() != journal::GenerationState::Closing {
        journal.mark_closing()?;
    }
    if let Some(child_control) = resources.child_control.as_ref() {
        let _ = wire::write_cancel(child_control, cleanup_io_deadline()?);
        let _ = child_control.shutdown(std::net::Shutdown::Both);
    }
    let cleanup_deadline = Instant::now() + CLEANUP_WINDOW;
    let term_deadline = Instant::now() + TERM_WINDOW;
    let mut sent_kill = false;
    loop {
        let remaining = capability::count(identity)?;
        if remaining == 0 {
            let child_reaped = reap_owned_child_after_drain(&mut resources.child)?;
            journal.mark_cleaned(remaining, child_reaped)?;
            if let Some(broker) = resources.broker.as_ref() {
                if resources.refused {
                    wire::write_spawn_outcome(
                        broker,
                        wire::SpawnOutcome::Refused,
                        cleanup_io_deadline()?,
                    )?;
                }
                wire::write_ack_cleaned(broker)?;
            }
            return Ok(());
        }
        if Instant::now() >= cleanup_deadline {
            journal.mark_unknown()?;
            return Err(Error::CleanupFailed);
        }
        let signal = if sent_kill || Instant::now() >= term_deadline {
            sent_kill = true;
            libc::SIGKILL
        } else {
            libc::SIGTERM
        };
        let _ = capability::drain(identity, signal)?;
        thread::sleep(RETRY_DELAY);
    }
}

fn hold_unknown_until_empty(
    journal: &mut journal::GenerationJournal,
    identity: &capability::Identity,
    resources: &mut SessionResources,
) {
    let _ = journal.mark_unknown();
    loop {
        if let Ok(remaining) = capability::count(identity) {
            if remaining == 0 {
                if reap_owned_child_after_drain(&mut resources.child).unwrap_or(false) {
                    return;
                }
            } else {
                let _ = capability::drain(identity, libc::SIGKILL);
            }
        } else {
            // Keep the root controller and journal alive while membership is
            // unreadable. A missing or recycled PID is never an empty proof.
            let _ = capability::current_cohorts();
        }
        thread::sleep(RETRY_DELAY);
    }
}

fn reap_owned_child_after_drain(child: &mut Option<Child>) -> Result<bool, Error> {
    let Some(direct_child) = child.as_mut() else {
        return Ok(true);
    };
    if !direct_child_exited(direct_child) {
        return Ok(false);
    }
    direct_child.wait().map_err(|_| Error::CleanupFailed)?;
    child.take();
    Ok(true)
}

fn direct_child_exited(child: &Child) -> bool {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return false;
    }
    unsafe { info.assume_init().si_pid() == child.id() as libc::pid_t }
}

fn nonblocking_read_deadline() -> Result<u64, Error> {
    wire::mach_now_ns()?
        .checked_add(1_000_000_000)
        .ok_or(Error::SpawnFailed)
}

fn cleanup_io_deadline() -> Result<u64, Error> {
    wire::mach_now_ns()?
        .checked_add(250_000_000)
        .ok_or(Error::CleanupFailed)
}

fn require_root_credentials() -> Result<(), Error> {
    if unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(Error::CleanupFailed)
    }
}
