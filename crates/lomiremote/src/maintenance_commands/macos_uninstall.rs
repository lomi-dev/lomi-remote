//! Owner-side work for administrator-managed macOS uninstall.
//!
//! The root maintenance handoff may inspect the protected public binding and
//! manage service/release state, but it must not open the Host profile or send
//! owner-local IPC. This module keeps those operations in a selected-account
//! child and revalidates the projection in that child.

#![cfg(target_os = "macos")]

use lomi_platform::{
    service_macos::{AdminHostIdentityBinding, AdminHostIdentityLookup, AdminHostMode},
    setup_context,
    unix::LocalClient,
};
use lomi_remote_protocol::{DecimalU64, HostId, OperationId, ipc::IpcProfileId, ipc::*};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

const OWNER_FLAG: &str = "--internal-maintenance-macos-owner-v1";
const MAX_OWNER_WAIT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
// Reserve Manual's 25s Host stop bound plus 15s for exact stopped-state
// inspection and the final owner re-fence.
const MANUAL_STOP_REFENCE_RESERVE: Duration = Duration::from_secs(40);
// The macOS service-control helper is bounded to 55s; retain another 15s for
// the final owner re-fence before removal.
const MANAGED_STOP_REFENCE_RESERVE: Duration = Duration::from_secs(70);
const MANUAL_START_STOP_MINIMUM: Duration = Duration::from_secs(55);
// Three full local requests after the initial status: Logout, runtime
// identity confirmation, and the first read-only LoginStatus poll.
const LOGOUT_CONFIRMATION_BUDGET: Duration = Duration::from_secs(30);

/// Root-side proof of the exact protected registration and its published
/// identity. Callers cannot construct this from command-line assertions.
pub(super) struct RootBinding {
    binding: AdminHostIdentityBinding,
    executable: PathBuf,
}

impl RootBinding {
    pub(super) fn profile(&self) -> &Path {
        self.binding.profile()
    }

    pub(super) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(super) fn account(&self) -> &str {
        self.binding.account()
    }

    pub(super) fn mode(&self) -> AdminHostMode {
        self.binding.mode()
    }

    pub(super) fn host_id(&self) -> HostId {
        self.binding.host_id()
    }

    pub(super) fn profile_id(&self) -> IpcProfileId {
        self.binding.profile_id()
    }

    pub(super) fn account_uid(&self) -> u32 {
        self.binding.account_uid()
    }

    pub(super) fn service_binding(
        &self,
    ) -> Result<lomi_platform::service_observation::ServiceBinding, super::Failure> {
        use lomi_platform::service_observation::{ServiceAccount, ServiceBinding, ServiceMode};

        let selected = setup_context::select_unix_account(self.account())
            .map_err(|_| super::Failure::identity())?;
        let account = selected.unix().ok_or(super::Failure::identity())?;
        if account.uid() != self.account_uid() || account.name() != self.account() {
            return Err(super::Failure::identity());
        }
        let mode = match self.mode() {
            AdminHostMode::Manual => ServiceMode::Manual,
            AdminHostMode::Login => ServiceMode::Login,
            AdminHostMode::Boot => ServiceMode::Boot,
        };
        Ok(ServiceBinding {
            account: ServiceAccount::Unix {
                uid: account.uid(),
                gid: account.gid(),
                name: account.name().to_owned(),
            },
            mode,
            profile: self.profile().to_path_buf(),
            executable: self.executable.clone(),
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum OwnerPhase {
    Health,
    FenceAndLogout,
    WaitAck,
    ReFenceAfterAck,
    StartManualWaitAck,
    StartManual { was_running: bool },
    StopManualForUpdate,
    PurgeAfterRecovery,
}

pub(super) struct OwnerObservation {
    pub(super) active_terminals: u64,
    pub(super) host_running: bool,
}

pub(super) enum OwnerHealth {
    Running,
    Stopped,
}

pub(super) enum OwnerRefenceOutcome {
    Complete,
    RevocationPending,
}

/// Process-independent monotonic deadline carried through sudo and selected
/// account execution, so neither handoff restarts the original budget.
#[derive(Clone, Copy)]
pub(super) struct Deadline(u128);

impl Deadline {
    pub(super) fn after(budget: Duration) -> Result<Self, super::Failure> {
        if budget.is_zero() || budget > MAX_OWNER_WAIT {
            return Err(super::Failure::uncertain());
        }
        monotonic_nanos()?
            .checked_add(budget.as_nanos())
            .map(Self)
            .ok_or_else(super::Failure::uncertain)
    }

    pub(super) fn parse_absolute(value: &str) -> Result<Self, super::Failure> {
        let deadline = value
            .parse::<u128>()
            .map_err(|_| super::Failure::invalid())?;
        deadline
            .checked_sub(monotonic_nanos()?)
            .filter(|remaining| *remaining > 0 && *remaining <= MAX_OWNER_WAIT.as_nanos())
            .ok_or_else(super::Failure::uncertain)?;
        Ok(Self(deadline))
    }

    pub(super) fn argument(self) -> OsString {
        OsString::from(self.0.to_string())
    }

    fn remaining(self) -> Option<Duration> {
        let remaining = self.0.checked_sub(monotonic_nanos().ok()?)?;
        (remaining > 0).then(|| Duration::from_nanos(u64::try_from(remaining).unwrap_or(u64::MAX)))
    }

    fn reserve_tail(self, reserve: Duration) -> Option<Self> {
        self.0
            .checked_sub(reserve.as_nanos())
            .filter(|deadline| *deadline > 0)
            .map(Self)
    }
}

/// Read the owner-visible public projection before the ordinary lifecycle
/// path attempts to inspect the owner-private Host database.
pub(super) fn lookup_owner_binding(
    profile: &Path,
    executable: &Path,
) -> Result<Option<AdminHostIdentityBinding>, super::Failure> {
    if lomi_platform::service_macos::is_administrator() {
        return Ok(None);
    }
    let profile = canonical_directory(profile)?;
    let executable = canonical_executable(executable)?;
    match lomi_platform::service_macos::lookup_admin_host_identity_binding(&profile, &executable)
        .map_err(|_| super::Failure::identity())?
    {
        AdminHostIdentityLookup::NotManaged => Ok(None),
        AdminHostIdentityLookup::Missing => Err(super::Failure::identity()),
        AdminHostIdentityLookup::Present(binding) => {
            if binding.profile() != profile {
                return Err(super::Failure::identity());
            }
            let selected =
                setup_context::select_current_account().map_err(|_| super::Failure::identity())?;
            let account = selected.unix().ok_or(super::Failure::identity())?;
            if account.uid() != binding.account_uid() || account.name() != binding.account() {
                return Err(super::Failure::identity());
            }
            Ok(Some(binding))
        }
    }
}

/// Obtain the active-terminal count through the selected owner's authenticated
/// IPC connection. A stopped Host is represented as `(0, false)`; a live but
/// unreachable owner remains an error.
pub(super) fn prepare_owner(
    profile: &Path,
    executable: &Path,
    expected: &AdminHostIdentityBinding,
) -> Result<OwnerObservation, super::Failure> {
    let binding = lookup_owner_binding(profile, executable)?.ok_or(super::Failure::identity())?;
    if &binding != expected {
        return Err(super::Failure::identity());
    }
    match crate::terminal_commands::connect_installed_macos_host(binding.profile()) {
        Ok(client) => live_owner_observation(client, &binding),
        Err(_) => match lomi_host::inspect_maintenance_profile(binding.profile()) {
            Ok(status) => offline_observation(status, &binding),
            Err(lomi_host::ProfilePurgeError::Busy) => {
                // A held OwnerLock means a live writer may exist. Only its
                // authenticated IPC identity can establish the current state.
                let client =
                    crate::terminal_commands::connect_installed_macos_host(binding.profile())
                        .map_err(|_| super::Failure::uncertain())?;
                live_owner_observation(client, &binding)
            }
            Err(lomi_host::ProfilePurgeError::IdentityMismatch) => Err(super::Failure::identity()),
            Err(_) => Err(super::Failure::uncertain()),
        },
    }
}

/// Re-read the protected root projection using the caller's account/mode only
/// as selectors. The returned binding, including IDs and account UID, is
/// derived from the verified projection.
pub(super) fn read_root_binding(
    profile: &Path,
    executable: &Path,
    account_selector: &str,
    mode_selector: AdminHostMode,
) -> Result<RootBinding, super::Failure> {
    if !lomi_platform::service_macos::is_administrator() {
        return Err(super::Failure::identity());
    }
    let profile = canonical_directory(profile)?;
    let executable = canonical_executable(executable)?;
    let binding = lomi_platform::service_macos::read_admin_host_identity_binding(
        &profile,
        &executable,
        account_selector,
        mode_selector,
    )
    .map_err(|_| super::Failure::identity())?;
    if binding.profile() != profile {
        return Err(super::Failure::identity());
    }
    let selected = setup_context::select_unix_account(binding.account())
        .map_err(|_| super::Failure::identity())?;
    let account = selected.unix().ok_or(super::Failure::identity())?;
    if account.uid() != binding.account_uid() || account.name() != binding.account() {
        return Err(super::Failure::identity());
    }
    Ok(RootBinding {
        binding,
        executable,
    })
}

/// Execute one closed owner phase under the account and identity from the
/// verified root projection. The supplied monotonic deadline is shared across
/// the sudo/selected-account process boundaries.
pub(super) fn run_owner_phase_as_selected(
    binding: &RootBinding,
    phase: OwnerPhase,
    operation_id: OperationId,
    deadline: Deadline,
) -> Result<u8, super::Failure> {
    if deadline.remaining().is_none() {
        return Err(super::Failure::uncertain());
    }
    let refreshed = lomi_platform::service_macos::read_admin_host_identity_binding(
        binding.profile(),
        binding.executable(),
        binding.account(),
        binding.mode(),
    )
    .map_err(|_| super::Failure::identity())?;
    if refreshed != binding.binding {
        return Err(super::Failure::identity());
    }
    let selected = setup_context::select_unix_account(binding.account())
        .map_err(|_| super::Failure::identity())?;
    setup_context::validate_selection(&selected).map_err(|_| super::Failure::identity())?;
    let account = selected.unix().ok_or(super::Failure::identity())?;
    if account.uid() != binding.account_uid() || account.name() != binding.account() {
        return Err(super::Failure::identity());
    }
    let phase_arg = match phase {
        OwnerPhase::Health => "health",
        OwnerPhase::FenceAndLogout => "fence-logout",
        OwnerPhase::WaitAck => "wait-ack",
        OwnerPhase::ReFenceAfterAck => "re-fence-after-ack",
        OwnerPhase::StartManualWaitAck => "start-manual-wait-ack",
        OwnerPhase::StartManual { was_running: true } => "start-manual",
        OwnerPhase::StartManual { was_running: false } => {
            return Err(super::Failure::identity());
        }
        OwnerPhase::StopManualForUpdate => "stop-manual-for-update",
        OwnerPhase::PurgeAfterRecovery => "purge-after-recovery",
    };
    let arguments = vec![
        OsString::from(OWNER_FLAG),
        OsString::from(phase_arg),
        binding.profile().as_os_str().to_owned(),
        OsString::from(String::from(binding.host_id())),
        OsString::from(String::from(binding.profile_id())),
        OsString::from(String::from(operation_id)),
        deadline.argument(),
    ];
    let status = setup_context::reexec_as_selected(&selected, binding.executable(), &arguments)
        .map_err(|_| super::Failure::uncertain())?;
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .ok_or_else(super::Failure::uncertain)
}

/// Ask the exact selected owner context for a read-only health observation.
/// The returned state is accepted only when the owner child revalidates the
/// protected binding and either authenticates the live runtime or acquires
/// the profile lock and verifies the stopped profile identity.
pub(super) fn health_as_selected(
    binding: &RootBinding,
    operation_id: OperationId,
    deadline: Deadline,
) -> Result<OwnerHealth, super::Failure> {
    match run_owner_phase_as_selected(binding, OwnerPhase::Health, operation_id, deadline)? {
        0 => Ok(OwnerHealth::Running),
        1 => Ok(OwnerHealth::Stopped),
        _ => Err(super::Failure::uncertain()),
    }
}

/// Reapply the local authorization fence after stop and ACK. The selected
/// owner context returns a positive result only after exact offline readback.
pub(super) fn refence_after_ack_as_selected(
    binding: &RootBinding,
    operation_id: OperationId,
    deadline: Deadline,
) -> Result<OwnerRefenceOutcome, super::Failure> {
    match run_owner_phase_as_selected(binding, OwnerPhase::ReFenceAfterAck, operation_id, deadline)?
    {
        0 => Ok(OwnerRefenceOutcome::Complete),
        12 => Ok(OwnerRefenceOutcome::RevocationPending),
        _ => Err(super::Failure::uncertain()),
    }
}

/// Dispatch the private selected-owner continuation before normal CLI
/// startup. The phase name is closed; no command, account, or identity is
/// accepted as authority from argv.
pub(super) fn dispatch_owner(args: &[OsString]) -> Option<u8> {
    if args.first().is_none_or(|arg| arg != OWNER_FLAG) {
        return None;
    }
    Some(run_owner_child(&args[1..]))
}

fn run_owner_child(args: &[OsString]) -> u8 {
    if args.len() != 6 || lomi_platform::service_macos::is_administrator() {
        return 2;
    }
    let Some(phase) = args[0].to_str() else {
        return 2;
    };
    let profile = match canonical_directory(Path::new(&args[1])) {
        Ok(profile) => profile,
        Err(_) => return 5,
    };
    let Ok(expected_host) = HostId::try_from(args[2].to_string_lossy().into_owned()) else {
        return 2;
    };
    let Ok(expected_profile) = IpcProfileId::try_from(args[3].to_string_lossy().into_owned())
    else {
        return 2;
    };
    let Ok(operation_id) = OperationId::try_from(args[4].to_string_lossy().into_owned()) else {
        return 2;
    };
    let deadline = match Deadline::parse_absolute(&args[5].to_string_lossy()) {
        Ok(deadline) => deadline,
        Err(error) => return error.exit,
    };
    let executable = match std::env::current_exe().and_then(|path| path.canonicalize()) {
        Ok(executable) => executable,
        Err(_) => return 5,
    };
    let binding = match lookup_owner_binding(&profile, &executable) {
        Ok(Some(binding)) => binding,
        _ => return 5,
    };
    if binding.host_id() != expected_host || binding.profile_id() != expected_profile {
        return 5;
    }

    match phase {
        "health" => owner_health(&binding, deadline),
        "fence-logout" => owner_fence_and_wait_ack(&binding, deadline),
        "wait-ack" => owner_wait_ack(&binding, deadline),
        "re-fence-after-ack" => owner_re_fence_after_ack(&binding, deadline),
        "start-manual-wait-ack" => owner_start_manual_wait_ack(&binding, deadline),
        "start-manual" => owner_start_manual(&binding, deadline),
        "stop-manual-for-update" => owner_stop_manual_for_update(&binding, deadline),
        "purge-after-recovery" => {
            if deadline.remaining().is_none() {
                return 7;
            }
            match lomi_host::purge_host_profile(
                &profile,
                binding.host_id(),
                binding.profile_id(),
                operation_id,
            ) {
                Ok(lomi_host::ProfilePurgeOutcome::Complete) => 0,
                Ok(lomi_host::ProfilePurgeOutcome::RevocationPending) => 12,
                Ok(lomi_host::ProfilePurgeOutcome::CleanupUncertain) => 13,
                Err(_) => 7,
            }
        }
        _ => 2,
    }
}

fn live_owner_observation(
    mut client: LocalClient,
    binding: &AdminHostIdentityBinding,
) -> Result<OwnerObservation, super::Failure> {
    let discovery = client.discovery().clone();
    if discovery.host_id != binding.host_id() || discovery.profile_id != binding.profile_id() {
        return Err(super::Failure::identity());
    }
    let maintenance = client
        .request(LocalCall::MaintenancePrepare(LocalOperatorIntent {
            operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
        }))
        .map_err(|_| super::Failure::uncertain())?;
    let LocalResult::MaintenanceStatus(maintenance) = maintenance
        .result
        .map_err(|_| super::Failure::uncertain())?
    else {
        return Err(super::Failure::uncertain());
    };
    if maintenance.host_id != discovery.host_id || maintenance.runtime_id != discovery.runtime_id {
        return Err(super::Failure::identity());
    }
    Ok(OwnerObservation {
        active_terminals: maintenance.active_terminals.0,
        host_running: true,
    })
}

fn offline_observation(
    observation: lomi_host::MaintenanceProfileObservation,
    binding: &AdminHostIdentityBinding,
) -> Result<OwnerObservation, super::Failure> {
    if observation.identity.host_id != binding.host_id()
        || observation.identity.profile_id != binding.profile_id()
    {
        return Err(super::Failure::identity());
    }
    Ok(OwnerObservation {
        active_terminals: 0,
        host_running: false,
    })
}

/// Read-only selected-owner health probe. Code 0 means a live runtime matched
/// the authenticated endpoint; code 1 means the owner lock was acquired and
/// the stopped profile matched the protected Host/Profile IDs. An unreachable
/// but busy profile is uncertain and never treated as stopped.
fn owner_health(binding: &AdminHostIdentityBinding, deadline: Deadline) -> u8 {
    if deadline
        .remaining()
        .is_none_or(|remaining| remaining < lomi_platform::unix::HANDSHAKE_TIMEOUT)
    {
        return 7;
    }
    match crate::terminal_commands::connect_installed_macos_host(binding.profile()) {
        Ok(mut client) => {
            let discovery = client.discovery().clone();
            if discovery.host_id != binding.host_id()
                || discovery.profile_id != binding.profile_id()
            {
                return 5;
            }
            let response =
                match owner_request_before_deadline(&mut client, LocalCall::Status {}, deadline) {
                    Ok(response) => response,
                    Err(_) => return 7,
                };
            let LocalResult::Status(status) = (match response.result {
                Ok(result) => result,
                Err(_) => return 7,
            }) else {
                return 7;
            };
            if status.host_id != discovery.host_id || status.runtime_id != discovery.runtime_id {
                return 5;
            }
            if deadline.remaining().is_none() {
                return 7;
            }
            0
        }
        Err(_) => match lomi_host::inspect_maintenance_profile(binding.profile()) {
            Ok(status) => {
                if status.identity.host_id != binding.host_id()
                    || status.identity.profile_id != binding.profile_id()
                {
                    return 5;
                }
                if deadline.remaining().is_none() { 7 } else { 1 }
            }
            Err(lomi_host::ProfilePurgeError::Busy) => 7,
            Err(lomi_host::ProfilePurgeError::IdentityMismatch) => 5,
            Err(_) => 7,
        },
    }
}

fn owner_request_before_deadline(
    client: &mut LocalClient,
    call: LocalCall,
    deadline: Deadline,
) -> Result<LocalResponse, ()> {
    if deadline
        .remaining()
        .is_none_or(|remaining| remaining < lomi_platform::unix::REQUEST_TIMEOUT)
    {
        return Err(());
    }
    client.request(call).map_err(|_| ())
}

fn owner_ack_deadline(
    binding: &AdminHostIdentityBinding,
    deadline: Deadline,
    minimum_poll_budget: Duration,
) -> Option<Deadline> {
    let reserve = if binding.mode() == AdminHostMode::Manual {
        MANUAL_STOP_REFENCE_RESERVE
    } else {
        MANAGED_STOP_REFENCE_RESERVE
    };
    let ack_deadline = deadline.reserve_tail(reserve)?;
    ack_deadline
        .remaining()
        .filter(|remaining| *remaining >= minimum_poll_budget)
        .map(|_| ack_deadline)
}

fn owner_fence_and_wait_ack(binding: &AdminHostIdentityBinding, deadline: Deadline) -> u8 {
    if deadline.remaining().is_none() {
        return 7;
    }
    match crate::terminal_commands::connect_installed_macos_host(binding.profile()) {
        Ok(client) => owner_live_logout_or_wait(binding, client, deadline),
        Err(_) => {
            if deadline.remaining().is_none() {
                return 7;
            }
            match lomi_host::inspect_maintenance_profile(binding.profile()) {
                Ok(before) => owner_offline_fence(binding, before, deadline),
                Err(lomi_host::ProfilePurgeError::Busy) => {
                    // Busy OwnerLock means a live owner may exist. It can proceed
                    // only after the exact authenticated IPC endpoint is reached.
                    let client = match crate::terminal_commands::connect_installed_macos_host(
                        binding.profile(),
                    ) {
                        Ok(client) => client,
                        Err(_) => return 7,
                    };
                    owner_live_logout_or_wait(binding, client, deadline)
                }
                Err(lomi_host::ProfilePurgeError::IdentityMismatch) => 5,
                Err(_) => 7,
            }
        }
    }
}

fn owner_offline_fence(
    binding: &AdminHostIdentityBinding,
    before: lomi_host::MaintenanceProfileObservation,
    deadline: Deadline,
) -> u8 {
    if deadline.remaining().is_none() {
        return 7;
    }
    if before.identity.host_id != binding.host_id()
        || before.identity.profile_id != binding.profile_id()
    {
        return 5;
    }
    let after = match lomi_host::fence_maintenance_profile(
        binding.profile(),
        binding.host_id(),
        binding.profile_id(),
    ) {
        Ok(after) => after,
        Err(lomi_host::ProfilePurgeError::Busy) => {
            // The owner may have started while fencing. Do not inspect rows
            // after Busy; retry only through a same-identity live connection.
            let client =
                match crate::terminal_commands::connect_installed_macos_host(binding.profile()) {
                    Ok(client) => client,
                    Err(_) => return 7,
                };
            return owner_live_logout_or_wait(binding, client, deadline);
        }
        Err(lomi_host::ProfilePurgeError::IdentityMismatch) => return 5,
        Err(_) => return 7,
    };
    if after.identity.host_id != binding.host_id()
        || after.identity.profile_id != binding.profile_id()
        || !after.remote_locked
        || after.authorization_generation < before.authorization_generation
        || after.authorization_generation > before.authorization_generation.saturating_add(1)
    {
        return 5;
    }
    if after.pending_cloud_revoke {
        if deadline.remaining().is_none() {
            return 12;
        }
        // The caller starts the Host, then uses WaitAck. Sending Logout again
        // would advance the generation a second time.
        14
    } else {
        0
    }
}

/// Re-fence after an ACK and a positive stop. `inspect_maintenance_profile`
/// must acquire the profile lock, so a live or unreachable runtime cannot be
/// mistaken for a stopped Host. A changed generation is accepted only when
/// the typed fence API made the single expected transition.
fn owner_re_fence_after_ack(binding: &AdminHostIdentityBinding, deadline: Deadline) -> u8 {
    if deadline.remaining().is_none() {
        return 7;
    }
    let before = match lomi_host::inspect_maintenance_profile(binding.profile()) {
        Ok(before) => before,
        Err(lomi_host::ProfilePurgeError::IdentityMismatch) => return 5,
        Err(_) => return 7,
    };
    if before.identity.host_id != binding.host_id()
        || before.identity.profile_id != binding.profile_id()
    {
        return 5;
    }
    let after = match lomi_host::fence_maintenance_profile(
        binding.profile(),
        binding.host_id(),
        binding.profile_id(),
    ) {
        Ok(after) => after,
        Err(lomi_host::ProfilePurgeError::IdentityMismatch) => return 5,
        // Busy means the Host was not positively stopped across this fence.
        Err(_) => return 7,
    };
    if after.identity.host_id != binding.host_id()
        || after.identity.profile_id != binding.profile_id()
        || !after.remote_locked
        || after.authorization_generation < before.authorization_generation
        || after.authorization_generation > before.authorization_generation.saturating_add(1)
    {
        return 5;
    }
    if after.pending_cloud_revoke {
        12
    } else if deadline.remaining().is_some() {
        0
    } else {
        7
    }
}

fn owner_live_logout_or_wait(
    binding: &AdminHostIdentityBinding,
    mut client: LocalClient,
    deadline: Deadline,
) -> u8 {
    if deadline.remaining().is_none() {
        return 7;
    }
    let discovery = client.discovery().clone();
    if discovery.host_id != binding.host_id() || discovery.profile_id != binding.profile_id() {
        return 5;
    }
    let prepared = match owner_request_before_deadline(
        &mut client,
        LocalCall::MaintenancePrepare(LocalOperatorIntent {
            operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
        }),
        deadline,
    ) {
        Ok(response) => response,
        Err(_) => return 7,
    };
    let LocalResult::MaintenanceStatus(prepared) = (match prepared.result {
        Ok(result) => result,
        Err(_) => return 7,
    }) else {
        return 7;
    };
    if prepared.host_id != discovery.host_id || prepared.runtime_id != discovery.runtime_id {
        return 5;
    }
    if deadline.remaining().is_none() {
        return 7;
    }

    let initial =
        match owner_request_before_deadline(&mut client, LocalCall::LoginStatus {}, deadline) {
            Ok(response) => response,
            Err(_) => return 7,
        };
    let LocalResult::LoginStatus(initial) = (match initial.result {
        Ok(result) => result,
        Err(_) => return 7,
    }) else {
        return 7;
    };
    if deadline.remaining().is_none() {
        return 7;
    }
    if initial.pending_cloud_revoke && !initial.locked {
        return 5;
    }
    let ack_deadline = match owner_ack_deadline(binding, deadline, LOGOUT_CONFIRMATION_BUDGET) {
        Some(deadline) => deadline,
        None => return 7,
    };
    let Some(expected_generation) = initial.generation.0.checked_add(1) else {
        return 7;
    };
    // Submit exactly one Logout for this invocation, including when this
    // profile was already locked or carried a pending revoke. A failed or
    // lost reply is uncertain and this mutating request is never replayed.
    let logout = match owner_request_before_deadline(
        &mut client,
        LocalCall::Logout(LocalOperatorIntent {
            operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
        }),
        ack_deadline,
    ) {
        Ok(response) => response,
        Err(_) => return 7,
    };
    let LocalResult::LoginStatus(logout) = (match logout.result {
        Ok(result) => result,
        Err(_) => return 7,
    }) else {
        return 7;
    };
    if logout.generation.0 != expected_generation || !logout.locked {
        return 7;
    }
    if logout.pending_cloud_revoke && logout.phase != LocalAuthPhase::PendingRevoke {
        return 7;
    }
    // The LoginStatus payload carries no Host/runtime identity. Confirm the
    // same authenticated LocalClient runtime immediately after the commit.
    let identity =
        match owner_request_before_deadline(&mut client, LocalCall::Status {}, ack_deadline) {
            Ok(response) => response,
            Err(_) => return 7,
        };
    let LocalResult::Status(identity) = (match identity.result {
        Ok(result) => result,
        Err(_) => return 7,
    }) else {
        return 7;
    };
    if identity.host_id != discovery.host_id || identity.runtime_id != discovery.runtime_id {
        return 5;
    }
    if !logout.pending_cloud_revoke {
        return finish_owner_ack(binding, deadline);
    }
    let result = owner_wait_ack_loop(&mut client, logout.generation, ack_deadline, false);
    if result != 0 {
        if binding.mode() == AdminHostMode::Manual {
            return owner_manual_pending_timeout(binding, logout.generation, deadline);
        }
        return result;
    }
    finish_owner_ack(binding, deadline)
}

fn owner_wait_ack(binding: &AdminHostIdentityBinding, deadline: Deadline) -> u8 {
    let ack_deadline =
        match owner_ack_deadline(binding, deadline, lomi_platform::unix::REQUEST_TIMEOUT) {
            Some(deadline) => deadline,
            None => return 7,
        };
    let mut client = match crate::terminal_commands::connect_installed_macos_host(binding.profile())
    {
        Ok(client) => client,
        Err(_) => return 7,
    };
    let discovery = client.discovery().clone();
    if discovery.host_id != binding.host_id() || discovery.profile_id != binding.profile_id() {
        return 5;
    }
    let initial =
        match owner_request_before_deadline(&mut client, LocalCall::LoginStatus {}, ack_deadline) {
            Ok(response) => response,
            Err(_) => return 7,
        };
    let LocalResult::LoginStatus(initial) = (match initial.result {
        Ok(result) => result,
        Err(_) => return 7,
    }) else {
        return 7;
    };
    if !initial.locked {
        return 5;
    }
    if !initial.pending_cloud_revoke {
        return finish_owner_ack(binding, deadline);
    }
    if ack_deadline.remaining().is_none() {
        return if binding.mode() == AdminHostMode::Manual {
            owner_manual_pending_timeout(binding, initial.generation, deadline)
        } else {
            12
        };
    }
    let generation = initial.generation;
    let result = owner_wait_ack_loop(&mut client, generation, ack_deadline, true);
    if result != 0 {
        if binding.mode() == AdminHostMode::Manual {
            return owner_manual_pending_timeout(binding, generation, deadline);
        }
        return result;
    }
    finish_owner_ack(binding, deadline)
}

fn finish_owner_ack(binding: &AdminHostIdentityBinding, deadline: Deadline) -> u8 {
    if binding.mode() == AdminHostMode::Manual {
        owner_stop_manual_for_update(binding, deadline)
    } else if deadline.remaining().is_some() {
        // Login and Boot runtimes are stopped by the root's exact service
        // binding after this selected-owner ACK phase.
        0
    } else {
        7
    }
}

fn owner_manual_pending_timeout(
    binding: &AdminHostIdentityBinding,
    generation: DecimalU64,
    deadline: Deadline,
) -> u8 {
    if binding.mode() != AdminHostMode::Manual {
        return 5;
    }
    let stop = owner_stop_manual_for_update(binding, deadline);
    if stop != 0 {
        return stop;
    }
    let stopped = match lomi_host::inspect_maintenance_profile(binding.profile()) {
        Ok(stopped) => stopped,
        Err(lomi_host::ProfilePurgeError::IdentityMismatch) => return 5,
        Err(_) => return 7,
    };
    if stopped.identity.host_id != binding.host_id()
        || stopped.identity.profile_id != binding.profile_id()
    {
        return 5;
    }
    if stopped.authorization_generation != generation.0 || !stopped.remote_locked {
        return 7;
    }
    if stopped.pending_cloud_revoke {
        12
    } else if deadline.remaining().is_some() {
        0
    } else {
        7
    }
}

fn owner_start_manual_wait_ack(binding: &AdminHostIdentityBinding, deadline: Deadline) -> u8 {
    if binding.mode() != AdminHostMode::Manual {
        return 5;
    }
    if deadline
        .remaining()
        .is_none_or(|remaining| remaining < MANUAL_START_STOP_MINIMUM)
    {
        return 7;
    }
    let fenced = match lomi_host::inspect_maintenance_profile(binding.profile()) {
        Ok(status) => status,
        Err(lomi_host::ProfilePurgeError::IdentityMismatch) => return 5,
        Err(_) => return 7,
    };
    if fenced.identity.host_id != binding.host_id()
        || fenced.identity.profile_id != binding.profile_id()
        || !fenced.remote_locked
        || !fenced.pending_cloud_revoke
    {
        return 5;
    }
    let generation = DecimalU64(fenced.authorization_generation);
    let identity = lomi_host::Identity {
        host_id: binding.host_id(),
        profile_id: binding.profile_id(),
    };
    let executable = match current_executable_for_binding(binding) {
        Ok(executable) => executable,
        Err(_) => return 5,
    };
    let start = lomi_host::start_identity_bound(&executable, binding.profile(), &identity);
    let mut poll_attempted = false;
    if start.is_ok() {
        if let Some(ack_deadline) = deadline.reserve_tail(MANUAL_STOP_REFENCE_RESERVE) {
            if ack_deadline.remaining().is_some() {
                if let Ok(mut client) =
                    crate::terminal_commands::connect_installed_macos_host(binding.profile())
                {
                    let discovery = client.discovery().clone();
                    if discovery.host_id == binding.host_id()
                        && discovery.profile_id == binding.profile_id()
                    {
                        poll_attempted = true;
                        // Regardless of ACK, timeout, or transport failure,
                        // stop the temporary runtime before checking final Store state.
                        let _ = owner_wait_ack_loop(&mut client, generation, ack_deadline, false);
                    }
                }
            }
        }
    }
    let stop = owner_stop_manual_for_ack(binding, deadline);
    if stop != 0 {
        // Do not let the root continue recovery/uninstall unless the exact
        // temporary Host has been stopped and joined.
        return if matches!(stop, 12 | 7) { 7 } else { stop };
    }
    match lomi_host::inspect_maintenance_profile(binding.profile()) {
        Ok(stopped) => {
            if stopped.identity.host_id != binding.host_id()
                || stopped.identity.profile_id != binding.profile_id()
                || stopped.authorization_generation != fenced.authorization_generation
                || !stopped.remote_locked
            {
                return 5;
            }
            if stopped.pending_cloud_revoke {
                12
            } else if deadline.remaining().is_none() {
                7
            } else if !poll_attempted || start.is_err() {
                7
            } else {
                0
            }
        }
        Err(lomi_host::ProfilePurgeError::Busy) => 7,
        Err(lomi_host::ProfilePurgeError::IdentityMismatch) => 5,
        Err(_) => 7,
    }
}

fn owner_stop_manual_for_ack(binding: &AdminHostIdentityBinding, deadline: Deadline) -> u8 {
    if binding.mode() != AdminHostMode::Manual {
        return 5;
    }
    if deadline
        .remaining()
        .is_none_or(|remaining| remaining < Duration::from_secs(25))
    {
        return 7;
    }
    match lomi_host::inspect_maintenance_profile(binding.profile()) {
        Ok(status) => {
            if status.identity.host_id != binding.host_id()
                || status.identity.profile_id != binding.profile_id()
                || !status.remote_locked
            {
                return 5;
            }
            return if deadline.remaining().is_some() { 0 } else { 7 };
        }
        Err(lomi_host::ProfilePurgeError::Busy) => {
            let client =
                match crate::terminal_commands::connect_installed_macos_host(binding.profile()) {
                    Ok(client) => client,
                    Err(_) => return 7,
                };
            if client.discovery().host_id != binding.host_id()
                || client.discovery().profile_id != binding.profile_id()
            {
                return 5;
            }
        }
        Err(lomi_host::ProfilePurgeError::IdentityMismatch) => return 5,
        Err(_) => return 7,
    }
    if deadline
        .remaining()
        .is_none_or(|remaining| remaining < Duration::from_secs(25))
    {
        return 7;
    }
    if lomi_host::stop_bound(binding.profile(), binding.host_id()).is_err() {
        return 7;
    }
    if deadline.remaining().is_none() {
        return 7;
    }
    match lomi_host::inspect_maintenance_profile(binding.profile()) {
        Ok(status)
            if status.identity.host_id == binding.host_id()
                && status.identity.profile_id == binding.profile_id()
                && status.remote_locked =>
        {
            if deadline.remaining().is_some() {
                0
            } else {
                7
            }
        }
        Ok(_) | Err(lomi_host::ProfilePurgeError::IdentityMismatch) => 5,
        Err(_) => 7,
    }
}

fn owner_start_manual(binding: &AdminHostIdentityBinding, deadline: Deadline) -> u8 {
    if binding.mode() != AdminHostMode::Manual {
        return 5;
    }
    if deadline.remaining().is_none() {
        return 7;
    }
    let identity = lomi_host::Identity {
        host_id: binding.host_id(),
        profile_id: binding.profile_id(),
    };
    let executable = match current_executable_for_binding(binding) {
        Ok(executable) => executable,
        Err(_) => return 5,
    };
    if lomi_host::start_identity_bound(&executable, binding.profile(), &identity).is_err() {
        return 7;
    }
    if deadline.remaining().is_none() {
        return 7;
    }
    let client = match crate::terminal_commands::connect_installed_macos_host(binding.profile()) {
        Ok(client) => client,
        Err(_) => return 7,
    };
    if client.discovery().host_id != binding.host_id()
        || client.discovery().profile_id != binding.profile_id()
    {
        return 5;
    }
    if deadline.remaining().is_none() {
        return 7;
    }
    0
}

fn owner_wait_ack_loop(
    client: &mut LocalClient,
    generation: DecimalU64,
    deadline: Deadline,
    mut has_status_proof: bool,
) -> u8 {
    loop {
        let Some(remaining) = deadline.remaining() else {
            return if has_status_proof { 12 } else { 7 };
        };
        if remaining < lomi_platform::unix::REQUEST_TIMEOUT {
            // Only a completed same-generation LoginStatus permits the
            // pending result. A Logout reply alone is not an ACK poll.
            return if has_status_proof { 12 } else { 7 };
        }
        let status =
            match owner_request_before_deadline(client, LocalCall::LoginStatus {}, deadline) {
                Ok(response) => response,
                Err(_) => return 7,
            };
        let LocalResult::LoginStatus(status) = (match status.result {
            Ok(result) => result,
            Err(_) => return 7,
        }) else {
            return 7;
        };
        if status.generation != generation || !status.locked {
            return 5;
        }
        if !status.pending_cloud_revoke {
            return 0;
        }
        has_status_proof = true;
        if deadline.remaining().is_none() {
            return 12;
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn owner_stop_manual_for_update(binding: &AdminHostIdentityBinding, deadline: Deadline) -> u8 {
    if binding.mode() != AdminHostMode::Manual {
        return 5;
    }
    if deadline.remaining().is_none() {
        return 7;
    }
    match lomi_host::inspect_maintenance_profile(binding.profile()) {
        Ok(status) => {
            if status.identity.host_id != binding.host_id()
                || status.identity.profile_id != binding.profile_id()
            {
                return 5;
            }
            return if deadline.remaining().is_some() { 0 } else { 7 };
        }
        Err(lomi_host::ProfilePurgeError::Busy) => {
            let client =
                match crate::terminal_commands::connect_installed_macos_host(binding.profile()) {
                    Ok(client) => client,
                    Err(_) => return 7,
                };
            if client.discovery().host_id != binding.host_id()
                || client.discovery().profile_id != binding.profile_id()
            {
                return 5;
            }
        }
        Err(lomi_host::ProfilePurgeError::IdentityMismatch) => return 5,
        Err(_) => return 7,
    }
    if deadline
        .remaining()
        .is_none_or(|remaining| remaining < Duration::from_secs(25))
    {
        return 7;
    }
    if lomi_host::stop_bound(binding.profile(), binding.host_id()).is_err() {
        return 7;
    }
    if deadline.remaining().is_none() {
        return 7;
    }
    match lomi_host::inspect_maintenance_profile(binding.profile()) {
        Ok(status)
            if status.identity.host_id == binding.host_id()
                && status.identity.profile_id == binding.profile_id() =>
        {
            if deadline.remaining().is_some() { 0 } else { 7 }
        }
        Ok(_) | Err(lomi_host::ProfilePurgeError::IdentityMismatch) => 5,
        Err(_) => 7,
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf, super::Failure> {
    let path = path
        .canonicalize()
        .map_err(|_| super::Failure::identity())?;
    if !path.is_dir() || path == Path::new("/") {
        return Err(super::Failure::identity());
    }
    Ok(path)
}

fn canonical_executable(path: &Path) -> Result<PathBuf, super::Failure> {
    let executable = path
        .canonicalize()
        .map_err(|_| super::Failure::identity())?;
    if !executable.is_file() {
        return Err(super::Failure::identity());
    }
    Ok(executable)
}

fn current_executable_for_binding(
    expected: &AdminHostIdentityBinding,
) -> Result<PathBuf, super::Failure> {
    let executable = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|_| super::Failure::identity())?;
    if lookup_owner_binding(expected.profile(), &executable)?.as_ref() != Some(expected) {
        return Err(super::Failure::identity());
    }
    Ok(executable)
}

fn monotonic_nanos() -> Result<u128, super::Failure> {
    lomi_platform::unix::monotonic_nanos()
        .map(u128::from)
        .map_err(|_| super::Failure::uncertain())
}
