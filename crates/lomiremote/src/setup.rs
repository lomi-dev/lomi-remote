//! Resumable, local-first first-run setup.
//!
//! Native entrypoints provide account selection, Host startup, typed service
//! management, prompts, and publication observation. This module owns ordering,
//! the private setup journal, recovery decisions, and the rule that sharing is
//! requested only after the selected Host is authenticated and service-ready.
use lomi_platform::setup_journal::{Error as JournalError, SetupJournalStore};
use lomi_remote_protocol::{DecimalU64, HostId, OperationId, WorkspaceId};
use lomi_remote_protocol::{
    ipc::{
        LocalAuthConfiguration, LocalAuthPhase, LocalAuthProvider, LocalCall, LocalHostName,
        LocalHostNameSet, LocalLoginPresentation, LocalLoginStart, LocalLoginStatus,
        LocalProcessArgument, LocalProjectName, LocalResult, LocalRootPath, LocalSharing,
        LocalShellEnvironment, LocalShellProfileRegister, LocalStartMode, LocalStatus,
        LocalWorkspaceConsentAuthorized, LocalWorkspaceImport, LocalWorkspaceImportReceipt,
        LocalWorkspaceRead, WorkspaceBinding, WorkspaceBindingsRead,
    },
    rpc::{BoundedList, Confirmed},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

use lomi_platform::setup_journal::JOURNAL_VERSION;
const PATH_LIMIT: usize = 4096;
const NAME_LIMIT: usize = 255;

/// Exact selected native service binding. Callers resolve the account and
/// canonical profile before opening the journal or touching the Host profile.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceBinding {
    pub mode: LocalStartMode,
    pub account_name: String,
    pub account: SetupAccount,
    pub profile_path: PathBuf,
    pub executable_path: PathBuf,
}

/// Native account identity in the process-selected user context. Numeric Unix
/// IDs are not used to represent a Windows token/SID.
#[derive(Clone, PartialEq, Eq)]
pub enum SetupAccount {
    Unix { uid: u32, gid: u32 },
    Windows { sid: String },
}

/// Shell values are passed to the local Host only after the service account is
/// selected. They are never copied into the setup journal or error messages.
pub struct SetupShellChoice {
    pub name: LocalProjectName,
    pub executable: LocalRootPath,
    pub args: BoundedList<LocalProcessArgument, 32>,
    pub environment: BoundedList<LocalShellEnvironment, 8>,
}

pub struct SetupChoices {
    /// Optional explicit local Host label. When omitted, setup keeps a
    /// journaled choice or uses the trusted native hostname suggestion.
    pub host_name: Option<LocalHostName>,
    /// Present only when the Host is not configured. Contains public endpoint
    /// pins and a storage choice, never access or refresh credentials.
    pub auth_configuration: Option<LocalAuthConfiguration>,
    pub workspace_name: LocalProjectName,
    /// Empty means the UI should use the current working directory. It must not
    /// substitute the user's home directory.
    pub workspace_root: PathBuf,
    /// Creation is allowed only after an explicit user choice.
    pub create_missing_workspace: bool,
    pub shell: SetupShellChoice,
    /// Explicit final sharing policy. `false` requests local-only setup subject
    /// to any sharing policy already attached to the canonical workspace.
    pub share_remote: bool,
    /// Required if an earlier Share request had an uncertain result and a fresh
    /// Host read still reports the workspace as unshared.
    pub renew_share_consent: bool,
    /// Explicit per-run consent to disable sharing that was already enabled on
    /// the canonical workspace returned by import.
    pub disable_existing_share: bool,
}

/// Caller-supplied choices and the already-resolved nonroot service context.
pub struct SetupOptions {
    pub binding: ServiceBinding,
    pub choices: Option<SetupChoices>,
    pub non_interactive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupStage {
    Draft,
    Enrolled,
    LocalConfigured,
    ServiceReady,
    SharePending,
    Shared,
    LocalOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupProblem {
    HostUnavailable,
    HostNameChangeUnknown,
    HostIdentityChanged,
    ServiceBindingChanged,
    ServiceInstallFailed,
    ServiceNotReady,
    AuthorizationConfigurationRequired,
    AuthorizationPending,
    AuthorizationContextChanged,
    AuthorizationUnavailable,
    WorkspaceUnavailable,
    ShellUnavailable,
    SharingConflict,
    ShareOutcomeUnknown,
    UnshareOutcomeUnknown,
    ShareConsentRenewalRequired,
    PublicationPending,
    PublicationUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupSharing {
    Shared,
    LocalOnly,
}

#[derive(Clone, PartialEq, Eq)]
pub enum SetupOutcome {
    /// No Host setup was changed; the entrypoint should show the existing
    /// dashboard instead of starting a second first-run flow.
    ExistingConfiguration { host_id: Option<HostId> },
    Complete {
        host_id: HostId,
        workspace_id: WorkspaceId,
        sharing: SetupSharing,
    },
    PendingLogin {
        host_id: HostId,
        operation_id: Option<OperationId>,
    },
    /// A visible, durable, resumable state. This is never reported as success.
    Incomplete {
        stage: SetupStage,
        problem: SetupProblem,
        host_id: Option<HostId>,
        workspace_id: Option<WorkspaceId>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupError {
    InvalidOptions,
    ChoicesRequired,
    ProfileRejected,
    JournalCorrupt,
    JournalUnavailable,
    BindingMismatch,
    ChoiceMismatch,
    InteractionUnavailable,
    HostUnavailable,
    ServiceUnavailable,
    ProtocolMismatch,
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOptions => "SETUP_INVALID_OPTIONS",
            Self::ChoicesRequired => "SETUP_CHOICES_REQUIRED",
            Self::ProfileRejected => "SETUP_PROFILE_REJECTED",
            Self::JournalCorrupt => "SETUP_JOURNAL_INVALID",
            Self::JournalUnavailable => "SETUP_JOURNAL_UNAVAILABLE",
            Self::BindingMismatch => "SETUP_BINDING_MISMATCH",
            Self::ChoiceMismatch => "SETUP_CHOICE_MISMATCH",
            Self::InteractionUnavailable => "SETUP_INTERACTION_UNAVAILABLE",
            Self::HostUnavailable => "SETUP_HOST_UNAVAILABLE",
            Self::ServiceUnavailable => "SETUP_SERVICE_UNAVAILABLE",
            Self::ProtocolMismatch => "SETUP_LOCAL_PROTOCOL_MISMATCH",
        })
    }
}

impl std::error::Error for SetupError {}

pub struct HostPreflight {
    /// True when a Host/workspace/auth/service configuration already exists.
    /// Existing installations go to the dashboard unless a setup journal is
    /// present and resumable.
    pub existing_configuration: bool,
    /// Host identity read from the selected persistent profile, independent of
    /// whether its service is currently running. Never source this from the
    /// setup journal.
    pub existing_host_id: Option<HostId>,
    /// A native existing-only owner lock proved a nonempty crash WAL. The
    /// read-only preflight cannot safely adopt a possibly stale SQLite view;
    /// bound startup must check the expected identity on its recovery connection.
    pub identity_pending_recovery: bool,
    /// Trusted native OS hostname, or the persisted value when the Host is
    /// already running. It is only a local display suggestion.
    pub suggested_host_name: LocalHostName,
    pub current_directory: PathBuf,
    pub release_version: String,
    pub network: SetupNetworkState,
    pub interactive_terminal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupNetworkState {
    Available,
    Offline,
    Unknown,
}

pub struct HostObservation {
    pub status: LocalStatus,
    pub profile_path: PathBuf,
    pub account: SetupAccount,
}

pub struct ShellCandidate {
    pub label: String,
    pub executable: PathBuf,
}

pub struct SetupProgress {
    pub setup_id: String,
    pub stage: SetupStage,
    pub account_name: String,
    pub account: SetupAccount,
    pub mode: LocalStartMode,
    pub host_id: Option<String>,
    pub host_name: Option<String>,
    pub auth_generation: Option<u64>,
    pub workspace_import_id: String,
    pub workspace_id: Option<String>,
    pub workspace_name: String,
    pub workspace_root: String,
    pub shell_profile_id: Option<String>,
    pub share_remote: bool,
    pub share_attempted: bool,
}

pub struct SetupReview {
    pub release_version: String,
    pub host_id: Option<HostId>,
    pub host_name: LocalHostName,
    pub mode: LocalStartMode,
    pub account_name: String,
    pub account: SetupAccount,
    pub profile_path: PathBuf,
    pub workspace_name: LocalProjectName,
    pub workspace_root: PathBuf,
    pub create_missing_workspace: bool,
    pub git_repository_detected: bool,
    pub shell_name: LocalProjectName,
    pub shell_executable: LocalRootPath,
    pub shell_args: Vec<LocalProcessArgument>,
    pub environment_names: Vec<String>,
    pub storage_provider: Option<&'static str>,
    pub share_remote: bool,
    pub disable_existing_share: bool,
}

/// The setup TUI implements these prompts. Login codes are requested only when
/// `reveal_login_presentation` returns true, so codes remain transient.
pub trait SetupInteraction {
    /// Interactive clients may wait briefly for host-owned device login to
    /// advance. Returning false leaves a durable pending state without retrying
    /// a credential exchange or resending a one-time operation.
    fn wait_for_login_update(&mut self) -> Result<bool, SetupError> {
        Ok(false)
    }
    fn wait_for_publication_update(&mut self) -> Result<bool, SetupError> {
        Ok(false)
    }
    fn collect_choices(
        &mut self,
        binding: &ServiceBinding,
        preflight: &HostPreflight,
        progress: Option<&SetupProgress>,
        shells: &[ShellCandidate],
    ) -> Result<SetupChoices, SetupError>;

    fn confirm_review(&mut self, review: &SetupReview) -> Result<bool, SetupError>;

    fn confirm_authorization_context_change(&mut self) -> Result<bool, SetupError>;

    fn reveal_login_presentation(&mut self) -> bool;

    fn show_login_presentation(&mut self, presentation: &LocalLoginPresentation);

    fn confirm_renewed_share(
        &mut self,
        workspace_name: &LocalProjectName,
        workspace_id: WorkspaceId,
    ) -> Result<bool, SetupError>;
}

/// Host operations must use the selected nonroot account and exact profile.
/// `preflight` and `observe` are read-only; `start_local` starts only the local
/// Host and must not enable autostart or consent.
pub trait SetupHost {
    fn preflight(&mut self, binding: &ServiceBinding) -> Result<HostPreflight, SetupError>;

    /// Ensure the selected local Host is running and IPC-ready under this
    /// account. This must be idempotent; it never enables autostart.
    fn start_local(
        &mut self,
        binding: &ServiceBinding,
        expected_host_id: Option<HostId>,
    ) -> Result<(), SetupError>;

    /// Return status from the freshly authenticated local IPC peer for exactly
    /// this profile and selected OS account.
    fn observe(&mut self, binding: &ServiceBinding) -> Result<HostObservation, SetupError>;

    fn request(&mut self, call: LocalCall) -> Result<LocalResult, SetupCallError>;

    /// Root integration supplies fresh consent plus current publication/outbox
    /// observation from HostStore. It must be bound to the actual Host and
    /// workspace, never to setup journal contents alone.
    fn publication_status(
        &mut self,
        workspace_id: WorkspaceId,
    ) -> Result<WorkspacePublication, SetupError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupCallError {
    Rejected,
    OutcomeUnknown,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    Pending,
    Acknowledged,
    Unknown,
}

pub struct WorkspacePublication {
    pub host_id: HostId,
    pub workspace_id: WorkspaceId,
    pub auth_generation: DecimalU64,
    pub consent: LocalSharing,
    /// `Acknowledged` means the Cloud has acknowledged the latest current
    /// workspace state, including a removal after local unshare.
    pub publication: PublicationState,
}

pub struct ServiceObservation {
    /// The native adapter sets this only after comparing the actual manager
    /// registration's account, UID/GID, mode, profile, and executable.
    pub binding_matches: bool,
    pub registration_present: bool,
    pub autostart_enabled: bool,
    pub active: bool,
    pub ipc_ready: bool,
}

/// Typed OS service boundary; implementations must never parse formatted CLI
/// status text or treat an unknown manager result as ready.
pub trait SetupServiceControl {
    /// Check that the process already runs as the native account in `binding`
    /// and validate its profile/executable. This must not elevate, impersonate,
    /// or open another account's profile. It runs before journal/Host access.
    fn validate_binding(&mut self, binding: &ServiceBinding) -> Result<(), SetupError>;

    fn detect_shells(
        &mut self,
        binding: &ServiceBinding,
    ) -> Result<Vec<ShellCandidate>, SetupError>;

    fn detect_git_repository(&mut self, workspace_root: &Path) -> Result<bool, SetupError>;

    fn verify_workspace_access(
        &mut self,
        binding: &ServiceBinding,
        workspace_root: &Path,
    ) -> Result<(), SetupError>;

    fn verify_shell_profile(
        &mut self,
        binding: &ServiceBinding,
        workspace_root: &Path,
        profile: &LocalShellProfileRegister,
    ) -> Result<(), SetupError>;

    fn inspect(&mut self, binding: &ServiceBinding) -> Result<ServiceObservation, SetupError>;

    fn install(&mut self, binding: &ServiceBinding) -> Result<(), SetupError>;

    fn start(&mut self, binding: &ServiceBinding) -> Result<(), SetupError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistedStage {
    Draft,
    Enrolled,
    LocalConfigured,
    ServiceReady,
    SharePending,
    Shared,
    LocalOnly,
}

impl From<PersistedStage> for SetupStage {
    fn from(value: PersistedStage) -> Self {
        match value {
            PersistedStage::Draft => Self::Draft,
            PersistedStage::Enrolled => Self::Enrolled,
            PersistedStage::LocalConfigured => Self::LocalConfigured,
            PersistedStage::ServiceReady => Self::ServiceReady,
            PersistedStage::SharePending => Self::SharePending,
            PersistedStage::Shared => Self::Shared,
            PersistedStage::LocalOnly => Self::LocalOnly,
        }
    }
}

struct Journal {
    revision: u64,
    setup_id: String,
    stage: PersistedStage,
    binding: ServiceBinding,
    host_id: Option<String>,
    host_name: Option<String>,
    host_name_set_attempted: bool,
    host_name_expected: Option<String>,
    auth_generation: Option<u64>,
    login_operation_id: Option<String>,
    storage_provider: Option<String>,
    workspace_import_id: String,
    workspace_id: Option<String>,
    workspace_name: String,
    workspace_root: String,
    create_missing_workspace: bool,
    import_attempted: bool,
    shell_profile_id: Option<String>,
    share_remote: bool,
    share_attempted: bool,
    unshare_attempted: bool,
}

impl Journal {
    fn progress(&self) -> SetupProgress {
        SetupProgress {
            setup_id: self.setup_id.clone(),
            stage: self.stage.into(),
            account_name: self.binding.account_name.clone(),
            account: self.binding.account.clone(),
            mode: self.binding.mode,
            host_id: self.host_id.clone(),
            host_name: self.host_name.clone(),
            auth_generation: self.auth_generation,
            workspace_import_id: self.workspace_import_id.clone(),
            workspace_id: self.workspace_id.clone(),
            workspace_name: self.workspace_name.clone(),
            workspace_root: self.workspace_root.clone(),
            shell_profile_id: self.shell_profile_id.clone(),
            share_remote: self.share_remote,
            share_attempted: self.share_attempted,
        }
    }

    fn workspace_id(&self) -> Result<Option<WorkspaceId>, SetupError> {
        self.workspace_id
            .as_ref()
            .map(|value| {
                WorkspaceId::try_from(value.clone()).map_err(|_| SetupError::JournalCorrupt)
            })
            .transpose()
    }

    fn persist(&mut self, store: &SetupJournalStore) -> Result<(), SetupError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(SetupError::JournalUnavailable)?;
        let bytes =
            serde_json::to_vec(&journal_value(self)).map_err(|_| SetupError::JournalUnavailable)?;
        store.replace_atomic(&bytes).map_err(map_journal_error)
    }
}

/// Run one bounded setup turn. Login and publication can remain pending; the
/// caller resumes by invoking this function with the same binding and choices.
///
/// A completed result is only a dashboard-routing hint. It carries no current
/// authorization, workspace consent, or publication authority.
pub fn completed_configuration(binding: &ServiceBinding) -> Result<Option<HostId>, SetupError> {
    validate_binding(binding)?;
    let Some(bytes) =
        SetupJournalStore::read_existing(&binding.profile_path).map_err(map_journal_error)?
    else {
        return Ok(None);
    };
    let journal = parse_journal(&bytes)?;
    match journal.stage {
        PersistedStage::Shared if journal.share_remote && journal.share_attempted => {}
        PersistedStage::LocalOnly if !journal.share_remote => {}
        PersistedStage::Shared | PersistedStage::LocalOnly => {
            return Err(SetupError::JournalCorrupt);
        }
        _ => return Ok(None),
    }
    if !same_binding(&journal.binding, binding) {
        return Err(SetupError::BindingMismatch);
    }

    let host_id = journal
        .host_id
        .ok_or(SetupError::JournalCorrupt)?
        .try_into()
        .map_err(|_| SetupError::JournalCorrupt)?;
    WorkspaceId::try_from(journal.workspace_id.ok_or(SetupError::JournalCorrupt)?)
        .map_err(|_| SetupError::JournalCorrupt)?;
    Ok(Some(host_id))
}

pub fn run(
    mut options: SetupOptions,
    host: &mut impl SetupHost,
    service: &mut impl SetupServiceControl,
    interaction: &mut impl SetupInteraction,
) -> Result<SetupOutcome, SetupError> {
    validate_binding(&options.binding)?;
    if options.non_interactive && options.choices.is_none() {
        return Err(SetupError::ChoicesRequired);
    }
    service.validate_binding(&options.binding)?;
    let preflight = host.preflight(&options.binding)?;
    if !options.non_interactive && !preflight.interactive_terminal {
        return Err(SetupError::InvalidOptions);
    }

    // The profile owner lock is acquired before the first durable transition.
    // Host startup and all user-facing waits happen only after this record exists.
    let store =
        SetupJournalStore::open(&options.binding.profile_path).map_err(map_journal_error)?;
    let canonical_profile =
        lomi_platform::diagnostics::canonical_profile_path(&options.binding.profile_path)
            .ok_or(SetupError::ProfileRejected)?;
    if canonical_profile != options.binding.profile_path {
        return Err(SetupError::ProfileRejected);
    }
    let persisted = store.read().map_err(map_journal_error)?;
    let mut supplied_choices = options.choices.take();
    let (mut journal, initial_choices) = match persisted {
        Some(bytes) => {
            let journal = parse_journal(&bytes)?;
            if !same_binding(&journal.binding, &options.binding) {
                return Err(SetupError::BindingMismatch);
            }
            (journal, None)
        }
        None if preflight.existing_configuration => {
            return Ok(SetupOutcome::ExistingConfiguration {
                host_id: preflight.existing_host_id,
            });
        }
        None => {
            let choices = match supplied_choices.take() {
                Some(choices) => choices,
                None => interaction.collect_choices(
                    &options.binding,
                    &preflight,
                    None,
                    &service.detect_shells(&options.binding)?,
                )?,
            };
            let mut choices = choices;
            resolve_host_name(&mut choices, &preflight.suggested_host_name)?;
            resolve_workspace_choice(&mut choices, &preflight.current_directory)?;
            let mut journal = initial_journal(&options.binding, &choices)?;
            journal.persist(&store)?;
            (journal, Some(choices))
        }
    };

    if let Some(expected_host_id) = journal.host_id.as_deref() {
        if preflight
            .existing_host_id
            .is_some_and(|current| expected_host_id != String::from(current))
            || (preflight.existing_host_id.is_none() && !preflight.identity_pending_recovery)
        {
            // Never start a fresh Host/profile when a prior identity was
            // pinned but cannot be recovered from the selected profile.
            return Ok(incomplete(&journal, SetupProblem::HostIdentityChanged));
        }
    }

    let choices = match initial_choices.or_else(|| supplied_choices.take()) {
        Some(choices) => choices,
        None => {
            let shells = service.detect_shells(&options.binding)?;
            interaction.collect_choices(
                &options.binding,
                &preflight,
                Some(&journal.progress()),
                &shells,
            )?
        }
    };
    let mut choices = choices;
    let saved_host_name = journal
        .host_name
        .as_deref()
        .map(|value| {
            LocalHostName::try_from(value.to_owned()).map_err(|_| SetupError::JournalCorrupt)
        })
        .transpose()?;
    resolve_host_name(
        &mut choices,
        saved_host_name
            .as_ref()
            .unwrap_or(&preflight.suggested_host_name),
    )?;
    resolve_workspace_choice(&mut choices, &preflight.current_directory)?;
    if journal.import_attempted {
        // Compare physical roots, including equivalent /tmp symlink or native
        // Windows extended-path spellings. Missing/imported roots are never
        // recreated during resume.
        choices.workspace_root = choices
            .workspace_root
            .canonicalize()
            .map_err(|_| SetupError::ChoiceMismatch)?;
    }
    reconcile_choices(&mut journal, &choices)?;
    journal.persist(&store)?;

    let workspace_root = match prepare_workspace_root(
        &journal.workspace_root,
        journal.create_missing_workspace,
        journal.import_attempted,
        &canonical_profile,
    ) {
        Ok(root) => root,
        Err(()) => {
            return Ok(incomplete(&journal, SetupProblem::WorkspaceUnavailable));
        }
    };
    let canonical_root_text = workspace_root
        .to_str()
        .ok_or(SetupError::InvalidOptions)?
        .to_owned();
    if journal.import_attempted && journal.workspace_root != canonical_root_text {
        return Ok(incomplete(&journal, SetupProblem::WorkspaceUnavailable));
    }
    journal.workspace_root = canonical_root_text;
    journal.persist(&store)?;
    let workspace_missing = !workspace_root.exists();
    let git_repository_detected = if workspace_missing {
        false
    } else {
        match service.detect_git_repository(&workspace_root) {
            Ok(detected) => detected,
            Err(_) => return Ok(incomplete(&journal, SetupProblem::WorkspaceUnavailable)),
        }
    };
    let review = make_review(
        &options.binding,
        &preflight,
        &journal,
        &choices,
        &workspace_root,
        git_repository_detected,
    )?;
    if !options.non_interactive && !interaction.confirm_review(&review)? {
        return Ok(incomplete(&journal, SetupProblem::WorkspaceUnavailable));
    }

    if workspace_missing {
        if !journal.create_missing_workspace || journal.import_attempted {
            return Ok(incomplete(&journal, SetupProblem::WorkspaceUnavailable));
        }
        if fs::create_dir_all(&workspace_root).is_err() {
            return Ok(incomplete(&journal, SetupProblem::WorkspaceUnavailable));
        }
        match workspace_root.canonicalize() {
            Ok(canonical) if canonical == workspace_root => {}
            _ => return Ok(incomplete(&journal, SetupProblem::WorkspaceUnavailable)),
        }
    }
    if service
        .verify_workspace_access(&options.binding, &workspace_root)
        .is_err()
    {
        return Ok(incomplete(&journal, SetupProblem::WorkspaceUnavailable));
    }

    if journal.host_id.is_none() {
        if let Some(existing_host_id) = preflight.existing_host_id {
            journal.host_id = Some(String::from(existing_host_id));
            journal.persist(&store)?;
        }
    }
    let expected_host_id = journal
        .host_id
        .as_ref()
        .map(|value| HostId::try_from(value.clone()).map_err(|_| SetupError::JournalCorrupt))
        .transpose()?;
    if host
        .start_local(&options.binding, expected_host_id)
        .is_err()
    {
        return Ok(incomplete(&journal, SetupProblem::HostUnavailable));
    }
    let observed = match host.observe(&options.binding) {
        Ok(observed) => observed,
        Err(_) => return Ok(incomplete(&journal, SetupProblem::HostUnavailable)),
    };
    if !host_matches(&observed, &options.binding, &canonical_profile) {
        return Ok(incomplete(&journal, SetupProblem::ServiceBindingChanged));
    }
    let host_id = observed.status.host_id;
    if journal
        .host_id
        .as_deref()
        .is_some_and(|expected| expected != String::from(host_id))
    {
        return Ok(incomplete(&journal, SetupProblem::HostIdentityChanged));
    }
    if journal.host_id.is_none() {
        journal.host_id = Some(String::from(host_id));
        journal.persist(&store)?;
    }
    match ensure_host_display_name(
        &mut journal,
        &store,
        &choices,
        &options.binding,
        &canonical_profile,
        host_id,
        &observed,
        host,
    )? {
        HostNameProgress::Ready => {}
        HostNameProgress::Blocked(problem) => return Ok(incomplete(&journal, problem)),
    }

    let login = loop {
        match ensure_login(&mut journal, &store, &choices, host, interaction)? {
            LoginProgress::Ready(status) => break status,
            LoginProgress::Pending(operation_id) => {
                if options.non_interactive || !interaction.wait_for_login_update()? {
                    return Ok(SetupOutcome::PendingLogin {
                        host_id,
                        operation_id,
                    });
                }
            }
            LoginProgress::Blocked(problem) => return Ok(incomplete(&journal, problem)),
        }
    };

    if journal.stage == PersistedStage::Draft {
        journal.stage = PersistedStage::Enrolled;
    }
    if journal.auth_generation != Some(login.generation.0) {
        if journal.auth_generation.is_some()
            && !interaction.confirm_authorization_context_change()?
        {
            return Ok(incomplete(
                &journal,
                SetupProblem::AuthorizationContextChanged,
            ));
        }
        journal.auth_generation = Some(login.generation.0);
        if journal.workspace_id.is_some() {
            journal.stage = PersistedStage::LocalConfigured;
            if journal.share_attempted {
                journal.stage = PersistedStage::SharePending;
            }
        } else {
            journal.stage = PersistedStage::Enrolled;
        }
        journal.persist(&store)?;
    }

    let workspace_id = match ensure_local_configuration(
        &mut journal,
        &store,
        &choices,
        &workspace_root,
        host,
        service,
    )? {
        LocalConfigurationProgress::Ready(workspace_id) => workspace_id,
        LocalConfigurationProgress::Blocked(problem) => return Ok(incomplete(&journal, problem)),
    };

    match ensure_service_ready(&mut journal, &store, &options.binding, host, service)? {
        ServiceProgress::Ready => {}
        ServiceProgress::Blocked(problem) => return Ok(incomplete(&journal, problem)),
    }

    let current_status = match current_login_status(host) {
        Ok(status) => status,
        Err(_) => return Ok(incomplete(&journal, SetupProblem::AuthorizationUnavailable)),
    };
    if !auth_ready(&current_status)
        || current_status.generation.0 != journal.auth_generation.unwrap_or_default()
    {
        return Ok(incomplete(
            &journal,
            SetupProblem::AuthorizationContextChanged,
        ));
    }

    let mut waiting_only = false;
    loop {
        let outcome = if waiting_only {
            observe_setup_completion(
                &mut journal,
                &store,
                host_id,
                workspace_id,
                host,
                service,
                &options.binding,
            )?
        } else if !journal.share_remote {
            ensure_local_only(
                &mut journal,
                &store,
                host_id,
                workspace_id,
                host,
                service,
                &options.binding,
                choices.disable_existing_share,
            )?
        } else {
            ensure_shared(
                &mut journal,
                &store,
                host_id,
                workspace_id,
                &choices,
                host,
                service,
                &options.binding,
                interaction,
                options.non_interactive,
            )?
        };
        if matches!(
            &outcome,
            SetupOutcome::Incomplete {
                problem: SetupProblem::PublicationPending,
                ..
            }
        ) && !options.non_interactive
            && interaction.wait_for_publication_update()?
        {
            waiting_only = true;
            continue;
        }
        return Ok(outcome);
    }
}

enum HostNameProgress {
    Ready,
    Blocked(SetupProblem),
}

fn ensure_host_display_name(
    journal: &mut Journal,
    store: &SetupJournalStore,
    choices: &SetupChoices,
    binding: &ServiceBinding,
    canonical_profile: &Path,
    host_id: HostId,
    observed: &HostObservation,
    host: &mut impl SetupHost,
) -> Result<HostNameProgress, SetupError> {
    let desired = choices
        .host_name
        .as_ref()
        .ok_or(SetupError::InvalidOptions)?;
    if &observed.status.host_name == desired {
        if journal.host_name_set_attempted {
            journal.host_name_set_attempted = false;
            journal.host_name_expected = None;
            journal.persist(store)?;
        }
        return Ok(HostNameProgress::Ready);
    }
    if journal.host_name_set_attempted
        && journal.host_name_expected.as_deref() != Some(observed.status.host_name.as_str())
    {
        // A different current name cannot be adopted as the expected value of
        // an uncertain attempt. The operator can review a new explicit choice.
        return Ok(HostNameProgress::Blocked(
            SetupProblem::HostNameChangeUnknown,
        ));
    }

    let expected_name = observed.status.host_name.clone();
    journal.host_name_set_attempted = true;
    journal.host_name_expected = Some(expected_name.as_str().to_owned());
    journal.persist(store)?;
    // This local metadata operation is a CAS. If an interrupted attempt still
    // observes its exact original value, repeating that same CAS cannot adopt
    // or overwrite a concurrent name. Terminal input and other mutations do
    // not use this recovery path.
    let result = host.request(LocalCall::HostNameSet(LocalHostNameSet {
        expected_name: Some(expected_name),
        name: desired.clone(),
    }));
    match result {
        Ok(LocalResult::HostNameSet(stored)) if &stored == desired => {
            journal.host_name_set_attempted = false;
            journal.host_name_expected = None;
            journal.persist(store)?;
            Ok(HostNameProgress::Ready)
        }
        Err(SetupCallError::OutcomeUnknown) | Ok(_) => {
            if observed_host_name_matches(host, binding, canonical_profile, host_id, desired) {
                journal.host_name_set_attempted = false;
                journal.host_name_expected = None;
                journal.persist(store)?;
                Ok(HostNameProgress::Ready)
            } else {
                Ok(HostNameProgress::Blocked(
                    SetupProblem::HostNameChangeUnknown,
                ))
            }
        }
        Err(SetupCallError::Unavailable | SetupCallError::Rejected) => {
            // These are known no-dispatch or no-effect rejections. Clear the
            // attempt marker so an operator can review and retry after resume.
            journal.host_name_set_attempted = false;
            journal.host_name_expected = None;
            journal.persist(store)?;
            Ok(HostNameProgress::Blocked(SetupProblem::HostUnavailable))
        }
    }
}

fn observed_host_name_matches(
    host: &mut impl SetupHost,
    binding: &ServiceBinding,
    canonical_profile: &Path,
    host_id: HostId,
    desired: &LocalHostName,
) -> bool {
    host.observe(binding).is_ok_and(|observed| {
        observed.status.host_id == host_id
            && observed.status.host_name == *desired
            && host_matches(&observed, binding, canonical_profile)
    })
}

/// After an effect was accepted, waiting is read-only. A later Unshare/auth
/// change cannot consume the old run's renewal flag to repeat an operation.
fn observe_setup_completion(
    journal: &mut Journal,
    store: &SetupJournalStore,
    host_id: HostId,
    workspace_id: WorkspaceId,
    host: &mut impl SetupHost,
    service: &mut impl SetupServiceControl,
    binding: &ServiceBinding,
) -> Result<SetupOutcome, SetupError> {
    let guard = match current_consent_guard(journal, host_id, workspace_id, host, service, binding)
    {
        Ok(guard) => guard,
        Err(problem) => return Ok(incomplete(journal, problem)),
    };
    let publication = match host.publication_status(workspace_id) {
        Ok(publication) => publication,
        Err(_) => return Ok(incomplete(journal, SetupProblem::PublicationUnavailable)),
    };
    if !publication_matches(
        &publication,
        host_id,
        workspace_id,
        guard.expected_authorization_generation,
    ) {
        return Ok(incomplete(
            journal,
            SetupProblem::AuthorizationContextChanged,
        ));
    }
    let desired = if journal.share_remote {
        LocalSharing::Enabled
    } else {
        LocalSharing::Disabled
    };
    if publication.consent != desired {
        return Ok(incomplete(
            journal,
            if journal.share_remote {
                SetupProblem::ShareConsentRenewalRequired
            } else {
                SetupProblem::SharingConflict
            },
        ));
    }
    if publication.publication != PublicationState::Acknowledged {
        return Ok(incomplete(
            journal,
            if publication.publication == PublicationState::Pending {
                SetupProblem::PublicationPending
            } else {
                SetupProblem::PublicationUnavailable
            },
        ));
    }
    journal.stage = if journal.share_remote {
        PersistedStage::Shared
    } else {
        PersistedStage::LocalOnly
    };
    journal.persist(store)?;
    Ok(SetupOutcome::Complete {
        host_id,
        workspace_id,
        sharing: if journal.share_remote {
            SetupSharing::Shared
        } else {
            SetupSharing::LocalOnly
        },
    })
}

enum LoginProgress {
    Ready(LocalLoginStatus),
    Pending(Option<OperationId>),
    Blocked(SetupProblem),
}

fn ensure_login(
    journal: &mut Journal,
    store: &SetupJournalStore,
    choices: &SetupChoices,
    host: &mut impl SetupHost,
    interaction: &mut impl SetupInteraction,
) -> Result<LoginProgress, SetupError> {
    let mut status = match current_login_status(host) {
        Ok(status) => status,
        Err(_) => {
            return Ok(LoginProgress::Blocked(
                SetupProblem::AuthorizationUnavailable,
            ));
        }
    };

    if status.phase == LocalAuthPhase::Unconfigured {
        let Some(configuration) = choices.auth_configuration.as_ref() else {
            return Ok(LoginProgress::Blocked(
                SetupProblem::AuthorizationConfigurationRequired,
            ));
        };
        configuration
            .validate()
            .map_err(|_| SetupError::InvalidOptions)?;
        let provider = storage_provider(configuration.provider);
        if journal
            .storage_provider
            .as_deref()
            .is_some_and(|stored| stored != provider)
        {
            return Err(SetupError::ChoiceMismatch);
        }
        if journal.storage_provider.is_none() {
            journal.storage_provider = Some(provider.to_owned());
            journal.persist(store)?;
        }
        match host.request(LocalCall::AuthConfigure(
            lomi_remote_protocol::ipc::LocalAuthConfigure {
                configuration: configuration.clone(),
                operator_intent: Confirmed::Confirmed,
            },
        )) {
            Ok(LocalResult::AuthConfigured {}) => {}
            _ => {
                status = match current_login_status(host) {
                    Ok(status) => status,
                    Err(_) => {
                        return Ok(LoginProgress::Blocked(
                            SetupProblem::AuthorizationConfigurationRequired,
                        ));
                    }
                };
                if status.phase == LocalAuthPhase::Unconfigured {
                    return Ok(LoginProgress::Blocked(
                        SetupProblem::AuthorizationConfigurationRequired,
                    ));
                }
            }
        }
        status = match current_login_status(host) {
            Ok(status) => status,
            Err(_) => {
                return Ok(LoginProgress::Blocked(
                    SetupProblem::AuthorizationUnavailable,
                ));
            }
        };
    }

    if auth_ready(&status) {
        return Ok(LoginProgress::Ready(status));
    }
    if status.pending_cloud_revoke || status.phase == LocalAuthPhase::PendingRevoke {
        return Ok(LoginProgress::Blocked(SetupProblem::AuthorizationPending));
    }

    let status_operation = status.operation_id;
    if let Some(operation_id) = status_operation {
        let journal_operation = journal
            .login_operation_id
            .as_deref()
            .and_then(|value| OperationId::try_from(value.to_owned()).ok());
        if journal_operation.is_some_and(|expected| expected != operation_id) {
            return Ok(LoginProgress::Blocked(
                SetupProblem::AuthorizationContextChanged,
            ));
        }
        if journal_operation.is_none() {
            journal.login_operation_id = Some(String::from(operation_id));
            journal.persist(store)?;
        }
        maybe_show_login_presentation(host, interaction);
        return Ok(LoginProgress::Pending(Some(operation_id)));
    }

    let operation_id = match journal
        .login_operation_id
        .as_deref()
        .map(|value| OperationId::try_from(value.to_owned()))
        .transpose()
    {
        Ok(Some(operation_id)) => operation_id,
        Ok(None) => {
            let operation_id = OperationId::from_bytes(*Uuid::new_v4().as_bytes())
                .map_err(|_| SetupError::JournalUnavailable)?;
            journal.login_operation_id = Some(String::from(operation_id));
            journal.persist(store)?;
            operation_id
        }
        Err(_) => return Err(SetupError::JournalCorrupt),
    };

    let _ = host.request(LocalCall::LoginStart(LocalLoginStart { operation_id }));
    status = match current_login_status(host) {
        Ok(status) => status,
        Err(_) => {
            return Ok(LoginProgress::Blocked(
                SetupProblem::AuthorizationUnavailable,
            ));
        }
    };
    if auth_ready(&status) {
        return Ok(LoginProgress::Ready(status));
    }
    if status.operation_id == Some(operation_id) {
        maybe_show_login_presentation(host, interaction);
        return Ok(LoginProgress::Pending(Some(operation_id)));
    }
    Ok(LoginProgress::Blocked(SetupProblem::AuthorizationPending))
}

fn maybe_show_login_presentation(
    host: &mut impl SetupHost,
    interaction: &mut impl SetupInteraction,
) {
    if !interaction.reveal_login_presentation() {
        return;
    }
    if let Ok(LocalResult::LoginPresentation(presentation)) =
        host.request(LocalCall::LoginPresentation {})
    {
        interaction.show_login_presentation(&presentation);
    }
}

fn current_login_status(host: &mut impl SetupHost) -> Result<LocalLoginStatus, SetupError> {
    match host.request(LocalCall::LoginStatus {}) {
        Ok(LocalResult::LoginStatus(status)) => Ok(status),
        _ => Err(SetupError::HostUnavailable),
    }
}

fn auth_ready(status: &LocalLoginStatus) -> bool {
    status.phase == LocalAuthPhase::Ready && !status.locked && !status.pending_cloud_revoke
}

enum LocalConfigurationProgress {
    Ready(WorkspaceId),
    Blocked(SetupProblem),
}

fn ensure_local_configuration(
    journal: &mut Journal,
    store: &SetupJournalStore,
    choices: &SetupChoices,
    workspace_root: &Path,
    host: &mut impl SetupHost,
    service: &mut impl SetupServiceControl,
) -> Result<LocalConfigurationProgress, SetupError> {
    if !journal.import_attempted {
        journal.import_attempted = true;
        journal.persist(store)?;
    }
    let import_id = WorkspaceId::try_from(journal.workspace_import_id.clone())
        .map_err(|_| SetupError::JournalCorrupt)?;
    if journal.workspace_id.is_none() {
        let root_path = workspace_root
            .to_str()
            .ok_or(SetupError::InvalidOptions)?
            .to_owned()
            .try_into()
            .map_err(|_| SetupError::InvalidOptions)?;
        let call = LocalCall::WorkspaceImport(LocalWorkspaceImport {
            workspace_id: import_id,
            name: choices.workspace_name.clone(),
            root_path,
            operator_intent: Confirmed::Confirmed,
        });
        match host.request(call) {
            Ok(LocalResult::WorkspaceImported(LocalWorkspaceImportReceipt {
                import_id: returned_import_id,
                workspace,
            })) if returned_import_id == import_id => {
                journal.workspace_id = Some(String::from(workspace.workspace_id));
                journal.persist(store)?;
            }
            _ => {
                return Ok(LocalConfigurationProgress::Blocked(
                    SetupProblem::WorkspaceUnavailable,
                ));
            }
        }
    }
    let workspace_id = journal.workspace_id()?.ok_or(SetupError::JournalCorrupt)?;
    let host_id = journal
        .host_id
        .as_ref()
        .ok_or(SetupError::JournalCorrupt)?
        .clone()
        .try_into()
        .map_err(|_| SetupError::JournalCorrupt)?;
    if current_workspace_binding(journal, host, host_id, workspace_id).is_err() {
        return Ok(LocalConfigurationProgress::Blocked(
            SetupProblem::WorkspaceUnavailable,
        ));
    }
    if journal.shell_profile_id.is_some() {
        let expected = journal.shell_profile_id.as_deref().unwrap();
        let profile = make_shell_profile(workspace_id, workspace_root, &choices.shell)?;
        if profile.profile_id.as_str() != expected {
            return Err(SetupError::ChoiceMismatch);
        }
    }
    let profile = make_shell_profile(workspace_id, workspace_root, &choices.shell)?;
    if service
        .verify_shell_profile(&journal.binding, workspace_root, &profile)
        .is_err()
    {
        return Ok(LocalConfigurationProgress::Blocked(
            SetupProblem::ShellUnavailable,
        ));
    }
    if journal.shell_profile_id.is_none() {
        journal.shell_profile_id = Some(profile.profile_id.as_str().to_owned());
        journal.persist(store)?;
    }
    match host.request(LocalCall::ShellProfileRegister(profile.clone())) {
        Ok(LocalResult::ShellProfileRegistered { profile_id })
            if profile_id == profile.profile_id => {}
        // Registration uses the profile's deterministic ID. Repeating this
        // exact configuration is safe: a conflicting same-ID profile is
        // rejected by Host, and no shell is started by registration.
        _ => {
            return Ok(LocalConfigurationProgress::Blocked(
                SetupProblem::ShellUnavailable,
            ));
        }
    }
    journal.stage = PersistedStage::LocalConfigured;
    journal.persist(store)?;
    Ok(LocalConfigurationProgress::Ready(workspace_id))
}

fn make_shell_profile(
    workspace_id: WorkspaceId,
    workspace_root: &Path,
    shell: &SetupShellChoice,
) -> Result<LocalShellProfileRegister, SetupError> {
    let cwd: LocalRootPath = workspace_root
        .to_str()
        .ok_or(SetupError::InvalidOptions)?
        .to_owned()
        .try_into()
        .map_err(|_| SetupError::InvalidOptions)?;
    LocalShellProfileRegister::new(
        workspace_id,
        shell.name.clone(),
        shell.executable.clone(),
        shell.args.clone(),
        cwd,
        shell.environment.clone(),
    )
    .map_err(|_| SetupError::InvalidOptions)
}

enum ServiceProgress {
    Ready,
    Blocked(SetupProblem),
}

fn ensure_service_ready(
    journal: &mut Journal,
    store: &SetupJournalStore,
    binding: &ServiceBinding,
    host: &mut impl SetupHost,
    service: &mut impl SetupServiceControl,
) -> Result<ServiceProgress, SetupError> {
    let mut observation = match service.inspect(binding) {
        Ok(observation) => observation,
        Err(_) => return Ok(ServiceProgress::Blocked(SetupProblem::ServiceNotReady)),
    };
    if !observation.binding_matches {
        return Ok(ServiceProgress::Blocked(
            SetupProblem::ServiceBindingChanged,
        ));
    }
    if binding.mode != LocalStartMode::Manual && !observation.registration_present {
        if service.install(binding).is_err() {
            return Ok(ServiceProgress::Blocked(SetupProblem::ServiceInstallFailed));
        }
        observation = match service.inspect(binding) {
            Ok(observation) => observation,
            Err(_) => return Ok(ServiceProgress::Blocked(SetupProblem::ServiceNotReady)),
        };
        if !observation.binding_matches || !observation.registration_present {
            return Ok(ServiceProgress::Blocked(
                SetupProblem::ServiceBindingChanged,
            ));
        }
    }
    if binding.mode == LocalStartMode::Manual {
        if observation.registration_present || observation.autostart_enabled {
            return Ok(ServiceProgress::Blocked(
                SetupProblem::ServiceBindingChanged,
            ));
        }
    } else if !observation.autostart_enabled {
        return Ok(ServiceProgress::Blocked(SetupProblem::ServiceNotReady));
    }

    if !observation.active || !observation.ipc_ready {
        if service.start(binding).is_err() {
            return Ok(ServiceProgress::Blocked(SetupProblem::ServiceNotReady));
        }
        observation = match service.inspect(binding) {
            Ok(observation) => observation,
            Err(_) => return Ok(ServiceProgress::Blocked(SetupProblem::ServiceNotReady)),
        };
    }
    if !observation.binding_matches
        || !observation.active
        || !observation.ipc_ready
        || (binding.mode == LocalStartMode::Manual && observation.autostart_enabled)
        || (binding.mode != LocalStartMode::Manual && !observation.autostart_enabled)
    {
        return Ok(ServiceProgress::Blocked(SetupProblem::ServiceNotReady));
    }
    let host_observation = match host.observe(binding) {
        Ok(observation) => observation,
        Err(_) => return Ok(ServiceProgress::Blocked(SetupProblem::ServiceNotReady)),
    };
    if !host_matches(&host_observation, binding, &binding.profile_path)
        || journal
            .host_id
            .as_deref()
            .is_none_or(|expected| expected != String::from(host_observation.status.host_id))
    {
        return Ok(ServiceProgress::Blocked(SetupProblem::HostIdentityChanged));
    }
    let status = match current_login_status(host) {
        Ok(status) => status,
        Err(_) => {
            return Ok(ServiceProgress::Blocked(
                SetupProblem::AuthorizationUnavailable,
            ));
        }
    };
    if !auth_ready(&status) {
        return Ok(ServiceProgress::Blocked(SetupProblem::AuthorizationPending));
    }
    if journal.auth_generation != Some(status.generation.0) {
        return Ok(ServiceProgress::Blocked(
            SetupProblem::AuthorizationContextChanged,
        ));
    }
    journal.stage = PersistedStage::ServiceReady;
    journal.persist(store)?;
    Ok(ServiceProgress::Ready)
}

#[allow(clippy::too_many_arguments)]
fn ensure_shared(
    journal: &mut Journal,
    store: &SetupJournalStore,
    host_id: HostId,
    workspace_id: WorkspaceId,
    choices: &SetupChoices,
    host: &mut impl SetupHost,
    service: &mut impl SetupServiceControl,
    binding: &ServiceBinding,
    interaction: &mut impl SetupInteraction,
    non_interactive: bool,
) -> Result<SetupOutcome, SetupError> {
    if current_workspace_binding(journal, host, host_id, workspace_id).is_err() {
        return Ok(incomplete(journal, SetupProblem::WorkspaceUnavailable));
    }
    let auth = match current_login_status(host) {
        Ok(status) => status,
        Err(_) => return Ok(incomplete(journal, SetupProblem::AuthorizationUnavailable)),
    };
    if !auth_ready(&auth) || Some(auth.generation.0) != journal.auth_generation {
        return Ok(incomplete(
            journal,
            SetupProblem::AuthorizationContextChanged,
        ));
    }
    let service_state = match service.inspect(binding) {
        Ok(state) => state,
        Err(_) => return Ok(incomplete(journal, SetupProblem::ServiceNotReady)),
    };
    if !service_state.binding_matches
        || !service_state.active
        || !service_state.ipc_ready
        || (binding.mode == LocalStartMode::Manual && service_state.autostart_enabled)
        || (binding.mode != LocalStartMode::Manual
            && (!service_state.registration_present || !service_state.autostart_enabled))
    {
        return Ok(incomplete(journal, SetupProblem::ServiceNotReady));
    }

    let mut publication = match host.publication_status(workspace_id) {
        Ok(publication) => publication,
        Err(_) => return Ok(incomplete(journal, SetupProblem::PublicationUnavailable)),
    };
    if publication.host_id != host_id
        || publication.workspace_id != workspace_id
        || publication.auth_generation.0 != auth.generation.0
    {
        return Ok(incomplete(journal, SetupProblem::PublicationUnavailable));
    }
    if publication.consent == LocalSharing::Enabled {
        if publication.publication == PublicationState::Acknowledged {
            journal.stage = PersistedStage::Shared;
            journal.persist(store)?;
            return Ok(SetupOutcome::Complete {
                host_id,
                workspace_id,
                sharing: SetupSharing::Shared,
            });
        }
        journal.stage = PersistedStage::SharePending;
        journal.share_attempted = true;
        journal.persist(store)?;
        return Ok(incomplete(journal, SetupProblem::PublicationPending));
    }

    if journal.share_attempted {
        let renewed = if options_has_renewal(choices) {
            true
        } else if non_interactive {
            false
        } else {
            interaction.confirm_renewed_share(
                &journal
                    .workspace_name
                    .clone()
                    .try_into()
                    .map_err(|_| SetupError::JournalCorrupt)?,
                workspace_id,
            )?
        };
        if !renewed {
            return Ok(incomplete(
                journal,
                SetupProblem::ShareConsentRenewalRequired,
            ));
        }
    } else if !choices.share_remote {
        return ensure_local_only(
            journal,
            store,
            host_id,
            workspace_id,
            host,
            service,
            binding,
            choices.disable_existing_share,
        );
    }

    journal.share_attempted = true;
    journal.stage = PersistedStage::SharePending;
    journal.persist(store)?;
    // Prompts and durable journal writes may take arbitrarily long. Re-observe
    // the selected Host/service and send a conditional consent mutation whose
    // expected authorization and workspace binding are consumed atomically.
    let guard = match current_consent_guard(journal, host_id, workspace_id, host, service, binding)
    {
        Ok(guard) => guard,
        Err(problem) => return Ok(incomplete(journal, problem)),
    };
    let result = host.request(LocalCall::ShareAuthorized(guard));
    // A lost or malformed reply is reconciled from fresh HostStore state. The
    // same Share request is never resent automatically.
    publication = match host.publication_status(workspace_id) {
        Ok(publication) => publication,
        Err(_) => return Ok(incomplete(journal, SetupProblem::ShareOutcomeUnknown)),
    };
    if publication.host_id != host_id
        || publication.workspace_id != workspace_id
        || publication.auth_generation.0 != auth.generation.0
    {
        return Ok(incomplete(journal, SetupProblem::PublicationUnavailable));
    }
    if publication.consent != LocalSharing::Enabled {
        let _ = result;
        return Ok(incomplete(journal, SetupProblem::ShareOutcomeUnknown));
    }
    if publication.publication == PublicationState::Acknowledged {
        journal.stage = PersistedStage::Shared;
        journal.persist(store)?;
        return Ok(SetupOutcome::Complete {
            host_id,
            workspace_id,
            sharing: SetupSharing::Shared,
        });
    }
    journal.stage = PersistedStage::SharePending;
    journal.persist(store)?;
    Ok(incomplete(journal, SetupProblem::PublicationPending))
}

fn ensure_local_only(
    journal: &mut Journal,
    store: &SetupJournalStore,
    host_id: HostId,
    workspace_id: WorkspaceId,
    host: &mut impl SetupHost,
    service: &mut impl SetupServiceControl,
    binding: &ServiceBinding,
    disable_existing_share: bool,
) -> Result<SetupOutcome, SetupError> {
    if current_workspace_binding(journal, host, host_id, workspace_id).is_err() {
        return Ok(incomplete(journal, SetupProblem::WorkspaceUnavailable));
    }
    let auth = match current_login_status(host) {
        Ok(status) => status,
        Err(_) => return Ok(incomplete(journal, SetupProblem::AuthorizationUnavailable)),
    };
    if !auth_ready(&auth) || Some(auth.generation.0) != journal.auth_generation {
        return Ok(incomplete(
            journal,
            SetupProblem::AuthorizationContextChanged,
        ));
    }
    let service_state = match service.inspect(binding) {
        Ok(state) => state,
        Err(_) => return Ok(incomplete(journal, SetupProblem::ServiceNotReady)),
    };
    if !service_state.binding_matches
        || !service_state.active
        || !service_state.ipc_ready
        || (binding.mode == LocalStartMode::Manual && service_state.autostart_enabled)
        || (binding.mode != LocalStartMode::Manual
            && (!service_state.registration_present || !service_state.autostart_enabled))
    {
        return Ok(incomplete(journal, SetupProblem::ServiceNotReady));
    }

    let mut publication = match host.publication_status(workspace_id) {
        Ok(publication) => publication,
        Err(_) => return Ok(incomplete(journal, SetupProblem::PublicationUnavailable)),
    };
    if !publication_matches(&publication, host_id, workspace_id, auth.generation) {
        return Ok(incomplete(journal, SetupProblem::PublicationUnavailable));
    }
    if publication.consent == LocalSharing::Enabled {
        if !disable_existing_share {
            return Ok(incomplete(journal, SetupProblem::SharingConflict));
        }
        // Persist that revocation started, but never treat this prior choice as
        // consent on a later run. The current caller must confirm again.
        if !journal.unshare_attempted {
            journal.unshare_attempted = true;
            journal.persist(store)?;
        }
        let guard =
            match current_consent_guard(journal, host_id, workspace_id, host, service, binding) {
                Ok(guard) => guard,
                Err(problem) => return Ok(incomplete(journal, problem)),
            };
        let _ = host.request(LocalCall::UnshareAuthorized(guard));
        publication = match host.publication_status(workspace_id) {
            Ok(publication) => publication,
            Err(_) => return Ok(incomplete(journal, SetupProblem::PublicationUnavailable)),
        };
        if !publication_matches(&publication, host_id, workspace_id, auth.generation) {
            return Ok(incomplete(journal, SetupProblem::PublicationUnavailable));
        }
        if publication.consent == LocalSharing::Enabled {
            return Ok(incomplete(journal, SetupProblem::UnshareOutcomeUnknown));
        }
    }
    if publication.consent != LocalSharing::Disabled {
        return Ok(incomplete(journal, SetupProblem::PublicationPending));
    }
    if journal.unshare_attempted && publication.publication != PublicationState::Acknowledged {
        return Ok(incomplete(
            journal,
            if publication.publication == PublicationState::Pending {
                SetupProblem::PublicationPending
            } else {
                SetupProblem::PublicationUnavailable
            },
        ));
    }
    journal.stage = PersistedStage::LocalOnly;
    journal.persist(store)?;
    Ok(SetupOutcome::Complete {
        host_id,
        workspace_id,
        sharing: SetupSharing::LocalOnly,
    })
}

fn publication_matches(
    publication: &WorkspacePublication,
    host_id: HostId,
    workspace_id: WorkspaceId,
    auth_generation: DecimalU64,
) -> bool {
    publication.host_id == host_id
        && publication.workspace_id == workspace_id
        && publication.auth_generation == auth_generation
}

fn current_workspace_binding(
    journal: &Journal,
    host: &mut impl SetupHost,
    host_id: HostId,
    workspace_id: WorkspaceId,
) -> Result<lomi_remote_protocol::WorkspaceContext, SetupError> {
    let import_id = WorkspaceId::try_from(journal.workspace_import_id.clone())
        .map_err(|_| SetupError::JournalCorrupt)?;
    let LocalResult::WorkspaceBindings(snapshot) = host
        .request(LocalCall::WorkspaceBindingsRead(WorkspaceBindingsRead {
            import_ids: BoundedList(vec![import_id]),
        }))
        .map_err(|_| SetupError::HostUnavailable)?
    else {
        return Err(SetupError::ProtocolMismatch);
    };
    if snapshot.host_id != host_id || snapshot.bindings.0.len() != 1 {
        return Err(SetupError::BindingMismatch);
    }
    match &snapshot.bindings.0[0] {
        WorkspaceBinding::Active {
            import_id: current_import,
            workspace_id: current_workspace,
            root_path,
        } if *current_import == import_id
            && *current_workspace == workspace_id
            && root_path.as_str() == journal.workspace_root => {}
        _ => return Err(SetupError::BindingMismatch),
    }
    let LocalResult::WorkspaceState(state) = host
        .request(LocalCall::WorkspaceInspect(LocalWorkspaceRead {
            workspace_id,
        }))
        .map_err(|_| SetupError::HostUnavailable)?
    else {
        return Err(SetupError::ProtocolMismatch);
    };
    if state.context.workspace_id != workspace_id || state.context.runtime_id != snapshot.runtime_id
    {
        return Err(SetupError::BindingMismatch);
    }
    Ok(state.context)
}

fn current_consent_guard(
    journal: &Journal,
    host_id: HostId,
    workspace_id: WorkspaceId,
    host: &mut impl SetupHost,
    service: &mut impl SetupServiceControl,
    binding: &ServiceBinding,
) -> Result<LocalWorkspaceConsentAuthorized, SetupProblem> {
    let observation = host
        .observe(binding)
        .map_err(|_| SetupProblem::HostUnavailable)?;
    if observation.status.host_id != host_id
        || !host_matches(&observation, binding, &binding.profile_path)
    {
        return Err(SetupProblem::ServiceBindingChanged);
    }
    let auth = current_login_status(host).map_err(|_| SetupProblem::AuthorizationUnavailable)?;
    if !auth_ready(&auth) || journal.auth_generation != Some(auth.generation.0) {
        return Err(SetupProblem::AuthorizationContextChanged);
    }
    let observed_service = service
        .inspect(binding)
        .map_err(|_| SetupProblem::ServiceNotReady)?;
    if !observed_service.binding_matches
        || !observed_service.active
        || !observed_service.ipc_ready
        || (binding.mode == LocalStartMode::Manual && observed_service.autostart_enabled)
        || (binding.mode != LocalStartMode::Manual
            && (!observed_service.registration_present || !observed_service.autostart_enabled))
    {
        return Err(SetupProblem::ServiceNotReady);
    }
    let context = current_workspace_binding(journal, host, host_id, workspace_id)
        .map_err(|_| SetupProblem::WorkspaceUnavailable)?;
    if context.runtime_id != observation.status.runtime_id {
        return Err(SetupProblem::HostIdentityChanged);
    }
    Ok(LocalWorkspaceConsentAuthorized {
        workspace_id,
        expected_host_id: host_id,
        expected_authorization_generation: auth.generation,
        expected_context: context,
        expected_import_id: journal
            .workspace_import_id
            .clone()
            .try_into()
            .map_err(|_| SetupProblem::WorkspaceUnavailable)?,
        expected_root_path: journal
            .workspace_root
            .clone()
            .try_into()
            .map_err(|_| SetupProblem::WorkspaceUnavailable)?,
        operator_intent: Confirmed::Confirmed,
    })
}

fn options_has_renewal(choices: &SetupChoices) -> bool {
    choices.renew_share_consent
}

fn initial_journal(
    binding: &ServiceBinding,
    choices: &SetupChoices,
) -> Result<Journal, SetupError> {
    validate_choices(&choices)?;
    let profile_path = binding
        .profile_path
        .to_str()
        .ok_or(SetupError::ProfileRejected)?
        .to_owned();
    let root = choices
        .workspace_root
        .to_str()
        .ok_or(SetupError::InvalidOptions)?
        .to_owned();
    let import_id = WorkspaceId::from_bytes(*Uuid::new_v4().as_bytes())
        .map_err(|_| SetupError::JournalUnavailable)?;
    let provider = choices
        .auth_configuration
        .as_ref()
        .map(|configuration| storage_provider(configuration.provider).to_owned());
    let host_name = choices
        .host_name
        .as_ref()
        .ok_or(SetupError::InvalidOptions)?;
    Ok(Journal {
        revision: 0,
        setup_id: Uuid::new_v4().to_string(),
        stage: PersistedStage::Draft,
        binding: ServiceBinding {
            mode: binding.mode,
            account_name: binding.account_name.clone(),
            account: binding.account.clone(),
            profile_path: PathBuf::from(profile_path),
            executable_path: binding.executable_path.clone(),
        },
        host_id: None,
        host_name: Some(host_name.as_str().to_owned()),
        host_name_set_attempted: false,
        host_name_expected: None,
        auth_generation: None,
        login_operation_id: None,
        storage_provider: provider,
        workspace_import_id: String::from(import_id),
        workspace_id: None,
        workspace_name: choices.workspace_name.as_str().to_owned(),
        workspace_root: root,
        create_missing_workspace: choices.create_missing_workspace,
        import_attempted: false,
        shell_profile_id: None,
        share_remote: choices.share_remote,
        share_attempted: false,
        unshare_attempted: false,
    })
}

fn reconcile_choices(journal: &mut Journal, choices: &SetupChoices) -> Result<(), SetupError> {
    validate_choices(&choices)?;
    let host_name = choices
        .host_name
        .as_ref()
        .ok_or(SetupError::InvalidOptions)?;
    if journal.host_name.as_deref() != Some(host_name.as_str()) {
        // A newly reviewed name is a new reversible metadata intent, rather
        // than a replay of the previous attempt with a different precondition.
        journal.host_name_set_attempted = false;
        journal.host_name_expected = None;
    }
    journal.host_name = Some(host_name.as_str().to_owned());
    let root = choices
        .workspace_root
        .to_str()
        .ok_or(SetupError::InvalidOptions)?
        .to_owned();
    let name = choices.workspace_name.as_str();
    if journal.import_attempted
        && (journal.workspace_root != root || journal.workspace_name != name)
    {
        return Err(SetupError::ChoiceMismatch);
    }
    if journal.shell_profile_id.is_some() && journal.workspace_name != name {
        return Err(SetupError::ChoiceMismatch);
    }
    if !journal.import_attempted {
        journal.workspace_root = root;
        journal.workspace_name = name.to_owned();
        journal.create_missing_workspace = choices.create_missing_workspace;
    }
    journal.share_remote = choices.share_remote;
    if let Some(configuration) = &choices.auth_configuration {
        let provider = storage_provider(configuration.provider);
        if journal
            .storage_provider
            .as_deref()
            .is_some_and(|saved| saved != provider)
        {
            return Err(SetupError::ChoiceMismatch);
        }
        if journal.storage_provider.is_none() {
            journal.storage_provider = Some(provider.to_owned());
        }
    }
    Ok(())
}

fn validate_choices(choices: &SetupChoices) -> Result<(), SetupError> {
    if choices.host_name.is_none() {
        return Err(SetupError::InvalidOptions);
    }
    if (choices.share_remote && choices.disable_existing_share)
        || (!choices.share_remote && choices.renew_share_consent)
    {
        return Err(SetupError::InvalidOptions);
    }
    let root_text = choices
        .workspace_root
        .to_str()
        .ok_or(SetupError::InvalidOptions)?;
    if !root_text.is_empty()
        && (root_text.len() > PATH_LIMIT
            || !choices.workspace_root.is_absolute()
            || choices
                .workspace_root
                .components()
                .any(|component| matches!(component, Component::ParentDir)))
    {
        return Err(SetupError::InvalidOptions);
    }
    if choices.workspace_name.as_str().len() > NAME_LIMIT {
        return Err(SetupError::InvalidOptions);
    }
    if let Some(configuration) = &choices.auth_configuration {
        configuration
            .validate()
            .map_err(|_| SetupError::InvalidOptions)?;
    }
    Ok(())
}

fn resolve_workspace_choice(
    choices: &mut SetupChoices,
    current_directory: &Path,
) -> Result<(), SetupError> {
    if choices.workspace_root.as_os_str().is_empty() {
        if !current_directory.is_absolute() {
            return Err(SetupError::InvalidOptions);
        }
        choices.workspace_root = current_directory.to_path_buf();
    }
    validate_choices(choices)
}

fn resolve_host_name(
    choices: &mut SetupChoices,
    fallback: &LocalHostName,
) -> Result<(), SetupError> {
    if choices.host_name.is_none() {
        choices.host_name = Some(fallback.clone());
    }
    Ok(())
}

fn prepare_workspace_root(
    path: &str,
    create_missing: bool,
    import_attempted: bool,
    profile: &Path,
) -> Result<PathBuf, ()> {
    let original = PathBuf::from(path);
    if !original.is_absolute()
        || original
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(());
    }
    if path.len() > PATH_LIMIT || paths_overlap(&original, profile) {
        return Err(());
    }
    let canonical = if original.exists() {
        let canonical = original.canonicalize().map_err(|_| ())?;
        if !canonical.is_dir() {
            return Err(());
        }
        canonical
    } else {
        if !create_missing || import_attempted {
            return Err(());
        }
        // Canonicalize the deepest existing parent without creating anything;
        // the review is shown before this explicit directory-creation effect.
        let mut ancestor = original.as_path();
        let mut missing = Vec::new();
        while !ancestor.exists() {
            let name = ancestor.file_name().ok_or(())?;
            missing.push(name.to_os_string());
            ancestor = ancestor.parent().ok_or(())?;
        }
        let mut prospective = ancestor.canonicalize().map_err(|_| ())?;
        if !prospective.is_dir() {
            return Err(());
        }
        for component in missing.into_iter().rev() {
            prospective.push(component);
        }
        prospective
    };
    if canonical.parent().is_none_or(|parent| parent == canonical)
        || paths_overlap(&canonical, profile)
        || canonical
            .to_str()
            .is_none_or(|text| text.len() > PATH_LIMIT)
    {
        return Err(());
    }
    Ok(canonical)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    let left = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let right = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    left.starts_with(&right) || right.starts_with(&left)
}

fn host_matches(
    observation: &HostObservation,
    binding: &ServiceBinding,
    canonical_profile: &Path,
) -> bool {
    observation.profile_path == canonical_profile && observation.account == binding.account
}

fn valid_account(account: &SetupAccount) -> bool {
    #[cfg(unix)]
    {
        matches!(account, SetupAccount::Unix { uid, .. } if *uid != 0)
    }
    #[cfg(windows)]
    {
        matches!(account, SetupAccount::Windows { sid } if valid_windows_sid(sid))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = account;
        false
    }
}

fn valid_windows_sid(value: &str) -> bool {
    if value.len() > 184 || !value.is_ascii() {
        return false;
    }
    let Some(components) = value.strip_prefix("S-1-") else {
        return false;
    };
    let components = components.split('-').collect::<Vec<_>>();
    if components.is_empty() || components.len() > 16 {
        return false;
    }
    components.iter().enumerate().all(|(index, component)| {
        if component.is_empty()
            || !component.bytes().all(|byte| byte.is_ascii_digit())
            || (component.len() > 1 && component.starts_with('0'))
        {
            return false;
        }
        let Ok(value) = component.parse::<u64>() else {
            return false;
        };
        if index == 0 {
            value <= 0x0000_FFFF_FFFF_FFFF
        } else {
            value <= u32::MAX as u64
        }
    })
}

fn validate_binding(binding: &ServiceBinding) -> Result<(), SetupError> {
    if !valid_account(&binding.account)
        || binding.account_name.is_empty()
        || binding.account_name.len() > NAME_LIMIT
        || binding.account_name.chars().any(char::is_control)
        || !binding.profile_path.is_absolute()
        || binding
            .profile_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || !binding.executable_path.is_absolute()
        || binding
            .executable_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || binding
            .profile_path
            .to_str()
            .is_none_or(|path| path.len() > PATH_LIMIT)
        || binding
            .executable_path
            .to_str()
            .is_none_or(|path| path.len() > PATH_LIMIT)
    {
        return Err(SetupError::ProfileRejected);
    }
    Ok(())
}

fn same_binding(left: &ServiceBinding, right: &ServiceBinding) -> bool {
    left.mode == right.mode
        && left.account_name == right.account_name
        && left.account == right.account
        && left.profile_path == right.profile_path
        && left.executable_path == right.executable_path
}

fn storage_provider(provider: LocalAuthProvider) -> &'static str {
    match provider {
        LocalAuthProvider::ProtectedFile => "protectedFile",
        LocalAuthProvider::MacOsKeychain => "macOsKeychain",
        LocalAuthProvider::WindowsDpapi => "windowsDpapi",
        LocalAuthProvider::LinuxSecretService => "linuxSecretService",
    }
}

fn make_review(
    binding: &ServiceBinding,
    preflight: &HostPreflight,
    journal: &Journal,
    choices: &SetupChoices,
    root: &Path,
    git_repository_detected: bool,
) -> Result<SetupReview, SetupError> {
    Ok(SetupReview {
        release_version: preflight.release_version.clone(),
        host_id: journal
            .host_id
            .as_deref()
            .and_then(|value| HostId::try_from(value.to_owned()).ok()),
        host_name: choices
            .host_name
            .clone()
            .ok_or(SetupError::InvalidOptions)?,
        mode: binding.mode,
        account_name: binding.account_name.clone(),
        account: binding.account.clone(),
        profile_path: binding.profile_path.clone(),
        workspace_name: choices.workspace_name.clone(),
        workspace_root: root.to_path_buf(),
        create_missing_workspace: journal.create_missing_workspace,
        git_repository_detected,
        shell_name: choices.shell.name.clone(),
        shell_executable: choices.shell.executable.clone(),
        shell_args: choices.shell.args.0.clone(),
        environment_names: choices
            .shell
            .environment
            .0
            .iter()
            .map(|entry| entry.name.as_str().to_owned())
            .collect(),
        storage_provider: choices
            .auth_configuration
            .as_ref()
            .map(|configuration| storage_provider(configuration.provider)),
        share_remote: choices.share_remote,
        disable_existing_share: choices.disable_existing_share,
    })
}

fn incomplete(journal: &Journal, problem: SetupProblem) -> SetupOutcome {
    SetupOutcome::Incomplete {
        stage: journal.stage.into(),
        problem,
        host_id: journal
            .host_id
            .as_deref()
            .and_then(|value| HostId::try_from(value.to_owned()).ok()),
        workspace_id: journal.workspace_id().ok().flatten(),
    }
}

fn account_value(account: &SetupAccount) -> Value {
    match account {
        SetupAccount::Unix { uid, gid } => json!({"kind":"unix", "uid":uid, "gid":gid}),
        SetupAccount::Windows { sid } => json!({"kind":"windows", "sid":sid}),
    }
}

fn parse_account(value: &Value) -> Result<SetupAccount, SetupError> {
    let object = value.as_object().ok_or(SetupError::JournalCorrupt)?;
    match object.get("kind").and_then(Value::as_str) {
        Some("unix") => {
            let object = exact_object(value, &["kind", "uid", "gid"])?;
            Ok(SetupAccount::Unix {
                uid: u32::try_from(get_u64(object, "uid")?)
                    .map_err(|_| SetupError::JournalCorrupt)?,
                gid: u32::try_from(get_u64(object, "gid")?)
                    .map_err(|_| SetupError::JournalCorrupt)?,
            })
        }
        Some("windows") => {
            let object = exact_object(value, &["kind", "sid"])?;
            let sid = get_str(object, "sid")?.to_owned();
            if !valid_windows_sid(&sid) {
                return Err(SetupError::JournalCorrupt);
            }
            Ok(SetupAccount::Windows { sid })
        }
        _ => Err(SetupError::JournalCorrupt),
    }
}

fn journal_value(journal: &Journal) -> Value {
    json!({
        "version": JOURNAL_VERSION,
        "revision": journal.revision,
        "setupId": journal.setup_id,
        "stage": stage_text(journal.stage),
        "binding": {
            "mode": mode_text(journal.binding.mode),
            "accountName": journal.binding.account_name,
            "account": account_value(&journal.binding.account),
            "profilePath": journal.binding.profile_path,
            "executablePath": journal.binding.executable_path,
        },
        "hostId": journal.host_id,
        "hostName": journal.host_name,
        "hostNameSetAttempted": journal.host_name_set_attempted,
        "hostNameExpected": journal.host_name_expected,
        "authGeneration": journal.auth_generation,
        "loginOperationId": journal.login_operation_id,
        "storageProvider": journal.storage_provider,
        "workspaceImportId": journal.workspace_import_id,
        "workspaceId": journal.workspace_id,
        "workspaceName": journal.workspace_name,
        "workspaceRoot": journal.workspace_root,
        "createMissingWorkspace": journal.create_missing_workspace,
        "importAttempted": journal.import_attempted,
        "shellProfileId": journal.shell_profile_id,
        "shareRemote": journal.share_remote,
        "shareAttempted": journal.share_attempted,
        "unshareAttempted": journal.unshare_attempted,
    })
}

fn parse_journal(bytes: &[u8]) -> Result<Journal, SetupError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| SetupError::JournalCorrupt)?;
    let object = exact_object_with_optional(
        &value,
        &[
            "version",
            "revision",
            "setupId",
            "stage",
            "binding",
            "hostId",
            "authGeneration",
            "loginOperationId",
            "storageProvider",
            "workspaceImportId",
            "workspaceId",
            "workspaceName",
            "workspaceRoot",
            "createMissingWorkspace",
            "importAttempted",
            "shellProfileId",
            "shareRemote",
            "shareAttempted",
            "unshareAttempted",
        ],
        &["hostName", "hostNameSetAttempted", "hostNameExpected"],
    )?;
    if get_u64(object, "version")? != JOURNAL_VERSION {
        return Err(SetupError::JournalCorrupt);
    }
    let binding_value = object.get("binding").ok_or(SetupError::JournalCorrupt)?;
    let binding_object = exact_object(
        binding_value,
        &[
            "mode",
            "accountName",
            "account",
            "profilePath",
            "executablePath",
        ],
    )?;
    let binding = ServiceBinding {
        mode: parse_mode(get_str(binding_object, "mode")?)?,
        account_name: get_str(binding_object, "accountName")?.to_owned(),
        account: parse_account(
            binding_object
                .get("account")
                .ok_or(SetupError::JournalCorrupt)?,
        )?,
        profile_path: PathBuf::from(get_str(binding_object, "profilePath")?),
        executable_path: PathBuf::from(get_str(binding_object, "executablePath")?),
    };
    validate_binding(&binding).map_err(|_| SetupError::JournalCorrupt)?;
    let setup_id = get_str(object, "setupId")?.to_owned();
    if Uuid::parse_str(&setup_id).is_err() || setup_id.len() != 36 {
        return Err(SetupError::JournalCorrupt);
    }
    let workspace_import_id = get_str(object, "workspaceImportId")?.to_owned();
    WorkspaceId::try_from(workspace_import_id.clone()).map_err(|_| SetupError::JournalCorrupt)?;
    let workspace_id = get_opt_str(object, "workspaceId")?.map(ToOwned::to_owned);
    if let Some(value) = &workspace_id {
        WorkspaceId::try_from(value.clone()).map_err(|_| SetupError::JournalCorrupt)?;
    }
    let host_id = get_opt_str(object, "hostId")?.map(ToOwned::to_owned);
    if let Some(value) = &host_id {
        HostId::try_from(value.clone()).map_err(|_| SetupError::JournalCorrupt)?;
    }
    let host_name = match object.get("hostName") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => {
            LocalHostName::try_from(value.clone()).map_err(|_| SetupError::JournalCorrupt)?;
            Some(value.clone())
        }
        _ => return Err(SetupError::JournalCorrupt),
    };
    let host_name_set_attempted = object
        .get("hostNameSetAttempted")
        .map(|_| get_bool(object, "hostNameSetAttempted"))
        .transpose()?
        .unwrap_or(false);
    if host_name_set_attempted && host_name.is_none() {
        return Err(SetupError::JournalCorrupt);
    }
    let host_name_expected = match object.get("hostNameExpected") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if host_name_set_attempted => {
            LocalHostName::try_from(value.clone()).map_err(|_| SetupError::JournalCorrupt)?;
            Some(value.clone())
        }
        _ => return Err(SetupError::JournalCorrupt),
    };
    let login_operation_id = get_opt_str(object, "loginOperationId")?.map(ToOwned::to_owned);
    if let Some(value) = &login_operation_id {
        OperationId::try_from(value.clone()).map_err(|_| SetupError::JournalCorrupt)?;
    }
    let storage_provider = get_opt_str(object, "storageProvider")?.map(ToOwned::to_owned);
    if storage_provider.as_deref().is_some_and(|value| {
        !matches!(
            value,
            "protectedFile" | "macOsKeychain" | "windowsDpapi" | "linuxSecretService"
        )
    }) {
        return Err(SetupError::JournalCorrupt);
    }
    let workspace_name = get_str(object, "workspaceName")?.to_owned();
    if workspace_name.is_empty()
        || workspace_name.len() > NAME_LIMIT
        || LocalProjectName::try_from(workspace_name.clone()).is_err()
    {
        return Err(SetupError::JournalCorrupt);
    }
    let workspace_root = get_str(object, "workspaceRoot")?.to_owned();
    let workspace_root_path = Path::new(&workspace_root);
    if workspace_root.is_empty()
        || workspace_root.len() > PATH_LIMIT
        || !workspace_root_path.is_absolute()
        || workspace_root_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SetupError::JournalCorrupt);
    }
    let journal = Journal {
        revision: get_u64(object, "revision")?,
        setup_id,
        stage: parse_stage(get_str(object, "stage")?)?,
        binding,
        host_id,
        host_name,
        host_name_set_attempted,
        host_name_expected,
        auth_generation: get_opt_u64(object, "authGeneration")?,
        login_operation_id,
        storage_provider,
        workspace_import_id,
        workspace_id,
        workspace_name,
        workspace_root,
        create_missing_workspace: get_bool(object, "createMissingWorkspace")?,
        import_attempted: get_bool(object, "importAttempted")?,
        shell_profile_id: get_opt_str(object, "shellProfileId")?.map(ToOwned::to_owned),
        share_remote: get_bool(object, "shareRemote")?,
        share_attempted: get_bool(object, "shareAttempted")?,
        unshare_attempted: get_bool(object, "unshareAttempted")?,
    };
    if journal.stage != PersistedStage::Draft
        && (journal.host_id.is_none() || journal.auth_generation.is_none())
    {
        return Err(SetupError::JournalCorrupt);
    }
    if matches!(
        journal.stage,
        PersistedStage::LocalConfigured
            | PersistedStage::ServiceReady
            | PersistedStage::SharePending
            | PersistedStage::Shared
            | PersistedStage::LocalOnly
    ) && (journal.workspace_id.is_none() || journal.shell_profile_id.is_none())
    {
        return Err(SetupError::JournalCorrupt);
    }
    if journal.revision == 0
        || (journal.workspace_id.is_some() && !journal.import_attempted)
        || (journal.shell_profile_id.is_some() && journal.workspace_id.is_none())
        || (journal.share_attempted && journal.workspace_id.is_none())
        || (journal.unshare_attempted && journal.workspace_id.is_none())
    {
        return Err(SetupError::JournalCorrupt);
    }
    Ok(journal)
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, SetupError> {
    let object = value.as_object().ok_or(SetupError::JournalCorrupt)?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(SetupError::JournalCorrupt);
    }
    Ok(object)
}

fn exact_object_with_optional<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, SetupError> {
    let object = value.as_object().ok_or(SetupError::JournalCorrupt)?;
    if required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err(SetupError::JournalCorrupt);
    }
    Ok(object)
}

fn get_str<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, SetupError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(SetupError::JournalCorrupt)
}

fn get_opt_str<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, SetupError> {
    match object.get(key).ok_or(SetupError::JournalCorrupt)? {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value)),
        _ => Err(SetupError::JournalCorrupt),
    }
}

fn get_u64(object: &serde_json::Map<String, Value>, key: &str) -> Result<u64, SetupError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(SetupError::JournalCorrupt)
}

fn get_opt_u64(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, SetupError> {
    match object.get(key).ok_or(SetupError::JournalCorrupt)? {
        Value::Null => Ok(None),
        Value::Number(number) => number.as_u64().map(Some).ok_or(SetupError::JournalCorrupt),
        _ => Err(SetupError::JournalCorrupt),
    }
}

fn get_bool(object: &serde_json::Map<String, Value>, key: &str) -> Result<bool, SetupError> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(SetupError::JournalCorrupt)
}

fn stage_text(stage: PersistedStage) -> &'static str {
    match stage {
        PersistedStage::Draft => "draft",
        PersistedStage::Enrolled => "enrolled",
        PersistedStage::LocalConfigured => "localConfigured",
        PersistedStage::ServiceReady => "serviceReady",
        PersistedStage::SharePending => "sharePending",
        PersistedStage::Shared => "shared",
        PersistedStage::LocalOnly => "localOnly",
    }
}

fn parse_stage(value: &str) -> Result<PersistedStage, SetupError> {
    match value {
        "draft" => Ok(PersistedStage::Draft),
        "enrolled" => Ok(PersistedStage::Enrolled),
        "localConfigured" => Ok(PersistedStage::LocalConfigured),
        "serviceReady" => Ok(PersistedStage::ServiceReady),
        "sharePending" => Ok(PersistedStage::SharePending),
        "shared" => Ok(PersistedStage::Shared),
        "localOnly" => Ok(PersistedStage::LocalOnly),
        _ => Err(SetupError::JournalCorrupt),
    }
}

fn mode_text(mode: LocalStartMode) -> &'static str {
    match mode {
        LocalStartMode::Manual => "manual",
        LocalStartMode::Login => "login",
        LocalStartMode::Boot => "boot",
    }
}

fn parse_mode(value: &str) -> Result<LocalStartMode, SetupError> {
    match value {
        "manual" => Ok(LocalStartMode::Manual),
        "login" => Ok(LocalStartMode::Login),
        "boot" => Ok(LocalStartMode::Boot),
        _ => Err(SetupError::JournalCorrupt),
    }
}

fn map_journal_error(error: JournalError) -> SetupError {
    match error {
        JournalError::InvalidProfile => SetupError::ProfileRejected,
        JournalError::Busy => SetupError::JournalUnavailable,
        JournalError::TooLarge => SetupError::JournalCorrupt,
        JournalError::Storage => SetupError::JournalUnavailable,
    }
}
