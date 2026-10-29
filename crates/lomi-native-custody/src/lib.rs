//! Host-owned native process custody for the qualified macOS runtime.
//!
//! The type and wire contracts compile on every target. Execution remains
//! explicitly unavailable unless the exact admitted Darwin ABI is present.

use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

mod process_identity;
pub use process_identity::Identity;

/// Native work performed while a durable kernel resource coalition is held.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Attempt,
    VersionProbe,
    Resolver,
    Collector,
    AccountTerminal,
    NativeGit,
}

/// Optional Host-supplied request binding for a NativeGit scope.
///
/// The Host verifies these values against the prepared plan and its durable
/// proof. Persisting them does not authorize a plan or prove its completion.
/// A Git Host should run every command in one prepared plan under one boundary.
/// This binding does not establish per-command or whole-plan completion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeBinding {
    pub exact_operation: Option<String>,
    pub request_hash: Option<String>,
    pub plan_hash: Option<String>,
    pub fence: Option<String>,
    pub host_runtime: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub operation_id: String,
    #[serde(default)]
    pub parent_operation_id: Option<String>,
    #[serde(default)]
    pub physical_account_root: Option<PathBuf>,
    #[serde(default)]
    pub storage_root: Option<PathBuf>,
    /// Empty only for `NativeGit`; agent purposes retain their account binding.
    pub account_id: String,
    /// Zero only for `NativeGit`; agent purposes retain their auth revision.
    pub auth_revision: u64,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub generation: Option<u64>,
    pub project_root: PathBuf,
    pub purpose: Purpose,
    #[serde(default)]
    pub binding: Option<ScopeBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSpec {
    pub program: PathBuf,
    pub arguments: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub policy: Policy,
    #[serde(default)]
    pub io: NativeIo,
}

/// Selects an explicit sandbox contract. The default Agent mode preserves the
/// existing per-user worker policy; NativeGit is a separate code-execution
/// capability granted only to a plan-bound Git scope.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    rename_all = "snake_case",
    tag = "kind",
    content = "nativeGit",
    deny_unknown_fields
)]
pub enum PolicyMode {
    #[default]
    Agent,
    NativeGit(NativeGitPolicy),
}

impl PolicyMode {
    /// Select the explicit NativeGit code-execution capability. Callers must
    /// derive its roots and credential socket from the captured Host runtime,
    /// then bind the resulting spec to the exact approved Git plan.
    pub fn native_git(policy: NativeGitPolicy) -> Self {
        Self::NativeGit(policy)
    }
}

/// Host-captured support for one authorized native Git plan. These roots must
/// come from the Host's captured runtime/environment and repository lease,
/// never from untrusted command arguments or arbitrary Git config strings.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeGitPolicy {
    /// Executable search roots captured by the Host, including required Git
    /// hooks and helpers. The project root is admitted separately for hooks.
    #[serde(default)]
    pub executable_roots: Vec<PathBuf>,
    /// Additional read-only runtime/configuration roots captured by the Host.
    #[serde(default)]
    pub runtime_read_roots: Vec<PathBuf>,
    /// External common Git directories covered by the Host's physical lease.
    #[serde(default)]
    pub repository_write_roots: Vec<PathBuf>,
    /// The exact plan is a remote operation and may use outbound networking.
    #[serde(default)]
    pub outbound_network: bool,
    /// Only the captured SSH_AUTH_SOCK may be used as a Unix credential
    /// socket; all other Unix delegation sockets remain denied.
    #[serde(default)]
    pub credential_socket: Option<PathBuf>,
}

fn is_agent_mode(mode: &PolicyMode) -> bool {
    matches!(mode, PolicyMode::Agent)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum NativeIo {
    #[default]
    Pipes,
    Pty {
        rows: u16,
        cols: u16,
    },
}

/// Explicit sandbox policy; all access remains caller-selected and validated.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub project_root: PathBuf,
    /// Present for Agent scopes. NativeGit uses explicit Host-captured
    /// credential/runtime roots and has no ambient account-root grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_root: Option<PathBuf>,
    pub temp_root: PathBuf,
    /// Omitted from serialized Agent policies to preserve their existing wire
    /// representation and sandbox profile byte-for-byte.
    #[serde(default, skip_serializing_if = "is_agent_mode")]
    pub mode: PolicyMode,
    pub runtime_reads: Vec<PathBuf>,
    #[serde(default)]
    pub protected_reads: Vec<PathBuf>,
    #[serde(default)]
    pub blocked_reads: Vec<PathBuf>,
    #[serde(default)]
    pub runtime_read_roots: Vec<PathBuf>,
    #[serde(default)]
    pub codex_preferences: bool,
    #[serde(default)]
    pub loopback_tcp_ports: Vec<u16>,
    #[serde(default)]
    pub loopback_listener: bool,
    #[serde(default)]
    pub unix_sockets: Vec<PathBuf>,
    #[serde(default)]
    pub allow_native_tools: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Member {
    pub identity: Identity,
    pub pid_version: u32,
    pub resource_coalition: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetiredReceipt {
    pub operation_id: String,
    pub boot: String,
    pub resource_coalition: u64,
    pub sealed_job: String,
}

/// Proves that a NativeGit worker from a different boot cannot still be
/// running. The release bit records only whether custody attempted to release
/// its helper; it does not prove that a NativeGit mutator started or completed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreviousBootReceipt {
    pub operation_id: String,
    pub old_boot: String,
    pub resource_coalition: u64,
    pub sealed_job: String,
    pub release_attempted: bool,
}

pub struct Transport {
    pub stdin: fs::File,
    pub stdout: fs::File,
    pub stderr: fs::File,
}

impl Scope {
    /// Validate purpose-specific identity constraints without granting policy
    /// defaults or converting a NativeGit scope into an agent account scope.
    pub fn validate(&self, spec: &NativeSpec, base: &std::path::Path) -> Result<(), String> {
        let failure =
            || "The native host boundary cannot prove ownership or retirement.".to_owned();
        if self.operation_id.len() != 32
            || !self.operation_id.bytes().all(|b| b.is_ascii_hexdigit())
            || self.project_root != spec.policy.project_root
        {
            return Err(failure());
        }
        match &self.purpose {
            Purpose::NativeGit => {
                let binding = self.binding.as_ref().ok_or_else(failure)?;
                if !self.account_id.is_empty()
                    || self.auth_revision != 0
                    || self.parent_operation_id.is_some()
                    || self.physical_account_root.is_some()
                    || self.storage_root.is_some()
                    || self.task_id.is_some()
                    || self.attempt_id.is_some()
                    || self.generation.is_some()
                    || !matches!(&spec.policy.mode, PolicyMode::NativeGit(_))
                    || spec.policy.account_root.is_some()
                    || !valid_text(binding.exact_operation.as_deref(), 200)
                    || !valid_hash(binding.request_hash.as_deref())
                    || !valid_hash(binding.plan_hash.as_deref())
                    || !valid_text(binding.fence.as_deref(), 200)
                    || !valid_text(binding.host_runtime.as_deref(), 200)
                {
                    return Err(failure());
                }
            }
            _ => {
                if self.account_id.is_empty()
                    || self.account_id.len() > 200
                    || self.account_id.chars().any(char::is_control)
                    || self.auth_revision == 0
                    || self.binding.is_some()
                    || !matches!(&spec.policy.mode, PolicyMode::Agent)
                    || spec.policy.account_root.is_none()
                    || self.parent_operation_id.as_ref().is_some_and(|parent| {
                        parent.is_empty()
                            || parent == &self.operation_id
                            || parent.len() > 200
                            || parent.chars().any(char::is_control)
                    })
                    || self
                        .physical_account_root
                        .as_ref()
                        .is_some_and(|root| spec.policy.account_root.as_ref() != Some(root))
                    || self.storage_root.as_ref().is_some_and(|root| {
                        let Some(parent) = self.parent_operation_id.as_deref() else {
                            return true;
                        };
                        base != root
                            .join("host-boundaries/parents")
                            .join(digest(parent.as_bytes()))
                    })
                {
                    return Err(failure());
                }
            }
        }
        Ok(())
    }
}

fn valid_text(value: Option<&str>, limit: usize) -> bool {
    value.is_some_and(|value| {
        !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
    })
}

fn valid_hash(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{Boundary, EffectGuard, EffectScope};

#[cfg(not(target_os = "macos"))]
mod unsupported;
#[cfg(not(target_os = "macos"))]
pub use unsupported::{Boundary, EffectGuard, EffectScope};

/// Dispatch a staged worker/native-child invocation before the Host CLI parser.
pub fn entry() -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        macos::entry()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Retire a durably recorded NativeGit boundary from an earlier boot.
///
/// `None` means the record belongs to the current boot and should be handled
/// by normal `Boundary::restore`. A receipt proves only process/job retirement,
/// never Git operation completion.
pub fn retire_previous_boot(
    root: &std::path::Path,
    expected_scope: &Scope,
    expected_spec: &NativeSpec,
) -> Result<Option<PreviousBootReceipt>, String> {
    #[cfg(target_os = "macos")]
    {
        macos::retire_previous_boot(root, expected_scope, expected_spec)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (root, expected_scope, expected_spec);
        Err(unavailable())
    }
}

/// Stage this executable as the isolated launchd supervisor.
pub fn staged_worker(storage_root: &std::path::Path) -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    {
        macos::staged_worker(storage_root)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = storage_root;
        Err(unavailable())
    }
}

#[cfg(not(target_os = "macos"))]
fn unavailable() -> String {
    "Native custody is unavailable outside its admitted Darwin ABI.".into()
}

impl NativeSpec {
    /// Apply the bounded wire, executable identity and sandbox validation.
    pub fn validate(&self) -> Result<(), String> {
        let failure =
            || "The native host boundary cannot prove ownership or retirement.".to_owned();
        if matches!(
            self.io,
            NativeIo::Pty { rows: 0, .. } | NativeIo::Pty { cols: 0, .. }
        ) || self.program.canonicalize().map_err(|_| failure())? != self.program
            || self.cwd.canonicalize().map_err(|_| failure())? != self.cwd
            || self.arguments.len() > 64
            || self
                .arguments
                .iter()
                .any(|argument| argument.len() > 65536 || argument.contains('\0'))
            || self.environment.len() > 64
            || self.environment.iter().any(|(key, value)| {
                key.is_empty()
                    || key.contains(['=', '\0'])
                    || value.len() > 65536
                    || value.contains('\0')
            })
        {
            return Err(failure());
        }
        #[cfg(target_os = "macos")]
        {
            process_identity::executable_identity(&self.program)?;
            macos::validate_policy(&self.policy)?;
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(unavailable())
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn new_id() -> Result<String, String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| "Cannot create runtime identity.")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Inspect a process as a qualified kernel coalition member.
pub fn member(pid: u32) -> Result<Member, String> {
    #[cfg(target_os = "macos")]
    {
        macos::member(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        Err(unavailable())
    }
}

/// Find the active host-effect scope for a qualified native process.
pub fn registered_scope(pid: u32) -> Result<Option<(Scope, std::sync::Arc<EffectScope>)>, String> {
    #[cfg(target_os = "macos")]
    {
        macos::registered_scope(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        Err(unavailable())
    }
}
