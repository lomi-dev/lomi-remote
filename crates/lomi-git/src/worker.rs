use crate::{GitServiceError, RequestControl};
use anyhow::Result;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use std::{fs::File, io::Read};
use wasmtime::{
    Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, UpdateDeadline,
};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{
    WasiCtxBuilder,
    filesystem::FsPerms,
    p1::{self, WasiP1Ctx},
};

const MAX_MODULE_BYTES: usize = 8 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_STDOUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 4096;
const FUEL_BUDGET: u64 = 100_000_000;
const RESTORE_FUEL_BUDGET: u64 = 5_000_000_000;
const MEMORY_BUDGET: usize = 128 * 1024 * 1024;
const RESTORE_MEMORY_BUDGET: usize = 384 * 1024 * 1024;
const MAX_RESTORE_BLOB_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const RESTORE_INDEX_OUTPUT_FILE: &str = ".lomi-restore-index-output";
const OWNER_CONTEXT_FILE: &str = "context.json";
const MAX_OWNER_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_OWNER_CONTEXT_BYTES: usize = 4 * 1024 * 1024 + 4096;
const TIMER_POLL: Duration = Duration::from_millis(10);
const MODULE_SHA256: &str = "4f8641721722b1f56ed4453c3f67369c2e7ec1abd3c602c0ee3578275b9ab0e4";

/// Inspect the embedded artifact without creating an engine, opening a
/// repository, executing Git, or accessing the network.
pub(crate) fn embedded_integrity() -> bool {
    let wasm = include_bytes!("../assets/lomi-git-read-worker.wasm");
    !wasm.is_empty()
        && wasm.len() <= MAX_MODULE_BYTES
        && wasm.starts_with(b"\0asm\x01\0\0\0")
        && format!("{:x}", Sha256::digest(wasm)) == MODULE_SHA256
}

const ALLOWED_WASI_IMPORTS: &[&str] = &[
    "args_get",
    "args_sizes_get",
    "environ_get",
    "environ_sizes_get",
    "clock_time_get",
    "clock_res_get",
    "random_get",
    "proc_exit",
    "sched_yield",
    "fd_advise",
    "fd_allocate",
    "fd_close",
    "fd_datasync",
    "fd_fdstat_get",
    "fd_fdstat_set_flags",
    "fd_filestat_get",
    "fd_filestat_set_size",
    "fd_filestat_set_times",
    "fd_pread",
    "fd_prestat_get",
    "fd_prestat_dir_name",
    "fd_pwrite",
    "fd_read",
    "fd_readdir",
    "fd_renumber",
    "fd_seek",
    "fd_sync",
    "fd_tell",
    "fd_write",
    "path_create_directory",
    "path_filestat_get",
    "path_filestat_set_times",
    "path_link",
    "path_open",
    "path_readlink",
    "path_remove_directory",
    "path_rename",
    "path_symlink",
    "path_unlink_file",
    "poll_oneoff",
];

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn is_lower_hex(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.len() <= maximum_bytes.saturating_mul(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_owner_config_hex(value: &str) -> bool {
    value.len().is_multiple_of(2)
        && value.len() <= MAX_OWNER_CONFIG_BYTES.saturating_mul(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_status_char(status: char) -> bool {
    " MADRCUT?!".contains(status)
}

fn validate_selected_change(
    change: &GuestSelectedChange,
    path: &[u8],
    selected_kind: GuestSelectedNodeKind,
) -> Result<(), GitServiceError> {
    if change.path_hex != encode_hex(path)
        || change
            .original_path_hex
            .as_ref()
            .is_some_and(|original| !is_lower_hex(original, 3072))
        || !valid_status_char(change.index)
        || !valid_status_char(change.worktree)
        || change.selected_kind != selected_kind
    {
        return Err(GitServiceError::ExecutorFailed);
    }
    Ok(())
}

fn validate_owner_context(context: &OwnerLocalGitContext) -> Result<(), GitServiceError> {
    if context.version != 1
        || context
            .common_config_hex
            .as_deref()
            .is_some_and(|value| !is_owner_config_hex(value))
        || context
            .worktree_config_hex
            .as_deref()
            .is_some_and(|value| !is_owner_config_hex(value))
    {
        return Err(GitServiceError::ExecutorFailed);
    }
    let serialized = serde_json::to_vec(context).map_err(|_| GitServiceError::ExecutorFailed)?;
    if serialized.len() > MAX_OWNER_CONTEXT_BYTES {
        return Err(GitServiceError::ResourceLimit);
    }
    Ok(())
}

fn canonical_private_directory(
    path: &std::path::Path,
) -> Result<std::path::PathBuf, GitServiceError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| GitServiceError::ExecutorFailed)?;
    if !metadata.file_type().is_dir() {
        return Err(GitServiceError::ExecutorFailed);
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| GitServiceError::ExecutorFailed)?;
    let opened_metadata =
        std::fs::symlink_metadata(&canonical).map_err(|_| GitServiceError::ExecutorFailed)?;
    if !opened_metadata.file_type().is_dir() {
        return Err(GitServiceError::ExecutorFailed);
    }
    Ok(canonical)
}

fn paths_overlap(left: &std::path::Path, right: &std::path::Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn read_owner_context(
    input_dir: &std::path::Path,
) -> Result<OwnerLocalGitContext, GitServiceError> {
    let input_dir = canonical_private_directory(input_dir)?;
    let mut entries = std::fs::read_dir(&input_dir).map_err(|_| GitServiceError::ExecutorFailed)?;
    let first = entries
        .next()
        .transpose()
        .map_err(|_| GitServiceError::ExecutorFailed)?
        .ok_or(GitServiceError::ExecutorFailed)?;
    if first.file_name() != OWNER_CONTEXT_FILE || entries.next().is_some() {
        return Err(GitServiceError::ExecutorFailed);
    }
    let path = input_dir.join(OWNER_CONTEXT_FILE);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| GitServiceError::ExecutorFailed)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_OWNER_CONTEXT_BYTES as u64 {
        return Err(GitServiceError::ExecutorFailed);
    }
    let file = File::open(&path).map_err(|_| GitServiceError::ExecutorFailed)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| GitServiceError::ExecutorFailed)?;
    if !opened_metadata.is_file() || opened_metadata.len() != metadata.len() {
        return Err(GitServiceError::ExecutorFailed);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_OWNER_CONTEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| GitServiceError::ExecutorFailed)?;
    if bytes.len() > MAX_OWNER_CONTEXT_BYTES || bytes.len() as u64 != metadata.len() {
        return Err(GitServiceError::ExecutorFailed);
    }
    let context: OwnerLocalGitContext =
        serde_json::from_slice(&bytes).map_err(|_| GitServiceError::ExecutorFailed)?;
    validate_owner_context(&context)?;
    Ok(context)
}

fn canonical_owner_local_directories(
    snapshot_path: &std::path::Path,
    input_dir: &std::path::Path,
    output_dir: Option<&std::path::Path>,
) -> Result<
    (
        std::path::PathBuf,
        std::path::PathBuf,
        Option<std::path::PathBuf>,
    ),
    GitServiceError,
> {
    let snapshot = canonical_private_directory(snapshot_path)?;
    let input = canonical_private_directory(input_dir)?;
    if paths_overlap(&snapshot, &input) {
        return Err(GitServiceError::ExecutorFailed);
    }
    let output = output_dir.map(canonical_private_directory).transpose()?;
    if let Some(output) = output.as_ref() {
        if paths_overlap(&snapshot, &output) || paths_overlap(&input, &output) {
            return Err(GitServiceError::ExecutorFailed);
        }
        if std::fs::read_dir(output)
            .map_err(|_| GitServiceError::ExecutorFailed)?
            .next()
            .is_some()
        {
            return Err(GitServiceError::ExecutorFailed);
        }
    }
    Ok((snapshot, input, output))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestStatus {
    pub head: String,
    pub entries: Vec<GuestStatusEntry>,
    pub truncated: bool,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestStatusEntry {
    pub path_hex: String,
    pub index: Option<String>,
    pub worktree: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestDiff {
    pub files: Vec<GuestDiffFile>,
    pub truncated: bool,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestDiffFile {
    pub path_hex: String,
    pub binary: bool,
    pub hunks: Vec<GuestDiffHunk>,
    pub truncated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestDiffHunk {
    pub old_start: u64,
    pub new_start: u64,
    pub lines: Vec<GuestDiffLine>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestDiffLine {
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestLog {
    pub commits: Vec<GuestCommit>,
    pub truncated: bool,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestCommit {
    pub object_id: String,
    pub subject: String,
    pub author: String,
    pub timestamp_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestMutation {
    pub object_ids: Vec<String>,
    #[serde(default)]
    pub commit_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GuestRestoreGuard {
    pub path: Vec<u8>,
    pub original_path: Option<Vec<u8>>,
    pub index: char,
    pub worktree: char,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestSelectedChange {
    pub path_hex: String,
    pub original_path_hex: Option<String>,
    pub index: char,
    pub worktree: char,
    pub selected_kind: GuestSelectedNodeKind,
    pub core_symlinks: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum GuestSelectedNodeKind {
    Absent,
    File,
    Symlink,
    Directory,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OwnerLocalGitContext {
    pub version: u32,
    pub selected_kind: GuestSelectedNodeKind,
    pub common_config_hex: Option<String>,
    pub worktree_config_hex: Option<String>,
}

impl OwnerLocalGitContext {
    pub(crate) fn new(
        selected_kind: GuestSelectedNodeKind,
        common_config: Option<&[u8]>,
        worktree_config: Option<&[u8]>,
    ) -> Result<Self, GitServiceError> {
        let context = Self {
            version: 1,
            selected_kind,
            common_config_hex: common_config.map(encode_hex),
            worktree_config_hex: worktree_config.map(encode_hex),
        };
        validate_owner_context(&context)?;
        Ok(context)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuestRestoreIndexMetadata {
    pub change: GuestSelectedChange,
    pub index_path_hex: String,
    pub blob_object_id: String,
    pub mode: u32,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct GuestRestoreIndex {
    pub change: GuestSelectedChange,
    pub index_path_hex: String,
    pub blob_object_id: String,
    pub mode: u32,
    pub size: u64,
    pub sha256: String,
}

struct WorkerState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

struct WasiGitExecutor {
    engine: Engine,
    module: Module,
}

fn set_request_epoch_deadline<T: 'static>(
    store: &mut Store<T>,
    control: RequestControl,
    continued_ticks: Option<Arc<AtomicUsize>>,
) {
    store.epoch_deadline_callback(move |_| {
        control
            .check()
            .map_err(|_| wasmtime::Error::msg("Git request interrupted"))?;
        if let Some(ticks) = &continued_ticks {
            ticks.fetch_add(1, Ordering::AcqRel);
        }
        // Epochs belong to the shared Engine. A tick can be caused by another
        // request's timer, so this store extends its own deadline unless its
        // own cancellation token or absolute deadline has expired.
        Ok(UpdateDeadline::Continue(1))
    });
    store.set_epoch_deadline(1);
}

impl WasiGitExecutor {
    fn embedded() -> Result<Self, GitServiceError> {
        static EXECUTOR: OnceLock<Result<Arc<WasiGitExecutor>, GitServiceError>> = OnceLock::new();
        EXECUTOR
            .get_or_init(|| Self::load_embedded().map(Arc::new))
            .as_ref()
            .map(Arc::clone)
            .map_err(|error| *error)
            .map(|executor| {
                Arc::try_unwrap(executor).unwrap_or_else(|executor| {
                    // The one-time executor is intentionally shared. Clone only its
                    // cheap Wasmtime handles for a request.
                    Self {
                        engine: executor.engine.clone(),
                        module: executor.module.clone(),
                    }
                })
            })
    }

    fn load_embedded() -> Result<Self, GitServiceError> {
        let wasm = include_bytes!("../assets/lomi-git-read-worker.wasm");
        if wasm.is_empty() || wasm.len() > MAX_MODULE_BYTES {
            return Err(GitServiceError::ExecutorUnavailable);
        }
        let digest = Sha256::digest(wasm);
        let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        if actual != MODULE_SHA256 {
            return Err(GitServiceError::ExecutorUnavailable);
        }
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config).map_err(|_| GitServiceError::ExecutorUnavailable)?;
        let module =
            Module::new(&engine, wasm).map_err(|_| GitServiceError::ExecutorUnavailable)?;
        for import in module.imports() {
            if import.module() != "wasi_snapshot_preview1"
                || !ALLOWED_WASI_IMPORTS.contains(&import.name())
            {
                return Err(GitServiceError::ExecutorUnavailable);
            }
        }
        Ok(Self { engine, module })
    }

    fn status(
        &self,
        snapshot_path: &std::path::Path,
        offset: usize,
        limit: usize,
        control: &RequestControl,
    ) -> Result<GuestStatus, GitServiceError> {
        self.execute(
            snapshot_path,
            serde_json::json!({
            "operation": "status",
            "offset": offset,
            "limit": limit,
            }),
            control,
        )
    }

    fn selected_change(
        &self,
        snapshot_path: &std::path::Path,
        path: &[u8],
        input_dir: &std::path::Path,
        control: &RequestControl,
    ) -> Result<GuestSelectedChange, GitServiceError> {
        self.execute_with_owner_io(
            snapshot_path,
            input_dir,
            None,
            serde_json::json!({
                "operation": "selectedChange",
                "pathHex": encode_hex(path),
            }),
            control,
            FsPerms::ReadOnly,
            MEMORY_BUDGET,
            FUEL_BUDGET,
        )
    }

    fn restore_index(
        &self,
        snapshot_path: &std::path::Path,
        guard: &GuestRestoreGuard,
        input_dir: &std::path::Path,
        output_dir: &std::path::Path,
        control: &RequestControl,
    ) -> Result<GuestRestoreIndexMetadata, GitServiceError> {
        let request = serde_json::json!({
            "operation": "restoreIndex",
            "pathHex": encode_hex(&guard.path),
            "expectedOriginalPathHex": guard.original_path.as_deref().map(encode_hex),
            "expectedIndex": guard.index.to_string(),
            "expectedWorktree": guard.worktree.to_string(),
        });
        self.execute_with_owner_io(
            snapshot_path,
            input_dir,
            Some(output_dir),
            request,
            control,
            FsPerms::ReadOnly,
            RESTORE_MEMORY_BUDGET,
            RESTORE_FUEL_BUDGET,
        )
    }

    fn diff(
        &self,
        snapshot_path: &std::path::Path,
        view: &str,
        offset: usize,
        limit: usize,
        path_filter_hex: Option<&str>,
        entry_filter_hex: Option<&str>,
        repository_id_hex: &str,
        control: &RequestControl,
    ) -> Result<GuestDiff, GitServiceError> {
        self.execute(
            snapshot_path,
            serde_json::json!({
                "operation": "diff",
                "view": view,
                "offset": offset,
                "limit": limit,
                "filterPathHex": path_filter_hex,
                "filterEntryId": entry_filter_hex,
                "repositoryId": repository_id_hex,
            }),
            control,
        )
    }

    fn log(
        &self,
        snapshot_path: &std::path::Path,
        offset: usize,
        limit: usize,
        control: &RequestControl,
    ) -> Result<GuestLog, GitServiceError> {
        self.execute(
            snapshot_path,
            serde_json::json!({
                "operation": "log",
                "offset": offset,
                "limit": limit,
            }),
            control,
        )
    }

    fn show(
        &self,
        snapshot_path: &std::path::Path,
        object_id: &str,
        offset: usize,
        limit: usize,
        control: &RequestControl,
    ) -> Result<(GuestCommit, GuestDiff), GitServiceError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GuestShow {
            commit: GuestCommit,
            files: Vec<GuestDiffFile>,
            truncated: bool,
            total: usize,
        }
        let result: GuestShow = self.execute(
            snapshot_path,
            serde_json::json!({
                "operation": "show",
                "objectId": object_id,
                "offset": offset,
                "limit": limit,
            }),
            control,
        )?;
        Ok((
            result.commit,
            GuestDiff {
                files: result.files,
                truncated: result.truncated,
                total: result.total,
            },
        ))
    }

    fn stage(
        &self,
        snapshot_path: &std::path::Path,
        paths: &[(Vec<u8>, bool)],
        control: &RequestControl,
    ) -> Result<GuestMutation, GitServiceError> {
        self.execute_mutation(
            snapshot_path,
            serde_json::json!({
                "operation": "stage",
                "paths": paths.iter().map(|(path, executable)| serde_json::json!({
                    "pathHex": encode_hex(path),
                    "executable": executable,
                })).collect::<Vec<_>>(),
            }),
            control,
        )
    }

    fn unstage(
        &self,
        snapshot_path: &std::path::Path,
        paths: &[Vec<u8>],
        control: &RequestControl,
    ) -> Result<GuestMutation, GitServiceError> {
        self.execute_mutation(
            snapshot_path,
            serde_json::json!({
                "operation": "unstage",
                "paths": paths.iter().map(|path| encode_hex(path)).collect::<Vec<_>>(),
            }),
            control,
        )
    }

    fn commit(
        &self,
        snapshot_path: &std::path::Path,
        message: &str,
        timestamp_seconds: i64,
        control: &RequestControl,
    ) -> Result<GuestMutation, GitServiceError> {
        self.execute_mutation(
            snapshot_path,
            serde_json::json!({
                "operation": "commit",
                "message": message,
                "timestampSeconds": timestamp_seconds,
            }),
            control,
        )
    }

    fn execute<T: DeserializeOwned>(
        &self,
        snapshot_path: &std::path::Path,
        request: serde_json::Value,
        control: &RequestControl,
    ) -> Result<T, GitServiceError> {
        self.execute_with_permissions(snapshot_path, request, control, FsPerms::ReadOnly)
    }

    fn execute_mutation<T: DeserializeOwned>(
        &self,
        snapshot_path: &std::path::Path,
        request: serde_json::Value,
        control: &RequestControl,
    ) -> Result<T, GitServiceError> {
        self.execute_with_permissions(snapshot_path, request, control, FsPerms::ReadWrite)
    }

    fn execute_with_permissions<T: DeserializeOwned>(
        &self,
        snapshot_path: &std::path::Path,
        request: serde_json::Value,
        control: &RequestControl,
        permissions: FsPerms,
    ) -> Result<T, GitServiceError> {
        self.execute_with_permissions_and_memory(
            snapshot_path,
            request,
            control,
            permissions,
            MEMORY_BUDGET,
        )
    }

    fn execute_with_permissions_and_memory<T: DeserializeOwned>(
        &self,
        snapshot_path: &std::path::Path,
        request: serde_json::Value,
        control: &RequestControl,
        permissions: FsPerms,
        memory_budget: usize,
    ) -> Result<T, GitServiceError> {
        self.execute_with_limits(
            snapshot_path,
            request,
            control,
            permissions,
            memory_budget,
            FUEL_BUDGET,
        )
    }

    fn execute_with_limits<T: DeserializeOwned>(
        &self,
        snapshot_path: &std::path::Path,
        request: serde_json::Value,
        control: &RequestControl,
        permissions: FsPerms,
        memory_budget: usize,
        fuel_budget: u64,
    ) -> Result<T, GitServiceError> {
        self.execute_with_preopens(
            snapshot_path,
            None,
            None,
            request,
            control,
            permissions,
            memory_budget,
            fuel_budget,
        )
    }

    fn execute_with_owner_io<T: DeserializeOwned>(
        &self,
        snapshot_path: &std::path::Path,
        input_dir: &std::path::Path,
        output_dir: Option<&std::path::Path>,
        request: serde_json::Value,
        control: &RequestControl,
        permissions: FsPerms,
        memory_budget: usize,
        fuel_budget: u64,
    ) -> Result<T, GitServiceError> {
        self.execute_with_preopens(
            snapshot_path,
            Some(input_dir),
            output_dir,
            request,
            control,
            permissions,
            memory_budget,
            fuel_budget,
        )
    }

    fn execute_with_preopens<T: DeserializeOwned>(
        &self,
        snapshot_path: &std::path::Path,
        input_dir: Option<&std::path::Path>,
        output_dir: Option<&std::path::Path>,
        request: serde_json::Value,
        control: &RequestControl,
        permissions: FsPerms,
        memory_budget: usize,
        fuel_budget: u64,
    ) -> Result<T, GitServiceError> {
        control.check()?;
        let input = serde_json::to_vec(&request).map_err(|_| GitServiceError::ExecutorFailed)?;
        if input.len() > MAX_INPUT_BYTES {
            return Err(GitServiceError::ResourceLimit);
        }

        let stdout = MemoryOutputPipe::new(MAX_STDOUT_BYTES);
        let stderr = MemoryOutputPipe::new(MAX_STDERR_BYTES);
        let mut wasi = WasiCtxBuilder::new();
        if input_dir.is_some() {
            // gix accepts GIT_WORK_TREE as a repository open override. This
            // fixed value is the only environment entry exposed to the guest.
            wasi.env("GIT_WORK_TREE", "/snapshot");
        }
        wasi.stdin(MemoryInputPipe::new(input))
            .stdout(stdout.clone())
            .stderr(stderr)
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .preopened_dir(snapshot_path, "/snapshot", permissions)
            .map_err(|_| GitServiceError::ExecutorFailed)?;
        if let Some(input_dir) = input_dir {
            wasi.preopened_dir(input_dir, "/input", FsPerms::ReadOnly)
                .map_err(|_| GitServiceError::ExecutorFailed)?;
        }
        if let Some(output_dir) = output_dir {
            wasi.preopened_dir(output_dir, "/output", FsPerms::ReadWrite)
                .map_err(|_| GitServiceError::ExecutorFailed)?;
        }
        let limits = StoreLimitsBuilder::new()
            .memory_size(memory_budget)
            .table_elements(100_000)
            .instances(1)
            .tables(1)
            .memories(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(
            &self.engine,
            WorkerState {
                wasi: wasi.build_p1(),
                limits,
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(fuel_budget)
            .map_err(|_| GitServiceError::ExecutorFailed)?;
        set_request_epoch_deadline(&mut store, control.clone(), None);

        let finished = Arc::new(AtomicBool::new(false));
        let timer_finished = finished.clone();
        let timer_engine = self.engine.clone();
        let timer_control = control.clone();
        let timer = thread::spawn(move || {
            loop {
                if timer_finished.load(Ordering::Acquire) {
                    return;
                }
                if timer_control.cancellation.is_cancelled()
                    || Instant::now() >= timer_control.deadline
                {
                    timer_engine.increment_epoch();
                    return;
                }
                thread::sleep(TIMER_POLL);
            }
        });

        let execution = (|| -> Result<()> {
            let mut linker = Linker::new(&self.engine);
            p1::add_to_linker_sync(&mut linker, |state: &mut WorkerState| &mut state.wasi)?;
            let instance = linker.instantiate(&mut store, &self.module)?;
            instance
                .get_typed_func::<(), ()>(&mut store, "_start")?
                .call(&mut store, ())?;
            Ok(())
        })();
        finished.store(true, Ordering::Release);
        timer.join().map_err(|_| GitServiceError::ExecutorFailed)?;
        control.check()?;
        execution.map_err(|_| GitServiceError::ExecutorFailed)?;
        let output = stdout.contents();
        if output.is_empty() || output.len() > MAX_STDOUT_BYTES {
            return Err(GitServiceError::ExecutorFailed);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&output).map_err(|_| GitServiceError::ExecutorFailed)?;
        if value.get("errorCode").and_then(serde_json::Value::as_str) == Some("identityRequired") {
            return Err(GitServiceError::IdentityRequired);
        }
        serde_json::from_value(value).map_err(|_| GitServiceError::ExecutorFailed)
    }
}

pub(crate) fn run_status(
    snapshot_path: &std::path::Path,
    offset: usize,
    limit: usize,
    control: &RequestControl,
) -> Result<GuestStatus, GitServiceError> {
    let executor = WasiGitExecutor::embedded()?;
    executor.status(snapshot_path, offset, limit, control)
}

pub(crate) fn run_selected_change(
    snapshot_path: &std::path::Path,
    path: &[u8],
    input_dir: &std::path::Path,
    control: &RequestControl,
) -> Result<GuestSelectedChange, GitServiceError> {
    if path.is_empty() || path.len() > 3072 {
        return Err(GitServiceError::MutationConflict);
    }
    let (snapshot, input, _) = canonical_owner_local_directories(snapshot_path, input_dir, None)?;
    let context = read_owner_context(&input)?;
    let change = WasiGitExecutor::embedded()?.selected_change(&snapshot, path, &input, control)?;
    validate_selected_change(&change, path, context.selected_kind)?;
    Ok(change)
}

pub(crate) fn run_restore_index(
    snapshot_path: &std::path::Path,
    guard: &GuestRestoreGuard,
    input_dir: &std::path::Path,
    output_dir: &std::path::Path,
    control: &RequestControl,
) -> Result<GuestRestoreIndex, GitServiceError> {
    if guard.path.is_empty()
        || guard.path.len() > 3072
        || guard
            .original_path
            .as_ref()
            .is_some_and(|path| path.len() > 3072)
        || !" MADRCUT?!".contains(guard.index)
        || !" MADRCUT?!".contains(guard.worktree)
    {
        return Err(GitServiceError::MutationConflict);
    }
    let (snapshot, input, output) =
        canonical_owner_local_directories(snapshot_path, input_dir, Some(output_dir))?;
    let output = output.ok_or(GitServiceError::ExecutorFailed)?;
    let output_path = output.join(RESTORE_INDEX_OUTPUT_FILE);
    match std::fs::symlink_metadata(&output_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(GitServiceError::ExecutorFailed),
    }
    let context = read_owner_context(&input)?;
    let metadata =
        WasiGitExecutor::embedded()?.restore_index(&snapshot, guard, &input, &output, control)?;
    validate_selected_change(&metadata.change, &guard.path, context.selected_kind)?;
    let expected_original = guard.original_path.as_deref().map(encode_hex);
    if metadata.change.original_path_hex != expected_original
        || metadata.change.index != guard.index
        || metadata.change.worktree != guard.worktree
        || (metadata.index_path_hex != encode_hex(&guard.path)
            && metadata.index_path_hex != expected_original.unwrap_or_default())
        || !matches!(metadata.mode, 0o100644 | 0o100755 | 0o120000)
        || metadata.size > MAX_RESTORE_BLOB_BYTES
        || !is_lower_hex(&metadata.blob_object_id, 32)
        || !matches!(metadata.blob_object_id.len(), 40 | 64)
    {
        return Err(GitServiceError::ExecutorFailed);
    }

    let path_metadata =
        std::fs::symlink_metadata(&output_path).map_err(|_| GitServiceError::ExecutorFailed)?;
    if !path_metadata.file_type().is_file() || path_metadata.len() != metadata.size {
        return Err(GitServiceError::ExecutorFailed);
    }
    let mut output = File::open(&output_path).map_err(|_| GitServiceError::ExecutorFailed)?;
    let opened_metadata = output
        .metadata()
        .map_err(|_| GitServiceError::ExecutorFailed)?;
    if !opened_metadata.is_file() || opened_metadata.len() != metadata.size {
        return Err(GitServiceError::ExecutorFailed);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut read_total = 0u64;
    loop {
        control.check()?;
        let count = output
            .read(&mut buffer)
            .map_err(|_| GitServiceError::ExecutorFailed)?;
        if count == 0 {
            break;
        }
        read_total = read_total
            .checked_add(count as u64)
            .ok_or(GitServiceError::ExecutorFailed)?;
        if read_total > metadata.size || read_total > MAX_RESTORE_BLOB_BYTES {
            return Err(GitServiceError::ExecutorFailed);
        }
        digest.update(&buffer[..count]);
    }
    if read_total != metadata.size {
        return Err(GitServiceError::ExecutorFailed);
    }
    Ok(GuestRestoreIndex {
        change: metadata.change,
        index_path_hex: metadata.index_path_hex,
        blob_object_id: metadata.blob_object_id,
        mode: metadata.mode,
        size: metadata.size,
        sha256: encode_hex(&digest.finalize()),
    })
}

pub(crate) fn run_diff(
    snapshot_path: &std::path::Path,
    view: &str,
    offset: usize,
    limit: usize,
    path_filter_hex: Option<&str>,
    entry_filter_hex: Option<&str>,
    repository_id_hex: &str,
    control: &RequestControl,
) -> Result<GuestDiff, GitServiceError> {
    WasiGitExecutor::embedded()?.diff(
        snapshot_path,
        view,
        offset,
        limit,
        path_filter_hex,
        entry_filter_hex,
        repository_id_hex,
        control,
    )
}

pub(crate) fn run_log(
    snapshot_path: &std::path::Path,
    offset: usize,
    limit: usize,
    control: &RequestControl,
) -> Result<GuestLog, GitServiceError> {
    WasiGitExecutor::embedded()?.log(snapshot_path, offset, limit, control)
}

pub(crate) fn run_show(
    snapshot_path: &std::path::Path,
    object_id: &str,
    offset: usize,
    limit: usize,
    control: &RequestControl,
) -> Result<(GuestCommit, GuestDiff), GitServiceError> {
    WasiGitExecutor::embedded()?.show(snapshot_path, object_id, offset, limit, control)
}

pub(crate) fn run_stage(
    snapshot_path: &std::path::Path,
    paths: &[(Vec<u8>, bool)],
    control: &RequestControl,
) -> Result<GuestMutation, GitServiceError> {
    WasiGitExecutor::embedded()?.stage(snapshot_path, paths, control)
}

pub(crate) fn run_unstage(
    snapshot_path: &std::path::Path,
    paths: &[Vec<u8>],
    control: &RequestControl,
) -> Result<GuestMutation, GitServiceError> {
    WasiGitExecutor::embedded()?.unstage(snapshot_path, paths, control)
}

pub(crate) fn run_commit(
    snapshot_path: &std::path::Path,
    message: &str,
    timestamp_seconds: i64,
    control: &RequestControl,
) -> Result<GuestMutation, GitServiceError> {
    WasiGitExecutor::embedded()?.commit(snapshot_path, message, timestamp_seconds, control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::mpsc;

    // Both Stores share one Engine, as production request workers do. An epoch
    // increment caused by cancelling one request must trap that request while
    // leaving the other Store's deadline live.
    #[test]
    fn cancelling_one_shared_engine_request_does_not_trap_another() {
        const LOOPING_MODULE: &[u8] = &[
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // () -> () type
            0x03, 0x02, 0x01, 0x00, // one function
            0x07, 0x06, 0x01, 0x02, b'r', b'n', 0x00, 0x00, // export "rn"
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b, // infinite loop
        ];

        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).expect("create test engine");
        let module = Module::new(&engine, LOOPING_MODULE).expect("compile loop module");
        let barrier = Arc::new(Barrier::new(3));
        let (finished_tx, finished_rx) = mpsc::channel();

        let spawn_request = |id: &'static str, cancellation: crate::CancellationToken| {
            let engine = engine.clone();
            let module = module.clone();
            let barrier = barrier.clone();
            let finished_tx = finished_tx.clone();
            thread::spawn(move || {
                let control = RequestControl::with_timeout(cancellation, Duration::from_secs(5))
                    .expect("valid test request deadline");
                let mut store = Store::new(&engine, ());
                set_request_epoch_deadline(&mut store, control, None);
                let instance = Linker::<()>::new(&engine)
                    .instantiate(&mut store, &module)
                    .expect("instantiate loop module");
                let run = instance
                    .get_typed_func::<(), ()>(&mut store, "rn")
                    .expect("find loop export");
                barrier.wait();
                let result = run.call(&mut store, ());
                finished_tx
                    .send((id, result.is_err()))
                    .expect("send completion");
            })
        };

        let cancel_a = crate::CancellationToken::new();
        let cancel_b = crate::CancellationToken::new();
        let request_a = spawn_request("a", cancel_a.clone());
        let request_b = spawn_request("b", cancel_b.clone());
        barrier.wait();

        // Give both calls time to enter the loop. The epoch interrupt itself
        // wakes them; a foreign tick must be extended by B's own callback.
        thread::sleep(Duration::from_millis(20));
        cancel_a.cancel();
        engine.increment_epoch();

        let completed_a = finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cancelled request should leave the loop");
        assert_eq!(completed_a.0, "a");
        assert!(completed_a.1, "cancelled request must trap");
        assert!(
            finished_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "unrelated request must remain active after request A's epoch tick"
        );

        cancel_b.cancel();
        engine.increment_epoch();
        let completed_b = finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("request B should stop after its own cancellation");
        assert_eq!(completed_b.0, "b");
        assert!(completed_b.1, "cancelled request B must trap");
        request_a.join().expect("join request A");
        request_b.join().expect("join request B");
    }
}
