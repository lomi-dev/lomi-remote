//! Durable Host-owned native Git job lifecycle.
//!
//! This journal records authorization and custody state only. It does not
//! launch processes or validate operating-system custody records. The Host
//! coordinator must independently verify the qualified OS helper's binding
//! before constructing a completion proof below.
use super::*;

const MAX_NATIVE_GIT_JOBS: usize = 4096;
const MAX_NATIVE_GIT_JSON_BYTES: usize = 131_072;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeGitJobState {
    Preparing,
    Prepared,
    Running,
    Succeeded,
    Failed,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeGitJobCompletion {
    NotStarted,
    CustodyVerified,
}

#[derive(Debug, Clone)]
pub struct NativeGitJobRecord {
    pub operation_id: ipc::NativeIntentId,
    pub request_hash: String,
    pub fence_id: ipc::NativeIntentId,
    pub host_runtime_id: RuntimeId,
    pub state: NativeGitJobState,
    pub fence_state: ipc::NativeWriterState,
    pub plan_hash: Option<String>,
    pub preview_json: Option<String>,
    pub custody_binding_json: Option<String>,
    pub custody_binding_sha256: Option<String>,
    pub result_json: Option<String>,
    pub execution_started_at_ms: Option<u64>,
    pub completion: Option<NativeGitJobCompletion>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub completed_at_ms: Option<u64>,
    pub acknowledged_at_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum NativeGitBegin {
    /// The only result that permits this Host runtime to begin preparation.
    Started(NativeGitJobRecord),
    /// The durable operation already exists. This result is status only.
    Existing(NativeGitJobRecord),
}

#[derive(Debug, Clone)]
pub enum NativeGitExecution {
    /// The one-shot prepared-to-running transition committed durably. The Host
    /// may now launch the already approved native Git helper once.
    Started(NativeGitJobRecord),
    /// The operation was already admitted to execution or is otherwise no
    /// longer eligible to launch. This result is status only.
    Existing(NativeGitJobRecord),
}

/// Evidence handoff produced only after independent Host-side OS/helper
/// verification establishes that this exact native Git custody ended. The
/// constructor does not verify the helper record; it is for the trusted Host
/// coordinator after that verification, never for local IPC input.
#[derive(Debug, Clone)]
pub struct NativeGitCustodyCompletion {
    operation_id: ipc::NativeIntentId,
    fence_id: ipc::NativeIntentId,
    request_hash: String,
    plan_hash: String,
    host_runtime_id: RuntimeId,
    custody_binding_sha256: String,
}

impl NativeGitCustodyCompletion {
    /// Create a completion handoff after the trusted Host OS custodian has
    /// independently verified the immutable binding registered for this job.
    /// This constructor is not itself an OS verifier. `custody_binding_sha256`
    /// must be the digest of the exact binding JSON durably registered with
    /// `bind_native_git_custody`.
    pub fn from_verified_custodian_binding(
        operation_id: ipc::NativeIntentId,
        fence_id: ipc::NativeIntentId,
        request_hash: &str,
        plan_hash: &str,
        host_runtime_id: RuntimeId,
        custody_binding_sha256: &str,
    ) -> Result<Self> {
        if !valid_sha256(request_hash)
            || !valid_sha256(plan_hash)
            || !valid_sha256(custody_binding_sha256)
        {
            return Err(StoreError::Invalid);
        }
        Ok(Self {
            operation_id,
            fence_id,
            request_hash: request_hash.to_owned(),
            plan_hash: plan_hash.to_owned(),
            host_runtime_id,
            custody_binding_sha256: custody_binding_sha256.to_owned(),
        })
    }
}

/// Typed trusted-Host proof that execution never crossed the durable Running
/// transition. If a custodian binding was registered, the proof must carry
/// that exact digest and must only be constructed after the Host verifies the
/// provider never granted a mutator. This is distinct from editor `Joined`.
#[derive(Debug, Clone)]
pub struct NativeGitNotStartedProof {
    operation_id: ipc::NativeIntentId,
    fence_id: ipc::NativeIntentId,
    request_hash: String,
    plan_hash: Option<String>,
    host_runtime_id: RuntimeId,
    custody_binding_sha256: Option<String>,
}

impl NativeGitNotStartedProof {
    /// Create a proof after the Host has joined preparation and independently
    /// established that no mutator was launched/granted. A bound provider must
    /// also have been verified to have never granted a mutator.
    pub fn from_verified_no_execution(
        operation_id: ipc::NativeIntentId,
        fence_id: ipc::NativeIntentId,
        request_hash: &str,
        plan_hash: Option<&str>,
        host_runtime_id: RuntimeId,
        custody_binding_sha256: Option<&str>,
    ) -> Result<Self> {
        if !valid_sha256(request_hash)
            || plan_hash.is_some_and(|hash| !valid_sha256(hash))
            || custody_binding_sha256.is_some_and(|hash| !valid_sha256(hash))
        {
            return Err(StoreError::Invalid);
        }
        Ok(Self {
            operation_id,
            fence_id,
            request_hash: request_hash.to_owned(),
            plan_hash: plan_hash.map(str::to_owned),
            host_runtime_id,
            custody_binding_sha256: custody_binding_sha256.map(str::to_owned),
        })
    }
}

impl HostStore {
    /// Atomically record a native Git operation and acquire the same global
    /// writer fence used by native editor and other local/remote file effects.
    /// `Started` authorizes preparation only. An exact duplicate returns only
    /// the existing status and can never authorize another launch.
    pub fn begin_native_git_job(
        &mut self,
        operation_id: ipc::NativeIntentId,
        request_hash: &str,
        connection: ipc::IpcNonce,
    ) -> Result<NativeGitBegin> {
        self.begin_native_git_job_inner(None, operation_id, request_hash, connection)
    }

    /// Start a native Git operation for a Host-validated workspace snapshot.
    /// The Store rechecks its context, canonical root, and fence in the same
    /// transaction that grants preparation authority.
    pub fn begin_native_git_job_for_workspace(
        &mut self,
        guard: &super::WorkspaceEffectGuard,
        operation_id: ipc::NativeIntentId,
        request_hash: &str,
        connection: ipc::IpcNonce,
    ) -> Result<NativeGitBegin> {
        self.begin_native_git_job_inner(Some(guard), operation_id, request_hash, connection)
    }

    fn begin_native_git_job_inner(
        &mut self,
        workspace_guard: Option<&super::WorkspaceEffectGuard>,
        operation_id: ipc::NativeIntentId,
        request_hash: &str,
        connection: ipc::IpcNonce,
    ) -> Result<NativeGitBegin> {
        if !valid_sha256(request_hash) {
            return Err(StoreError::Invalid);
        }
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        prune_native_git_jobs(&tx, now)?;

        if let Some(existing) = native_git_job_record(&tx, operation_id)? {
            let exact = existing.request_hash == request_hash;
            tx.commit()?;
            return if exact {
                Ok(NativeGitBegin::Existing(existing))
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }

        if let Some(guard) = workspace_guard {
            super::workspace_removal::validate_workspace_effect_guard(&tx, guard)?;
        }
        // Native Git can write a linked worktree's shared Git common
        // directory outside this workspace root. Keep the marker global until
        // the Store carries that complete physical scope.
        super::workspace_removal::ensure_no_workspace_removal_in_progress(&tx)?;

        let collides: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_intents WHERE id=?1)
                 OR EXISTS(SELECT 1 FROM native_file_stages WHERE operation_id=?1)
                 OR EXISTS(SELECT 1 FROM native_editor_jobs WHERE operation_id=?1)",
            [key(operation_id)],
            |row| row.get(0),
        )?;
        if collides {
            tx.commit()?;
            return Err(StoreError::IdempotencyConflict);
        }
        if count(&tx, "SELECT count(*) FROM native_git_jobs")? >= MAX_NATIVE_GIT_JOBS {
            tx.commit()?;
            return Err(StoreError::ResourceExhausted);
        }
        if has_active_native_writer(&tx)? || remote_file_git_effect_pending(&tx)? {
            tx.commit()?;
            return Err(StoreError::NativeWriterBusy);
        }
        prune_finished_native_intents(&tx, now)?;
        if count(&tx, "SELECT count(*) FROM native_intents")? >= MAX_NATIVE_INTENT_ROWS
            || count(
                &tx,
                "SELECT count(*) FROM native_intents WHERE state IN('registered','active','quarantine')",
            )? >= 256
        {
            tx.commit()?;
            return Err(StoreError::ResourceExhausted);
        }

        let fence_id = loop {
            let candidate = ipc::NativeIntentId::from_bytes(Uuid::new_v4().into_bytes())
                .map_err(|_| StoreError::Storage)?;
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM native_intents WHERE id=?1)
                     OR EXISTS(SELECT 1 FROM native_editor_jobs WHERE operation_id=?1)
                     OR EXISTS(SELECT 1 FROM native_git_jobs WHERE operation_id=?1)
                     OR EXISTS(SELECT 1 FROM native_file_stages WHERE operation_id=?1)
                     OR ?1=?2",
                params![key(candidate), key(operation_id)],
                |row| row.get(0),
            )?;
            if !exists {
                break candidate;
            }
        };
        let expires_at_ms = now
            .checked_add(ipc::NATIVE_LEASE_MAX_MS)
            .ok_or(StoreError::ResourceExhausted)?;
        tx.execute(
            "INSERT INTO native_intents(id,connection,scope,state,fence,expires_at_ms)
             VALUES(?1,?2,'unscoped','active','1',?3)",
            params![key(fence_id), key(connection), expires_at_ms.to_string()],
        )?;
        tx.execute(
            "INSERT INTO native_git_jobs(
                operation_id,request_hash,fence_id,host_runtime_id,state,plan_hash,
                preview_json,custody_binding_json,custody_binding_sha256,result_json,
                execution_started_at_ms,completion_proof,created_at_ms,updated_at_ms,
                completed_at_ms,acknowledged_at_ms
             ) VALUES(?1,?2,?3,?4,'preparing',NULL,NULL,NULL,NULL,NULL,NULL,NULL,?5,?5,NULL,NULL)",
            params![
                key(operation_id),
                request_hash,
                key(fence_id),
                key(self.runtime),
                now.to_string(),
            ],
        )?;
        let record = native_git_job_record(&tx, operation_id)?.ok_or(StoreError::Storage)?;
        tx.commit()?;
        Ok(NativeGitBegin::Started(record))
    }

    /// Persist the exact prepared plan and optional bounded JSON preview.
    /// Replays of the same preparation are idempotent; they never authorize
    /// execution. No process or helper work occurs while the transaction is
    /// open.
    pub fn record_native_git_prepared(
        &mut self,
        operation_id: ipc::NativeIntentId,
        request_hash: &str,
        plan_hash: &str,
        preview_json: Option<&str>,
    ) -> Result<NativeGitJobRecord> {
        validate_native_git_hashes(request_hash, Some(plan_hash))?;
        validate_native_git_json(preview_json)?;
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        let mut record = native_git_job_record(&tx, operation_id)?.ok_or(StoreError::NotFound)?;
        check_native_git_request(&record, request_hash)?;
        if record.state == NativeGitJobState::Prepared {
            let exact = record.plan_hash.as_deref() == Some(plan_hash)
                && record.preview_json.as_deref() == preview_json;
            tx.commit()?;
            return if exact {
                Ok(record)
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }
        if record.state != NativeGitJobState::Preparing
            || record.host_runtime_id != self.runtime
            || record.fence_state != ipc::NativeWriterState::Active
        {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_git_jobs SET state='prepared',plan_hash=?2,preview_json=?3,updated_at_ms=?4
             WHERE operation_id=?1 AND state='preparing' AND request_hash=?5 AND host_runtime_id=?6",
            params![
                key(operation_id),
                plan_hash,
                preview_json,
                now.to_string(),
                request_hash,
                key(self.runtime),
            ],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        record = native_git_job_record(&tx, operation_id)?.ok_or(StoreError::Storage)?;
        tx.commit()?;
        Ok(record)
    }

    /// Register the immutable OS/helper custody binding for an exact prepared
    /// plan. Host code must independently build and validate the binding JSON;
    /// Store retains its bytes and digest without claiming OS verification.
    pub fn bind_native_git_custody(
        &mut self,
        operation_id: ipc::NativeIntentId,
        request_hash: &str,
        plan_hash: &str,
        custody_binding_json: &str,
    ) -> Result<String> {
        validate_native_git_hashes(request_hash, Some(plan_hash))?;
        validate_native_git_json(Some(custody_binding_json))?;
        let binding_sha256 = format!("{:x}", Sha256::digest(custody_binding_json.as_bytes()));
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        let record = native_git_job_record(&tx, operation_id)?.ok_or(StoreError::NotFound)?;
        check_native_git_request(&record, request_hash)?;
        if record.state != NativeGitJobState::Prepared
            || record.host_runtime_id != self.runtime
            || record.fence_state != ipc::NativeWriterState::Active
            || record.plan_hash.as_deref() != Some(plan_hash)
        {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if let Some(old_binding) = record.custody_binding_json.as_deref() {
            let exact = old_binding == custody_binding_json
                && record.custody_binding_sha256.as_deref() == Some(binding_sha256.as_str());
            tx.commit()?;
            return if exact {
                Ok(binding_sha256)
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }
        if tx.execute(
            "UPDATE native_git_jobs SET custody_binding_json=?2,custody_binding_sha256=?3,updated_at_ms=?4
             WHERE operation_id=?1 AND state='prepared' AND request_hash=?5 AND plan_hash=?6
               AND host_runtime_id=?7 AND custody_binding_json IS NULL AND custody_binding_sha256 IS NULL",
            params![
                key(operation_id),
                custody_binding_json,
                binding_sha256,
                now.to_string(),
                request_hash,
                plan_hash,
                key(self.runtime),
            ],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.commit()?;
        Ok(binding_sha256)
    }

    /// Commit the one-shot Prepared -> Running transition before process
    /// launch. Every duplicate call is status-only. The exact approved plan,
    /// request, runtime, registered custody digest, and active writer fence
    /// must all match.
    pub fn begin_native_git_execution(
        &mut self,
        operation_id: ipc::NativeIntentId,
        request_hash: &str,
        plan_hash: &str,
        custody_binding_sha256: &str,
    ) -> Result<NativeGitExecution> {
        validate_native_git_hashes(request_hash, Some(plan_hash))?;
        if !valid_sha256(custody_binding_sha256) {
            return Err(StoreError::Invalid);
        }
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        let mut record = native_git_job_record(&tx, operation_id)?.ok_or(StoreError::NotFound)?;
        check_native_git_request(&record, request_hash)?;
        if record.plan_hash.as_deref() != Some(plan_hash)
            || record.custody_binding_sha256.as_deref() != Some(custody_binding_sha256)
        {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if record.state != NativeGitJobState::Prepared {
            tx.commit()?;
            return Ok(NativeGitExecution::Existing(record));
        }
        if record.host_runtime_id != self.runtime
            || record.fence_state != ipc::NativeWriterState::Active
        {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_git_jobs SET state='running',execution_started_at_ms=?2,updated_at_ms=?2
             WHERE operation_id=?1 AND state='prepared' AND request_hash=?3 AND plan_hash=?4
               AND custody_binding_sha256=?5 AND host_runtime_id=?6 AND execution_started_at_ms IS NULL",
            params![
                key(operation_id),
                now.to_string(),
                request_hash,
                plan_hash,
                custody_binding_sha256,
                key(self.runtime),
            ],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        record = native_git_job_record(&tx, operation_id)?.ok_or(StoreError::Storage)?;
        tx.commit()?;
        Ok(NativeGitExecution::Started(record))
    }

    /// Read status after applying the original lease expiry. Expiry retains a
    /// quarantined writer fence; it never proves native execution has ended.
    pub fn native_git_job(
        &mut self,
        operation_id: ipc::NativeIntentId,
    ) -> Result<NativeGitJobRecord> {
        self.refresh_native_git_expiry()?;
        native_git_job_record(&self.db, operation_id)?.ok_or(StoreError::NotFound)
    }

    /// Read status for an exact retry. It never returns authorization to
    /// prepare or launch another helper.
    pub fn native_git_job_retry(
        &mut self,
        operation_id: ipc::NativeIntentId,
        request_hash: &str,
    ) -> Result<Option<NativeGitJobRecord>> {
        if !valid_sha256(request_hash) {
            return Err(StoreError::Invalid);
        }
        self.refresh_native_git_expiry()?;
        let Some(record) = native_git_job_record(&self.db, operation_id)? else {
            return Ok(None);
        };
        check_native_git_request(&record, request_hash)?;
        Ok(Some(record))
    }

    /// Enumerate unfinished custody obligations for Host startup recovery.
    /// These records are evidence to reconcile, never grants to prepare or
    /// execute an operation again. Apply the original lease expiry before
    /// returning them so a restarted Host cannot revive an expired writer.
    pub fn native_git_jobs_requiring_custody(&mut self) -> Result<Vec<NativeGitJobRecord>> {
        self.refresh_native_git_expiry()?;
        let operation_ids = {
            let mut query = self.db.prepare(
                "SELECT operation_id FROM native_git_jobs
                 WHERE completion_proof IS NULL
                 ORDER BY CAST(created_at_ms AS INTEGER), operation_id LIMIT ?1",
            )?;
            query
                .query_map([(MAX_NATIVE_GIT_JOBS + 1) as i64], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        if operation_ids.len() > MAX_NATIVE_GIT_JOBS {
            return Err(StoreError::Storage);
        }
        operation_ids
            .into_iter()
            .map(|id| {
                let id = ipc::NativeIntentId::try_from(id).map_err(|_| StoreError::Storage)?;
                native_git_job_record(&self.db, id)?.ok_or(StoreError::Storage)
            })
            .collect()
    }

    fn refresh_native_git_expiry(&mut self) -> Result<()> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Mark a Running job uncertain after its Host connection/custody is lost.
    /// This always quarantines and retains the fence; it is not completion.
    pub fn mark_native_git_outcome_unknown(
        &mut self,
        operation_id: ipc::NativeIntentId,
    ) -> Result<NativeGitJobRecord> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        let record = native_git_job_record(&tx, operation_id)?.ok_or(StoreError::NotFound)?;
        if record.state != NativeGitJobState::Running {
            tx.commit()?;
            return Ok(record);
        }
        if !matches!(
            record.fence_state,
            ipc::NativeWriterState::Active | ipc::NativeWriterState::Quarantine
        ) {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_intents SET state='quarantine' WHERE id=?1 AND state IN('active','quarantine')",
            [key(record.fence_id)],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_git_jobs SET state='outcomeUnknown',result_json=NULL,completion_proof=NULL,
             completed_at_ms=NULL,updated_at_ms=?2 WHERE operation_id=?1 AND state='running'",
            params![key(operation_id), now.to_string()],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        let record = native_git_job_record(&tx, operation_id)?.ok_or(StoreError::Storage)?;
        tx.commit()?;
        Ok(record)
    }

    /// Finish only after the Host OS custodian independently verified that the
    /// exact bound mutator has ceased. Result certainty and custody certainty
    /// are separate: `OutcomeUnknown` may finish this fence if custody ended.
    pub fn complete_native_git_job(
        &mut self,
        proof: NativeGitCustodyCompletion,
        state: NativeGitJobState,
        result_json: Option<String>,
    ) -> Result<()> {
        if !matches!(
            state,
            NativeGitJobState::Succeeded
                | NativeGitJobState::Failed
                | NativeGitJobState::OutcomeUnknown
        ) {
            return Err(StoreError::Invalid);
        }
        validate_native_git_json(result_json.as_deref())?;
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        let record = native_git_job_record(&tx, proof.operation_id)?.ok_or(StoreError::NotFound)?;
        check_native_git_proof_binding(&record, &proof)?;
        if record.execution_started_at_ms.is_none() {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if record.completion == Some(NativeGitJobCompletion::CustodyVerified) {
            let exact = record.state == state && record.result_json == result_json;
            tx.commit()?;
            return if exact {
                Ok(())
            } else {
                Err(StoreError::Fenced)
            };
        }
        if !matches!(
            record.state,
            NativeGitJobState::Running | NativeGitJobState::OutcomeUnknown
        ) {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if !matches!(
            record.fence_state,
            ipc::NativeWriterState::Active | ipc::NativeWriterState::Quarantine
        ) {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_intents SET state='finished',expires_at_ms=?2
             WHERE id=?1 AND state IN('active','quarantine')",
            params![key(record.fence_id), now.to_string()],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_git_jobs SET state=?2,result_json=?3,completion_proof='custodyVerified',
             completed_at_ms=?4,updated_at_ms=?4 WHERE operation_id=?1
             AND state IN('running','outcomeUnknown') AND execution_started_at_ms IS NOT NULL
             AND custody_binding_sha256=?5",
            params![
                key(proof.operation_id),
                native_git_job_state_text(state),
                result_json,
                now.to_string(),
                proof.custody_binding_sha256,
            ],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.commit()?;
        Ok(())
    }

    /// Record a Host-verified pre-execution failure. This is forbidden after
    /// the Running transition, even if process spawn itself reported failure.
    /// A registered custody provider must be independently verified to have
    /// never granted a mutator before it can release its fence.
    pub fn fail_native_git_not_started(
        &mut self,
        proof: NativeGitNotStartedProof,
        result_json: Option<String>,
    ) -> Result<()> {
        validate_native_git_json(result_json.as_deref())?;
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        let record = native_git_job_record(&tx, proof.operation_id)?.ok_or(StoreError::NotFound)?;
        check_native_git_not_started_binding(&record, &proof)?;
        if record.completion == Some(NativeGitJobCompletion::NotStarted) {
            let exact =
                record.state == NativeGitJobState::Failed && record.result_json == result_json;
            tx.commit()?;
            return if exact {
                Ok(())
            } else {
                Err(StoreError::Fenced)
            };
        }
        if record.execution_started_at_ms.is_some()
            || !matches!(
                record.state,
                NativeGitJobState::Preparing | NativeGitJobState::Prepared
            )
        {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if !matches!(
            record.fence_state,
            ipc::NativeWriterState::Active | ipc::NativeWriterState::Quarantine
        ) {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_intents SET state='finished',expires_at_ms=?2
             WHERE id=?1 AND state IN('active','quarantine')",
            params![key(record.fence_id), now.to_string()],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_git_jobs SET state='failed',result_json=?2,completion_proof='notStarted',
             completed_at_ms=?3,updated_at_ms=?3 WHERE operation_id=?1
             AND state IN('preparing','prepared') AND execution_started_at_ms IS NULL",
            params![key(proof.operation_id), result_json, now.to_string()],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.commit()?;
        Ok(())
    }

    /// Persist the owner's durable observation of a terminal result. Active,
    /// quarantined, or unverified unknown jobs cannot be acknowledged.
    pub fn acknowledge_native_git_job(&mut self, operation_id: ipc::NativeIntentId) -> Result<()> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        let record = native_git_job_record(&tx, operation_id)?;
        let Some(record) = record else {
            tx.commit()?;
            return Ok(());
        };
        let terminal = matches!(
            record.state,
            NativeGitJobState::Succeeded
                | NativeGitJobState::Failed
                | NativeGitJobState::OutcomeUnknown
        ) && record.completion.is_some()
            && record.completed_at_ms.is_some()
            && record.fence_state == ipc::NativeWriterState::Finished;
        if !terminal {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        tx.execute(
            "UPDATE native_git_jobs SET acknowledged_at_ms=COALESCE(acknowledged_at_ms,?2)
             WHERE operation_id=?1 AND completion_proof IN('notStarted','custodyVerified')",
            params![key(operation_id), now.to_string()],
        )?;
        if tx.execute(
            "UPDATE native_intents SET acknowledged_at_ms=COALESCE(acknowledged_at_ms,?2)
             WHERE id=?1 AND state='finished'",
            params![key(record.fence_id), now.to_string()],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.commit()?;
        Ok(())
    }
}

fn validate_native_git_hashes(request_hash: &str, plan_hash: Option<&str>) -> Result<()> {
    if !valid_sha256(request_hash) || plan_hash.is_some_and(|hash| !valid_sha256(hash)) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn validate_native_git_json(value: Option<&str>) -> Result<()> {
    if value.is_some_and(|value| {
        value.len() > MAX_NATIVE_GIT_JSON_BYTES
            || serde_json::from_str::<serde_json::Value>(value).is_err()
    }) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn check_native_git_request(record: &NativeGitJobRecord, request_hash: &str) -> Result<()> {
    if record.request_hash == request_hash {
        Ok(())
    } else {
        Err(StoreError::IdempotencyConflict)
    }
}

fn check_native_git_proof_binding(
    record: &NativeGitJobRecord,
    proof: &NativeGitCustodyCompletion,
) -> Result<()> {
    if record.operation_id == proof.operation_id
        && record.fence_id == proof.fence_id
        && record.request_hash == proof.request_hash
        && record.plan_hash.as_deref() == Some(proof.plan_hash.as_str())
        && record.host_runtime_id == proof.host_runtime_id
        && record.custody_binding_sha256.as_deref() == Some(proof.custody_binding_sha256.as_str())
    {
        Ok(())
    } else {
        Err(StoreError::Fenced)
    }
}

fn check_native_git_not_started_binding(
    record: &NativeGitJobRecord,
    proof: &NativeGitNotStartedProof,
) -> Result<()> {
    if record.operation_id != proof.operation_id
        || record.fence_id != proof.fence_id
        || record.request_hash != proof.request_hash
        || record.plan_hash != proof.plan_hash
        || record.host_runtime_id != proof.host_runtime_id
        || record.custody_binding_sha256 != proof.custody_binding_sha256
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn native_git_job_record(
    db: &Connection,
    operation_id: ipc::NativeIntentId,
) -> Result<Option<NativeGitJobRecord>> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    );
    let row: Option<Row> = db
        .query_row(
            "SELECT jobs.request_hash,jobs.fence_id,jobs.host_runtime_id,jobs.state,fence.state,
                    jobs.plan_hash,jobs.preview_json,jobs.custody_binding_json,jobs.custody_binding_sha256,
                    jobs.result_json,jobs.execution_started_at_ms,jobs.completion_proof,
                    jobs.created_at_ms,jobs.updated_at_ms,jobs.completed_at_ms,jobs.acknowledged_at_ms,
                    fence.expires_at_ms
             FROM native_git_jobs jobs JOIN native_intents fence ON fence.id=jobs.fence_id
             WHERE jobs.operation_id=?1",
            [key(operation_id)],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                    row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?, row.get(14)?,
                    row.get(15)?, row.get(16)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            request_hash,
            fence_id,
            host_runtime_id,
            state,
            fence_state,
            plan_hash,
            preview_json,
            custody_binding_json,
            custody_binding_sha256,
            result_json,
            execution_started_at_ms,
            completion_proof,
            created_at_ms,
            updated_at_ms,
            completed_at_ms,
            acknowledged_at_ms,
            _fence_expiry,
        )| {
            if !valid_sha256(&request_hash)
                || plan_hash
                    .as_deref()
                    .is_some_and(|value| !valid_sha256(value))
                || custody_binding_sha256
                    .as_deref()
                    .is_some_and(|value| !valid_sha256(value))
                || custody_binding_json.as_deref().is_some_and(|value| {
                    value.len() > MAX_NATIVE_GIT_JSON_BYTES
                        || custody_binding_sha256.as_deref()
                            != Some(format!("{:x}", Sha256::digest(value.as_bytes())).as_str())
                })
                || custody_binding_json.is_some() != custody_binding_sha256.is_some()
                || preview_json
                    .as_deref()
                    .is_some_and(|value| validate_native_git_json(Some(value)).is_err())
                || result_json
                    .as_deref()
                    .is_some_and(|value| validate_native_git_json(Some(value)).is_err())
            {
                return Err(StoreError::Storage);
            }
            let completion = match completion_proof.as_deref() {
                None => None,
                Some("notStarted") => Some(NativeGitJobCompletion::NotStarted),
                Some("custodyVerified") => Some(NativeGitJobCompletion::CustodyVerified),
                Some(_) => return Err(StoreError::Storage),
            };
            Ok(NativeGitJobRecord {
                operation_id,
                request_hash,
                fence_id: ipc::NativeIntentId::try_from(fence_id)
                    .map_err(|_| StoreError::Storage)?,
                host_runtime_id: RuntimeId::try_from(host_runtime_id)
                    .map_err(|_| StoreError::Storage)?,
                state: native_git_job_state(&state)?,
                fence_state: native_writer_state(&fence_state)?,
                plan_hash,
                preview_json,
                custody_binding_json,
                custody_binding_sha256,
                result_json,
                execution_started_at_ms: execution_started_at_ms.map(canonical_u64).transpose()?,
                completion,
                created_at_ms: canonical_u64(created_at_ms)?,
                updated_at_ms: canonical_u64(updated_at_ms)?,
                completed_at_ms: completed_at_ms.map(canonical_u64).transpose()?,
                acknowledged_at_ms: acknowledged_at_ms.map(canonical_u64).transpose()?,
            })
        },
    )
    .transpose()
}

fn native_git_job_state(value: &str) -> Result<NativeGitJobState> {
    match value {
        "preparing" => Ok(NativeGitJobState::Preparing),
        "prepared" => Ok(NativeGitJobState::Prepared),
        "running" => Ok(NativeGitJobState::Running),
        "succeeded" => Ok(NativeGitJobState::Succeeded),
        "failed" => Ok(NativeGitJobState::Failed),
        "outcomeUnknown" => Ok(NativeGitJobState::OutcomeUnknown),
        _ => Err(StoreError::Storage),
    }
}

fn native_git_job_state_text(value: NativeGitJobState) -> &'static str {
    match value {
        NativeGitJobState::Preparing => "preparing",
        NativeGitJobState::Prepared => "prepared",
        NativeGitJobState::Running => "running",
        NativeGitJobState::Succeeded => "succeeded",
        NativeGitJobState::Failed => "failed",
        NativeGitJobState::OutcomeUnknown => "outcomeUnknown",
    }
}

/// Prune only acknowledged, proof-backed terminal results after the receipt
/// window. Running/unknown/quarantined custody records are never pruned.
pub(super) fn prune_native_git_jobs(tx: &Transaction<'_>, now_ms: u64) -> Result<()> {
    const RECEIPT_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
    let cutoff = i64::try_from(now_ms.saturating_sub(RECEIPT_RETENTION_MS))
        .map_err(|_| StoreError::ResourceExhausted)?;
    let expired = {
        let mut query = tx.prepare(
            "SELECT jobs.operation_id,jobs.fence_id
             FROM native_git_jobs jobs JOIN native_intents fence ON fence.id=jobs.fence_id
             WHERE jobs.state IN('succeeded','failed','outcomeUnknown')
               AND jobs.completion_proof IN('notStarted','custodyVerified')
               AND jobs.completed_at_ms IS NOT NULL
               AND jobs.acknowledged_at_ms IS NOT NULL
               AND CAST(jobs.acknowledged_at_ms AS INTEGER)<=?1
               AND fence.state='finished'",
        )?;
        query
            .query_map([cutoff], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (operation_id, fence_id) in expired {
        tx.execute(
            "DELETE FROM native_git_jobs WHERE operation_id=?1 AND fence_id=?2",
            params![operation_id, fence_id],
        )?;
        tx.execute(
            "DELETE FROM native_intents WHERE id=?1 AND state='finished'
             AND NOT EXISTS(SELECT 1 FROM native_editor_jobs jobs WHERE jobs.fence_id=native_intents.id)
             AND NOT EXISTS(SELECT 1 FROM native_git_jobs jobs WHERE jobs.fence_id=native_intents.id)
             AND NOT EXISTS(SELECT 1 FROM native_evidence_bindings bindings WHERE bindings.intent_id=native_intents.id)",
            [fence_id],
        )?;
    }
    Ok(())
}
