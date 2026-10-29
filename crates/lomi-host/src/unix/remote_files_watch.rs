//! Remote `files.watch`: invalidation-only change notification for one
//! directory of the pinned workspace root.
//!
//! Native directory and child-file events invalidate a stable fingerprint over
//! (entry, kind, size, revision); all platforms reconcile at a bounded polling
//! interval to detect ancestor changes and recover from backend limitations.
//! A change is reported as an
//! `Invalidated` frame naming the directory entry, never as file content; the
//! client re-lists to learn what changed. The cursor is the fingerprint of the
//! last state the client was told about, so resuming with a stale cursor yields
//! an immediate invalidation and a client can never silently miss a change.
//! A directory that is too large, or that disappears, ends the watch with a
//! `ResyncRequired` frame; an empty success is never produced for those cases.
//! At most one watch exists per connection, and at most `MAX_UNACKED` frames
//! may be outstanding, after which polling pauses until the client acks.

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use lomi_files::DirectoryWatch;
use lomi_files::{self as engine, EntryRef, FileRoot};
use lomi_remote_protocol::{
    DecimalU64, EntryId, ErrorCode, RemoteError, WorkspaceContext,
    rpc::{BoundedList, FilesWatchParams, FilesWatchResult, SubscriptionId},
    streams::{
        FileWatchAck, FileWatchEvent, FileWatchFrame, FilesInvalidated, ResyncReason, WatchSeq,
        WorkspaceResync,
    },
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Native events are the normal trigger; this slower identity reconciliation
// also detects an ancestor rename, which a watch on the pinned leaf cannot.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
const POLL_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const PAGE: usize = 200;
const MAX_PAGES: usize = 5;
const MAX_UNACKED: u64 = 8;

type Fingerprint = [u8; 16];

enum Observed {
    Fingerprint(Fingerprint),
    Overflow,
}

pub(super) struct RemoteWatch {
    files: Arc<FileRoot>,
    directory: EntryRef,
    directory_id: EntryId,
    context: WorkspaceContext,
    subscription_id: SubscriptionId,
    seq: u64,
    acked: u64,
    fingerprint: Fingerprint,
    next_poll: Instant,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    watcher: Option<DirectoryWatch>,
    stale_resume: bool,
    finished: bool,
}

fn fault(code: ErrorCode) -> RemoteError {
    RemoteError::new(
        code,
        false,
        lomi_remote_protocol::Effect::None,
        lomi_remote_protocol::ErrorDetails::empty(),
        None,
    )
    .expect("static safe error")
}

type Row = (Vec<u8>, [u8; 16], u8, u64, String);

fn observe(files: &FileRoot, directory: EntryRef) -> engine::Result<Observed> {
    // The directory's own revision covers its mtime/ctime, which every create,
    // delete and rename inside it advances: an entry that appears and vanishes
    // between two polls still moves the fingerprint.
    let directory_revision = files.stat(directory, None)?.revision;
    let mut cursor: Option<Vec<u8>> = None;
    let mut rows: Vec<Row> = Vec::new();
    for _ in 0..MAX_PAGES {
        let page = files.list(directory, cursor.as_deref(), PAGE)?;
        if page.truncated && page.next.is_none() {
            // A truncated page without a continuation cursor cannot be
            // reconciled safely; don't fingerprint it as a complete listing.
            return Ok(Observed::Overflow);
        }
        for meta in page.entries {
            let kind = match meta.kind {
                engine::Kind::File => 0u8,
                engine::Kind::Directory => 1,
                engine::Kind::Symlink => 2,
                engine::Kind::Other => 3,
            };
            rows.push((
                meta.name,
                meta.entry.to_bytes(),
                kind,
                meta.size,
                meta.revision,
            ));
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => {
                rows.sort();
                let mut hash = Sha256::new();
                hash.update(directory_revision.as_bytes());
                for (name, entry, kind, size, revision) in &rows {
                    hash.update((name.len() as u64).to_be_bytes());
                    hash.update(name);
                    hash.update(entry);
                    hash.update([*kind]);
                    hash.update(size.to_be_bytes());
                    hash.update((revision.len() as u64).to_be_bytes());
                    hash.update(revision.as_bytes());
                }
                let digest = hash.finalize();
                let mut out = [0u8; 16];
                out.copy_from_slice(&digest[..16]);
                return Ok(Observed::Fingerprint(out));
            }
        }
    }
    Ok(Observed::Overflow)
}

fn token(fingerprint: &Fingerprint) -> String {
    fingerprint.iter().map(|b| format!("{b:02x}")).collect()
}

impl RemoteWatch {
    /// Replaces the connection's single watch slot. A failed replacement also
    /// closes the previous subscription, so a rejected `files.watch` request
    /// cannot leave an older stream silently active.
    pub(super) fn replace(
        slot: &mut Option<Self>,
        open: impl FnOnce() -> Result<(Self, FilesWatchResult), RemoteError>,
    ) -> Result<FilesWatchResult, RemoteError> {
        *slot = None;
        let (watch, result) = open()?;
        *slot = Some(watch);
        Ok(result)
    }

    /// Starts a watch on `params.entry_id`. `generation` makes the subscription
    /// id unique within the connection.
    pub(super) fn open(
        files: Arc<FileRoot>,
        params: &FilesWatchParams,
        generation: u64,
        now: Instant,
    ) -> Result<(Self, FilesWatchResult), RemoteError> {
        let directory = EntryRef::from_bytes(params.entry_id.to_bytes());
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        let watcher = files
            .watch_directory(directory)
            .map_err(super::remote_files::map_error)?;
        let fingerprint = match observe(&files, directory) {
            Ok(Observed::Fingerprint(fingerprint)) => fingerprint,
            Ok(Observed::Overflow) => return Err(fault(ErrorCode::HostBusy)),
            Err(error) => return Err(super::remote_files::map_error(error)),
        };
        let current = token(&fingerprint);
        let internal = |_| fault(ErrorCode::HostBusy);
        let cursor =
            lomi_remote_protocol::EventCursor::try_from(current.clone()).map_err(internal)?;
        let subscription_id =
            SubscriptionId::try_from(format!("watch-{generation}")).map_err(internal)?;
        let stale_resume = params
            .cursor
            .as_ref()
            .is_some_and(|resume| resume.as_str() != current);
        let result = FilesWatchResult {
            subscription_id: subscription_id.clone(),
            cursor,
            through_seq: WatchSeq(DecimalU64(0)),
        };
        Ok((
            Self {
                files,
                directory,
                directory_id: params.entry_id,
                context: params.context.clone(),
                subscription_id,
                seq: 0,
                acked: 0,
                fingerprint,
                next_poll: now + POLL_INTERVAL,
                #[cfg(any(target_os = "linux", target_os = "macos", windows))]
                watcher: Some(watcher),
                stale_resume,
                finished: false,
            },
            result,
        ))
    }

    fn resync(&mut self, reason: ResyncReason) -> FileWatchFrame {
        self.finished = true;
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        drop(self.watcher.take());
        FileWatchFrame::ResyncRequired(WorkspaceResync {
            context: self.context.clone(),
            subscription_id: self.subscription_id.clone(),
            reason,
        })
    }

    fn invalidated(&mut self) -> Option<FileWatchFrame> {
        self.seq += 1;
        let cursor = lomi_remote_protocol::EventCursor::try_from(token(&self.fingerprint)).ok()?;
        Some(FileWatchFrame::Invalidated(FileWatchEvent {
            context: self.context.clone(),
            subscription_id: self.subscription_id.clone(),
            watch_seq: WatchSeq(DecimalU64(self.seq)),
            cursor,
            invalidation: FilesInvalidated {
                entries: BoundedList(vec![self.directory_id]),
                overflow: false,
            },
        }))
    }

    /// Returns the next frame to send, if any. Cheap when nothing is due.
    pub(super) fn poll(&mut self, now: Instant) -> Option<FileWatchFrame> {
        if self.finished || self.seq - self.acked >= MAX_UNACKED {
            return None;
        }
        if self.stale_resume {
            self.stale_resume = false;
            return self.invalidated();
        }
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        let native_changed = match self
            .watcher
            .as_ref()
            .map(DirectoryWatch::changed)
            .unwrap_or(Err(engine::Error::Changed))
        {
            Ok(false) if now < self.next_poll => return None,
            Ok(changed) => {
                self.next_poll = now + POLL_INTERVAL;
                if changed {
                    // Re-arm child watches after create/replace events. Install
                    // the new watcher before dropping the old one so a change
                    // cannot fall into an unwatched gap.
                    match self.files.watch_directory(self.directory) {
                        Ok(watcher) => self.watcher = Some(watcher),
                        Err(_) => {
                            let reason = if self.files.stat(self.directory, None).is_ok() {
                                ResyncReason::WatchOverflow
                            } else {
                                ResyncReason::StaleCursor
                            };
                            return Some(self.resync(reason));
                        }
                    }
                }
                changed
            }
            Err(_) => return Some(self.resync(ResyncReason::WatchOverflow)),
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            if now < self.next_poll {
                return None;
            }
            self.next_poll = now + POLL_INTERVAL;
        }
        match observe(&self.files, self.directory) {
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            Ok(Observed::Fingerprint(fingerprint))
                if fingerprint == self.fingerprint && native_changed =>
            {
                // The cursor describes observed state, while watch_seq orders
                // invalidations. A real inotify event can matter even when
                // state has returned to the same fingerprint by reconciliation.
                self.invalidated()
            }
            Ok(Observed::Fingerprint(fingerprint)) if fingerprint == self.fingerprint => None,
            Ok(Observed::Fingerprint(fingerprint)) => {
                self.fingerprint = fingerprint;
                self.invalidated()
            }
            Ok(Observed::Overflow) => Some(self.resync(ResyncReason::WatchOverflow)),
            Err(_) => Some(self.resync(ResyncReason::StaleCursor)),
        }
    }

    /// Accepts the client's acknowledgement; anything that does not match this
    /// subscription or acknowledges an unsent or already acknowledged sequence
    /// is a protocol violation.
    pub(super) fn ack(&mut self, ack: &FileWatchAck) -> bool {
        let through = ack.through_seq.0.0;
        if ack.context != self.context
            || ack.subscription_id != self.subscription_id
            || through > self.seq
            || through < self.acked
        {
            return false;
        }
        self.acked = through;
        true
    }
}
