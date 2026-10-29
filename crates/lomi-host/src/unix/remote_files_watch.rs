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

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_protocol::{RuntimeId, WorkspaceEpoch, WorkspaceId};

    fn context() -> WorkspaceContext {
        WorkspaceContext {
            workspace_id: WorkspaceId::from_bytes([1; 16]).unwrap(),
            workspace_epoch: WorkspaceEpoch::from_bytes([2; 16]).unwrap(),
            runtime_id: RuntimeId::from_bytes([3; 16]).unwrap(),
            runtime_generation: DecimalU64(1),
            host_access_epoch: DecimalU64(1),
            grant_revision: DecimalU64(1),
        }
    }

    fn open(dir: &std::path::Path) -> Result<(RemoteWatch, FilesWatchResult), RemoteError> {
        let root_entry = EntryRef::from_bytes([1; 16]);
        let files = Arc::new(FileRoot::open_with_root_entry(dir, &[], root_entry).unwrap());
        open_entry(files, root_entry)
    }

    fn open_entry(
        files: Arc<FileRoot>,
        entry: EntryRef,
    ) -> Result<(RemoteWatch, FilesWatchResult), RemoteError> {
        let params = FilesWatchParams {
            context: context(),
            entry_id: EntryId::from_bytes(entry.to_bytes()).unwrap(),
            cursor: None,
        };
        RemoteWatch::open(files, &params, 1, Instant::now())
    }

    #[test]
    fn failed_replacement_closes_the_previous_subscription() {
        let dir = tempfile::tempdir().unwrap();
        let (watch, _) = open(dir.path()).unwrap();
        let mut slot = Some(watch);

        let result = RemoteWatch::replace(&mut slot, || Err(fault(ErrorCode::ResourceNotFound)));

        assert_eq!(result.unwrap_err().code(), ErrorCode::ResourceNotFound);
        assert!(
            slot.is_none(),
            "a failed replacement must not keep the old watch alive"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    fn wait_for_frame(watch: &mut RemoteWatch) -> Option<FileWatchFrame> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Some(frame) = watch.poll(Instant::now()) {
                return Some(frame);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    fn set_mtime(path: &std::path::Path, modified: std::time::SystemTime) {
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let times = std::fs::FileTimes::new().set_modified(modified);
        file.set_times(times).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    fn rounded_mtime(metadata: &std::fs::Metadata) -> std::time::SystemTime {
        let seconds = metadata
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::time::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[cfg(any(target_os = "macos", windows))]
    fn restore_mtime(path: &std::path::Path, original: &std::fs::Metadata) {
        set_mtime(path, original.modified().unwrap());
        assert_eq!(
            std::fs::metadata(path).unwrap().modified().unwrap(),
            original.modified().unwrap(),
            "the test restores the original mtime"
        );
    }

    #[cfg(target_os = "linux")]
    fn restore_mtime(path: &std::path::Path, old: &std::fs::Metadata) {
        use std::os::unix::fs::MetadataExt;

        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let times = [
            libc::timespec {
                tv_sec: old.atime() as libc::time_t,
                tv_nsec: old.atime_nsec() as libc::c_long,
            },
            libc::timespec {
                tv_sec: old.mtime() as libc::time_t,
                tv_nsec: old.mtime_nsec() as libc::c_long,
            },
        ];
        assert_eq!(
            unsafe { libc::futimens(std::os::fd::AsRawFd::as_raw_fd(&file), times.as_ptr()) },
            0
        );
    }

    #[test]
    fn a_directory_over_the_bound_is_refused_not_watched_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..(PAGE * MAX_PAGES + 1) {
            std::fs::write(dir.path().join(format!("f{i:05}")), b"").unwrap();
        }
        let error = open(dir.path()).err().expect("overflow must not succeed");
        assert_eq!(error.code(), ErrorCode::HostBusy);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn native_watch_reports_same_size_child_edits_with_restored_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("same-mtime");
        std::fs::write(&path, b"before").unwrap();
        set_mtime(&path, rounded_mtime(&std::fs::metadata(&path).unwrap()));
        let old = std::fs::metadata(&path).unwrap();
        let (mut watch, _) = open(dir.path()).unwrap();

        std::fs::write(&path, b"after!").unwrap();
        restore_mtime(&path, &old);

        assert!(matches!(
            wait_for_frame(&mut watch),
            Some(FileWatchFrame::Invalidated(_))
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn nested_native_watch_reports_same_size_edits_with_restored_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let path = nested.join("same-mtime");
        std::fs::write(&path, b"before").unwrap();
        set_mtime(&path, rounded_mtime(&std::fs::metadata(&path).unwrap()));

        let root_entry = EntryRef::from_bytes([1; 16]);
        let files = Arc::new(FileRoot::open_with_root_entry(dir.path(), &[], root_entry).unwrap());
        let nested_entry = files
            .list(root_entry, None, 10)
            .unwrap()
            .entries
            .into_iter()
            .find(|entry| entry.name == b"nested")
            .expect("nested directory is listed");
        assert_eq!(nested_entry.kind, lomi_files::Kind::Directory);
        let (mut watch, _) =
            open_entry(files, EntryRef::from_bytes(nested_entry.entry.to_bytes())).unwrap();

        let old = std::fs::metadata(&path).unwrap();
        std::fs::write(&path, b"after!").unwrap();
        restore_mtime(&path, &old);

        assert!(matches!(
            wait_for_frame(&mut watch),
            Some(FileWatchFrame::Invalidated(_))
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn native_watch_rearms_for_a_file_created_after_subscription() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("late-file");
        let (mut watch, _) = open(dir.path()).unwrap();

        std::fs::write(&path, b"before").unwrap();
        set_mtime(&path, rounded_mtime(&std::fs::metadata(&path).unwrap()));
        assert!(matches!(
            wait_for_frame(&mut watch),
            Some(FileWatchFrame::Invalidated(_))
        ));

        let old = std::fs::metadata(&path).unwrap();
        std::fs::write(&path, b"after!").unwrap();
        restore_mtime(&path, &old);
        assert!(matches!(
            wait_for_frame(&mut watch),
            Some(FileWatchFrame::Invalidated(_))
        ));
    }

    #[test]
    fn observe_follows_pages_through_the_bounded_capacity() {
        for count in [PAGE + 1, PAGE * MAX_PAGES, PAGE * MAX_PAGES + 1] {
            let dir = tempfile::tempdir().unwrap();
            for i in 0..count {
                std::fs::write(dir.path().join(format!("f{i:05}")), b"").unwrap();
            }
            let root_entry = EntryRef::from_bytes([1; 16]);
            let files = FileRoot::open_with_root_entry(dir.path(), &[], root_entry).unwrap();
            let observed = observe(&files, root_entry).unwrap();
            if count <= PAGE * MAX_PAGES {
                assert!(
                    matches!(observed, Observed::Fingerprint(_)),
                    "{count} entries fit within the {MAX_PAGES}-page bound"
                );
            } else {
                assert!(
                    matches!(observed, Observed::Overflow),
                    "{count} entries exceed the {MAX_PAGES}-page bound"
                );
            }
        }
    }

    #[test]
    fn growing_past_the_bound_forces_resync_and_ends_the_watch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"").unwrap();
        let (mut watch, _) = open(dir.path()).unwrap();
        let later = Instant::now() + Duration::from_secs(2);
        assert!(watch.poll(later).is_none(), "unchanged is quiet");
        for i in 0..(PAGE * MAX_PAGES + 1) {
            std::fs::write(dir.path().join(format!("f{i:05}")), b"").unwrap();
        }
        let frame = watch.poll(later + Duration::from_secs(2)).unwrap();
        assert!(matches!(
            frame,
            FileWatchFrame::ResyncRequired(WorkspaceResync {
                reason: ResyncReason::WatchOverflow,
                ..
            })
        ));
        assert!(watch.poll(later + Duration::from_secs(10)).is_none());
    }

    #[test]
    fn a_removed_directory_forces_resync() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let root_entry = EntryRef::from_bytes([1; 16]);
        let files = Arc::new(FileRoot::open_with_root_entry(dir.path(), &[], root_entry).unwrap());
        let sub = files.list(root_entry, None, 10).unwrap().entries[0].entry;
        let params = FilesWatchParams {
            context: context(),
            entry_id: EntryId::from_bytes(sub.to_bytes()).unwrap(),
            cursor: None,
        };
        let (mut watch, _) = RemoteWatch::open(files, &params, 1, Instant::now()).unwrap();
        std::fs::remove_dir(dir.path().join("sub")).unwrap();
        let frame = watch
            .poll(watch.next_poll + Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            frame,
            FileWatchFrame::ResyncRequired(WorkspaceResync {
                reason: ResyncReason::StaleCursor,
                ..
            })
        ));
        assert!(
            watch
                .poll(Instant::now() + Duration::from_secs(9))
                .is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_resync_releases_the_inotify_watcher() {
        let dir = tempfile::tempdir().unwrap();
        let (mut watch, _) = open(dir.path()).unwrap();
        assert!(watch.watcher.is_some());
        let frame = watch.resync(ResyncReason::WatchOverflow);
        assert!(matches!(frame, FileWatchFrame::ResyncRequired(_)));
        assert!(watch.watcher.is_none());
    }

    #[test]
    fn a_renamed_ancestor_is_found_by_identity_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("parent/child")).unwrap();
        let root_entry = EntryRef::from_bytes([1; 16]);
        let files = Arc::new(FileRoot::open_with_root_entry(dir.path(), &[], root_entry).unwrap());
        let parent = files.list(root_entry, None, 10).unwrap().entries[0].entry;
        let child = files.list(parent, None, 10).unwrap().entries[0].entry;
        let params = FilesWatchParams {
            context: context(),
            entry_id: EntryId::from_bytes(child.to_bytes()).unwrap(),
            cursor: None,
        };
        let (mut watch, _) = RemoteWatch::open(files, &params, 1, Instant::now()).unwrap();
        std::fs::rename(dir.path().join("parent"), dir.path().join("moved")).unwrap();
        let frame = watch
            .poll(Instant::now() + POLL_INTERVAL + Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            frame,
            FileWatchFrame::ResyncRequired(WorkspaceResync {
                reason: ResyncReason::StaleCursor,
                ..
            })
        ));
    }

    #[test]
    fn polling_pauses_while_too_many_frames_are_unacknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let (mut watch, _) = open(dir.path()).unwrap();
        let mut now = Instant::now();
        for round in 0..MAX_UNACKED {
            now += Duration::from_secs(2);
            std::fs::write(dir.path().join(format!("f{round}")), b"x").unwrap();
            assert!(watch.poll(now).is_some());
        }
        now += Duration::from_secs(2);
        std::fs::write(dir.path().join("one-more"), b"x").unwrap();
        assert!(watch.poll(now).is_none(), "bounded by the unacked window");
        let ack = FileWatchAck {
            context: context(),
            subscription_id: watch.subscription_id.clone(),
            through_seq: WatchSeq(DecimalU64(MAX_UNACKED)),
            cursor: lomi_remote_protocol::EventCursor::try_from(token(&watch.fingerprint)).unwrap(),
        };
        assert!(watch.ack(&ack));
        assert!(
            watch.poll(now).is_some(),
            "the coalesced change is reported"
        );
    }

    #[test]
    fn acks_must_match_the_subscription_and_a_sent_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let (mut watch, _) = open(dir.path()).unwrap();
        std::fs::write(dir.path().join("a"), b"x").unwrap();
        watch.poll(Instant::now() + Duration::from_secs(2)).unwrap();
        let cursor =
            lomi_remote_protocol::EventCursor::try_from(token(&watch.fingerprint)).unwrap();
        let ack = |through: u64, subscription: &SubscriptionId| FileWatchAck {
            context: context(),
            subscription_id: subscription.clone(),
            through_seq: WatchSeq(DecimalU64(through)),
            cursor: cursor.clone(),
        };
        let other = SubscriptionId::try_from("watch-9".to_owned()).unwrap();
        assert!(!watch.ack(&ack(1, &other)), "foreign subscription");
        assert!(
            !watch.ack(&ack(2, &watch.subscription_id.clone())),
            "unsent sequence"
        );
        assert!(watch.ack(&ack(1, &watch.subscription_id.clone())));
        assert!(
            !watch.ack(&ack(0, &watch.subscription_id.clone())),
            "going backwards"
        );
    }

    #[test]
    fn a_modification_that_is_reverted_is_still_reported() {
        // The revision covers mtime and ctime, so restoring the old bytes does
        // not restore the old fingerprint.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"same").unwrap();
        let (mut watch, _) = open(dir.path()).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(dir.path().join("a"), b"diff").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(dir.path().join("a"), b"same").unwrap();
        let frame = watch.poll(Instant::now() + Duration::from_secs(2));
        assert!(matches!(frame, Some(FileWatchFrame::Invalidated(_))));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inotify_invalidates_same_mtime_content_changes() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("same-mtime");
        std::fs::write(&path, b"before").unwrap();
        let old = std::fs::metadata(&path).unwrap();
        let (mut watch, _) = open(dir.path()).unwrap();
        let before = watch.fingerprint;
        std::fs::write(&path, b"after!").unwrap();
        restore_mtime(&path, &old);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(old.len(), after.len(), "content replacement keeps size");
        assert_eq!(old.mtime(), after.mtime(), "mtime is restored");
        assert_eq!(old.mtime_nsec(), after.mtime_nsec(), "mtime is restored");
        let observed = observe(&watch.files, watch.directory).unwrap();
        if old.ctime() == after.ctime() && old.ctime_nsec() == after.ctime_nsec() {
            assert!(
                matches!(observed, Observed::Fingerprint(fingerprint) if fingerprint == before),
                "when the filesystem preserves ctime too, the whole cursor fingerprint is unchanged"
            );
        }
        assert!(matches!(
            watch.poll(Instant::now()),
            Some(FileWatchFrame::Invalidated(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inotify_immediately_invalidates_a_transient_child_create_delete() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stable"), b"same").unwrap();
        let (mut watch, _) = open(dir.path()).unwrap();

        // Both namespace operations are real child events. The final entries
        // match the original set, but directory ctime may advance and is part
        // of the host fingerprint. The native event must invalidate now rather
        // than waiting for the bounded reconciliation interval.
        std::fs::write(dir.path().join("transient"), b"x").unwrap();
        std::fs::remove_file(dir.path().join("transient")).unwrap();
        let observed = match observe(&watch.files, watch.directory).unwrap() {
            Observed::Fingerprint(observed) => observed,
            Observed::Overflow => panic!("small directory must stay within the watch bound"),
        };

        let frame = watch.poll(Instant::now());
        let Some(FileWatchFrame::Invalidated(event)) = frame else {
            panic!("inotify child event must invalidate before the poll interval");
        };
        assert_eq!(event.watch_seq.0.0, 1);
        assert_eq!(event.cursor.as_str(), token(&observed));
        assert_eq!(watch.fingerprint, observed);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn files_created_or_replaced_after_open_reconcile_same_mtime_edits() {
        for replace in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("late-file");
            if replace {
                std::fs::write(&path, b"before").unwrap();
            }
            let (mut watch, _) = open(dir.path()).unwrap();

            if replace {
                let replacement = dir.path().join("replacement");
                std::fs::write(&replacement, b"before").unwrap();
                std::fs::rename(&replacement, &path).unwrap();
            } else {
                std::fs::write(&path, b"before").unwrap();
            }

            // The namespace event is covered by the directory watch and
            // establishes the new file as the client's observed baseline.
            assert!(matches!(
                watch.poll(Instant::now()),
                Some(FileWatchFrame::Invalidated(_))
            ));

            // Settle any delayed create/rename notifications before making
            // the content edit, then confirm the namespace state is the
            // baseline already reported to the client.
            while watch.watcher.as_ref().unwrap().changed().unwrap() {}
            let baseline = observe(&watch.files, watch.directory).unwrap();
            assert!(matches!(
                baseline,
                Observed::Fingerprint(fingerprint) if fingerprint == watch.fingerprint
            ));

            let old = std::fs::metadata(&path).unwrap();
            std::fs::write(&path, b"after!").unwrap();
            restore_mtime(&path, &old);

            // New inodes are outside the bounded initial inotify set, so the
            // fingerprint reconciliation must still find the edit. Any
            // immediate frame can only follow the content operation because
            // the namespace event queue was drained above.
            let immediate = watch.poll(Instant::now());
            let frame = immediate.or_else(|| watch.poll(watch.next_poll));
            assert!(matches!(frame, Some(FileWatchFrame::Invalidated(_))));
        }
    }

    #[test]
    fn an_entry_created_and_deleted_between_polls_is_still_reported() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"x").unwrap();
        let (mut watch, _) = open(dir.path()).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(dir.path().join("transient"), b"x").unwrap();
        std::fs::remove_file(dir.path().join("transient")).unwrap();
        let frame = watch.poll(Instant::now() + Duration::from_secs(2));
        assert!(matches!(frame, Some(FileWatchFrame::Invalidated(_))));
    }
}
