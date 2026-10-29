//! Bounded, redacted in-memory diagnostic events for the local Host.
//!
//! Entries contain no dynamic strings, paths, account data, terminal output,
//! file contents or environment values. Root wires producers and canonical
//! IPC serialization separately.

use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

pub const DIAGNOSTIC_LOG_CAPACITY: usize = 256;
pub const DIAGNOSTIC_LOG_MAX_PAGE: usize = 128;

pub use lomi_remote_protocol::ipc::{
    DiagnosticCode, DiagnosticComponent, DiagnosticLogEntry, DiagnosticLogSnapshot,
    DiagnosticSeverity,
};
use lomi_remote_protocol::{DecimalU64, rpc::BoundedList};

#[derive(Debug, Default)]
struct State {
    next_sequence: u64,
    entries: VecDeque<DiagnosticLogEntry>,
}

#[derive(Debug, Default)]
pub struct DiagnosticLogRing {
    state: Mutex<State>,
}

impl DiagnosticLogRing {
    pub fn last_error(&self) -> Option<Option<DiagnosticLogEntry>> {
        let state = self.state.lock().ok()?;
        Some(
            state
                .entries
                .iter()
                .rev()
                .find(|entry| {
                    matches!(
                        entry.severity,
                        DiagnosticSeverity::Warning | DiagnosticSeverity::Error
                    )
                })
                .cloned(),
        )
    }
    pub fn record(
        &self,
        severity: DiagnosticSeverity,
        component: DiagnosticComponent,
        code: DiagnosticCode,
    ) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let Some(sequence) = state.next_sequence.checked_add(1) else {
            return false;
        };
        state.next_sequence = sequence;
        if state.entries.len() == DIAGNOSTIC_LOG_CAPACITY {
            state.entries.pop_front();
        }
        let unix_time_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .map(DecimalU64);
        state.entries.push_back(DiagnosticLogEntry {
            sequence: DecimalU64(sequence),
            unix_time_ms,
            severity,
            component,
            code,
        });
        true
    }

    /// Return a bounded page of events whose sequence is greater than
    /// `after_sequence`. `None` reads from the oldest event still retained.
    /// A truncated page can be continued with its `next_cursor`.
    pub fn snapshot(
        &self,
        after_sequence: Option<u64>,
        requested_limit: usize,
    ) -> DiagnosticLogSnapshot {
        let limit = requested_limit.clamp(1, DIAGNOSTIC_LOG_MAX_PAGE);
        let Ok(state) = self.state.lock() else {
            return DiagnosticLogSnapshot {
                entries: BoundedList(Vec::new()),
                next_cursor: DecimalU64(after_sequence.unwrap_or(0)),
                truncated: false,
                available: false,
            };
        };

        let oldest = state.entries.front().map(|entry| entry.sequence.0);
        let cursor = after_sequence.unwrap_or_else(|| oldest.unwrap_or(1).saturating_sub(1));
        let evicted = oldest.is_some_and(|oldest| {
            (after_sequence.is_none() && oldest > 1) || cursor.saturating_add(1) < oldest
        });
        let mut entries = Vec::with_capacity(limit.min(state.entries.len()));
        for entry in state
            .entries
            .iter()
            .filter(|entry| entry.sequence.0 > cursor)
        {
            if entries.len() == limit {
                break;
            }
            entries.push(entry.clone());
        }
        let has_more = entries.last().is_some_and(|last| {
            state
                .entries
                .back()
                .is_some_and(|newest| last.sequence.0 < newest.sequence.0)
        });
        let next_cursor = entries
            .last()
            .map(|entry| entry.sequence.0)
            .unwrap_or(cursor);
        DiagnosticLogSnapshot {
            entries: BoundedList(entries),
            next_cursor: DecimalU64(next_cursor),
            truncated: evicted || has_more,
            available: true,
        }
    }
}
