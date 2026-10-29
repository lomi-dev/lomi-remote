//! Fixture-only saturation of persisted reservations. These 31 records never
//! bootstrap jobs or grant workloads; their held owner locks exercise the same
//! persisted admission gate as the one real quarantined generation.
use lomi_terminal::{Error, Result, SpawnProfile, TerminalService};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
unsafe extern "C" {
    fn lomi_coalition_safe_acl(fd: i32) -> i32;
}
// Reuse the reviewed nofollow/ACL/file-publication helpers without changing the
// product backend or exposing a test API. This module is fixture-only.
#[allow(dead_code)]
#[path = "../../crates/lomi-terminal/src/supervisor/macos_coalition/filesystem.rs"]
mod private_fs;
use private_fs::Directory;

pub fn reservations(
    service: &TerminalService,
    profile: &Path,
    payload: &SpawnProfile,
) -> serde_json::Value {
    let private = Directory::open(profile, false).unwrap();
    let generations = Directory::open(&profile.join("pty-generations"), false).unwrap();
    let names = generations.names().unwrap();
    assert_eq!(names.len(), 1);
    let original = Directory::open(&generations.path.join(&names[0]), false).unwrap();
    let original_bytes = original.read("journal.json").unwrap().unwrap();
    let template: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
    assert!(template["admissionConsumed"] == true && template["stage"] != "Cleaned");
    let mut leases = Vec::new();
    {
        let _operation = private
            .lock("pty-operations.lock", Duration::from_secs(3))
            .unwrap();
        for _ in 0..31 {
            let run = uuid::Uuid::new_v4().to_string();
            let directory = generations.child(&run).unwrap();
            let lease = directory.lock("owner.lock", Duration::ZERO).unwrap();
            let metadata = directory.file.metadata().unwrap();
            let mut value = template.clone();
            value["run"] = run.into();
            value["nonce"] = uuid::Uuid::new_v4().to_string().into();
            value["stage"] = "Prepared".into();
            value["generationPin"] = serde_json::json!([metadata.dev(), metadata.ino()]);
            for field in ["controller", "lifetime", "runtimePin", "socketPin"] {
                value[field] = serde_json::Value::Null;
            }
            for field in [
                "disposed",
                "leaderReaped",
                "drained",
                "admissionConsumed",
                "runtimeRemovalStarted",
                "runtimeRemoved",
            ] {
                value[field] = false.into();
            }
            value["hostStep"] = "Prepared".into();
            value["workerStep"] = "Unconnected".into();
            let bytes = serde_json::to_vec(&value).unwrap();
            directory.write("journal.json", &bytes, None).unwrap();
            leases.push((directory, lease, bytes));
        }
    }
    let called = std::cell::Cell::new(false);
    let id = lomi_remote_protocol::TerminalSessionId::from_bytes([31; 16]).unwrap();
    let epoch = lomi_remote_protocol::SessionEpoch::from_bytes([32; 16]).unwrap();
    let outcome = service.spawn_with_checks(
        id,
        epoch,
        payload,
        || {
            called.set(true);
            false
        },
        || Ok(()),
    );
    let rejected = matches!(outcome, Err(Error::ResourceExhausted));
    let unchanged = original.read("journal.json").unwrap().unwrap() == original_bytes;
    let no_extra_generation = generations.names().unwrap().len() == 32;
    {
        let _operation = private
            .lock("pty-operations.lock", Duration::from_secs(3))
            .unwrap();
        for (directory, lease, bytes) in leases {
            let mut entries = directory.names().unwrap();
            entries.sort();
            assert_eq!(entries, ["journal.json", "owner.lock"].map(str::to_owned));
            // Exact private records created by this fixture, no job/plist/socket
            // was ever published. Delete while their original owner FD is held.
            directory.remove("journal.json", &bytes).unwrap();
            directory.remove("owner.lock", b"").unwrap();
            std::fs::remove_dir(&directory.path).unwrap();
            drop(lease);
        }
        generations.sync().unwrap();
    }
    serde_json::json!({"realUncertainGenerations":1,"syntheticHeldPreparedReservations":31,
        "reservationGateRejectedAt32":rejected,"finalFenceCalled":called.get(),
        "originalJournalUnchanged":unchanged,"noAdditionalGeneration":no_extra_generation,
        "syntheticReservationsRemoved":true,"is32RunningJobQualification":false})
}
