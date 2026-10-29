//! E0.6 library verification experiment. Never use these public test keys for releases.
use jiff::Timestamp;
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use tough::{
    IntoVec, Repository, RepositoryLoader, TargetName,
    editor::{RepositoryEditor, signed::PathExists},
    key_source::{KeySource, LocalKeySource},
};
use url::Url;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const PAYLOAD: &[u8] = b"synthetic unsigned executable substitute; never executed\n";
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/release/fixtures")
}
fn dir_url(path: &Path) -> Url {
    Url::from_directory_path(path).expect("absolute test directory")
}
struct SignedFixture {
    _temp: TempDir,
    metadata: PathBuf,
    targets: PathBuf,
}
impl SignedFixture {
    async fn new(version: u64, expired: bool) -> Result<Self> {
        let temp = TempDir::new()?;
        let source = temp.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("synthetic-target.bin"), PAYLOAD)?;
        let mut editor = RepositoryEditor::new(fixtures().join("root.json")).await?;
        let future: Timestamp = "2099-01-01T00:00:00Z".parse()?;
        let timestamp_expiry = if expired {
            "2000-01-01T00:00:00Z".parse()?
        } else {
            future
        };
        let v = NonZeroU64::new(version).unwrap();
        editor
            .targets_expires(future)?
            .targets_version(v)?
            .snapshot_expires(future)
            .snapshot_version(v)
            .timestamp_expires(timestamp_expiry)
            .timestamp_version(v)
            .add_target_paths(vec![source.join("synthetic-target.bin")])
            .await?;
        let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
            path: fixtures().join("snakeoil.pem"),
        })];
        let signed = editor.sign(&keys).await?;
        let metadata = temp.path().join("metadata");
        let targets = temp.path().join("targets");
        signed.write(&metadata).await?;
        signed
            .copy_targets(&source, &targets, PathExists::Fail)
            .await?;
        Ok(Self {
            _temp: temp,
            metadata,
            targets,
        })
    }
    async fn load(
        &self,
        store: &Path,
    ) -> std::result::Result<Repository, Box<tough::error::Error>> {
        load(
            &fs::read(fixtures().join("root.json")).unwrap(),
            &self.metadata,
            &self.targets,
            store,
        )
        .await
    }
}
async fn load(
    root: &[u8],
    metadata: &Path,
    targets: &Path,
    store: &Path,
) -> std::result::Result<Repository, Box<tough::error::Error>> {
    RepositoryLoader::new(&root, dir_url(metadata), dir_url(targets))
        .datastore(store)
        .load()
        .await
        .map_err(Box::new)
}
async fn read_verified(repo: &Repository) -> Result<Vec<u8>> {
    let name = TargetName::new("synthetic-target.bin")?;
    let stream = repo
        .read_target(&name)
        .await?
        .ok_or("synthetic target missing")?;
    // Never publish, install, or use streamed chunks before complete hash validation.
    Ok(stream.into_vec().await?)
}
fn observation(id: &str, passed: bool, details: Value) -> Value {
    json!({"id":id,"passed":passed,"status":if passed {"passed"} else {"failed"},"details":details})
}
async fn probes() -> Result<Value> {
    let good = SignedFixture::new(1, false).await?;
    let mut cases = Vec::new();
    let store = TempDir::new()?;
    let repo = good.load(store.path()).await?;
    cases.push(observation(
        "valid_signed_target",
        read_verified(&repo).await? == PAYLOAD,
        json!({"full_stream_consumed_before_use":true}),
    ));
    drop(repo);
    // Change bytes without changing signed target metadata.
    let target = fs::read_dir(&good.targets)?
        .next()
        .ok_or("target file missing")??
        .path();
    let original = fs::read(&target)?;
    let mut altered = original.clone();
    altered[0] ^= 1;
    fs::write(&target, altered)?;
    let repo = good.load(store.path()).await?;
    let tamper = read_verified(&repo).await;
    let tamper_is_hash = matches!(&tamper,Err(e) if format!("{e:?}").contains("HashMismatch"));
    cases.push(observation(
        "tampered_target_rejected",
        tamper_is_hash,
        json!({"hash_mismatch":tamper_is_hash,"target_not_used":true}),
    ));
    fs::write(&target, original)?;
    drop(repo);

    let timestamp_path = good.metadata.join("timestamp.json");
    let original = fs::read(&timestamp_path)?;
    let mut invalid: Value = serde_json::from_slice(&original)?;
    for sig in invalid["signatures"].as_array_mut().unwrap() {
        let len = sig["sig"].as_str().unwrap().len();
        sig["sig"] = Value::String("0".repeat(len));
    }
    fs::write(&timestamp_path, serde_json::to_vec(&invalid)?)?;
    let rejected = matches!(
        good.load(TempDir::new()?.path()).await,
        Err(error) if matches!(*error, tough::error::Error::VerifyMetadata { .. })
    );
    cases.push(observation(
        "bad_timestamp_signature_rejected",
        rejected,
        json!({"signature_verification_failed":rejected}),
    ));
    fs::write(&timestamp_path, original)?;

    let expired = SignedFixture::new(1, true).await?;
    let rejected = matches!(
        expired.load(TempDir::new()?.path()).await,
        Err(error) if matches!(*error, tough::error::Error::ExpiredMetadata { .. })
    );
    cases.push(observation(
        "expired_timestamp_freeze_rejected",
        rejected,
        json!({"expiration_enforcement":"Safe default","signed_expired_metadata":true}),
    ));

    let newer = SignedFixture::new(2, false).await?;
    let persistent = TempDir::new()?;
    let repo = newer.load(persistent.path()).await?;
    let newer_version = repo.timestamp().signed.version.get();
    drop(repo);
    let rejected = matches!(
        good.load(persistent.path()).await,
        Err(error) if matches!(*error, tough::error::Error::OlderMetadata { .. })
    );
    cases.push(observation(
        "timestamp_downgrade_rejected_after_loader_restart",
        newer_version == 2 && rejected,
        json!({"persisted_version":newer_version,"fresh_loader_rejected_v1":rejected}),
    ));

    // Counterexample: interrupted writes/corrupt cache must fail closed in a real wrapper.
    // This probe intentionally uses the raw library's datastore contract.
    fs::write(persistent.path().join("timestamp.json"), b"{")?;
    fs::write(persistent.path().join("snapshot.json"), b"{")?;
    let rolled_back = good.load(persistent.path()).await;
    let accepted_v1 = matches!(&rolled_back,Ok(r) if r.timestamp().signed.version.get()==1);
    cases.push(observation("corrupt_cached_metadata_fails_closed",!accepted_v1,json!({"corrupt_timestamp_and_snapshot_accepted_v1":accepted_v1,"production_wrapper":"not implemented"})));
    drop(rolled_back);

    // The raw loader also ignores a malformed cached time watermark.
    let clock_store = TempDir::new()?;
    drop(good.load(clock_store.path()).await?);
    fs::write(
        clock_store.path().join("latest_known_time.json"),
        b"\"2099-01-01T00:00:00Z\"",
    )?;
    let future_rejected = matches!(
        good.load(clock_store.path()).await,
        Err(error) if matches!(*error, tough::error::Error::SystemTimeSteppedBackward { .. })
    );
    fs::write(clock_store.path().join("latest_known_time.json"), b"{")?;
    let corrupt_accepted = good.load(clock_store.path()).await.is_ok();
    cases.push(observation("corrupt_clock_watermark_fails_closed",future_rejected&&!corrupt_accepted,json!({"valid_future_watermark_rejected":future_rejected,"corrupt_watermark_accepted":corrupt_accepted})));

    let rotated_dir = TempDir::new()?;
    for entry in fs::read_dir(fixtures().join("rotated-root"))? {
        let e = entry?;
        fs::copy(e.path(), rotated_dir.path().join(e.file_name()))?;
    }
    let root1 = fs::read(rotated_dir.path().join("1.root.json"))?;
    let rotated_store = TempDir::new()?;
    let repo = load(
        &root1,
        rotated_dir.path(),
        rotated_dir.path(),
        rotated_store.path(),
    )
    .await?;
    let reached_v2 = repo.root().signed.version.get() == 2;
    drop(repo);
    let persisted_root = fs::read(rotated_store.path().join("root.json"))?;
    let persisted_v2: Value = serde_json::from_slice(&persisted_root)?;
    fs::remove_file(rotated_dir.path().join("2.root.json"))?;
    let automatic_restart = load(
        &root1,
        rotated_dir.path(),
        rotated_dir.path(),
        rotated_store.path(),
    )
    .await;
    let restart_failed = automatic_restart.is_err();
    drop(automatic_restart);
    let after_restart: Value =
        serde_json::from_slice(&fs::read(rotated_store.path().join("root.json"))?)?;
    // Explicitly supplying the saved newest root works. Selecting and atomically
    // persisting it is the caller's responsibility, not furnished by this spike.
    let explicit_store = TempDir::new()?;
    let explicit = load(
        &persisted_root,
        rotated_dir.path(),
        rotated_dir.path(),
        explicit_store.path(),
    )
    .await?;
    let explicit_v2 = explicit.root().signed.version.get() == 2;
    cases.push(observation("newest_root_restored_after_loader_restart",!restart_failed&&after_restart["signed"]["version"]==2,json!({
        "initial_rotation_reached_v2":reached_v2,"initial_persisted_version":persisted_v2["signed"]["version"],
        "bootstrap_root_restart_failed_without_v2_refetch":restart_failed,"persisted_version_after_failed_restart":after_restart["signed"]["version"],
        "explicit_saved_root_restart_succeeded":explicit_v2,"caller_trust_state_wrapper":"not implemented"})));
    Ok(
        json!({"stage":"S0.6","candidate":"tough=0.24.0","profile":"raw-loader-persistence-experimental","qualified":false,"cases":cases,
        "not_run":["atomic crash-safe trust-state persistence","cross-process serialized update lock","root bootstrap policy and key ceremony","installer/platform integration","network mirror adversarial tests"],
        "decision":"rejected: caller trust-state wrapper incomplete; regression success confirms known observations"}),
    )
}
fn assert_known(report: &Value) {
    let failures = [
        "corrupt_cached_metadata_fails_closed",
        "corrupt_clock_watermark_fails_closed",
        "newest_root_restored_after_loader_restart",
    ];
    let cases = report["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        assert_eq!(c["passed"], !failures.contains(&id), "{id}");
    }
    let find = |id: &str| cases.iter().find(|c| c["id"] == id).unwrap();
    let root = &find("newest_root_restored_after_loader_restart")["details"];
    assert_eq!(root["initial_rotation_reached_v2"], true);
    assert_eq!(root["initial_persisted_version"], 2);
    assert_eq!(
        root["bootstrap_root_restart_failed_without_v2_refetch"],
        true
    );
    assert_eq!(root["persisted_version_after_failed_restart"], 1);
    assert_eq!(root["explicit_saved_root_restart_succeeded"], true);
    let clock = &find("corrupt_clock_watermark_fails_closed")["details"];
    assert_eq!(clock["valid_future_watermark_rejected"], true);
    assert_eq!(clock["corrupt_watermark_accepted"], true);
    assert_eq!(report["qualified"], false);
}
#[tokio::main]
async fn main() -> Result<()> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "report".into());
    if !["report", "regression", "qualify"].contains(&command.as_str()) {
        eprintln!("usage: lomi-release-spike [report|regression|qualify]");
        std::process::exit(2);
    }
    let report = probes().await?;
    if command == "regression" {
        assert_known(&report);
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    if command == "qualify" {
        std::process::exit(1);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn signed_repository_and_persistence_counterexamples() -> Result<()> {
        assert_known(&probes().await?);
        Ok(())
    }
}
