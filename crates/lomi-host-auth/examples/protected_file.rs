//! Process/reopen smoke probe; trusted private fixture path contains no secrets.
#[cfg(unix)]
fn main() {
    use lomi_host_auth::{Config, HostAuth, Status};
    use lomi_platform::{
        secrets::{ProtectedFileAcknowledgement, Selection},
        unix::{OwnerLock, secrets::ProtectedFile},
    };
    use lomi_remote_protocol::{HostId, ipc::IpcProfileId};
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("mode");
    let path = args.next().expect("private fixture directory");
    assert!(args.next().is_none());
    let owner = OwnerLock::acquire(std::path::Path::new(&path)).expect("private fixture owner");
    let mut storage = ProtectedFile::open(
        owner.profile(),
        Selection::ProtectedFile(ProtectedFileAcknowledgement::OsPermissionsOnly),
    )
    .expect("explicit protected file");
    let config = Config::new(
        HostId::from_bytes([1; 16]).unwrap(),
        IpcProfileId::from_bytes([2; 16]).unwrap(),
        "https://auth.example".into(),
        "host".to_owned().try_into().unwrap(),
    )
    .unwrap();
    let mut auth = HostAuth::open(&mut storage, config, 100).expect("protected lifecycle reopen");
    match mode.as_str() {
        "create" => {
            assert_eq!(auth.status(), Status::Empty);
            auth.initialize().unwrap();
        }
        "reopen" => assert_eq!(auth.status(), Status::PendingInit),
        _ => panic!("mode"),
    }
    let request = auth.init_request().unwrap();
    lomi_remote_crypto::verify_host_key_initiation(&request).unwrap();
    println!("protected_lifecycle_{}:passed", mode);
}
#[cfg(not(unix))]
fn main() {
    println!("not_run: Unix required");
}
