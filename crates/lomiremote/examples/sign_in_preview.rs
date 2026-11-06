//! Appearance-only sign-in preview. Uses sample data; never opens a browser or
//! connects to a Host. `--complete` simulates approval after five seconds.
//! Run: cargo run --locked -p lomiremote --example sign_in_preview

use lomi_remote_protocol::{
    DecimalU64, HostId, OperationId, RuntimeId,
    ipc::{
        LocalAuthNetwork, LocalAuthPhase, LocalAuthStorage, LocalCall, LocalHostName,
        LocalLoginAccepted, LocalLoginPresentation, LocalLoginStatus, LocalResult, LocalRootPath,
        LocalSharing, LocalStatus,
    },
    rpc::BoundedList,
};
use lomiremote::ui::{self, Backend};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Preview {
    started: Option<(OperationId, Instant)>,
    expires_at: u64,
    complete: bool,
}

impl Backend for Preview {
    fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
        match call {
            LocalCall::LoginStatus {} => {
                let approved = self.complete
                    && self
                        .started
                        .is_some_and(|(_, started)| started.elapsed() >= Duration::from_secs(5));
                Ok(LocalResult::LoginStatus(LocalLoginStatus {
                    phase: if approved {
                        LocalAuthPhase::Ready
                    } else if self.started.is_some() {
                        LocalAuthPhase::AwaitingApproval
                    } else {
                        LocalAuthPhase::Idle
                    },
                    storage: LocalAuthStorage::Available,
                    network: LocalAuthNetwork::Available,
                    generation: DecimalU64(1),
                    locked: !approved,
                    pending_cloud_revoke: false,
                    operation_id: self.started.map(|(id, _)| id),
                    access_expires_at: None,
                    refresh_at: None,
                }))
            }
            LocalCall::LoginStart(start) => {
                self.started
                    .get_or_insert((start.operation_id, Instant::now()));
                if self.expires_at == 0 {
                    self.expires_at = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 600;
                }
                Ok(LocalResult::LoginAccepted(LocalLoginAccepted {
                    operation_id: self.started.unwrap().0,
                    generation: DecimalU64(1),
                }))
            }
            LocalCall::LoginPresentation {} if self.started.is_some() => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Ok(LocalResult::LoginPresentation(LocalLoginPresentation {
                    user_code: "DEMO1234".to_owned().try_into().unwrap(),
                    verification_url: LocalRootPath::try_from(
                        "https://example.invalid/lomi-sign-in-preview".to_owned(),
                    )
                    .unwrap(),
                    expires_at: DecimalU64(self.expires_at),
                    next_poll_at: DecimalU64(now + 1),
                }))
            }
            LocalCall::Status {} => Ok(LocalResult::Status(LocalStatus {
                host_name: LocalHostName::try_from("SIGN-IN PREVIEW — sample data".to_owned())
                    .unwrap(),
                host_id: HostId::from_bytes([1; 16]).unwrap(),
                runtime_id: RuntimeId::from_bytes([2; 16]).unwrap(),
                sharing: LocalSharing::Disabled,
            })),
            LocalCall::Workspaces {} => Ok(LocalResult::Workspaces(BoundedList(Vec::new()))),
            _ => Err("PREVIEW_ACTION_DISABLED"),
        }
    }
}

fn main() -> std::io::Result<()> {
    ui::run(&mut Preview {
        started: None,
        expires_at: 0,
        complete: std::env::args().any(|arg| arg == "--complete"),
    })
}
