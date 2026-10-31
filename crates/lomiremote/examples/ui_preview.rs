//! Appearance-only preview of the real dashboard. No Host, IPC or OS services.
//! Run with: cargo run --locked -p lomiremote --example ui_preview

use lomi_remote_protocol::{
    CapabilitySet, DecimalU64, HostId, PaneId, RuntimeId, SessionEpoch, TabId, TerminalContext,
    TerminalProfile, TerminalSessionId, WorkspaceContext, WorkspaceEpoch, WorkspaceId,
    ipc::{
        DiagnosticCode, DiagnosticComponent, DiagnosticSeverity, LocalAuthNetwork, LocalAuthPhase,
        LocalAuthStorage, LocalCall, LocalHostName, LocalLoginStatus, LocalProjectName,
        LocalResult, LocalRootPath, LocalSharing, LocalStartMode, LocalStartModePreference,
        LocalStatus, LocalWorkspaceDetails, LocalWorkspaceSummary,
    },
    rpc::{
        BoundedList, DisplayText, HostProfile, HostProfileId, PaneState, RpcCall, RpcResponse,
        RpcResult, SplitAxis, TerminalLayout, TerminalPane, TerminalTab,
        WorkspaceCapabilitiesResult, WorkspaceState,
    },
};
use lomiremote::{
    diagnostics::{
        DiagnosticCheck, DiagnosticReport, DiagnosticReportBuilder, DiagnosticRunMode,
        DiagnosticSource, DiagnosticState,
    },
    ui::{
        self, Backend,
        operations::{
            CurrentAccessSnapshot, ServiceAccountKind, ServiceAutostartState, ServiceMode,
            ServiceRuntimeState, ServiceSnapshot, UiDiagnosticLogEntry, UiDiagnosticLogSnapshot,
        },
    },
};
use std::io;

const PREVIEW_ONLY: &str = "UI_PREVIEW_ACTION_DISABLED";

struct PreviewBackend {
    workspaces: Vec<LocalWorkspaceSummary>,
}

impl PreviewBackend {
    fn new() -> Self {
        Self {
            workspaces: ["Lomi Desktop", "Remote Server", "Website"]
                .into_iter()
                .enumerate()
                .map(|(index, name)| LocalWorkspaceSummary {
                    workspace_id: WorkspaceId::from_bytes([index as u8 + 1; 16]).unwrap(),
                    name: LocalProjectName::try_from(name.to_owned()).unwrap(),
                    sharing: if index == 0 {
                        LocalSharing::Enabled
                    } else {
                        LocalSharing::Disabled
                    },
                })
                .collect(),
        }
    }

    fn workspace(&self, id: WorkspaceId) -> Result<LocalWorkspaceSummary, &'static str> {
        self.workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == id)
            .cloned()
            .ok_or("UI_PREVIEW_WORKSPACE_UNKNOWN")
    }

    fn status(&self) -> LocalStatus {
        LocalStatus {
            host_name: LocalHostName::try_from("MacBook - UI PREVIEW (sample data)".to_owned())
                .unwrap(),
            host_id: HostId::from_bytes([16; 16]).unwrap(),
            runtime_id: RuntimeId::from_bytes([17; 16]).unwrap(),
            sharing: LocalSharing::Enabled,
        }
    }

    fn login(&self) -> LocalLoginStatus {
        LocalLoginStatus {
            phase: LocalAuthPhase::Ready,
            storage: LocalAuthStorage::Available,
            network: LocalAuthNetwork::Available,
            generation: DecimalU64(1),
            locked: false,
            pending_cloud_revoke: false,
            operation_id: None,
            access_expires_at: None,
            refresh_at: None,
        }
    }

    fn workspace_state(&self, id: WorkspaceId) -> Result<WorkspaceState, &'static str> {
        let workspace = self.workspace(id)?;
        let workspace_index = id.to_bytes()[0] - 1;
        let context = WorkspaceContext {
            workspace_id: id,
            workspace_epoch: WorkspaceEpoch::from_bytes([18 + workspace_index; 16]).unwrap(),
            runtime_id: self.status().runtime_id,
            runtime_generation: DecimalU64(1),
            host_access_epoch: DecimalU64(1),
            grant_revision: DecimalU64(1),
        };
        let tab_names = match workspace_index {
            0 => ["Development", "Dev server", "Tests"],
            1 => ["Server shell", "Deploy logs", "Health checks"],
            _ => ["Frontend", "Vite server", "Tests"],
        };
        let pane = |ordinal: u8, state: PaneState| {
            let pane_id = PaneId::from_bytes([40 + workspace_index * 8 + ordinal; 16]).unwrap();
            let session = (state == PaneState::Running).then(|| TerminalContext {
                workspace: context.clone(),
                pane_id,
                session_id: TerminalSessionId::from_bytes([80 + workspace_index * 8 + ordinal; 16])
                    .unwrap(),
                session_epoch: SessionEpoch::from_bytes([120 + workspace_index * 8 + ordinal; 16])
                    .unwrap(),
                profile: TerminalProfile::ExperimentalRustGridV1,
            });
            TerminalPane {
                pane_id,
                session,
                state,
            }
        };
        let tab = |ordinal: u8, name: &str, layout| TerminalTab {
            tab_id: TabId::from_bytes([60 + workspace_index * 4 + ordinal; 16]).unwrap(),
            name: DisplayText::try_from(name.to_owned()).unwrap(),
            layout,
        };
        Ok(WorkspaceState {
            context: context.clone(),
            domain_revision: DecimalU64(1),
            name: DisplayText::try_from(workspace.name.as_str().to_owned()).unwrap(),
            tabs: BoundedList(vec![
                tab(
                    0,
                    tab_names[0],
                    TerminalLayout::Split {
                        axis: SplitAxis::Vertical,
                        first: Box::new(TerminalLayout::Pane {
                            pane: pane(0, PaneState::Running),
                        }),
                        second: Box::new(TerminalLayout::Pane {
                            pane: pane(1, PaneState::Running),
                        }),
                    },
                ),
                tab(
                    1,
                    tab_names[1],
                    TerminalLayout::Pane {
                        pane: pane(2, PaneState::Running),
                    },
                ),
                tab(
                    2,
                    tab_names[2],
                    TerminalLayout::Pane {
                        pane: pane(3, PaneState::Stopped),
                    },
                ),
            ]),
        })
    }
}

impl Backend for PreviewBackend {
    fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
        // This closed read allowlist has no transport or fallback to a real Host.
        // In particular, never acknowledge a mutation as if it had succeeded.
        match call {
            LocalCall::Status {} => Ok(LocalResult::Status(self.status())),
            LocalCall::Workspaces {} => Ok(LocalResult::Workspaces(BoundedList(
                self.workspaces.clone(),
            ))),
            LocalCall::LoginStatus {} => Ok(LocalResult::LoginStatus(self.login())),
            LocalCall::SetupStartModeRead {} => {
                Ok(LocalResult::SetupStartMode(LocalStartModePreference {
                    start_mode: LocalStartMode::Boot,
                }))
            }
            LocalCall::WorkspaceInspect(read) => Ok(LocalResult::WorkspaceState(Box::new(
                self.workspace_state(read.workspace_id)?,
            ))),
            LocalCall::WorkspaceDetails(read) => {
                let workspace = self.workspace(read.workspace_id)?;
                let root_name = match workspace.workspace_id.to_bytes()[0] {
                    1 => "lomi-desktop",
                    2 => "remote-server",
                    _ => "website",
                };
                Ok(LocalResult::WorkspaceDetails(LocalWorkspaceDetails {
                    root_path: LocalRootPath::try_from(format!("/preview/{root_name}")).unwrap(),
                    workspace,
                    remote_web_url: None,
                }))
            }
            LocalCall::Rpc(request) => {
                let result = match request.call {
                    RpcCall::WorkspaceCapabilities(read) => {
                        self.workspace(read.context.workspace_id)?;
                        RpcResult::WorkspaceCapabilities(WorkspaceCapabilitiesResult {
                            capabilities: CapabilitySet::try_from(vec![]).unwrap(),
                            profiles: BoundedList(
                                ["zsh", "bash"]
                                    .into_iter()
                                    .map(|name| HostProfile {
                                        profile_id: HostProfileId::try_from(name.to_owned())
                                            .unwrap(),
                                        name: DisplayText::try_from(name.to_owned()).unwrap(),
                                    })
                                    .collect(),
                            ),
                        })
                    }
                    _ => return Err(PREVIEW_ONLY),
                };
                Ok(LocalResult::Rpc(Box::new(RpcResponse::Result {
                    v: request.v,
                    request_id: request.request_id,
                    result,
                })))
            }
            _ => Err(PREVIEW_ONLY),
        }
    }

    fn service_status(&mut self) -> Result<ServiceSnapshot, &'static str> {
        Ok(ServiceSnapshot {
            mode: Some(ServiceMode::Boot),
            runtime: ServiceRuntimeState::Running,
            autostart: ServiceAutostartState::Enabled,
            account: ServiceAccountKind::CurrentUser,
            host_uptime_seconds: Some(3600),
            connected_clients: Some(0),
            active_terminals: Some(0),
        })
    }

    fn current_access_snapshot(&mut self) -> Result<CurrentAccessSnapshot, &'static str> {
        Ok(CurrentAccessSnapshot {
            login: self.login(),
            connected_clients: Some(0),
            active_terminals: Some(0),
        })
    }

    fn doctor_report(&mut self) -> Result<DiagnosticReport, &'static str> {
        // Always succeed with fixtures so the UI never falls back to OS probes.
        let mut report = DiagnosticReportBuilder::new(DiagnosticRunMode::Online);
        for check in [
            DiagnosticCheck::IpcVersion,
            DiagnosticCheck::ProfileOwner,
            DiagnosticCheck::Service,
            DiagnosticCheck::Authorization,
            DiagnosticCheck::Storage,
        ] {
            report.add(check, DiagnosticState::Healthy, DiagnosticSource::LocalHost);
        }
        Ok(report.finish())
    }

    fn read_diagnostic_logs(
        &mut self,
        _cursor: Option<u64>,
        _limit: usize,
    ) -> Result<UiDiagnosticLogSnapshot, &'static str> {
        // These closed, host-wide fixtures avoid workspace-specific or private
        // terminal content while giving the Logs view a useful sample history.
        let fixtures = [
            (
                DiagnosticSeverity::Info,
                DiagnosticComponent::Host,
                DiagnosticCode::HostStarted,
            ),
            (
                DiagnosticSeverity::Warning,
                DiagnosticComponent::Ipc,
                DiagnosticCode::IpcRequestRejected,
            ),
            (
                DiagnosticSeverity::Warning,
                DiagnosticComponent::Profile,
                DiagnosticCode::ProfileInvalid,
            ),
            (
                DiagnosticSeverity::Warning,
                DiagnosticComponent::Service,
                DiagnosticCode::ServiceUnavailable,
            ),
            (
                DiagnosticSeverity::Warning,
                DiagnosticComponent::Network,
                DiagnosticCode::NetworkTimeout,
            ),
            (
                DiagnosticSeverity::Error,
                DiagnosticComponent::Storage,
                DiagnosticCode::StorageUnavailable,
            ),
            (
                DiagnosticSeverity::Warning,
                DiagnosticComponent::Shell,
                DiagnosticCode::ShellExecutableUnavailable,
            ),
            (
                DiagnosticSeverity::Warning,
                DiagnosticComponent::Terminal,
                DiagnosticCode::ResourceLimitReached,
            ),
        ];
        Ok(UiDiagnosticLogSnapshot {
            entries: fixtures
                .into_iter()
                .enumerate()
                .map(
                    |(index, (severity, component, code))| UiDiagnosticLogEntry {
                        sequence: index as u64 + 1,
                        unix_time_ms: Some(1_793_000_000_000 + index as u64 * 60_000),
                        severity,
                        component,
                        code,
                    },
                )
                .collect(),
            next_cursor: 8,
            truncated: false,
            available: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_workspace_fixtures_validate() {
        let backend = PreviewBackend::new();
        for workspace in &backend.workspaces {
            backend
                .workspace_state(workspace.workspace_id)
                .unwrap()
                .validate()
                .unwrap();
        }
    }
}

fn main() -> io::Result<()> {
    // Unconfigured debug builds also keep the native auth-configuration path
    // unavailable before it can inspect an entered filesystem/keychain path.
    if lomiremote::bootstrap::public_release_pins().is_some() {
        return Err(io::Error::other(
            "UI preview requires a debug build without LOMI_HOST_* release pins",
        ));
    }
    // This explicit visual preview must show the theme even when launched
    // from development tools that export NO_COLOR for their command logs.
    crossterm::style::force_color_output(true);
    ui::run(&mut PreviewBackend::new())
}
