//! Authority-free existing-pane layout planning. No Store, journal, operation,
//! capability, callback, PTY spawn/stop or remote admission is provided here.
use lomi_remote_protocol::{PaneId, TabId, rpc::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalMoveLayout {
    pub pane_id: PaneId,
    pub source_tab_id: TabId,
    pub target_tab_id: TabId,
    pub target_pane_id: PaneId,
    pub placement: MovePlacement,
}
impl From<&TerminalMoveParams> for TerminalMoveLayout {
    fn from(params: &TerminalMoveParams) -> Self {
        Self {
            pane_id: params.pane_id,
            source_tab_id: params.source_tab_id,
            target_tab_id: params.target_tab_id,
            target_pane_id: params.target_pane_id,
            placement: params.placement,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalMoveError {
    InvalidArgument,
    NotFound,
    ResourceExhausted,
}

/// Clone and move exactly one existing pane. Preserve context, revision, names
/// and the entire pane/session tuple. Failure leaves the input unchanged.
/// The caller alone owns any CAS, journal, revision advance or authorization.
pub fn plan_terminal_move(
    state: &WorkspaceState,
    movement: &TerminalMoveLayout,
) -> Result<WorkspaceState, TerminalMoveError> {
    let mut next = state.clone();
    if movement.pane_id == movement.target_pane_id {
        return Err(TerminalMoveError::InvalidArgument);
    }
    let index = next
        .tabs
        .0
        .iter()
        .position(|tab| tab.tab_id == movement.source_tab_id)
        .ok_or(TerminalMoveError::NotFound)?;
    let (layout, moved) = remove_pane(next.tabs.0[index].layout.clone(), movement.pane_id);
    let moved = moved.ok_or(TerminalMoveError::NotFound)?;
    if let Some(layout) = layout {
        next.tabs.0[index].layout = layout;
    } else {
        next.tabs.0.remove(index);
    }
    let target = next
        .tabs
        .0
        .iter_mut()
        .find(|tab| tab.tab_id == movement.target_tab_id)
        .ok_or(TerminalMoveError::NotFound)?;
    if !replace_node(&mut target.layout, movement.target_pane_id, &mut |old| {
        let moved = TerminalLayout::Pane {
            pane: moved.clone(),
        };
        let (first, second) = if movement.placement == MovePlacement::Before {
            (moved, old)
        } else {
            (old, moved)
        };
        TerminalLayout::Split {
            axis: SplitAxis::Horizontal,
            first: Box::new(first),
            second: Box::new(second),
        }
    }) {
        return Err(TerminalMoveError::NotFound);
    }
    if next.tabs.0.len() > 32 || next.validate().is_err() {
        return Err(TerminalMoveError::ResourceExhausted);
    }
    Ok(next)
}

fn replace_node(
    layout: &mut TerminalLayout,
    id: PaneId,
    replace: &mut impl FnMut(TerminalLayout) -> TerminalLayout,
) -> bool {
    match layout {
        TerminalLayout::Pane { pane } if pane.pane_id == id => {
            *layout = replace(layout.clone());
            true
        }
        TerminalLayout::Split { first, second, .. } => {
            replace_node(first, id, replace) || replace_node(second, id, replace)
        }
        _ => false,
    }
}
fn remove_pane(
    layout: TerminalLayout,
    id: PaneId,
) -> (Option<TerminalLayout>, Option<TerminalPane>) {
    match layout {
        TerminalLayout::Pane { pane } if pane.pane_id == id => (None, Some(pane)),
        TerminalLayout::Split {
            axis,
            first,
            second,
        } => {
            let (first, removed) = remove_pane(*first, id);
            if let Some(removed) = removed {
                return (
                    match first {
                        Some(first) => Some(TerminalLayout::Split {
                            axis,
                            first: Box::new(first),
                            second,
                        }),
                        None => Some(*second),
                    },
                    Some(removed),
                );
            }
            let (second, removed) = remove_pane(*second, id);
            (
                match second {
                    Some(second) => Some(TerminalLayout::Split {
                        axis,
                        first: Box::new(first.expect("no removal in first")),
                        second: Box::new(second),
                    }),
                    None => first,
                },
                removed,
            )
        }
        other => (Some(other), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_protocol::*;

    fn context() -> WorkspaceContext {
        WorkspaceContext {
            workspace_id: WorkspaceId::from_bytes([1; 16]).unwrap(),
            workspace_epoch: WorkspaceEpoch::from_bytes([2; 16]).unwrap(),
            runtime_id: RuntimeId::from_bytes([3; 16]).unwrap(),
            runtime_generation: DecimalU64(4),
            host_access_epoch: DecimalU64(5),
            grant_revision: DecimalU64(6),
        }
    }
    fn pane(id: u8, running: bool) -> TerminalLayout {
        let pane_id = PaneId::from_bytes([id; 16]).unwrap();
        TerminalLayout::Pane {
            pane: TerminalPane {
                pane_id,
                state: if running {
                    PaneState::Running
                } else {
                    PaneState::Stopped
                },
                session: running.then(|| TerminalContext {
                    workspace: context(),
                    pane_id,
                    session_id: TerminalSessionId::from_bytes([id + 40; 16]).unwrap(),
                    session_epoch: SessionEpoch::from_bytes([id + 80; 16]).unwrap(),
                    profile: TerminalProfile::ExperimentalRustGridV1,
                }),
            },
        }
    }
    fn split(first: TerminalLayout, second: TerminalLayout) -> TerminalLayout {
        TerminalLayout::Split {
            axis: SplitAxis::Horizontal,
            first: Box::new(first),
            second: Box::new(second),
        }
    }
    fn state() -> WorkspaceState {
        WorkspaceState {
            context: context(),
            domain_revision: DecimalU64(7),
            name: "workspace".to_owned().try_into().unwrap(),
            tabs: BoundedList(vec![
                TerminalTab {
                    tab_id: TabId::from_bytes([11; 16]).unwrap(),
                    name: "source".to_owned().try_into().unwrap(),
                    layout: split(pane(21, true), pane(22, false)),
                },
                TerminalTab {
                    tab_id: TabId::from_bytes([12; 16]).unwrap(),
                    name: "target".to_owned().try_into().unwrap(),
                    layout: pane(23, true),
                },
            ]),
        }
    }
    fn movement(placement: MovePlacement) -> TerminalMoveLayout {
        TerminalMoveLayout {
            pane_id: PaneId::from_bytes([21; 16]).unwrap(),
            source_tab_id: TabId::from_bytes([11; 16]).unwrap(),
            target_tab_id: TabId::from_bytes([12; 16]).unwrap(),
            target_pane_id: PaneId::from_bytes([23; 16]).unwrap(),
            placement,
        }
    }
    fn panes(state: &WorkspaceState) -> std::collections::BTreeMap<PaneId, TerminalPane> {
        let mut result = std::collections::BTreeMap::new();
        let mut stack: Vec<_> = state.tabs.0.iter().map(|tab| &tab.layout).collect();
        while let Some(layout) = stack.pop() {
            match layout {
                TerminalLayout::Pane { pane } => {
                    assert!(result.insert(pane.pane_id, pane.clone()).is_none());
                }
                TerminalLayout::Split { first, second, .. } => {
                    stack.push(first);
                    stack.push(second);
                }
            }
        }
        result
    }
    #[test]
    fn same_tab_before_after_preserves_exact_live_and_stopped_panes() {
        let before = state();
        before.validate().unwrap();
        for placement in [MovePlacement::Before, MovePlacement::After] {
            let mut request = movement(placement);
            request.target_tab_id = request.source_tab_id;
            request.pane_id = PaneId::from_bytes([22; 16]).unwrap();
            request.target_pane_id = PaneId::from_bytes([21; 16]).unwrap();
            let after = plan_terminal_move(&before, &request).unwrap();
            let mut expected = before.clone();
            expected.tabs.0[0].layout = if placement == MovePlacement::Before {
                split(pane(22, false), pane(21, true))
            } else {
                split(pane(21, true), pane(22, false))
            };
            assert_eq!(after, expected);
            assert_eq!(panes(&after), panes(&before));
            after.validate().unwrap();
        }
    }
    #[test]
    fn cross_tab_before_after_and_sole_source_removal_preserve_metadata() {
        for sole in [false, true] {
            for placement in [MovePlacement::Before, MovePlacement::After] {
                let mut before = state();
                if sole {
                    before.tabs.0[0].layout = pane(21, true);
                }
                before.validate().unwrap();
                let after = plan_terminal_move(&before, &movement(placement)).unwrap();
                let mut expected = before.clone();
                if sole {
                    expected.tabs.0.remove(0);
                } else {
                    expected.tabs.0[0].layout = pane(22, false);
                }
                expected.tabs.0.last_mut().unwrap().layout = if placement == MovePlacement::Before {
                    split(pane(21, true), pane(23, true))
                } else {
                    split(pane(23, true), pane(21, true))
                };
                assert_eq!(after, expected);
                assert_eq!(panes(&after), panes(&before));
                after.validate().unwrap();
            }
        }
    }
    #[test]
    fn missing_source_or_target_and_self_target_leave_input_unchanged() {
        let before = state();
        let saved = before.clone();
        for field in 0..4 {
            let mut request = movement(MovePlacement::Before);
            match field {
                0 => request.source_tab_id = TabId::from_bytes([90; 16]).unwrap(),
                1 => request.pane_id = PaneId::from_bytes([90; 16]).unwrap(),
                2 => request.target_tab_id = TabId::from_bytes([90; 16]).unwrap(),
                _ => request.target_pane_id = PaneId::from_bytes([90; 16]).unwrap(),
            }
            assert_eq!(
                plan_terminal_move(&before, &request),
                Err(TerminalMoveError::NotFound)
            );
            assert_eq!(before, saved);
        }
        let mut request = movement(MovePlacement::After);
        request.target_pane_id = request.pane_id;
        request.source_tab_id = TabId::from_bytes([90; 16]).unwrap();
        assert_eq!(
            plan_terminal_move(&before, &request),
            Err(TerminalMoveError::InvalidArgument)
        );
        assert_eq!(before, saved);
    }
    #[test]
    fn final_layout_depth_and_pane_bounds_use_existing_validation() {
        let mut before = state();
        let mut target = pane(23, true);
        for id in 30..64 {
            target = split(pane(id, false), target);
        }
        before.tabs.0[1].layout = target;
        let saved = before.clone();
        assert!(before.validate().is_err());
        assert_eq!(
            plan_terminal_move(&before, &movement(MovePlacement::After)),
            Err(TerminalMoveError::ResourceExhausted)
        );
        assert_eq!(before, saved);
    }
}
