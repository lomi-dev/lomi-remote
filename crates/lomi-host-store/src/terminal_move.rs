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
