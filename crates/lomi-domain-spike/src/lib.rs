//! Pure synthetic layout proof. No desktop integration or PTY ownership.
use lomi_remote_protocol::{CapabilitySet, DecimalU64};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalTree {
    Pane(String),
    Split(Box<Self>, Box<Self>),
}
impl TerminalTree {
    fn panes(&self, out: &mut Vec<String>) {
        match self {
            Self::Pane(id) => out.push(id.clone()),
            Self::Split(a, b) => {
                a.panes(out);
                b.panes(out);
            }
        }
    }
    fn remove(self, target: &str) -> Option<Self> {
        match self {
            Self::Pane(id) => (id != target).then_some(Self::Pane(id)),
            Self::Split(a, b) => collapse_terminal(a.remove(target), b.remove(target)),
        }
    }
}
fn collapse_terminal(a: Option<TerminalTree>, b: Option<TerminalTree>) -> Option<TerminalTree> {
    match (a, b) {
        (Some(a), Some(b)) => Some(TerminalTree::Split(Box::new(a), Box::new(b))),
        (Some(a), None) | (None, Some(a)) => Some(a),
        _ => None,
    }
}

/// An application-owned handle only. Buffer bytes and private view state never
/// enter this crate's host model, nor are they cloned by reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateViewRef(pub String);
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTree {
    TerminalRef(String),
    PrivateRef(PrivateViewRef),
    Split(Box<Self>, Box<Self>),
}
impl LocalTree {
    pub fn terminal_projection(&self) -> Option<TerminalTree> {
        match self {
            Self::TerminalRef(id) => Some(TerminalTree::Pane(id.clone())),
            Self::PrivateRef(_) => None,
            Self::Split(a, b) => {
                collapse_terminal(a.terminal_projection(), b.terminal_projection())
            }
        }
    }
    fn retain_terminals(self, live: &BTreeSet<String>) -> Option<Self> {
        match self {
            Self::TerminalRef(id) => live.contains(&id).then_some(Self::TerminalRef(id)),
            node @ Self::PrivateRef(_) => Some(node),
            Self::Split(a, b) => match (a.retain_terminals(live), b.retain_terminals(live)) {
                (Some(a), Some(b)) => Some(Self::Split(Box::new(a), Box::new(b))),
                (Some(a), None) | (None, Some(a)) => Some(a),
                _ => None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalTab {
    pub id: String,
    pub tree: TerminalTree,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTab {
    pub host_tab_id: String,
    pub tree: LocalTree,
}
/// Application-owned presentation, separate from HostDomain. Private refs may
/// include editor, browser, Android, chat, or protected native task handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopPresentation {
    pub tabs: Vec<LocalTab>,
}
impl DesktopPresentation {
    /// Apply authoritative removal events to existing local references. This
    /// synthetic proof handles close; full desktop move/add integration is E4.
    pub fn reconcile_closes(&mut self, host: &HostDomain) {
        self.tabs = std::mem::take(&mut self.tabs)
            .into_iter()
            .filter_map(|tab| {
                let live = host
                    .tabs
                    .get(&tab.host_tab_id)
                    .map(pane_set)
                    .unwrap_or_default();
                tab.tree.retain_terminals(&live).map(|tree| LocalTab {
                    host_tab_id: tab.host_tab_id,
                    tree,
                })
            })
            .collect();
    }
}
fn pane_set(tree: &TerminalTree) -> BTreeSet<String> {
    let mut panes = Vec::new();
    tree.panes(&mut panes);
    panes.into_iter().collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    RevisionConflict,
    RevisionExhausted,
    CrossWorkspaceMove,
    NotFound,
    DuplicateIdentity,
    ScopeDenied,
}
/// The only authoritative terminal layout. It has no private-view field, private
/// buffers, executable task state or application-owned document data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDomain {
    workspace_id: String,
    revision: DecimalU64,
    tabs: BTreeMap<String, TerminalTree>,
    attachments: BTreeSet<(String, String)>,
}
impl HostDomain {
    pub fn new(
        workspace_id: String,
        revision: DecimalU64,
        tabs: Vec<TerminalTab>,
    ) -> Result<Self, DomainError> {
        let mut by_id = BTreeMap::new();
        let mut panes = BTreeSet::new();
        for tab in tabs {
            let mut ids = Vec::new();
            tab.tree.panes(&mut ids);
            if ids.into_iter().any(|id| !panes.insert(id))
                || by_id.insert(tab.id, tab.tree).is_some()
            {
                return Err(DomainError::DuplicateIdentity);
            }
        }
        Ok(Self {
            workspace_id,
            revision,
            tabs: by_id,
            attachments: BTreeSet::new(),
        })
    }
    pub fn revision(&self) -> DecimalU64 {
        self.revision
    }
    pub fn terminal_tabs(&self) -> &BTreeMap<String, TerminalTree> {
        &self.tabs
    }
    pub fn pane_count(&self) -> usize {
        self.tabs.values().map(|t| pane_set(t).len()).sum()
    }
    fn next_revision(
        &self,
        expected: DecimalU64,
        caps: &CapabilitySet,
        method: &str,
    ) -> Result<DecimalU64, DomainError> {
        caps.authorize(method, false)
            .map_err(|_| DomainError::ScopeDenied)?;
        if self.revision != expected {
            return Err(DomainError::RevisionConflict);
        }
        self.revision
            .0
            .checked_add(1)
            .map(DecimalU64)
            .ok_or(DomainError::RevisionExhausted)
    }
    fn prune_attachments(&mut self) {
        let live: BTreeSet<_> = self.tabs.values().flat_map(pane_set).collect();
        self.attachments.retain(|(_, pane)| live.contains(pane));
    }
    pub fn close_pane(
        &mut self,
        pane: &str,
        expected: DecimalU64,
        caps: &CapabilitySet,
    ) -> Result<(), DomainError> {
        let next = self.next_revision(expected, caps, "terminal.close")?;
        let tab = self
            .tabs
            .iter()
            .find(|(_, t)| pane_set(t).contains(pane))
            .map(|(id, _)| id.clone())
            .ok_or(DomainError::NotFound)?;
        let tree = self.tabs.remove(&tab).unwrap();
        if let Some(tree) = tree.remove(pane) {
            self.tabs.insert(tab, tree);
        }
        self.revision = next;
        self.prune_attachments();
        Ok(())
    }
    pub fn close_tab(
        &mut self,
        tab: &str,
        expected: DecimalU64,
        caps: &CapabilitySet,
    ) -> Result<(), DomainError> {
        let next = self.next_revision(expected, caps, "terminal.close")?;
        self.tabs.remove(tab).ok_or(DomainError::NotFound)?;
        self.revision = next;
        self.prune_attachments();
        Ok(())
    }
    pub fn move_pane(
        &mut self,
        target_workspace: &str,
        pane: &str,
        destination_tab: &str,
        expected: DecimalU64,
        caps: &CapabilitySet,
    ) -> Result<(), DomainError> {
        let next = self.next_revision(expected, caps, "terminal.move")?;
        if target_workspace != self.workspace_id {
            return Err(DomainError::CrossWorkspaceMove);
        }
        if !self.tabs.contains_key(destination_tab) {
            return Err(DomainError::NotFound);
        }
        let source = self
            .tabs
            .iter()
            .find(|(_, t)| pane_set(t).contains(pane))
            .map(|(id, _)| id.clone())
            .ok_or(DomainError::NotFound)?;
        if source == destination_tab {
            return Ok(());
        }
        let tree = self.tabs.remove(&source).unwrap();
        if let Some(tree) = tree.remove(pane) {
            self.tabs.insert(source, tree);
        }
        let destination = self.tabs.remove(destination_tab).unwrap();
        self.tabs.insert(
            destination_tab.to_owned(),
            TerminalTree::Split(
                Box::new(destination),
                Box::new(TerminalTree::Pane(pane.to_owned())),
            ),
        );
        self.revision = next;
        Ok(())
    }
    /// Attaching only records a view reference. There is no shell factory or
    /// execution callback on this path; existing membership is mandatory.
    pub fn attach(
        &mut self,
        view: &str,
        pane: &str,
        caps: &CapabilitySet,
    ) -> Result<(), DomainError> {
        caps.authorize("terminal.attach", false)
            .map_err(|_| DomainError::ScopeDenied)?;
        if !self.tabs.values().any(|t| pane_set(t).contains(pane)) {
            return Err(DomainError::NotFound);
        }
        self.attachments.insert((view.to_owned(), pane.to_owned()));
        Ok(())
    }
    pub fn detach(&mut self, view: &str) {
        self.attachments.retain(|(v, _)| v != view);
    }
    pub fn attachment_count(&self) -> usize {
        self.attachments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;
    fn caps() -> CapabilitySet {
        CapabilitySet::control_with_workspace_tools()
    }
    fn host() -> HostDomain {
        HostDomain::new(
            "workspace-a".into(),
            DecimalU64(7),
            vec![
                TerminalTab {
                    id: "tab-a".into(),
                    tree: TerminalTree::Split(
                        Box::new(TerminalTree::Pane("one".into())),
                        Box::new(TerminalTree::Pane("two".into())),
                    ),
                },
                TerminalTab {
                    id: "tab-b".into(),
                    tree: TerminalTree::Pane("three".into()),
                },
            ],
        )
        .unwrap()
    }
    fn local() -> DesktopPresentation {
        DesktopPresentation {
            tabs: vec![LocalTab {
                host_tab_id: "tab-a".into(),
                tree: LocalTree::Split(
                    Box::new(LocalTree::Split(
                        Box::new(LocalTree::TerminalRef("one".into())),
                        Box::new(LocalTree::PrivateRef(PrivateViewRef("dirty-editor".into()))),
                    )),
                    Box::new(LocalTree::Split(
                        Box::new(LocalTree::TerminalRef("two".into())),
                        Box::new(LocalTree::PrivateRef(PrivateViewRef(
                            "protected-task".into(),
                        ))),
                    )),
                ),
            }],
        }
    }
    #[test]
    fn projection_removes_private_views_and_collapses_splits() {
        let desktop = local();
        let host = host();
        assert_eq!(
            desktop.tabs[0].tree.terminal_projection().as_ref(),
            host.terminal_tabs().get("tab-a")
        );
        let private = LocalTree::PrivateRef(PrivateViewRef("protected-task".into()));
        assert_eq!(private.terminal_projection(), None);
        assert_eq!(host.pane_count(), 3);
    }
    #[test]
    fn remote_pane_and_tab_close_preserve_dirty_editor_and_protected_task_refs() {
        // The actual application owns this buffer; the host never receives it.
        let dirty = Rc::new(("unsaved secret".to_owned(), true));
        let documents =
            BTreeMap::from([(PrivateViewRef("dirty-editor".into()).0, Rc::clone(&dirty))]);
        let mut desktop = local();
        let mut host = host();
        host.close_pane("one", DecimalU64(7), &caps()).unwrap();
        desktop.reconcile_closes(&host);
        assert_eq!(
            desktop.tabs[0].tree.terminal_projection(),
            Some(TerminalTree::Pane("two".into()))
        );
        host.close_tab("tab-a", DecimalU64(8), &caps()).unwrap();
        desktop.reconcile_closes(&host);
        assert_eq!(desktop.tabs.len(), 1);
        assert_eq!(
            desktop.tabs[0].tree,
            LocalTree::Split(
                Box::new(LocalTree::PrivateRef(PrivateViewRef("dirty-editor".into()))),
                Box::new(LocalTree::PrivateRef(PrivateViewRef(
                    "protected-task".into()
                )))
            )
        );
        assert!(Rc::ptr_eq(documents.get("dirty-editor").unwrap(), &dirty));
        assert_eq!(&*dirty, &("unsaved secret".to_owned(), true));
        assert_eq!(desktop.tabs[0].tree.terminal_projection(), None);
    }
    #[test]
    fn cas_rejects_stale_concurrent_mutation_without_partial_change() {
        let mut host = host();
        host.close_pane("one", DecimalU64(7), &caps()).unwrap();
        let before = host.clone();
        assert_eq!(
            host.close_tab("tab-a", DecimalU64(7), &caps()),
            Err(DomainError::RevisionConflict)
        );
        assert_eq!(host, before);
    }
    #[test]
    fn move_only_within_workspace_and_preserves_identity() {
        let mut host = host();
        let before = host.clone();
        assert_eq!(
            host.move_pane("workspace-b", "one", "tab-b", DecimalU64(7), &caps()),
            Err(DomainError::CrossWorkspaceMove)
        );
        assert_eq!(host, before);
        host.move_pane("workspace-a", "one", "tab-b", DecimalU64(7), &caps())
            .unwrap();
        assert_eq!(host.pane_count(), 3);
        assert_eq!(host.revision(), DecimalU64(8));
        assert_eq!(
            host.tabs.get("tab-a"),
            Some(&TerminalTree::Pane("two".into()))
        );
        assert!(pane_set(&host.tabs["tab-b"]).contains("one"));
    }
    #[test]
    fn repeated_and_new_window_attach_never_create_terminal_or_change_revision() {
        let mut host = host();
        let tabs = host.tabs.clone();
        host.attach("window-one", "one", &caps()).unwrap();
        host.attach("window-one", "one", &caps()).unwrap();
        host.attach("window-two", "one", &caps()).unwrap();
        assert_eq!(host.attachment_count(), 2);
        assert_eq!(host.tabs, tabs);
        assert_eq!(host.revision(), DecimalU64(7));
        host.detach("window-one");
        host.detach("window-two");
        assert_eq!(host.pane_count(), 3);
        assert_eq!(host.attachment_count(), 0);
        assert_eq!(
            host.attach("new-window", "unknown", &caps()),
            Err(DomainError::NotFound)
        );
    }
    #[test]
    fn missing_manage_and_revision_overflow_do_not_mutate() {
        let mut host = host();
        let before = host.clone();
        let observer = CapabilitySet::try_from(vec![
            lomi_remote_protocol::Capability::WorkspaceRead,
            lomi_remote_protocol::Capability::TerminalObserve,
        ])
        .unwrap();
        assert_eq!(
            host.close_tab("tab-a", DecimalU64(7), &observer),
            Err(DomainError::ScopeDenied)
        );
        assert_eq!(host, before);
        host.revision = DecimalU64(u64::MAX);
        let before = host.clone();
        assert_eq!(
            host.close_tab("tab-a", DecimalU64(u64::MAX), &caps()),
            Err(DomainError::RevisionExhausted)
        );
        assert_eq!(host, before);
    }
}
