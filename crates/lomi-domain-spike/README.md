# Mixed layout proof (E0)

This crate exercises synthetic, in-memory terminal ownership and reference
reconciliation. It does not integrate with the desktop, own a PTY, preserve real
processes, implement persistence, or qualify the E4 migration gate.

`HostDomain` holds terminal-only tabs and one CAS revision. Desktop trees live in
a separate type and contain opaque application-owned private-view handles. Actual
buffers, task state and private view data remain outside the host. Projection
removes private references and collapses splits; it is a proof helper, not a
client snapshot-write API. Host mutations never import a desktop projection.

Close reconciliation prunes terminal references using the authoritative host,
retaining private handles and mixed tabs with remaining private views. Tests keep
a dirty document in an external application map and check its pointer and bytes
remain unchanged. A protected task reference is also excluded from projection.
Move validates the exact workspace identity and preserves terminal identity.
Attachments reference existing panes and cannot call a shell factory. Full
application event ordering, move/add presentation, session epochs, protected-task
write admission and real process lifecycle remain integration work.
