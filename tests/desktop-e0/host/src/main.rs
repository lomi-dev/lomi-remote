//! Bounded stdio driver for the canonical E0 domain, never a product host.
use lomi_domain_spike::{HostDomain, TerminalTab, TerminalTree};
use lomi_remote_protocol::{CapabilitySet, DecimalU64};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
fn tree(node: &TerminalTree) -> Value {
    match node {
        TerminalTree::Pane(id) => json!({"type":"terminal","id":id}),
        TerminalTree::Split(a, b) => json!({"type":"split","first":tree(a),"second":tree(b)}),
    }
}
fn main() {
    let mut host: Option<HostDomain> = None;
    let caps = CapabilitySet::control_with_workspace_tools();
    for line in io::stdin().lock().lines().take(32) {
        let line = line.unwrap();
        assert!(line.len() <= 16384);
        let request: Value = serde_json::from_str(&line).unwrap();
        let field = |s: &str| request[s].as_str().unwrap();
        let expected = DecimalU64(request["expected"].as_u64().unwrap_or(1));
        let result = match field("op") {
            "init" => {
                host = Some(
                    HostDomain::new(
                        "fixture".into(),
                        DecimalU64(1),
                        vec![
                            TerminalTab {
                                id: field("tabA").into(),
                                tree: TerminalTree::Split(
                                    Box::new(TerminalTree::Pane(field("paneA").into())),
                                    Box::new(TerminalTree::Pane(field("paneC").into())),
                                ),
                            },
                            TerminalTab {
                                id: field("tabB").into(),
                                tree: TerminalTree::Pane(field("paneB").into()),
                            },
                        ],
                    )
                    .unwrap(),
                );
                Ok(())
            }
            "attach" => host
                .as_mut()
                .unwrap()
                .attach(field("view"), field("pane"), &caps),
            "close" => host
                .as_mut()
                .unwrap()
                .close_pane(field("pane"), expected, &caps),
            "move" => host.as_mut().unwrap().move_pane(
                "fixture",
                field("pane"),
                field("tab"),
                expected,
                &caps,
            ),
            _ => panic!("unsupported fixture command"),
        };
        let host = host.as_ref().unwrap();
        println!(
            "{}",
            json!({"ok":result.is_ok(),"error":result.err().map(|e|format!("{e:?}")),"revision":host.revision().0,"attachments":host.attachment_count(),"tabs":host.terminal_tabs().iter().map(|(id,t)|json!({"id":id,"tree":tree(t)})).collect::<Vec<_>>() })
        );
        io::stdout().flush().unwrap();
    }
}
