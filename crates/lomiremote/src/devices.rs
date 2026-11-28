//! `lomiremote devices ...` (P3a.12): list, approve, deny, revoke and the mode, over the Host's
//! owner-local `devices.*` calls. The TUI screen reuses the helpers here.
use clap::ArgMatches;
use lomi_remote_protocol::ipc::{
    LocalCall, LocalDeviceApproval, LocalDeviceGrant, LocalDeviceLevel, LocalDeviceMode,
    LocalDeviceModeState, LocalDeviceReason, LocalDeviceRevoke, LocalDeviceTarget, LocalDevices,
    LocalResult,
};
use std::fmt::Write;

/// How many leading fingerprint characters are shown (and the fewest that may select a device).
pub const SHORT: usize = 12;
const MIN_PREFIX: usize = 4;

pub fn short(fingerprint: &str) -> &str {
    fingerprint.get(..SHORT).unwrap_or(fingerprint)
}
pub fn level(l: LocalDeviceLevel) -> &'static str {
    match l {
        LocalDeviceLevel::Read => "read",
        LocalDeviceLevel::Control => "control",
    }
}
pub fn mode_name(m: LocalDeviceMode) -> &'static str {
    match m {
        LocalDeviceMode::Auto => "auto",
        LocalDeviceMode::Confirm => "confirm",
    }
}
pub fn reason(r: LocalDeviceReason) -> &'static str {
    match r {
        LocalDeviceReason::NewDevice => "new device",
        LocalDeviceReason::Control => "control request",
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Pick<'a, T> {
    None,
    One(&'a T),
    Many(Vec<&'a T>),
}
fn pick<T>(mut hits: Vec<&T>) -> Pick<'_, T> {
    match hits.len() {
        0 => Pick::None,
        1 => Pick::One(hits.remove(0)),
        _ => Pick::Many(hits),
    }
}
/// The 6-digit code the device shows, or the start (at least 4 characters) of the circuit id.
pub fn pick_approval<'a>(
    pending: &'a [LocalDeviceApproval],
    arg: &str,
) -> Pick<'a, LocalDeviceApproval> {
    let by_code: Vec<_> = pending.iter().filter(|p| p.code.as_str() == arg).collect();
    if !by_code.is_empty() {
        return pick(by_code);
    }
    let arg = arg.to_ascii_lowercase();
    pick(if arg.len() < MIN_PREFIX {
        Vec::new()
    } else {
        pending
            .iter()
            .filter(|p| p.circuit.as_str().starts_with(&arg))
            .collect()
    })
}
/// The start (at least 4 characters) of the fingerprint.
pub fn pick_grant<'a>(grants: &'a [LocalDeviceGrant], prefix: &str) -> Pick<'a, LocalDeviceGrant> {
    let prefix = prefix.to_ascii_lowercase();
    pick(if prefix.len() < MIN_PREFIX {
        Vec::new()
    } else {
        grants
            .iter()
            .filter(|g| g.fingerprint.as_str().starts_with(&prefix))
            .collect()
    })
}

fn label(s: &str) -> String {
    crate::ui::safe_label(s)
}
pub fn grant_line(g: &LocalDeviceGrant) -> String {
    format!(
        "{}  {}  {}  {}{}",
        short(g.fingerprint.as_str()),
        label(g.name.as_str()),
        g.kind.as_str(),
        level(g.level),
        if g.valid {
            ""
        } else {
            "  [not confirmed by the server]"
        }
    )
}
pub fn approval_line(a: &LocalDeviceApproval) -> String {
    format!(
        "code {}  {}  {}  ({})",
        a.code.as_str(),
        label(a.device_name.as_str()),
        short(a.fingerprint.as_str()),
        reason(a.reason)
    )
}
pub fn render(d: &LocalDevices) -> String {
    let mut out = format!("Mode: {}\n", mode_name(d.mode));
    if d.pending.0.is_empty() {
        out.push_str("No approvals waiting.\n");
    } else {
        out.push_str("Waiting for approval:\n");
        for a in &d.pending.0 {
            let _ = writeln!(out, "  {}", approval_line(a));
        }
    }
    if d.grants.0.is_empty() {
        out.push_str("No devices.\n");
    } else {
        out.push_str("Devices:\n");
        for g in &d.grants.0 {
            let _ = writeln!(out, "  {}", grant_line(g));
        }
    }
    out
}

fn ambiguous<T>(hits: &[&T], line: impl Fn(&T) -> String) {
    eprintln!("More than one match; use more characters:");
    for h in hits {
        eprintln!("  {}", line(h));
    }
}

/// Runs one `devices` subcommand. `call` performs a local IPC call and reports its own failures
/// (returning the exit code). Exit codes: 0 done, 2 usage or ambiguous, 7 nothing matched.
pub fn run(
    args: &ArgMatches,
    json: bool,
    call: &mut dyn FnMut(LocalCall) -> Result<LocalResult, u8>,
) -> u8 {
    let list = |call: &mut dyn FnMut(LocalCall) -> Result<LocalResult, u8>| match call(
        LocalCall::DevicesList {},
    ) {
        Ok(LocalResult::Devices(d)) => Ok(d),
        Ok(_) => Err(6),
        Err(code) => Err(code),
    };
    let finish = |result: LocalResult, text: String| {
        if json {
            if serde_json::to_writer(std::io::stdout().lock(), &result).is_err() {
                return 4;
            }
            println!();
        } else {
            print!("{text}");
        }
        0
    };
    match args.subcommand() {
        Some(("list", _)) | None => match call(LocalCall::DevicesList {}) {
            Ok(LocalResult::Devices(d)) => finish(LocalResult::Devices(d.clone()), render(&d)),
            Ok(_) => 6,
            Err(code) => code,
        },
        Some((verb @ ("approve" | "deny"), sub)) => {
            let arg = sub.get_one::<String>("code").cloned().unwrap_or_default();
            let d = match list(call) {
                Ok(d) => d,
                Err(code) => return code,
            };
            let a = match pick_approval(&d.pending.0, &arg) {
                Pick::One(a) => a,
                Pick::None => {
                    eprintln!(
                        "No waiting approval matches {arg:?}. See `lomiremote devices list`."
                    );
                    return 7;
                }
                Pick::Many(hits) => {
                    ambiguous(&hits, approval_line);
                    return 2;
                }
            };
            let target = LocalDeviceTarget {
                circuit: a.circuit.clone(),
            };
            let (request, done) = if verb == "approve" {
                (LocalCall::DevicesApprove(target), "Approved")
            } else {
                (LocalCall::DevicesDeny(target), "Denied")
            };
            match call(request) {
                Ok(r) => finish(r, format!("{done}: {}\n", label(a.device_name.as_str()))),
                Err(code) => code,
            }
        }
        Some(("revoke", sub)) => {
            if !sub.get_flag("confirm") {
                eprintln!(
                    "CONFIRMATION_REQUIRED: revoking closes the device's tunnels; add --confirm"
                );
                return 2;
            }
            let arg = sub
                .get_one::<String>("fingerprint")
                .cloned()
                .unwrap_or_default();
            let d = match list(call) {
                Ok(d) => d,
                Err(code) => return code,
            };
            let g = match pick_grant(&d.grants.0, &arg) {
                Pick::One(g) => g,
                Pick::None => {
                    eprintln!("No device matches {arg:?}. See `lomiremote devices list`.");
                    return 7;
                }
                Pick::Many(hits) => {
                    ambiguous(&hits, grant_line);
                    return 2;
                }
            };
            match call(LocalCall::DevicesRevoke(LocalDeviceRevoke {
                fingerprint: g.fingerprint.clone(),
            })) {
                Ok(r) => finish(r, format!("Revoked: {}\n", label(g.name.as_str()))),
                Err(code) => code,
            }
        }
        Some(("mode", sub)) => {
            let request = match sub.get_one::<String>("mode").map(String::as_str) {
                None => LocalCall::DevicesModeGet {},
                Some(m) => LocalCall::DevicesModeSet(LocalDeviceModeState {
                    mode: if m == "confirm" {
                        LocalDeviceMode::Confirm
                    } else {
                        LocalDeviceMode::Auto
                    },
                }),
            };
            match call(request) {
                Ok(LocalResult::DeviceMode(m)) => finish(
                    LocalResult::DeviceMode(m.clone()),
                    format!("Mode: {}\n", mode_name(m.mode)),
                ),
                Ok(_) => 6,
                Err(code) => code,
            }
        }
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli;
    use lomi_remote_protocol::{DecimalU64, ipc::LocalDeviceText, rpc::BoundedList};

    fn text(s: &str) -> LocalDeviceText {
        LocalDeviceText::try_from(s.to_owned()).unwrap()
    }
    fn approval(circuit: &str, code: &str) -> LocalDeviceApproval {
        LocalDeviceApproval {
            circuit: text(circuit),
            device_name: text("Phone"),
            fingerprint: text(&"ab".repeat(32)),
            code: text(code),
            reason: LocalDeviceReason::NewDevice,
            at: DecimalU64(1),
        }
    }
    fn grant(fingerprint: &str) -> LocalDeviceGrant {
        LocalDeviceGrant {
            name: text("Laptop"),
            kind: text("web"),
            fingerprint: text(fingerprint),
            level: LocalDeviceLevel::Read,
            granted_at: DecimalU64(1),
            server_confirmed_at: DecimalU64(1),
            valid: true,
        }
    }
    fn parse(args: &[&str]) -> ArgMatches {
        let m = cli::command()
            .try_get_matches_from(["lomiremote", "devices"].iter().chain(args))
            .unwrap();
        m.subcommand_matches("devices").unwrap().clone()
    }

    #[test]
    fn arguments_parse() {
        assert!(
            parse(&["list", "--json"])
                .subcommand_matches("list")
                .unwrap()
                .get_flag("json")
        );
        assert_eq!(
            parse(&["approve", "123456"])
                .subcommand_matches("approve")
                .unwrap()
                .get_one::<String>("code")
                .unwrap(),
            "123456"
        );
        assert!(
            parse(&["revoke", "ab12", "--confirm"])
                .subcommand_matches("revoke")
                .unwrap()
                .get_flag("confirm")
        );
        assert_eq!(
            parse(&["mode", "confirm"])
                .subcommand_matches("mode")
                .unwrap()
                .get_one::<String>("mode")
                .unwrap(),
            "confirm"
        );
        assert!(
            parse(&["mode"])
                .subcommand_matches("mode")
                .unwrap()
                .get_one::<String>("mode")
                .is_none()
        );
        assert!(
            cli::command()
                .try_get_matches_from(["lomiremote", "devices", "mode", "loud"])
                .is_err()
        );
        assert!(
            cli::command()
                .try_get_matches_from(["lomiremote", "devices", "approve"])
                .is_err()
        );
    }

    #[test]
    fn approvals_are_picked_by_code_or_circuit_prefix() {
        let a = approval(&"11".repeat(16), "111111");
        let b = approval(&"12".repeat(16), "222222");
        let p = [a.clone(), b.clone()];
        assert_eq!(pick_approval(&p, "222222"), Pick::One(&p[1]));
        assert_eq!(pick_approval(&p, "1212"), Pick::One(&p[1]));
        assert!(matches!(pick_approval(&p, "1"), Pick::None), "too short");
        assert!(matches!(pick_approval(&p, "333333"), Pick::None));
        let twin = [a.clone(), approval(&"13".repeat(16), "111111")];
        assert!(matches!(pick_approval(&twin, "111111"), Pick::Many(h) if h.len() == 2));
    }

    #[test]
    fn grants_are_picked_by_fingerprint_prefix() {
        let g = [grant(&"ab".repeat(32)), grant(&"abcd".repeat(16))];
        assert!(matches!(pick_grant(&g, "abab"), Pick::One(_)));
        assert!(matches!(pick_grant(&g, "ab"), Pick::None), "too short");
        assert!(matches!(pick_grant(&g, "abc"), Pick::None), "too short");
        assert!(matches!(pick_grant(&g, "abcd"), Pick::One(_)));
        assert!(matches!(pick_grant(&g, "ABCD"), Pick::One(_)));
        assert!(matches!(pick_grant(&g, "ffff"), Pick::None));
        let same = [
            grant(&"ab".repeat(32)),
            grant(&format!("abab{}", "0".repeat(60))),
        ];
        assert!(matches!(pick_grant(&same, "abab"), Pick::Many(_)));
    }

    #[test]
    fn approve_and_revoke_resolve_then_call_the_host() {
        let d = LocalDevices {
            mode: LocalDeviceMode::Confirm,
            grants: BoundedList(vec![grant(&"cd".repeat(32))]),
            pending: BoundedList(vec![approval(&"11".repeat(16), "123456")]),
        };
        let mut calls = Vec::new();
        let mut host = |c: LocalCall| {
            calls.push(c.clone());
            Ok(LocalResult::Devices(d.clone()))
        };
        assert_eq!(run(&parse(&["approve", "123456"]), true, &mut host), 0);
        assert_eq!(run(&parse(&["deny", "999999"]), true, &mut host), 7);
        assert_eq!(
            run(&parse(&["revoke", "cdcd"]), true, &mut host),
            2,
            "needs --confirm"
        );
        assert_eq!(
            run(&parse(&["revoke", "cdcd", "--confirm"]), true, &mut host),
            0
        );
        assert!(
            matches!(&calls[1], LocalCall::DevicesApprove(t) if t.circuit.as_str() == "11".repeat(16))
        );
        assert!(
            matches!(calls.last(), Some(LocalCall::DevicesRevoke(r)) if r.fingerprint.as_str() == "cd".repeat(32))
        );
        assert_eq!(calls.len(), 5, "list+approve, list(deny), list+revoke");
    }
}
