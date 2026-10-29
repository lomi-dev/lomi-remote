//! Synthetic projection fixtures; these do not qualify arbitrary CLI compatibility.
use lomi_terminal_state::{GridPatch, PROFILE, TerminalState};
use serde_json::json;
fn main() {
    let mut eviction = Vec::new();
    for _ in 0..2000 {
        eviction.extend_from_slice(b"synthetic line\r\n");
    }
    let astral_marks = format!("🙂{}", "\u{1d185}".repeat(64));
    let cases: Vec<(&str, &[u8], &[u8])> = vec![
        ("normal_ascii", b"hello\r\nworld", b"!"),
        (
            "file_hyperlink_projected",
            b"\x1b]8;id=file;file:///tmp/example\x1b\\visible",
            b"!",
        ),
        (
            "javascript_hyperlink_projected",
            b"\x1b]8;id=script;javascript:alert(1)\x1b\\visible",
            b"!",
        ),
        (
            "invalid_https_projected",
            b"\x1b]8;id=invalid;http://[broken\x1b\\visible",
            b"!",
        ),
        (
            "valid_https_metadata",
            "\u{1b}]8;id=fixture;https://example.invalid/界\u{1b}\\visible".as_bytes(),
            b"!",
        ),
        (
            "c1_hyperlink_projected",
            "\u{1b}]8;id=bad\u{85};https://example.invalid\u{1b}\\visible".as_bytes(),
            b"!",
        ),
        (
            "c1_title_projected",
            "\u{1b}]2;before\u{85}after\u{7}visible".as_bytes(),
            b"!",
        ),
        (
            "astral_combining_utf16_limit",
            astral_marks.as_bytes(),
            b"!",
        ),
        (
            "dynamic_palette_bounds",
            b"\x1b]10;#112233;#445566;#778899;#abcdef\x07\x1b]4;259;#123456\x07visible",
            b"!",
        ),
        (
            "alternate_to_normal",
            b"NORMAL\x1b[?1049hALT",
            b"\x1b[?1049l!",
        ),
        (
            "inactive_alternate",
            b"NORMAL\x1b[?1049hALT\x1b[?1049l",
            b"!",
        ),
        ("pending_csi", b"hello\x1b[2;", b"3HX"),
        ("pending_utf8", &[b'A', 0xe7, 0x95], &[0x8c, b'!']),
        (
            "unicode_cells",
            "A界e\u{301}🙂".as_bytes(),
            "Z界".as_bytes(),
        ),
        (
            "colors_modes",
            b"\x1b[31;44;1mRED\x1b[?1h\x1b[?2004h\x1b[?1000h\x1b[?1006h",
            b"X",
        ),
        ("scroll_region_origin", b"\x1b[2;5r\x1b[?6hA", b"\x1b[H!"),
        ("saved_cursor", b"ABC\x1b7\x1b[4;8H", b"\x1b8!"),
        (
            "osc_title_hyperlink",
            b"\x1b]2;synthetic title\x07\x1b]8;id=fixture;https://example.invalid\x1b\\link",
            b"!\x1b]8;;\x1b\\",
        ),
        ("pending_osc", b"\x1b]2;synthetic", b" title\x07!"),
        ("pending_dcs", b"\x1bP$q", b"m\x1b\\done"),
        (
            "resize_reflow",
            b"abcdefghijklmnopqrstuvwxyz0123456789",
            b"!\r\nend",
        ),
        ("bounded_history_evicted", &eviction, b"\r\nlast"),
        (
            "tabs_margins",
            b"A\x1b[3g\x1b[9G\x1bH\x1b[2;5r",
            b"\r\tX\x1b[5;1H\n!",
        ),
        (
            "palette",
            b"\x1b]4;1;rgb:12/34/56\x07\x1b[31mX",
            b"\x1b]104;1\x07!",
        ),
    ];
    let mut fixtures: Vec<_> = cases
        .into_iter()
        .map(|(id, prefix, live)| {
            let mut host = TerminalState::new(6, 24, 8).unwrap();
            for chunk in prefix.chunks(65536) {
                host.feed(chunk).unwrap();
            }
            if id == "resize_reflow" {
                host.resize(6, 16).unwrap();
            }
            let snapshot = host.snapshot().unwrap();
            let mut previous = snapshot.clone();
            let mut deltas = Vec::new();
            if id == "resize_reflow" {
                host.resize(8, 20).unwrap();
                let d = host.next_delta(&previous).unwrap();
                previous = d.state.clone();
                deltas.push(d);
            }
            host.feed(live).unwrap();
            deltas.push(host.next_delta(&previous).unwrap());
            json!({"id":id,"snapshot":snapshot,"deltas":deltas,"final":host.snapshot().unwrap()})
        })
        .collect();
    let mut host = TerminalState::new(6, 24, 8).unwrap();
    let snapshot = host.snapshot().unwrap();
    let mut previous = snapshot.clone();
    let mut deltas = Vec::new();
    for byte in "A界\u{1b}[2;3HX\u{1b}]2;title\u{7}\u{1b}P$qm\u{1b}\\!".as_bytes() {
        host.feed(&[*byte]).unwrap();
        let d = host.next_delta(&previous).unwrap();
        previous = d.state.clone();
        deltas.push(d);
    }
    fixtures.push(json!({"id":"every_byte_parser_boundaries","snapshot":snapshot,"deltas":deltas,"final":host.snapshot().unwrap()}));
    let mut host = TerminalState::new(6, 24, 8).unwrap();
    host.feed(b"before\x1b[?2026hafter\x1b[6n").unwrap();
    let snapshot = host.snapshot().unwrap();
    host.expire_sync(host.sync_deadline().unwrap()).unwrap();
    let timed = host.next_delta(&snapshot).unwrap();
    host.feed(b"!").unwrap();
    let live = host.next_delta(&timed.state).unwrap();
    fixtures.push(json!({"id":"synchronized_update_owner_timeout","snapshot":snapshot,"deltas":[timed,live],"final":host.snapshot().unwrap()}));
    for id in ["history_growth_trim", "scroll_unicode_styles_modes"] {
        let mut host = TerminalState::new(6, 24, 8).unwrap();
        let snapshot = host.snapshot().unwrap();
        let mut previous = snapshot.clone();
        let mut deltas = Vec::new();
        for round in 0..12 {
            let text = if id == "history_growth_trim" {
                format!("round {round}\r\n").repeat(3)
            } else {
                format!("\x1b[{}m界e\u{301} {round}\x1b[0m\r\n", 31 + round % 6).repeat(3)
            };
            host.feed(text.as_bytes()).unwrap();
            let delta = host.next_delta(&previous).unwrap();
            previous = delta.state.clone();
            deltas.push(delta);
        }
        fixtures.push(
            json!({"id":id,"snapshot":snapshot,"deltas":deltas,"final":host.snapshot().unwrap()}),
        );
    }
    // Emit the production patch beside each unchanged legacy proof delta.
    for fixture in &mut fixtures {
        let mut previous: lomi_terminal_state::Snapshot =
            serde_json::from_value(fixture["snapshot"].clone()).unwrap();
        let mut patches = Vec::new();
        for delta in fixture["deltas"].as_array().unwrap() {
            let next: lomi_terminal_state::Snapshot =
                serde_json::from_value(delta["state"].clone()).unwrap();
            let patch = GridPatch::between(&previous, &next).unwrap();
            assert_eq!(patch.apply(&previous).unwrap(), next);
            patches.push(patch);
            previous = next;
        }
        fixture["patches"] = serde_json::to_value(patches).unwrap();
    }
    println!(
        "{}",
        json!({"profile":PROFILE,"patchFormat":"grid-patch-v1","qualified":false,"rows":6,"cols":24,"scrollback":8,"cases":fixtures,"compatibilityLimits":["DEC private mode 47 is unsupported by Alacritty 0.26; inactive-buffer fixture uses 1049","No parser transfer or host-crash process recovery","Synthetic projection equality does not establish raw xterm or arbitrary CLI compatibility"]})
    );
}
