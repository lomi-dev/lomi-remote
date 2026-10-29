use lomi_remote_protocol::DecimalU64;
use lomi_terminal_state::{Snapshot, TerminalState};
#[cfg(unix)]
use std::fs;
use uuid::Uuid;
#[cfg(unix)]
mod git_capture;

#[test]
fn synchronized_output_expires_without_more_pty_bytes_or_observer_side_effects() {
    let mut host = TerminalState::new(6, 24, 8).unwrap();
    host.feed(b"before\x1b[?2026hafter\x1b[6n").unwrap();
    let pending = host.snapshot().unwrap();
    assert_eq!(host.snapshot().unwrap(), pending);
    assert_eq!(host.snapshot().unwrap(), pending);
    assert!(host.take_replies().is_empty());
    let deadline = host.sync_deadline().expect("owner timer must be armed");
    assert!(
        !host
            .expire_sync(deadline - std::time::Duration::from_nanos(1))
            .unwrap()
    );
    assert_eq!(host.snapshot().unwrap(), pending);
    assert!(host.expire_sync(deadline).unwrap());
    let event = host.next_delta(&pending).unwrap();
    assert_eq!(event.state.output_offset, pending.output_offset);
    assert_eq!(event.state.sequence.0, pending.sequence.0 + 1);
    let text: String = event.state.normal.lines[0]
        .cells
        .iter()
        .map(|c| c.text.as_str())
        .collect();
    assert!(text.starts_with("beforeafter"));
    assert_eq!(host.take_replies().len(), 1);
    assert!(host.sync_deadline().is_none());
    assert!(!host.expire_sync(deadline).unwrap());
    assert!(host.take_replies().is_empty());
    host.feed(b"!").unwrap();
    host.next_delta(&event.state).unwrap();
}

#[test]
fn resize_enforces_expanded_snapshot_budget_before_reporting_success() {
    let mut host = TerminalState::new(2, 2, 0).unwrap();
    host.feed(b"\x1b]8;id=fixture;https://example.invalid\x1b\\x")
        .unwrap();
    host.snapshot().unwrap();
    assert_eq!(
        host.resize(128, 128),
        Err(lomi_terminal_state::Error::SnapshotTooLarge)
    );
    assert_eq!(
        host.feed(b"more"),
        Err(lomi_terminal_state::Error::SnapshotTooLarge)
    );
    assert_eq!(
        host.resize(2, 2),
        Err(lomi_terminal_state::Error::SnapshotTooLarge)
    );
}
fn comparable(mut s: Snapshot) -> Snapshot {
    s.session_epoch = Uuid::nil();
    s.sequence = DecimalU64(0);
    s
}
#[test]
#[cfg(unix)]
fn captured_real_git_diff_survives_every_attach_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before");
    let after = dir.path().join("after");
    fs::write(&before, "first\nold 界\n").unwrap();
    fs::write(&after, "first\nnew 界🙂\n").unwrap();
    let output = git_capture::diff(dir.path()).expect("isolated Git CLI capture");
    assert!(output.windows(4).any(|s| s == b"diff"));
    let mut uninterrupted = TerminalState::new(12, 80, 32).unwrap();
    uninterrupted.feed(&output).unwrap();
    let expected = comparable(uninterrupted.snapshot().unwrap());
    for cut in 0..=output.len() {
        let mut host = TerminalState::new(12, 80, 32).unwrap();
        host.feed(&output[..cut]).unwrap();
        host.snapshot().unwrap();
        host.feed(&output[cut..]).unwrap();
        assert_eq!(
            comparable(host.snapshot().unwrap()),
            expected,
            "git diff cut {cut}"
        );
    }
}
#[test]
fn wire_deserialization_rejects_invalid_profiles_geometry_and_cells() {
    let state = TerminalState::new(6, 24, 8).unwrap();
    let good = serde_json::to_value(state.snapshot().unwrap()).unwrap();
    for (pointer, value) in [
        ("/version", serde_json::json!(2)),
        ("/profile", serde_json::json!("unknown")),
        ("/sequence", serde_json::json!("01")),
        ("/active", serde_json::json!("bogus")),
        ("/normal/cursor/x", serde_json::json!(25)),
        ("/normal/lines/0/cells/0/width", serde_json::json!(3)),
        (
            "/normal/lines/0/cells/0/flags",
            serde_json::json!(["unsupported"]),
        ),
        (
            "/normal/lines/0/cells/0/fg",
            serde_json::json!({"kind":"indexed","index":269}),
        ),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            serde_json::from_value::<Snapshot>(bad).is_err(),
            "{pointer}"
        );
    }
    let mut bad = good.clone();
    bad["normal"]["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Snapshot>(bad).is_err());
    assert!(serde_json::from_value::<Snapshot>(good).is_ok());
}
#[test]
fn wide_wrap_and_delayed_wrap_are_valid_projections() {
    let mut t = TerminalState::new(2, 4, 4).unwrap();
    t.feed("abc界".as_bytes()).unwrap();
    let s = t.snapshot().unwrap();
    s.validate().unwrap();
    assert_eq!(s.normal.lines[0].cells[3].width, 1);
    assert!(s.normal.lines[1].wrapped);
    t.feed(b"xy").unwrap();
    assert_eq!(t.snapshot().unwrap().normal.cursor.x, 4);
}
#[test]
fn bounded_attributes_and_hidden_state_do_not_retain_unlimited_text() {
    let mut t = TerminalState::new(6, 24, 8).unwrap();
    t.feed(b"x").unwrap();
    let combining = "\u{301}".repeat(1000);
    t.feed(combining.as_bytes()).unwrap();
    assert_eq!(
        t.snapshot().unwrap().normal.lines[0].cells[0]
            .text
            .chars()
            .count(),
        65
    );
    t.feed(b"\x1b]2;accepted\x07").unwrap();
    let title = format!("\x1b]2;{}\x07", "t".repeat(4097));
    t.feed(title.as_bytes()).unwrap();
    assert_eq!(t.snapshot().unwrap().title.as_deref(), Some("accepted"));
    let uri = format!(
        "\x1b]8;id=oversize;https://example.invalid/{}\x1b\\y",
        "x".repeat(2048)
    );
    t.feed(uri.as_bytes()).unwrap();
    assert!(
        t.snapshot().unwrap().normal.lines[0].cells[1]
            .hyperlink
            .is_none()
    );
    let id = format!(
        "\x1b]8;id={};https://example.invalid\x1b\\z",
        "i".repeat(257)
    );
    t.feed(id.as_bytes()).unwrap();
    assert!(
        t.snapshot().unwrap().normal.lines[0].cells[2]
            .hyperlink
            .is_none()
    );
    t.feed(b"\x1b[?u\x1b[>1u").unwrap();
    assert!(t.take_replies().is_empty());
    assert_eq!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off);
}
#[test]
fn same_osc_color_queries_resolve_at_effect_time() {
    let mut t = TerminalState::new(6, 24, 8).unwrap();
    t.feed(b"\x1b]4;1;rgb:12/34/56;1;?;1;rgb:ab/cd/ef;1;?\x07")
        .unwrap();
    let r = t.take_replies();
    assert_eq!(r.len(), 2);
    assert!(r[0].contains("1212/3434/5656"), "{r:?}");
    assert!(r[1].contains("abab/cdcd/efef"), "{r:?}");
}
#[test]
fn expanded_hyperlinks_fault_before_snapshot_allocation() {
    let mut t = TerminalState::new(2, 512, 0).unwrap();
    let link = format!(
        "\x1b]8;id=bounded;https://example.invalid/{}\x1b\\",
        "u".repeat(1900)
    );
    t.feed(link.as_bytes()).unwrap();
    assert_eq!(
        t.feed(&vec![b'x'; 1000]),
        Err(lomi_terminal_state::Error::SnapshotTooLarge)
    );
    assert_eq!(
        t.feed(b"more"),
        Err(lomi_terminal_state::Error::SnapshotTooLarge)
    );
    assert_eq!(
        t.resize(2, 2),
        Err(lomi_terminal_state::Error::SnapshotTooLarge)
    );
    assert_eq!(
        t.snapshot(),
        Err(lomi_terminal_state::Error::SnapshotTooLarge)
    );
}
#[test]
fn nullable_wire_fields_are_required() {
    let snapshot = TerminalState::new(6, 24, 8).unwrap().snapshot().unwrap();
    let mut v = serde_json::to_value(snapshot).unwrap();
    v.as_object_mut().unwrap().remove("title");
    assert!(serde_json::from_value::<Snapshot>(v).is_err());
}

#[test]
fn host_projects_unsupported_hyperlinks_without_losing_visible_cells() {
    for uri in [
        "file:///tmp/example",
        "javascript:alert(1)",
        "http://[broken",
        "https://exa\u{85}mple.invalid",
    ] {
        let mut host = TerminalState::new(6, 24, 8).unwrap();
        host.feed(
            format!("\x1b]8;id=fixture;{uri}\x1b\\\x1b[31;1mvisible\x1b]8;;\x1b\\").as_bytes(),
        )
        .unwrap();
        let snapshot = host.snapshot().unwrap();
        snapshot.validate().unwrap();
        let cell = &snapshot.normal.lines[0].cells[0];
        assert_eq!(cell.text, "v");
        assert!(cell.hyperlink.is_none(), "{uri}");
        assert!(cell.flags.contains(&"bold".to_owned()));
        assert_eq!(cell.fg, lomi_terminal_state::Color::Indexed { index: 1 });
    }
    for uri in [
        "https://example.invalid/界",
        "HTTP://example.invalid",
        "mailto:person@example.invalid",
    ] {
        let mut host = TerminalState::new(6, 24, 8).unwrap();
        host.feed(format!("\x1b]8;id=fixture;{uri}\x1b\\v").as_bytes())
            .unwrap();
        assert_eq!(
            host.snapshot().unwrap().normal.lines[0].cells[0]
                .hyperlink
                .as_ref()
                .unwrap()
                .uri,
            uri
        );
    }
}
#[test]
fn host_projects_c1_titles_and_astral_combining_at_js_utf16_boundary() {
    let mut host = TerminalState::new(6, 24, 8).unwrap();
    host.feed("\x1b]2;before\u{85}after\x07🙂".as_bytes())
        .unwrap();
    // U+1D185 MUSICAL SYMBOL COMBINING STEM is an astral combining mark.
    host.feed("\u{1d185}".repeat(64).as_bytes()).unwrap();
    let snapshot = host.snapshot().unwrap();
    assert_eq!(snapshot.title.as_deref(), Some("beforeafter"));
    let cell = &snapshot.normal.lines[0].cells[0];
    assert_eq!(cell.width, 2);
    assert!(cell.text.starts_with('🙂'));
    assert_eq!(cell.text.encode_utf16().count(), 128);
    assert_eq!(cell.text.chars().count(), 64);
}
#[test]
fn strict_wire_text_uses_js_utf16_lengths_and_rejects_control_metadata() {
    let original = TerminalState::new(6, 24, 8).unwrap().snapshot().unwrap();
    for text in ["a\u{85}".to_owned(), "a\n".to_owned(), "🙂".repeat(65)] {
        let mut s = original.clone();
        s.normal.lines[0].cells[0].text = text;
        assert!(s.validate().is_err());
        assert!(serde_json::from_value::<Snapshot>(serde_json::to_value(s).unwrap()).is_err());
    }
    for title in ["bad\u{7f}".to_owned(), "🙂".repeat(2049)] {
        let mut s = original.clone();
        s.title = Some(title);
        assert!(s.validate().is_err());
    }
    for (id, uri) in [
        ("bad\u{85}".to_owned(), "https://example.invalid".to_owned()),
        ("i".repeat(1025), "https://example.invalid".to_owned()),
        (
            "i".to_owned(),
            "https://example.invalid/".to_owned() + &"🙂".repeat(2040),
        ),
        ("i".to_owned(), "file:///tmp/example".to_owned()),
        ("i".to_owned(), "http://[broken".to_owned()),
    ] {
        let mut s = original.clone();
        s.normal.lines[0].cells[0].hyperlink = Some(lomi_terminal_state::Hyperlink { id, uri });
        assert!(s.validate().is_err());
    }
    let mut s = original;
    s.normal.lines[0].cells[0].text = "🙂".repeat(64);
    s.title = Some("🙂".repeat(2048));
    s.validate().unwrap();
}
#[test]
fn dynamic_colors_never_export_private_palette_slots() {
    let mut host = TerminalState::new(6, 24, 8).unwrap();
    host.feed(b"\x1b]10;#112233;#445566;#778899;#abcdef\x07\x1b]4;259;#123456\x07text")
        .unwrap();
    let snapshot = host.snapshot().unwrap();
    assert_eq!(
        snapshot.colors[256],
        Some(lomi_terminal_state::RgbColor {
            r: 17,
            g: 34,
            b: 51
        })
    );
    assert!(snapshot.colors[259..].iter().all(Option::is_none));
    snapshot.validate().unwrap();
}
