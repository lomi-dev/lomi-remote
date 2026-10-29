use lomi_terminal_state::{Delta, GridPatch, MAX_SNAPSHOT_BYTES, Snapshot, TerminalState};
use serde_json::{Value, json};

#[test]
fn patches_reconstruct_every_existing_fixture_projection() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_state-fixtures"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let fixtures: Value = serde_json::from_slice(&output.stdout).unwrap();
    let cases = fixtures["cases"].as_array().unwrap();
    assert!(cases.len() >= 26);
    let mut projections = 0;
    for case in cases {
        let mut previous: Snapshot = serde_json::from_value(case["snapshot"].clone()).unwrap();
        for delta in case["deltas"].as_array().unwrap() {
            let delta: Delta = serde_json::from_value(delta.clone()).unwrap();
            let patch = GridPatch::between(&previous, &delta.state).unwrap();
            let encoded = serde_json::to_vec(&patch).unwrap();
            let patch = GridPatch::from_json(&encoded).unwrap();
            previous = patch.apply(&previous).unwrap();
            assert_eq!(previous, delta.state, "fixture {}", case["id"]);
            projections += 1;
        }
        let expected: Snapshot = serde_json::from_value(case["final"].clone()).unwrap();
        assert_eq!(previous, expected);
    }
    assert!(projections > 50);
}

fn example() -> (Snapshot, Snapshot, GridPatch) {
    let mut model = TerminalState::new(24, 80, 8).unwrap();
    let previous = model.snapshot().unwrap();
    model.feed(b"prompt> hello").unwrap();
    let next = model.snapshot().unwrap();
    let patch = GridPatch::between(&previous, &next).unwrap();
    (previous, next, patch)
}
#[test]
fn ordinary_prompt_echo_is_compact_and_has_no_checkpoint() {
    let (previous, next, patch) = example();
    let bytes = serde_json::to_vec(&patch).unwrap();
    assert!(bytes.len() < 8192, "{} bytes", bytes.len());
    assert!(!String::from_utf8(bytes).unwrap().contains("\"state\""));
    assert_eq!(patch.apply(&previous).unwrap(), next);
    assert!(patch.apply(&next).is_err());
}

#[test]
fn malformed_stale_duplicate_and_noncanonical_updates_are_rejected() {
    let (previous, _, patch) = example();
    let value = serde_json::to_value(&patch).unwrap();
    let reject =
        |v: Value| assert!(GridPatch::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    for (field, replacement) in [
        ("format", json!("legacy")),
        ("profile", json!("other")),
        ("sequence", json!("01")),
        ("sequence", json!("3")),
        (
            "sessionEpoch",
            json!("00000000-0000-0000-0000-000000000000"),
        ),
        ("rows", json!(usize::MAX)),
    ] {
        let mut v = value.clone();
        v[field] = replacement;
        reject(v);
    }
    for epoch in [
        "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB",
        "abcdefabcdefabcdefabcdefabcdefab",
    ] {
        let mut v = value.clone();
        v["sessionEpoch"] = json!(epoch);
        reject(v);
    }
    let mut v = value.clone();
    v["unknown"] = json!(true);
    reject(v);
    let mut v = value.clone();
    v["update"]["normal"]["rows"][0]["index"] = json!(999);
    reject(v);
    let mut v = value.clone();
    v["update"]["normal"]["rows"][0]["cells"][0]["index"] = json!(80);
    reject(v);
    let mut v = value.clone();
    let duplicate = v["update"]["normal"]["rows"][0].clone();
    v["update"]["normal"]["rows"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    reject(v);
    let mut v = value.clone();
    let duplicate = v["update"]["normal"]["rows"][0]["cells"][0].clone();
    v["update"]["normal"]["rows"][0]["cells"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    reject(v);
    for repeat in [0, 81, usize::MAX] {
        let mut v = value.clone();
        v["update"]["normal"]["rows"][0]["cells"][0]["repeat"] = json!(repeat);
        reject(v);
    }
    let mut v = value.clone();
    v["update"]["normal"]["retainedStart"] = json!(usize::MAX);
    reject(v);
    let mut v = value.clone();
    v["update"]["normal"]["retainedLines"] = json!(23);
    reject(v); // A new row must be present and cover every column.
    let mut v = value.clone();
    v["update"]["normal"]["rows"][0]["cells"][0]["cell"]["text"] = json!("\u{1b}");
    reject(v);
    let mut v = value.clone();
    v["update"]["normal"]["rows"][0]["cells"][0]["cell"]["width"] = json!(2);
    let patch = GridPatch::from_json(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(patch.apply(&previous).is_err()); // orphaned wide cell in final grid
    let mut stale = previous.clone();
    stale.output_offset.0 = 1000;
    assert!(patch.apply(&stale).is_err());
    let mut stale = previous.clone();
    stale.session_epoch = uuid::Uuid::new_v4();
    assert!(patch.apply(&stale).is_err());
    let mut v = value;
    v["update"]["normal"]["previousBaseY"] = json!(1);
    v["update"]["normal"]["previousLineCount"] = json!(25);
    let patch = GridPatch::from_json(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(patch.apply(&previous).is_err());
    assert!(GridPatch::from_json(&vec![b' '; MAX_SNAPSHOT_BYTES + 1]).is_err());
}

#[test]
fn resize_and_history_checkpoints_preserve_both_buffers() {
    let mut model = TerminalState::new(6, 24, 8).unwrap();
    let mut previous = model.snapshot().unwrap();
    for bytes in [
        b"normal\x1b[?1049hALT\x1b[?1049l".as_slice(),
        "界🙂e\u{301}\x1b[31m\x1b]2;title\x07".as_bytes(),
        b"\r\n1\r\n2\r\n3\r\n4\r\n5\r\n6\r\n7".as_slice(),
    ] {
        model.feed(bytes).unwrap();
        let next = model.snapshot().unwrap();
        previous = GridPatch::between(&previous, &next)
            .unwrap()
            .apply(&previous)
            .unwrap();
        assert_eq!(previous, next);
    }
    model.resize(8, 20).unwrap();
    let next = model.snapshot().unwrap();
    let patch = GridPatch::between(&previous, &next).unwrap();
    assert_eq!(
        serde_json::to_value(&patch).unwrap()["update"]["kind"],
        "checkpoint"
    );
    assert_eq!(patch.apply(&previous).unwrap(), next);
}

#[test]
fn growing_and_evicted_history_stays_compact_and_exact() {
    let mut model = TerminalState::new(24, 80, 256).unwrap();
    let mut previous = model.snapshot().unwrap();
    let mut queued_bytes = 0;
    let mut max_bytes = 0;
    for i in 0..320 {
        model
            .feed(format!("line {i:03}: ordinary prompt output\r\n").as_bytes())
            .unwrap();
        let next = model.snapshot().unwrap();
        let patch = GridPatch::between(&previous, &next).unwrap();
        let bytes = serde_json::to_vec(&patch).unwrap();
        max_bytes = max_bytes.max(bytes.len());
        assert!(bytes.len() < 16 * 1024, "line {i}: {} bytes", bytes.len());
        assert_eq!(
            serde_json::to_value(&patch).unwrap()["update"]["kind"],
            "sparse"
        );
        if i < 100 {
            queued_bytes += bytes.len();
        }
        previous = GridPatch::from_json(&bytes)
            .unwrap()
            .apply(&previous)
            .unwrap();
        assert_eq!(previous, next, "line {i}");
    }
    assert_eq!(previous.normal.base_y, 256);
    assert!(
        queued_bytes < 1024 * 1024,
        "100 lines cost {queued_bytes} bytes"
    );
    eprintln!(
        "80x24 history256: 100 queued patches {queued_bytes} bytes; 320-line maximum {max_bytes} bytes"
    );
}

#[test]
fn compact_repeat_runs_cannot_allocate_an_oversized_expanded_snapshot() {
    let mut model = TerminalState::new(16, 512, 0).unwrap();
    let previous = model.snapshot().unwrap();
    model.feed(b"").unwrap();
    let patch = GridPatch::between(&previous, &model.snapshot().unwrap()).unwrap();
    let mut wire = serde_json::to_value(patch).unwrap();
    let mut cell = serde_json::to_value(&previous.normal.lines[0].cells[0]).unwrap();
    cell["text"] = json!("x".repeat(128));
    cell["hyperlink"] = json!({"id":"i".repeat(1024),"uri":format!("https://example.invalid/{}", "a".repeat(4000))});
    let rows:Vec<_> = (0..16).map(|index| json!({"index":index,"wrapped":false,"cells":[{"index":0,"repeat":512,"cell":cell}]})).collect();
    wire["update"]["normal"]["rows"] = json!(rows);
    wire["update"]["alternate"]["rows"] = json!(rows);
    let bytes = serde_json::to_vec(&wire).unwrap();
    assert!(bytes.len() < 256 * 1024);
    let patch = GridPatch::from_json(&bytes).unwrap();
    // The borrowed prospective-state serializer rejects the >80 MiB expansion
    // before either the old snapshot or replacement runs are cloned.
    assert_eq!(
        patch.apply(&previous),
        Err(lomi_terminal_state::Error::SnapshotTooLarge)
    );
}
