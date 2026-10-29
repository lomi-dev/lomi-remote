use lomi_terminal_state::TerminalState;
#[test]
fn title_stack_keeps_exactly_the_newest_64_entries() {
    let mut host = TerminalState::new(6, 24, 8).unwrap();
    for i in 0..70 {
        host.feed(format!("\x1b]2;title-{i}\x07\x1b[22;0t").as_bytes())
            .unwrap();
    }
    host.feed(b"\x1b]2;current\x07").unwrap();
    for i in (6..70).rev() {
        host.feed(b"\x1b[23;0t").unwrap();
        assert_eq!(host.snapshot().unwrap().title, Some(format!("title-{i}")));
    }
    host.feed(b"\x1b]2;empty-stack-marker\x07\x1b[23;0t")
        .unwrap();
    assert_eq!(
        host.snapshot().unwrap().title.as_deref(),
        Some("empty-stack-marker")
    );
}
