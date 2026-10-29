//! S0.1 investigation only: this is not a production terminal profile.
use alacritty_terminal::{
    Term,
    event::{Event, EventListener},
    term::Config,
    vte::ansi::Processor,
};
use serde::Serialize;
use serde_json::{Value, json};

const ROWS: u16 = 6;
const COLS: u16 = 24;
const SCROLLBACK: usize = 8;

#[derive(Clone, Serialize)]
struct Fixture {
    id: &'static str,
    prefix: Vec<u8>,
    live: Vec<u8>,
    resize_before: Option<(u16, u16)>,
    resize_live: Option<(u16, u16)>,
}
fn case(id: &'static str, prefix: &[u8], live: &[u8]) -> Fixture {
    Fixture {
        id,
        prefix: prefix.into(),
        live: live.into(),
        resize_before: None,
        resize_live: None,
    }
}
fn fixtures() -> Vec<Fixture> {
    let mut resize = case(
        "resize_reflow",
        b"abcdefghijklmnopqrstuvwxyz0123456789",
        b"!\r\nend",
    );
    resize.resize_before = Some((6, 16));
    resize.resize_live = Some((8, 20));
    let mut eviction = case("bounded_replay_evicted", b"", b"\r\nlast");
    for _ in 0..2000 {
        eviction.prefix.extend_from_slice(b"synthetic line\r\n");
    }
    vec![
        case("normal_ascii", b"hello\r\nworld", b"!"),
        case(
            "alternate_to_normal",
            b"NORMAL\x1b[?1049hALT",
            b"\x1b[?1049l!",
        ),
        case(
            "inactive_alternate",
            b"NORMAL\x1b[?47hALT\x1b[?47l",
            b"\x1b[?47h!",
        ),
        case("pending_csi", b"hello\x1b[2;", b"3HX"),
        case("pending_utf8", &[b'A', 0xe7, 0x95], &[0x8c, b'!']),
        case(
            "unicode_cells",
            "A界e\u{301}🙂".as_bytes(),
            "Z界".as_bytes(),
        ),
        case(
            "colors_modes",
            b"\x1b[31;44;1mRED\x1b[?1h\x1b[?2004h\x1b[?1000h\x1b[?1006h",
            b"X",
        ),
        case("scroll_region_origin", b"\x1b[2;5r\x1b[?6hA", b"\x1b[H!"),
        case("saved_cursor", b"ABC\x1b7\x1b[4;8H", b"\x1b8!"),
        case(
            "osc_title_hyperlink",
            b"\x1b]2;synthetic title\x07\x1b]8;;https://example.invalid\x1b\\link",
            b"!\x1b]8;;\x1b\\",
        ),
        case("pending_osc", b"\x1b]2;synthetic", b" title\x07!"),
        resize,
        eviction,
    ]
}
fn source(f: &Fixture) -> vt100::Parser {
    let mut p = vt100::Parser::new(ROWS, COLS, SCROLLBACK);
    p.process(&f.prefix);
    if let Some((r, c)) = f.resize_before {
        p.screen_mut().set_size(r, c);
    }
    p
}
fn snapshot(p: &vt100::Parser) -> Vec<u8> {
    // Deliberately test the stock formatter. No replay, hidden suffix or claimed
    // serializer for state the public API does not expose.
    let mut bytes = b"\x1bc".to_vec();
    bytes.extend(p.screen().state_formatted());
    bytes
}
fn continue_live(p: &mut vt100::Parser, f: &Fixture) {
    if let Some((r, c)) = f.resize_live {
        p.screen_mut().set_size(r, c);
    }
    p.process(&f.live);
}
fn rust_case(f: &Fixture) -> Value {
    let mut uninterrupted = source(f);
    let (r, c) = uninterrupted.screen().size();
    let mut restored = vt100::Parser::new(r, c, SCROLLBACK);
    restored.process(&snapshot(&uninterrupted));
    continue_live(&mut uninterrupted, f);
    continue_live(&mut restored, f);
    let passed = uninterrupted.screen().state_formatted() == restored.screen().state_formatted();
    json!({"id":f.id,"passed":passed,"status":if passed {"passed"} else {"failed"},
        "comparison":"vt100 active screen formatter after live continuation; not full-state proof"})
}
#[derive(Clone, Default)]
struct ReplyProbe(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl EventListener for ReplyProbe {
    fn send_event(&self, event: Event) {
        if matches!(event, Event::PtyWrite(_)) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
struct ProbeSize;
impl alacritty_terminal::grid::Dimensions for ProbeSize {
    fn total_lines(&self) -> usize {
        usize::from(ROWS)
    }
    fn screen_lines(&self) -> usize {
        usize::from(ROWS)
    }
    fn columns(&self) -> usize {
        usize::from(COLS)
    }
}
fn alacritty_probe() -> Value {
    let listener = ReplyProbe::default();
    let mut term = Term::new(Config::default(), &ProbeSize, listener.clone());
    let mut parser: Processor = Processor::new();
    parser.advance(&mut term, b"NORMAL\x1b[?1049hALT");
    let alternate = term
        .mode()
        .contains(alacritty_terminal::term::TermMode::ALT_SCREEN);
    parser.advance(&mut term, b"\x1b[?1049l");
    let normal_restored = term.grid()[alacritty_terminal::index::Point::new(
        alacritty_terminal::index::Line(0),
        alacritty_terminal::index::Column(0),
    )]
    .c == 'N';
    parser.advance(&mut term, b"\x1b[6n\x1b[c");
    let query_replies = listener.0.load(std::sync::atomic::Ordering::Relaxed);
    json!({"candidate":"alacritty_terminal=0.26.0", "qualified":false,
        "probe":{"alternate_entered":alternate,"normal_buffer_preserved":normal_restored,"dsr_da_host_replies":query_replies},
        "restore_adapter":"not implemented", "decision":"unqualified: no xterm serializer or parser-state restore adapter built by this probe"})
}
fn report() -> Value {
    json!({"stage":"S0.1","candidate":"vt100=0.16.2", "profile":"stock-state-formatted-experimental", "qualified":false,
        "scope":"synthetic native differential observations only", "cases":fixtures().iter().map(rust_case).collect::<Vec<_>>(),
        "alacritty":alacritty_probe(),
        "blocking_requirements":["inactive buffer and pending parser state not exported", "full xterm compatibility unproven", "real CLI, multi-hour soak and DSR/DA ownership not qualified"]})
}
fn main() {
    let command = std::env::args().nth(1).unwrap_or_else(|| "report".into());
    match command.as_str() {
        "fixtures" => {
            let cases: Vec<_> = fixtures()
                .iter()
                .map(|f| {
                    let p = source(f);
                    json!({"fixture":f,"restore":snapshot(&p),"size":p.screen().size()})
                })
                .collect();
            println!(
                "{}",
                json!({"candidate":"vt100=0.16.2","profile":"stock-state-formatted-experimental","rows":ROWS,"cols":COLS,"scrollback":SCROLLBACK,"cases":cases})
            );
        }
        "report" | "qualify" => {
            println!("{}", serde_json::to_string_pretty(&report()).unwrap());
            if command == "qualify" {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: lomi-terminal-spike [report|fixtures|qualify]");
            std::process::exit(2);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stock_formatter_counterexamples_are_reproducible() {
        for id in ["alternate_to_normal", "pending_csi", "pending_utf8"] {
            let f = fixtures().into_iter().find(|f| f.id == id).unwrap();
            assert_eq!(rust_case(&f)["passed"], false, "{id}");
        }
    }
    #[test]
    fn ascii_control_and_evicted_replay_are_exercised() {
        let cases = fixtures();
        assert_eq!(rust_case(&cases[0])["passed"], true);
        assert!(
            cases
                .iter()
                .find(|f| f.id == "bounded_replay_evicted")
                .unwrap()
                .prefix
                .len()
                > SCROLLBACK * usize::from(COLS)
        );
        assert_eq!(report()["qualified"], false);
    }
    #[test]
    fn all_native_observations_match_the_recorded_baseline() {
        let passes = [
            "normal_ascii",
            "unicode_cells",
            "colors_modes",
            "osc_title_hyperlink",
            "resize_reflow",
            "bounded_replay_evicted",
        ];
        let cases = fixtures();
        assert_eq!(cases.len(), 13);
        for f in cases {
            assert_eq!(rust_case(&f)["passed"], passes.contains(&f.id), "{}", f.id);
        }
    }
    #[test]
    fn alacritty_model_keeps_both_screens_without_claiming_export() {
        let p = alacritty_probe();
        assert_eq!(p["probe"]["alternate_entered"], true);
        assert_eq!(p["probe"]["normal_buffer_preserved"], true);
        assert_eq!(p["probe"]["dsr_da_host_replies"], 2);
        assert_eq!(p["qualified"], false);
    }
}
