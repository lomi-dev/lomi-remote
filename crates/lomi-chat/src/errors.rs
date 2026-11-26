//! Classifies a failed turn's error text into a stable machine kind plus an
//! optional retry time. Providers and CLIs only report free text, so this is
//! a best-effort substring match over the messages seen in practice.
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Auth,
    RateLimit,
    Network,
    MissingCli,
    ContextLength,
    Other,
}

impl ErrorKind {
    /// The serde name, as stored in the `error_kind` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::RateLimit => "rate_limit",
            Self::Network => "network",
            Self::MissingCli => "missing_cli",
            Self::ContextLength => "context_length",
            Self::Other => "other",
        }
    }
}

/// A reset further away than this is treated as a misparse.
const MAX_RETRY_MS: u64 = 31 * 24 * 3600 * 1000;

fn has(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

/// Kind of `message` and, for rate limits, the epoch milliseconds at which the
/// limit resets when the text carries one (`now_ms` anchors relative times).
pub fn classify(message: &str, now_ms: u64) -> (ErrorKind, Option<u64>) {
    let t = message.to_lowercase();
    let kind = if has(
        &t,
        &[
            "check that it is installed",
            "not installed",
            "command not found",
            "no such file or directory",
            "enoent",
        ],
    ) {
        ErrorKind::MissingCli
    } else if has(
        &t,
        &[
            "context length",
            "context_length",
            "context window",
            "prompt is too long",
            "maximum context",
            "input is too long",
            "too many tokens",
        ],
    ) {
        ErrorKind::ContextLength
    } else if has(
        &t,
        &[
            "rate limit",
            "rate_limit",
            "usage limit",
            "usagelimit",
            "limit reached",
            "hit your limit",
            "http 429",
            "too many requests",
            "quota",
        ],
    ) {
        ErrorKind::RateLimit
    } else if has(
        &t,
        &[
            "not logged in",
            "not signed in",
            "/login",
            "authentication failed",
            "authentication_error",
            "invalid api key",
            "invalid x-api-key",
            "api key is missing",
            "re-enter the api key",
            "http 401",
            "unauthorized",
            "login required",
        ],
    ) {
        ErrorKind::Auth
    } else if has(
        &t,
        &[
            "cannot connect to",
            "did not respond",
            "connection closed",
            "connection reset",
            "connection refused",
            "timed out",
            "network",
            "dns error",
        ],
    ) {
        ErrorKind::Network
    } else {
        ErrorKind::Other
    };
    let retry = (kind == ErrorKind::RateLimit)
        .then(|| retry_at(message, now_ms))
        .flatten()
        .filter(|at| *at > now_ms && *at - now_ms <= MAX_RETRY_MS);
    (kind, retry)
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid pattern"))
}

/// Reset time from the shapes the CLIs print: Claude's `limit reached|<epoch s>`,
/// structured `resets_in_seconds` / `resets_at`, and `try again in 2 hours 14 minutes`.
/// A wall-clock "resets 3pm" has no date or zone, so it yields `None`.
fn retry_at(message: &str, now_ms: u64) -> Option<u64> {
    static EPOCH: OnceLock<Regex> = OnceLock::new();
    static IN_SECS: OnceLock<Regex> = OnceLock::new();
    static SPAN: OnceLock<Regex> = OnceLock::new();
    static UNIT: OnceLock<Regex> = OnceLock::new();
    let epoch = re(
        &EPOCH,
        r#"(?i)(?:limit reached\||resets?_?at"?\s*[:=]\s*)(\d{10})\b"#,
    );
    if let Some(c) = epoch.captures(message) {
        return Some(c[1].parse::<u64>().ok()? * 1000);
    }
    let in_secs = re(&IN_SECS, r#"(?i)resets?_?in_?seconds"?\s*[:=]\s*(\d{1,9})"#);
    if let Some(c) = in_secs.captures(message) {
        return Some(now_ms + c[1].parse::<u64>().ok()? * 1000);
    }
    let span = re(
        &SPAN,
        r"(?i)(?:again in|resets? in|retry in|retry after|available in)\s+((?:\d+\s*[a-z]+[\s,]*(?:and\s+)?)+)",
    );
    let unit = re(&UNIT, r"(\d+)\s*([a-z])[a-z]*");
    let chunk = span.captures(message)?.get(1)?.as_str().to_lowercase();
    let mut total = 0u64;
    for c in unit.captures_iter(&chunk) {
        let n: u64 = c[1].parse().ok()?;
        total += n * match &c[2] {
            "d" => 86_400,
            "h" => 3_600,
            "m" => 60,
            "s" => 1,
            _ => return None,
        };
    }
    (total > 0).then(|| now_ms + total * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn kinds_from_real_messages() {
        for (text, kind) in [
            ("Not logged in", ErrorKind::Auth),
            ("Invalid API key · Please run /login", ErrorKind::Auth),
            (
                "Authentication failed (HTTP 401). Check the API key.",
                ErrorKind::Auth,
            ),
            (
                "The API key is missing from the system key store. Re-enter the API key.",
                ErrorKind::Auth,
            ),
            ("Rate limited (HTTP 429). Slow down.", ErrorKind::RateLimit),
            (
                "Claude AI usage limit reached|1800003600",
                ErrorKind::RateLimit,
            ),
            (
                "You've hit your usage limit. Try again in 2 hours.",
                ErrorKind::RateLimit,
            ),
            ("Cannot connect to api.openai.com.", ErrorKind::Network),
            (
                "The provider did not respond for 120 seconds.",
                ErrorKind::Network,
            ),
            (
                "Cannot start the CLI. Check that it is installed.",
                ErrorKind::MissingCli,
            ),
            ("Prompt is too long", ErrorKind::ContextLength),
            (
                "This model's maximum context length is 128000 tokens.",
                ErrorKind::ContextLength,
            ),
            ("The CLI exited (exit status: 1)", ErrorKind::Other),
        ] {
            assert_eq!(classify(text, NOW).0, kind, "{text}");
        }
    }

    #[test]
    fn retry_times() {
        let at = |t: &str| classify(t, NOW).1;
        assert_eq!(
            at("Claude AI usage limit reached|1800003600"),
            Some(1_800_003_600_000)
        );
        assert_eq!(
            at(r#"usage limit {"resets_in_seconds": 90}"#),
            Some(NOW + 90_000)
        );
        assert_eq!(
            at("You've hit your usage limit. Try again in 2 hours 14 minutes."),
            Some(NOW + (2 * 3600 + 14 * 60) * 1000)
        );
        // Wall-clock resets carry no date, so no time is guessed.
        assert_eq!(
            at("You've hit your limit · resets 3pm (Europe/Warsaw)"),
            None
        );
        // A past or absurd time is dropped; non rate limits never get one.
        assert_eq!(at("usage limit reached|1700000000"), None);
        assert_eq!(at("Not logged in|1800003600"), None);
    }
}
