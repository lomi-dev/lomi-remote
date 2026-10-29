"""Pure closed diagnostic protocol. Never launch a process or retain raw output."""

from dataclasses import asdict, dataclass

FIXTURE_SHA256 = "1fe715e2245f05b372cb2dd8904d3dee08aeed893ae75f8f367a996df1c375c8"
MARKERS = (
    "setup-runtime", "principal-runtime", "scalar-invoker", "scalar-wronghash",
    "scalar-repeat", "assertion-root", "assertion-wronghash", "assertion-repeat",
    "recipient-root", "typed-inventory", "typed-wronghash", "typed-repeat", "rollback",
)
MARKER_LINES = (59, 78, 110, 110, 110, 147, 147, 147, 147, 187, 187, 187, 198)
ERROR_STAGES = (
    ("initial-identity", 11), ("setup-runtime", 59), ("principal-runtime", 78),
    ("scalar-group", 110), ("roots-group", 147), ("typed-group", 187), ("rollback", 198),
)
ERROR_COUNTS = ((0,), (0,), (1,), (2, 3, 4), (5, 6, 7, 8), (9, 10, 11), (12,))
CLIENT_FLAGS = (
    "-X", "--no-password", "-qAt", "-v", "ON_ERROR_STOP=1",
    "-v", "VERBOSITY=terse", "-v", "SHOW_CONTEXT=never", "-v", "ECHO=none",
    "-v", "ECHO_HIDDEN=off",
)
SERVER_SETTINGS = (
    ("log_destination", "stderr"), ("logging_collector", "off"),
    ("log_statement", "none"), ("log_min_error_statement", "panic"),
    ("log_min_messages", "panic"), ("log_error_verbosity", "terse"),
    ("log_min_duration_statement", "-1"), ("log_min_duration_sample", "-1"),
    ("log_transaction_sample_rate", "0"), ("log_parameter_max_length", "0"),
    ("log_parameter_max_length_on_error", "0"),
)
SERVER_FLAGS = tuple(part for key, value in SERVER_SETTINGS for part in ("-c", f"{key}={value}"))
PRIVATE_ENV_FIXED = (
    ("LC_ALL", "C"), ("PGCLIENTENCODING", "UTF8"),
    ("PSQL_HISTORY", "/dev/null"), ("PSQLRC", "/dev/null"),
)
PRIVATE_ENV_REQUIRED = ("HOME", "PGHOST", "PGPORT", "PGDATABASE", "PGUSER")
STDOUT_LIMIT = 1_024
STDERR_LIMIT = 8_192
COMBINED_LIMIT = 8_192
LINE_LIMIT = 256


def notice_line(index):
    """Construct trusted protocol bytes for tests, never from process output."""
    return (f"psql:positive-auth.sql:{MARKER_LINES[index]}: NOTICE:  "
            f"positive-auth:{MARKERS[index]}:PASS\n").encode("ascii")


@dataclass(frozen=True, slots=True)
class Result:
    stage: str
    state: str | None
    marker_ids: tuple[str, ...]
    count: int
    exit: int | None
    deadline: bool

    def evidence(self):
        return asdict(self)


class DiagnosticParser:
    """Bytewise allowlist matcher; no arbitrary input bytes are stored.

    All non-ASCII bytes fail immediately, so accepted input is strict UTF-8.
    ASCII SQLSTATE bytes are retained only after whole-envelope validation.
    repr exposes no parser state. Feed methods never echo invalid arguments.
    """

    __slots__ = ("_failed", "_finished", "_count", "_totals", "_position",
                 "_candidates", "_error", "_state_chars", "_line_length")

    def __init__(self):
        self._failed = self._finished = False
        self._count = 0
        self._totals = [0, 0]
        self._error = None
        self._reset_line()

    def __repr__(self):
        return "<DiagnosticParser private>"

    def _reset_line(self):
        self._position = self._line_length = 0
        self._state_chars = []
        self._candidates = []
        if self._count < len(MARKERS):
            self._candidates.append((notice_line(self._count), None))
        for (stage, line), counts in zip(ERROR_STAGES, ERROR_COUNTS):
            if self._count not in counts:
                continue
            template = (f"psql:positive-auth.sql:{line}: ERROR:  "
                        f"positive-auth:{stage}:").encode("ascii") + b"?????\n"
            self._candidates.append((template, stage))

    def _reject(self):
        self._failed = True
        self._error = None
        self._candidates.clear()
        self._state_chars.clear()
        self._position = self._line_length = 0

    def feed_stdout(self, chunk):
        self._feed(0, chunk)

    def feed_stderr(self, chunk):
        self._feed(1, chunk)

    def _feed(self, stream, chunk):
        if self._finished:
            self._reject()
            return
        if type(chunk) is not bytes:
            self._reject()
            return
        for byte in chunk:
            if self._failed:
                return
            self._totals[stream] += 1
            if (self._totals[stream] > (STDOUT_LIMIT, STDERR_LIMIT)[stream]
                    or sum(self._totals) > COMBINED_LIMIT or stream == 0
                    or self._error is not None or byte > 127):
                self._reject()
                return
            self._line_length += 1
            if self._line_length > LINE_LIMIT:
                self._reject()
                return
            matches = []
            wildcard = False
            for template, stage in self._candidates:
                if self._position >= len(template):
                    continue
                expected = template[self._position]
                is_state = stage is not None and expected == 63
                if (is_state and (48 <= byte <= 57 or 65 <= byte <= 90)
                        or not is_state and byte == expected):
                    matches.append((template, stage))
                    wildcard = wildcard or is_state
            if not matches:
                self._reject()
                return
            self._candidates = matches
            if wildcard:
                self._state_chars.append(chr(byte))
            self._position += 1
            if byte == 10:
                template, stage = matches[0]
                if self._position != len(template):
                    self._reject()
                    return
                if stage is None:
                    self._count += 1
                    self._reset_line()
                else:
                    state = "".join(self._state_chars)
                    if len(state) != 5 or state.startswith("00"):
                        self._reject()
                        return
                    self._error = (stage, state)
                    self._candidates.clear()
                    self._state_chars.clear()
                    self._position = self._line_length = 0

    def finish(self, exit_code, *, deadline=False, cancelled=False):
        """Call only after both pipes close and the child is reaped.

        exit is normalized to 0/1/None; arbitrary caller integers never persist.
        Cancellation and every malformed stream yield the same generic failure.
        """
        valid_exit = type(exit_code) is int
        normalized_exit = (0 if exit_code == 0 else 1) if valid_exit else None
        valid_flags = type(deadline) is bool and type(cancelled) is bool
        deadline = deadline is True
        if (self._finished or self._failed or self._position or not valid_exit
                or not valid_flags or deadline or cancelled is not False):
            self._reject()
        self._finished = True
        markers = MARKERS[:self._count]
        if self._failed:
            result = Result("generic-failure", None, (), 0, normalized_exit, deadline)
        elif self._error and exit_code != 0:
            result = Result(*self._error, markers, len(markers), normalized_exit, deadline)
        elif exit_code == 0 and self._error is None and self._count == len(MARKERS):
            result = Result("complete", None, markers, len(markers), 0, False)
        else:
            self._reject()
            result = Result("generic-failure", None, (), 0, normalized_exit, deadline)
        self._candidates.clear()
        self._state_chars.clear()
        return result
