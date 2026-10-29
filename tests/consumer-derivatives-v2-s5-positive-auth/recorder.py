"""Pure bounded recorder for the S5 positive-auth output protocol.

This module accepts already captured bytes in memory. It never starts a child,
persists raw output, or decides whether S5 is admitted or accepted.
"""

from dataclasses import asdict, dataclass
import hashlib
import importlib.util
from pathlib import Path
import sys

PARSER_SHA256 = "4c4248088591e64f95008758682967b6e1e39c645609a769497f06b613d53328"
PARSER_PATH = (Path(__file__).resolve().parents[1] / "consumer-private-streams"
               / "closed_dependencies" / "diagnostics.py")
GENERIC_STAGE = "generic-failure"
ALLOWED_STAGES = frozenset(("initial-identity", "setup-runtime",
                            "principal-runtime", "scalar-group", "roots-group",
                            "typed-group", "rollback"))
ALLOWED_MARKERS = (
    "positive-auth:setup-runtime:PASS",
    "positive-auth:principal-runtime:PASS",
    "positive-auth:scalar-invoker:PASS",
    "positive-auth:scalar-wronghash:PASS",
    "positive-auth:scalar-repeat:PASS",
    "positive-auth:assertion-root:PASS",
    "positive-auth:assertion-wronghash:PASS",
    "positive-auth:assertion-repeat:PASS",
    "positive-auth:recipient-root:PASS",
    "positive-auth:typed-inventory:PASS",
    "positive-auth:typed-wronghash:PASS",
    "positive-auth:typed-repeat:PASS",
    "positive-auth:rollback:PASS",
)


def _load_parser():
    """Load the closed parser only when its exact source is present."""
    source = PARSER_PATH.read_bytes()
    if hashlib.sha256(source).hexdigest() != PARSER_SHA256:
        raise RuntimeError("positive-auth recorder dependency mismatch")
    name = "_positive_auth_closed_diagnostics"
    spec = importlib.util.spec_from_file_location(name, PARSER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("positive-auth recorder dependency unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    if (tuple("positive-auth:" + value + ":PASS" for value in module.MARKERS)
            != ALLOWED_MARKERS
            or frozenset(stage for stage, _ in module.ERROR_STAGES) != ALLOWED_STAGES):
        raise RuntimeError("positive-auth recorder protocol mismatch")
    return module


_diagnostics = _load_parser()


@dataclass(frozen=True, slots=True)
class Evidence:
    """Only fixed protocol facts; never includes a diagnostic payload."""

    status: str
    markers: tuple[str, ...]
    stage: str
    sqlstate: str | None
    failure: str | None
    exit_code: int | None
    deadline: bool
    cleanup_completed: bool

    def evidence(self):
        return asdict(self)

    def __repr__(self):
        return "<PositiveAuthEvidence private>"


def _generic(exit_code, deadline, cleanup_completed):
    normalized_exit = (0 if exit_code == 0 else 1) if type(exit_code) is int else None
    return Evidence("generic-failure", (), GENERIC_STAGE, None, None,
                    normalized_exit, deadline is True, cleanup_completed is True)


def record(stdout, stderr, exit_code, *, deadline=False, cleanup_completed=False):
    """Convert bounded in-memory output into a closed evidence record.

    Unknown, malformed, oversized, or contradictory output becomes the same
    generic record. The inputs and parser state are not returned or persisted.
    ``cleanup_completed`` is a reported fact, not a cleanup or admission check.
    """
    if (type(deadline) is not bool or type(cleanup_completed) is not bool
            or type(exit_code) is not int):
        return _generic(exit_code, False, False)

    parser = None
    try:
        parser = _diagnostics.DiagnosticParser()
        parser.feed_stdout(stdout)
        parser.feed_stderr(stderr)
        result = parser.finish(exit_code, deadline=deadline, cancelled=False)
        if result.stage == "complete" and result.state is None:
            if (result.marker_ids != _diagnostics.MARKERS
                    or result.exit != 0 or result.deadline):
                return _generic(exit_code, deadline, cleanup_completed)
            return Evidence("complete", ALLOWED_MARKERS, "complete", None, None,
                            0, False, cleanup_completed)
        if (result.stage in ALLOWED_STAGES
                and type(result.state) is str
                and len(result.state) == 5
                and all(ch in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" for ch in result.state)
                and not result.state.startswith("00")
                and result.exit == 1
                and result.deadline is False):
            failure = "positive-auth:" + result.stage + ":" + result.state
            prior_markers = tuple("positive-auth:" + value + ":PASS"
                                  for value in result.marker_ids)
            if prior_markers != ALLOWED_MARKERS[:len(prior_markers)]:
                return _generic(exit_code, deadline, cleanup_completed)
            return Evidence("fixed-error", prior_markers, result.stage, result.state, failure,
                            1, False, cleanup_completed)
    except BaseException:
        # Never retain or stringify an exception: diagnostics may be sensitive.
        pass
    return _generic(exit_code, deadline, cleanup_completed)

