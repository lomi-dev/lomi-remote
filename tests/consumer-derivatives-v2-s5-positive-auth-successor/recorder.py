"""Pinned pure recorder; in-memory only, with no runtime admission."""
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
from pathlib import Path
import sys

PARSER_SHA256 = "4c4248088591e64f95008758682967b6e1e39c645609a769497f06b613d53328"
PARSER_PATH = Path(__file__).resolve().parent / "closed_dependencies" / "diagnostics.py"
GENERIC_STAGE = "generic-failure"
ALLOWED_STAGES = frozenset(("initial-identity", "setup-runtime", "principal-runtime", "scalar-group", "roots-group", "typed-group", "rollback"))
ALLOWED_MARKERS = (
    "positive-auth:setup-runtime:PASS", "positive-auth:principal-runtime:PASS",
    "positive-auth:scalar-invoker:PASS", "positive-auth:scalar-wronghash:PASS",
    "positive-auth:scalar-repeat:PASS", "positive-auth:assertion-root:PASS",
    "positive-auth:assertion-wronghash:PASS", "positive-auth:assertion-repeat:PASS",
    "positive-auth:recipient-root:PASS", "positive-auth:typed-inventory:PASS",
    "positive-auth:typed-wronghash:PASS", "positive-auth:typed-repeat:PASS",
    "positive-auth:rollback:PASS",
)

def _load_parser():
    source = PARSER_PATH.read_bytes()
    if hashlib.sha256(source).hexdigest() != PARSER_SHA256:
        raise RuntimeError("protocol mismatch")
    spec = importlib.util.spec_from_file_location("_s5_successor_diagnostics", PARSER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if tuple("positive-auth:" + m + ":PASS" for m in module.MARKERS) != ALLOWED_MARKERS:
        raise RuntimeError("protocol mismatch")
    return module

_diagnostics = _load_parser()

@dataclass(frozen=True, slots=True)
class Evidence:
    status: str
    markers: tuple[str, ...]
    stage: str
    sqlstate: str | None
    failure: str | None
    exit_code: int | None
    deadline: bool
    cleanup_completed: bool
    def evidence(self): return asdict(self)
    def __repr__(self): return "<S5SuccessorEvidence private>"

def generic():
    return Evidence("generic-failure", (), GENERIC_STAGE, None, None, None, False, False)

def record(stdout, stderr, exit_code, *, deadline=False, cancelled=False, cleanup_completed=False):
    if (type(stdout) is not bytes or type(stderr) is not bytes or type(exit_code) is not int
            or type(deadline) is not bool or type(cancelled) is not bool
            or type(cleanup_completed) is not bool): return generic()
    try:
        parser = _diagnostics.DiagnosticParser()
        parser.feed_stdout(stdout); parser.feed_stderr(stderr)
        result = parser.finish(exit_code, deadline=deadline, cancelled=cancelled)
        if result.stage == "complete" and result.marker_ids == _diagnostics.MARKERS and result.exit == 0:
            return Evidence("complete", ALLOWED_MARKERS, "complete", None, None, 0, False, cleanup_completed)
        if (result.stage in ALLOWED_STAGES and result.state is not None and result.exit == 1
                and not result.deadline):
            prior = tuple("positive-auth:" + m + ":PASS" for m in result.marker_ids)
            if prior == ALLOWED_MARKERS[:len(prior)]:
                return Evidence("fixed-error", prior, result.stage, result.state,
                                "positive-auth:" + result.stage + ":" + result.state,
                                1, False, cleanup_completed)
    except BaseException:
        pass
    return generic()
