"""Source-only bounded adapter for fakeable anonymous-pipe observations.

No process, SQL, database, or runtime entrypoint is opened here.
"""
from dataclasses import dataclass
import importlib.util
import math
from pathlib import Path
import sys

_recorder_path = Path(__file__).resolve().parent / "recorder.py"
_spec = importlib.util.spec_from_file_location("_s5_successor_recorder", _recorder_path)
_recorder = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _recorder
_spec.loader.exec_module(_recorder)
record, generic = _recorder.record, _recorder.generic

MAX_TOTAL = 8192
MAX_CHUNK = 1024
MAX_CHUNKS = 32

def _finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False

@dataclass(frozen=True, slots=True)
class PipeCapture:
    chunks: tuple
    eof: bool

@dataclass(frozen=True, slots=True)
class ChildFacts:
    exit_code: object
    normal_exit: bool
    reaped: bool
    process_group_quiet: bool
    cleanup_completed: bool
    ownership_complete: bool

def _collect(capture, now, deadline):
    if (type(capture) is not PipeCapture or type(capture.eof) is not bool
            or not capture.eof or type(capture.chunks) is not tuple
            or len(capture.chunks) > MAX_CHUNKS):
        return None
    out = bytearray()
    try:
        for part in capture.chunks:
            if now() > deadline or type(part) is not bytes or len(part) > MAX_CHUNK:
                return None
            if len(out) + len(part) > MAX_TOTAL: return None
            out.extend(part)
    except BaseException:
        return None
    return bytes(out)

def consume(stdout, stderr, child, *, start_time, deadline, now, cancelled=False):
    """Consume completed fake captures against one original monotonic window."""
    if (not _finite_number(start_time) or not _finite_number(deadline)
            or deadline <= start_time or type(cancelled) is not bool): return generic()
    last = [start_time]
    def checked_now():
        value = now()
        if (not _finite_number(value) or value < last[0] or value > deadline):
            raise ValueError
        last[0] = value
        return value
    try:
        if checked_now() < start_time or cancelled: return generic()
        out = _collect(stdout, checked_now, deadline)
        err = _collect(stderr, checked_now, deadline)
        checked_now()
        if out is None or err is None: return generic()
        if (type(child) is not ChildFacts or child.normal_exit is not True
                or child.reaped is not True or child.process_group_quiet is not True
                or child.cleanup_completed is not True or child.ownership_complete is not True
                or type(child.exit_code) is not int): return generic()
        if child.exit_code != 0: return generic()
        evidence = record(out, err, child.exit_code, cleanup_completed=True)
        if evidence.status != "complete": return generic()
        return evidence
    except BaseException:
        return generic()

# A runtime-facing entrypoint intentionally remains closed.
def run_runtime(*args, **kwargs):
    return generic()
