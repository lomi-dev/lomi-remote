"""Source-only private pipe seam. No process creation, raw logs, or PID lookup."""
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import math
import os
from pathlib import Path
import stat
import sys

PARSER_SHA256 = "4c4248088591e64f95008758682967b6e1e39c645609a769497f06b613d53328"
READ_SIZE = 256
POLL_SECONDS = 0.05


def _load_parser():
    path = Path(__file__).resolve().parent / "closed_dependencies" / "diagnostics.py"
    if hashlib.sha256(path.read_bytes()).hexdigest() != PARSER_SHA256:
        raise RuntimeError("private parser source mismatch")
    spec = importlib.util.spec_from_file_location("_consumer_private_stream_parser", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_diagnostics = _load_parser()


def new_parser():
    return _diagnostics.DiagnosticParser()


@dataclass(frozen=True, slots=True)
class StreamResult:
    outcome: str
    diagnostic: _diagnostics.Result
    stdout_eof: bool
    stderr_eof: bool
    child_reaped: bool
    stop_requested: bool
    cleanup_required: bool = True

    def evidence(self):
        return asdict(self)


class AnonymousPipeIO:
    """Only pump() is the exception-sanitizing entry point.

    Receives two exclusively owned read descriptors; never closes either pipe.
    Caller guarantees anonymous pipes and no concurrent descriptor reuse/reads.
    FIFO mode rejects regular files but cannot establish anonymous provenance.
    """
    __slots__ = ("_fds", "_selector")

    def __init__(self, stdout_fd, stderr_fd):
        self._fds = (stdout_fd, stderr_fd)
        self._selector = None

    def __repr__(self):
        return "<AnonymousPipeIO private>"

    def start(self):
        # Lazy import: fake-I/O tests do not instantiate a native selector.
        import selectors
        if (any(type(fd) is not int or fd < 0 for fd in self._fds)
                or self._fds[0] == self._fds[1]):
            raise RuntimeError("private pipe descriptors invalid")
        self._selector = selectors.DefaultSelector()
        for stream, fd in enumerate(self._fds):
            if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                raise RuntimeError("private pipe descriptor required")
            os.set_blocking(fd, False)
            self._selector.register(fd, selectors.EVENT_READ, stream)

    def ready(self, timeout):
        return tuple(key.data for key, mask in self._selector.select(timeout))

    def read(self, stream):
        return os.read(self._fds[stream], READ_SIZE)

    def retire(self, stream):
        self._selector.unregister(self._fds[stream])

    def close(self):
        if self._selector is not None:
            self._selector.close()
            self._selector = None


def _finite_number(value):
    return type(value) in (int, float) and math.isfinite(value)


def pump(owner, child, io, parser, *, end, clock, cancelled):
    """Consume already-registered child pipes; ownership never transfers here.

    owner.retains(child) must return literal True for the same retained record.
    owner.reap_if_ready(child) returns None, or an exact int ONLY after retained
    group/identity checks and actual reaping. owner.request_stop(child) must
    retain the record and safely request cancellation (idempotent if reaped).
    All callbacks are trusted, bounded, credential-safe and non-logging.
    Caller MUST run its owner final cleanup in finally for every result.
    """
    outcome = "io-failure"
    eof = [False, False]
    reaped = stop_requested = admitted = completed = deadline = False
    exit_code = None
    diagnostic = None
    chunk = None
    parser_valid = type(parser) is _diagnostics.DiagnosticParser
    try:
        if owner.retains(child) is not True:
            outcome = "ownership-failure"
        else:
            admitted = True
            if not parser_valid or not _finite_number(end):
                outcome = "invalid-control"
            else:
                io.start()
                while True:
                    if owner.retains(child) is not True:
                        outcome = "ownership-failure"
                        break
                    flag = cancelled()
                    now = clock()
                    if type(flag) is not bool or not _finite_number(now):
                        outcome = "invalid-control"
                        break
                    if flag:
                        outcome = "cancelled"
                        break
                    if now >= end:
                        outcome = "deadline"
                        deadline = True
                        break
                    if not reaped:
                        status = owner.reap_if_ready(child)
                        if status is not None:
                            if type(status) is not int:
                                outcome = "ownership-failure"
                                break
                            reaped = True
                            exit_code = status
                    if all(eof) and reaped:
                        # Reap hooks may consume time or observe cancellation.
                        # Recheck controls at the final completion gate.
                        flag = cancelled()
                        now = clock()
                        if type(flag) is not bool or not _finite_number(now):
                            outcome = "invalid-control"
                            break
                        if flag:
                            outcome = "cancelled"
                            break
                        if now >= end:
                            outcome = "deadline"
                            deadline = True
                            break
                        if owner.retains(child) is not True:
                            outcome = "ownership-failure"
                            break
                        diagnostic = parser.finish(exit_code, deadline=False, cancelled=False)
                        outcome = "stream-finished"
                        completed = True
                        break
                    ready = io.ready(min(POLL_SECONDS, end - now))
                    if (type(ready) is not tuple or len(ready) > 2
                            or any(type(stream) is not int or stream not in (0, 1) for stream in ready)
                            or len(set(ready)) != len(ready)):
                        outcome = "io-failure"
                        break
                    for stream in ready:
                        if eof[stream]:
                            outcome = "io-failure"
                            break
                        try:
                            chunk = io.read(stream)
                        except (BlockingIOError, InterruptedError):
                            # Readiness is advisory; retry on a later bounded tick.
                            continue
                        try:
                            if type(chunk) is not bytes or len(chunk) > READ_SIZE:
                                outcome = "io-failure"
                                break
                            if chunk == b"":
                                io.retire(stream)
                                eof[stream] = True
                            else:
                                (parser.feed_stdout if stream == 0 else parser.feed_stderr)(chunk)
                                if parser._failed:
                                    # Exact pinned private seam; no raw-output fallback.
                                    outcome = "protocol-failure"
                                    break
                        finally:
                            chunk = None
                    else:
                        continue
                    break
    except BaseException:
        # Never retain/stringify/rethrow exceptions: they may contain credentials.
        outcome = "io-failure"
    finally:
        chunk = None
        try:
            io.close()
        except BaseException:
            outcome = "io-failure"
            completed = False
        if not completed:
            if parser_valid:
                parser._reject()
            diagnostic = _diagnostics.Result("generic-failure", None, (), 0,
                                            (0 if exit_code == 0 else 1) if reaped else None,
                                            deadline)
            if admitted:
                try:
                    # This callback does not transfer/drop ownership, even on error.
                    owner.request_stop(child)
                    stop_requested = True
                except BaseException:
                    stop_requested = False
    return StreamResult(outcome, diagnostic, eof[0], eof[1], reaped, stop_requested)
