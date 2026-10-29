"""Fake descriptors/selector/owner only; no native pipe, child, or socket calls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parent
AUDIT = {"child_attempts": 0, "network_attempts": 0, "pipe_attempts": 0}


def audit(event, args):
    if event in ("subprocess.Popen", "os.system", "os.posix_spawn", "os.fork", "os.forkpty", "pty.spawn", "os.exec", "os.spawn"):
        AUDIT["child_attempts"] += 1
        raise RuntimeError("child creation forbidden")
    if event.startswith("socket."):
        AUDIT["network_attempts"] += 1
        raise RuntimeError("network forbidden")


sys.addaudithook(audit)
spec = importlib.util.spec_from_file_location("private_streams", ROOT / "streams.py")
s = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = s
spec.loader.exec_module(s)
CANARY = "PRIVATE_STREAM_CANARY_TOKEN_HASH_IDENTIFIER_123"
GOOD = b"".join(s._diagnostics.notice_line(i) for i in range(13))


class Hostile:
    def __repr__(self):
        raise AssertionError("must not inspect repr")

    def __str__(self):
        raise AssertionError("must not inspect str")

    def __bool__(self):
        raise AssertionError("must not inspect truthiness")


class FakeIO:
    def __init__(self, stdout=(), stderr=(), *, end=True):
        self.chunks = [list(stdout), list(stderr)]
        self.eof_enabled = end
        self.active = [True, True]
        self.ticks = 0
        self.elapsed = 0.0
        self.started = self.closed = False
        self.reads = [0, 0]
        self.max_chunk = 0
        self.read_order = []
        self.fault = None

    def start(self):
        self.started = True
        if self.fault == "start":
            raise RuntimeError(CANARY)

    def ready(self, timeout):
        if self.fault == "ready":
            raise RuntimeError(CANARY)
        if not 0 < timeout <= s.POLL_SECONDS:
            raise AssertionError("unbounded selector timeout")
        self.ticks += 1
        self.elapsed += timeout
        return tuple(i for i in range(2) if self.active[i] and (self.chunks[i] or self.eof_enabled))

    def read(self, stream):
        self.reads[stream] += 1
        self.read_order.append(stream)
        if self.fault == "read":
            raise RuntimeError(CANARY)
        if not self.chunks[stream]:
            return b""
        value = self.chunks[stream].pop(0)
        if isinstance(value, BaseException):
            raise value
        if type(value) is bytes and len(value) > s.READ_SIZE:
            self.chunks[stream].insert(0, value[s.READ_SIZE:])
            value = value[:s.READ_SIZE]
        if type(value) is bytes:
            self.max_chunk = max(self.max_chunk, len(value))
        return value

    def retire(self, stream):
        if self.fault == "retire":
            raise RuntimeError(CANARY)
        self.active[stream] = False

    def close(self):
        self.closed = True
        if self.fault == "close":
            raise RuntimeError(CANARY)


class FakeOwner:
    def __init__(self, child, io, *, status=0, reap_tick=1):
        self.children = [child]
        self.io = io
        self.status = status
        self.reap_tick = reap_tick
        self.reap_calls = self.actual_reaps = self.stops = 0
        self.fault = None

    def retains(self, child):
        if self.fault == "retains":
            raise RuntimeError(CANARY)
        return any(record is child for record in self.children)

    def reap_if_ready(self, child):
        if self.fault == "reap":
            raise RuntimeError(CANARY)
        self.reap_calls += 1
        if self.io.ticks < self.reap_tick:
            return None
        if self.actual_reaps:
            raise AssertionError("double reap")
        self.actual_reaps += 1
        return self.status

    def request_stop(self, child):
        self.stops += 1
        if self.fault == "stop":
            raise RuntimeError(CANARY)


class StreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No accidental native process/pipe I/O during a fake-only test.
        cls.saved = {name: getattr(s.os, name) for name in ("read", "set_blocking", "fstat", "pipe")}
        def forbidden(*args, **kwargs):
            AUDIT["pipe_attempts"] += 1
            raise RuntimeError("native pipe I/O forbidden")
        for name in cls.saved:
            setattr(s.os, name, forbidden)

    @classmethod
    def tearDownClass(cls):
        for name, original in cls.saved.items():
            setattr(s.os, name, original)
        if any(AUDIT.values()):
            raise AssertionError("pure audit gate failed")

    def run_pump(self, io=None, *, owner_fault=None, status=0, reap_tick=1, end=2.0,
                 cancelled=None, parser=None, reap_effect=None):
        io = io if io is not None else FakeIO(stderr=(GOOD,))
        child = Hostile()
        owner = FakeOwner(child, io, status=status, reap_tick=reap_tick)
        owner.fault = owner_fault
        if reap_effect is not None:
            original_reap = owner.reap_if_ready
            def reap(child):
                status = original_reap(child)
                if status is not None:
                    reap_effect(owner)
                return status
            owner.reap_if_ready = reap
        parser = parser if parser is not None else s.new_parser()
        finished = []
        original = s._diagnostics.DiagnosticParser.finish
        def finish(instance, code, **flags):
            finished.append((code, flags, tuple(io.active), owner.actual_reaps))
            return original(instance, code, **flags)
        s._diagnostics.DiagnosticParser.finish = finish
        try:
            result = s.pump(owner, child, io, parser, end=end,
                            clock=lambda: io.elapsed,
                            cancelled=cancelled if cancelled is not None else lambda: False)
        finally:
            s._diagnostics.DiagnosticParser.finish = original
        self.assertIs(owner.children[0], child)
        self.assertTrue(io.closed)
        self.assertTrue(result.cleanup_required)
        self.assertLessEqual(io.max_chunk, s.READ_SIZE)
        for output in (repr(result), json.dumps(result.evidence()), repr(parser)):
            self.assertNotIn(CANARY, output)
        for _, flags, active, actual_reaps in finished:
            self.assertEqual(flags, {"deadline": False, "cancelled": False})
            self.assertEqual(active, (False, False))
            self.assertEqual(actual_reaps, 1)
        if result.outcome != "stream-finished":
            if io.fault != "close":
                self.assertEqual(finished, [])
            self.assertEqual(result.diagnostic.stage, "generic-failure")
        return result, io, owner, finished

    def test_success_all_split_boundaries(self):
        for boundary in range(1, len(GOOD)):
            result, _, owner, finished = self.run_pump(FakeIO(stderr=(GOOD[:boundary], GOOD[boundary:])))
            self.assertEqual((result.outcome, result.diagnostic.stage), ("stream-finished", "complete"))
            self.assertEqual(len(finished), 1)
            self.assertEqual(owner.stops, 0)

    def test_one_byte_chunks(self):
        result, _, _, _ = self.run_pump(FakeIO(stderr=tuple(bytes((byte,)) for byte in GOOD)), end=100.0)
        self.assertEqual(result.diagnostic.count, 13)

    def test_unexpected_stdout_and_all_secret_diagnostics(self):
        for label in ("MESSAGE", "DETAIL", "HINT", "CONTEXT", "QUERY", "row"):
            data = f"{label}: {CANARY}\n".encode()
            for io in (FakeIO(stdout=(data,), stderr=(GOOD,)), FakeIO(stderr=(GOOD, data))):
                result, _, owner, _ = self.run_pump(io)
                self.assertEqual(result.outcome, "protocol-failure")
                self.assertEqual(owner.stops, 1)

    def test_malformed_notice_duplicate_reorder_invalid_utf8(self):
        for data in (GOOD[:-1], GOOD.replace(b":59:", b":60:"), GOOD + b"\xff",
                     s._diagnostics.notice_line(0) * 2, s._diagnostics.notice_line(1), b"\xc0\xaf"):
            result, _, _, _ = self.run_pump(FakeIO(stderr=(data,)))
            self.assertEqual(result.diagnostic.stage, "generic-failure")

    def test_exact_error_sanitized_only_after_eof_and_reap(self):
        envelope = b"psql:positive-auth.sql:59: ERROR:  positive-auth:setup-runtime:28000\n"
        for boundary in range(1, len(envelope)):
            result, _, _, _ = self.run_pump(FakeIO(stderr=(envelope[:boundary], envelope[boundary:])), status=3)
            self.assertEqual((result.diagnostic.stage, result.diagnostic.state), ("setup-runtime", "28000"))
        for suffix in (CANARY.encode(), b"DETAIL: " + CANARY.encode()):
            result, _, _, _ = self.run_pump(FakeIO(stderr=(envelope, suffix)), status=3)
            self.assertEqual(result.diagnostic.stage, "generic-failure")

    def test_nonzero_after_markers_and_missing_markers(self):
        for data, code in ((GOOD, 3), (b"", 0), (GOOD[:-1], 0)):
            result, _, _, finished = self.run_pump(FakeIO(stderr=(data,) if data else ()), status=code)
            self.assertEqual(result.diagnostic.stage, "generic-failure")
            self.assertEqual(len(finished), 1)

    def test_oversize_reads_are_bounded_and_stop_early(self):
        io = FakeIO(stderr=((CANARY * 100_000).encode(),))
        result, io, owner, _ = self.run_pump(io)
        self.assertEqual(result.outcome, "protocol-failure")
        self.assertEqual(io.reads[1], 1)
        self.assertEqual(owner.stops, 1)

    def test_adapter_rejects_oversized_or_nonbyte_backend_read(self):
        for bad in (b"x" * (s.READ_SIZE + 1), Hostile(), CANARY):
            io = FakeIO()
            io.read = lambda stream: bad
            result, _, _, _ = self.run_pump(io)
            self.assertEqual(result.outcome, "io-failure")

    def test_backpressure_fairness_and_readiness_races(self):
        io = FakeIO(stderr=(BlockingIOError(CANARY), InterruptedError(CANARY), GOOD))
        result, io, _, _ = self.run_pump(io)
        self.assertEqual(result.diagnostic.stage, "complete")
        self.assertEqual(io.read_order[:2], [0, 1])
        self.assertEqual(io.reads[0], 1)
        self.assertGreater(io.reads[1], 3)

    def test_cancel_retains_child_and_does_not_finish(self):
        io = FakeIO(stderr=(GOOD,))
        result, _, owner, _ = self.run_pump(io, cancelled=lambda: io.ticks >= 1)
        self.assertEqual(result.outcome, "cancelled")
        self.assertEqual(owner.stops, 1)

    def test_deadline_including_eof_without_reap(self):
        for io in (FakeIO(end=False), FakeIO(stderr=(GOOD,))):
            result, _, owner, finished = self.run_pump(io, reap_tick=100, end=0.2)
            self.assertEqual(result.outcome, "deadline")
            self.assertIs(result.diagnostic.deadline, True)
            self.assertFalse(result.child_reaped)
            self.assertEqual(finished, [])
            self.assertEqual(owner.stops, 1)

    def test_reap_without_eof_cannot_finish(self):
        result, _, _, _ = self.run_pump(FakeIO(end=False), end=0.2)
        self.assertEqual(result.outcome, "deadline")
        self.assertTrue(result.child_reaped)

    def test_controls_and_ownership_rechecked_after_reap(self):
        controls = {"cancelled": False}
        def cancel_after_reap(owner):
            controls["cancelled"] = True
        result, _, _, _ = self.run_pump(reap_tick=10, cancelled=lambda: controls["cancelled"],
                                      reap_effect=cancel_after_reap)
        self.assertEqual(result.outcome, "cancelled")
        self.assertTrue(result.child_reaped)
        result, _, _, _ = self.run_pump(reap_tick=10,
                                      reap_effect=lambda owner: setattr(owner.io, "elapsed", 10.0))
        self.assertEqual(result.outcome, "deadline")
        self.assertTrue(result.child_reaped)
        # Simulate a violated owner contract: never accept the resulting exit.
        result, _, _, _ = self.run_pump(reap_tick=10,
                                      reap_effect=lambda owner: setattr(owner, "retains", lambda child: False))
        self.assertEqual(result.outcome, "ownership-failure")

    def test_all_io_failures_are_sanitized_handoffs(self):
        for fault in ("start", "ready", "read", "retire", "close"):
            io = FakeIO(stderr=(GOOD,))
            io.fault = fault
            result, _, owner, finished = self.run_pump(io)
            self.assertEqual(result.outcome, "io-failure")
            self.assertEqual(owner.stops, 1)
            # A selector-close fault may invalidate an already-finished parser.
            self.assertLessEqual(len(finished), 1)

    def test_midread_failure_and_hostile_exception_do_not_escape(self):
        class HostileError(BaseException, Hostile):
            __str__ = Hostile.__str__
            __repr__ = Hostile.__repr__
        for error in (RuntimeError(CANARY), HostileError()):
            result, _, _, _ = self.run_pump(FakeIO(stderr=(GOOD[:256], error)))
            self.assertEqual(result.outcome, "io-failure")

    def test_owner_faults_and_invalid_reap_cannot_qualify(self):
        for fault in ("retains", "reap", "stop"):
            result, _, owner, _ = self.run_pump(FakeIO(stdout=(CANARY.encode(),)), owner_fault=fault)
            self.assertEqual(result.diagnostic.stage, "generic-failure")
            self.assertEqual(len(owner.children), 1)
        for status in (True, CANARY, Hostile()):
            result, _, _, _ = self.run_pump(status=status)
            self.assertEqual(result.outcome, "ownership-failure")

    def test_invalid_controls_never_inspected(self):
        for value in (0, 1, "true", None, CANARY, Hostile()):
            result, _, _, _ = self.run_pump(cancelled=lambda: value)
            self.assertEqual(result.outcome, "invalid-control")
        for end in (True, CANARY, Hostile(), float("nan"), float("inf")):
            result, _, _, _ = self.run_pump(end=end)
            self.assertEqual(result.outcome, "invalid-control")

    def test_closed_dependency_and_repr(self):
        self.assertEqual(hashlib.sha256((ROOT / "closed_dependencies/diagnostics.py").read_bytes()).hexdigest(), s.PARSER_SHA256)
        self.assertEqual(repr(s.AnonymousPipeIO(Hostile(), Hostile())), "<AnonymousPipeIO private>")
        self.assertEqual(AUDIT, {"child_attempts": 0, "network_attempts": 0, "pipe_attempts": 0})

    def test_anonymous_adapter_with_fake_selector_and_fake_os_calls(self):
        calls = []
        class Selector:
            def register(self, fd, event, data):
                calls.append(("register", fd, event, data))

            def select(self, timeout):
                calls.append(("select", timeout))
                return [(SimpleNamespace(data=0), 1), (SimpleNamespace(data=1), 1)]

            def unregister(self, fd):
                calls.append(("unregister", fd))

            def close(self):
                calls.append(("close-selector",))
        old_selector = sys.modules.get("selectors")
        old_os = {name: getattr(s.os, name) for name in ("read", "set_blocking", "fstat")}
        sys.modules["selectors"] = SimpleNamespace(DefaultSelector=Selector, EVENT_READ=1)
        s.os.fstat = lambda fd: SimpleNamespace(st_mode=0o010000)
        s.os.set_blocking = lambda fd, value: calls.append(("blocking", fd, value))
        def read(fd, length):
            calls.append(("read", fd, length))
            return b"x" * length
        s.os.read = read
        try:
            adapter = s.AnonymousPipeIO(10, 11)
            adapter.start()
            self.assertEqual(adapter.ready(0.05), (0, 1))
            self.assertEqual(adapter.read(1), b"x" * 256)
            adapter.retire(1)
            adapter.close()
        finally:
            for name, original in old_os.items():
                setattr(s.os, name, original)
            if old_selector is None:
                del sys.modules["selectors"]
            else:
                sys.modules["selectors"] = old_selector
        self.assertEqual(calls, [("blocking", 10, False), ("register", 10, 1, 0),
                                 ("blocking", 11, False), ("register", 11, 1, 1),
                                 ("select", 0.05), ("read", 11, 256),
                                 ("unregister", 11), ("close-selector",)])


if __name__ == "__main__":
    unittest.main()
