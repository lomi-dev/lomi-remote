"""Pure staged adapter tests: fake process factory, clock, signals and pipes."""
import hashlib
import ctypes  # CPython's own ctypes bootstrap precedes the native-operation gate.
import importlib.util
import json
from pathlib import Path
import signal
import sys
import tempfile
import unittest

AUDIT = {"children": 0, "network": 0, "native_pipe": 0}


def audit(event, args):
    if event in ("subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.spawn", "os.kill", "os.killpg", "ctypes.dlopen"):
        AUDIT["children"] += 1
        raise RuntimeError("native operation forbidden")
    if event.startswith("socket."):
        AUDIT["network"] += 1
        raise RuntimeError("network forbidden")


sys.addaudithook(audit)
ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("private_guardian_staged_tests", ROOT/"private_guardian.py")
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
CANARY = "PRIVATE_GUARDIAN_CANARY_TOKEN_HASH_ID_456"
GOOD = b"".join(m.streams._diagnostics.notice_line(i) for i in range(13))


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, value):
        self.now += value


class Signals:
    ITIMER_REAL = 0
    def __init__(self):
        self.handlers = {}

    def getsignal(self, sig):
        return self.handlers.get(sig, "previous")

    def signal(self, sig, handler):
        self.handlers[sig] = handler

    def setitimer(self, *args):
        pass


class Pipe:
    def __init__(self, content):
        self.content = content
        self.closed = False

    def take(self):
        chunk, self.content = self.content[:256], self.content[256:]
        return chunk

    def close(self):
        self.closed = True

    def __repr__(self):
        return "<FakePipe private>"


class Handle:
    def __init__(self, pid, code):
        self.pid, self.code = pid, code
        self.reaped = False
        self.members = []
        self.stdout = self.stderr = None

    def poll(self):
        raise AssertionError("independent poll forbidden")

    def wait(self, *args, **kwargs):
        raise AssertionError("independent wait forbidden")


class Fake(m.SinkRouting):
    test_only = True
    def __init__(self, clock):
        self.clock = clock
        self.guardian = None
        self.children = []
        self.calls = []
        self.events = []
        self.public_code = 0
        self.public_output = b""
        self.public_stdout = None
        self.private_output = GOOD
        self.private_stdout = b""
        self.private_code = 0
        self.on_spawn = None
        self.fail_factory = False
        self._factory = self.factory

    def initialize(self):
        self.initialized = True

    def require_owner(self):
        if not self.initialized:
            raise RuntimeError("fake owner not initialized")

    def factory(self, argv, **options):
        g = self.guardian
        route = g._spawn_route[0]
        self.calls.append((route, tuple(argv), options["stdout"], options["stderr"]))
        if self.fail_factory and route == "private":
            raise RuntimeError(CANARY)
        code = self.public_code if route == "public" else self.private_code if route == "private" else 0
        if route == "server":
            code = None
        if Path(argv[0]).name == "pg_ctl" and argv[-1] == "status":
            code = 3 if g.postgres and g.postgres.handle.code is not None else 0
        handle = Handle(2000+len(self.children), code)
        self.children.append(handle)
        self.events.append(("spawn", route, handle))
        if route == "private":
            if options["stdout"] != m.subprocess.PIPE or options["stderr"] != m.subprocess.PIPE:
                raise AssertionError("private bytes routed to files")
            handle.stdout = Pipe(self.private_stdout)
            handle.stderr = Pipe(self.private_output)
        if route == "public":
            script = Path(argv[-1]).name
            stdout = (b"\n" if script == "fixture-ownership-bootstrap.sql" else b"")
            if self.public_stdout is not None:
                stdout = self.public_stdout
            options["stdout"].write(stdout)
            options["stderr"].write(self.public_output)
        if route == "server":
            if options["stdout"] != m.subprocess.DEVNULL or options["stderr"] != m.subprocess.DEVNULL:
                raise AssertionError("server bytes routed to files")
            (g.work/"data").mkdir(exist_ok=True)
            (g.work/"data/postmaster.pid").write_text(f"{handle.pid}\n{g.work/'data'}\n0\n55439\n{g.work/'socket'}\n\n")
            (g.work/"socket/fake-socket").write_text("fake")
        if Path(argv[0]).name == "pg_ctl" and argv[-1] == "stop":
            g.postgres.handle.code = 0
            (g.work/"data/postmaster.pid").unlink()
            (g.work/"socket/fake-socket").unlink()
        if self.on_spawn:
            self.on_spawn(route, handle)
        return handle

    def peek(self, handle):
        if not any(child is handle for child in self.children) or handle.reaped:
            raise RuntimeError("fake identity unavailable")
        return handle.code

    def other_live_group_members(self, handle):
        self.peek(handle)
        return list(handle.members)

    def reap(self, handle, timeout):
        self.peek(handle)
        if handle.code is None or handle.members:
            raise AssertionError("premature retained reap")
        handle.reaped = True
        self.events.append(("reap", handle))
        return handle.code

    def signal_group(self, handle, sig):
        self.peek(handle)
        self.events.append(("signal", handle, sig))
        if sig == signal.SIGKILL:
            handle.code = -9
            handle.members = []


class FakeIO:
    def __init__(self, record, clock):
        self.record, self.clock = record, clock
        self.active = [True, True]

    def start(self):
        pass

    def ready(self, timeout):
        self.clock.sleep(timeout)
        return tuple(i for i in range(2) if self.active[i])

    def read(self, stream):
        return (self.record.handle.stdout if stream == 0 else self.record.handle.stderr).take()

    def retire(self, stream):
        self.active[stream] = False

    def close(self):
        pass


class PrivateGuardianTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = {name: getattr(m.base.os, name) for name in ("read", "pipe", "set_blocking")}
        def deny(*args):
            AUDIT["native_pipe"] += 1
            raise RuntimeError("native pipe operation forbidden")
        for name in cls.native:
            setattr(m.base.os, name, deny)

    @classmethod
    def tearDownClass(cls):
        for name, value in cls.native.items():
            setattr(m.base.os, name, value)
        if any(AUDIT.values()):
            raise AssertionError("pure audit gate failed")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="private-guardian-fake-")
        self.root = Path(self.temp.name).resolve()
        self.work = self.root/"work"
        self.work.mkdir(mode=0o700)
        self.tools = {}
        for name in ("postgres", "pg_ctl", "initdb", "psql", "node"):
            path = self.root/name
            path.write_text("inert fake executable " + name)
            self.tools[name] = m.base.Executable(path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.clock = Clock()
        self.fake = Fake(self.clock)
        self.owners = []

    def tearDown(self):
        self.temp.cleanup()

    def run_body(self, body, **options):
        def wrapped(g):
            self.owners.append(g)
            body(g)
        result = m.run_appointment(self.work, self.tools, wrapped, started=0.0,
                                   backend=self.fake, clock=self.clock, sleep=self.clock.sleep,
                                   signals=Signals(), io_factory=lambda record: FakeIO(record, self.clock),
                                   **options)
        for serialized in (repr(result), json.dumps(result.evidence())):
            self.assertNotIn(CANARY, serialized)
        self.assertFalse(result.full_s5_qualified)
        self.assertTrue(all(handle.reaped for handle in self.fake.children))
        return result

    def prepare(self, g):
        g.initialize()
        g.start_postgres()
        g.wait_startup()

    def test_valid_gate_then_exact_private_pipe_routing_and_cleanup(self):
        def body(g):
            self.prepare(g)
            self.assertTrue(g.verify_private_policy())
            result = g.launch_private_sql()
            self.assertEqual(result.diagnostic.stage, "complete")
        result = self.run_body(body)
        self.assertEqual(result.stage, "private-stream-complete")
        self.assertTrue(result.cleanup_proven)
        self.assertTrue(result.owner_qualification_eligible)
        g = self.owners[0]
        self.assertEqual((g.started+840, g.qualification_deadline, g.emergency_deadline), (840, 900, 960))
        private = [call for call in self.fake.calls if call[0] == "private"]
        self.assertEqual(private[0][1], (str(self.tools["psql"].path), *g._private_args()))
        self.assertEqual(private[0][2:], (m.subprocess.PIPE, m.subprocess.PIPE))
        for call in self.fake.calls:
            if call[0] in ("server", "utility"):
                self.assertEqual(call[2:], (m.subprocess.DEVNULL, m.subprocess.DEVNULL))
        for record in g.children:
            if record.name != "psql" or "--file" in record.argv:
                self.assertEqual((record.stdout.read_bytes(), record.stderr.read_bytes()), (b"", b""))
        self.assertTrue(all(handle.stdout is None or handle.stdout.closed for handle in self.fake.children))
        for key, value in m.streams._diagnostics.SERVER_SETTINGS:
            self.assertIn(f"{key}={value}", g._postgres_args())

    def test_positive_before_gate_rejected_before_factory(self):
        self.run_body(lambda g: g.launch_private_sql())
        self.assertEqual(self.fake.calls, [])

    def test_known_public_schema_registry_precedes_private_latch(self):
        def body(g):
            self.prepare(g)
            self.assertTrue(g.run_public_schema("fixture-ownership-bootstrap.sql"))
            self.assertTrue(g.run_public_schema("fixture-ops.sql"))
            self.assertTrue(g.verify_private_policy())
            self.assertEqual(g.launch_private_sql().diagnostic.count, 13)
        self.run_body(body)
        public = [call for call in self.fake.calls if call[0] == "public"]
        self.assertEqual([Path(call[1][-1]).name for call in public],
                         ["fixture-ownership-bootstrap.sql", "fixture-ops.sql", "verify-private-policy.sql"])
        self.assertTrue(all(call[2] != m.subprocess.PIPE and call[3] != m.subprocess.PIPE for call in public))

    def test_bootstrap_exact_one_blank_stdout_is_accepted(self):
        self.fake.public_stdout = b"\n"
        def body(g):
            self.prepare(g)
            self.assertTrue(g.run_public_schema("fixture-ownership-bootstrap.sql"))
            record = g.children[-1]
            self.assertEqual(record.stdout.read_bytes(), b"\n")
            self.assertEqual(record.stderr.read_bytes(), b"")
        result = self.run_body(body)
        self.assertTrue(result.cleanup_proven)

    def test_bootstrap_missing_blank_stdout_is_rejected(self):
        self.fake.public_stdout = b""
        self.rejected_bootstrap()

    def test_bootstrap_extra_blank_stdout_is_rejected(self):
        self.fake.public_stdout = b"\n\n"
        self.rejected_bootstrap()

    def test_bootstrap_crlf_stdout_is_rejected_by_raw_hash(self):
        self.fake.public_stdout = b"\r\n"
        self.rejected_bootstrap()

    def test_bootstrap_bare_cr_stdout_is_rejected_by_raw_hash(self):
        self.fake.public_stdout = b"\r"
        self.rejected_bootstrap()

    def test_bootstrap_nonempty_stdout_is_rejected(self):
        self.fake.public_stdout = b"unexpected public row\n"
        self.rejected_bootstrap()

    def test_bootstrap_nonempty_stderr_is_rejected(self):
        self.fake.public_output = b"unexpected public diagnostic\n"
        self.rejected_bootstrap()

    def rejected_bootstrap(self):
        def body(g):
            self.prepare(g)
            g.run_public_schema("fixture-ownership-bootstrap.sql")
            g.verify_private_policy()
        result = self.run_body(body)
        self.assertFalse(result.owner_qualification_eligible)
        self.assertEqual(result.stage, "private-failure")
        self.assertFalse(any(call[0] == "private" for call in self.fake.calls))

    def test_ops_one_blank_stdout_is_wrong_script_and_rejected(self):
        self.fake.public_stdout = b"\n"
        result = self.run_body(lambda g: (self.prepare(g), g.run_public_schema("fixture-ops.sql")))
        self.assertFalse(result.owner_qualification_eligible)

    def test_guc_one_blank_stdout_is_wrong_script_and_rejected(self):
        self.fake.public_stdout = b"\n"
        result = self.run_body(lambda g: (self.prepare(g), g.verify_private_policy()))
        self.assertFalse(result.owner_qualification_eligible)
        self.assertFalse(any(call[0] == "private" for call in self.fake.calls))

    def rejected_gate(self, code, output):
        self.fake.public_code, self.fake.public_output = code, output
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            g.launch_private_sql()
        result = self.run_body(body)
        self.assertEqual(result.stage, "private-failure")
        self.assertFalse(any(call[0] == "private" for call in self.fake.calls))

    def test_wrong_guc_nonzero_never_latches(self):
        self.rejected_gate(3, b"ERROR: private policy rejected\n")

    def test_nonempty_public_output_never_latches(self):
        self.rejected_gate(0, b"unexpected public output\n")

    def test_no_actual_public_exit_never_latches(self):
        self.rejected_gate(None, b"")

    def test_source_replacement_rejected_before_public_factory(self):
        def body(g):
            self.prepare(g)
            (g.work/"verify-private-policy.sql").write_text(CANARY)
            g.verify_private_policy()
        self.run_body(body)
        self.assertFalse(any(call[0] in ("public", "private") for call in self.fake.calls))

    def test_positive_source_replacement_rejected_before_private_factory(self):
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            (g.work/"positive-auth.sql").write_text(CANARY)
            g.launch_private_sql()
        self.run_body(body)
        self.assertFalse(any(call[0] == "private" for call in self.fake.calls))

    def test_no_public_retry_after_private_latch(self):
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            calls = len(self.fake.calls)
            with self.assertRaises(m.PrivateFailure):
                g.run_public_schema("fixture-ops.sql")
            with self.assertRaises(m.PrivateFailure):
                g.verify_private_policy()
            self.assertEqual(len(self.fake.calls), calls)
        self.run_body(body)

    def test_unknown_public_and_node_argv_rejected_before_factory(self):
        def body(g):
            for action in (lambda: g.psql(g.database, g.work/"positive-auth.sql"),
                           lambda: g.run_public_schema("unknown.sql"),
                           lambda: g._launch("psql", ("--file", "unknown.sql")),
                           lambda: g.run_node(CANARY), lambda: g.tool_version("psql")):
                with self.assertRaises(m.PrivateFailure):
                    action()
        self.run_body(body)
        self.assertEqual(self.fake.calls, [])

    def test_cancel_inside_factory_registers_before_pump_and_cleans(self):
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            def cancel(route, handle):
                if route == "private":
                    self.assertFalse(any(record.handle is handle for record in g.children))
                    handle.code = None
                    g.cancel.handle(signal.SIGTERM)
            self.fake.on_spawn = cancel
            result = g.launch_private_sql()
            self.assertEqual(result.outcome, "cancelled")
            self.assertTrue(any(record.handle is self.fake.children[-1] for record in g.children))
        result = self.run_body(body)
        self.assertTrue(result.cleanup_proven)
        self.assertFalse(result.owner_qualification_eligible)
        self.assertTrue(any(event[0] == "signal" for event in self.fake.events))

    def test_private_canaries_never_reach_files_or_evidence(self):
        self.fake.private_output = ("CONTEXT: " + CANARY).encode()
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            self.assertEqual(g.launch_private_sql().diagnostic.stage, "generic-failure")
        result = self.run_body(body)
        self.assertFalse(result.owner_qualification_eligible)
        for path in (self.work/"logs").iterdir():
            self.assertNotIn(CANARY.encode(), path.read_bytes())

    def test_private_io_observes_original_work_deadline_and_cleanup_reserve(self):
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            self.clock.now = 839.99
            self.fake.private_code = None
            result = g.launch_private_sql()
            self.assertEqual(result.outcome, "deadline")
            self.assertIs(result.diagnostic.deadline, True)
            self.assertLess(self.clock.now, 900)
            self.assertEqual(g.emergency_deadline, 960)
        result = self.run_body(body)
        self.assertTrue(result.cleanup_proven)
        self.assertFalse(result.owner_qualification_eligible)

    def test_factory_failure_is_fixed_and_outer_cleanup_runs(self):
        self.fake.fail_factory = True
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            with self.assertRaises(m.PrivateFailure) as captured:
                g.launch_private_sql()
            self.assertEqual(str(captured.exception), "private operation rejected")
            self.assertIsNone(captured.exception.__context__)
            self.assertIsNone(captured.exception.__cause__)
            raise m.PrivateFailure()
        result = self.run_body(body)
        self.assertTrue(result.cleanup_proven)
        self.assertEqual(result.stage, "private-failure")

    def test_registration_close_failure_retains_handle_for_outer_cleanup(self):
        original = m.base.ExitStack
        class FaultyStack(original):
            def close(stack):
                super().close()
                if self.fake.guardian._phase == "private-launch":
                    raise RuntimeError(CANARY)
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            m.base.ExitStack = FaultyStack
            g.launch_private_sql()
        try:
            result = self.run_body(body)
        finally:
            m.base.ExitStack = original
        self.assertTrue(result.cleanup_proven)
        self.assertTrue(any(handle.stdout is not None and handle.stdout.closed for handle in self.fake.children))

    def test_recording_failure_after_private_result_still_cleans(self):
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            g.launch_private_sql()
            raise RuntimeError(CANARY)
        result = self.run_body(body)
        self.assertTrue(result.cleanup_proven)
        self.assertFalse(result.owner_qualification_eligible)

    def test_pump_failure_after_registration_keeps_owned_cleanup(self):
        class FailingIO(FakeIO):
            def read(self, stream):
                raise RuntimeError(CANARY)
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            g._io_factory = lambda record: FailingIO(record, self.clock)
            self.assertEqual(g.launch_private_sql().outcome, "io-failure")
        result = self.run_body(body)
        self.assertTrue(result.cleanup_proven)
        self.assertFalse(result.owner_qualification_eligible)

    def test_pipe_adapter_setup_failure_after_registration_still_cleans(self):
        def fail(record):
            self.assertTrue(any(child is record for child in self.owners[0].children))
            raise RuntimeError(CANARY)
        def body(g):
            self.prepare(g)
            g.verify_private_policy()
            g._io_factory = fail
            g.launch_private_sql()
        result = self.run_body(body)
        self.assertTrue(result.cleanup_proven)
        self.assertFalse(result.owner_qualification_eligible)

    def test_constructor_failure_calls_outer_finish_owner(self):
        calls = []
        original = m.PrivateGuardian.finish_owner
        def finish(owner):
            calls.append(True)
            return original(owner)
        m.PrivateGuardian.finish_owner = finish
        try:
            result = self.run_body(lambda g: None, database="unapproved")
        finally:
            m.PrivateGuardian.finish_owner = original
        self.assertEqual(calls, [True])
        self.assertFalse(result.cleanup_proven)
        self.assertEqual(self.fake.calls, [])

    def test_gate_requires_owned_ready_foreground(self):
        self.run_body(lambda g: g.verify_private_policy())
        self.assertEqual(self.fake.calls, [])

    def test_source_admission_failure_prevents_every_factory_call(self):
        result = self.run_body(lambda g: self.prepare(g), source_root=self.root)
        self.assertEqual(self.fake.calls, [])
        self.assertTrue(result.cleanup_proven)
        self.assertFalse(result.owner_qualification_eligible)

    def test_pins_guc_script_and_audit(self):
        for relative, expected in m.DEPENDENCIES.items():
            self.assertEqual(hashlib.sha256((ROOT/relative).read_bytes()).hexdigest(), expected)
        sql = (ROOT/"verify-private-policy.sql").read_text()
        for key, value in m.streams._diagnostics.SERVER_SETTINGS:
            self.assertIn(f"current_setting('{key}') IS DISTINCT FROM '{value}'", sql)
        self.assertNotIn("RAISE NOTICE", sql)
        self.assertEqual(AUDIT, {"children": 0, "network": 0, "native_pipe": 0})


if __name__ == "__main__":
    unittest.main()
