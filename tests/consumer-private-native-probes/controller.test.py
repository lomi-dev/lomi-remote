"""Pure controller checks. All process, signal, pipe and selector I/O is fake."""
import ctypes  # CPython bootstrap only, before native-operation audit rejection.
import hashlib
import importlib.util
import json
from pathlib import Path
import re
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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


c = load("private_native_probe_controller", ROOT/"controller.py")
# Reuse the exact closed fake classes from the reviewed 31-test adapter fixture.
# Import does not execute its unittest suite or start any child.
fake_path = ROOT/"closed_dependencies/private_guardian_staging/private_guardian.test.py"
assert hashlib.sha256(fake_path.read_bytes()).hexdigest() == "f353ca878c7bd5a799d5345e8089f8b400432994a68d1e71f388c4d2a685b198"
fixture = load("private_native_probe_closed_fakes", fake_path)
p = fixture.m
Probe = c.probe_type(p)
CANARY = "PRIVATE_PIPE_PROBE_SYNTHETIC_CANARY_8A19"
GOOD = b"".join(p.streams._diagnostics.notice_line(i) for i in range(13))


class ProbeFake(fixture.Fake):
    """Model initdb's owned0700 data directory before foreground startup."""
    def factory(self, argv, **options):
        if Path(argv[0]).name == "initdb":
            (self.guardian.work/"data").mkdir(mode=0o700, exist_ok=True)
        return super().factory(argv, **options)


class ControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.originals = {name: getattr(c.os, name) for name in ("read", "pipe", "set_blocking", "kill", "killpg")}
        def deny(*args):
            AUDIT["native_pipe"] += 1
            raise RuntimeError("native operation forbidden")
        for name in cls.originals:
            setattr(c.os, name, deny)

    @classmethod
    def tearDownClass(cls):
        for name, value in cls.originals.items():
            setattr(c.os, name, value)
        if any(AUDIT.values()) or any(fixture.AUDIT.values()):
            raise AssertionError("pure audit gate failed")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="private-probe-fake-")
        self.root = Path(self.temp.name).resolve()
        self.work = self.root/"work"
        self.work.mkdir(mode=0o700)
        self.clock = fixture.Clock()
        self.backend = ProbeFake(self.clock)
        self.tools = {}
        for name in ("initdb", "postgres", "pg_ctl", "psql", "node"):
            path = self.root/name
            path.write_text("inert synthetic tool " + name)
            self.tools[name] = p.base.Executable(path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.guardian = Probe(self.work, self.tools, started=0.0, backend=self.backend,
                              clock=self.clock, sleep=self.clock.sleep, signals=fixture.Signals(),
                              probe_io_builder=self.io_builder)

    def tearDown(self):
        # Native code uses execute_case's mandatory finally, never this test escape.
        if not self.guardian._emergency_sink.closed:
            self.guardian.finish_owner()
        self.temp.cleanup()

    def io_builder(self, record):
        self.assertTrue(any(child is record for child in self.guardian.children))
        return fixture.FakeIO(record, self.clock)

    def run_case(self, case, **kwargs):
        facts = c.execute_case(case, self.guardian, source_root=c.PROJECT, end=1.0, **kwargs)
        self.assertTrue(self.guardian._emergency_sink.closed)
        self.assertTrue(all(child.reaped and child.group_quiet for child in self.guardian.children))
        self.assertNotIn(CANARY, json.dumps(facts))
        self.assertNotIn(CANARY, repr(facts))
        self.assertEqual(facts["positiveSqlCallsExecuted"], 0)
        self.assertFalse(facts["fullS5Qualified"])
        return facts

    def test_default_and_invalid_cli_are_childless_status(self):
        result, code = c.main([])
        self.assertEqual(code, 0)
        self.assertTrue(all(value == "NOT_RUN" for value in result["cases"].values()))
        self.assertEqual(c.main(["--unknown"])[1], 1)
        self.assertEqual(self.backend.calls, [])

    def test_exact_root_admission_schema(self):
        good = {"scope": c.SCOPE, "freezeSha256": "a"*64, "rootReviewed": True}
        self.assertTrue(c.valid_admission(good, "a"*64))
        for value in (False, 1, 1.0, "true", None):
            self.assertFalse(c.valid_admission({**good, "rootReviewed": value}, "a"*64))
        self.assertFalse(c.valid_admission({**good, "extra": True}, "a"*64))
        self.assertFalse(c.valid_admission({**good, "scope": "positive-auth"}, "a"*64))

    def test_parent_environment_is_private_closed_and_never_echoed(self):
        previous = dict(c.os.environ)
        try:
            c.os.environ.clear()
            c.os.environ.update(HOME=str(self.root), TMPDIR=str(self.root), PATH="/usr/bin:/bin", LC_ALL="C")
            c.private_parent_environment()
            c.os.environ["PGPASSWORD"] = CANARY
            with self.assertRaises(RuntimeError) as captured:
                c.private_parent_environment()
            self.assertEqual(str(captured.exception), "probe rejected")
            self.assertNotIn(CANARY, str(captured.exception))
        finally:
            c.os.environ.clear()
            c.os.environ.update(previous)

    def test_valid_protocol_reaps_after_eof_and_finishes_before_publication(self):
        facts = self.run_case("valid")
        self.assertTrue(c.case_passes(facts, require_native_provenance=False))
        self.assertFalse(c.case_passes(facts))  # Fake I/O never claims native provenance.
        self.assertEqual(facts["stream"]["diagnostic"]["count"], 13)
        self.assertTrue(facts["stream"]["stdout_eof"])
        self.assertTrue(facts["stream"]["stderr_eof"])
        self.assertTrue(facts["stream"]["child_reaped"])

    def test_malformed_canary_is_closed_failure_and_never_archived(self):
        self.backend.private_output = CANARY.encode()+b"\n"
        facts = self.run_case("malformed")
        self.assertTrue(c.case_passes(facts, require_native_provenance=False))
        self.assertEqual(facts["stream"]["diagnostic"]["marker_ids"], ())
        self.assertTrue(c.empty_metadata(self.guardian))

    def test_valid_markers_followed_by_canary_never_complete(self):
        self.backend.private_output = GOOD+CANARY.encode()+b"\n"
        facts = self.run_case("trailing")
        self.assertTrue(c.case_passes(facts, require_native_provenance=False))
        self.assertEqual(facts["stream"]["diagnostic"]["count"], 0)

    def test_cancel_is_latched_after_first_read_while_child_live(self):
        self.backend.private_code = None
        facts = self.run_case("cancel-writer")
        self.assertTrue(c.case_passes(facts, require_native_provenance=False))
        self.assertTrue(facts["firstNonemptyReadWhileLive"])
        self.assertTrue(facts["cancellationLatchedAfterRead"])

    def test_both_eof_while_alive_cannot_complete_without_reap(self):
        self.backend.private_output = b""
        self.backend.private_code = None
        facts = self.run_case("eof-alive")
        self.assertTrue(c.case_passes(facts, require_native_provenance=False))
        self.assertTrue(facts["bothEofWhileChildLive"])
        self.assertFalse(facts["stream"]["child_reaped"])
        self.assertTrue(self.guardian.children[-1].reaped)  # Actual fake stop/reap follows handoff.

    def test_standalone_public_database_and_guc_gate_need_no_auth_schema(self):
        order = []
        def admit_data(g):
            self.assertIsNone(g.postgres)
            self.assertEqual(g.children[-1].name, "initdb")
            self.assertTrue(g.children[-1].reaped)
            order.append("data-admission")
        facts = self.run_case("private-guc", admit_data=admit_data)
        self.assertEqual(order, ["data-admission"])
        self.assertTrue(c.case_passes(facts, require_native_provenance=False))
        self.assertFalse(c.case_passes(facts))  # Fake GUC/DEVNULL cannot prove native routing.
        public = [call for call in self.backend.calls if call[0] == "public"]
        self.assertEqual([Path(call[1][-1]).name for call in public],
                         ["create-probe-database.sql", "verify-private-policy.sql"])
        self.assertFalse(any("positive-auth.sql" in call[1] for call in self.backend.calls))
        self.assertTrue(facts["normalPostmasterExit"])
        self.assertTrue(facts["statusAbsent"])

    def test_unknown_node_mode_and_arbitrary_argv_rejected_before_factory(self):
        self.guardian.verify_source_admission(c.PROJECT)
        self.guardian.install()
        for action in (lambda: self.guardian.launch_probe("unknown", 1.0),
                       lambda: self.guardian._launch("node", ("-e", CANARY)),
                       lambda: self.guardian.run_node(CANARY)):
            with self.assertRaises(p.PrivateFailure):
                action()
        self.assertEqual(self.backend.calls, [])

    def test_emitter_replacement_rejected_before_factory(self):
        (self.work/"emitter.cjs").write_text(CANARY)
        facts = self.run_case("valid")
        self.assertFalse(c.case_passes(facts, require_native_provenance=False))
        self.assertEqual(self.backend.calls, [])

    def test_public_database_setup_replacement_never_reaches_psql(self):
        (self.work/"create-probe-database.sql").write_text(CANARY)
        facts = self.run_case("private-guc")
        self.assertFalse(c.case_passes(facts))
        self.assertFalse(any(call[0] == "public" for call in self.backend.calls))

    def test_read_failure_handoff_is_sanitized_and_cleanup_precedes_summary(self):
        class Failed(fixture.FakeIO):
            def read(self, stream):
                raise RuntimeError(CANARY)
        self.guardian._probe_io_builder = lambda record: Failed(record, self.clock)
        original = c.closed_case_summary
        called = []
        def summary(*args):
            self.assertTrue(self.guardian._emergency_sink.closed)
            self.assertTrue(all(record.reaped for record in self.guardian.children))
            called.append(True)
            return original(*args)
        c.closed_case_summary = summary
        try:
            facts = self.run_case("valid")
        finally:
            c.closed_case_summary = original
        self.assertEqual(called, [True])
        self.assertEqual(facts["stream"]["outcome"], "io-failure")

    def test_summary_failure_cannot_echo_exception_or_skip_cleanup(self):
        original = c.closed_case_summary
        def failed(*args):
            raise RuntimeError(CANARY)
        c.closed_case_summary = failed
        try:
            facts = self.run_case("valid")
        finally:
            c.closed_case_summary = original
        self.assertFalse(facts["bodyComplete"])
        self.assertTrue(facts["cleanupProven"])

    def test_probe_cannot_be_relaunched(self):
        self.guardian.verify_source_admission(c.PROJECT)
        self.guardian.install()
        self.guardian.launch_probe("valid", 1.0)
        calls = len(self.backend.calls)
        with self.assertRaises(p.PrivateFailure):
            self.guardian.launch_probe("valid", 1.0)
        self.assertEqual(len(self.backend.calls), calls)

    def test_constructor_failure_always_calls_finish_owner_without_echo(self):
        work = self.root/"constructor-failure"
        work.mkdir(mode=0o700)
        calls = []
        original = p.PrivateGuardian.finish_owner
        def finish(owner):
            calls.append(True)
            return original(owner)
        p.PrivateGuardian.finish_owner = finish
        try:
            with self.assertRaises(RuntimeError) as captured:
                c.construct_owner(Probe, work, self.tools, started=0.0, clock=self.clock,
                                  backend=self.backend, database="unknown")
            self.assertEqual(str(captured.exception), "probe rejected")
            self.assertIsNone(captured.exception.__context__)
        finally:
            p.PrivateGuardian.finish_owner = original
        self.assertEqual(calls, [True])
        self.assertEqual(self.backend.calls, [])

    def test_clock_never_offsets_or_renews_original_time(self):
        original = c.time.monotonic
        c.time.monotonic = lambda: 1000.0
        try:
            clock = c.ProbeClock(100.0, 200.0, "valid")
            clock.guardian = self.guardian
            self.assertEqual(clock(), 1000.0)
            self.assertEqual(clock.work_end, 205.0)
            self.assertTrue(clock.work_expired and clock.wall_expired and clock.aggregate_expired)
            self.assertTrue(self.guardian.cancel.requested)
            self.assertEqual((self.guardian.qualification_deadline, self.guardian.emergency_deadline), (900, 960))
        finally:
            c.time.monotonic = original

    def test_resource_scan_failure_latches_cancel_without_exception_text(self):
        old_time, old_scan = c.time.monotonic, c.allocated_bytes
        c.time.monotonic = lambda: 1.0
        def scan(paths):
            raise RuntimeError(CANARY)
        c.allocated_bytes = scan
        try:
            clock = c.ProbeClock(0.0, 0.0, "valid", [self.work])
            clock.guardian = self.guardian
            self.assertEqual(clock(), 1.0)
            self.assertTrue(clock.resource_exceeded)
            self.assertTrue(self.guardian.cancel.requested)
        finally:
            c.time.monotonic, c.allocated_bytes = old_time, old_scan

    def test_guc_failure_after_database_creation_cannot_pass(self):
        def on_spawn(route, handle):
            if route == "public" and Path(self.backend.calls[-1][1][-1]).name == "verify-private-policy.sql":
                handle.code = 3
        self.backend.on_spawn = on_spawn
        facts = self.run_case("private-guc")
        self.assertFalse(c.case_passes(facts, require_native_provenance=False))
        self.assertFalse(facts["effectiveGucGate"])
        self.assertTrue(facts["cleanupProven"])

    def test_public_metadata_binds_owned_marker_times_and_retained_pid(self):
        facts = self.run_case("valid")
        metadata = facts["publicMetadata"]
        self.assertTrue(metadata["recordedAfterFinishOwner"])
        work = metadata["work"]
        self.assertEqual(work["path"], str(self.work))
        self.assertEqual(work["runId"], self.guardian.run_id)
        self.assertEqual(work["markerSha256"], c.digest(self.guardian.marker_path))
        self.assertEqual(work["identity"]["inode"], self.work.lstat().st_ino)
        self.assertTrue(work["postmasterPidAbsent"] and work["socketEmpty"])
        timing = metadata["timing"]
        self.assertEqual(timing["clockKind"], "fake-injected")
        self.assertEqual((timing["originalStarted"], timing["qualificationDeadline"], timing["emergencyDeadline"]), (0, 900, 960))
        self.assertEqual(timing["caseElapsedSeconds"], timing["caseEnded"]-timing["caseStarted"])
        operation, = metadata["operations"]
        self.assertEqual(operation["operation"], "node.valid")
        self.assertEqual(operation["processRole"], "node-emitter")
        self.assertEqual(operation["retainedPid"], self.guardian.children[0].handle.pid)
        self.assertEqual(operation["exitCode"], 0)
        self.assertTrue(operation["reaped"] and operation["groupQuiet"])
        self.assertNotIn("argv", operation)

    def test_public_pg_metadata_preserves_status_stop_and_reap_sequence(self):
        metadata = self.run_case("private-guc")["publicMetadata"]
        self.assertEqual([(r["operation"], r["exitCode"]) for r in metadata["operations"]],
                         [("initdb", 0), ("postgres.foreground", 0), ("pg_ctl.status", 0),
                          ("psql.create-probe-database", 0), ("psql.verify-private-policy", 0),
                          ("pg_ctl.stop", 0), ("pg_ctl.status", 3)])
        self.assertTrue(all(type(r["retainedPid"]) is int and r["retainedPid"] > 0
                            and r["reaped"] and r["groupQuiet"] for r in metadata["operations"]))

    def reject_metadata_mutation(self, mutation, case="valid"):
        original = c.closed_case_summary
        def summary(*args):
            self.assertTrue(self.guardian._emergency_sink.closed)
            mutation()
            return original(*args)
        c.closed_case_summary = summary
        try:
            facts = self.run_case(case)
        finally:
            c.closed_case_summary = original
        self.assertEqual(facts["metadataStatus"], "rejected")
        self.assertFalse(c.case_passes(facts, require_native_provenance=False))

    def test_replaced_marker_identity_rejected_after_cleanup(self):
        def mutation():
            path = self.guardian.marker_path
            data = path.read_bytes()
            path.rename(self.work/"old-marker")
            path.write_bytes(data)
            path.chmod(0o600)
        self.reject_metadata_mutation(mutation)

    def test_injected_marker_runid_rejected_without_echo(self):
        self.reject_metadata_mutation(lambda: setattr(self.guardian, "run_id", CANARY))

    def test_reappeared_pid_and_socket_rejected_after_cleanup(self):
        self.reject_metadata_mutation(lambda: (self.work/"socket/reappeared").write_text(CANARY))

    def test_reappeared_postmaster_pid_rejected_after_cleanup(self):
        self.reject_metadata_mutation(lambda: (self.work/"data/postmaster.pid").write_text(CANARY), "private-guc")

    def test_nonfinite_and_hostile_metadata_never_inspected_or_echoed(self):
        class Hostile:
            def __repr__(self):
                raise AssertionError(CANARY)
            __str__ = __repr__
            __bool__ = __repr__
        for value in (True, float("nan"), float("inf"), Hostile()):
            with self.assertRaisesRegex(RuntimeError, "^probe metadata rejected$"):
                c.finite_time(value)
            with self.assertRaisesRegex(RuntimeError, "^probe metadata rejected$"):
                c.bounded_integer(value)

    def test_bool_pid_is_rejected_after_owned_reap(self):
        self.reject_metadata_mutation(lambda: setattr(self.guardian.children[0].handle, "pid", True))

    def test_bool_exit_is_rejected_after_owned_reap(self):
        self.reject_metadata_mutation(lambda: setattr(self.guardian.children[0], "exit_code", True))

    def test_unknown_operation_cannot_persist_argv(self):
        self.reject_metadata_mutation(lambda: setattr(self.guardian.children[0], "argv", (CANARY,)))

    def test_changed_original_deadline_cannot_be_published(self):
        self.reject_metadata_mutation(lambda: setattr(self.guardian, "qualification_deadline", 901))

    def test_metadata_requires_actual_finish_owner_boundary(self):
        with self.assertRaisesRegex(RuntimeError, "^probe metadata rejected$"):
            c.post_cleanup_metadata(self.guardian, "valid")

    def test_explicit_uid_bound_framework_encoding_marker_is_accepted(self):
        previous = c.os.environ
        c.os.environ = {"HOME":str(self.root),"TMPDIR":str(self.root),"PATH":"/usr/bin:/bin",
                        "__CF_USER_TEXT_ENCODING":f"0x{c.os.getuid():X}:0x0:0x0"}
        try:
            c.private_parent_environment()
            self.assertEqual(self.backend.calls, [])
            self.assertNotIn("__CF_USER_TEXT_ENCODING",self.guardian.env)
        finally:
            c.os.environ = previous

    def test_framework_encoding_marker_rejects_every_noncanonical_form(self):
        previous = c.os.environ
        marker = f"0x{c.os.getuid():X}:0x0:0x0"
        class Hostile:
            def __repr__(self):raise AssertionError(CANARY)
            __str__ = __repr__
            __bool__ = __repr__
            def __eq__(self, other):raise AssertionError(CANARY)
        bad = (f"0x{c.os.getuid()+1:X}:0x0:0x0", marker+"\n", " "+marker, marker+":0x0",
               marker.replace(":0x0:0x0",":0x1:0x0"),marker.replace(":0x0:0x0",":0x0:0x1"),
               marker.replace("0x","0X"),marker.replace("0x","0х"),"",CANARY,
               f"0x0{c.os.getuid():X}:0x0:0x0",True,1,None,Hostile())
        try:
            for value in bad:
                c.os.environ = {"HOME":str(self.root),"TMPDIR":str(self.root),"PATH":"/usr/bin:/bin",
                                "__CF_USER_TEXT_ENCODING":value}
                with self.assertRaisesRegex(RuntimeError,"^probe rejected$") as captured:
                    c.private_parent_environment()
                self.assertNotIn(CANARY,str(captured.exception))
            self.assertEqual(self.backend.calls,[])
        finally:
            c.os.environ = previous

    def test_framework_marker_does_not_admit_unknown_environment_keys(self):
        previous=c.os.environ
        c.os.environ={"HOME":str(self.root),"TMPDIR":str(self.root),"PATH":"/usr/bin:/bin",
                      "__CF_USER_TEXT_ENCODING":f"0x{c.os.getuid():X}:0x0:0x0","UNKNOWN_FRAMEWORK_KEY":CANARY}
        try:
            with self.assertRaisesRegex(RuntimeError,"^probe rejected$"):
                c.private_parent_environment()
            self.assertEqual(self.backend.calls,[])
        finally:
            c.os.environ=previous

    def test_emitter_and_dependency_source_pins(self):
        self.assertEqual(c.digest(ROOT/"emitter.cjs"), c.EMITTER_SHA256)
        self.assertEqual(c.digest(ROOT/"create-probe-database.sql"), c.DATABASE_SQL_SHA256)
        self.assertEqual(c.digest(ROOT/"closed_dependencies/private_guardian_staging/private_guardian.py"), c.ADAPTER_SHA256)
        self.assertEqual(c.digest(ROOT/"tools.json"), c.TOOLS_SHA256)
        self.assertEqual(c.digest(ROOT/"closed_dependencies/resource_policy.py"), c.POLICY_SHA256)
        text = (ROOT/"emitter.cjs").read_text()
        markers = re.findall(r"\['([a-z-]+)', ([0-9]+)\]", text)
        self.assertEqual(markers, list(zip(p.streams._diagnostics.MARKERS,
                                          map(str, p.streams._diagnostics.MARKER_LINES))))
        self.assertEqual(len(json.loads((ROOT/"tools.json").read_text())["postgresFiles"]), 47)
        self.assertEqual(AUDIT, {"children": 0, "network": 0, "native_pipe": 0})


if __name__ == "__main__":
    unittest.main()
