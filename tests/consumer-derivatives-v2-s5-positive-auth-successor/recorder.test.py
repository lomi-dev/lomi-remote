"""Pure fake integration tests; no process, SQL, or PostgreSQL calls."""
import importlib.util
import hashlib
import math
import sys
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("s5_successor_adapter", HERE / "adapter.py")
adapter = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = adapter
spec.loader.exec_module(adapter)
d = adapter.record.__globals__["_diagnostics"]

def capture(data, size=512): return adapter.PipeCapture(tuple(data[i:i+size] for i in range(0,len(data),size)), True)
def facts(**overrides):
    values=dict(exit_code=0,normal_exit=True,reaped=True,process_group_quiet=True,cleanup_completed=True,ownership_complete=True)
    values.update(overrides); return adapter.ChildFacts(**values)
def invoke(out=None, err=None, child=None, now=None, cancelled=False):
    tick=iter(now or [10.0]*100)
    return adapter.consume(out or capture(b""), err or capture(b""), child or facts(), start_time=10.0, deadline=20.0, now=lambda: next(tick), cancelled=cancelled)
def markers(): return b"".join(d.notice_line(i) for i in range(13))
def fixed_error(): return b"psql:positive-auth.sql:59: ERROR:  positive-auth:setup-runtime:28000\n"

class SuccessorIntegration(unittest.TestCase):
    def test_pinned_sql_and_case_plan_hashes(self):
        expected = {
            "positive-auth.sql": "1fe715e2245f05b372cb2dd8904d3dee08aeed893ae75f8f367a996df1c375c8",
            "case-plan.json": "c11a562d388fbe36016743b6b4b105e49ed447efeba3a2f852033175195fbea7",
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                self.assertEqual(hashlib.sha256((HERE / filename).read_bytes()).hexdigest(), digest)

    def test_thirteen_marker_success_requires_all_ownership_and_cleanup_facts(self):
        e=invoke(err=capture(markers())); self.assertEqual(e.status,"complete"); self.assertEqual(e.markers,adapter.record.__globals__["ALLOWED_MARKERS"])
    def test_fixed_sqlstate_error_is_generic_at_integration_boundary(self):
        e=invoke(err=capture(fixed_error()),child=facts(exit_code=3)); self.assertEqual(e.status,"generic-failure")
    def test_raw_secret_and_unknown_diagnostic_are_not_retained(self):
        secret=b"raw-secret-canary"; e=invoke(err=capture(secret)); self.assertEqual(e.status,"generic-failure"); self.assertNotIn(secret.decode(),repr(e.evidence()))
    def test_partial_eof_and_chunk_type_fault(self):
        for p in (adapter.PipeCapture((markers(),),False),adapter.PipeCapture(("secret",),True)):
            self.assertEqual(invoke(err=p).status,"generic-failure")
    def test_oversized_capture_and_chunk_fault(self):
        self.assertEqual(invoke(err=adapter.PipeCapture((b"x"*1025,),True)).status,"generic-failure")
        self.assertEqual(invoke(err=capture(b"x"*9000)).status,"generic-failure")
    def test_capture_chunk_container_and_count_are_bounded_before_iteration(self):
        self.assertEqual(invoke(err=adapter.PipeCapture([b""], True)).status, "generic-failure")
        self.assertEqual(invoke(err=adapter.PipeCapture((b"",) * (adapter.MAX_CHUNKS + 1), True)).status,
                         "generic-failure")
        class NeverIterate:
            def __iter__(self):
                raise AssertionError("must not iterate untrusted chunk source")
        self.assertEqual(invoke(err=adapter.PipeCapture(NeverIterate(), True)).status,
                         "generic-failure")

    def test_nonzero_after_markers_is_generic(self):
        self.assertEqual(invoke(err=capture(markers()),child=facts(exit_code=1)).status,"generic-failure")
    def test_deadline_and_cancel_are_generic(self):
        self.assertEqual(invoke(err=capture(markers()),now=[10,21]).status,"generic-failure")
        self.assertEqual(invoke(err=capture(markers()),cancelled=True).status,"generic-failure")
    def test_reap_quiet_cleanup_or_ownership_failure_is_generic(self):
        for k in ("reaped","process_group_quiet","cleanup_completed","ownership_complete"):
            self.assertEqual(invoke(err=capture(markers()),child=facts(**{k:False})).status,"generic-failure")
    def test_non_finite_start_deadline_and_clock_samples_are_generic(self):
        for value in (math.nan, math.inf, -math.inf, 10**10000):
            with self.subTest(field="start", value=value):
                self.assertEqual(adapter.consume(capture(b""), capture(markers()), facts(),
                    start_time=value, deadline=20.0, now=lambda: 10.0).status, "generic-failure")
            with self.subTest(field="deadline", value=value):
                self.assertEqual(adapter.consume(capture(b""), capture(markers()), facts(),
                    start_time=10.0, deadline=value, now=lambda: 10.0).status, "generic-failure")
            with self.subTest(field="now", value=value):
                self.assertEqual(adapter.consume(capture(b""), capture(markers()), facts(),
                    start_time=10.0, deadline=20.0, now=lambda: value).status, "generic-failure")

    def test_clock_must_never_move_backward(self):
        samples = iter((10.0, 11.0, 10.5, 11.0))
        e = adapter.consume(capture(b""), capture(markers()), facts(), start_time=10.0,
                            deadline=20.0, now=lambda: next(samples))
        self.assertEqual(e.status, "generic-failure")

    def test_runtime_entrypoint_is_closed(self):
        self.assertEqual(adapter.run_runtime().status,"generic-failure")
        self.assertEqual(adapter.run_runtime("sql", process=True).status,"generic-failure")

if __name__ == "__main__": unittest.main()
