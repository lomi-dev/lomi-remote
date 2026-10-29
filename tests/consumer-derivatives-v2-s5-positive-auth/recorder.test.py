"""Pure in-memory recorder tests. Never launch a process or execute SQL."""

import importlib.util
import json
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("positive_auth_recorder_test", HERE / "recorder.py")
recorder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recorder)
diagnostics = recorder._diagnostics
SQL_PATH = HERE / "positive-auth.sql"
PLAN_PATH = HERE / "case-plan.json"


def markers_bytes(count=13):
    return b"".join(diagnostics.notice_line(index) for index in range(count))


def fixed_error(stage, line, count, state="28000"):
    prefix = markers_bytes(count)
    return (prefix + (f"psql:positive-auth.sql:{line}: ERROR:  "
                      f"positive-auth:{stage}:{state}\n").encode("ascii"))


class PositiveAuthRecorderTests(unittest.TestCase):
    def test_real_source_marker_order_and_error_envelopes_match_protocol(self):
        sql = SQL_PATH.read_text(encoding="utf-8")
        marker_ids = tuple(
            match.group(1) for match in re.finditer(
                r"RAISE NOTICE 'positive-auth:([a-z-]+):PASS';", sql
            )
        )
        self.assertEqual(marker_ids, diagnostics.MARKERS)
        self.assertEqual(
            tuple("positive-auth:" + marker + ":PASS" for marker in marker_ids),
            recorder.ALLOWED_MARKERS,
        )
        self.assertEqual(len(marker_ids), len(recorder.ALLOWED_MARKERS))

        envelope_stages = tuple(
            match.group(1) for match in re.finditer(
                r"MESSAGE='positive-auth:([a-z-]+):' \|\| code", sql
            )
        )
        expected_errors = tuple(
            stage for stage, _ in diagnostics.ERROR_STAGES
            if stage not in {"initial-identity", "rollback"}
        )
        self.assertEqual(envelope_stages, expected_errors)
        block_by_stage = {
            "setup-runtime": "setup", "principal-runtime": "principal",
            "scalar-group": "scalar", "roots-group": "roots",
            "typed-group": "typed",
        }
        for stage, line in diagnostics.ERROR_STAGES:
            if stage == "rollback":
                rollback = re.search(r"END \$rolled_back\$;", sql)
                self.assertIsNotNone(rollback)
                self.assertEqual(sql.count("\n", 0, rollback.start()) + 1, line)
                continue
            block = block_by_stage.get(stage)
            if block is None:
                close = re.search(r"END \$initial_identity\$;", sql)
            else:
                close = re.search(rf"END \${block}\$;", sql)
            self.assertIsNotNone(close)
            self.assertEqual(sql.count("\n", 0, close.start()) + 1, line)
        initial_match = re.search(r"END \$initial_identity\$;", sql)
        self.assertIsNotNone(initial_match)
        initial_line = sql.count("\n", 0, initial_match.start()) + 1
        self.assertEqual(
            ("initial-identity", initial_line), diagnostics.ERROR_STAGES[0]
        )
        self.assertEqual(
            frozenset(stage for stage, _ in diagnostics.ERROR_STAGES),
            recorder.ALLOWED_STAGES,
        )

    def test_real_case_plan_matches_declared_calls_and_failure_contract(self):
        plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        cases = plan["cases"]
        case_ids = tuple(case["id"] for case in cases)
        sql = SQL_PATH.read_text(encoding="utf-8")
        # Setup and rollback are source protocol steps; the remaining markers
        # map one-to-one to the plan's eleven calls.
        source_call_ids = tuple(
            marker.removeprefix("positive-auth:").removesuffix(":PASS")
            for marker in recorder.ALLOWED_MARKERS
            if marker not in {
                "positive-auth:setup-runtime:PASS",
                "positive-auth:rollback:PASS",
            }
        )
        self.assertEqual(case_ids, source_call_ids)
        self.assertEqual(len(cases), 11)
        self.assertTrue(all(case["status"] == "NOT_RUN" for case in cases))

        for case in cases:
            with self.subTest(case=case["id"]):
                if case["id"].endswith("wronghash"):
                    self.assertEqual(case["expected"], {
                        "message": "actual credential required",
                        "sqlstate": "28000",
                    })
                    self.assertIn(
                        "EXCEPTION WHEN SQLSTATE '28000'", sql
                    )
                    self.assertIn(
                        "diagnostic IS DISTINCT FROM 'actual credential required'",
                        sql,
                    )
                else:
                    self.assertIs(
                        case["expected"]["successfulActualInvocation"], True
                    )
                self.assertIn("function", case)
                self.assertIn("role", case)

    def test_exact_thirteen_markers_are_the_only_success_evidence(self):
        result = recorder.record(b"", markers_bytes(), 0, cleanup_completed=True)
        evidence = result.evidence()
        self.assertEqual(result.status, "complete")
        self.assertEqual(result.markers, recorder.ALLOWED_MARKERS)
        self.assertEqual(result.stage, "complete")
        self.assertIsNone(result.sqlstate)
        self.assertIsNone(result.failure)
        self.assertEqual(result.exit_code, 0)
        self.assertIs(result.cleanup_completed, True)
        self.assertEqual(tuple(evidence["markers"]), recorder.ALLOWED_MARKERS)

    def test_each_fixed_error_stage_and_canonical_state(self):
        for (stage, line), counts in zip(diagnostics.ERROR_STAGES,
                                         diagnostics.ERROR_COUNTS):
            for count in counts:
                with self.subTest(stage=stage, count=count):
                    result = recorder.record(b"", fixed_error(stage, line, count), 3)
                    self.assertEqual(result.status, "fixed-error")
                    self.assertEqual(result.stage, stage)
                    self.assertEqual(result.sqlstate, "28000")
                    self.assertEqual(result.failure, f"positive-auth:{stage}:28000")
                    self.assertEqual(result.markers, recorder.ALLOWED_MARKERS[:count])
                    self.assertEqual(result.exit_code, 1)

    def test_unknown_and_malformed_output_collapses_to_generic(self):
        canary = b"raw-secret-canary"
        good = markers_bytes()
        bad = (
            (canary, good, 0),
            (b"", good + canary, 0),
            (b"", good[:-1], 0),
            (b"", good + diagnostics.notice_line(12), 0),
            (b"", diagnostics.notice_line(1), 0),
            (b"", good.replace(b":59:", b":60:"), 0),
            (b"", b"\xff", 1),
            (b"", good, 3),
        )
        for stdout, stderr, code in bad:
            with self.subTest(stderr_len=len(stderr), code=code):
                result = recorder.record(stdout, stderr, code)
                self.assertEqual(result.status, "generic-failure")
                self.assertEqual(result.stage, recorder.GENERIC_STAGE)
                self.assertIsNone(result.sqlstate)
                self.assertIsNone(result.failure)
                self.assertEqual(result.markers, ())
                self.assertNotIn(canary.decode(), repr(result.evidence()))

    def test_fixed_error_rejects_trailing_diagnostics_and_invalid_states(self):
        line = fixed_error("setup-runtime", 59, 0)
        for suffix in (b"DETAIL: raw-secret-canary\n", b"CONTEXT: canary\n",
                       b"\n", b"NOTICE: extra\n"):
            result = recorder.record(b"", line + suffix, 3)
            self.assertEqual(result.status, "generic-failure")
            self.assertNotIn(b"canary", repr(result.evidence()).encode())
        for state in ("00000", "28a00", "ABCDE1", "AB 00", "?????"):
            with self.subTest(state=state):
                raw = fixed_error("setup-runtime", 59, 0, state)
                result = recorder.record(b"", raw, 3)
                self.assertEqual(result.status, "generic-failure")

    def test_oversized_input_and_untrusted_argument_types_are_generic(self):
        oversized = b"x" * 20_000
        for args in ((b"", oversized, 3), ("secret", b"", 0),
                     (b"", b"", True), (b"", b"", 0.0)):
            with self.subTest(args_type=type(args[0]).__name__):
                result = recorder.record(*args)
                self.assertEqual(result.status, "generic-failure")
                self.assertIsNone(result.sqlstate)
                self.assertIsNone(result.failure)

    def test_deadline_and_cleanup_facts_are_literal_and_bounded(self):
        result = recorder.record(b"", markers_bytes(), 0, deadline=True,
                                 cleanup_completed=False)
        self.assertEqual(result.status, "generic-failure")
        self.assertTrue(result.deadline)
        self.assertFalse(result.cleanup_completed)
        result = recorder.record(b"", markers_bytes(), 0, cleanup_completed=True)
        self.assertTrue(result.cleanup_completed)
        result = recorder.record(b"", markers_bytes(), 0, cleanup_completed=1)
        self.assertEqual(result.status, "generic-failure")
        self.assertFalse(result.cleanup_completed)

    def test_no_output_or_exception_is_retained_or_rendered(self):
        secret = b"token=raw-secret-canary"
        result = recorder.record(secret, secret, 3)
        representation = repr(result) + repr(result.evidence())
        self.assertNotIn("raw-secret-canary", representation)
        self.assertEqual(set(result.evidence()), {
            "status", "markers", "stage", "sqlstate", "failure", "exit_code",
            "deadline", "cleanup_completed",
        })


if __name__ == "__main__":
    unittest.main()
