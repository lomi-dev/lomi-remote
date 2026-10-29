"""Pure fake-stream tests; audit hook rejects all child creation/network use."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import traceback
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("private_diagnostics", ROOT / "diagnostics.py")
d = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = d
spec.loader.exec_module(d)
AUDIT = {"child_attempts": 0, "network_attempts": 0}


def audit(event, args):
    if event in ("subprocess.Popen", "os.system", "os.posix_spawn", "os.fork", "os.forkpty", "pty.spawn", "os.exec", "os.spawn"):
        AUDIT["child_attempts"] += 1
        raise RuntimeError("child creation forbidden")
    if event.startswith("socket."):
        AUDIT["network_attempts"] += 1
        raise RuntimeError("network forbidden")


sys.addaudithook(audit)
CANARY = "PRIVATE_CANARY_TOKEN_HASH_IDENTIFIER_789"
GOOD = b"".join(d.notice_line(i) for i in range(13))


class ProtocolTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        if AUDIT != {"child_attempts": 0, "network_attempts": 0}:
            raise AssertionError("pure audit gate failed")

    def parse(self, data, *, stdout=b"", exit_code=0, **kwargs):
        parser = d.DiagnosticParser()
        parser.feed_stdout(stdout)
        parser.feed_stderr(data)
        return parser, parser.finish(exit_code, **kwargs)

    def assert_generic(self, data, **kwargs):
        parser, result = self.parse(data, **kwargs)
        self.assertEqual(result.stage, "generic-failure")
        self.assertEqual((result.state, result.marker_ids, result.count), (None, (), 0))
        self.assertFalse(parser._candidates)
        self.assertFalse(parser._state_chars)
        for rendered in (repr(parser), repr(result), json.dumps(result.evidence())):
            self.assertNotIn(CANARY, rendered)
        return result

    def test_complete_all_chunk_boundaries(self):
        for boundary in range(len(GOOD) + 1):
            parser = d.DiagnosticParser()
            parser.feed_stderr(GOOD[:boundary])
            parser.feed_stderr(GOOD[boundary:])
            result = parser.finish(0)
            self.assertEqual((result.stage, result.marker_ids, result.count), ("complete", d.MARKERS, 13))

    def test_one_byte_chunks(self):
        parser = d.DiagnosticParser()
        for byte in GOOD:
            parser.feed_stderr(bytes((byte,)))
        self.assertEqual(parser.finish(0).stage, "complete")

    def test_exact_errors(self):
        counts = (0, 0, 1, 4, 8, 11, 12)
        for (stage, line), count in zip(d.ERROR_STAGES, counts):
            data = b"".join(d.notice_line(i) for i in range(count))
            error = f"psql:positive-auth.sql:{line}: ERROR:  positive-auth:{stage}:28000\n".encode()
            for boundary in range(len(error) + 1):
                parser = d.DiagnosticParser()
                parser.feed_stderr(data + error[:boundary])
                parser.feed_stderr(error[boundary:])
                result = parser.finish(3)
                self.assertEqual((result.stage, result.state, result.count, result.exit), (stage, "28000", count, 1))

    def test_injected_secret_every_channel_and_diagnostic(self):
        for label in ("MESSAGE", "DETAIL", "HINT", "CONTEXT", "QUERY", "LOCATION", "row"):
            data = f"{label}: {CANARY}\n".encode()
            for prefix in (b"", d.notice_line(0), GOOD):
                self.assert_generic(prefix + data)
                self.assert_generic(prefix, stdout=data)
        self.assert_generic(GOOD, stdout=CANARY.encode())

    def test_missing_duplicate_order(self):
        self.assert_generic(b"")
        self.assert_generic(GOOD[:-1])
        self.assert_generic(b"".join(d.notice_line(i) for i in range(12)))
        self.assert_generic(d.notice_line(0) * 2)
        self.assert_generic(d.notice_line(1) + GOOD)
        self.assert_generic(GOOD + d.notice_line(12))

    def test_invalid_utf8_and_controls(self):
        for bad in (b"\xff", b"\xc0\xaf", b"\xe2\x82", b"\x00", b"\r\n"):
            self.assert_generic(GOOD + bad)
            self.assert_generic(bad + GOOD)

    def test_oversize_and_no_retained_raw_buffer(self):
        for stream in ("feed_stdout", "feed_stderr"):
            parser = d.DiagnosticParser()
            getattr(parser, stream)((CANARY * 100_000).encode())
            self.assertEqual(parser.finish(0).stage, "generic-failure")
            self.assertEqual(parser._totals, [1, 0] if stream == "feed_stdout" else [0, 1])
            self.assertFalse(parser._candidates)
            self.assertFalse(parser._state_chars)

    def test_independent_and_combined_caps(self):
        # Fault-inject counters to exercise each cap without relaxing the grammar.
        for totals, stream in (([d.STDOUT_LIMIT, 0], 0), ([0, d.STDERR_LIMIT], 1),
                               ([1, d.COMBINED_LIMIT - 1], 1)):
            parser = d.DiagnosticParser()
            parser._totals = totals
            (parser.feed_stdout if stream == 0 else parser.feed_stderr)(b"p")
            self.assertEqual(parser.finish(0).stage, "generic-failure")

    def test_exit_deadline_cancel_and_reuse(self):
        for exit_code in (1, -9, None, True, CANARY):
            self.assert_generic(GOOD, exit_code=exit_code)
        self.assert_generic(GOOD, deadline=True)
        self.assert_generic(GOOD, cancelled=True)
        parser, result = self.parse(GOOD)
        parser.feed_stderr(CANARY.encode())
        self.assertEqual(parser.finish(0).stage, "generic-failure")
        self.assertEqual(result.stage, "complete")

    def test_malformed_error_envelopes(self):
        base = b"psql:positive-auth.sql:59: ERROR:  positive-auth:setup-runtime:"
        for state in ("00000", "00ABC", "28a00", "2800", "280000", CANARY):
            self.assert_generic(base + state.encode() + b"\n", exit_code=3)
        self.assert_generic(base + b"28000\n", exit_code=0)
        self.assert_generic(base + b"28000\nDETAIL: " + CANARY.encode(), exit_code=3)
        self.assert_generic(GOOD + base + b"28000\n", exit_code=3)
        for changed in (GOOD.replace(b"positive-auth.sql", b"/private/positive-auth.sql"),
                        GOOD.replace(b":59:", b":60:"), GOOD.replace(b"NOTICE:  ", b"NOTICE: ")):
            self.assert_generic(changed)

    def test_flags_require_exact_bools_without_inspecting_values(self):
        class Hostile:
            def __repr__(self):
                raise AssertionError("must never inspect flag repr")

            def __str__(self):
                raise AssertionError("must never inspect flag str")

            def __bool__(self):
                raise AssertionError("must never inspect flag truthiness")

        for value in (0, 1, "true", None, CANARY, Hostile()):
            for flag in ("deadline", "cancelled"):
                result = self.assert_generic(GOOD, **{flag: value})
                self.assertIs(result.deadline, False)
            self.assert_generic(GOOD, deadline=value, cancelled=value)
        self.assertIs(self.assert_generic(GOOD, deadline=True).deadline, True)
        self.assertEqual(self.parse(GOOD, deadline=False, cancelled=False)[1].stage, "complete")

    def test_no_exception_echo_repr_or_artifact_leak(self):
        class Bad:
            def __repr__(self):
                raise AssertionError("must never inspect input")
        parser = d.DiagnosticParser()
        try:
            parser.feed_stderr(Bad())
            parser.feed_stdout(CANARY.encode())
            result = parser.finish(Bad())
        except Exception:
            self.fail("parser leaked exception: " + traceback.format_exc())
        artifact = json.dumps(result.evidence()) + repr(result) + repr(parser)
        self.assertNotIn(CANARY, artifact)
        self.assertNotIn("Bad", artifact)
        self.assertEqual(result.stage, "generic-failure")

    def test_frozen_fixture_and_protocol(self):
        fixture = ROOT.parent / "consumer-derivatives-v2-s5-positive-auth" / "positive-auth.sql"
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), d.FIXTURE_SHA256)
        plan = json.loads(fixture.with_name("case-plan.json").read_text())
        self.assertEqual(plan["fixedNoticeMarkers"], [f"positive-auth:{marker}:PASS" for marker in d.MARKERS])
        lines = fixture.read_text().splitlines()
        for number in set(d.MARKER_LINES) | {line for _, line in d.ERROR_STAGES}:
            self.assertTrue(lines[number - 1].startswith("END $"))

    def test_policy_and_zero_children(self):
        self.assertIn("--no-password", d.CLIENT_FLAGS)
        self.assertIn("-X", d.CLIENT_FLAGS)
        self.assertEqual(dict(d.SERVER_SETTINGS)["logging_collector"], "off")
        self.assertEqual(AUDIT, {"child_attempts": 0, "network_attempts": 0})


if __name__ == "__main__":
    unittest.main()
