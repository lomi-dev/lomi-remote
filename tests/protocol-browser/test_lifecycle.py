"""Real Chromium cancellation and fresh-evidence lifecycle regressions."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tests/protocol-browser/run.py"


class BrowserLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lomi-protocol-browser-")
        self.directory = Path(self.temporary.name)
        self.evidence = self.directory / "evidence.json"
        self.evidence.write_text(json.dumps({"attemptId": "previous-passed", "passed": True, "complete": True}))

    def tearDown(self):
        self.temporary.cleanup()

    def report(self):
        return json.loads(self.evidence.read_text())

    def assert_gone(self, owned):
        deadline = time.monotonic() + 5
        while True:
            active = []
            for key in ("nodePid", "browserPid"):
                if key not in owned:
                    continue
                state = subprocess.run(["/bin/ps", "-p", str(owned[key]), "-o", "stat="],
                                       capture_output=True, text=True, timeout=2).stdout.strip()
                if state and not state.startswith("Z"):
                    active.append(key)
            for key in ("serverPort", "browserServerPort"):
                if key not in owned:
                    continue
                with socket.socket() as connection:
                    connection.settimeout(0.1)
                    if connection.connect_ex(("127.0.0.1", owned[key])) == 0:
                        active.append(key)
            if not active or time.monotonic() >= deadline:
                self.assertEqual(active, [], "owned processes/listeners survived cancellation")
                return
            time.sleep(0.05)

    def interrupt_ready_browser(self, signum):
        child = subprocess.Popen([sys.executable, str(RUNNER), "--evidence", str(self.evidence),
                                  "--hold-after-ready"], cwd=ROOT, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, start_new_session=True)
        owned = {}
        try:
            deadline = time.monotonic() + 35
            while child.poll() is None and time.monotonic() < deadline:
                report = self.report()
                if report.get("phase") == "browser-ready":
                    owned = report["owned"]
                    break
                time.sleep(0.025)
            self.assertTrue(owned, "fixture did not reach a real owned Chromium/listener")
            self.assertNotEqual(report["attemptId"], "previous-passed")
            self.assertFalse(report["passed"])
            self.assertFalse(report["complete"])
            os.kill(child.pid, signum)
            stdout, stderr = child.communicate(timeout=20)
            self.assertNotEqual(child.returncode, 0)
            self.assertNotIn("Traceback", stderr)
            self.assertNotIn("uncaught", stderr.lower())
            final = self.report()
            self.assertEqual(final["attemptId"], report["attemptId"])
            self.assertEqual(final["phase"], "interrupted")
            self.assertFalse(final["passed"])
            self.assertFalse(final["complete"])
            self.assertTrue(final["wrapper"]["childReaped"])
            self.assertTrue(final["wrapper"]["interruptionObserved"])
            self.assertTrue(final["cleanup"]["browserClosed"])
            self.assertTrue(final["cleanup"]["serverClosed"])
            self.assert_gone(owned)
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.communicate(timeout=3)

    def test_sigint_invalidates_prior_pass_and_reaps_real_browser(self):
        self.interrupt_ready_browser(signal.SIGINT)

    def test_sigterm_invalidates_prior_pass_and_reaps_real_browser(self):
        self.interrupt_ready_browser(signal.SIGTERM)

    def test_dynamic_import_failure_cannot_preserve_prior_pass(self):
        # Copy only the harness so its relative Playwright import genuinely fails.
        script = self.directory / "browser.mjs"
        script.write_bytes((ROOT / "tests/protocol-browser/browser.mjs").read_bytes())
        environment = dict(os.environ, LOMI_PROTOCOL_BROWSER_EVIDENCE=str(self.evidence))
        result = subprocess.run(["node", str(script)], cwd=ROOT, env=environment,
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        report = self.report()
        self.assertNotEqual(report["attemptId"], "previous-passed")
        self.assertFalse(report["passed"])
        self.assertFalse(report["complete"])
        self.assertEqual(report["phase"], "failed")
        self.assertTrue(report["cleanup"]["browserClosed"])
        self.assertTrue(report["cleanup"]["serverClosed"])
        self.assertNotIn("uncaught", result.stderr.lower())

    def test_forced_deadline_cannot_preserve_prior_pass(self):
        result = subprocess.run([sys.executable, str(RUNNER), "--evidence", str(self.evidence),
                                 "--timeout", "0.001"], cwd=ROOT, capture_output=True,
                                text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        report = self.report()
        self.assertNotEqual(report["attemptId"], "previous-passed")
        self.assertFalse(report["passed"])
        self.assertFalse(report["complete"])
        self.assertEqual(report["phase"], "timed-out")
        self.assertTrue(report["wrapper"]["childReaped"])
        self.assert_gone(report.get("owned", {}))


if __name__ == "__main__":
    unittest.main()
