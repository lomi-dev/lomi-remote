"""Real PG17 lifecycle regressions after a successful Better Auth suite.

Set AUTH_BINDING_TEST_PG_BIN to the explicit PostgreSQL 17 binary directory.
No inherited database or application configuration is used.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("binding_runner", ROOT / "tools/run_auth_binding_spike.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
PG = os.environ.get("AUTH_BINDING_TEST_PG_BIN")


@unittest.skipUnless(PG, "set explicit AUTH_BINDING_TEST_PG_BIN for actual PG17 fault tests")
class ShutdownEvidenceTests(unittest.TestCase):
    def exercise(self, interruption):
        real_run = runner.run_owned
        cluster = None
        with tempfile.TemporaryDirectory(prefix="binding-evidence-test-") as tmp:
            evidence = Path(tmp) / "evidence.json"
            def stop_fault(command, **kwargs):
                nonlocal cluster
                if Path(command[0]).name == "pg_ctl" and "stop" in command:
                    cluster = Path(command[command.index("-D") + 1])
                    if interruption:
                        raise KeyboardInterrupt()
                    raise subprocess.TimeoutExpired(command, 180)
                return real_run(command, **kwargs)
            try:
                with patch.object(sys, "argv", ["run_auth_binding_spike.py", "--pg-bin", PG, "--output", str(evidence)]), patch.object(runner, "run_owned", stop_fault), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(BaseException):
                        runner.main()
                report = json.loads(evidence.read_text())
                self.assertEqual(report["exitCode"], 1)
                self.assertFalse(report["shutdownAndCleanupCompleted"])
                suite = next(check for check in report["checks"] if check["step"] == "actual-handler-pg-bindings-and-concurrency")
                self.assertEqual(suite["exitCode"], 0)
                stop = next(check for check in report["checks"] if check["step"] == "stop-private-pg17")
                self.assertIsNone(stop["exitCode"])
                self.assertEqual(stop["outcome"], "interrupted" if interruption else "timeout")
                self.assertIsNotNone(cluster)
                self.assertTrue((cluster / "postmaster.pid").exists())
            finally:
                if cluster is not None:
                    # The runner deliberately preserves a cluster whose stop is
                    # uncertain. This test then explicitly reaps its own server.
                    result = subprocess.run([str(Path(PG) / "pg_ctl"), "-D", str(cluster), "-m", "immediate", "-w", "stop"], text=True, capture_output=True, timeout=30)
                    if result.returncode != 0 or (cluster / "postmaster.pid").exists():
                        raise RuntimeError("test cluster stop uncertain; files preserved")
                    shutil.rmtree(cluster.parent)

    def test_timeout_after_success_is_failed_and_preserved(self):
        self.exercise(False)

    def test_interrupt_after_success_is_failed_and_preserved(self):
        self.exercise(True)


if __name__ == "__main__":
    unittest.main()
