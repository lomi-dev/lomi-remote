"""No native state mutations: verify isolation and bounded protocol failures."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("macos_runner", ROOT / "tools/run_macos_service_fixture.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class IsolationTests(unittest.TestCase):
    def test_agent_only_owns_explicit_synthetic_program(self):
        agent = runner.launchagent("dev.lomi.e0.unique", "/fixture/bin", "/private/tmp/fixture")
        self.assertEqual(agent["ProgramArguments"], ["/fixture/bin", "owner", "/private/tmp/fixture"])
        self.assertFalse(agent["KeepAlive"])
        self.assertFalse(agent["RunAtLoad"])
        self.assertEqual(agent["Umask"], 0o077)
        self.assertNotIn("UserName", agent)
        self.assertEqual(agent["StandardOutPath"], "/dev/null")

    def test_reject_nonisolated_paths_and_labels(self):
        for args in [("other.label", "/binary", "/state"), ("dev.lomi.e0.x", "relative", "/state"), ("dev.lomi.e0.x", "/binary", "relative")]:
            with self.assertRaises(ValueError):
                runner.launchagent(*args)

    def test_reject_terminal_content_before_connect(self):
        with patch.object(runner.socket, "socket") as connect:
            with self.assertRaises(ValueError):
                runner.ipc(Path("/tmp/fixture"), "arbitrary terminal bytes")
            connect.assert_not_called()

    def test_wait_deadline_is_failure(self):
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            runner.wait_for(lambda budget: False, bool, timeout=0)

    def test_group_cleanup_ignores_only_zombies(self):
        with patch.object(runner, "process_rows", return_value={3: (1, 2, "Z"), 5: (1, 4, "S")}):
            self.assertTrue(runner.groups_gone({2}))
            self.assertFalse(runner.groups_gone({4}))


class LifecycleRegressionTests(unittest.TestCase):
    def setup_failure(self, failure, hash_values=None):
        import json
        import tempfile
        with tempfile.TemporaryDirectory(prefix="lomi-mac-test-", dir="/tmp") as temporary:
            base = Path(temporary)
            artifacts = base / "artifacts"
            artifacts.mkdir()
            previous = {"passed": True, "label": "old"}
            (artifacts / "evidence.json").write_text(json.dumps(previous))
            (artifacts / "old.json").write_text(json.dumps(previous))
            private = base / "private"
            private.mkdir()
            with patch.object(runner, "ARTIFACTS", artifacts), \
                 patch.object(runner.tempfile, "mkdtemp", return_value=str(private)), \
                 patch.object(runner.shutil, "copy2", side_effect=failure), \
                 patch.object(runner, "sha", side_effect=hash_values or ["same"] * 10), \
                 patch.object(runner, "run_owned") as native:
                self.assertEqual(runner.native_proof(), 1)
                native.assert_not_called()
            current = json.loads((artifacts / "evidence.json").read_text())
            self.assertFalse(current["passed"])
            self.assertNotEqual(current["label"], "old")
            self.assertFalse(current["resourcesPreserved"])
            self.assertTrue(current["privateDirectoryRemoved"])
            self.assertFalse(private.exists())
            self.assertEqual(json.loads((artifacts / "old.json").read_text()), previous)
            self.assertEqual(json.loads((artifacts / (current["label"] + ".json")).read_text()), current)
            return current

    def test_copy_failure_replaces_stale_success_and_cleans_directory(self):
        self.assertEqual(self.setup_failure(OSError("copy failed"))["failureClass"], "OSError")

    def test_hash_change_replaces_stale_success_and_cleans_directory(self):
        self.assertEqual(self.setup_failure(None, ["before", "after"])["failureId"], "fixture_binary_changed_during_copy")

    def test_setup_interrupt_replaces_stale_success_and_cleans_directory(self):
        self.assertEqual(self.setup_failure(KeyboardInterrupt())["failureClass"], "KeyboardInterrupt")


class DeadlineRegressionTests(unittest.TestCase):
    def exchange(self, delay, timeout):
        import socket
        import tempfile
        import threading
        import time
        with tempfile.TemporaryDirectory(prefix="lomi-ipc-", dir="/tmp") as temporary:
            state = Path(temporary)
            stop = threading.Event()
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(state / "fixture.sock"))
                server.listen(4)
                def serve():
                    with server.accept()[0] as connection:
                        connection.recv(128)
                        for byte in b'{"fixture":true}':
                            if stop.wait(delay):
                                break
                            try:
                                connection.sendall(bytes([byte]))
                            except (BrokenPipeError, ConnectionResetError):
                                break
                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                start = time.monotonic()
                try:
                    value = runner.wait_for(lambda budget: runner.ipc(state, "status", timeout=budget), bool, timeout=timeout)
                    return value, time.monotonic() - start
                finally:
                    stop.set()
                    worker.join(timeout=1)
                    self.assertFalse(worker.is_alive())

    def test_slow_drip_cannot_extend_absolute_ipc_deadline(self):
        import time
        start = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            self.exchange(delay=0.2, timeout=0.5)
        self.assertLess(time.monotonic() - start, 0.9)

    def test_prompt_complete_reply_succeeds_within_deadline(self):
        result, elapsed = self.exchange(delay=0, timeout=0.5)
        self.assertTrue(result["fixture"])
        self.assertLess(elapsed, 0.5)

    def test_wait_rejects_success_returned_after_deadline(self):
        import time
        def late_probe(budget):
            time.sleep(0.03)
            return True
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            runner.wait_for(late_probe, bool, timeout=0.01)


if __name__ == "__main__":
    unittest.main()
