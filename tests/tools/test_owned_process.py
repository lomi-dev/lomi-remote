import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "tools/owned_process.py"
spec = importlib.util.spec_from_file_location("owned_process", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@unittest.skipUnless(os.name == "posix", "POSIX process-group fixture")
class OwnedProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module.initialize_process_ownership()

    def fixture(self, pidfile):
        # The descendant ignores graceful termination; the group's SIGKILL
        # must remove it even though only the wrapper was started by our caller.
        worker = (
            "import os,pathlib,signal,time; "
            "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); "
            "time.sleep(5)"
        )
        parent = (
            "import pathlib,subprocess,sys,time; "
            f"p=subprocess.Popen([sys.executable,'-c',{worker!r}]); "
            "time.sleep(5)"
        )
        return [sys.executable, "-c", parent]

    def wait_for_pidfile(self, path):
        deadline = time.monotonic() + 3
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(path.exists(), "synthetic descendant did not start")
        return int(path.read_text())

    def assert_not_running(self, pid):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            # Zombies are terminated; Linux container init may reap them later.
            status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, timeout=1)
            if not status.stdout.strip() or status.stdout.lstrip().startswith("Z"):
                return
            time.sleep(0.02)
        self.fail("synthetic descendant survived owned command cancellation")

    def cleanup_fixture(self, pid):
        # The command owner may already have reaped its leader. A numeric PID
        # read from a file is diagnostic data, never authority for cleanup.
        # Fixtures expire themselves even when the cancellation assertion fails.
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            status = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, timeout=1)
            if not status.stdout.strip() or status.stdout.lstrip().startswith("Z"):
                return
            time.sleep(0.02)
        self.fail("self-expiring synthetic process did not finish")

    def test_interrupt_after_communicate_reaped_never_signals_old_group(self):
        original = subprocess.Popen.communicate
        interrupted = False

        def interrupt_after_reap(child, *args, **kwargs):
            nonlocal interrupted
            result = original(child, *args, **kwargs)
            if not interrupted:
                interrupted = True
                self.assertIsNotNone(child.returncode)
                raise KeyboardInterrupt
            return result

        with patch.object(subprocess.Popen, "communicate", interrupt_after_reap):
            with patch.object(os, "killpg") as send:
                with self.assertRaisesRegex(RuntimeError, "identity is unconfirmed"):
                    module.run_owned([sys.executable, "-c", "pass"], timeout=5)
                send.assert_not_called()

    def test_kernel_child_check_rejects_stale_none_returncode(self):
        with subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True) as child:
            child.wait(timeout=5)
            reaped_code = child.returncode
            child.returncode = None
            try:
                with patch.object(os, "killpg") as send:
                    with self.assertRaisesRegex(RuntimeError, "no child"):
                        module.signal_group(child, signal.SIGTERM)
                    send.assert_not_called()
            finally:
                child.returncode = reaped_code

    def test_ignored_sigchld_is_rejected_before_spawning(self):
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            with patch.object(subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RuntimeError, "SIGCHLD ownership"):
                    module.run_owned([sys.executable, "-c", "pass"])
                spawn.assert_not_called()
        finally:
            signal.signal(signal.SIGCHLD, previous)

    def test_uninitialized_library_is_rejected_before_spawning(self):
        with patch.object(module, "_initialized_pid", None):
            with patch.object(subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RuntimeError, "SIGCHLD ownership"):
                    module.run_owned([sys.executable, "-c", "pass"])
                spawn.assert_not_called()

    def test_timeout_terminates_wrapper_and_its_descendant(self):
        with tempfile.TemporaryDirectory() as folder:
            pidfile = Path(folder) / "descendant.pid"
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    module.run_owned(self.fixture(pidfile), timeout=0.5)
                pid = self.wait_for_pidfile(pidfile)
                self.assert_not_running(pid)
            finally:
                if pidfile.exists():
                    self.cleanup_fixture(int(pidfile.read_text()))

    def test_interruption_also_cleans_the_owned_group(self):
        with tempfile.TemporaryDirectory() as folder:
            pidfile = Path(folder) / "descendant.pid"
            original = subprocess.Popen.communicate
            interrupted = False

            def interrupt_once(child, *args, **kwargs):
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    self.wait_for_pidfile(pidfile)
                    raise KeyboardInterrupt
                return original(child, *args, **kwargs)

            try:
                with patch.object(subprocess.Popen, "communicate", interrupt_once):
                    with self.assertRaises(KeyboardInterrupt):
                        module.run_owned(self.fixture(pidfile), timeout=5)
                self.assert_not_running(self.wait_for_pidfile(pidfile))
            finally:
                if pidfile.exists():
                    self.cleanup_fixture(int(pidfile.read_text()))

    def test_nonzero_status_and_output_are_preserved(self):
        result = module.run_owned([sys.executable, "-c", "print('synthetic'); raise SystemExit(7)"], timeout=5)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "synthetic\n")

    def test_timeout_handles_a_group_that_exits_on_graceful_termination(self):
        # On Darwin the final SIGKILL can report EPERM for zombie-only groups.
        # That must neither mask the timeout nor leave the direct child unreaped.
        with tempfile.TemporaryDirectory() as folder:
            pidfile = Path(folder) / "wrapper.pid"
            command = (
                "import os,pathlib,time; "
                f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); "
                "time.sleep(5)"
            )
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    module.run_owned([sys.executable, "-c", command], timeout=0.5)
                self.assert_not_running(self.wait_for_pidfile(pidfile))
            finally:
                if pidfile.exists():
                    self.cleanup_fixture(int(pidfile.read_text()))


if __name__ == "__main__":
    unittest.main()
