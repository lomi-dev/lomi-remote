"""No VM operations: regression coverage for invocation/proof ownership."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("linux_service_runner_under_test", ROOT / "tools/run_linux_service_fixture.py")
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
REQUIRED = ["prepare", "after-disconnect", "after-reboot", "cleanup"]


class LinuxServiceRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.artifacts = driver.ARTIFACTS
        self.report = copy.deepcopy(driver.report)
        driver.ARTIFACTS = Path(self.temp.name)
        driver.report = {"operations": [], "phases": [
            {"phase": name, "passed": True, "checks": [{"id": name, "passed": True}]}
            for name in REQUIRED], "invocationPassed": True,
            "guestSourceRoot": "/home/lomi-e0/lomi-source-" + "a" * 32}
        driver.save()

    def tearDown(self):
        driver.ARTIFACTS = self.artifacts
        driver.report = self.report
        self.temp.cleanup()

    def recorded(self):
        return json.loads((driver.ARTIFACTS / "evidence.json").read_text())

    def test_new_prepare_invalidates_successful_old_proof_before_work(self):
        self.assertTrue(driver.report["passed"])
        driver.begin_invocation("prepare")
        saved = self.recorded()
        self.assertEqual(saved["invocationState"], "running")
        self.assertFalse(saved["invocationPassed"])
        self.assertFalse(saved["finalComplete"])
        self.assertFalse(saved["allRequiredLatestPhasesPassed"])
        self.assertTrue(all(p.get("invalidatedByInvocation") for p in saved["phases"]))
        driver.report["phases"].append({"phase": "prepare", "passed": True, "checks": []})
        driver.save()
        self.assertFalse(driver.report["finalComplete"])
        self.assertEqual(set(driver.report["latestPhaseResults"]), {"prepare"})

    def test_new_source_build_invalidates_downstream_old_results(self):
        prior = driver.report["guestSourceRoot"]
        driver.begin_invocation("transfer-build")
        self.assertFalse(driver.report["finalComplete"])
        self.assertEqual(driver.report["latestPhaseResults"], {})
        self.assertEqual(len(driver.report["completedProofHistory"]), 1)
        self.assertNotEqual(driver.report["guestSourceRoot"], prior)
        self.assertRegex(driver.report["guestSourceRoot"], r"^/home/lomi-e0/lomi-source-[0-9a-f]{32}$")

    def test_full_run_retains_old_attempts_and_selects_fresh_source_root(self):
        prior_root = driver.report["guestSourceRoot"]
        old_attempts = len(driver.report["phases"])
        def inspect_new_run():
            self.assertNotEqual(driver.report["guestSourceRoot"], prior_root)
            self.assertEqual(len(driver.report["phases"]), old_attempts)
            self.assertTrue(all(p.get("invalidatedByInvocation") for p in driver.report["phases"]))
            self.assertEqual(len(driver.report["completedProofHistory"]), 1)
        with patch.object(driver.sys, "argv", ["driver", "--phase", "all"]), \
             patch.object(driver.sys, "platform", "darwin"), \
             patch.dict(driver.ENV, {"LIMA_HOME": self.temp.name}), \
             patch.object(driver, "transfer_build", side_effect=inspect_new_run), \
             patch.object(driver, "phase"), patch.object(driver, "disconnect"), \
             patch.object(driver, "reboot"):
            self.assertEqual(driver.main(), 0)
        saved = self.recorded()
        self.assertEqual(len(saved["phases"]), old_attempts)
        self.assertNotEqual(saved["guestSourceRoot"], prior_root)

    def test_phase_continuation_preserves_source_root(self):
        source_root = driver.report["guestSourceRoot"]
        driver.begin_invocation("prepare")
        self.assertEqual(driver.report["guestSourceRoot"], source_root)

    def test_phase_continuation_fails_closed_without_valid_source_root(self):
        del driver.report["guestSourceRoot"]
        with self.assertRaisesRegex(RuntimeError, "continuation_source_root_unavailable"):
            driver.begin_invocation("prepare")

    def test_native_validation_transfers_owned_process_support(self):
        inventory = {"files": {"tools/owned_process.py": "digest",
                               "tests/services-linux/guest_probe.py": "digest"}, "digest": "source"}
        names = driver.native_validation_sources(inventory)
        self.assertIn("tools/owned_process.py", names)

    def test_new_reboot_invalidates_boot_and_cleanup_only(self):
        driver.begin_invocation("reboot")
        self.assertEqual(set(driver.report["latestPhaseResults"]), {"prepare", "after-disconnect"})
        self.assertFalse(driver.report["finalComplete"])

    def test_keyboard_interrupt_saves_exit_130_and_no_stale_success(self):
        def interrupted(_name):
            before = self.recorded()
            self.assertFalse(before["invocationPassed"])
            self.assertEqual(before["invocationState"], "running")
            raise KeyboardInterrupt
        with patch.object(driver.sys, "argv", ["driver", "--phase", "prepare"]), \
             patch.object(driver.sys, "platform", "darwin"), \
             patch.dict(driver.ENV, {"LIMA_HOME": self.temp.name}), \
             patch.object(driver, "phase", side_effect=interrupted):
            self.assertEqual(driver.main(), 130)
        saved = self.recorded()
        self.assertEqual(saved["invocationState"], "interrupted")
        self.assertEqual(saved["invocations"][-1]["exitCode"], 130)
        self.assertFalse(saved["passed"])
        self.assertFalse(saved["finalComplete"])

    def test_interrupted_unknown_guest_phase_cannot_race_automatic_cleanup(self):
        def interrupted(_name):
            driver.report["remotePhaseCompletionUnverified"] = True
            raise KeyboardInterrupt
        with patch.object(driver.sys, "argv", ["driver", "--phase", "all"]), \
             patch.object(driver.sys, "platform", "darwin"), \
             patch.dict(driver.ENV, {"LIMA_HOME": self.temp.name}), \
             patch.object(driver, "transfer_build"), \
             patch.object(driver, "phase", side_effect=interrupted) as phase:
            self.assertEqual(driver.main(), 130)
        phase.assert_called_once_with("prepare")
        self.assertTrue(driver.report["cleanupDeferred"])
        self.assertFalse(driver.report["passed"])

    def test_local_command_interrupt_is_recorded_and_uses_owned_process_runner(self):
        driver.begin_invocation("prepare")
        with patch.object(driver, "run_owned", side_effect=KeyboardInterrupt) as owned:
            with self.assertRaises(KeyboardInterrupt):
                driver.invoke("synthetic-interrupt", ["/usr/bin/true"])
        owned.assert_called_once()
        operation = driver.report["operations"][-1]
        self.assertEqual(operation["command"], ["/usr/bin/true"])
        self.assertEqual(operation["state"], "interrupted")
        self.assertFalse(self.recorded()["invocationPassed"])

    def test_guest_completion_requires_token_and_records_bounded_timeout(self):
        driver.begin_invocation("prepare")
        def completed(argv, **kwargs):
            self.assertIn("90s", argv)
            self.assertEqual(kwargs["timeout"], 110)
            token = argv[argv.index("--invocation-id") + 1]
            return SimpleNamespace(returncode=0, stdout=json.dumps({
                "phase": "prepare", "passed": True, "completed": True,
                "invocationId": token, "checks": []}))
        with patch.object(driver, "run_owned", side_effect=completed):
            driver.phase("prepare")
        self.assertFalse(driver.report["remotePhaseCompletionUnverified"])
        self.assertFalse(driver.report["finalComplete"])

    def test_cleanup_is_deferred_until_unknown_guest_deadline_and_lock_are_verified(self):
        driver.begin_invocation("cleanup")
        driver.report["remotePhaseCompletionUnverified"] = True
        driver.report["remotePhaseDeadlineUnix"] = time.time() + 90
        with patch.object(driver, "run_owned") as owned:
            with self.assertRaises(RuntimeError):
                driver.phase("cleanup")
        owned.assert_not_called()
        self.assertTrue(driver.report["cleanupDeferred"])

    def test_guest_deadline_and_released_lock_allow_followup_cleanup(self):
        driver.begin_invocation("cleanup")
        driver.report["remotePhaseCompletionUnverified"] = True
        driver.report["remotePhaseDeadlineUnix"] = time.time() - 1
        def completed(argv, **_kwargs):
            if "flock" in argv:
                return SimpleNamespace(returncode=0, stdout="")
            token = argv[argv.index("--invocation-id") + 1]
            return SimpleNamespace(returncode=0, stdout=json.dumps({
                "phase": "cleanup", "passed": True, "completed": True,
                "invocationId": token, "checks": []}))
        with patch.object(driver, "run_owned", side_effect=completed) as owned:
            driver.phase("cleanup")
        self.assertEqual(owned.call_count, 2)
        self.assertFalse(driver.report["remotePhaseCompletionUnverified"])
        self.assertFalse(driver.report["cleanupDeferred"])


if __name__ == "__main__":
    unittest.main()
