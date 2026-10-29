"""Offline regression tests: evidence must preserve failures and expose final scope."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("service_fixture_driver", ROOT / "tools/run_linux_service_fixture.py")
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def phase(name, passed):
    return {"phase": name, "passed": passed, "checks": [{"id": name, "passed": passed}], "command": ["synthetic-test-command"]}


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.original_artifacts = driver.ARTIFACTS
        self.original_report = copy.deepcopy(driver.report)
        driver.ARTIFACTS = Path(self.temporary.name)
        driver.report = {"operations": [], "phases": [], "invocationPassed": True}

    def tearDown(self):
        driver.ARTIFACTS = self.original_artifacts
        driver.report = self.original_report
        self.temporary.cleanup()

    def test_corrected_attempt_keeps_failed_observation_and_explicit_supersession(self):
        driver.report["phases"] = [phase("prepare", True), phase("after-disconnect", True),
                                    phase("after-reboot", False), phase("after-reboot", True), phase("cleanup", True)]
        driver.report["failedOperation"] = "after-reboot"
        driver.save()
        self.assertTrue(driver.report["passed"])
        self.assertTrue(driver.report["finalComplete"])
        self.assertTrue(driver.report["allRequiredLatestPhasesPassed"])
        self.assertFalse(driver.report["phases"][2]["passed"])
        self.assertFalse(driver.report["phases"][2]["current"])
        self.assertEqual(driver.report["phases"][2]["supersededByAttempt"], 2)
        self.assertNotIn("failedOperation", driver.report)
        self.assertTrue(driver.report["historicalFailures"][0]["superseded"])
        self.assertEqual(driver.report["latestChecksPassed"], 4)

    def test_partial_run_cannot_claim_completed_proof(self):
        driver.report["phases"] = [phase("prepare", True)]
        driver.save()
        self.assertFalse(driver.report["finalComplete"])
        self.assertFalse(driver.report["allRequiredLatestPhasesPassed"])
        self.assertFalse(driver.report["passed"])

    def test_latest_failure_cannot_reuse_an_earlier_success(self):
        driver.report["phases"] = [phase(name, True) for name in ["prepare", "after-disconnect", "after-reboot", "cleanup"]]
        driver.report["phases"].append(phase("after-reboot", False))
        driver.save()
        self.assertTrue(driver.report["finalComplete"])
        self.assertFalse(driver.report["allRequiredLatestPhasesPassed"])
        self.assertFalse(driver.report["passed"])
        self.assertFalse(driver.report["phases"][2]["current"])


if __name__ == "__main__":
    unittest.main()
