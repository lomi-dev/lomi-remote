"""No VM access: preserve proof inputs when remote completion is unknown."""
import hashlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location("linux_product_runner_under_test", ROOT / "tools/run_linux_product_host.py")
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
CONTINUITY_SPEC = importlib.util.spec_from_file_location(
    "linux_product_continuity_under_test", ROOT / "tests/product-linux/continuity.py")
continuity = importlib.util.module_from_spec(CONTINUITY_SPEC)
CONTINUITY_SPEC.loader.exec_module(continuity)
RUN_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")


class LinuxProductRunnerTests(unittest.TestCase):
    def test_continuity_owner_lock_distinguishes_live_owner_from_stale_lock_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile"
            profile.mkdir(mode=0o700)
            lock_path = profile / "owner.lock"
            lock_path.touch(mode=0o600)
            os.chmod(lock_path, 0o600)
            self.assertFalse(continuity.owner_lock_is_held(profile, os.geteuid()))
            descriptor = os.open(lock_path, os.O_RDONLY)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertTrue(continuity.owner_lock_is_held(profile, os.geteuid()))
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def execute(self, failure=None, with_service=False, with_boot_service=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text("synthetic source\n")
            inventory = {"algorithm": "sha256", "digest": "synthetic",
                         "files": {"Cargo.toml": hashlib.sha256((root / "Cargo.toml").read_bytes()).hexdigest()}}
            commands = []

            def run(command, **_kwargs):
                commands.append(command)
                text = command[-1]
                output = ""
                code = 0
                if command[0] == driver.LIMA and command[-1] == "/etc/ssh/ssh_host_ed25519_key.pub":
                    output = "ssh-ed25519 AAAA synthetic\n"
                elif command[0] == driver.LIMA and "list" in command:
                    output = json.dumps({"name": "lomi-e0", "status": "Running", "sshLocalPort": 12345})
                elif command[0] == driver.LIMA and "stop" in command:
                    if failure == "lima-stop-uncertain":
                        raise subprocess.TimeoutExpired("limactl stop", 1)
                elif command[0] == driver.LIMA and "start" in command:
                    if failure == "lima-start-uncertain":
                        raise subprocess.TimeoutExpired("limactl start", 1)
                elif command[0] == driver.LIMA and "lomi-e0" in command and "cat" in command:
                    output = "ssh-ed25519 AAAA synthetic\n"
                elif command[0] == "ssh" and "cargo" in text and "build" in text:
                    if isinstance(failure, BaseException):
                        raise failure
                    if failure == "ssh-255":
                        code = 255
                elif command[0] == "ssh" and "platform.platform" in text:
                    output = "{}"
                elif command[0] == "ssh" and "shutil.copyfile" in text:
                    output = json.dumps({"bytes": 1, "sha256": "synthetic",
                                         "directoryMode": 0o775 if failure == "public-binary-parent" else 0o700})
                elif command[0] == "ssh" and "continuity.py" in text:
                    output = json.dumps({"passed": True})
                    if failure == "verify-failed" and " verify " in text:
                        code = 1
                    if failure == "continuity-cleanup-failed" and " cleanup " in text:
                        code = 1
                    if failure == "continuity-cleanup-unknown" and " cleanup " in text:
                        raise subprocess.TimeoutExpired("continuity cleanup", 1)
                elif command[0] == "ssh" and ("service_lifecycle.py" in text or "boot_service_lifecycle.py" in text):
                    output = json.dumps({"passed": True})
                    if failure == "service-verify-failed" and " verify " in text:
                        code = 1
                    if failure == "service-cleanup-failed" and " cleanup " in text:
                        code = 1
                    if failure == "service-cleanup-unknown" and " cleanup " in text:
                        raise subprocess.TimeoutExpired("service cleanup", 1)
                return SimpleNamespace(returncode=code, stdout=output, stderr="")

            with patch.object(driver, "ROOT", root), \
                    patch.object(driver, "source_inventory", return_value=inventory), \
                    patch.object(driver, "run_owned", side_effect=run), \
                    patch.object(driver.uuid, "uuid4", return_value=RUN_ID), \
                    patch.object(sys, "argv", ["driver", "--run"] + (["--with-service"] if with_service else [])
                                 + (["--with-boot-service"] if with_boot_service else [])):
                result = driver.main()
            report = json.loads((root / "artifacts/product-linux" / str(RUN_ID) / "report.json").read_text())
            return result, report, commands

    def test_each_build_and_copy_use_the_same_uuid_private_target(self):
        result, report, commands = self.execute()
        self.assertEqual(result, 0)
        self.assertTrue(report["complete"])
        self.assertTrue(report["remoteCompletionKnown"])
        expected = "/home/lomi-e0/lomi-product-" + str(RUN_ID) + "/target"
        cargo_commands = [c[-1] for c in commands if c[0] == "ssh" and "cargo" in c[-1]]
        self.assertEqual(len(cargo_commands), 2)
        self.assertTrue(all("CARGO_TARGET_DIR=" + expected in c for c in cargo_commands))
        copy = next(c[-1] for c in commands if c[0] == "ssh" and "shutil.copyfile" in c[-1])
        self.assertIn(expected + "/debug/lomiremote", copy)

    def test_transport_timeout_interrupt_and_255_preserve_inputs_without_cleanup(self):
        for failure in (subprocess.TimeoutExpired("synthetic ssh", 1), KeyboardInterrupt(), "ssh-255"):
            with self.subTest(failure=type(failure).__name__):
                result, report, _ = self.execute(failure)
                self.assertEqual(result, 1)
                self.assertFalse(report["complete"])
                self.assertFalse(report["remoteCompletionKnown"])
                self.assertFalse(report["cleanup"]["confirmed"])
                self.assertIn("preservedRemoteRoot", report["cleanup"])
                names = [operation["name"] for operation in report["operations"]]
                self.assertNotIn("ssh-cleanup", names)
                self.assertNotIn("remove-owned-inputs", names)

    def test_successful_cleanup_cannot_turn_failed_verification_into_a_pass(self):
        result, report, _ = self.execute("verify-failed")
        self.assertEqual(result, 1)
        self.assertFalse(report["complete"])
        self.assertFalse(report["passed"])
        self.assertTrue(report["remoteCompletionKnown"])
        self.assertTrue(report["cleanup"]["confirmed"])

    def test_service_phases_are_required_and_cleanup_failure_preserves_inputs(self):
        result, report, _ = self.execute(with_service=True)
        self.assertEqual(result, 0)
        self.assertTrue(report["serviceRequested"])
        self.assertTrue(report["serviceVerify"]["passed"])
        self.assertTrue(report["cleanup"]["service"]["passed"])
        names = [op["name"] for op in report["operations"]]
        self.assertLess(names.index("ssh-service-cleanup"), names.index("remove-owned-inputs"))
        for failure in ("service-verify-failed", "service-cleanup-failed"):
            with self.subTest(failure=failure):
                result, report, _ = self.execute(failure, with_service=True)
                self.assertEqual(result, 1)
                self.assertFalse(report["passed"])
                if failure == "service-cleanup-failed":
                    self.assertFalse(report["cleanup"]["confirmed"])
                    self.assertIn("preservedRemoteRoot", report["cleanup"])
                    self.assertNotIn("remove-owned-inputs", [op["name"] for op in report["operations"]])

    def test_untrusted_frozen_binary_parent_is_rejected_before_service_install(self):
        result, report, _ = self.execute("public-binary-parent", with_service=True)
        self.assertEqual(result, 1)
        self.assertFalse(report["complete"])
        self.assertNotIn("ssh-service-prepare", [op["name"] for op in report["operations"]])

    def test_boot_option_orders_cold_cycle_and_cleanup_after_verification(self):
        result, report, commands = self.execute(with_boot_service=True)
        self.assertEqual(result, 0)
        self.assertTrue(report["bootServiceRequested"])
        names = [op["name"] for op in report["operations"]]
        self.assertLess(names.index("ssh-boot-service-prepare"), names.index("lima-cold-stop"))
        self.assertLess(names.index("lima-cold-stop"), names.index("lima-cold-start"))
        self.assertLess(names.index("lima-cold-start"), names.index("ssh-boot-service-verify"))
        self.assertLess(names.index("ssh-boot-service-verify"), names.index("ssh-service-cleanup"))
        self.assertLess(names.index("ssh-service-cleanup"), names.index("ssh-cleanup"))
        self.assertLess(names.index("ssh-service-cleanup"), names.index("remove-owned-inputs"))
        self.assertIn("lomi-e0", commands[names.index("lima-cold-stop")])
        self.assertIn("lomi-e0", commands[names.index("lima-cold-start")])

    def test_uncertain_cold_transition_preserves_fixture_and_linger_journal(self):
        for failure in ("lima-stop-uncertain", "lima-start-uncertain"):
            with self.subTest(failure=failure):
                result, report, _ = self.execute(failure, with_boot_service=True)
                self.assertEqual(result, 1)
                self.assertFalse(report["remoteCompletionKnown"])
                self.assertFalse(report["cleanup"]["confirmed"])
                self.assertIn("preservedRemoteRoot", report["cleanup"])
                names = [op["name"] for op in report["operations"]]
                self.assertNotIn("ssh-service-cleanup", names)
                self.assertNotIn("remove-owned-inputs", names)

    def test_boot_cleanup_uncertainty_preserves_root_and_orders_service_first(self):
        result, report, _ = self.execute(with_boot_service=True)
        self.assertEqual(result, 0)
        names = [operation["name"] for operation in report["operations"]]
        self.assertLess(names.index("ssh-service-cleanup"), names.index("ssh-cleanup"))
        for failure in ("continuity-cleanup-failed", "continuity-cleanup-unknown",
                        "service-cleanup-failed", "service-cleanup-unknown"):
            with self.subTest(failure=failure):
                result, report, _ = self.execute(failure, with_boot_service=True)
                self.assertEqual(result, 1)
                self.assertFalse(report["cleanup"]["confirmed"])
                self.assertIn("preservedRemoteRoot", report["cleanup"])
                names = [operation["name"] for operation in report["operations"]]
                self.assertNotIn("remove-owned-inputs", names)
                if failure == "continuity-cleanup-unknown":
                    self.assertIn("ssh-service-cleanup", names)
                    self.assertFalse(report["remoteCompletionKnown"])
                if failure == "service-cleanup-unknown":
                    self.assertNotIn("ssh-cleanup", names)
                    self.assertFalse(report["remoteCompletionKnown"])
                if failure in ("continuity-cleanup-failed", "service-cleanup-failed"):
                    self.assertIn("ssh-cleanup", names)
                    self.assertTrue(report["remoteCompletionKnown"])


if __name__ == "__main__":
    unittest.main()
