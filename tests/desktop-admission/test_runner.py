import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).parent))
import build_receipt
import cleanup
spec = importlib.util.spec_from_file_location("admission_runner", ROOT / "tools/run_desktop_admission.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CleanupTests(unittest.TestCase):
    def exercise(self, error):
        with tempfile.TemporaryDirectory() as folder:
            evidence = Path(folder) / "evidence.json"
            visited = []
            def failing():
                visited.append("first")
                raise error
            report = {"passed": True}
            cleanup.finish(report, [("first", failing), ("later process", lambda: visited.append("process")),
                                    ("later path", lambda: visited.append("path"))], evidence)
            self.assertEqual(visited, ["first", "process", "path"])
            saved = json.loads(evidence.read_text())
            self.assertFalse(saved["passed"])
            self.assertFalse(saved["cleanupCompleted"])
            self.assertEqual(saved["cleanupErrors"][0]["error"], type(error).__name__)

    def test_early_cleanup_failure_does_not_skip_remaining_resources_or_evidence(self):
        self.exercise(OSError("synthetic first cleanup failure"))

    def test_cleanup_interruption_does_not_skip_remaining_resources_or_evidence(self):
        self.exercise(KeyboardInterrupt())

    def test_actual_reply_then_exit73_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            reply = Path(folder) / "reply.json"
            child = subprocess.Popen([sys.executable, "-c",
                                      "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('{\"ok\":true}'); raise SystemExit(73)", str(reply)], start_new_session=True)
            report = {"passed": False}
            try:
                with self.assertRaises(RuntimeError):
                    cleanup.require_clean_exit(child, report)
                self.assertTrue(json.loads(reply.read_text())["ok"])
                self.assertEqual(report["desktopExit"], {"code": 73, "signal": None, "forcedCleanup": False})
            finally:
                if child.returncode is None:
                    runner.stop_group(child)


class DependencyLinkTests(unittest.TestCase):
    def fixture(self, directory):
        main = Path(directory) / "approved"
        checkout = Path(directory) / "checkout"
        for relative in ["node_modules", "packages/ai-runtime/node_modules", "packages/remote-terminal-runtime/node_modules"]:
            approved = main / relative
            approved.mkdir(parents=True)
            (approved / "installed.js").write_text("fixed installed dependency")
            actual = checkout / relative
            actual.parent.mkdir(parents=True, exist_ok=True)
            actual.symlink_to(approved, target_is_directory=True)
        return main, checkout

    def test_actual_three_dependency_links_and_resolved_targets_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            main, checkout = self.fixture(directory)
            inputs = build_receipt.dependency_inputs(checkout, main)
            self.assertEqual(len(inputs), 3)
            for relative, value in inputs.items():
                self.assertEqual(value["link"], str(main / relative))
                self.assertEqual(value["resolvedTarget"], str((main / relative).resolve()))

    def test_retargeted_dependency_link_is_rejected_even_with_identical_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            main, checkout = self.fixture(directory)
            original = build_receipt.dependency_inputs(checkout, main)
            decoy = Path(directory) / "decoy"
            decoy.mkdir()
            (decoy / "installed.js").write_text("fixed installed dependency")
            self.assertEqual(original["node_modules"]["sha256"], build_receipt.files_digest(decoy))
            actual = checkout / "node_modules"
            actual.unlink()
            actual.symlink_to(decoy, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "dependency target changed"):
                build_receipt.dependency_inputs(checkout, main)

    def test_missing_or_unreadable_dependency_directory_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with self.assertRaises(RuntimeError):
                build_receipt.files_digest(missing)
            with patch.object(build_receipt.os, "scandir", side_effect=PermissionError("synthetic unreadable dependency")):
                with self.assertRaises(PermissionError):
                    build_receipt.files_digest(Path(directory))


class ReceiptTests(unittest.TestCase):
    def fixture(self, folder):
        source = Path(folder) / "input.rs"
        binary = Path(folder) / "desktop"
        receipt = Path(folder) / "receipt.json"
        source.write_text("source-v1")
        binary.write_bytes(b"binary-v1")
        inputs = {"sources": {"input.rs": build_receipt.digest(source)}, "features": ["probe"], "toolchain": "fixed"}
        binaries = {"desktop": binary}
        build_receipt.atomic_json(receipt, {"schema": build_receipt.SCHEMA, "inputs": inputs,
                                           "binaries": {"desktop": build_receipt.digest(binary)}})
        return source, binary, receipt, inputs, binaries

    def test_matching_receipt_is_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            _, _, receipt, inputs, binaries = self.fixture(folder)
            build_receipt.verify(receipt, inputs, binaries)

    def test_missing_receipt_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            _, _, receipt, inputs, binaries = self.fixture(folder)
            receipt.unlink()
            with self.assertRaises(FileNotFoundError):
                build_receipt.verify(receipt, inputs, binaries)

    def test_changed_source_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            source, _, receipt, inputs, binaries = self.fixture(folder)
            source.write_text("changed source")
            inputs["sources"]["input.rs"] = build_receipt.digest(source)
            with self.assertRaises(RuntimeError):
                build_receipt.verify(receipt, inputs, binaries)

    def test_changed_binary_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            _, binary, receipt, inputs, binaries = self.fixture(folder)
            binary.write_bytes(b"changed binary")
            with self.assertRaises(RuntimeError):
                build_receipt.verify(receipt, inputs, binaries)

    def test_tampered_receipt_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            _, _, receipt, inputs, binaries = self.fixture(folder)
            value = json.loads(receipt.read_text())
            value["inputs"]["features"] = ["normal"]
            build_receipt.atomic_json(receipt, value)
            with self.assertRaises(RuntimeError):
                build_receipt.verify(receipt, inputs, binaries)

    def test_runner_rejects_stale_receipt_without_fixture_creation_or_native_launch(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "artifacts") as folder:
            _, binary, receipt, inputs, binaries = self.fixture(folder)
            manifest = Path(folder) / "source-manifest.json"
            manifest.write_text(json.dumps({"revision": "baseline", "patchedSha256": {}}))
            evidence = Path(folder) / "evidence.json"
            # Narrow the checks unrelated to receipt policy; all native/process
            # launch sites still use the real runner and are forbidden below.
            with patch.object(sys, "argv", ["runner", "--skip-build"]), patch.object(runner, "EVIDENCE", evidence), \
                 patch.object(runner, "SOURCE", Path(folder)), patch.object(runner, "RECEIPT", receipt), \
                 patch.object(runner, "BINARIES", binaries), patch.object(runner, "digest", return_value="fixed"), \
                 patch.object(build_receipt, "command", return_value="baseline"), \
                 patch.object(build_receipt, "snapshot", return_value={**inputs, "toolchain": "stale"}), \
                 patch.object(runner.tempfile, "mkdtemp", side_effect=AssertionError("fixture created before receipt check")), \
                 patch.object(runner.subprocess, "Popen", side_effect=AssertionError("native launch before receipt check")), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 1)
            saved = json.loads(evidence.read_text())
            self.assertIn("receipt/input/binary", saved["error"])
            self.assertFalse(saved["passed"])


if __name__ == "__main__":
    unittest.main()
