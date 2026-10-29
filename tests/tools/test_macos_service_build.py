"""Build receipt rejection and unique-linker-artifact regression tests."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from macos_service_build import BuildRejected, build_frozen, verify_build, frozen_command, manifest, sha, ancestor_config_absence
from owned_process import initialize_process_ownership


class FrozenBuildTests(unittest.TestCase):
    def setUp(self):
        initialize_process_ownership()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.inputs / "source.rs").write_text("reviewed input")
        self.environment = {"PATH": "/usr/bin:/bin", "CARGO_TARGET_DIR": str(self.root / "shared-target")}

    def tearDown(self):
        self.temporary.cleanup()

    def receipt(self):
        return json.loads((self.root / "build-receipt.json").read_text())

    def test_build_failure_never_qualifies_or_exposes_binary(self):
        with self.assertRaises(BuildRejected):
            build_frozen(self.root, self.inputs, [sys.executable, "-c", "raise SystemExit(13)"], self.environment)
        self.assertEqual(self.receipt()["exitCode"], 13)
        self.assertFalse(self.receipt()["qualifiedSourceBuild"])
        self.assertFalse((self.root / "bin/lomiremote").exists())

    def test_input_change_during_successful_build_is_rejected(self):
        command = [sys.executable, "-c", "from pathlib import Path; Path('source.rs').write_text('changed while compiling')"]
        with self.assertRaises(BuildRejected):
            build_frozen(self.root, self.inputs, command, self.environment)
        self.assertEqual(self.receipt()["exitCode"], 0)
        self.assertFalse(self.receipt()["inputsUnchanged"])
        self.assertFalse(self.receipt()["qualifiedSourceBuild"])
        self.assertFalse((self.root / "bin/lomiremote").exists())

    def test_copy_uses_unique_linker_artifact_not_mutable_shared_alias(self):
        target = Path(self.environment["CARGO_TARGET_DIR"])
        (target / "debug/deps").mkdir(parents=True)
        (target / "debug/lomiremote").write_bytes(b"another concurrent build")
        (target / "debug/deps/lomiremote-ab123").write_bytes(b"our exact linked binary")

        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, "", "Running `rustc --crate-name lomiremote --crate-type bin -C extra-filename=-ab123 -C metadata=test_nonce --out-dir ignored`\n")

        receipt = build_frozen(self.root, self.inputs, ["controlled cargo"], self.environment, runner=runner, link_nonce="test_nonce")
        self.assertTrue(receipt["linkedBinaryVerified"])
        self.assertFalse(receipt["qualifiedSourceBuild"])
        self.assertEqual((self.root / "bin/lomiremote").read_bytes(), b"our exact linked binary")

    def test_frozen_python_reexecution_does_not_mutate_compile_inputs(self):
        helper = self.inputs / "helper.py"
        helper.write_text("VALUE = 42\n")
        script = self.inputs / "runner.py"
        script.write_text("import helper; print(helper.VALUE)\n")
        before = manifest(self.inputs)
        result = subprocess.run(frozen_command(sys.executable, script, self.root), capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "42")
        self.assertEqual(manifest(self.inputs), before)
        self.assertFalse((self.inputs / "__pycache__").exists())

    def test_changed_inputs_and_replaced_manifest_cannot_reuse_receipt(self):
        binary = self.root / "bin/lomiremote"
        binary.parent.mkdir()
        binary.write_bytes(b"verified binary")
        manifest_path = self.root / "input-manifest.json"
        manifest_path.write_text(json.dumps(manifest(self.inputs)))
        receipt = {"completed": True, "qualifiedSourceBuild": True, "binarySha256": sha(binary), "beforeManifestSha256": sha(manifest_path)}
        (self.root / "build-receipt.json").write_text(json.dumps(receipt))
        verify_build(self.root)
        (self.inputs / "source.rs").write_text("changed after build")
        manifest_path.write_text(json.dumps(manifest(self.inputs)))
        with self.assertRaises(BuildRejected):
            verify_build(self.root)

    def test_incomplete_qualified_receipt_cannot_resume_native(self):
        binary = self.root / "bin/lomiremote"
        binary.parent.mkdir()
        binary.write_bytes(b"binary")
        (self.root / "build-receipt.json").write_text(json.dumps({"qualifiedSourceBuild": True, "binarySha256": sha(binary)}))
        with self.assertRaises(BuildRejected):
            verify_build(self.root)

    def test_external_ancestor_config_is_rejected(self):
        (self.root / ".cargo").mkdir()
        (self.root / ".cargo/config.toml").write_text("[build]\njobs=1\n")
        with self.assertRaises(BuildRejected):
            ancestor_config_absence(self.inputs)


if __name__ == "__main__":
    unittest.main()
