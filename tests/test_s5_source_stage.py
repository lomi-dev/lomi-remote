import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/s5_source_stage.py"
spec = importlib.util.spec_from_file_location("s5_source_stage", SCRIPT)
stage_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage_module)


@unittest.skipIf(os.geteuid() == 0, "staging tests require an unprivileged user")
class SourceStageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        shutil.copytree(stage_module.SOURCE, self.source)

    def test_accepts_and_stages_exact_closure(self):
        pins = stage_module.verify()
        dest = self.root / "stage"
        stage_module.stage(dest)
        self.assertEqual(len(pins), 90)
        self.assertEqual(stage_module.verify_staged(dest, pins), pins)
        self.assertEqual(os.stat(dest).st_uid, os.geteuid())
        self.assertTrue((dest / "launcher.py").is_file())
        self.assertTrue((dest / "freeze.json").is_file())
        self.assertFalse((dest / "admission.json").exists())
        self.assertFalse((dest / "run-admission.json").exists())

    def assert_rejected(self):
        with self.assertRaises(stage_module.ClosureError):
            stage_module.verify(self.source)

    def test_rejects_tampered_source(self):
        path = self.source / "controller.py"
        path.write_bytes(path.read_bytes() + b"\ntampered\n")
        self.assert_rejected()

    def test_rejects_added_source(self):
        (self.source / "unexpected.txt").write_text("extra")
        self.assert_rejected()

    def test_rejects_deleted_source(self):
        (self.source / "controller.py").unlink()
        self.assert_rejected()

    def test_rejects_symlink(self):
        target = self.source / "controller.py"
        target.unlink()
        target.symlink_to(stage_module.SOURCE / "controller.py")
        self.assert_rejected()

    def test_rejects_non_object_manifest_json(self):
        bad_manifest = self.root / "manifest.json"
        for value in ("[]", "null"):
            with self.subTest(value=value):
                bad_manifest.write_text(value, encoding="utf-8")
                with patch.object(stage_module, "MANIFEST_PATH", bad_manifest):
                    self.assert_rejected()

    def test_rejects_boolean_manifest_schema_version(self):
        bad_manifest = self.root / "manifest.json"
        value = json.loads(stage_module.MANIFEST_PATH.read_text(encoding="utf-8"))
        value["schemaVersion"] = True
        bad_manifest.write_text(json.dumps(value), encoding="utf-8")
        with patch.object(stage_module, "MANIFEST_PATH", bad_manifest):
            self.assert_rejected()

    def test_rejects_unexpected_manifest_key(self):
        bad_manifest = self.root / "manifest.json"
        value = json.loads(stage_module.MANIFEST_PATH.read_text(encoding="utf-8"))
        value["unexpected"] = "value"
        bad_manifest.write_text(json.dumps(value), encoding="utf-8")
        with patch.object(stage_module, "MANIFEST_PATH", bad_manifest):
            self.assert_rejected()

    def test_rejects_duplicate_manifest_json_keys(self):
        bad_manifest = self.root / "manifest.json"
        value = stage_module.MANIFEST_PATH.read_text(encoding="utf-8").rstrip()
        bad_manifest.write_text(value[:-1] + ', "schemaVersion": 1}', encoding="utf-8")
        with patch.object(stage_module, "MANIFEST_PATH", bad_manifest):
            self.assert_rejected()

    def test_rejects_missing_freeze_from_source_closure(self):
        (self.source / "freeze.json").unlink()
        self.assert_rejected()

    def test_root_refusal_does_not_create_destination_parent(self):
        destination = self.root / "not-created" / "stage"
        with patch.object(stage_module.os, "geteuid", return_value=0):
            with self.assertRaises(stage_module.ClosureError):
                stage_module.stage(destination)
        self.assertFalse(destination.parent.exists())


if __name__ == "__main__":
    unittest.main()
