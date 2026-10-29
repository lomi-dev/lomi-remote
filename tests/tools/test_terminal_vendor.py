import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("terminal_vendor", ROOT / "tools/check_terminal_vendor.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class TerminalVendorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "vendor", self.root / "vendor")

    def test_original_inventory_and_recorded_patches(self):
        self.assertEqual(checker.verify(self.root), 226)

    def test_unrecorded_source_or_patch_change_is_rejected(self):
        source = self.root / "vendor/vte/src/lib.rs"
        original = source.read_bytes()
        source.write_bytes(original + b"\n")
        with self.assertRaisesRegex(ValueError, "source drift"):
            checker.verify(self.root)
        source.write_bytes(original)
        artifact = next((self.root / "vendor/patches").glob("*.patch"))
        artifact.write_bytes(artifact.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "patch artifact drift"):
            checker.verify(self.root)

    def test_missing_license_and_unlisted_source_are_rejected(self):
        license_path = self.root / "vendor/vte/LICENSE-MIT"
        original = license_path.read_bytes()
        license_path.unlink()
        with self.assertRaisesRegex(ValueError, "license inventory"):
            checker.verify(self.root)
        license_path.write_bytes(original)
        (self.root / "vendor/vte/unexpected.rs").write_text("synthetic")
        with self.assertRaisesRegex(ValueError, "license inventory"):
            checker.verify(self.root)

    def test_external_file_symlink_is_rejected(self):
        source = self.root / "vendor/vte/src/lib.rs"
        original = source.read_bytes()
        source.unlink()
        outside = self.root / "outside"
        outside.write_bytes(original)
        source.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "nonregular vendor"):
            checker.verify(self.root)


if __name__ == "__main__":
    unittest.main()
