"""Focused corruption checks for the extraction inventory; no application writes."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("check_crypto_source", ROOT / "tools/check_crypto_source.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        shutil.copytree(ROOT / "crates/lomi-remote-crypto", self.root / "crates/lomi-remote-crypto")
        target = self.root / "tests/crypto-provenance"
        target.mkdir(parents=True)
        shutil.copyfile(ROOT / "tests/crypto-provenance/source.json", target / "source.json")
        for relative in checker.PROOF:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

    def test_intact_copy(self):
        self.assertGreater(checker.verify(self.root), 50)

    def test_vendor_patch_drift(self):
        path = self.root / "crates/lomi-remote-crypto/vendor/snow/src/resolvers/default.rs"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "destination drift"):
            checker.verify(self.root)

    def test_new_enrollment_drift(self):
        path = self.root / "crates/lomi-remote-crypto/src/enrollment.rs"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "added source drift"):
            checker.verify(self.root)

    def test_new_grant_source_drift(self):
        path = self.root / "crates/lomi-remote-crypto/src/grant_v3.rs"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "added source drift"):
            checker.verify(self.root)

    def test_external_proof_drift(self):
        path = self.root / "tests/grant-v3/vectors.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "grant/context proof drift"):
            checker.verify(self.root)

    def test_external_proof_symlink(self):
        path = self.root / "tests/grant-v3/vectors.json"
        path.unlink()
        path.symlink_to(ROOT / "tests/grant-v3/vectors.json")
        with self.assertRaisesRegex(ValueError, "symlink in provenance path"):
            checker.verify(self.root)

    def test_unexpected_proof_file(self):
        (self.root / "tests/grant-v3/unlisted.txt").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected grant/context proof files"):
            checker.verify(self.root)

    def test_v3_browser_source_drift(self):
        path = self.root / "crates/lomi-remote-crypto/src/browser_v3.rs"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "added source drift"):
            checker.verify(self.root)

    def test_v3_browser_vectors_drift(self):
        path = self.root / "tests/crypto-v3-browser/native-vectors.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "grant/context proof drift"):
            checker.verify(self.root)

    def test_v3_browser_runner_drift(self):
        path = self.root / "tools/run_crypto_v3_browser.py"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "grant/context proof drift"):
            checker.verify(self.root)

    def test_shared_process_helper_drift(self):
        path = self.root / "tools/owned_process.py"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "grant/context proof drift"):
            checker.verify(self.root)

    def test_authority_wire_verifier_drift(self):
        path = self.root / "crates/lomi-remote-crypto/src/enrollment_wire.rs"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "added source drift"):
            checker.verify(self.root)

    def test_authority_runtime_wrapper_drift(self):
        path = self.root / "packages/authority-crypto-wasm/src/index.mjs"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "grant/context proof drift"):
            checker.verify(self.root)

    def test_unexpected_v3_browser_file(self):
        (self.root / "tests/crypto-v3-browser/unlisted.txt").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected grant/context proof files"):
            checker.verify(self.root)

    def test_missing_license(self):
        (self.root / "crates/lomi-remote-crypto/vendor/snow/LICENSE-MIT").unlink()
        with self.assertRaisesRegex(ValueError, "missing source file"):
            checker.verify(self.root)

    def test_unexpected_nested_lock(self):
        (self.root / "crates/lomi-remote-crypto/Cargo.lock").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected crypto source files"):
            checker.verify(self.root)


if __name__ == "__main__":
    unittest.main()
