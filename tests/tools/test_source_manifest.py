import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "tools/source_manifest.py"
spec = importlib.util.spec_from_file_location("source_manifest", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SourceManifestTests(unittest.TestCase):
    def test_source_digest_ignores_generated_output_and_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            (repo / "tools").mkdir()
            (repo / "tools/check.py").write_text("print('synthetic')\n")
            first = module.source_inventory(repo)
            (repo / "tools/.env").write_text("SYNTHETIC=private-fixture\n")
            (repo / "artifacts").mkdir()
            (repo / "artifacts/result.json").write_text('{}')
            (repo / "tests/node_modules").mkdir(parents=True)
            (repo / "tests/node_modules/generated.js").write_text("fixture")
            self.assertEqual(first, module.source_inventory(repo))
            (repo / "tools/check.py").write_text("print('changed')\n")
            self.assertNotEqual(first["digest"], module.source_inventory(repo)["digest"])

    def test_source_symlink_refuses_reading_an_external_file(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder) / "repo"
            (repo / "tools").mkdir(parents=True)
            outside = Path(folder) / "outside"
            outside.write_text("synthetic-private-fixture")
            (repo / "tools/external.py").symlink_to(outside)
            with self.assertRaises(ValueError):
                module.source_inventory(repo)

    def test_named_source_root_cannot_be_an_external_directory_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            repo, outside = base / "repo", base / "outside"
            repo.mkdir()
            outside.mkdir()
            (outside / "private.txt").write_text("synthetic-private-fixture")
            (repo / "tools").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "directory symlinks"):
                module.source_inventory(repo)

    def test_nested_directory_symlinks_are_rejected_without_silent_omission(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            repo, outside = base / "repo", base / "outside"
            (repo / "tools").mkdir(parents=True)
            outside.mkdir()
            (outside / "private.txt").write_text("synthetic-private-fixture")
            (repo / "tools/nested").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "directory symlinks"):
                module.source_inventory(repo)

    def test_ctas_private_runtime_view_is_excluded_from_source_transfer(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            package = repo / "tests/consumer-derivatives-v2-s5-pre012-ctas-successor"
            package.mkdir(parents=True)
            (package / "runner.py").write_text("print('source')\n")
            before = module.source_inventory(repo)
            runtime = package / ".ctas-runner-view-0123456789abcdef0123456789abcdef"
            runtime.mkdir()
            outside = Path(folder) / "external-tool"
            outside.write_text("private tool bytes")
            (runtime / "runtime-link").symlink_to(outside)
            self.assertEqual(before, module.source_inventory(repo))

    def test_ctas_runtime_view_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            repo, outside = base / "repo", base / "outside"
            package = repo / "tests/consumer-derivatives-v2-s5-pre012-ctas-successor"
            package.mkdir(parents=True)
            outside.mkdir()
            (package / ".ctas-runner-view-0123456789abcdef0123456789abcdef").symlink_to(
                outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "directory symlinks"):
                module.source_inventory(repo)

    def test_ctas_runtime_pattern_does_not_exclude_other_source_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            repo, outside = base / "repo", base / "outside"
            package = repo / "tests/consumer-derivatives-v2-s5-pre012-ctas-successor"
            package.mkdir(parents=True)
            outside.write_text("synthetic-private-fixture")
            (package / ".ctas-runner-view-not-a-uuid").mkdir()
            (package / ".ctas-runner-view-not-a-uuid/external.py").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "source inventory refuses symlinks"):
                module.source_inventory(repo)

    def test_broken_source_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            (repo / "crates").symlink_to(repo / "missing", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "directory symlinks"):
                module.source_inventory(repo)

    def test_source_scan_failure_cannot_silently_produce_a_partial_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            (repo / "tools").mkdir()
            with patch.object(module.os, "scandir", side_effect=PermissionError("synthetic scan denial")):
                with self.assertRaises(PermissionError):
                    module.source_inventory(repo)

    def test_named_source_root_cannot_be_a_regular_file(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            (repo / "crates").write_text("synthetic invalid source layout")
            with self.assertRaisesRegex(ValueError, "must be a directory"):
                module.source_inventory(repo)

    def test_missing_repositories_never_become_release_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder) / "lomi-remote"
            repo.mkdir()
            report = module.capture(repo)
            self.assertFalse(report["releaseReady"])
            self.assertFalse(report["specification"]["complete"])
            self.assertEqual(report["implementation"]["state"], "missing")
            self.assertGreaterEqual(len(module.release_blockers(report)), 9)


if __name__ == "__main__":
    unittest.main()
