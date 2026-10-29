"""Isolated source-inventory regressions; fixtures contain only public dummy text."""
from pathlib import Path
import tempfile
import unittest
from source_coverage import SOURCE_ROOTS, check_source_coverage


class SourceCoverageTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="lomi-host-auth-coverage-")
        self.addCleanup(self.fixture.cleanup)
        self.repo = Path(self.fixture.name).resolve()
        for name in SOURCE_ROOTS:
            (self.repo / name).mkdir(parents=True)
        self.name = SOURCE_ROOTS[0] + "/lib.rs"
        (self.repo / self.name).write_text("pub fn fixture() {}\n")

    def test_complete_inventory_passes(self):
        check_source_coverage(self.repo, [self.name])

    def test_new_unlisted_module_fails(self):
        (self.repo / SOURCE_ROOTS[3] / "json_wire.rs").write_text("pub fn added() {}\n")
        with self.assertRaisesRegex(RuntimeError, "inventory mismatch"):
            check_source_coverage(self.repo, [self.name])

    def test_extra_missing_listed_module_fails(self):
        with self.assertRaisesRegex(RuntimeError, "inventory mismatch"):
            check_source_coverage(self.repo, [self.name, SOURCE_ROOTS[4] + "/missing.rs"])

    def test_symlink_file_fails(self):
        link = self.repo / SOURCE_ROOTS[1] / "linked.rs"
        link.symlink_to(self.repo / self.name)
        with self.assertRaisesRegex(RuntimeError, "linked"):
            check_source_coverage(self.repo, [self.name, link.relative_to(self.repo).as_posix()])

    def test_unlisted_symlink_directory_fails(self):
        target = self.repo / "public-fixture"
        target.mkdir()
        (target / "hidden.rs").write_text("pub fn hidden() {}\n")
        (self.repo / SOURCE_ROOTS[2] / "linked").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "linked"):
            check_source_coverage(self.repo, [self.name])

    def test_symlink_source_root_fails(self):
        root = self.repo / SOURCE_ROOTS[0]
        root.rename(root.with_name("real-src"))
        root.symlink_to(root.with_name("real-src"), target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "linked|unsafe"):
            check_source_coverage(self.repo, [self.name])

    def test_duplicate_and_parent_relative_entries_fail(self):
        for names in [[self.name, self.name], ["../outside.rs"]]:
            with self.assertRaises(RuntimeError):
                check_source_coverage(self.repo, names)


if __name__ == "__main__":
    unittest.main()
