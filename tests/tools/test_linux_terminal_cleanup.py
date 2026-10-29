"""Synthetic systemctl/cgroup observations; no host service operations."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("linux_terminal_runner", ROOT / "tools/run_linux_terminal_fixture.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
UNIT = "lomi-pty-proof-" + "a" * 32 + ".service"
GROUP = "/system.slice/" + UNIT


def state(load="loaded", active="inactive", sub="dead", group=GROUP):
    return "\n".join(("LoadState=" + load, "ActiveState=" + active,
                      "SubState=" + sub, "ControlGroup=" + group)) + "\n"


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []

    def runner(self, outputs):
        def run(argv, **kwargs):
            self.calls.append(argv)
            self.assertEqual(argv[2], UNIT)
            self.assertEqual(kwargs["capture_output"], True)
            self.assertLessEqual(kwargs["timeout"], 10)
            code, out = outputs.pop(0)
            return subprocess.CompletedProcess(argv, code, out, "")
        return run

    def cleanup(self, outputs):
        return module.cleanup_owned_unit(UNIT, self.runner(outputs), self.root)

    def group(self, members="", child=None):
        path = self.root / GROUP.lstrip("/")
        path.mkdir(parents=True)
        (path / "cgroup.procs").write_text(members)
        if child is not None:
            (path / "descendant").mkdir()
            (path / "descendant/cgroup.procs").write_text(child)

    def test_query_error_is_not_absence(self):
        for output in ("", state("not-found", group="")):
            with self.assertRaisesRegex(RuntimeError, "query failed"):
                self.cleanup([(1, output)])

    def test_empty_successful_query_is_uncertain(self):
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.cleanup([(0, "")])

    def test_explicit_not_found_verifies_default_group_absence(self):
        result = self.cleanup([(0, state("not-found", group=""))])
        self.assertTrue(result["unitAbsent"])
        self.assertTrue(result["descendantCgroupsEmpty"])
        self.assertEqual(len(self.calls), 1)

    def test_absent_unit_with_live_old_group_fails(self):
        self.group("123\n")
        with self.assertRaisesRegex(RuntimeError, "members"):
            self.cleanup([(0, state("not-found", group=""))])

    def test_failed_unit_is_stopped_but_live_descendant_rejected(self):
        self.group(child="123\n")
        with self.assertRaisesRegex(RuntimeError, "members"):
            self.cleanup([(0, state(active="failed", sub="failed")), (0, ""), (0, state())])
        self.assertEqual(self.calls[1], ["systemctl", "stop", UNIT])

    def test_failed_after_stop_is_not_empty_proof(self):
        self.group()
        with self.assertRaisesRegex(RuntimeError, "did not stop"):
            self.cleanup([(0, state()), (0, ""), (0, state(active="failed", sub="failed"))])

    def test_empty_unit_and_descendants_verified_after_stop(self):
        self.group(child="")
        result = self.cleanup([(0, state(active="active", sub="running")), (0, ""), (0, state())])
        self.assertEqual(result["cgroupsChecked"], 2)
        self.assertTrue(result["stopVerified"])

    def test_stop_or_second_query_errors_fail(self):
        for outputs in ([(0, state()), (1, "")], [(0, state()), (0, ""), (1, "")]):
            with self.assertRaises(RuntimeError):
                self.cleanup(outputs)

    def test_missing_members_file_is_uncertain(self):
        self.group()
        (self.root / GROUP.lstrip("/") / "cgroup.procs").unlink()
        with self.assertRaises(FileNotFoundError):
            self.cleanup([(0, state()), (0, ""), (0, state())])

    def test_unrelated_group_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "invalid control group"):
            self.cleanup([(0, state(group="/")), (0, ""), (0, state())])


if __name__ == "__main__":
    unittest.main()
