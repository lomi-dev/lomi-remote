"""Pure tests for the unstaged launcher prototype; no privileged operations."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("trusted_launcher", HERE / "trusted_launcher.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class TrustedLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="trusted-launcher-")
        self.base = Path(self.temp.name)
        self.uid = os.getuid()
        self.install = self.base / "install"
        self.install.mkdir(mode=0o700)
        self.controller = b"SIDE_EFFECT = 'verified'\n"
        self.controller_sha = hashlib.sha256(self.controller).hexdigest()
        self.launcher = (HERE / "trusted_launcher.py").read_bytes()
        self.launcher_sha = hashlib.sha256(self.launcher).hexdigest()
        self.freeze_raw = json.dumps({"sourceSha256": {"controller.py": self.controller_sha}},
                                     sort_keys=True, separators=(",", ":")).encode("ascii")
        self.freeze_sha = hashlib.sha256(self.freeze_raw).hexdigest()
        self.write(self.install / launcher.CONTROLLER_NAME, self.controller)
        self.write(self.install / launcher.LAUNCHER_NAME, self.launcher)
        self.write(self.install / launcher.FREEZE_NAME, self.freeze_raw)
        self.write_admission()
        self.install.chmod(0o500)
        self.base.chmod(0o500)

    def tearDown(self):
        self.base.chmod(0o700)
        self.install.chmod(0o700)
        self.temp.cleanup()

    @staticmethod
    def write(path, data, mode=0o400):
        path.write_bytes(data)
        path.chmod(mode)

    def write_admission(self, **overrides):
        admission = {"schemaVersion": 1, "scope": launcher.SCOPE,
                     "freezeSha256": self.freeze_sha, "rootReviewed": True,
                     "controllerSha256": self.controller_sha,
                     "launcherSha256": self.launcher_sha}
        admission.update(overrides)
        path = self.install / launcher.ADMISSION_NAME
        if path.exists(): path.chmod(0o600)
        self.write(path, json.dumps(admission, sort_keys=True).encode("ascii"))

    def admit(self, root=None, **kw):
        return launcher.admit_from_root(root_path=str(root or self.install), base_path=str(self.base),
            uid=self.uid, **kw)

    def test_valid_admission_and_freeze_bind_controller_bytes(self):
        self.assertEqual(self.admit(), self.controller)

    def test_schema_scope_review_freeze_and_digest_fail_closed(self):
        for mutation in ({"scope": "other"}, {"freezeSha256": "a" * 64},
                         {"rootReviewed": 1}, {"extra": 1}, {"schemaVersion": 2},
                         {"controllerSha256": "0" * 64}, {"launcherSha256": "A" * 64},
                         {"launcherSha256": "0" * 64}):
            with self.subTest(mutation=mutation):
                self.write_admission(**mutation)
                with self.assertRaises(launcher.Rejected): self.admit()
        self.write_admission()
        admission_path = self.install / launcher.ADMISSION_NAME
        admission_path.chmod(0o600)
        missing = json.loads(admission_path.read_text(encoding="ascii"))
        del missing["launcherSha256"]
        self.write(admission_path, json.dumps(missing, sort_keys=True).encode("ascii"))
        with self.assertRaises(launcher.Rejected): self.admit()
        self.write_admission()
        self.base.chmod(0o700); self.install.chmod(0o700)
        (self.install / launcher.LAUNCHER_NAME).unlink()
        self.install.chmod(0o500); self.base.chmod(0o500)
        with self.assertRaises(launcher.Rejected): self.admit()
        self.base.chmod(0o700); self.install.chmod(0o700)
        self.write(self.install / launcher.LAUNCHER_NAME, self.launcher + b"# tampered\n")
        self.install.chmod(0o500); self.base.chmod(0o500)
        with self.assertRaises(launcher.Rejected): self.admit()
        self.base.chmod(0o700); self.install.chmod(0o700)
        (self.install / launcher.LAUNCHER_NAME).chmod(0o600)
        self.write(self.install / launcher.LAUNCHER_NAME, self.launcher)
        (self.install / launcher.ADMISSION_NAME).unlink()
        with self.assertRaises(launcher.Rejected): self.admit()

    def test_freeze_raw_digest_and_embedded_controller_digest_are_both_bound(self):
        self.install.chmod(0o700)
        freeze_path = self.install / launcher.FREEZE_NAME
        freeze_path.chmod(0o600)
        freeze_path.write_text(json.dumps({"sourceSha256": {"controller.py": "a" * 64}}), encoding="ascii")
        freeze_path.chmod(0o400); self.install.chmod(0o500)
        with self.assertRaises(launcher.Rejected): self.admit()

    def test_rejects_bad_file_metadata_and_oversized_controller(self):
        admission_path = self.install / launcher.ADMISSION_NAME
        admission_path.chmod(0o600)
        with self.assertRaises(launcher.Rejected): self.admit()
        admission_path.chmod(0o400)
        if self.uid != 0:
            with self.assertRaises(launcher.Rejected):
                launcher.admit_from_root(root_path=str(self.install), base_path=str(self.base), uid=0,
                                         )
        fd = os.open(self.install, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(launcher.Rejected):
                launcher._read_at(fd, launcher.CONTROLLER_NAME, uid=self.uid, max_bytes=2)
        finally:
            os.close(fd)

    def test_default_status_is_reported_as_fixed_text(self):
        output = StringIO()
        with redirect_stdout(output):
            launcher._report_status("PREPARED_NOT_EXECUTED")
        self.assertEqual(output.getvalue(), "PREPARED_NOT_EXECUTED\n")
        output = StringIO()
        with redirect_stdout(output):
            launcher._report_status("EXECUTED")
        self.assertEqual(output.getvalue(), "")

    def test_rejects_symlink_or_writable_ancestor(self):
        self.base.chmod(0o700)
        link = self.base / "link"
        link.symlink_to(self.install, target_is_directory=True)
        with self.assertRaises(launcher.Rejected): self.admit(root=link)
        link.unlink()
        writable = self.base / "writable"
        writable.mkdir(mode=0o777)
        writable.chmod(0o777)
        nested = writable / "install"
        nested.mkdir(mode=0o500)
        with self.assertRaises(launcher.Rejected): self.admit(root=nested)

    def test_replacement_after_admission_does_not_change_executed_bytes(self):
        source = self.admit()
        replacement = b"SIDE_EFFECT = 'replacement'\n"
        self.base.chmod(0o700); self.install.chmod(0o700)
        (self.install / launcher.CONTROLLER_NAME).chmod(0o600)
        self.write(self.install / launcher.CONTROLLER_NAME, replacement, 0o400)
        namespace = {}
        launcher.execute_admitted(source, namespace=namespace)
        self.assertEqual(namespace["SIDE_EFFECT"], "verified")

    def test_production_entrypoint_has_no_overrides_and_fails_closed_unstaged(self):
        self.assertEqual(launcher.TRUSTED_ROOT,
            "/Library/PrivilegedHelperTools/Lomi/private-positive-eleven")
        self.assertEqual(launcher.ROOT_UID, 0)
        self.assertEqual(launcher.PINNED_PYTHON,
            "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14")
        import inspect
        self.assertEqual(len(inspect.signature(launcher.main).parameters), 0)
        original = launcher.sys.argv
        try:
            launcher.sys.argv = ["launcher.py", "--override"]
            with self.assertRaises(launcher.Rejected): launcher.main()
        finally:
            launcher.sys.argv = original
        fd = os.open(self.install, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertEqual(launcher._run_from_fd(fd, self.uid), "PREPARED_NOT_EXECUTED")
        finally:
            os.close(fd)

    def test_root_traversal_base_accepts_root_owned_0755(self):
        root_fd = launcher._trusted_root_fd("/", uid=0)
        try:
            info = os.fstat(root_fd)
            self.assertTrue(stat.S_ISDIR(info.st_mode))
            self.assertEqual(info.st_uid, 0)
            self.assertEqual(info.st_mode & 0o022, 0)
        finally:
            os.close(root_fd)

    def test_run_admission_binds_exact_native_admission_path_and_argv(self):
        run_path = "/private/var/db/lomi/consumer-private-eleven-root-admission/12345678-1234-4234-8234-123456789abc/native-admission.json"
        run = {"schemaVersion": 1, "scope": launcher.SCOPE, "freezeSha256": self.freeze_sha,
               "rootReviewed": True, "controllerSha256": self.controller_sha,
               "executeController": True, "nativeAdmissionPath": run_path}
        self.base.chmod(0o700); self.install.chmod(0o700)
        self.write(self.install / launcher.RUN_ADMISSION_NAME,
                   json.dumps(run, sort_keys=True).encode("ascii"))
        self.install.chmod(0o500); self.base.chmod(0o500)
        observed = []
        original_execute = launcher.execute_admitted
        original_argv = launcher.sys.argv
        launcher.execute_admitted = lambda source, **kw: observed.append((source, kw, launcher.sys.argv[:]))
        fd = os.open(self.install, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertEqual(launcher._run_from_fd(fd, self.uid), "EXECUTED")
        finally:
            os.close(fd)
            launcher.execute_admitted = original_execute
            launcher.sys.argv = original_argv
        self.assertEqual(observed[0][0], self.controller)
        self.assertEqual(observed[0][2], [
            os.path.join(launcher.TRUSTED_ROOT, launcher.CONTROLLER_NAME),
            "--native-admission", run_path])

        self.base.chmod(0o700); self.install.chmod(0o700)
        (self.install / launcher.RUN_ADMISSION_NAME).chmod(0o600)
        run["nativeAdmissionPath"] = "/tmp/untrusted.json"
        self.write(self.install / launcher.RUN_ADMISSION_NAME,
                   json.dumps(run, sort_keys=True).encode("ascii"))
        self.install.chmod(0o500); self.base.chmod(0o500)
        fd = os.open(self.install, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertEqual(launcher._run_from_fd(fd, self.uid), "PREPARED_NOT_EXECUTED")
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
