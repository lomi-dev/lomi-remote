import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "trusted_bootstrap.c"


class TrustedBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="lomi-trusted-bootstrap-")
        cls.base = Path(cls.workspace.name).resolve()
        cls.root = cls.base / "trusted"
        cls.root.mkdir(mode=0o700)
        cls.home = cls.base / "home"
        cls.tmpdir = cls.base / "tmp"
        cls.home.mkdir(mode=0o700)
        cls.tmpdir.mkdir(mode=0o700)
        cls.binary = cls.base / "bootstrap"
        cls.reject_binary = cls.base / "bootstrap-reject-validation"
        cls.validation_marker = cls.base / "validation-succeeded"
        cls.child_effect = cls.base / "child-effect"
        cls.spawn_marker = cls.base / "spawn-attempted"
        cls.child_pid = cls.base / "child-pid"
        cls.kill_eintr_marker = cls.base / "kill-eintr-injected"
        cls.python = "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
        cls.interpreter_shim = cls.base / "python-pinned-test-shim"
        cls.interpreter_shim.write_text(
            "#!/bin/sh\nexec " + cls.python + " \"$@\"\n", encoding="ascii"
        )
        cls.interpreter_shim.chmod(0o555)
        args = [
            "/usr/bin/clang", "-Wall", "-Wextra", "-Werror", str(SOURCE),
            "-framework", "Security", "-framework", "CoreFoundation", "-o", str(cls.binary),
            f'-DTRUSTED_ROOT="{cls.root}"',
            f'-DBOOTSTRAP_PATH="{cls.binary}"',
            f'-DPINNED_PYTHON="{cls.interpreter_shim}"',
            f'-DTEST_VALIDATION_MARKER_PATH="{cls.validation_marker}"',
            f'-DTEST_CHILD_EFFECT_PATH="{cls.child_effect}"',
            f'-DTEST_SPAWN_MARKER_PATH="{cls.spawn_marker}"',
            f'-DTEST_CHILD_PID_PATH="{cls.child_pid}"',
            f'-DTEST_KILL_EINTR_MARKER_PATH="{cls.kill_eintr_marker}"',
            "-DBOOTSTRAP_TESTING=1",
        ]
        subprocess.run(args, check=True, capture_output=True, text=True)
        cls.sigchld_ignore_binary = cls.base / "bootstrap-sigchld-ignore"
        cls.sigchld_nocldwait_binary = cls.base / "bootstrap-sigchld-nocldwait"

        def compile_variant(binary, defines):
            variant_args = list(args)
            variant_args[variant_args.index("-o") + 1] = str(binary)
            variant_args[variant_args.index(f'-DBOOTSTRAP_PATH="{cls.binary}"')] = f'-DBOOTSTRAP_PATH="{binary}"'
            variant_args.extend(defines)
            subprocess.run(variant_args, check=True, capture_output=True, text=True)

        compile_variant(cls.reject_binary, ["-DTEST_VALIDATION_REJECT=1", "-DTEST_KILL_EINTR_ONCE=1"])
        compile_variant(cls.sigchld_ignore_binary, ["-DTEST_SIGCHLD_IGNORE=1"])
        compile_variant(cls.sigchld_nocldwait_binary, ["-DTEST_SIGCHLD_NOCLDWAIT=1"])

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        for marker in (self.validation_marker, self.child_effect, self.spawn_marker, self.child_pid,
                       self.kill_eintr_marker):
            if marker.exists():
                marker.unlink()
        self.root.chmod(0o700)
        for child in self.root.iterdir():
            if child.is_symlink() or child.is_file():
                child.unlink()
            elif child.is_dir():
                import shutil
                shutil.rmtree(child)
        self.launcher = (
            "import os, sys\n"
            f"open({str(self.child_effect)!r}, 'w').write('early' if not os.path.exists({str(self.validation_marker)!r}) else 'after-validation')\n"
            "os.write(2, b'LAUNCHED\\n')\n"
            "print('BOOTSTRAP_OK|' + str(sys.flags.isolated) + '|' + "
            "str(sys.flags.no_site) + '|' + str(sys.dont_write_bytecode) + '|' + "
            "sys.argv[0] + '|' + repr(os.environ))\n"
        ).encode()
        self.controller = b"# trusted controller fixture\n"
        self.controller_sha = hashlib.sha256(self.controller).hexdigest()
        self.freeze = json.dumps({"sourceSha256": {"controller.py": self.controller_sha}}, separators=(",", ":")).encode()
        self._write(self.root / "freeze.json", self.freeze)
        self._write(self.root / "controller.py", self.controller)
        self._write(self.root / "launcher.py", self.launcher)
        self._write_admission()

    @staticmethod
    def _write(path, value, mode=0o444):
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_bytes(value)
        path.chmod(mode)

    def _write_admission(self, freeze_sha=None, launcher_sha=None):
        data = {
            "schemaVersion": 1,
            "scope": "private-positive-auth-eleven-only",
            "freezeSha256": freeze_sha or hashlib.sha256(self.freeze).hexdigest(),
            "rootReviewed": True,
            "controllerSha256": self.controller_sha,
            "launcherSha256": launcher_sha or hashlib.sha256(self.launcher).hexdigest(),
        }
        self._write(self.root / "admission.json", json.dumps(data, separators=(",", ":")).encode())

    def _run(self, *args, env=None, binary=None):
        return subprocess.run(
            [str(binary or self.binary), *args], env=self._environment() if env is None else env,
            capture_output=True, text=True,
        )

    def _environment(self):
        return {
            "HOME": str(self.home),
            "TMPDIR": str(self.tmpdir),
            "PATH": "/usr/bin:/bin",
            "__CF_USER_TEXT_ENCODING": f"0x{os.getuid():X}:0x0:0x0",
        }

    def test_executes_exact_validated_launcher_fd_in_pinned_isolated_python(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("BOOTSTRAP_OK|1|1|True|/dev/fd/", result.stdout)
        self.assertIn("__CF_USER_TEXT_ENCODING", result.stdout)
        self.assertIn("0x" + format(os.getuid(), "X") + ":0x0:0x0", result.stdout)
        self.assertTrue(self.validation_marker.exists())
        self.assertEqual(self.child_effect.read_text(), "after-validation")

    def test_rejected_suspended_child_never_runs(self):
        result = self._run(binary=self.reject_binary)
        self.assertEqual(result.returncode, 126, result.stderr)
        self.assertNotIn("LAUNCHED", result.stderr)
        self.assertFalse(self.validation_marker.exists())
        self.assertFalse(self.child_effect.exists())
        self.assertTrue(self.spawn_marker.exists())
        self.assertTrue(self.kill_eintr_marker.exists())
        child_pid = int(self.child_pid.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_rejects_sigchld_ignore_before_spawn(self):
        result = self._run(binary=self.sigchld_ignore_binary)
        self.assertEqual(result.returncode, 126, result.stderr)
        self.assertFalse(self.spawn_marker.exists())
        self.assertFalse(self.child_pid.exists())
        self.assertFalse(self.child_effect.exists())

    def test_rejects_sigchld_nocldwait_before_spawn(self):
        result = self._run(binary=self.sigchld_nocldwait_binary)
        self.assertEqual(result.returncode, 126, result.stderr)
        self.assertFalse(self.spawn_marker.exists())
        self.assertFalse(self.child_pid.exists())
        self.assertFalse(self.child_effect.exists())

    def test_rejects_argument_and_environment_deviations(self):
        self.assertEqual(self._run("unexpected").returncode, 126)
        self.assertEqual(self._run("--python", "/usr/bin/python3").returncode, 126)
        extra = self._environment()
        extra["UNSAFE"] = "x"
        self.assertEqual(self._run(env=extra).returncode, 126)
        wrong_cf = self._environment()
        wrong_cf["__CF_USER_TEXT_ENCODING"] = "0x0:0x0:0x0"
        self.assertEqual(self._run(env=wrong_cf).returncode, 126)

    def test_rejects_symlinked_private_environment_directory(self):
        real = self.base / "home-real"
        self.home.rename(real)
        self.home.symlink_to(real, target_is_directory=True)
        try:
            self.assertEqual(self._run().returncode, 126)
        finally:
            self.home.unlink()
            real.rename(self.home)

    def test_rejects_freeze_admission_hash_mismatch(self):
        self._write_admission(freeze_sha="0" * 64)
        result = self._run()
        self.assertEqual(result.returncode, 126)
        self.assertNotIn("BOOTSTRAP_OK", result.stdout)

    def test_rejects_launcher_admission_hash_mismatch(self):
        self._write_admission(launcher_sha="0" * 64)
        result = self._run()
        self.assertEqual(result.returncode, 126)
        self.assertNotIn("BOOTSTRAP_OK", result.stdout)

    def test_rejects_controller_admission_hash_mismatch(self):
        data = json.loads((self.root / "admission.json").read_text())
        data["controllerSha256"] = "0" * 64
        self._write(self.root / "admission.json", json.dumps(data, separators=(",", ":")).encode())
        result = self._run()
        self.assertEqual(result.returncode, 126)
        self.assertNotIn("BOOTSTRAP_OK", result.stdout)

    def test_rejects_freeze_controller_binding_mismatch(self):
        wrong_freeze = json.dumps({"sourceSha256": {"controller.py": "0" * 64}}, separators=(",", ":")).encode()
        self._write(self.root / "freeze.json", wrong_freeze)
        self._write_admission(freeze_sha=hashlib.sha256(wrong_freeze).hexdigest())
        result = self._run()
        self.assertEqual(result.returncode, 126)
        self.assertNotIn("BOOTSTRAP_OK", result.stdout)

    def test_rejects_trailing_comma_in_admission(self):
        path = self.root / "admission.json"
        self._write(path, path.read_bytes()[:-1] + b",}\n")
        self.assertEqual(self._run().returncode, 126)

    def test_rejects_writable_input_and_symlinked_launcher(self):
        (self.root / "launcher.py").chmod(0o644)
        self.assertEqual(self._run().returncode, 126)
        (self.root / "launcher.py").unlink()
        target = self.base / "launcher-target.py"
        target.write_bytes(self.launcher)
        target.chmod(0o444)
        (self.root / "launcher.py").symlink_to(target)
        self.assertEqual(self._run().returncode, 126)

    def test_rejects_writable_trusted_root(self):
        self.root.chmod(0o777)
        try:
            self.assertEqual(self._run().returncode, 126)
        finally:
            self.root.chmod(0o700)

    def test_rejects_extended_acl_on_trusted_input_and_directory(self):
        launcher = self.root / "launcher.py"
        subprocess.run(["/bin/chmod", "+a", "everyone allow write", str(launcher)], check=True, capture_output=True)
        try:
            self.assertEqual(self._run().returncode, 126)
        finally:
            subprocess.run(["/bin/chmod", "-N", str(launcher)], check=False, capture_output=True)

        subprocess.run(["/bin/chmod", "+a", "everyone allow write", str(self.home)], check=True, capture_output=True)
        try:
            self.assertEqual(self._run().returncode, 126)
        finally:
            subprocess.run(["/bin/chmod", "-N", str(self.home)], check=False, capture_output=True)

    def test_rejects_extended_acl_on_pinned_interpreter(self):
        subprocess.run(["/bin/chmod", "+a", "everyone allow write", str(self.interpreter_shim)], check=True, capture_output=True)
        try:
            self.assertEqual(self._run().returncode, 126)
        finally:
            subprocess.run(["/bin/chmod", "-N", str(self.interpreter_shim)], check=False, capture_output=True)

    def test_rejects_symlinked_trusted_root_component(self):
        real = self.base / "trusted-real"
        self.root.rename(real)
        self.root.symlink_to(real, target_is_directory=True)
        try:
            self.assertEqual(self._run().returncode, 126)
        finally:
            self.root.unlink()
            real.rename(self.root)

    def test_source_pins_production_interpreter_and_same_fd_contract(self):
        source = SOURCE.read_text()
        self.assertIn('/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14', source)
        self.assertIn('"/dev/fd/%d", lfd', source)
        self.assertIn('posix_spawn(&child, PINNED_PYTHON, NULL, &attributes, child_argv, child_env)', source)
        self.assertIn('POSIX_SPAWN_START_SUSPENDED', source)
        self.assertIn('SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &guest)', source)
        self.assertIn('SecCodeCheckValidity(guest', source)
        self.assertIn('kill_and_reap_stopped_child(child, wait_outcome)', source)
        self.assertIn('do { kill_result = kill_stopped_child(pid); } while (kill_result != 0 && errno == EINTR)', source)
        self.assertIn('waitpid(pid, &status, WNOHANG)', source)
        self.assertIn('kill(child, SIGCONT)', source)
        self.assertIn('action.sa_handler == SIG_DFL', source)
        self.assertIn('(action.sa_flags & SA_NOCLDWAIT) == 0', source)
        self.assertIn('pinned_interpreter_is_trusted()', source)
        self.assertIn('pinned_python_bundle_is_trusted()', source)
        self.assertIn('SecStaticCodeCheckValidity(code', source)
        self.assertIn('kSecCSCheckAllArchitectures', source)
        self.assertIn('fcntl(lfd, F_SETFD, 0)', source)
        self.assertIn('st.st_uid == uid', source)
        self.assertIn('has_no_extended_acl(fd)', source)
        self.assertIn('strcmp(expected_controller, actual_controller)', source)
        self.assertIn('freeze_binds_controller(freeze_raw, freeze_len, expected_controller)', source)
        self.assertIn("j.p[j.i] == '}'", source)
        self.assertIn('O_NOFOLLOW', source)


if __name__ == "__main__":
    unittest.main()
