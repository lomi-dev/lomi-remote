import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / "tools/install_linux_local.py"
SPEC = importlib.util.spec_from_file_location("linux_local_installer", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class LinuxLocalInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lomi installer ")
        self.root = Path(self.temp.name)
        self.home = self.root / "user home with spaces"
        self.home.mkdir()
        self.home.chmod(0o755)
        self.binary = self.root / "built lomiremote"
        self.binary.write_bytes(b"first local build")
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def install(self, digest=None):
        return installer.install(self.binary, digest or self.digest, self.home,
                                 os_name="Linux", arch="x86_64")

    def prepare_bindir(self):
        bindir = self.home / ".local/bin"
        bindir.mkdir(parents=True)
        (self.home / ".local").chmod(0o755)
        bindir.chmod(0o755)
        return bindir

    def test_checksum_mismatch_does_not_create_install(self):
        with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
            self.install("0" * 64)
        self.assertFalse((self.home / ".local").exists())

    def test_install_and_owned_replacement_are_idempotent(self):
        target = self.install()
        self.assertEqual(target.read_bytes(), b"first local build")
        self.assertEqual(target.stat().st_mode & 0o777, 0o555)
        self.assertTrue(target.is_symlink())
        self.binary.write_bytes(b"replacement local build")
        target = self.install(hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(target.read_bytes(), b"replacement local build")
        target = self.install(hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(target.read_bytes(), b"replacement local build")

    def test_refuses_symlink_target(self):
        bindir = self.prepare_bindir()
        victim = self.root / "unrelated"
        victim.write_text("preserve me")
        (bindir / "lomiremote").symlink_to(victim)
        with self.assertRaisesRegex(RuntimeError, "unrelated symlink"):
            self.install()
        self.assertEqual(victim.read_text(), "preserve me")

    def test_refuses_unclaimed_regular_file(self):
        bindir = self.prepare_bindir()
        target = bindir / "lomiremote"
        target.write_text("unrelated file")
        with self.assertRaisesRegex(RuntimeError, "non-installer file"):
            self.install()
        self.assertEqual(target.read_text(), "unrelated file")
        self.assertFalse((bindir / installer.OBJECTS_DIR).exists())

    def test_refuses_directories_writable_by_other_users(self):
        local = self.home / ".local"
        local.mkdir()
        local.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, "writable by other users"):
            self.install()
        self.assertFalse((local / "bin").exists())
        self.home.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, "current-user-owned directory"):
            installer.install(self.binary, self.digest, self.home, os_name="Linux", arch="x86_64")

    def test_refuses_unsupported_platform(self):
        with self.assertRaisesRegex(RuntimeError, "unsupported platform"):
            installer.install(self.binary, self.digest, self.home, os_name="Linux", arch="riscv64")
        with self.assertRaisesRegex(RuntimeError, "unsupported platform"):
            installer.install(self.binary, self.digest, self.home, os_name="Darwin", arch="x86_64")

    def test_no_service_or_login_side_effects(self):
        self.install()
        self.assertEqual(sorted(p.name for p in self.home.iterdir()), [".local"])
        bindir = self.home / ".local/bin"
        self.assertEqual(sorted(p.name for p in bindir.iterdir()), [".lomiremote-objects", "lomiremote"])
        self.assertEqual(len(list((bindir / ".lomiremote-objects").iterdir())), 1)

    def test_new_directories_are_private_even_with_group_umask(self):
        previous = os.umask(0o002)
        try:
            self.install()
        finally:
            os.umask(previous)
        for directory in (self.home / ".local", self.home / ".local/bin",
                          self.home / ".local/bin" / installer.OBJECTS_DIR):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_source_change_after_initial_hash_is_rejected(self):
        original = tempfile.NamedTemporaryFile

        def mutate_then_stage(*args, **kwargs):
            self.binary.write_bytes(b"changed after initial digest")
            return original(*args, **kwargs)

        with mock.patch.object(installer.tempfile, "NamedTemporaryFile", side_effect=mutate_then_stage):
            with self.assertRaisesRegex(RuntimeError, "after staging"):
                self.install()
        self.assertFalse((self.home / ".local/bin/lomiremote").exists())
        self.assertEqual(list((self.home / ".local/bin/.lomiremote-objects").iterdir()), [])

    def test_interrupted_pointer_update_keeps_previous_binary_active(self):
        target = self.install()
        old_link = os.readlink(target)
        self.binary.write_bytes(b"new but interrupted build")
        new_digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        real_replace = os.replace

        def fail_active_switch(source, destination):
            if Path(destination) == target:
                raise OSError("simulated interruption before pointer switch")
            return real_replace(source, destination)

        with mock.patch.object(installer.os, "replace", side_effect=fail_active_switch):
            with self.assertRaisesRegex(OSError, "simulated interruption"):
                self.install(new_digest)
        self.assertEqual(os.readlink(target), old_link)
        self.assertEqual(target.read_bytes(), b"first local build")
        self.assertTrue((target.parent / installer.OBJECTS_DIR / new_digest).is_file())


if __name__ == "__main__":
    unittest.main()
