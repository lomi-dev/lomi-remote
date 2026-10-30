"""Focused tests for local release isolation, snapshots, and serving."""
from __future__ import annotations

import contextlib
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import ssl
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

import local_release as driver
import publish_release
import trust


class LocalReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="lomi-local-release-")
        cls.base = Path(cls.temp.name)
        cls.state = cls.base / "state"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.paths = driver.initialize(cls.state)
        cls.config = driver.read_json(cls.paths["public"] / "release-public.json")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_init_uses_a_separate_development_root_and_loopback_ca(self):
        production = driver.read_json(driver.ROOT / "release" / "trust" / "release-public.json")
        dev_root = self.paths["public"] / self.config["root_file"]
        self.assertEqual(self.config["origin"], driver.LOCAL_ORIGIN)
        self.assertEqual(self.config["repo"], production["repo"])
        self.assertNotEqual(self.config["root_sha256"], production["root_sha256"])
        self.assertNotEqual(dev_root.read_bytes(),
                            (driver.ROOT / "release" / "trust" / production["root_file"]).read_bytes())
        for name in ("root.pem", "targets.pem", "snapshot.pem", "timestamp.pem",
                     "index.pem", "linux-bootstrap.pem"):
            self.assertEqual(stat.S_IMODE((self.paths["keys"] / name).lstat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.paths["tls"] / "local-test-ca.key.pem").lstat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.paths["tls"] / "server.key.pem").lstat().st_mode), 0o600)
        self.assertTrue((self.paths["tls"] / "local-test-ca.der").is_file())

    def test_dirty_tracked_snapshot_is_stable_and_excludes_untracked_files(self):
        source = self.base / "source"
        source.mkdir()
        subprocess.run(["git", "init", "--quiet", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "config", "user.name", "Local Test User"], check=True)
        subprocess.run(["git", "-C", str(source), "config", "user.email", "local-test@example.invalid"], check=True)
        (source / "Cargo.toml").write_text(
            "[workspace]\n[workspace.package]\nversion = \"1.2.3\"\n", encoding="utf-8")
        (source / "tracked.txt").write_text("committed\n", encoding="utf-8")
        (source / "deleted.txt").write_text("remove me\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(source), "add", "--all"], check=True)
        subprocess.run(["git", "-C", str(source), "commit", "--quiet", "-m", "test: seed"], check=True)

        (source / "tracked.txt").write_text("dirty tracked content\n", encoding="utf-8")
        os.chmod(source / "tracked.txt", 0o755)
        (source / "staged-new.txt").write_text("staged new file\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(source), "add", "staged-new.txt"], check=True)
        (source / "deleted.txt").unlink()
        (source / "untracked.txt").write_text("must not enter snapshot\n", encoding="utf-8")
        before = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"])

        state = self.base / "snapshot-state"
        with contextlib.redirect_stdout(io.StringIO()):
            first = driver.snapshot_source(source, state)
            second = driver.snapshot_source(source, state)
        self.assertEqual(first["snapshotId"], second["snapshotId"])
        self.assertEqual(first["snapshotRevision"], second["snapshotRevision"])
        snapshot = first["path"]
        self.assertEqual((snapshot / "tracked.txt").read_text(encoding="utf-8"), "dirty tracked content\n")
        self.assertEqual((snapshot / "staged-new.txt").read_text(encoding="utf-8"), "staged new file\n")
        self.assertFalse((snapshot / "deleted.txt").exists())
        self.assertFalse((snapshot / "untracked.txt").exists())
        self.assertTrue(os.access(snapshot / "tracked.txt", os.X_OK))
        ident = subprocess.check_output(["git", "-C", str(snapshot), "show", "-s", "--format=%an <%ae>"], text=True).strip()
        self.assertEqual(ident, "Local Test User <local-test@example.invalid>")
        self.assertEqual(before, subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"]))
        self.assertEqual(subprocess.check_output(["git", "-C", str(snapshot), "status", "--porcelain"]), b"")

    def _signed_index(self, flat: Path, content: bytes) -> dict:
        flat.mkdir(parents=True)
        metadata = flat / "targets-local.json"
        metadata.write_bytes(content)
        installer = flat / "install.sh"
        installer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        files = {
            "metadata/targets.json": publish_release.asset_record(metadata),
            "install.sh": publish_release.asset_record(installer),
        }
        return publish_release.write_index(
            flat, files, ["linux-x86_64"], "v1.2.3", self.config, self.paths["keys"])

    def test_incomplete_macos_bundle_retains_notarization_evidence(self):
        for suffix in (".notarization.pending", ".notarization.json", ".notarization-log.json"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory(dir=self.base) as temporary:
                output = Path(temporary) / "bundle-output"
                output.mkdir()
                evidence = output / ("release.zip" + suffix)
                evidence.write_bytes(b"preserved evidence")
                with self.assertRaisesRegex(driver.LocalReleaseError, "notarization evidence"):
                    driver._remove_incomplete_bundle(output, "macos-aarch64")
                self.assertEqual(evidence.read_bytes(), b"preserved evidence")

    def test_incomplete_bundle_without_notarization_can_be_rebuilt(self):
        with tempfile.TemporaryDirectory(dir=self.base) as temporary:
            output = Path(temporary) / "bundle-output"
            output.mkdir()
            (output / "partial.zip").write_bytes(b"incomplete archive")
            driver._remove_incomplete_bundle(output, "macos-aarch64")
            self.assertFalse(output.exists())

    def test_tracked_parent_symlink_cannot_copy_data_outside_checkout(self):
        with tempfile.TemporaryDirectory(dir=self.base) as temporary:
            base = Path(temporary)
            checkout = base / "checkout"
            outside = base / "outside"
            snapshot = base / "snapshot"
            for directory in (checkout, outside, snapshot):
                directory.mkdir()
            (outside / "file.txt").write_text("external fixture data")
            (checkout / "tracked-dir").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(driver.LocalReleaseError, "outside the checkout"):
                driver._copy_tracked(checkout, snapshot, ["tracked-dir/file.txt"])
            self.assertFalse((snapshot / "tracked-dir/file.txt").exists())

    def test_candidate_aliases_follow_atomic_current_and_keep_old_candidate(self):
        web = self.paths["web"]
        releases = web / "remote" / "releases"
        version_dir = releases / "v1.2.3"
        version_dir.mkdir(parents=True, exist_ok=True)
        first_id = "a" * 64
        first_flat = self.base / "first-flat"
        first_index = self._signed_index(first_flat, b"first targets metadata\n")
        first = version_dir / first_id
        driver._write_candidate(first_flat, first_index, first,
                                version="1.2.3", tag="v1.2.3", config=self.config)
        driver._promote(web, first, first_index)
        first_bytes = (first / "metadata" / "targets.json").read_bytes()
        self.assertEqual((releases / "metadata" / "targets.json").read_bytes(), first_bytes)
        self.assertEqual((releases / "latest.json").resolve(), (first / "latest.json").resolve())
        self.assertEqual((web / "remote" / "install.sh").resolve(), (first / "install.sh").resolve())

        second_id = "b" * 64
        second_flat = self.base / "second-flat"
        second_index = self._signed_index(second_flat, b"second targets metadata\n")
        second = version_dir / second_id
        driver._write_candidate(second_flat, second_index, second,
                                version="1.2.3", tag="v1.2.3", config=self.config)
        driver._promote(web, second, second_index)
        self.assertEqual((releases / ".current").resolve(), second.resolve())
        self.assertEqual((releases / "metadata" / "targets.json").read_bytes(),
                         b"second targets metadata\n")
        self.assertEqual((first / "metadata" / "targets.json").read_bytes(), first_bytes)
        self.assertEqual((first / "metadata" / "targets.json").read_bytes(),
                         b"first targets metadata\n")

    def test_https_serves_regular_web_files_but_rejects_private_keys_and_escapes(self):
        web = self.paths["web"]
        public_dir = web / "remote" / "releases"
        public_dir.mkdir(parents=True, exist_ok=True)
        (public_dir / "public.txt").write_text("public\n", encoding="utf-8")
        (public_dir / "outside.pem").symlink_to(self.paths["tls"] / "server.key.pem")
        server = driver._https_server(web, self.paths["tls"], 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            context = ssl.create_default_context(cafile=str(self.paths["tls"] / "local-test-ca.pem"))
            # Rustls and strict OpenSSL readers reject a truncated TLS stream.
            # Explicitly require a close_notify when HTTP asks to close.
            with socket.create_connection(("127.0.0.1", server.server_port), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname="127.0.0.1",
                                         suppress_ragged_eofs=False) as stream:
                    stream.sendall(b"GET /remote/releases/public.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    data = bytearray()
                    while chunk := stream.recv(4096):
                        data.extend(chunk)
                    self.assertIn(b"public\n", data)

            def get(path: str):
                connection = http.client.HTTPSConnection("127.0.0.1", server.server_port,
                                                         context=context, timeout=3)
                try:
                    connection.request("GET", path)
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            self.assertEqual(get("/remote/releases/public.txt"), (200, b"public\n"))
            for path in ("/tls/server.key.pem", "/remote/releases/outside.pem",
                         "/remote/releases/%2e%2e/tls/server.key.pem"):
                status, _ = get(path)
                self.assertEqual(status, 404, path)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
