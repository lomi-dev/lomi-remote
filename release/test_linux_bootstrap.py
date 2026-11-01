"""End-to-end checks for the authenticated Linux bootstrap extractor."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
import warnings
import zipfile


ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "release" / "linux-bootstrap.sh.in"
PLATFORM = "linux-x86_64"
TARGET = "lomiremote-linux-x86_64"
VERSION = "9.8.7"
ROOT_SHA256 = "a" * 64
ARCHIVE_NAME = f"lomi-remote-{PLATFORM}-{VERSION}.zip"
MANIFEST_NAME = f"lomi-remote-{PLATFORM}-{VERSION}.bootstrap-manifest"
SIGNATURE_NAME = f"lomi-remote-{PLATFORM}-{VERSION}.sig"
PUBLIC_KEY_NAME = f"lomi-remote-{PLATFORM}-{VERSION}.der"
INSTALLER = (
    b"#!/bin/sh\n"
    b"set -eu\n"
    b"bundle_dir=${0%/*}\n"
    b"[ -x \"$0\" ] || { printf '%s\\n' 'INSTALLER_NOT_EXECUTABLE'; exit 81; }\n"
    b"[ -x \"$bundle_dir/lomi-update-trust\" ] || { printf '%s\\n' 'UPDATER_NOT_EXECUTABLE'; exit 82; }\n"
    b"\"$bundle_dir/lomi-update-trust\"\n"
    b"for argument do printf 'INSTALL_ARG=<%s>\\n' \"$argument\"; done\n"
)
UPDATER = b"#!/bin/sh\nprintf '%s\\n' UPDATER_EXECUTABLE\n"


def _openssl3() -> Path | None:
    candidates = [
        Path("/opt/homebrew/opt/openssl@3/bin/openssl"),
        Path("/usr/local/opt/openssl@3/bin/openssl"),
    ]
    for candidate in (shutil.which("openssl3"), shutil.which("openssl")):
        if candidate:
            candidates.append(Path(candidate))
    for candidate in candidates:
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        result = subprocess.run(
            [str(candidate), "version"], capture_output=True, text=True, check=False
        )
        if result.returncode == 0 and result.stdout.startswith("OpenSSL 3."):
            return candidate
    return None


class LinuxBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.openssl = _openssl3()
        if self.openssl is None:
            self.skipTest("the Linux bootstrap regression test requires OpenSSL 3")

        self.temporary = tempfile.TemporaryDirectory(prefix="lomi-linux-bootstrap-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.fixtures = self.directory / "fixtures"
        self.fixtures.mkdir()
        self.private_key = self.directory / "bootstrap-private.pem"
        self.public_key = self.directory / "bootstrap-public.der"
        self._openssl("genpkey", "-algorithm", "Ed25519", "-out", str(self.private_key))
        self._openssl(
            "pkey", "-in", str(self.private_key), "-pubout", "-outform", "DER",
            "-out", str(self.public_key),
        )
        self.public_der = self.public_key.read_bytes()
        self.key_sha256 = hashlib.sha256(self.public_der).hexdigest()
        self.curl_log = self.directory / "curl-assets.log"

        self.tool_directories = {
            "python": self._make_tool_directory(include_unzip=False, include_python=True),
            "none": self._make_tool_directory(include_unzip=False, include_python=False),
        }
        try:
            self.tool_directories["unzip"] = self._make_tool_directory(
                include_unzip=True, include_python=False
            )
        except unittest.SkipTest:
            self.tool_directories["unzip"] = None
        self.available_extractors = ["python"]
        if self.tool_directories["unzip"] is not None:
            self.available_extractors.append("unzip")

    def _openssl(self, *arguments: str) -> None:
        result = subprocess.run(
            [str(self.openssl), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            result.stderr.decode(errors="replace"),
        )

    def _make_tool_directory(self, *, include_unzip: bool, include_python: bool) -> Path:
        directory = self.directory / (
            f"tools-unzip-{include_unzip}-python-{include_python}"
        )
        directory.mkdir()
        utilities = (
            "sha256sum", "mktemp", "mkdir", "rm", "head", "wc", "tr", "cmp", "cat"
        )
        for name in utilities:
            source = shutil.which(name)
            if source is None:
                raise unittest.SkipTest(f"test requires {name}")
            (directory / name).symlink_to(source)
        (directory / "openssl").symlink_to(self.openssl)

        fake_uname = directory / "uname"
        fake_uname.write_text(
            "#!/bin/sh\n"
            "case ${1-} in\n"
            "  -s) printf '%s\\n' Linux ;;\n"
            "  -m) printf '%s\\n' x86_64 ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake_uname.chmod(0o755)

        fake_curl = directory / "curl"
        fake_curl.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "for argument do url=$argument; done\n"
            "asset=${url##*/}\n"
            "printf '%s\\n' \"$asset\" >> \"$CURL_ASSET_LOG\"\n"
            "[ -f \"$CURL_FIXTURE_DIR/$asset\" ] || exit 22\n"
            "cat \"$CURL_FIXTURE_DIR/$asset\"\n",
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)

        if include_unzip:
            source = shutil.which("unzip")
            if source is None:
                raise unittest.SkipTest("test requires unzip")
            (directory / "unzip").symlink_to(source)
        if include_python:
            source = shutil.which("python3")
            if source is None:
                raise unittest.SkipTest("test requires python3")
            (directory / "python3").symlink_to(source)
        return directory

    def _write_zip(self, entries: list[tuple[str, bytes, int]]) -> bytes:
        archive_path = self.fixtures / ARCHIVE_NAME
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                for name, contents, mode in entries:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = (mode & 0xFFFF) << 16
                    archive.writestr(info, contents)
        return archive_path.read_bytes()

    def _regular_entry(self, name: str, contents: bytes, permissions: int = 0o644):
        return name, contents, stat.S_IFREG | permissions

    def _release_entries(self) -> list[tuple[str, bytes, int]]:
        return [
            self._regular_entry("install.sh", INSTALLER, 0o500),
            self._regular_entry("lomi-update-trust", UPDATER, 0o500),
            self._regular_entry("lomiremote", b"authenticated cli fixture\n", 0o500),
        ]

    def _prepare_release(
        self,
        *,
        entries: list[tuple[str, bytes, int]] | None = None,
        archive_bytes: bytes | None = None,
    ) -> bytes:
        if archive_bytes is None:
            archive_bytes = self._write_zip(entries if entries is not None else self._release_entries())
        (self.fixtures / ARCHIVE_NAME).write_bytes(archive_bytes)
        manifest = (
            "LOMI-LINUX-BOOTSTRAP-V1\n"
            f"platform={PLATFORM}\n"
            f"target={TARGET}\n"
            f"version={VERSION}\n"
            f"public-tuf-root-sha256={ROOT_SHA256}\n"
            f"archive={ARCHIVE_NAME}\n"
            f"archive-size={len(archive_bytes)}\n"
            f"archive-sha256={hashlib.sha256(archive_bytes).hexdigest()}\n"
        ).encode("ascii")
        manifest_path = self.fixtures / MANIFEST_NAME
        manifest_path.write_bytes(manifest)
        self._openssl(
            "pkeyutl", "-sign", "-rawin", "-inkey", str(self.private_key),
            "-in", str(manifest_path), "-out", str(self.fixtures / SIGNATURE_NAME),
        )
        (self.fixtures / PUBLIC_KEY_NAME).write_bytes(self.public_der)

        replacements = {
            "@@BOOTSTRAP_ORIGIN_SHELL@@": "https://example.test/releases/",
            "@@BOOTSTRAP_PLATFORM_SHELL@@": PLATFORM,
            "@@BOOTSTRAP_TARGET_SHELL@@": TARGET,
            "@@BOOTSTRAP_VERSION_SHELL@@": VERSION,
            "@@BOOTSTRAP_ROOT_SHA256_SHELL@@": ROOT_SHA256,
            "@@BOOTSTRAP_KEY_SHA256_SHELL@@": self.key_sha256,
            "@@BOOTSTRAP_ARCHIVE_NAME_SHELL@@": ARCHIVE_NAME,
            "@@BOOTSTRAP_ARCHIVE_SIZE_SHELL@@": str(len(archive_bytes)),
            "@@BOOTSTRAP_ARCHIVE_SHA256_SHELL@@": hashlib.sha256(archive_bytes).hexdigest(),
            "@@BOOTSTRAP_ARCHIVE_MAX_BYTES_SHELL@@": str(1024 * 1024 * 1024),
            "@@BOOTSTRAP_MANIFEST_NAME_SHELL@@": MANIFEST_NAME,
            "@@BOOTSTRAP_MANIFEST_SIZE_SHELL@@": str(len(manifest)),
            "@@BOOTSTRAP_SIGNATURE_NAME_SHELL@@": SIGNATURE_NAME,
            "@@BOOTSTRAP_PUBLIC_KEY_NAME_SHELL@@": PUBLIC_KEY_NAME,
        }
        rendered = TEMPLATE.read_text(encoding="utf-8")
        for placeholder, value in replacements.items():
            if placeholder.endswith(("_SIZE_SHELL@@", "_MAX_BYTES_SHELL@@")):
                replacement = value
            else:
                replacement = shlex.quote(value)
            rendered = rendered.replace(placeholder, replacement)
        self.assertNotIn("@@BOOTSTRAP_", rendered)
        script = self.directory / "linux-bootstrap.sh"
        script.write_text(rendered, encoding="utf-8")
        script.chmod(0o700)
        self.curl_log.unlink(missing_ok=True)
        return archive_bytes

    def _run_bootstrap(self, tool_set: str, *arguments: str, pythonpath: str | None = None):
        environment = os.environ.copy()
        environment.update({
            "PATH": str(self.tool_directories[tool_set]),
            "TMPDIR": str(self.directory),
            "CURL_FIXTURE_DIR": str(self.fixtures),
            "CURL_ASSET_LOG": str(self.curl_log),
        })
        if pythonpath is not None:
            environment["PYTHONPATH"] = pythonpath
        return subprocess.run(
            ["/bin/sh", str(self.directory / "linux-bootstrap.sh"), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )

    def test_authenticated_fixture_extracts_with_unzip_and_forwards_arguments(self) -> None:
        if self.tool_directories["unzip"] is None:
            self.skipTest("the unzip extraction test requires unzip")
        self._prepare_release()

        result = self._run_bootstrap(
            "unzip", "install", "--version", VERSION, "--install-dir",
            "/tmp/lomi bootstrap path", "--no-path",
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"UPDATER_EXECUTABLE", result.stdout)
        self.assertIn(b"INSTALL_ARG=<install>", result.stdout)
        self.assertIn(b"INSTALL_ARG=</tmp/lomi bootstrap path>", result.stdout)

    def test_authenticated_fixture_extracts_with_python_and_preserves_executable_modes(self) -> None:
        self._prepare_release()

        result = self._run_bootstrap(
            "python", "install", "--version", VERSION, "--install-dir",
            "/tmp/python fallback path", "--no-path",
        )

        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"UPDATER_EXECUTABLE", result.stdout)
        self.assertIn(b"INSTALL_ARG=<install>", result.stdout)
        self.assertIn(b"INSTALL_ARG=</tmp/python fallback path>", result.stdout)

    def test_python_fallback_ignores_pythonpath_module_shadowing(self) -> None:
        self._prepare_release()
        shadow = self.directory / "pythonpath-shadow"
        shadow.mkdir()
        (shadow / "zipfile.py").write_text(
            "raise RuntimeError('untrusted zipfile module loaded')\n", encoding="utf-8"
        )

        result = self._run_bootstrap("python", "install", pythonpath=str(shadow))

        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertIn(b"UPDATER_EXECUTABLE", result.stdout)

    def test_missing_extractors_fail_before_any_download(self) -> None:
        self._prepare_release()

        result = self._run_bootstrap("none", "install")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"either unzip or python3", result.stderr)
        self.assertFalse(self.curl_log.exists())

    def test_archive_digest_mismatch_never_extracts_or_runs_installer(self) -> None:
        archive_bytes = self._prepare_release()
        tampered = bytearray(archive_bytes)
        tampered[-1] ^= 1
        (self.fixtures / ARCHIVE_NAME).write_bytes(tampered)

        result = self._run_bootstrap("python", "install")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"release archive digest is invalid", result.stderr)
        self.assertNotIn(b"UPDATER_EXECUTABLE", result.stdout)
        self.assertNotIn(b"INSTALL_ARG", result.stdout)

    def test_malformed_zip_is_rejected_by_both_extractors(self) -> None:
        self._prepare_release(archive_bytes=b"not a ZIP archive\n")

        for tool_set in self.available_extractors:
            with self.subTest(extractor=tool_set):
                result = self._run_bootstrap(tool_set, "install")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b"UPDATER_EXECUTABLE", result.stdout)
                if tool_set == "unzip":
                    self.assertIn(b"not a valid ZIP file", result.stderr)
                else:
                    self.assertIn(b"Python ZIP extraction failed", result.stderr)

    def test_python_fallback_rejects_unsafe_entry_names_and_types(self) -> None:
        malicious_entries = {
            "traversal": self._regular_entry("../../lomi-bootstrap-escape", b"x"),
            "absolute": self._regular_entry(
                str(self.directory / "lomi-bootstrap-absolute-escape"), b"x"
            ),
            "drive_path": self._regular_entry("C:/lomi-bootstrap-escape", b"x"),
            "symlink": ("unsafe-link", b"install.sh", stat.S_IFLNK | 0o777),
            "special": ("unsafe-fifo", b"", stat.S_IFIFO | 0o600),
            "duplicate": self._regular_entry("payload", b"second copy"),
        }
        for name, malicious in malicious_entries.items():
            with self.subTest(entry=name):
                entries = self._release_entries()
                if name == "duplicate":
                    entries.extend([
                        self._regular_entry("payload", b"first copy"),
                        malicious,
                    ])
                else:
                    entries.append(malicious)
                self._prepare_release(entries=entries)

                result = self._run_bootstrap("python", "install")

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Python ZIP extraction failed", result.stderr)
                self.assertNotIn(b"UPDATER_EXECUTABLE", result.stdout)
                self.assertNotIn(b"INSTALL_ARG", result.stdout)
                self.assertFalse((self.directory / "lomi-bootstrap-escape").exists())
                self.assertFalse((self.directory / "lomi-bootstrap-absolute-escape").exists())

    def test_archive_without_required_updater_fails_closed(self) -> None:
        for tool_set in self.available_extractors:
            with self.subTest(extractor=tool_set):
                entries = [self._regular_entry("install.sh", INSTALLER, 0o500)]
                self._prepare_release(entries=entries)

                result = self._run_bootstrap(tool_set, "install")

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"lomi-update-trust", result.stderr)
                self.assertNotIn(b"INSTALL_ARG", result.stdout)

    def test_archive_without_required_installer_fails_closed(self) -> None:
        entries = [self._regular_entry("lomi-update-trust", UPDATER, 0o500)]
        self._prepare_release(entries=entries)

        result = self._run_bootstrap("python", "install")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"archive lacks install.sh", result.stderr)
        self.assertNotIn(b"UPDATER_EXECUTABLE", result.stdout)


if __name__ == "__main__":
    unittest.main()
