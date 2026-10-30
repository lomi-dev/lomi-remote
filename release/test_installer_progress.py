"""Focused checks for the public shell installer's download feedback."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

if os.name == "posix":
    import pty
    import select
else:
    pty = None
    select = None


ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "release" / "bootstrap" / "install.sh.in"
LINUX_BOOTSTRAP_TEMPLATE = ROOT / "release" / "linux-bootstrap.sh.in"
PREFLIGHT = b"#!/bin/sh\nprintf '%s\\n' 'PREFLIGHT_EXECUTED'\n"


@unittest.skipUnless(os.name == "posix", "the shell installer test requires POSIX")
class InstallerProgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="lomi-installer-progress-")
        self.directory = Path(self.temporary.name)
        self.bin_directory = self.directory / "bin"
        self.bin_directory.mkdir()
        self.payload_path = self.directory / "payload"
        self.payload_path.write_bytes(PREFLIGHT)
        self.curl_log = self.directory / "curl-arguments"

        fake_curl = self.bin_directory / "curl"
        fake_curl.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['CURL_ARGUMENTS_LOG'], 'w', encoding='utf-8') as log:\n"
            "    log.write('\\n'.join(args))\n"
            "with open(os.environ['CURL_PAYLOAD'], 'rb') as payload:\n"
            "    sys.stdout.buffer.write(payload.read())\n"
            "sys.stdout.flush()\n"
            "if '--progress-bar' in args:\n"
            "    sys.stderr.write('# simulated curl progress\\n')\n"
            "sys.exit(int(os.environ.get('CURL_EXIT_CODE', '0')))\n",
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)

        fake_uname = self.bin_directory / "uname"
        fake_uname.write_text(
            "#!/bin/sh\n"
            "case $1 in -s) printf '%s\\n' Linux ;; -m) printf '%s\\n' x86_64 ;; esac\n",
            encoding="utf-8",
        )
        fake_uname.chmod(0o755)

        fake_sha256sum = self.bin_directory / "sha256sum"
        fake_sha256sum.write_text(
            "#!/usr/bin/env python3\n"
            "import hashlib, sys\n"
            "with open(sys.argv[1], 'rb') as source:\n"
            "    print(hashlib.sha256(source.read()).hexdigest(), sys.argv[1])\n",
            encoding="utf-8",
        )
        fake_sha256sum.chmod(0o755)

        digest = hashlib.sha256(PREFLIGHT).hexdigest()
        target = (
            "        linux-x86_64) "
            "asset_url='https://example.test/releases/preflight.sh'; "
            f"asset_sha256='{digest}'; asset_size={len(PREFLIGHT)} ;;"
        )
        self.installer_path = self.directory / "install.sh"
        rendered = TEMPLATE.read_text(encoding="utf-8")
        rendered = rendered.replace("@@RELEASE_VERSION_SH@@", "'1.2.3'")
        rendered = rendered.replace("@@TARGETS_SH@@", target)
        self.installer_path.write_text(rendered, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_installer(
        self,
        *,
        terminal: bool,
        payload: bytes = PREFLIGHT,
        curl_exit_code: int = 0,
        term: str | None = None,
    ) -> tuple[int, bytes, bytes, list[str]]:
        self.payload_path.write_bytes(payload)
        environment = os.environ.copy()
        environment.update({
            "PATH": str(self.bin_directory) + os.pathsep + environment.get("PATH", ""),
            "TMPDIR": str(self.directory),
            "TERM": term if term is not None else ("xterm" if terminal else "dumb"),
            "NO_COLOR": "1",
            "CURL_PAYLOAD": str(self.payload_path),
            "CURL_ARGUMENTS_LOG": str(self.curl_log),
            "CURL_EXIT_CODE": str(curl_exit_code),
        })

        if not terminal:
            result = subprocess.run(
                ["/bin/sh", str(self.installer_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )
            return result.returncode, result.stdout, result.stderr, self._curl_arguments()

        master, slave = pty.openpty()
        try:
            process = subprocess.Popen(
                ["/bin/sh", str(self.installer_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=slave,
                env=environment,
            )
        finally:
            os.close(slave)

        terminal_output = bytearray()
        try:
            while process.poll() is None:
                readable, _, _ = select.select([master], [], [], 0.1)
                if readable:
                    try:
                        chunk = os.read(master, 4096)
                        if not chunk:
                            break
                        terminal_output.extend(chunk)
                    except OSError:
                        break
            while True:
                readable, _, _ = select.select([master], [], [], 0)
                if not readable:
                    break
                try:
                    chunk = os.read(master, 4096)
                    if not chunk:
                        break
                    terminal_output.extend(chunk)
                except OSError:
                    break
            returncode = process.wait(timeout=10)
            stdout = process.stdout.read() if process.stdout is not None else b""
            if process.stdout is not None:
                process.stdout.close()
        finally:
            os.close(master)
        return returncode, stdout, bytes(terminal_output), self._curl_arguments()

    def _curl_arguments(self) -> list[str]:
        return self.curl_log.read_text(encoding="utf-8").splitlines()

    def use_linux_download_helper(self, *, show_progress: bool = True) -> Path:
        template = LINUX_BOOTSTRAP_TEMPLATE.read_text(encoding="utf-8")
        start = template.index("download_bounded() {")
        end = template.index("\nfetch() {", start)
        helper = template[start:end]
        work = self.directory / "bootstrap-work"
        work.mkdir(exist_ok=True)
        destination = work / "archive.zip"
        script = (
            "#!/bin/sh\nset -eu\n"
            f"work={shlex.quote(str(work))}\n"
            "fail() { printf '%s\\n' \"Lomi Remote Linux bootstrap: $1\" >&2; exit 1; }\n"
            f"{helper}\n"
            f"download_bounded 'https://example.test/archive.zip' "
            f"{shlex.quote(str(destination))} {len(PREFLIGHT)} {1 if show_progress else 0}\n"
        )
        self.installer_path.write_text(script, encoding="utf-8")
        return destination

    def test_tty_download_uses_curl_progress_bar_and_runs_verified_preflight(self) -> None:
        returncode, stdout, stderr, arguments = self.run_installer(terminal=True)

        self.assertEqual(returncode, 0, stderr.decode(errors="replace"))
        self.assertIn("--progress-bar", arguments)
        self.assertIn(b"Fetching the Lomi Remote v1.2.3 installer for linux-x86_64", stderr)
        self.assertIn(b"# simulated curl progress", stderr)
        self.assertNotIn(b"\x1b", stderr)
        self.assertIn(b"PREFLIGHT_EXECUTED", stdout)

    def test_non_tty_keeps_plain_status_and_does_not_enable_progress_bar(self) -> None:
        returncode, stdout, stderr, arguments = self.run_installer(terminal=False)

        self.assertEqual(returncode, 0, stderr.decode(errors="replace"))
        self.assertNotIn("--progress-bar", arguments)
        self.assertIn("--silent", arguments)
        self.assertIn(b"Fetching the Lomi Remote v1.2.3 installer for linux-x86_64", stderr)
        self.assertNotIn(b"\x1b", stderr)
        self.assertIn(b"PREFLIGHT_EXECUTED", stdout)

    def test_dumb_tty_keeps_plain_curl_output(self) -> None:
        returncode, stdout, stderr, arguments = self.run_installer(terminal=True, term="dumb")

        self.assertEqual(returncode, 0, stderr.decode(errors="replace"))
        self.assertNotIn("--progress-bar", arguments)
        self.assertIn("--silent", arguments)
        self.assertIn(b"PREFLIGHT_EXECUTED", stdout)

    def test_failed_or_truncated_download_never_runs_preflight(self) -> None:
        failed = self.run_installer(terminal=False, curl_exit_code=22)
        truncated = self.run_installer(terminal=False, payload=PREFLIGHT[:-2])

        for returncode, stdout, stderr, _arguments in (failed, truncated):
            self.assertNotEqual(returncode, 0)
            self.assertNotIn(b"PREFLIGHT_EXECUTED", stdout)
            self.assertIn(b"Lomi Remote installer:", stderr)

    def test_linux_archive_helper_uses_tty_progress_and_captures_curl_failure(self) -> None:
        destination = self.use_linux_download_helper()
        returncode, _stdout, stderr, arguments = self.run_installer(terminal=True)
        self.assertEqual(returncode, 0, stderr.decode(errors="replace"))
        self.assertIn("--progress-bar", arguments)
        self.assertEqual(destination.read_bytes(), PREFLIGHT)

        self.use_linux_download_helper()
        failed = self.run_installer(terminal=False, curl_exit_code=22)
        truncated = self.run_installer(terminal=False, payload=PREFLIGHT[:-2])
        for result in (failed, truncated):
            self.assertNotEqual(result[0], 0)
            self.assertIn(b"Lomi Remote Linux bootstrap:", result[2])

    def test_linux_metadata_helper_keeps_progress_disabled_even_on_tty(self) -> None:
        self.use_linux_download_helper(show_progress=False)
        returncode, _stdout, stderr, arguments = self.run_installer(terminal=True)

        self.assertEqual(returncode, 0, stderr.decode(errors="replace"))
        self.assertNotIn("--progress-bar", arguments)


if __name__ == "__main__":
    unittest.main()
