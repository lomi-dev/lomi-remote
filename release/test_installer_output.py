"""Hermetic checks for the rendered inner POSIX installer's status output."""
from __future__ import annotations

import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "release" / "install.sh.in"
VERSION = "1.2.3"
TEAM_ID = "TESTTEAM"
ROOT_PIN = "a" * 64


@unittest.skipUnless(os.name == "posix", "the inner installer test requires POSIX")
class InstallerOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="lomi-inner-installer-output-")
        self.directory = Path(self.temporary.name)
        self.bundle = self.directory / "bundle"
        self.bundle.mkdir()
        self.bin_directory = self.directory / "bin"
        self.bin_directory.mkdir()

        self.support_base = self.directory / "Application Support"
        self.support_base.mkdir()
        self.profile_dir = self.directory / "selected-account-profile"
        self.profile_dir.mkdir()
        self.install_dir = self.support_base / "LomiRemote" / "Install" / "selected-account"
        self.cli_path = self.install_dir / "lomiremote"
        self.actual_cli_path = self.cli_path.resolve()
        self.cli_log = self.directory / "cli-arguments.log"

        rendered = TEMPLATE.read_text(encoding="utf-8")
        replacements = {
            "@@RELEASE_ORIGIN_SHELL@@": "'https://example.test/releases'",
            "@@VERSION_SHELL@@": f"'{VERSION}'",
            "@@TARGET_NAME_SHELL@@": "'lomi-macos-arm64.tar.zst'",
            "@@PLATFORM_SHELL@@": "'macos-aarch64'",
            "@@ROOT_SHA256_SHELL@@": f"'{ROOT_PIN}'",
            "@@TEAM_ID_SHELL@@": f"'{TEAM_ID}'",
            "base='/Library/Application Support'": f"base='{self.support_base}'",
        }
        for placeholder, value in replacements.items():
            self.assertIn(placeholder, rendered)
            rendered = rendered.replace(placeholder, value)
        self.installer_path = self.bundle / "install.sh"
        self.installer_path.write_text(rendered, encoding="utf-8")
        self.installer_path.chmod(0o700)

        updater = self.bundle / "lomi-update-trust"
        cli_source = """#!/usr/bin/env python3
import os
import sys

args = sys.argv[1:]
with open(os.environ["FIXTURE_CLI_LOG"], "a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\\n")
if "service" in args:
    operation = args[args.index("service") + 1]
    exit_code = int(os.environ.get("SERVICE_" + operation.upper() + "_EXIT", "0"))
    if exit_code:
        print("native service " + operation + " failure", file=sys.stderr)
        raise SystemExit(exit_code)
"""
        updater_source = """#!/usr/bin/env python3
import os
import pathlib
import sys

args = sys.argv[1:]
command = args[0] if args else ""
root_pin = %r
cli_source = %r
if command == "root-pin":
    print(root_pin)
elif command == "admin-macos-install-dir":
    print(os.environ["FIXTURE_INSTALL_DIR"])
elif command == "admin-macos-profile":
    print(os.environ["FIXTURE_PROFILE_DIR"])
elif command == "admin-boot-recovery-needed":
    print("clear")
elif command == "initialize-release":
    pathlib.Path(args[1]).mkdir(parents=True, exist_ok=True)
elif command == "install-release-admin-boot":
    install_dir = pathlib.Path(args[5])
    cli = install_dir / "lomiremote"
    cli.write_text(cli_source, encoding="utf-8")
    cli.chmod(0o755)
    print('{"activeObject":{"version":"1.2.3"}}')
elif command in ("validate-admin-boot-install-dir", "bind-admin-boot-profile", "status-release", "uninstall-release-admin-boot"):
    pass
else:
    print("unexpected updater command: " + command, file=sys.stderr)
    raise SystemExit(2)
""" % (ROOT_PIN, cli_source)
        updater.write_text(updater_source, encoding="utf-8")
        updater.chmod(0o700)

        self._write_executable(
            self.bin_directory / "codesign",
            "#!/bin/sh\n"
            "case $1 in\n"
            "  -dv) printf 'TeamIdentifier=TESTTEAM\\n' >&2 ;;\n"
            "  --verify) exit 0 ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
        )
        self._write_executable(
            self.bin_directory / "id",
            "#!/bin/sh\n[ \"$1\" = -u ] || exit 2\nprintf '0\\n'\n",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_executable(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o700)

    def run_installer(
        self,
        *,
        tty: bool = False,
        no_color: bool = False,
        service_install_exit: int = 0,
        service_start_exit: int = 0,
    ) -> tuple[int, bytes, bytes]:
        environment = os.environ.copy()
        environment.update({
            "PATH": str(self.bin_directory) + os.pathsep + environment.get("PATH", ""),
            "HOME": str(self.directory),
            "TERM": "xterm" if tty else "dumb",
            "FIXTURE_INSTALL_DIR": str(self.install_dir),
            "FIXTURE_PROFILE_DIR": str(self.profile_dir),
            "FIXTURE_CLI_LOG": str(self.cli_log),
            "SERVICE_INSTALL_EXIT": str(service_install_exit),
            "SERVICE_START_EXIT": str(service_start_exit),
        })
        environment.pop("NO_COLOR", None)
        if no_color:
            environment["NO_COLOR"] = "1"

        if not tty:
            result = subprocess.run(
                ["/bin/sh", str(self.installer_path), "admin-install", "fixture-account", "boot"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )
            return result.returncode, result.stdout, result.stderr

        master, slave = pty.openpty()
        try:
            process = subprocess.Popen(
                ["/bin/sh", str(self.installer_path), "admin-install", "fixture-account", "boot"],
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
                    except OSError:
                        break
                    if not chunk:
                        break
                    terminal_output.extend(chunk)
            while True:
                readable, _, _ = select.select([master], [], [], 0)
                if not readable:
                    break
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                terminal_output.extend(chunk)
            returncode = process.wait(timeout=10)
            stdout = process.stdout.read() if process.stdout is not None else b""
            if process.stdout is not None:
                process.stdout.close()
        finally:
            os.close(master)
        return returncode, stdout, bytes(terminal_output)

    def assert_no_activation_json_on_stdout(self, stdout: bytes) -> None:
        self.assertNotIn(b"activeObject", stdout)

    def test_boot_success_reports_actual_cli_path_and_progress(self) -> None:
        returncode, stdout, stderr = self.run_installer()

        self.assertEqual(returncode, 0, stderr.decode(errors="replace"))
        self.assert_no_activation_json_on_stdout(stdout)
        self.assertIn(b"Verifying and installing Lomi Remote v1.2.3", stderr)
        self.assertIn(b"Configuring the macOS boot service", stderr)
        self.assertIn(b"Starting Lomi Remote...", stderr)
        self.assertIn(f"Installed Lomi Remote v{VERSION} to {self.actual_cli_path}.".encode(), stderr)
        self.assertIn(str(self.actual_cli_path).encode(), stdout)
        self.assertNotIn(b"\x1b", stderr)

    def test_no_color_tty_success_keeps_completion_message_plain(self) -> None:
        returncode, _stdout, stderr = self.run_installer(tty=True, no_color=True)

        self.assertEqual(returncode, 0, stderr.decode(errors="replace"))
        self.assertIn(f"Installed Lomi Remote v{VERSION} to {self.actual_cli_path}.".encode(), stderr)
        self.assertNotIn(b"\x1b", stderr)

    def test_service_install_failure_keeps_native_error_and_program_path(self) -> None:
        returncode, stdout, stderr = self.run_installer(service_install_exit=27)

        self.assertNotEqual(returncode, 0)
        self.assert_no_activation_json_on_stdout(stdout)
        self.assertIn(b"native service install failure", stderr)
        self.assertIn(str(self.actual_cli_path).encode(), stderr)
        self.assertNotIn(b"Installed Lomi Remote", stderr)
        self.assertNotIn(b"\x1b", stderr)

    def test_service_start_failure_keeps_native_error_and_never_reports_success(self) -> None:
        returncode, stdout, stderr = self.run_installer(service_start_exit=29)

        self.assertNotEqual(returncode, 0)
        self.assert_no_activation_json_on_stdout(stdout)
        self.assertIn(b"native service start failure", stderr)
        self.assertNotIn(b"Installed Lomi Remote", stderr)
        self.assertNotIn(b"Host is running (boot mode)", stderr)
        self.assertNotIn(b"\x1b", stderr)


if __name__ == "__main__":
    unittest.main()
