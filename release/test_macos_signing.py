"""Mocked regression tests for macOS signing and notarization."""

from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

import macos_signing


DEFAULT_IDENTITY = "74BA50CC483B0CF55535C3EA70F8A88A7A938629"
DEFAULT_TEAM_ID = "C9JMAQ7GG3"
DEFAULT_PROFILE = "lomi-remote-notarization"
ACCEPTED_SUBMISSION = "4d3f4a69-c612-4c94-9d25-e80e6f2d8301"
IDENTITY_OUTPUT = (
    f'1) {DEFAULT_IDENTITY} "Developer ID Application: Lomi ({DEFAULT_TEAM_ID})"\n'
)
SIGNATURE_DETAILS = (
    "Authority=Developer ID Application: Lomi (C9JMAQ7GG3)\n"
    "TeamIdentifier=C9JMAQ7GG3\n"
    "Timestamp=2026-10-29T12:00:00Z\n"
)


def completed(command, *, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def write_zip(path: Path, payload: bytes = b"archive payload") -> bytes:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.bin", payload)
    return path.read_bytes()


class MacOSSigningTests(unittest.TestCase):
    def config(self, **overrides):
        values = {
            "identity": DEFAULT_IDENTITY,
            "team_id": DEFAULT_TEAM_ID,
            "notary_profile": DEFAULT_PROFILE,
            "keychain": None,
            "timeout_seconds": 1800,
        }
        values.update(overrides)
        return macos_signing.MacOSSigningConfig(**values)

    @contextlib.contextmanager
    def mocked_macos(self):
        with (
            mock.patch.object(macos_signing.platform, "system", return_value="Darwin"),
            mock.patch.object(macos_signing.shutil, "which", return_value="/usr/bin/mock-tool"),
        ):
            yield

    def test_cli_config_uses_explicit_values_then_environment_then_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "signing.json"
            config_path.write_text(
                json.dumps(
                    {
                        "format": 1,
                        "identity": "C" * 40,
                        "team_id": "JSONTEAM12",
                        "notary_profile": "json-profile",
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                "LOMI_MACOS_SIGNING_IDENTITY": "B" * 40,
                "LOMI_MACOS_TEAM_ID": "ENVTEAM123",
                "LOMI_MACOS_NOTARY_PROFILE": "environment-profile",
                "LOMI_MACOS_KEYCHAIN": "/tmp/environment.keychain-db",
            }
            observed = []
            output = io.StringIO()
            with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
                macos_signing,
                "preflight",
                side_effect=lambda config, **kwargs: observed.append(config) or {"checked": True},
            ), contextlib.redirect_stdout(output):
                status = macos_signing.main(
                    ["check", "--config", str(config_path), "--identity", "A" * 40]
                )

        self.assertEqual(status, 0)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0].identity, "A" * 40)
        self.assertEqual(observed[0].team_id, "ENVTEAM123")
        self.assertEqual(observed[0].notary_profile, "environment-profile")
        self.assertEqual(observed[0].keychain, Path("/tmp/environment.keychain-db"))
        self.assertEqual(json.loads(output.getvalue()), {"checked": True})

    def test_default_config_uses_public_defaults_without_credentials(self):
        names = (
            "LOMI_MACOS_SIGNING_IDENTITY",
            "LOMI_MACOS_TEAM_ID",
            "LOMI_MACOS_NOTARY_PROFILE",
            "LOMI_MACOS_KEYCHAIN",
        )
        with mock.patch.dict(os.environ, {}, clear=False):
            for name in names:
                os.environ.pop(name, None)
            configured = macos_signing.load_config(
                config_path=Path(__file__).with_name("macos-signing.json")
            )

        self.assertEqual(configured.identity, DEFAULT_IDENTITY)
        self.assertEqual(configured.team_id, DEFAULT_TEAM_ID)
        self.assertEqual(configured.notary_profile, DEFAULT_PROFILE)
        self.assertNotIn("password", repr(configured).lower())
        self.assertNotIn("privatekey", repr(configured).lower())

    def test_preflight_rejects_identity_with_wrong_team(self):
        other_team_identity = (
            f'1) {DEFAULT_IDENTITY} "Developer ID Application: Other Org (OTHERTEAM12)"\n'
        )
        with self.mocked_macos(), mock.patch.object(
            macos_signing,
            "_run",
            return_value=completed(["security"], stdout=other_team_identity),
        ):
            with self.assertRaises(macos_signing.MacOSSigningError):
                macos_signing.preflight(self.config(), check_notary=False)

    def test_preflight_rejects_ambiguous_identity_names(self):
        name = "Developer ID Application: Lomi (C9JMAQ7GG3)"
        ambiguous = (
            '1) 1111111111111111111111111111111111111111 '
            f'"{name}"\n'
            '2) 2222222222222222222222222222222222222222 '
            f'"{name}"\n'
        )
        config = self.config(identity=name)
        with self.mocked_macos(), mock.patch.object(
            macos_signing,
            "_run",
            return_value=completed(["security"], stdout=ambiguous),
        ):
            with self.assertRaisesRegex(macos_signing.MacOSSigningError, "ambiguous"):
                macos_signing.preflight(config, check_notary=False)

    def test_cli_missing_notary_profile_does_not_print_private_credentials(self):
        private_marker = "PRIVATE-CREDENTIAL-MUST-NOT-LEAK"
        responses = [
            completed(["security"], stdout=IDENTITY_OUTPUT),
            completed(
                ["xcrun"],
                stdout=private_marker,
                stderr=f"profile not found: {private_marker}",
                returncode=1,
            ),
        ]
        output = io.StringIO()
        with self.mocked_macos(), mock.patch.object(
            macos_signing, "_run", side_effect=responses
        ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = macos_signing.main(["check"])

        self.assertEqual(status, 1)
        self.assertNotIn(private_marker, output.getvalue())

    def test_signing_uses_strict_verification_and_restores_readonly_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "install.sh"
            script.write_bytes(b"#!/bin/sh\nexit 0\n")
            script.chmod(0o500)
            calls = []

            def fake_run(command, **kwargs):
                calls.append(list(command))
                if command[0] == "security":
                    return completed(command, stdout=IDENTITY_OUTPUT)
                if command[:3] == ["codesign", "-dv", "--verbose=4"]:
                    return completed(command, stderr=SIGNATURE_DETAILS)
                return completed(command)

            with self.mocked_macos(), mock.patch.object(
                macos_signing, "_run", side_effect=fake_run
            ):
                macos_signing.sign_file(script, self.config())

            self.assertEqual(script.stat().st_mode & 0o777, 0o500)
            self.assertTrue(any(command[:2] == ["codesign", "--force"] for command in calls))
            self.assertTrue(
                any("--verify" in command and "--strict" in command for command in calls),
                calls,
            )
            self.assertTrue(any("--sign" in command for command in calls), calls)

    def test_signing_failure_restores_original_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "install.sh"
            script.write_bytes(b"#!/bin/sh\nexit 0\n")
            script.chmod(0o400)

            def fake_run(command, **kwargs):
                if command[0] == "security":
                    return completed(command, stdout=IDENTITY_OUTPUT)
                if command[:2] == ["codesign", "--force"]:
                    raise macos_signing.MacOSSigningError("mock signing failure")
                return completed(command)

            with self.mocked_macos(), mock.patch.object(
                macos_signing, "_run", side_effect=fake_run
            ):
                with self.assertRaises(macos_signing.MacOSSigningError):
                    macos_signing.sign_file(script, self.config())

            self.assertEqual(script.stat().st_mode & 0o777, 0o400)

    def test_signing_rejects_a_valid_signature_from_the_wrong_team(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "lomiremote"
            binary.write_bytes(b"executable bytes")

            def fake_run(command, **kwargs):
                if command[0] == "security":
                    return completed(command, stdout=IDENTITY_OUTPUT)
                if command[:3] == ["codesign", "-dv", "--verbose=4"]:
                    return completed(
                        command,
                        stderr=SIGNATURE_DETAILS.replace(DEFAULT_TEAM_ID, "OTHERTEAM12"),
                    )
                return completed(command)

            with self.mocked_macos(), mock.patch.object(
                macos_signing, "_run", side_effect=fake_run
            ):
                with self.assertRaisesRegex(macos_signing.MacOSSigningError, "Team ID"):
                    macos_signing.sign_file(binary, self.config())

    def test_notarization_requires_accepted_status_valid_uuid_and_unchanged_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.zip"
            original = write_zip(archive, b"zip payload stays byte-for-byte unchanged")
            accepted = json.dumps({"status": "Accepted", "id": ACCEPTED_SUBMISSION})
            with mock.patch.object(
                macos_signing,
                "_run",
                return_value=completed(["xcrun"], stdout=accepted),
            ):
                receipt = macos_signing.notarize_archive(archive, self.config())

            self.assertEqual(archive.read_bytes(), original)
            self.assertEqual(receipt["archive_sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(receipt["submission_id"], ACCEPTED_SUBMISSION)
            self.assertEqual(receipt["status"], "Accepted")
            receipt_path = Path(str(archive) + ".notarization.json")
            self.assertEqual(json.loads(receipt_path.read_text(encoding="utf-8")), receipt)

    def test_notarization_rejects_zero_exit_without_accepted_status_or_valid_uuid(self):
        bad_results = (
            json.dumps({"status": "Accepted", "id": "not-a-uuid"}),
            json.dumps({"status": "In Progress", "id": ACCEPTED_SUBMISSION}),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, result in enumerate(bad_results):
                with self.subTest(result=result):
                    archive = Path(temporary) / f"release-{index}.zip"
                    write_zip(archive)
                    with mock.patch.object(
                        macos_signing,
                        "_run",
                        return_value=completed(["xcrun"], stdout=result),
                    ):
                        with self.assertRaises(macos_signing.MacOSSigningError):
                            macos_signing.notarize_archive(archive, self.config())

    def test_notarization_rejection_and_timeout_return_cli_failure(self):
        rejected = json.dumps({"status": "Invalid", "id": ACCEPTED_SUBMISSION})
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.zip"
            write_zip(archive)
            output = io.StringIO()
            with mock.patch.object(macos_signing, "preflight"), mock.patch.object(
                macos_signing,
                "_run",
                return_value=completed(["xcrun"], stdout=rejected),
            ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                status = macos_signing.main(["notarize", str(archive)])
            self.assertEqual(status, 1)
            self.assertIn(ACCEPTED_SUBMISSION, output.getvalue())

            timed_archive = Path(temporary) / "timed-out.zip"
            write_zip(timed_archive)
            output = io.StringIO()
            with mock.patch.object(macos_signing, "preflight"), mock.patch.object(
                macos_signing,
                "_run",
                side_effect=macos_signing.MacOSSigningError("notarytool timed out"),
            ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                status = macos_signing.main(["notarize", str(timed_archive)])
            self.assertEqual(status, 1)
            self.assertIn("timed out", output.getvalue())

    def test_overlapping_notarizations_submit_only_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.zip"
            write_zip(archive)
            entered = threading.Event()
            release = threading.Event()
            submissions = []

            def fake_run(command, **kwargs):
                submissions.append(command)
                entered.set()
                self.assertTrue(release.wait(5))
                return completed(command, stdout=json.dumps({"status": "Accepted", "id": ACCEPTED_SUBMISSION}))

            with mock.patch.object(macos_signing, "_run", side_effect=fake_run), ThreadPoolExecutor(max_workers=1) as executor:
                first = executor.submit(macos_signing.notarize_archive, archive, self.config())
                try:
                    self.assertTrue(entered.wait(5))
                    with self.assertRaisesRegex(macos_signing.MacOSSigningError, "reserved"):
                        macos_signing.notarize_archive(archive, self.config())
                finally:
                    release.set()
                self.assertEqual(first.result(timeout=5)["status"], "Accepted")
            self.assertEqual(len(submissions), 1)
            self.assertFalse(Path(str(archive) + ".notarization.pending").exists())

    def test_interrupted_submission_retains_reservation_before_any_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.zip"
            write_zip(archive)
            with mock.patch.object(macos_signing, "_run", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    macos_signing.notarize_archive(archive, self.config())
            self.assertTrue(Path(str(archive) + ".notarization.pending").is_file())
            with mock.patch.object(macos_signing, "_run") as run:
                with self.assertRaisesRegex(macos_signing.MacOSSigningError, "reserved"):
                    macos_signing.notarize_archive(archive, self.config())
                run.assert_not_called()

    def test_accepted_submission_cannot_approve_changed_archive_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "release.zip"
            write_zip(archive)

            def fake_run(command, **kwargs):
                if "submit" in command:
                    write_zip(archive, b"changed content")
                return completed(command, stdout=json.dumps({"status": "Accepted", "id": ACCEPTED_SUBMISSION}))

            with mock.patch.object(macos_signing, "_run", side_effect=fake_run):
                with self.assertRaisesRegex(macos_signing.MacOSSigningError, "ArchiveChanged"):
                    macos_signing.notarize_archive(archive, self.config())
            receipt = json.loads(Path(str(archive) + ".notarization.json").read_text())
            self.assertEqual(receipt["status"], "ArchiveChanged")

    def test_bounded_runner_times_out_and_rejects_excessive_output(self):
        sleeper = [sys.executable, "-c", "import time; time.sleep(5)"]
        started = time.monotonic()
        with self.assertRaisesRegex(macos_signing.MacOSSigningError, "timed out"):
            macos_signing._run(sleeper, timeout=0.1)
        self.assertLess(time.monotonic() - started, 2)

        noisy = [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1100000)"]
        with self.assertRaisesRegex(macos_signing.MacOSSigningError, "output limit"):
            macos_signing._run(noisy, timeout=5)


if __name__ == "__main__":
    unittest.main()
