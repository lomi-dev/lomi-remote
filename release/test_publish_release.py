"""Offline integration tests for authenticated release assembly and refresh."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import build_release
import publish_release
import trust


REVISION = "a" * 40
TAG = "v1.2.3"
VERSION = TAG[1:]
PLATFORM = "linux-x86_64"
ORIGIN = trust.ORIGIN
ARTIFACT_ORIGIN = ORIGIN + TAG + "/"
TARGET_NAME = "linux/x86_64/lomiremote"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: dict) -> bytes:
    data = trust.canonical(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


class PublisherFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lomi-publish-test-")
        self.base = Path(self.temporary.name)
        self.private = self.base / "private"
        self.private.mkdir(mode=0o700)
        self.private.chmod(0o700)
        self.public = self.base / "public"
        self.config = trust.initialize(self.private, self.public)
        self.bundle = self.base / "bundles" / PLATFORM
        (self.bundle / "bundle" / "targets" / "linux" / "x86_64").mkdir(parents=True)
        self.archive_name = f"lomi-remote-{PLATFORM}-{VERSION}.zip"
        self.archive = self.bundle / self.archive_name
        self.target_bytes = b"synthetic target bytes; never executed\n"
        self.target = self.bundle / "bundle" / "targets" / TARGET_NAME
        self.target.write_bytes(self.target_bytes)

        payloads = {
            "lomiremote": b"synthetic CLI bytes; never executed\n",
            "lomi-update-trust": b"synthetic updater bytes; never executed\n",
            "install.sh": b"#!/bin/sh\n# synthetic installer; never executed\n",
            "source-manifest.json": b'{"format":1,"synthetic":true}\n',
            "targets/" + TARGET_NAME: self.target_bytes,
        }
        for name, contents in payloads.items():
            path = self.bundle / "bundle" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)

        policy = {
            "format": 1,
            "platform": PLATFORM,
            "version": VERSION,
            "minProfileSchema": 0,
            "maxProfileSchema": 1,
        }
        manifest_value = {
            "sourceRevision": REVISION,
            "version": VERSION,
            "platform": PLATFORM,
            "releaseOrigin": ORIGIN,
            "artifactOrigin": ARTIFACT_ORIGIN,
            "publicTufRootSha256": self.config["root_sha256"],
            "tufTargetName": TARGET_NAME,
            "tufTargetCustom": {"lomiRelease": policy},
            "files": {name: digest(contents) for name, contents in payloads.items()},
        }
        self.manifest_path = self.bundle / "bundle" / "build-manifest.json"
        manifest_bytes = write_json(self.manifest_path, manifest_value)
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, contents in payloads.items():
                archive.writestr(name, contents)
            archive.writestr("build-manifest.json", manifest_bytes)

        root_path = self.public / self.config["root_file"]
        root_bytes = root_path.read_bytes()
        (self.bundle / root_path.name).write_bytes(root_bytes)
        root_artifact = {
            "url": ARTIFACT_ORIGIN + root_path.name,
            "sha256": digest(root_bytes),
            "size": len(root_bytes),
        }
        archive_data = self.archive.read_bytes()
        archive_artifact = {
            "url": ORIGIN + self.archive_name,
            "sha256": digest(archive_data),
            "size": len(archive_data),
        }

        bootstrap_base = self.archive.with_suffix("").name
        public_key = (self.public / self.config["linux_bootstrap_public_key_file"]).read_bytes()
        openssl_dir = str(Path(trust._openssl()).resolve().parent)
        with mock.patch.dict(os.environ, {"PATH": openssl_dir + os.pathsep + os.environ.get("PATH", "")}):
            build_release.create_linux_bootstrap_outputs(
                output=self.bundle,
                archive=self.archive,
                platform=PLATFORM,
                target_name=TARGET_NAME,
                version=VERSION,
                root_sha256=self.config["root_sha256"],
                release_origin=ARTIFACT_ORIGIN,
                public_key=public_key,
                public_key_sha256=self.config["linux_bootstrap_key_sha256"],
                signing_key_path=self.private / "linux-bootstrap.pem",
                signing_key_passphrase=None,
            )
        build_release.create_installation_entry(
            self.bundle,
            self.archive,
            PLATFORM,
            VERSION,
            ARTIFACT_ORIGIN,
            root_path,
            self.config["root_sha256"],
        )
        self.bundles = self.base / "bundles"
        self.output = self.base / "assembled"

    def tearDown(self):
        self.temporary.cleanup()

    def assemble(self, **kwargs):
        return publish_release.assemble(
            self.bundles,
            kwargs.pop("output", self.output),
            kwargs.pop("tag", TAG),
            kwargs.pop("revision", REVISION),
            self.private,
            self.public,
            **kwargs,
        )

    def assert_rejected(self, **kwargs):
        with self.assertRaises(trust.TrustError):
            self.assemble(**kwargs)


class AssembleTests(PublisherFixture):
    def test_assembles_authenticated_linux_release_and_pinned_installers(self):
        index = self.assemble()
        root_document = trust.loads((self.public / self.config["root_file"]).read_bytes())
        root = root_document["signed"]
        self.assertIs(trust.verify_metadata(root_document, root, "root"), root)

        index_bytes = (self.output / "release-index.json").read_bytes()
        envelope = trust.loads(index_bytes)
        self.assertEqual(set(envelope), {"signed", "signature"})
        self.assertEqual(trust.canonical(envelope), index_bytes)
        index_signature = base64.b64decode(envelope["signature"], validate=True)
        index_public = {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {"public": base64.b64decode(self.config["index_public_key_base64"]).hex()},
        }
        self.assertTrue(trust.verify_bytes(trust.canonical(index), index_signature, index_public))
        self.assertEqual((self.output / "release-index.sig").read_bytes(), index_signature)
        self.assertEqual(envelope["signed"], index)
        self.assertEqual(index["platforms"], [PLATFORM])
        self.assertEqual(index["tag"], TAG)
        self.assertEqual(index["version"], VERSION)

        metadata = {}
        for role in ("targets", "snapshot", "timestamp"):
            logical = f"metadata/{role}.json"
            path = self.output / index["files"][logical]["asset"]
            raw = path.read_bytes()
            record = index["files"][logical]
            self.assertEqual(record["size"], len(raw))
            self.assertEqual(record["sha256"], digest(raw))
            document = trust.loads(raw)
            metadata[role] = trust.verify_metadata(document, root, role)

        targets_bytes = (self.output / index["files"]["metadata/targets.json"]["asset"]).read_bytes()
        snapshot_bytes = (self.output / index["files"]["metadata/snapshot.json"]["asset"]).read_bytes()
        self.assertEqual(metadata["snapshot"]["meta"]["targets.json"]["length"], len(targets_bytes))
        self.assertEqual(metadata["snapshot"]["meta"]["targets.json"]["hashes"]["sha256"], digest(targets_bytes))
        self.assertEqual(metadata["timestamp"]["meta"]["snapshot.json"]["length"], len(snapshot_bytes))
        self.assertEqual(metadata["timestamp"]["meta"]["snapshot.json"]["hashes"]["sha256"], digest(snapshot_bytes))

        target = metadata["targets"]["targets"][TARGET_NAME]
        self.assertEqual(target["length"], len(self.target_bytes))
        self.assertEqual(target["hashes"]["sha256"], digest(self.target_bytes))
        self.assertEqual(target["custom"]["lomiRelease"]["platform"], PLATFORM)

        for logical, record in index["files"].items():
            asset_path = self.output / record["asset"]
            self.assertTrue(asset_path.is_file(), logical)
            self.assertEqual(record["size"], asset_path.stat().st_size, logical)
            self.assertEqual(record["sha256"], digest(asset_path.read_bytes()), logical)

        shell = (self.output / "install.sh").read_text(encoding="utf-8")
        powershell = (self.output / "install.ps1").read_text(encoding="utf-8")
        self.assertIn(ARTIFACT_ORIGIN + self.archive.with_suffix("").name + ".install.sh", shell)
        self.assertIn(digest((self.bundle / (self.archive.with_suffix("").name + ".install.sh")).read_bytes()), shell)
        self.assertNotRegex(shell, r"(?im)^\s*eval(?:\s|$)")
        self.assertNotRegex(powershell, r"(?im)^\s*(?:iex|Invoke-Expression)(?:\s|$)")
        self.assertNotIn("@@", shell + powershell)
        self.assertNotIn("windows-x86_64", "\n".join(index["platforms"]))

    def test_requires_stable_tag_source_and_exact_platform_completeness(self):
        self.assert_rejected(tag="1.2.3")
        self.assert_rejected(revision="not-a-commit")
        self.assert_rejected(expected_platforms={PLATFORM, "linux-aarch64"})

    def test_rejects_public_root_pin_mismatch(self):
        config_path = self.public / "release-public.json"
        config = trust.loads(config_path.read_bytes())
        config["root_sha256"] = "0" * 64
        write_json(config_path, config)
        self.assert_rejected()

    def test_rejects_archive_and_target_mutations(self):
        original_archive = self.archive.read_bytes()
        self.archive.write_bytes(original_archive + b"mutated")
        self.assert_rejected()
        self.archive.write_bytes(original_archive)

        self.target.write_bytes(self.target_bytes + b"mutated")
        self.assert_rejected()

    def test_rejects_archive_payload_mutation_even_when_archive_digest_is_updated(self):
        with zipfile.ZipFile(self.archive, "r") as archive:
            contents = {item.filename: archive.read(item) for item in archive.infolist()}
        contents["lomiremote"] += b"tampered"
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in contents.items():
                archive.writestr(name, data)

        entry_path = self.bundle / "installation-entry.json"
        entry = trust.loads(entry_path.read_bytes())
        archive_bytes = self.archive.read_bytes()
        entry["archive"]["sha256"] = digest(archive_bytes)
        entry["archive"]["size"] = len(archive_bytes)
        write_json(entry_path, entry)
        self.assert_rejected()


class RefreshTests(PublisherFixture):
    def setUp(self):
        super().setUp()
        self.index = self.assemble()
        self.release_files = {
            record["asset"]: self.output / record["asset"]
            for record in self.index["files"].values()
        }
        self.release_files["release-index.json"] = self.output / "release-index.json"
        self.release_files["release-index-recovery.json"] = self.output / "release-index-recovery.json"
        self.release_files["release-index.sig"] = self.output / "release-index.sig"

    def mock_downloads(self, mutate=None, calls=None):
        def download(_tag, name, directory, _repo):
            if calls is not None:
                calls.append(name)
            source = self.release_files[name]
            if mutate and name in mutate:
                changed = directory / name
                changed.write_bytes(mutate[name](source.read_bytes()))
                return changed
            return source

        return download

    def assert_index_signature_valid(self, raw):
        envelope = trust.loads(raw)
        public = {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {"public": base64.b64decode(self.config["index_public_key_base64"]).hex()},
        }
        self.assertTrue(trust.verify_bytes(
            trust.canonical(envelope["signed"]),
            base64.b64decode(envelope["signature"], validate=True),
            public,
        ))
        return envelope["signed"]

    def test_refresh_authenticates_previous_inventory_and_preserves_target_hashes(self):
        previous_targets = trust.verify_metadata(
            trust.loads((self.output / self.index["files"]["metadata/targets.json"]["asset"]).read_bytes()),
            trust.loads((self.public / self.config["root_file"]).read_bytes())["signed"],
            "targets",
        )
        refreshed_output = self.base / "refreshed"
        with mock.patch.object(publish_release, "gh_download", side_effect=self.mock_downloads()):
            refreshed = publish_release.refresh(TAG, refreshed_output, self.private, self.public)

        self.assertEqual(refreshed["platforms"], self.index["platforms"])
        self.assertEqual(refreshed["files"]["targets/" + TARGET_NAME], self.index["files"]["targets/" + TARGET_NAME])
        for logical in ("metadata/targets.json", "metadata/snapshot.json", "metadata/timestamp.json"):
            self.assertNotEqual(refreshed["files"][logical]["asset"], self.index["files"][logical]["asset"])
            self.assertEqual(refreshed["files"][logical]["sha256"], digest((refreshed_output / refreshed["files"][logical]["asset"]).read_bytes()))

        root = trust.loads((self.public / self.config["root_file"]).read_bytes())["signed"]
        refreshed_targets_path = refreshed_output / refreshed["files"]["metadata/targets.json"]["asset"]
        refreshed_targets = trust.verify_metadata(trust.loads(refreshed_targets_path.read_bytes()), root, "targets")
        self.assertGreater(refreshed_targets["version"], previous_targets["version"])
        self.assertEqual(refreshed_targets["targets"], previous_targets["targets"])

    def test_tampered_prior_signature_or_targets_digest_fails_before_signing(self):
        def invalid_index_signature(raw):
            envelope = trust.loads(raw)
            signature = bytearray(base64.b64decode(envelope["signature"], validate=True))
            signature[0] ^= 1
            envelope["signature"] = base64.b64encode(signature).decode("ascii")
            return trust.canonical(envelope)

        cases = (
            {
                "release-index.json": invalid_index_signature,
                "release-index-recovery.json": invalid_index_signature,
            },
            {self.index["files"]["metadata/targets.json"]["asset"]: lambda raw: raw + b"tampered"},
        )
        for mutation in cases:
            with self.subTest(mutation=next(iter(mutation))):
                refreshed_output = self.base / ("bad-" + str(len(list(self.base.glob("bad-*")))))
                with mock.patch.object(publish_release, "gh_download", side_effect=self.mock_downloads(mutation)), \
                     mock.patch.object(publish_release, "metadata_chain") as sign, \
                     mock.patch.object(publish_release, "write_index") as publish_index:
                    with self.assertRaises(trust.TrustError):
                        publish_release.refresh(TAG, refreshed_output, self.private, self.public)
                    sign.assert_not_called()
                    publish_index.assert_not_called()
                self.assertFalse(any(refreshed_output.iterdir()))

    def test_refresh_does_not_read_optional_detached_index_signature(self):
        calls = []
        refreshed_output = self.base / "detached-signature-ignored"
        with mock.patch.object(publish_release, "gh_download", side_effect=self.mock_downloads(calls=calls)):
            publish_release.refresh(TAG, refreshed_output, self.private, self.public)
        self.assertEqual(calls[0], "release-index.json")
        self.assertNotIn("release-index.sig", calls)

    def test_primary_pointer_deletion_recovers_from_uploaded_envelope_without_changing_targets(self):
        output = self.base / "promotion-output"
        remote_assets = {name: path.read_bytes() for name, path in self.release_files.items()}
        original_targets = trust.verify_metadata(
            trust.loads((self.output / self.index["files"]["metadata/targets.json"]["asset"]).read_bytes()),
            trust.loads((self.public / self.config["root_file"]).read_bytes())["signed"],
            "targets",
        )["targets"]
        upload_calls = []

        def run(command, **_kwargs):
            if command[:3] == ["gh", "release", "upload"]:
                upload_calls.append(command)
                if len(upload_calls) == 4:
                    # GitHub --clobber deletes the old primary before a failed upload.
                    remote_assets.pop("release-index.json", None)
                    raise publish_release.subprocess.CalledProcessError(1, command)
                for value in command:
                    candidate = Path(value)
                    if candidate.is_file():
                        remote_assets[candidate.name] = candidate.read_bytes()
            return mock.Mock(returncode=0)

        argv = [
            "publish_release.py", "refresh", "--tag", TAG, "--output", str(output),
            "--key-dir", str(self.private), "--public-dir", str(self.public),
        ]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(publish_release, "gh_download", side_effect=self.mock_downloads()), \
             mock.patch.object(publish_release.subprocess, "run", side_effect=run):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    publish_release.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(len(upload_calls), 4)
        self.assertEqual(Path(upload_calls[2][-1]).name, "release-index-recovery.json")
        self.assertEqual(Path(upload_calls[3][-1]).name, "release-index.json")
        self.assertNotIn("release-index.json", remote_assets)

        recovery_index = self.assert_index_signature_valid(remote_assets["release-index-recovery.json"])
        self.assertNotEqual(recovery_index, self.index)
        self.assertEqual(recovery_index["files"]["targets/" + TARGET_NAME], self.index["files"]["targets/" + TARGET_NAME])

        recovery_downloads = []

        def download_remote(_tag, name, directory, _repo):
            recovery_downloads.append(name)
            if name not in remote_assets:
                raise publish_release.subprocess.CalledProcessError(1, ["gh", "release", "download", name])
            path = directory / name
            path.write_bytes(remote_assets[name])
            return path

        recovered_output = self.base / "recovered-refresh"
        with mock.patch.object(publish_release, "gh_download", side_effect=download_remote):
            recovered = publish_release.refresh(TAG, recovered_output, self.private, self.public)
        self.assertEqual(recovery_downloads[:2], ["release-index.json", "release-index-recovery.json"])
        self.assertEqual(recovered["files"]["targets/" + TARGET_NAME], self.index["files"]["targets/" + TARGET_NAME])
        recovered_targets = trust.verify_metadata(
            trust.loads((recovered_output / recovered["files"]["metadata/targets.json"]["asset"]).read_bytes()),
            trust.loads((self.public / self.config["root_file"]).read_bytes())["signed"],
            "targets",
        )
        self.assertEqual(recovered_targets["targets"], original_targets)

    def test_retry_after_primary_clobber_failure_preserves_recovery_for_another_attempt(self):
        remote_assets = {name: path.read_bytes() for name, path in self.release_files.items()}
        remote_assets.pop("release-index.json")
        original_recovery = remote_assets["release-index-recovery.json"]
        original_targets = trust.verify_metadata(
            trust.loads((self.output / self.index["files"]["metadata/targets.json"]["asset"]).read_bytes()),
            trust.loads((self.public / self.config["root_file"]).read_bytes())["signed"],
            "targets",
        )["targets"]
        downloads = []

        def download_remote(_tag, name, directory, _repo):
            downloads.append(name)
            if name not in remote_assets:
                raise publish_release.subprocess.CalledProcessError(1, ["gh", "release", "download", name])
            path = directory / name
            path.write_bytes(remote_assets[name])
            return path

        def invoke_refresh(output, run):
            argv = [
                "publish_release.py", "refresh", "--tag", TAG, "--output", str(output),
                "--key-dir", str(self.private), "--public-dir", str(self.public),
            ]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(publish_release, "gh_download", side_effect=download_remote), \
                 mock.patch.object(publish_release.subprocess, "run", side_effect=run):
                with contextlib.redirect_stderr(io.StringIO()):
                    return publish_release.main()

        first_attempt_uploads = []

        def fail_primary_after_delete(command, **_kwargs):
            if command[:3] == ["gh", "release", "upload"]:
                first_attempt_uploads.append(command)
                if len(first_attempt_uploads) == 3:
                    self.assertEqual(Path(command[-1]).name, "release-index.json")
                    remote_assets.pop("release-index.json", None)
                    raise publish_release.subprocess.CalledProcessError(1, command)
                for value in command:
                    candidate = Path(value)
                    if candidate.is_file():
                        remote_assets[candidate.name] = candidate.read_bytes()
            return mock.Mock(returncode=0)

        with self.assertRaises(SystemExit) as interrupted:
            invoke_refresh(self.base / "retry-first-output", fail_primary_after_delete)
        self.assertEqual(interrupted.exception.code, 1)
        self.assertEqual([Path(command[-1]).name for command in first_attempt_uploads[1:]],
                         ["release-index.sig", "release-index.json"])
        self.assertNotIn("release-index.json", remote_assets)
        self.assertEqual(remote_assets["release-index-recovery.json"], original_recovery)
        self.assertEqual(self.assert_index_signature_valid(remote_assets["release-index-recovery.json"])["files"]["targets/" + TARGET_NAME],
                         self.index["files"]["targets/" + TARGET_NAME])

        second_attempt_uploads = []

        def complete_second_attempt(command, **_kwargs):
            if command[:3] == ["gh", "release", "upload"]:
                second_attempt_uploads.append(command)
                for value in command:
                    candidate = Path(value)
                    if candidate.is_file():
                        remote_assets[candidate.name] = candidate.read_bytes()
            return mock.Mock(returncode=0)

        self.assertEqual(invoke_refresh(self.base / "retry-second-output", complete_second_attempt), 0)
        pointer_order = [Path(command[-1]).name for command in second_attempt_uploads[1:]]
        self.assertEqual(pointer_order, [
            "release-index.sig", "release-index.json", "release-index-recovery.json",
        ])
        self.assertEqual(downloads[:2], ["release-index.json", "release-index-recovery.json"])
        self.assertEqual(downloads[3:5], ["release-index.json", "release-index-recovery.json"])

        primary_index = self.assert_index_signature_valid(remote_assets["release-index.json"])
        recovery_index = self.assert_index_signature_valid(remote_assets["release-index-recovery.json"])
        self.assertEqual(primary_index, recovery_index)
        self.assertEqual(primary_index["files"]["targets/" + TARGET_NAME], self.index["files"]["targets/" + TARGET_NAME])
        targets_path = remote_assets[primary_index["files"]["metadata/targets.json"]["asset"]]
        refreshed_targets = trust.verify_metadata(
            trust.loads(targets_path),
            trust.loads((self.public / self.config["root_file"]).read_bytes())["signed"],
            "targets",
        )
        self.assertEqual(refreshed_targets["targets"], original_targets)

    def test_recovery_upload_failure_keeps_primary_envelope_valid(self):
        output = self.base / "recovery-upload-failure"
        remote_assets = {name: path.read_bytes() for name, path in self.release_files.items()}
        original_primary = remote_assets["release-index.json"]
        upload_calls = []

        def run(command, **_kwargs):
            if command[:3] == ["gh", "release", "upload"]:
                upload_calls.append(command)
                if len(upload_calls) == 3:
                    raise publish_release.subprocess.CalledProcessError(1, command)
                for value in command:
                    candidate = Path(value)
                    if candidate.is_file():
                        remote_assets[candidate.name] = candidate.read_bytes()
            return mock.Mock(returncode=0)

        argv = [
            "publish_release.py", "refresh", "--tag", TAG, "--output", str(output),
            "--key-dir", str(self.private), "--public-dir", str(self.public),
        ]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(publish_release, "gh_download", side_effect=self.mock_downloads()), \
             mock.patch.object(publish_release.subprocess, "run", side_effect=run):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    publish_release.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(len(upload_calls), 3)
        self.assertEqual(Path(upload_calls[-1][-1]).name, "release-index-recovery.json")
        self.assertEqual(remote_assets["release-index.json"], original_primary)
        primary = self.assert_index_signature_valid(remote_assets["release-index.json"])
        self.assertEqual(primary, self.index)


class UploadTests(PublisherFixture):
    def test_upload_never_overwrites_a_published_release(self):
        output = self.base / "upload"
        output.mkdir()
        (output / "asset.txt").write_text("test\n", encoding="utf-8")
        existing = mock.Mock(returncode=0, stdout='{"isDraft":false}')
        with mock.patch.object(publish_release.subprocess, "run", return_value=existing) as run:
            with self.assertRaisesRegex(trust.TrustError, "cannot be rebuilt or overwritten"):
                publish_release.upload(TAG, output)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][:3], ["gh", "release", "view"])

    def test_upload_creates_and_publishes_only_through_mocked_gh(self):
        output = self.base / "upload"
        output.mkdir()
        asset = output / "asset.txt"
        asset.write_text("test\n", encoding="utf-8")
        responses = [mock.Mock(returncode=1), mock.Mock(returncode=0), mock.Mock(returncode=0)]
        with mock.patch.object(publish_release.subprocess, "run", side_effect=responses) as run:
            publish_release.upload(TAG, output, publish=False)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual([command[2] for command in commands], ["view", "create", "upload"])
        self.assertIn(str(asset), commands[-1])

    def test_upload_refuses_to_promote_a_version_older_than_current_latest(self):
        output = self.base / "upload"
        output.mkdir()
        (output / "asset.txt").write_text("test\n", encoding="utf-8")
        responses = [
            mock.Mock(returncode=0, stdout='{"isDraft":true}'),
            mock.Mock(returncode=0),
            mock.Mock(returncode=0, stdout='{"tagName":"v1.2.4"}'),
        ]
        with mock.patch.object(publish_release.subprocess, "run", side_effect=responses) as run:
            with self.assertRaisesRegex(trust.TrustError, "new release must be newer"):
                publish_release.upload(TAG, output)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 3)
        self.assertEqual(commands[2][:3], ["gh", "release", "view"])
        self.assertFalse(any(command[:3] == ["gh", "release", "edit"] for command in commands))


if __name__ == "__main__":
    unittest.main()
