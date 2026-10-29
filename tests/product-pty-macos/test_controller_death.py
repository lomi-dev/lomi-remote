import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import controller_death as fault


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.record = {"run": "00000000-0000-4000-8000-000000000001", "nonce": "00000000-0000-4000-8000-000000000002", "stage": "AdmissionConsumed", "admissionConsumed": True, "drained": False, "controller": {"pid": 123}, "host": {"pid": 124}, "profilePin": [1, 2], "generationPin": [1, 3], "lifetime": [1, 4]}
        self.proof = {"schema": 1, "nonce": self.record["nonce"], "controllerPid": 123, "hostPid": 124, "workloadPid": 125, "initialLiveCount": 2, "numericSignalsUsed": False, "allRegistrationsAccepted": True, "sameControllerAuditSignal": True, "controllerNoteExit": True, "workloadNoteExit": True, "fixtureGenerationProcessesGone": True, "workloadLiveAfterControllerNoteExit": True}
        self.host_proof = {"schema": 1, "nonce": self.record["nonce"], "hostPid": 124, "hostNoteExit": True, "fixtureAllThreeProcessesGone": True}

    def test_manager_absence_is_quiescence_not_product_cleanup(self):
        self.assertEqual(fault.quiescent_manager_state(None), "absent")
        self.assertEqual(fault.quiescent_manager_state({"pid": None}), "loadedWithoutPid")
        for state in ({"pid": 123}, {}, {"pid": None, "foreign": True}):
            with self.assertRaises(RuntimeError):
                fault.quiescent_manager_state(state)

    def test_normal_intermediate_directories_remain_pinned_and_not_writable(self):
        with tempfile.TemporaryDirectory(prefix=".lomi-controller-check-", dir=Path.home()) as folder:
            runtime = Path(folder)
            library = runtime / "Library"
            library.mkdir(mode=0o755)
            info = library.stat()
            manifest = {"directories": [{"path": ["Library"], "pin": fault.pin(info)}], "files": []}
            fault._remaining_manifest(runtime, manifest)
            library.chmod(0o777)
            with self.assertRaises(RuntimeError):
                fault._remaining_manifest(runtime, manifest)
            library.chmod(0o755)

    def test_missing_live_orphan_evidence_never_passes_acceptance(self):
        fault.require_live_orphan(self.proof)
        for value in (None, False):
            proof = dict(self.proof)
            if value is None:
                del proof["workloadLiveAfterControllerNoteExit"]
            else:
                proof["workloadLiveAfterControllerNoteExit"] = value
            with self.assertRaises(RuntimeError):
                fault.require_live_orphan(proof)
            # True exit certificates can independently permit fixture cleanup,
            # even though the stronger live-orphan acceptance remains unproved.
            fault.require_certificate(self.record, proof, self.host_proof, 125)

    def test_missing_or_wrong_subject_death_never_authorizes_operator_cleanup(self):
        fault.require_certificate(self.record, self.proof, self.host_proof, 125)
        for field, value in (("workloadPid", 999), ("controllerNoteExit", False), ("workloadNoteExit", False), ("initialLiveCount", 1), ("sameControllerAuditSignal", False)):
            proof = dict(self.proof, **{field: value})
            with self.assertRaises(RuntimeError):
                fault.require_certificate(self.record, proof, self.host_proof, 125)
        with self.assertRaises(RuntimeError):
            fault.require_certificate(self.record, self.proof, {}, 125)
        with self.assertRaises(RuntimeError):
            fault.require_certificate(dict(self.record, stage="Cleaned"), self.proof, self.host_proof, 125)

    def manifest(self):
        dirs, files = fault._allowed_paths(self.record)
        generation = ("Library", "Application Support", "LomiRemote", "pty-generations", self.record["run"])
        data = json.dumps(self.record).encode()
        manifest = {"directories": [], "files": []}
        for i, parts in enumerate(sorted(dirs)):
            identity = [2, i + 1]
            if not parts:
                identity = [1, 1]
            if parts == generation[:3]:
                identity = self.record["profilePin"]
            if parts == generation:
                identity = self.record["generationPin"]
            manifest["directories"].append({"path": list(parts), "pin": identity})
        for i, parts in enumerate(sorted(files)):
            if len(parts) == 1:
                continue
            identity = self.record["lifetime"] if parts[-1] == "controller.lock" else [3, i + 1]
            content = data if parts[-1] == "journal.json" else b""
            manifest["files"].append({"path": list(parts), "pin": identity, "private": True, "hex": content.hex()})
        return manifest, hashlib.sha256(data).hexdigest()

    def test_malformed_or_escaping_deletion_manifest_is_refused(self):
        manifest, digest = self.manifest()
        fault._validate_manifest(manifest, self.record, [1, 1], digest)
        for change in ("escape", "duplicate", "foreign_pin", "wrong_journal", "nonempty_lock"):
            value = copy.deepcopy(manifest)
            if change == "escape":
                value["files"][0]["path"] = ["..", "unrelated"]
            elif change == "duplicate":
                value["files"].append(value["files"][0])
            elif change == "foreign_pin":
                value["directories"][0]["pin"] = [99, 99]
            elif change == "wrong_journal":
                next(item for item in value["files"] if item["path"][-1] == "journal.json")["hex"] = b"foreign".hex()
            else:
                next(item for item in value["files"] if item["path"][-1] == "owner.lock")["hex"] = b"foreign".hex()
            with self.assertRaises(RuntimeError):
                fault._validate_manifest(value, self.record, [1, 1], digest)

    def test_partial_deletion_retry_preserves_an_unexpected_entry(self):
        with tempfile.TemporaryDirectory(prefix=".lomi-controller-check-", dir=Path.home()) as folder:
            root = Path(folder)
            node = root / "owned"
            node.write_bytes(b"owned")
            node.chmod(0o600)
            data, identity = fault.read_file(node)
            descriptor = fault.directory(root)
            root_pin = fault.pin(os.fstat(descriptor))
            os.close(descriptor)
            manifest = {"directories": [{"path": [], "pin": root_pin}], "files": [{"path": ["owned"], "pin": identity, "private": True, "hex": data.hex()}]}
            node.unlink()  # Real partial unlink effect after a durable intent.
            fault._remaining_manifest(root, manifest)
            foreign = root / "foreign"
            foreign.write_bytes(b"preserve")
            with self.assertRaises(RuntimeError):
                fault._remaining_manifest(root, manifest)
            self.assertEqual(foreign.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
