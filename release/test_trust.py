"""Focused tests for the offline TUF trust helper."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import trust


class TrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.private = self.base / "private"
        self.private.mkdir(mode=0o700)
        self.private.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def test_canonical_json_and_reader_reject_floats_and_duplicate_keys(self):
        self.assertEqual(trust.canonical({"z": "é", "a": [True, 1]}),
                         b'{"a":[true,1],"z":"\\u00e9"}')
        with self.assertRaises(trust.TrustError):
            trust.canonical({"n": 1.5})
        with self.assertRaises(trust.TrustError):
            trust.loads('{"key":1,"key":2}')
        with self.assertRaises(trust.TrustError):
            trust.loads('{"key":1.0}')

    def test_ed25519_key_sign_verify_and_no_overwrite(self):
        path = self.private / "one.pem"
        public = trust.create_key(path)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(bytes.fromhex(public["keyval"]["public"])), 32)
        self.assertEqual(trust.key_id(public), hashlib.sha256(trust.canonical(public)).hexdigest())
        signature = trust.sign_bytes(b"release metadata", path)
        self.assertEqual(len(signature), 64)
        self.assertTrue(trust.verify_bytes(b"release metadata", signature, public))
        self.assertFalse(trust.verify_bytes(b"altered", signature, public))
        with self.assertRaises(trust.TrustError):
            trust.create_key(path)

    def _signed_root(self, root_key, targets_key):
        root_public = trust.public_key(root_key)
        targets_public = trust.public_key(targets_key)
        ids = {"root": trust.key_id(root_public), "targets": trust.key_id(targets_public)}
        root = {
            "_type": "root", "spec_version": "1.0.0", "version": 1,
            "expires": "2999-01-01T00:00:00Z", "consistent_snapshot": False,
            "keys": {ids["root"]: root_public, ids["targets"]: targets_public},
            "roles": {name: {"keyids": [kid], "threshold": 1}
                      for name, kid in ids.items()},
        }
        return root, ids

    def test_metadata_threshold_role_version_expiry_and_key_hash(self):
        root_key, targets_key = self.private / "root.pem", self.private / "targets.pem"
        trust.create_key(root_key)
        trust.create_key(targets_key)
        root, ids = self._signed_root(root_key, targets_key)
        signed = {"_type": "targets", "version": 2,
                  "expires": "2999-01-01T00:00:00Z", "targets": {}}
        document = trust.sign_metadata(signed, targets_key)
        self.assertIs(trust.verify_metadata(document, root, "targets"), signed)

        altered = {**document, "signed": {**signed, "version": 3}}
        with self.assertRaisesRegex(trust.TrustError, "threshold"):
            trust.verify_metadata(altered, root, "targets")
        duplicate = {**document, "signatures": document["signatures"] * 2}
        with self.assertRaisesRegex(trust.TrustError, "duplicate"):
            trust.verify_metadata(duplicate, root, "targets")
        wrong_type = trust.sign_metadata({**signed, "_type": "snapshot"}, targets_key)
        with self.assertRaisesRegex(trust.TrustError, "role type"):
            trust.verify_metadata(wrong_type, root, "targets")
        with self.assertRaisesRegex(trust.TrustError, "version"):
            trust.verify_metadata(trust.sign_metadata({**signed, "version": True}, targets_key), root, "targets")
        expired = {**signed, "expires": (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        with self.assertRaisesRegex(trust.TrustError, "expired"):
            trust.verify_metadata(trust.sign_metadata(expired, targets_key), root, "targets")
        bad_root = json.loads(json.dumps(root))
        bad_root["keys"][ids["targets"]]["keyval"]["public"] = "0" * 64
        with self.assertRaisesRegex(trust.TrustError, "key identifier"):
            trust.verify_metadata(document, bad_root, "targets")

    def test_initialize_writes_self_signed_root_and_public_config(self):
        public_dir = self.base / "public"
        config = trust.initialize(self.private, public_dir)
        self.assertEqual(config["repo"], trust.REPO)
        self.assertEqual(config["origin"], trust.ORIGIN)
        self.assertEqual(config["root_file"], "metadata/1.root.json")
        root_bytes = (public_dir / config["root_file"]).read_bytes()
        self.assertEqual(trust.sha256(root_bytes), config["root_sha256"])
        document = trust.loads(root_bytes)
        root = document["signed"]
        self.assertEqual(root["spec_version"], "1.0.0")
        self.assertEqual(root["version"], 1)
        self.assertGreaterEqual(datetime.fromisoformat(root["expires"].replace("Z", "+00:00")).year,
                                datetime.now(timezone.utc).year + 5)
        self.assertFalse(root["consistent_snapshot"])
        self.assertEqual(set(root["roles"]), {"root", "targets", "snapshot", "timestamp"})
        self.assertEqual(trust.verify_metadata(document, root, "root"), root)
        self.assertEqual({p.name for p in self.private.glob("*.pem")},
                         {f"{name}.pem" for name in trust._KEYS})
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in self.private.glob("*.pem")))
        index_public = base64.b64decode(config["index_public_key_base64"])
        self.assertEqual(len(index_public), 32)
        bootstrap_der = (public_dir / config["linux_bootstrap_public_key_file"]).read_bytes()
        self.assertEqual(len(bootstrap_der), 44)
        self.assertEqual(config["linux_bootstrap_key_sha256"], trust.sha256(bootstrap_der))
        self.assertEqual(json.loads((public_dir / "release-public.json").read_bytes()), config)
        with self.assertRaises(trust.TrustError):
            trust.initialize(self.private, public_dir)


if __name__ == "__main__":
    unittest.main()
