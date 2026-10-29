import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("rpc_parity", ROOT / "tools/check_rpc_parity_manifest.py")
rpc_parity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rpc_parity)


class RpcParityManifestTest(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "crates/lomi-remote-protocol/src/lib.rs").read_text()
        self.manifest = json.loads((ROOT / "contracts/client-rpc-parity.json").read_text())

    def test_manifest_matches_canonical_method_set(self):
        self.assertEqual(rpc_parity.validate(self.source, self.manifest), [])

    def test_method_drift_is_reported(self):
        changed = self.source.replace('WorkspaceGet => "workspace.get",', 'WorkspaceGet => "workspace.lookup",', 1)
        errors = rpc_parity.validate(changed, self.manifest)
        self.assertTrue(any("missing canonical wire methods" in error for error in errors))
        self.assertTrue(any("unknown wire methods" in error for error in errors))

    def test_duplicate_wire_name_in_rust_is_rejected(self):
        changed = self.source.replace(
            'WorkspaceGet => "workspace.get",',
            'WorkspaceGet => "workspace.get",\n    WorkspaceLookup => "workspace.get",',
            1,
        )
        errors = rpc_parity.validate(changed, self.manifest)
        self.assertTrue(any("duplicate wire names" in error for error in errors))

    def test_git_methods_remain_blocked(self):
        self.assertTrue(all(
            details["status"] == "blocked"
            for wire, entry in self.manifest["methods"].items() if wire.startswith("git.")
            for details in entry["clients"].values()
        ))


if __name__ == "__main__":
    unittest.main()
