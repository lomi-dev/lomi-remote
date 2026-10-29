"""Source-only assertions for the v3 preparation package."""
from pathlib import Path
import ast
import hashlib
import json
import tempfile
import unittest

import prepare


class PreparationTests(unittest.TestCase):
    def test_current_allowlist_and_candidate_source_closure_are_pinned(self):
        lock, _, contents = prepare.load_inputs()
        self.assertGreater(len(lock["sourceAllowlist"]), 30)
        self.assertEqual(set(contents), set(lock["sourceAllowlist"]))
        self.assertIn("auth-app/prisma/schema.prisma", contents)
        self.assertIn("lomi-remote/staging/consumer-derivatives-v3-successor/approval-intent.candidate.sql", contents)

    def test_source_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "source.txt"
            target.write_bytes(b"pinned bytes")
            expected = hashlib.sha256(b"pinned bytes").hexdigest()
            self.assertEqual(prepare.verify_allowlist(root, {"source.txt": expected})["source.txt"], b"pinned bytes")
            target.write_bytes(b"changed bytes")
            with self.assertRaisesRegex(ValueError, "drift"):
                prepare.verify_allowlist(root, {"source.txt": expected})

    def test_allowlist_rejects_symlinked_parent_that_escapes_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            outside = root.parent / (root.name + "-outside")
            outside.mkdir()
            try:
                target = outside / "source.txt"
                target.write_bytes(b"pinned bytes")
                (root / "redirect").symlink_to(outside, target_is_directory=True)
                expected = hashlib.sha256(b"pinned bytes").hexdigest()
                with self.assertRaisesRegex(ValueError, "symlink|escapes root"):
                    prepare.verify_allowlist(root, {"redirect/source.txt": expected})
            finally:
                if outside.exists():
                    (outside / "source.txt").unlink(missing_ok=True)
                    outside.rmdir()

    def test_non_null_catalog_or_helper_pins_are_rejected(self):
        lock, _, contents = prepare.load_inputs()
        prefix = "lomi-remote/staging/consumer-derivatives-v3-successor/"
        catalog = json.loads(contents[prefix + "catalog-contract.pending.json"])
        helper = json.loads(contents[prefix + "helper-seal.pending.json"])
        prepare.assert_null_pins(catalog, helper)
        catalog["roots"][0]["old_catalog_sha256"] = "measured"
        with self.assertRaisesRegex(ValueError, "must remain NULL"):
            prepare.assert_null_pins(catalog, helper)
        self.assertEqual(lock["admission"], "CLOSED_REQUIRES_SEPARATE_EXPLICIT_APPOINTMENT")

    def test_bundle_rejects_extra_files_and_source_drift(self):
        lock, lock_bytes, contents = prepare.load_inputs()
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary).resolve() / "bundle"
            prepare.create_bundle(bundle)
            prepare.validate_bundle(bundle, lock, lock_bytes, contents)
            (bundle / "unexpected.txt").write_text("extra")
            with self.assertRaisesRegex(ValueError, "file set differs"):
                prepare.validate_bundle(bundle, lock, lock_bytes, contents)

    def test_destination_rejects_symlinked_ancestry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = root / "real"
            real.mkdir()
            link = root / "redirect"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                prepare.create_bundle(link / "bundle")

    def test_plan_semantics_are_checked_on_load_and_bundle_read(self):
        lock, lock_bytes, contents = prepare.load_inputs()
        original = json.loads(prepare.PLAN_PATH.read_text())
        mutations = []
        for key, value in (("admission", "ADMITTED"), ("qualification", "PASSED"), ("postgresTarget", "latest"), ("status", "QUALIFIED")):
            changed = dict(original)
            changed[key] = value
            mutations.append(changed)
        changed = json.loads(json.dumps(original))
        changed["sourceOnlyProhibition"]["sqlInvocations"] = 1
        mutations.append(changed)
        changed = json.loads(json.dumps(original))
        changed["sourceOnlyProhibition"]["toolVersionQueries"] = 1
        mutations.append(changed)
        changed = json.loads(json.dumps(original))
        changed["stages"][2]["status"] = "PASSED"
        mutations.append(changed)
        for changed in mutations:
            encoded = json.dumps(changed).encode()
            with self.subTest(changed=changed.get("status")):
                with self.assertRaises(ValueError):
                    prepare.load_inputs(plan_override=encoded)
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary).resolve() / "bundle"
            prepare.create_bundle(bundle)
            changed = json.loads((bundle / "plan.json").read_text())
            changed["admission"] = "ADMITTED"
            (bundle / "plan.json").write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "must not record admission"):
                prepare.validate_bundle(bundle, lock, lock_bytes, contents)

    def test_plan_is_unadmitted_and_all_invocation_counts_are_zero(self):
        lock, _, _ = prepare.load_inputs()
        plan = json.loads(prepare.PLAN_PATH.read_text())
        self.assertEqual(plan["status"], "PREPARED_NOT_EXECUTED")
        self.assertIsNone(plan["admission"])
        self.assertEqual(plan["qualification"], "NOT_RUN")
        self.assertEqual(plan["postgresTarget"], "18.6")
        self.assertEqual(plan["sourceOnlyProhibition"]["toolVersionQueries"], 0)
        self.assertTrue(all(stage["status"] == "NOT_RUN" for stage in plan["stages"]))
        self.assertTrue(all(value == 0 for value in plan["sourceOnlyProhibition"].values()))
        self.assertTrue(all(value == 0 for value in lock["sourceOnlyProhibition"].values()))

    def test_package_has_no_runner_subprocess_or_connect_code(self):
        package = Path(__file__).resolve().parent
        expected_tree = {"README.md", "inputs.lock.json", "plan.json", "prepare.py", "test_prepare.py"}
        actual_tree = {path.relative_to(package).as_posix() for path in package.rglob("*")}
        self.assertEqual(actual_tree, expected_tree)
        forbidden_modules = {
            "subprocess", "socket", "psycopg", "asyncpg", "pg8000", "sqlalchemy",
            "requests", "urllib", "http", "httpx", "aiohttp", "ftplib", "smtplib",
            "sqlite3", "asyncio", "multiprocessing", "threading", "ctypes", "os", "sys",
        }
        forbidden_calls = {
            "run", "Popen", "call", "check_call", "check_output", "system", "popen",
            "spawn", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve",
            "spawnvp", "spawnvpe", "exec", "execv", "execve", "execl", "execlp",
            "execlpe", "execvp", "execvpe", "fork", "forkpty", "startfile", "connect",
            "create_connection", "create_subprocess_exec", "create_subprocess_shell",
            "urlopen", "request", "eval",
        }
        for path in package.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertTrue(all(alias.name.split(".")[0] not in forbidden_modules for alias in node.names), str(path))
                elif isinstance(node, ast.ImportFrom):
                    self.assertNotIn((node.module or "").split(".")[0], forbidden_modules, str(path))
                elif isinstance(node, ast.Call):
                    name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
                    self.assertNotIn(name, forbidden_calls, str(path))

    def test_locked_prisma_schema_has_reviewed_cascade_relations(self):
        lock, _, contents = prepare.load_inputs()
        path = "auth-app/prisma/schema.prisma"
        schema = contents[path].decode()
        self.assertEqual(hashlib.sha256(schema.encode()).hexdigest(), lock["sourceAllowlist"][path])
        for relation in (
            'consumerApproval ConsumerApprovalIntent? @relation("ServiceApproval"',
            'consumerApproval ConsumerApprovalIntent? @relation("WebApproval"',
            'consumerApproval ConsumerApprovalIntent? @relation("MobileApproval"',
        ):
            start = schema.index(relation)
            line = schema[start:schema.index("\n", start)]
            self.assertIn("onDelete: Cascade, onUpdate: NoAction", line)


if __name__ == "__main__":
    unittest.main()
