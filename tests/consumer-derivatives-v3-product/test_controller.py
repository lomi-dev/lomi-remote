"""Source-only mutation tests; this module never invokes external tools."""
from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

# python -I ignores the script directory and ambient working directory.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import admission
import controller
import evidence
import prepare
import helper_denials
import owner_state_denials
import test_owner_state_denials as owner_state_test_data


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def function_row(signature, definition, owner="lomi_remote_inventory_owner", acl=None):
    raw = definition.encode("utf-8")
    return {
        "kind": "function",
        "signature": signature,
        "owner": owner,
        "securityDefiner": False,
        "config": None,
        "definition": definition,
        "definitionUtf8Hex": raw.hex(),
        "catalogSha256": digest(raw),
        "acl": [] if acl is None else acl,
    }


def capture(*rows):
    return b"".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode() + b"\n" for row in rows)


FROZEN = HERE.parents[1] / "staging/consumer-derivatives-v3-product-successor/inputs/frozen-v3-successor"
BUNDLED_FROZEN = HERE / "inputs/lomi-remote/staging/consumer-derivatives-v3-product-successor/inputs/frozen-v3-successor"


def frozen_bytes(name):
    root = BUNDLED_FROZEN if BUNDLED_FROZEN.is_dir() else FROZEN
    return (root / name).read_bytes()


def valid_plan_fixture():
    return json.loads((HERE / "plan.json").read_text())


class QualificationPlanContractTests(unittest.TestCase):
    def test_accepts_closed_v2_per_kind_growth_policy_in_both_guards(self):
        plan = valid_plan_fixture()
        prepare.validate_plan(plan)
        controller.validate_qualification_plan(plan)
        self.assertEqual(plan["schemaVersion"], 2)
        self.assertEqual(plan["s7GrowthPolicy"], prepare.S7_GROWTH_POLICY)
        self.assertEqual(plan["s7GrowthPolicy"], controller.S7_GROWTH_POLICY)

    def test_both_guards_reject_legacy_malformed_or_misleading_plans(self):
        def schema_v1(plan):
            plan["schemaVersion"] = 1

        def old_account_targets(plan):
            plan["s7GrowthPolicy"]["targets"] = [2048, 4096]

        def boolean_version(plan):
            plan["schemaVersion"] = True

        def boolean_target(plan):
            plan["s7GrowthPolicy"]["targets"][0] = True

        def non_policy_target(plan):
            plan["s7GrowthPolicy"]["targets"][1] = 10001

        def wrong_unit(plan):
            plan["s7GrowthPolicy"]["unit"] = "issued-accounts"

        def extra_policy_key(plan):
            plan["s7GrowthPolicy"]["allowRounding"] = True

        def wrong_fixture_count(plan):
            plan["s7GrowthPolicy"]["dedicatedFixturesExcluded"] = 7

        def boolean_fixture_count(plan):
            plan["s7GrowthPolicy"]["dedicatedFixturesExcluded"] = True

        def missing_kind(plan):
            plan["s7GrowthPolicy"]["kinds"].remove("mobile")

        def missing_relation(plan):
            del plan["s7GrowthPolicy"]["minimumRelationRowsByTarget"]["1000"]["mobile_session"]

        def undersized_kind_population(plan):
            plan["s7GrowthPolicy"]["minimumRelationRowsByTarget"]["10000"]["mobile_session"] = 9999

        def undersized_shared_population(plan):
            plan["s7GrowthPolicy"]["minimumRelationRowsByTarget"]["1000"]["consumer_approval_intent"] = 1999

        def malformed_stage_entry(plan):
            plan["stages"][7] = "S7 NOT_RUN"

        def stage_extra_key(plan):
            plan["stages"][7]["result"] = "PASS"

        def stage_premature_status(plan):
            plan["stages"][7]["status"] = "PASS"

        def top_level_premature_qualification(plan):
            plan["qualification"] = "PASS"

        def top_level_premature_status(plan):
            plan["status"] = "PRIVATE_S0_S7_PASS_NOT_PRODUCTION_QUALIFIED"

        def premature_admission(plan):
            plan["admission"] = {"root": "present"}

        def production_qualified(plan):
            plan["productionQualified"] = True

        def changed_deadline(plan):
            plan["bounds"]["workDeadlineSeconds"] = 841

        def bool_deadline(plan):
            plan["bounds"]["workDeadlineSeconds"] = True

        def changed_pool_limit(plan):
            plan["bounds"]["maximumConnectionsPerRolePool"] = 3

        mutations = (
            schema_v1, old_account_targets, boolean_version, boolean_target, non_policy_target,
            wrong_unit, extra_policy_key, wrong_fixture_count, boolean_fixture_count,
            missing_kind, missing_relation,
            undersized_kind_population, undersized_shared_population, malformed_stage_entry,
            stage_extra_key, stage_premature_status, top_level_premature_qualification,
            top_level_premature_status, premature_admission,
            production_qualified, changed_deadline, bool_deadline, changed_pool_limit,
        )
        validators = (prepare.validate_plan, controller.validate_qualification_plan)
        for mutate in mutations:
            for validate in validators:
                with self.subTest(mutation=mutate.__name__, validator=validate.__module__):
                    plan = valid_plan_fixture()
                    mutate(plan)
                    with self.assertRaises((prepare.Rejected, controller.Rejected)):
                        validate(plan)

    def test_both_guards_reject_non_object_roots(self):
        for invalid in (None, [], "plan"):
            for validate in (prepare.validate_plan, controller.validate_qualification_plan):
                with self.subTest(value=invalid, validator=validate.__module__):
                    with self.assertRaises((prepare.Rejected, controller.Rejected)):
                        validate(invalid)


class HostParentBoundaryTests(unittest.TestCase):
    def rows(self):
        baseline = [
            {"kind": "relation", "relation": relation, "owner": "lomi_migrator",
             "acl": [], "columns": [{"name": column, "type": "text", "acl": []}
                                      for column in columns]}
            for relation, columns in controller.EXCHANGE_PARENT_READ_COLUMNS.items()
        ]
        baseline.append({"kind": "relation", "relation": "public.host_registration",
                         "owner": "lomi_migrator", "acl": [],
                         "columns": [{"name": "id", "type": "uuid", "acl": []}]})
        final = json.loads(json.dumps(baseline))
        for row in final[:-1]:
            for column in row["columns"]:
                column["acl"].append({"grantor": "lomi_migrator", "grantee": "lomi_remote_exchange",
                                      "privilege": "SELECT", "grantable": False})
        return baseline, final

    def test_accepts_only_exact_nine_reviewed_parent_select_grants(self):
        baseline, final = self.rows()
        before = json.dumps(baseline, sort_keys=True)
        receipt = controller.assert_host_parent_relations(baseline, final)
        self.assertEqual(receipt["parentAclDelta"]["columns"], controller.EXCHANGE_PARENT_READ_COLUMNS)
        self.assertEqual(sum(len(row["columns"]) for row in final[:-1]), 9)
        self.assertEqual(json.dumps(baseline, sort_keys=True), before)

    def test_rejects_missing_broadened_regrantable_and_unrelated_changes(self):
        def remove(rows): rows[0]["columns"][0]["acl"].clear()
        def broaden(rows): rows[0]["acl"].append({"grantee": "lomi_remote_exchange", "privilege": "SELECT"})
        def grant_option(rows): rows[0]["columns"][0]["acl"][0]["grantable"] = True
        def wrong_grantor(rows): rows[0]["columns"][0]["acl"][0]["grantor"] = "e2_owner"
        def write(rows): rows[0]["columns"][0]["acl"][0]["privilege"] = "UPDATE"
        def duplicate_acl(rows): rows[0]["columns"][0]["acl"] *= 2
        def owner(rows): rows[0]["owner"] = "e2_owner"
        def schema(rows): rows[0]["columns"][0]["type"] = "bytea"
        def host(rows): rows[-1]["columns"][0]["type"] = "text"
        def new_host(rows): rows.append(dict(rows[-1], relation="public.host_unreviewed"))
        def missing_host(rows): rows.pop()
        def duplicate_relation(rows): rows.append(rows[-1])
        for mutate in (remove, broaden, grant_option, wrong_grantor, write, duplicate_acl,
                       owner, schema, host, new_host, missing_host, duplicate_relation):
            baseline, final = self.rows()
            mutate(final)
            with self.subTest(mutation=mutate.__name__), self.assertRaises(controller.Rejected):
                controller.assert_host_parent_relations(baseline, final)

    def test_keeps_existing_column_grants_and_rejects_unexpected_baseline_exchange_acl(self):
        baseline, final = self.rows()
        other = {"grantor": "lomi_migrator", "grantee": "lomi_remote_inventory_owner",
                 "privilege": "SELECT", "grantable": False}
        baseline[0]["columns"][0]["acl"].append(dict(other))
        final[0]["columns"][0]["acl"].append(dict(other))
        controller.assert_host_parent_relations(baseline, final)
        final[0]["columns"][0]["acl"].remove(other)
        with self.assertRaises(controller.Rejected):
            controller.assert_host_parent_relations(baseline, final)
        baseline[0]["columns"][1]["acl"].append(final[0]["columns"][1]["acl"][0])
        with self.assertRaisesRegex(controller.Rejected, "unexpected baseline Exchange"):
            controller.assert_host_parent_relations(baseline, final)


class HelperDenialIntegrationTests(unittest.TestCase):
    def fixture(self, *, wrong_identity=False, unrelated_drift=False):
        run_uuid = "7e1c2b9f-9b28-4b52-a345-12dfcb08a012"
        attempts = helper_denials.build_attempts(run_uuid)
        rows = [function_row(helper["signature"], "CREATE FUNCTION guard() RETURNS void AS $$BEGIN RETURN; END$$;",
                             owner=helper_denials.BODY_OWNER) for helper in helper_denials.HELPERS]
        initial = capture(*rows)

        class Fixture:
            run_id = run_uuid
            calls = []

            def psql(self, database, *, user, script, label, expected, timeout):
                attempt = attempts[len(self.calls)]
                self.calls.append((database, user, script, expected))
                actor = "e2_owner" if wrong_identity else attempt["role"]
                output = (
                    f"CONSUMER_DENIAL_RESULT|run={run_uuid}|attempt={attempt['attemptId']}"
                    f"|role={attempt['role']}|session_user={actor}|current_user={actor}"
                    "|rolsuper=false|rolcreaterole=false|is_superuser=false|sqlstate=42501\n"
                    f"CONSUMER_DENIAL_ROLLBACK_ACK|run={run_uuid}|attempt={attempt['attemptId']}|role={attempt['role']}\n"
                ).encode()
                return {"returnCode": 0, "stderr": output, "stdout": b"",
                        "stdoutSha256": digest(b""), "stderrSha256": digest(output)}

            def capture_catalog(self, database, label):
                if unrelated_drift:
                    return initial + capture({"kind": "role", "name": "unexpected_role"})
                return initial

        return Fixture(), initial, attempts

    def test_executes_entire_matrix_as_nonoperator_logins(self):
        fixture, initial, attempts = self.fixture()
        receipt = controller.run_sealed_helper_denials(fixture, initial)
        self.assertEqual(receipt["deniedCount"], 80)
        self.assertEqual(len(receipt["captureHashes"]), 80)
        self.assertEqual(len(fixture.calls), 80)
        for call, attempt in zip(fixture.calls, attempts):
            database, user, script, expected = call
            self.assertEqual(database, "lomi_auth_test")
            self.assertEqual(user, attempt["role"])
            self.assertNotEqual(user, "e2_owner")
            self.assertEqual(script, attempt["sql"].encode())
            self.assertEqual(expected, (0,))

    def test_rejects_wrong_identity_or_drift_outside_the_target_helper(self):
        for options in ({"wrong_identity": True}, {"unrelated_drift": True}):
            fixture, initial, _ = self.fixture(**options)
            with self.subTest(options=options), self.assertRaises((controller.Rejected, helper_denials.Rejected)):
                controller.run_sealed_helper_denials(fixture, initial)
            self.assertEqual(len(fixture.calls), 1)


class OwnerStateIntegrationTests(unittest.TestCase):
    def run_adapter(self, root, *, reason_override=None, capture_drift=False, bad_control=False,
                    operator_ids=("helperSeal", "threeRoots")):
        sources, hashes, controls, attempts = owner_state_test_data.setup_plan()
        attempts = [attempt for attempt in attempts if attempt["operator"] in operator_ids]
        controls = {name: control for name, control in controls.items() if name in operator_ids}
        (root / "sql").mkdir(mode=0o700)
        for name, relative in (("helperSeal", "operator-helper-seal.private.sql"),
                               ("threeRoots", "operator-three-roots.private.sql")):
            controller.write_new(root / "sql" / relative, sources[name])
        before = b'{"kind":"role","name":"lomi_consumer_auth_body_owner"}\n'

        class Fixture:
            run_id = owner_state_test_data.RUN_UUID
            work = root
            filled_operators = {name: {"filledSha256": value} for name, value in hashes.items()}

            def __init__(self): self.calls = []

            def capture_catalog(self, database, label):
                return before + (b' {"kind":"role","name":"unexpected"}\n'
                                 if capture_drift and self.calls else b"")

            def psql(self, database, *, user, script, label, catalog_search_path, expected, timeout):
                attempt = attempts[len(self.calls)]
                self.calls.append((database, user, script, catalog_search_path, expected))
                output = owner_state_test_data.transcript(attempt, reason_code=reason_override)
                return {"returnCode": 0, "stderr": output, "stdout": b"",
                        "stdoutSha256": digest(b""), "stderrSha256": digest(output)}

        fixture = Fixture()
        operator_evidence = {"operators": {
            name: {key: value for key, value in control.items() if key != "operatorSha256"}
            for name, control in controls.items()
        }}
        if bad_control:
            operator_evidence["operators"]["helperSeal"]["allNewIdempotent"] = 1
        self.last_fixture = fixture
        receipt, outcomes = controller.run_owner_state_denials(
            fixture, operator_evidence, operator_ids=operator_ids)
        self.last_outcomes = outcomes
        return fixture, attempts, receipt

    def test_runs_both_bound_operators_and_every_case_with_catalog_search_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture, attempts, receipt = self.run_adapter(Path(temporary))
            self.assertEqual(receipt["attemptCount"], 28)
            self.assertEqual(receipt["deniedCount"], 28)
            self.assertEqual(len(fixture.calls), 28)
            for call, attempt in zip(fixture.calls, attempts):
                database, user, script, search_path, expected = call
                self.assertEqual(database, "lomi_auth_test")
                self.assertEqual(user, "e2_owner")
                self.assertEqual(script, attempt["sql"].encode())
                self.assertTrue(search_path)
                self.assertEqual(expected, (0,))

    def test_each_measured_phase_runs_only_its_own_fourteen_bound_attempts(self):
        for name, first_index in (("helperSeal", 0), ("threeRoots", 14)):
            with tempfile.TemporaryDirectory() as temporary:
                fixture, attempts, receipt = self.run_adapter(Path(temporary), operator_ids=(name,))
                self.assertEqual(len(fixture.calls), 14)
                self.assertEqual({attempt["operator"] for attempt in attempts}, {name})
                self.assertEqual(attempts[0]["attemptId"].rsplit(":", 1)[1], f"{first_index:03d}")
                self.assertFalse(receipt["fullOwnerStateDenialMatrixValidated"])
                self.assertFalse(receipt["fullS5Qualified"])

    def test_rejects_generic_failure_catalog_drift_or_failed_positive_control(self):
        for options in ({"reason_override": "unexpected_rejection"},
                        {"capture_drift": True}, {"bad_control": True}):
            with tempfile.TemporaryDirectory() as temporary:
                with self.subTest(options=options), self.assertRaises(owner_state_denials.Rejected):
                    self.run_adapter(Path(temporary), **options)
                self.assertEqual(len(self.last_fixture.calls), 0 if options.get("bad_control") else 1)


class SourceClosureTests(unittest.TestCase):
    def test_product_core_is_installed_before_ownership_and_typed_layers(self):
        self.assertEqual(controller.successor_source_layers(), (
            controller.PACKAGE_REL + "/inputs/frozen-v3-successor/approval-intent.candidate.sql",
            controller.PACKAGE_REL + "/inputs/frozen-v3-successor/012-derivative-authority.candidate.sql",
            controller.PACKAGE_REL + "/authority-core.candidate.sql",
            controller.PACKAGE_REL + "/inputs/frozen-v3-successor/typed-entrypoints.candidate.sql",
        ))

    def test_successor_validator_origins_are_closed_under_the_bundle_input_root(self):
        lock, _ = prepare.load_lock()
        package = Path("/Users/woro/Documents/Lomi/lomi-remote/staging/consumer-derivatives-v3-product-successor")
        manifest = json.loads((package / "source-manifest.json").read_text())
        origins = {}
        for item in manifest["inputs"]:
            previous = origins.setdefault(item["origin"], item["sha256"])
            self.assertEqual(previous, item["sha256"], item["origin"])
        self.assertEqual(len(origins), 45)
        for relative, expected in origins.items():
            self.assertEqual(lock["sourceAllowlist"].get(relative), expected, relative)
        for tree in (
            "auth-app/staging/consumer-derivatives-product",
            "lomi-remote/staging/consumer-derivatives-v3-successor",
        ):
            files = sorted(path.relative_to(Path("/Users/woro/Documents/Lomi")).as_posix()
                           for path in (Path("/Users/woro/Documents/Lomi") / tree).rglob("*")
                           if path.is_file())
            self.assertEqual(lock["closedTrees"].get(tree), files, tree)
        self.assertTrue(set(origins) <= set(lock["sourceAllowlist"]))
        prepare.verify_allowlist(Path("/Users/woro/Documents/Lomi"), lock)

    def test_allowlist_rejects_hash_change_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source.sql"
            source.write_bytes(b"literal SQL\n")
            lock = {"sourceAllowlist": {"source.sql": digest(b"literal SQL\n")}, "closedTrees": {}}
            self.assertEqual(prepare.verify_allowlist(root, lock)["source.sql"], b"literal SQL\n")
            source.write_bytes(b"changed SQL\n")
            with self.assertRaisesRegex(prepare.Rejected, "hash drift"):
                prepare.verify_allowlist(root, lock)
            source.unlink()
            outside = root.parent / (root.name + "-outside.sql")
            outside.write_bytes(b"literal SQL\n")
            try:
                source.symlink_to(outside)
                with self.assertRaisesRegex(prepare.Rejected, "symlink"):
                    prepare.verify_allowlist(root, lock)
            finally:
                source.unlink(missing_ok=True)
                outside.unlink(missing_ok=True)

    def test_closed_tree_rejects_added_regular_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            tree = root / "inputs"
            tree.mkdir()
            file = tree / "literal.sql"
            file.write_bytes(b"source")
            lock = {
                "sourceAllowlist": {"inputs/literal.sql": digest(b"source")},
                "closedTrees": {"inputs": ["inputs/literal.sql"]},
            }
            prepare.verify_allowlist(root, lock)
            (tree / "unexpected.txt").write_text("extra")
            with self.assertRaisesRegex(prepare.Rejected, "file set drift"):
                prepare.verify_allowlist(root, lock)
            (tree / "unexpected.txt").unlink()
            outside = root / "outside"
            outside.write_text("x")
            (tree / "alias").symlink_to(outside)
            with self.assertRaisesRegex(prepare.Rejected, "symlink"):
                prepare.verify_allowlist(root, lock)

    def test_lock_rejects_unsafe_paths_duplicates_and_tool_drift(self):
        base = {
            "schemaVersion": 1,
            "status": "SOURCE_LOCKED_NOT_ADMITTED",
            "admission": "TWO_DISTINCT_SOURCE_BOUND_INTEGRATOR_AND_REVIEWER_RECEIPTS_REQUIRED",
            "productionQualified": False,
            "postgresVersion": "18.6",
            "bunVersion": "1.4.2",
            "sourceAllowlist": {
                "auth-app/test.ts": "a" * 64,
                "lomi-remote/staging/consumer-derivatives-v3-product-successor/source-manifest.json": "b" * 64,
            },
            "successorManifestSha256": "b" * 64,
            "closedTrees": {"auth-app": ["auth-app/test.ts"]},
            "postgresRoot": "/opt/homebrew/Cellar/postgresql@18/18.6_1",
            "postgresFiles": {
                **{f"lib/closure-{index}": "a" * 64 for index in range(3000)},
                "bin/initdb": "a" * 64,
                "bin/postgres": "a" * 64,
                "bin/pg_ctl": "a" * 64,
                "bin/psql": "a" * 64,
            },
            "postgresSymlinks": {},
            "postgresDependencies": {"/tmp/lib.dylib": "a" * 64},
            "postgresDependencyAliases": {},
            "postgresDependencyAliasTargets": {},
            "postgresFormulaAliases": {},
            "systemDependencies": {"/usr/lib/libSystem.B.dylib": [{
                "compatibilityVersion": "1.0.0", "currentVersion": "1359.0.0",
            }]},
            "hostPlatform": {"macVersion": "27.0.1", "machine": "arm64"},
            "postgresLoadCommands": {"bin/postgres": []},
            "postgresLoadCommandsSha256": "a" * 64,
            "bunLoadCommands": {"bun": []},
            "bunLoadCommandsSha256": "a" * 64,
            "bunPath": prepare.BUN_PATH,
            "bunCanonicalPath": prepare.BUN_CANONICAL_PATH,
            "bunSha256": prepare.BUN_SHA256,
            "bunDependencies": {"/tmp/libbun.dylib": "a" * 64},
            "bunDependencyAliases": {},
            "bunDependencyAliasTargets": {},
            "runtimeDependencyPath": str(prepare.WORKSPACE / "auth-app/node_modules"),
            "runtimeDependencySymlinks": {},
            "runtimeDependencyTreeSha256": "a" * 64,
            "prismaCliPath": prepare.PRISMA_CLI_PATH,
            "prismaCliSha256": prepare.PRISMA_CLI_SHA256,
            "prismaSchemaEnginePath": prepare.PRISMA_SCHEMA_ENGINE_PATH,
            "prismaSchemaEngineSha256": prepare.PRISMA_SCHEMA_ENGINE_SHA256,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inputs.lock.json"
            path.write_text(json.dumps(base))
            original = prepare.LOCK_PATH
            prepare.LOCK_PATH = path
            try:
                prepare.load_lock()
                for change in (
                    {"postgresVersion": "latest"},
                    {"admission": "OPEN"},
                    {"productionQualified": True},
                    {"sourceAllowlist": {"../outside": "a" * 64}},
                    {"closedTrees": {"auth-app": ["auth-app/test.ts", "auth-app/test.ts"]}},
                    {"prismaCliSha256": "0" * 64},
                    {"prismaSchemaEnginePath": "/tmp/unpinned-schema-engine"},
                    {"successorManifestSha256": "c" * 64},
                    {"successorManifestSha256": None},
                ):
                    changed = dict(base)
                    changed.update(change)
                    path.write_text(json.dumps(changed))
                    with self.subTest(change=change), self.assertRaises(prepare.Rejected):
                        prepare.load_lock()
            finally:
                prepare.LOCK_PATH = original


class RawCaptureAndPinFillTests(unittest.TestCase):
    def test_capture_retains_exact_utf8_definition_and_rejects_mutation(self):
        row = function_row("public.f(uuid)", "CREATE FUNCTION public.f()\n  -- keep spacing\n  SELECT 'é';\n")
        raw = capture(row)
        parsed = evidence.verify_capture(raw)
        self.assertEqual(parsed["functions"]["public.f(uuid)"]["definition"], row["definition"])
        changed = json.loads(raw)
        changed["definition"] = changed["definition"].replace("keep spacing", "changed")
        with self.assertRaisesRegex(evidence.Rejected, "raw UTF-8 bytes"):
            evidence.verify_capture(capture(changed))

    def test_duplicate_functions_and_wrong_category_closure_fail(self):
        row = function_row("public.f(uuid)", "CREATE FUNCTION f()\n")
        with self.assertRaisesRegex(evidence.Rejected, "duplicate"):
            evidence.verify_capture(capture(row, row))
        with self.assertRaisesRegex(evidence.Rejected, "category closure"):
            evidence.verify_capture(capture(row), expected_kinds={"function", "role"})

    def test_null_pin_fill_changes_only_explicit_null_tokens(self):
        source = b'{\n  "roots": [{"old": null, "new": null}],\n  "note": "preserve \xc3\xa9"\n}\n'
        values = {("roots", 0, "old"): "1" * 64, ("roots", 0, "new"): ["EXECUTE"]}
        correlations = {path: {"ref": "independent"} for path in values}
        output, deltas = evidence.fill_null_spans(source, values, correlations)
        self.assertEqual(len(deltas), 2)
        self.assertIn(b'"note": "preserve \xc3\xa9"', output)
        self.assertEqual(json.loads(output)["roots"][0]["old"], "1" * 64)
        self.assertEqual(json.loads(output)["roots"][0]["new"], ["EXECUTE"])
        with self.assertRaisesRegex(evidence.Rejected, "closure"):
            evidence.fill_null_spans(source, {("roots", 0, "old"): "x"}, {("roots", 0, "old"): {}})

    def test_pin_values_are_derived_from_reference_captures_only(self):
        signature = "public.root(uuid)"
        helper_signature = "public.helper(uuid)"
        old_row = function_row(signature, "CREATE FUNCTION root_old()\n")
        new_row = function_row(signature, "CREATE FUNCTION root_new()\n")
        helper_old = function_row(helper_signature, "CREATE FUNCTION helper_old()\n", "lomi_migrator")
        helper_new = function_row(helper_signature, "CREATE FUNCTION helper_new()\n", "lomi_consumer_auth_body_owner")
        contract = {
            "status": "UNMEASURED_CATALOG_FAIL_CLOSED",
            "roots": [{
                "signature": signature,
                "owner": "lomi_remote_inventory_owner",
                "old_catalog_sha256": None,
                "new_catalog_sha256": None,
                "old_acl": None,
                "new_acl": None,
            }],
            "prerequisites": [],
        }
        helper_contract = {
            "status": "UNMEASURED_CATALOG_FAIL_CLOSED",
            "helpers": [{
                "signature": helper_signature,
                "old_owner": "lomi_migrator",
                "new_owner": "lomi_consumer_auth_body_owner",
                "old_catalog_sha256": None,
                "new_catalog_sha256": None,
                "old_acl": None,
                "new_acl": None,
            }],
        }
        values, correlations = evidence.pin_values_from_references(
            contract, capture(old_row), capture(new_row), helper_contract,
            capture(helper_old), capture(helper_new),
        )
        root_values = values["catalog-contract.pending.json"]
        self.assertEqual(root_values[("roots", 0, "old_catalog_sha256")], old_row["catalogSha256"])
        self.assertEqual(root_values[("roots", 0, "new_catalog_sha256")], new_row["catalogSha256"])
        self.assertEqual(correlations["catalog-contract.pending.json"][("roots", 0, "old_catalog_sha256")]["referenceState"], "old")
        self.assertEqual(values["helper-seal.pending.json"][("helpers", 0, "new_acl")], helper_new["acl"])

    def test_frozen_contract_pin_keys_and_null_fill_cover_all_rows(self):
        contract_raw = frozen_bytes("catalog-contract.pending.json")
        helper_raw = frozen_bytes("helper-seal.pending.json")
        contract = evidence.strict_json(contract_raw, "frozen catalog contract")
        helper_contract = evidence.strict_json(helper_raw, "frozen helper contract")
        evidence.validate_null_pins(contract, helper_contract)
        signatures = {
            row["signature"]
            for rows in (contract["roots"], contract["prerequisites"], helper_contract["helpers"])
            for row in rows
        }
        def add_capture_row(target, item, state, owner):
            signature = item["signature"]
            acl = [{"grantor": "fixture_owner", "grantee": "PUBLIC" if state == "old" else "lomi_runtime",
                    "privilege": "EXECUTE", "grantable": False}]
            target.append(function_row(signature, f"CREATE FUNCTION {signature} -- {state}\n",
                                       owner=owner, acl=acl))

        old_rows = []
        new_rows = []
        old_seen = set()
        new_seen = set()
        for item in contract["roots"]:
            add_capture_row(old_rows, item, "old", item["owner"])
            add_capture_row(new_rows, item, "new", item["owner"])
            old_seen.add(item["signature"])
            new_seen.add(item["signature"])
        for item in helper_contract["helpers"]:
            add_capture_row(old_rows, item, "old", item["old_owner"])
            old_seen.add(item["signature"])
        for item in contract["prerequisites"]:
            if item["signature"] not in new_seen:
                add_capture_row(new_rows, item, "new", item["owner"])
                new_seen.add(item["signature"])
        for item in helper_contract["helpers"]:
            if item["signature"] not in new_seen:
                add_capture_row(new_rows, item, "new", item["new_owner"])
                new_seen.add(item["signature"])
        values, correlations = evidence.pin_values_from_references(
            contract, capture(*old_rows), capture(*new_rows), helper_contract,
            capture(*old_rows), capture(*new_rows),
        )
        catalog_values = values["catalog-contract.pending.json"]
        helper_values = values["helper-seal.pending.json"]
        self.assertEqual(len(catalog_values), len(contract["roots"]) * 4 + len(contract["prerequisites"]) * 2)
        self.assertEqual(len(helper_values), len(helper_contract["helpers"]) * 4)
        self.assertIn(("roots", 0, "old_catalog_sha256"), catalog_values)
        self.assertIn(("roots", 0, "new_acl"), catalog_values)
        self.assertIn(("prerequisites", 0, "catalog_sha256"), catalog_values)
        self.assertNotIn(("roots", 0, "catalog_sha256_old"), catalog_values)
        filled_catalog, _ = evidence.fill_null_spans(contract_raw, catalog_values,
                                                     correlations["catalog-contract.pending.json"])
        filled_helpers, _ = evidence.fill_null_spans(helper_raw, helper_values,
                                                     correlations["helper-seal.pending.json"])
        self.assertTrue(all(pin is None for row in contract["roots"] for pin in
                            (row["old_catalog_sha256"], row["new_catalog_sha256"], row["old_acl"], row["new_acl"])))
        self.assertTrue(all(pin is None for row in helper_contract["helpers"] for pin in
                            (row["old_catalog_sha256"], row["new_catalog_sha256"], row["old_acl"], row["new_acl"])))
        self.assertEqual(len(evidence.strict_json(filled_catalog)["roots"]), len(contract["roots"]))
        self.assertEqual(len(evidence.strict_json(filled_helpers)["helpers"]), len(helper_contract["helpers"]))
        self.assertTrue(all(correlations["catalog-contract.pending.json"][key]["referenceState"] in ("old", "new")
                            for key in catalog_values))

    def test_non_null_or_unmeasured_source_contract_never_fills(self):
        contract = {
            "status": "UNMEASURED_CATALOG_FAIL_CLOSED",
            "roots": [{"old_catalog_sha256": "filled", "new_catalog_sha256": None, "old_acl": None, "new_acl": None}],
            "prerequisites": [],
        }
        helper = {"status": "UNMEASURED_CATALOG_FAIL_CLOSED", "helpers": []}
        with self.assertRaisesRegex(evidence.Rejected, "modified"):
            evidence.validate_null_pins(contract, helper)

    def test_reference_equality_maps_only_internal_foreign_key_trigger_identity(self):
        structure = {
            "kind": "trigger",
            "relation": "public.remote_session_binding",
            "constraint": "remote_session_binding_session_id_fkey",
            "enabled": "O",
            "internal": True,
            "function": "pg_catalog.ri_fkey_cascade_del()",
            "type": 9,
            "deferrable": False,
            "deferred": False,
            "referencedRelation": "public.session_metadata",
            "constraintIndex": "public.remote_session_binding_session_id_fkey",
            "columns": "1",
        }
        old_trigger = {**structure, "name": "RI_ConstraintTrigger_a_12345",
                       "definition": "CREATE TRIGGER RI_ConstraintTrigger_a_12345 ..."}
        new_trigger = {**structure, "name": "RI_ConstraintTrigger_a_98765",
                       "definition": "CREATE TRIGGER RI_ConstraintTrigger_a_98765 ..."}
        stable = function_row("public.lomi_example(uuid)", "CREATE FUNCTION exact()\n")
        self.assertTrue(evidence.stable_catalog_equality(capture(old_trigger, stable),
                                                         capture(new_trigger, stable)))
        changed = {**new_trigger, "constraint": "other_constraint"}
        self.assertFalse(evidence.stable_catalog_equality(capture(old_trigger, stable),
                                                          capture(changed, stable)))
        changed_function = function_row("public.lomi_example(uuid)", "CREATE FUNCTION changed()\n")
        self.assertFalse(evidence.stable_catalog_equality(capture(old_trigger, stable),
                                                          capture(new_trigger, changed_function)))


class AdmissionAndStageTests(unittest.TestCase):
    def _receipts(self):
        controller = "a" * 64
        manifest = "b" * 64
        independent = {
            "schemaVersion": 1,
            "scope": admission.SCOPE,
            "reviewerId": "independent-reviewer",
            "reviewStatus": "PASS",
            "reviewNonce": "10000000-0000-4000-8000-000000000001",
            "controllerSha256": controller,
            "bundleManifestSha256": manifest,
            "reviewedFullS0S7Source": True,
            "reviewedNoRunBeforeAdmission": True,
            "identifiedStageGapsExplicitly": True,
        }
        independent_raw = (json.dumps(independent, sort_keys=True) + "\n").encode("ascii")
        root = {
            "schemaVersion": 1,
            "scope": admission.SCOPE,
            "integratorId": "root-integrator",
            "rootReviewStatus": "PASS",
            "rootReviewComplete": True,
            "executionAuthorized": True,
            "admissionNonce": "20000000-0000-4000-8000-000000000002",
            "controllerSha256": controller,
            "bundleManifestSha256": manifest,
            "independentReviewSha256": digest(independent_raw),
            "postgresVersion": "18.6",
            "databaseName": "lomi_auth_test",
            "maximumConnections": 16,
            "maximumRealRolePools": 4,
            "maximumPoolSize": 2,
            "originalDeadlineSeconds": 900,
            "productionTargetOption": False,
            "acknowledgedStageGaps": True,
        }
        root_raw = (json.dumps(root, sort_keys=True) + "\n").encode("ascii")
        return root_raw, independent_raw, controller, manifest

    def test_admission_requires_both_exactly_bound_distinct_reviewers(self):
        root_raw, independent_raw, controller, manifest = self._receipts()
        admission.validate_receipts(root_raw, independent_raw,
                                    controller_sha256=controller,
                                    manifest_sha256=manifest)
        with self.assertRaisesRegex(admission.Rejected, "root receipt"):
            admission.validate_receipts(b"{}", independent_raw,
                                        controller_sha256=controller,
                                        manifest_sha256=manifest)
        changed = json.loads(independent_raw)
        changed["bundleManifestSha256"] = "c" * 64
        changed_raw = (json.dumps(changed, sort_keys=True) + "\n").encode("ascii")
        with self.assertRaisesRegex(admission.Rejected, "independent review"):
            admission.validate_receipts(root_raw, changed_raw,
                                        controller_sha256=controller,
                                        manifest_sha256=manifest)

    def test_wrong_resource_budget_or_same_reviewer_rejected(self):
        root_raw, independent_raw, controller, manifest = self._receipts()
        root = json.loads(root_raw)
        root["maximumConnections"] = 2
        with self.assertRaisesRegex(admission.Rejected, "root receipt"):
            admission.validate_receipts((json.dumps(root) + "\n").encode(), independent_raw,
                                        controller_sha256=controller,
                                        manifest_sha256=manifest)
        root_raw, independent_raw, controller, manifest = self._receipts()
        root = json.loads(root_raw)
        root["integratorId"] = "independent-reviewer"
        root_raw = (json.dumps(root, sort_keys=True) + "\n").encode("ascii")
        with self.assertRaisesRegex(admission.Rejected, "root receipt"):
            admission.validate_receipts(root_raw, independent_raw,
                                        controller_sha256=controller,
                                        manifest_sha256=manifest)

    def test_s6_marker_requires_full_exact_key_set_and_all_true(self):
        values = {key: True for key in evidence.S6_ACCEPTANCE_KEYS}
        result = evidence.parse_s6_acceptance(
            b"LOMI_CONSUMER_DERIVATIVE_PRODUCT_ACCEPTED="
            + json.dumps(values, sort_keys=True).encode() + b"\n"
        )
        self.assertTrue(result["pairingChannelTicketActualTransactions"])
        values["positiveFixtureCleanupVerified"] = False
        with self.assertRaisesRegex(evidence.Rejected, "every asserted behavior"):
            evidence.parse_s6_acceptance(
                b"LOMI_CONSUMER_DERIVATIVE_PRODUCT_ACCEPTED="
                + json.dumps(values).encode() + b"\n"
            )

    def test_stage_cannot_pass_without_authoritative_evidence(self):
        statuses = {f"S{i}": "NOT_RUN" for i in range(8)}
        evidence.validate_stage_statuses(statuses, {})
        statuses["S7"] = "PASS"
        with self.assertRaisesRegex(evidence.Rejected, "without authoritative"):
            evidence.validate_stage_statuses(statuses, {"S7": False})
        with self.assertRaisesRegex(evidence.Rejected, "invalid stage status"):
            evidence.validate_stage_statuses({**statuses, "S7": "SUBSET_PASS"}, {"S7": True})


class ControllerSafetyTests(unittest.TestCase):
    def void_row(self):
        return function_row(
            "public.lomi_consumer_probe(uuid)",
            "CREATE OR REPLACE FUNCTION public.lomi_consumer_probe(p_id uuid)\n"
            " RETURNS void\n LANGUAGE plpgsql\n SECURITY DEFINER\n"
            " SET search_path TO 'pg_catalog', 'public', 'pg_temp'\n"
            "AS $function$\nBEGIN RAISE EXCEPTION 'deny'; END;\n$function$\n",
        )

    def test_body_bypass_probe_preserves_header_and_rejects_unverified_shapes(self):
        row = self.void_row()
        raw = controller.bypass_void_body_sql(row)
        header = row["definition"].split("$function$", 1)[0] + "$function$"
        self.assertTrue(raw.startswith(header.encode()))
        self.assertIn(b"\nBEGIN RETURN; END;\n$function$\n;\n", raw)
        self.assertNotIn(b"RAISE EXCEPTION", raw)
        for change in (
            {"definitionUtf8Hex": "00"}, {"catalogSha256": "0" * 64},
            {"definition": row["definition"].replace("RETURNS void", "RETURNS boolean")},
            {"definition": row["definition"].replace("$function$", "$other$")},
        ):
            with self.subTest(change=change), self.assertRaises(controller.Rejected):
                controller.bypass_void_body_sql({**row, **change})

    def test_exact_operator_reason_rejects_other_errors_or_reason_in_source_context(self):
        expected = "unexpected root definition/ACL: public.lomi_consumer_probe(uuid)"

        class Fixture:
            def psql(self, database, **options):
                self.options = options
                return {"returnCode": 3, "stderr": self.stderr, "stdout": b"",
                        "stderrSha256": digest(self.stderr)}

        fixture = Fixture()
        fixture.stderr = ("psql:/private/probe.sql:4: ERROR:  P0001: " + expected + "\n").encode()
        result = controller.expected_operator_denial(
            fixture, operator=Path("/private/probe.sql"), label="body-probe",
            expected_error=expected, exact_reason=True)
        self.assertTrue(result["exactP0001ReasonVerified"])
        self.assertEqual(fixture.options["extra_args"], ("-v", "VERBOSITY=verbose"))
        for text in (
            "ERROR: 42601: syntax error\nCONTEXT: " + expected + "\n",
            "ERROR: P0001: unmeasured catalog/ACL pins\nCONTEXT: " + expected + "\n",
            "ERROR: 42501: " + expected + "\n",
            "ERROR: P0001: " + expected + "\nERROR: P0001: other\n",
        ):
            fixture.stderr = text.encode()
            with self.subTest(text=text), self.assertRaises(controller.Rejected):
                controller.expected_operator_denial(
                    fixture, operator=Path("/private/probe.sql"), label="body-probe",
                    expected_error=expected, exact_reason=True)

    def test_body_drift_requires_complete_preservation_and_restoration(self):
        original = self.void_row()
        modified = {**original, "definition": controller.bypass_void_body_sql(original)[:-2].decode()}
        modified["definitionUtf8Hex"] = modified["definition"].encode().hex()
        modified["catalogSha256"] = digest(modified["definition"].encode())
        reason = "unexpected root definition/ACL: " + original["signature"]
        for drift in (False, True):
            class Fixture:
                captures = 0
                scripts = []

                def capture_catalog(self, database, label):
                    rows = (original, modified, modified, original)
                    raw = capture(rows[self.captures])
                    if drift and self.captures == 2:
                        raw += capture({"kind": "role", "name": "unexpected_role"})
                    self.captures += 1
                    return raw

                def apply_script(self, database, raw, label): self.scripts.append(raw)

                def psql(self, database, **options):
                    raw = ("ERROR: P0001: " + reason + "\n").encode()
                    return {"returnCode": 3, "stderr": raw, "stdout": b"", "stderrSha256": digest(raw)}

            fixture = Fixture()
            parameters = {"operator": Path("/private/probe.sql"), "signature": original["signature"],
                          "expected_row": original, "label": "body-drift", "expected_error": reason}
            if drift:
                with self.assertRaisesRegex(controller.Rejected, "changed catalog state"):
                    controller.run_catalog_body_denial(fixture, **parameters)
                self.assertEqual(len(fixture.scripts), 1)
            else:
                receipt = controller.run_catalog_body_denial(fixture, **parameters)
                self.assertTrue(receipt["completeCatalogRestoredBeforePositiveControl"])
                self.assertEqual(receipt["beforeCaptureSha256"], receipt["restoredCaptureSha256"])
                self.assertEqual(len(fixture.scripts), 2)

    def test_all_helper_plans_pass_real_psql_role_gate_with_exact_private_targets(self):
        run_uuid = "7e1c2b9f-9b28-4b52-a345-12dfcb08a012"
        with tempfile.TemporaryDirectory() as temporary:
            fixture = object.__new__(controller.Fixture)
            fixture.work = Path(temporary)
            (fixture.work / "sql").mkdir(mode=0o700)

            class Counter:
                serial = 0

            fixture.runner = Counter()
            fixture.lock, _ = prepare.load_lock()
            fixture.pg = Path(fixture.lock["postgresRoot"])
            observed = []

            def command(label, argv, **options):
                observed.append((argv, options))
                fixture.runner.serial += 1
                return {"label": label}

            fixture.command = command
            for index, attempt in enumerate(helper_denials.build_attempts(run_uuid)):
                raw = attempt["sql"].encode()
                fixture.psql("lomi_auth_test", user=attempt["connectionRole"],
                             script=raw, label=f"helper-{index:03d}", expected=(0,), timeout=20)
                argv, options = observed[-1]
                self.assertEqual(argv[0], str(fixture.pg / "bin/psql"))
                self.assertEqual(argv[argv.index("-U") + 1], attempt["role"])
                self.assertNotEqual(argv[argv.index("-U") + 1], "e2_owner")
                self.assertEqual(argv[argv.index("-d") + 1], "lomi_auth_test")
                self.assertEqual(argv[argv.index("-h") + 1], str(fixture.work / "socket"))
                self.assertEqual(argv[argv.index("-p") + 1], controller.PORT)
                self.assertEqual(Path(argv[argv.index("-f") + 1]).read_bytes(), raw)
                self.assertIn("ON_ERROR_STOP=1", argv)
                self.assertIn("--no-psqlrc", argv)
                self.assertEqual(options["expected"], (0,))
            self.assertEqual(len(observed), 80)
            for role in ("postgres", "unknown_role", helper_denials.BODY_OWNER):
                with self.subTest(role=role), self.assertRaisesRegex(controller.Rejected, "unapproved private database role"):
                    fixture.psql("lomi_auth_test", user=role, script=b"SELECT 1;")
            with self.assertRaisesRegex(controller.Rejected, "outside the private fixture"):
                fixture.psql("production", user="lomi_migrator", script=b"SELECT 1;")
            self.assertEqual(len(observed), 80)

    def test_repeated_script_label_preserves_distinct_database_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = object.__new__(controller.Fixture)
            fixture.work = Path(temporary)
            (fixture.work / "sql").mkdir(mode=0o700)

            class Counter:
                serial = 0

            fixture.runner = Counter()
            observed = []

            def psql(database, *, user, source_path, label):
                observed.append((database, source_path, source_path.read_bytes()))
                fixture.runner.serial += 1
                return {"label": label}

            fixture.psql = psql
            raw = b"SELECT 1;\n"
            fixture.apply_script(controller.DATABASES["target"], raw, "ownership")
            fixture.apply_script(controller.DATABASES["referenceNew"], raw, "ownership")
            self.assertEqual(len(observed), 2)
            self.assertNotEqual(observed[0][1], observed[1][1])
            self.assertEqual([entry[2] for entry in observed], [raw, raw])
            self.assertEqual({entry[1].parent for entry in observed}, {fixture.work / "sql"})
            self.assertEqual(len(list((fixture.work / "sql").iterdir())), 2)

    def test_private_server_settings_pins_homebrew_text_and_numeric_version(self):
        work = Path("/tmp/lomi-e2-server-version-test")
        capture_row = {
            "listen": "",
            "socket": str(work / "socket"),
            "data": str(work / "data"),
            "max": "16",
            "port": "55439",
            "version": "18.6 (Homebrew)",
            "version_num": "180006",
        }
        captured = controller.strict_json(
            json.dumps(capture_row, separators=(",", ":")).encode("utf-8"),
            "actual server-settings capture shape",
        )
        controller.validate_private_server_settings(captured, work)
        self.assertEqual(capture_row["version"], controller.PINNED_POSTGRES_TEXT_VERSION)
        self.assertEqual(capture_row["version_num"], controller.PINNED_POSTGRES_SERVER_VERSION_NUM)

        for version in ("18.6", "18.7 (Homebrew)", "18.6 (custom)"):
            invalid = dict(capture_row, version=version)
            with self.subTest(version=version), self.assertRaisesRegex(
                    controller.Rejected, "socket/version/connection settings"):
                controller.validate_private_server_settings(invalid, work)
        invalid_numeric = dict(capture_row, version_num="180007")
        with self.assertRaisesRegex(controller.Rejected, "socket/version/connection settings"):
            controller.validate_private_server_settings(invalid_numeric, work)

    def test_postfailure_source_hash_status_does_not_claim_deadline_elapsed(self):
        self.assertEqual(controller.SOURCE_AFTER_FAILURE_STATUS, "NOT_VERIFIED_AFTER_FAILURE")

    def test_s6_private_urls_and_pgport_are_one_socket_endpoint(self):
        socket_path = "/tmp/lomi-e2-12345678/socket"
        env = controller.s6_private_environment(Path("/tmp/lomi-e2-12345678"), socket_path)
        controller.validate_s6_private_environment(env, socket_path)
        self.assertEqual(env["PGPORT"], controller.PORT)
        for variable, url in controller.s6_urls(socket_path).items():
            self.assertEqual(env[variable], url)

        wrong_port = dict(env, PGPORT="5432")
        with self.assertRaisesRegex(controller.Rejected, "PGPORT"):
            controller.validate_s6_private_environment(wrong_port, socket_path)
        explicit_port = dict(env)
        explicit_port["LOMI_E2_PRIVATE_RUNTIME_URL"] = (
            f"postgresql://lomi_runtime@localhost:{controller.PORT}/"
            f"{controller.DATABASES['target']}?host={socket_path}")
        with self.assertRaisesRegex(controller.Rejected, "private socket"):
            controller.validate_s6_private_environment(explicit_port, socket_path)
        extra_endpoint = dict(env)
        extra_endpoint["LOMI_E2_PRIVATE_EXCHANGE_URL"] += "&port=5432"
        with self.assertRaisesRegex(controller.Rejected, "private socket"):
            controller.validate_s6_private_environment(extra_endpoint, socket_path)
        wrong_role = dict(env)
        wrong_role["LOMI_E2_PRIVATE_REMOTE_URL"] = env["LOMI_E2_PRIVATE_RUNTIME_URL"]
        with self.assertRaisesRegex(controller.Rejected, "private socket"):
            controller.validate_s6_private_environment(wrong_role, socket_path)

    def test_s7_uses_same_role_targets_and_only_owned_evidence_paths(self):
        work = Path("/tmp/lomi-e2-12345678")
        socket_path = str(work / "socket")
        with patch.dict(os.environ, {"DATABASE_URL": "postgresql://production.invalid/db",
                                     "LOMI_E2_S7_OUTPUT_PATH": "/tmp/unowned"}):
            env = controller.s7_private_environment(work, socket_path)
        additions = {
            "LOMI_E2_CONSUMER_DERIVATIVE_POPULATED_RUNTIME": "true",
            "LOMI_E2_S7_SOURCE_ROOT": str(work / "s7-sources"),
            "LOMI_E2_S7_PLAN_PATH": str(work / "s7-plan.json"),
            "LOMI_E2_S7_OUTPUT_PATH": str(work / "s7-output.json"),
        }
        self.assertEqual({key: env[key] for key in additions}, additions)
        base = {key: value for key, value in env.items() if key not in additions}
        controller.validate_s6_private_environment(base, socket_path)
        self.assertNotIn("DATABASE_URL", env)

    def test_prisma_source_closure_is_only_pinned_project_config_and_migrations(self):
        lock, _ = prepare.load_lock()
        paths = controller.prisma_migration_source_paths(lock["sourceAllowlist"])
        migration_files = {path for path in paths if path.endswith("/migration.sql")}
        self.assertEqual(set(paths) - migration_files, {
            "auth-app/package.json",
            "auth-app/bun.lock",
            "auth-app/prisma.config.ts",
            "auth-app/prisma/schema.prisma",
            "auth-app/prisma/migrations/migration_lock.toml",
        })
        migration_names = [Path(path).parent.name for path in paths if path.endswith("/migration.sql")]
        self.assertIn("202610220012_web_channel_window_binding", migration_names)
        self.assertIn("202610220013_consumer_challenge_pruning", migration_names)
        self.assertEqual(len(migration_names), len(set(migration_names)))
        with self.assertRaisesRegex(controller.Rejected, "inputs are incomplete"):
            controller.prisma_migration_source_paths({"auth-app/package.json": "a" * 64})
        without_012 = {key: value for key, value in lock["sourceAllowlist"].items()
                       if not key.startswith("auth-app/prisma/migrations/202610220012_")}
        with self.assertRaisesRegex(controller.Rejected, "must include 202610220012"):
            controller.prisma_migration_source_paths(without_012)

    def test_prisma_config_has_only_explicit_migration_database_url(self):
        lock, _ = prepare.load_lock()
        config = prepare.read_exact(prepare.WORKSPACE, "auth-app/prisma.config.ts",
                                    lock["sourceAllowlist"]["auth-app/prisma.config.ts"])
        self.assertEqual(controller.validate_prisma_config_source(config), {
            "schema": "prisma/schema.prisma",
            "migrations": "prisma/migrations",
            "databaseUrlVariable": "MIGRATION_DATABASE_URL",
        })
        mutations = (
            config.replace(b'MIGRATION_DATABASE_URL', b'DATABASE_URL'),
            config.replace(b'datasource: { url: env("MIGRATION_DATABASE_URL") }',
                           b'datasource: { url: env("MIGRATION_DATABASE_URL") || env("DATABASE_URL") }'),
            config + b"\nconst fallback = process.env.DATABASE_URL;\n",
            config.replace(b'prisma/migrations', b'other/migrations'),
        )
        for mutated in mutations:
            with self.subTest(source=mutated), self.assertRaisesRegex(
                    controller.Rejected, "must use only the private migration URL"):
                controller.validate_prisma_config_source(mutated)

    def test_prisma_ledger_verifies_every_pinned_migration_checksum_and_finished_state(self):
        migration_sources = {
            "auth-app/prisma/migrations/202610220012_web_binding/migration.sql": b"CREATE TABLE a;\n",
            "auth-app/prisma/migrations/202610220013_pruning/migration.sql": b"CREATE TABLE b;\n",
        }
        expected = controller.prisma_expected_migrations(migration_sources)
        good_rows = [
            {"migrationName": item["migrationName"], "checksum": item["checksum"],
             "finishedAt": "2026-10-23T10:00:00Z", "rolledBackAt": None}
            for item in expected
        ]
        raw = b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in good_rows)
        self.assertEqual(controller.validate_prisma_migration_ledger(raw, expected), good_rows)
        self.assertEqual(controller.digest(migration_sources["auth-app/prisma/migrations/202610220012_web_binding/migration.sql"]),
                         expected[0]["checksum"])

        bad_sets = (
            [dict(good_rows[0], checksum="0" * 64), good_rows[1]],
            [dict(good_rows[0], finishedAt=None), good_rows[1]],
            [dict(good_rows[0], rolledBackAt="2026-10-23T10:00:00Z"), good_rows[1]],
            [good_rows[0]],
            [*good_rows, dict(good_rows[1])],
            [dict(good_rows[0], unexpected=True), good_rows[1]],
        )
        for rows in bad_sets:
            candidate = b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows)
            with self.subTest(rows=rows), self.assertRaises(controller.Rejected):
                controller.validate_prisma_migration_ledger(candidate, expected)
        with self.assertRaisesRegex(controller.Rejected, "omits active migration"):
            controller.prisma_expected_migrations({
                "auth-app/prisma/migrations/202610220013_pruning/migration.sql": b"x"
            })

    def test_prisma_migration_environment_pins_login_url_port_and_socket(self):
        work = Path("/tmp/lomi-e2-10000000-0000-4000-8000-000000000001")
        socket_path = str(work / "socket")
        engine = controller.PRISMA_SCHEMA_ENGINE_PATH
        env = controller.prisma_migration_environment(
            work, controller.DATABASES["target"], socket_path, engine)
        controller.validate_prisma_migration_environment(
            env, work, controller.DATABASES["target"], socket_path, engine)
        parsed = controller.urlsplit(env["MIGRATION_DATABASE_URL"])
        self.assertEqual(parsed.username, "lomi_migrator")
        self.assertEqual(parsed.hostname, "localhost")
        self.assertEqual(parsed.port, int(controller.PORT))
        self.assertEqual(parsed.path, "/" + controller.DATABASES["target"])
        self.assertEqual(controller.parse_qsl(parsed.query, strict_parsing=True), [("host", socket_path)])
        self.assertEqual(env["PGPORT"], controller.PORT)
        self.assertEqual(env["PRISMA_SCHEMA_ENGINE_BINARY"], str(engine))
        self.assertEqual(env["JITI_FS_CACHE"], "0")
        self.assertEqual(env["CHECKPOINT_DISABLE"], "1")
        self.assertEqual(env["PRISMA_HIDE_UPDATE_MESSAGE"], "1")
        self.assertFalse({"DATABASE_URL", "DIRECT_URL", "AUTH_SECRET", "PGHOST", "PGUSER"} & set(env))

        invalid_envs = (
            dict(env, PGPORT="5432"),
            dict(env, DATABASE_URL="postgresql://production/"),
            dict(env, MIGRATION_DATABASE_URL=env["MIGRATION_DATABASE_URL"].replace(":55439/", ":5432/")),
            dict(env, PRISMA_SCHEMA_ENGINE_BINARY="/tmp/unpinned-engine"),
            dict(env, JITI_FS_CACHE="1"),
            {key: value for key, value in env.items() if key != "JITI_FS_CACHE"},
        )
        for invalid in invalid_envs:
            with self.subTest(env=invalid), self.assertRaises(controller.Rejected):
                controller.validate_prisma_migration_environment(
                    invalid, work, controller.DATABASES["target"], socket_path, engine)
        with self.assertRaisesRegex(controller.Rejected, "marked private socket"):
            controller.prisma_migration_url(controller.DATABASES["target"], "/tmp/lomi-e2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/socket")
        with self.assertRaisesRegex(controller.Rejected, "outside the private fixture"):
            controller.prisma_migration_url("production", socket_path)
        self.assertEqual(controller.prisma_migration_argv(controller.BUN_PATH), [
            str(controller.BUN_PATH), "--no-env-file", "node_modules/prisma/build/index.js",
            "migrate", "deploy", "--config", "prisma.config.ts",
        ])
        with self.assertRaisesRegex(controller.Rejected, "pinned Bun"):
            controller.prisma_migration_argv(Path("/usr/bin/bun"))

    def test_prisma_project_tree_requires_exact_copied_sources_and_single_dependency_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            project = root / "prisma-project"
            project.mkdir(mode=0o700)
            dependency_target = str(root / "node_modules")
            (root / "node_modules").mkdir(mode=0o700)
            expected = {
                "package.json": digest(b'{"name":"auth"}\n'),
                "prisma/migrations/migration_lock.toml": digest(b'provider = "postgresql"\n'),
            }
            (project / "package.json").write_bytes(b'{"name":"auth"}\n')
            (project / "package.json").chmod(0o600)
            (project / "prisma").mkdir(mode=0o700)
            (project / "prisma/migrations").mkdir(mode=0o700)
            (project / "prisma/migrations/migration_lock.toml").write_bytes(b'provider = "postgresql"\n')
            (project / "prisma/migrations/migration_lock.toml").chmod(0o600)
            (project / "node_modules").symlink_to(dependency_target)
            controller.validate_prisma_project_tree(project, expected, dependency_target, require_complete=True)

            (project / "prisma/migrations/migration_lock.toml").write_bytes(b"mutated\n")
            (project / "prisma/migrations/migration_lock.toml").chmod(0o600)
            with self.assertRaisesRegex(controller.Rejected, "source hash drift"):
                controller.validate_prisma_project_tree(project, expected, dependency_target, require_complete=True)
            (project / "prisma/migrations/migration_lock.toml").write_bytes(b'provider = "postgresql"\n')
            (project / "dotenv.env").write_text("DATABASE_URL=external\n")
            (project / "dotenv.env").chmod(0o600)
            with self.assertRaisesRegex(controller.Rejected, "unpinned file"):
                controller.validate_prisma_project_tree(project, expected, dependency_target, require_complete=True)
            (project / "dotenv.env").unlink()
            (project / "unexpected-link").symlink_to(dependency_target)
            with self.assertRaisesRegex(controller.Rejected, "unapproved dependency link"):
                controller.validate_prisma_project_tree(project, expected, dependency_target, require_complete=True)

    def test_prisma_project_incomplete_copy_can_be_cleaned_only_when_all_entries_are_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            project = root / "prisma-project"
            project.mkdir(mode=0o700)
            dependency_target = str(root / "node_modules")
            (root / "node_modules").mkdir(mode=0o700)
            source = b'{"name":"auth"}\n'
            expected = {"package.json": digest(source), "prisma/schema.prisma": digest(b"schema\n")}
            (project / "package.json").write_bytes(source)
            (project / "package.json").chmod(0o600)
            controller.validate_prisma_project_tree(project, expected, dependency_target, require_complete=False)
            with self.assertRaisesRegex(controller.Rejected, "incomplete"):
                controller.validate_prisma_project_tree(project, expected, dependency_target, require_complete=True)
            (project / "package.json").write_bytes(b"tampered\n")
            (project / "package.json").chmod(0o600)
            with self.assertRaisesRegex(controller.Rejected, "source hash drift"):
                controller.validate_prisma_project_tree(project, expected, dependency_target, require_complete=False)

    def test_phase_pin_values_bind_each_contract_to_its_independent_state(self):
        root = "public.lomi_consumer_root(uuid)"
        prerequisite = "public.lomi_consumer_prerequisite(uuid)"
        helper = "public.lomi_consumer_helper(uuid)"
        channel = "public.lomi_channel_consumer_prepare(uuid)"
        channel_prereq = "public.lomi_channel_consumer_dependency(uuid)"
        contract = {
            "status": "UNMEASURED_CATALOG_FAIL_CLOSED",
            "roots": [{"signature": root, "owner": "lomi_owner",
                       "old_catalog_sha256": None, "new_catalog_sha256": None,
                       "old_acl": None, "new_acl": None}],
            "prerequisites": [{"signature": prerequisite, "owner": "lomi_owner",
                               "catalog_sha256": None, "acl": None}],
        }
        helper_contract = {
            "status": "UNMEASURED_CATALOG_FAIL_CLOSED",
            "helpers": [{"signature": helper, "old_owner": "lomi_migrator",
                         "new_owner": "lomi_consumer_auth_body_owner",
                         "old_catalog_sha256": None, "new_catalog_sha256": None,
                         "old_acl": None, "new_acl": None}],
        }
        channel_contract = {
            "status": "UNMEASURED_CATALOG_FAIL_CLOSED",
            "roots": [{"signature": channel, "owner": "lomi_owner",
                       "old_catalog_sha256": None, "new_catalog_sha256": None,
                       "old_acl": None, "new_acl": None}],
            "prerequisites": [{"signature": channel_prereq, "owner": "lomi_owner",
                               "catalog_sha256": None, "acl": None}],
        }

        def row(signature, token, owner):
            return function_row(
                signature, f"CREATE FUNCTION product_{token}(uuid) RETURNS void LANGUAGE sql AS $$SELECT$$;\n",
                owner=owner,
                acl=[{"grantor": owner, "grantee": "lomi_runtime_" + token,
                      "privilege": "EXECUTE", "grantable": False}],
            )

        rows_by_phase = {
            "activeBaseline": [row(root, "root_old_active", "lomi_owner")],
            "postSourcePreSeal": [row(helper, "helper_old_source", "lomi_migrator")],
            "postHelperSeal": [row(helper, "helper_new_sealed", "lomi_consumer_auth_body_owner")],
            "postThreeRoots": [row(root, "root_new_three", "lomi_owner"),
                               row(prerequisite, "prerequisite_new_three", "lomi_owner")],
            "preChannelAccess": [row(channel, "channel_old_access", "lomi_owner")],
            "postChannel": [row(channel, "channel_new_sealed", "lomi_owner"),
                            row(channel_prereq, "channel_prerequisite_new", "lomi_owner")],
        }
        captures = {
            name: b"".join(json.dumps(item, separators=(",", ":")).encode() + b"\n"
                           for item in rows)
            for name, rows in rows_by_phase.items()
        }
        primary, _, channel_values, _ = controller.derive_phase_pin_values(
            contract, helper_contract, channel_contract, captures)
        catalog = primary["catalog-contract.pending.json"]
        helpers = primary["helper-seal.pending.json"]
        channels = channel_values["catalog-contract.pending.json"]
        self.assertEqual(catalog[("roots", 0, "old_catalog_sha256")], rows_by_phase["activeBaseline"][0]["catalogSha256"])
        self.assertEqual(catalog[("roots", 0, "new_catalog_sha256")], rows_by_phase["postThreeRoots"][0]["catalogSha256"])
        self.assertEqual(catalog[("prerequisites", 0, "catalog_sha256")], rows_by_phase["postThreeRoots"][1]["catalogSha256"])
        self.assertEqual(helpers[("helpers", 0, "old_catalog_sha256")], rows_by_phase["postSourcePreSeal"][0]["catalogSha256"])
        self.assertEqual(helpers[("helpers", 0, "new_catalog_sha256")], rows_by_phase["postHelperSeal"][0]["catalogSha256"])
        self.assertEqual(channels[("roots", 0, "old_catalog_sha256")], rows_by_phase["preChannelAccess"][0]["catalogSha256"])
        self.assertEqual(channels[("roots", 0, "new_catalog_sha256")], rows_by_phase["postChannel"][0]["catalogSha256"])
        self.assertEqual(channels[("prerequisites", 0, "catalog_sha256")], rows_by_phase["postChannel"][1]["catalogSha256"])
        self.assertEqual(controller.phase_pin_capture_mapping(), {
            "threeRootOld": {"contract": "activeBaseline"},
            "threeRootNewAndPrerequisites": {"contract": "postThreeRoots"},
            "helperOld": {"contract": "postSourcePreSeal"},
            "helperNew": {"contract": "postHelperSeal"},
            "channelOld": {"contract": "preChannelAccess"},
            "channelNewAndPrerequisites": {"contract": "postChannel"},
        })

    def test_complete_function_row_restore_includes_definition_and_acl_reset(self):
        signature = "public.lomi_consumer_test(uuid)"
        old = function_row(signature, "CREATE OR REPLACE FUNCTION public.lomi_consumer_test(uuid) RETURNS void LANGUAGE sql AS $$SELECT 1$$;",
                           owner="lomi_old_owner", acl=[
                               {"grantor": "lomi_old_owner", "grantee": "lomi_runtime",
                                "privilege": "EXECUTE", "grantable": True},
                           ])
        new = function_row(signature, "CREATE OR REPLACE FUNCTION public.lomi_consumer_test(uuid) RETURNS void LANGUAGE sql AS $$SELECT 2$$;",
                           owner="lomi_new_owner", acl=[
                               {"grantor": "lomi_new_owner", "grantee": "lomi_remote_api",
                                "privilege": "EXECUTE", "grantable": False},
                           ])
        sql = controller.restore_function_capture_row_sql(signature, old, new)
        self.assertIn(old["definition"].encode(), sql)
        self.assertIn(b"ALTER FUNCTION " + signature.encode() + b" OWNER TO lomi_old_owner;", sql)
        self.assertIn(b"REVOKE ALL ON FUNCTION " + signature.encode()
                      + b" FROM PUBLIC,lomi_old_owner,lomi_remote_api,lomi_runtime;", sql)
        self.assertIn(b"GRANT EXECUTE ON FUNCTION " + signature.encode()
                      + b" TO lomi_runtime WITH GRANT OPTION;", sql)
        self.assertNotIn(b"TO lomi_remote_api", sql)

    def test_function_replay_appends_delimiter_without_changing_capture_bytes(self):
        signature = "public.lomi_consumer_test(uuid)"
        old_definition = (
            "CREATE OR REPLACE FUNCTION public.lomi_consumer_test(uuid) RETURNS void\n"
            " LANGUAGE plpgsql\nAS $function$\nBEGIN\n RETURN;\nEND;\n$function$\n"
        )
        current_definition = (
            "CREATE OR REPLACE FUNCTION public.lomi_consumer_test(uuid) RETURNS void\n"
            " LANGUAGE plpgsql\nAS $function$\nBEGIN\n RAISE NOTICE 'new';\nEND;\n$function$\n"
        )
        old = function_row(signature, old_definition, owner="lomi_owner", acl=[])
        current = function_row(signature, current_definition, owner="lomi_owner", acl=[])
        old_before = dict(old)
        sql = controller.restore_function_capture_row_sql(signature, old, current)
        old_bytes = old_definition.encode("utf-8")
        self.assertIn(old_bytes + b";\n", sql)
        self.assertEqual(old["definition"], old_before["definition"])
        self.assertEqual(old["definitionUtf8Hex"], old_before["definitionUtf8Hex"])
        self.assertEqual(old["catalogSha256"], old_before["catalogSha256"])
        bad = function_row(signature, "CREATE FUNCTION public.lomi_consumer_test(uuid)",
                           owner="lomi_owner", acl=[])
        with self.assertRaisesRegex(controller.Rejected, "safe SQL replay terminator"):
            controller.restore_function_capture_row_sql(signature, bad, current)

    def test_function_owner_acl_restore_recreates_owner_entries_and_absence(self):
        signature = "public.lomi_consumer_test(uuid)"
        owner = "lomi_owner"
        owner_acl_rows = (
            {"grantor": owner, "grantee": owner, "privilege": "EXECUTE", "grantable": True},
            {"grantor": owner, "grantee": "lomi_runtime", "privilege": "EXECUTE", "grantable": False},
        )
        for owner_row, suffix in ((owner_acl_rows[0], b" WITH GRANT OPTION"),
                                  ({**owner_acl_rows[0], "grantable": False}, b"")):
            row = {"owner": owner, "acl": [owner_row]}
            sql = controller.restore_function_owner_acl_sql(signature, row)
            self.assertIn(b"GRANT EXECUTE ON FUNCTION " + signature.encode()
                          + b" TO lomi_owner" + suffix + b";", sql)

        owner_absent = {"owner": owner, "acl": [owner_acl_rows[1]]}
        reset = controller.restore_function_owner_acl_sql(
            signature, owner_absent, extra_grantees=(owner,))
        self.assertIn(b"REVOKE ALL ON FUNCTION " + signature.encode()
                      + b" FROM PUBLIC,lomi_owner,lomi_runtime;", reset)
        self.assertNotIn(b"GRANT EXECUTE ON FUNCTION " + signature.encode()
                         + b" TO lomi_owner", reset)
        changed_owner_absent = controller.restore_function_owner_acl_sql(
            signature, owner_absent, extra_grantees=("lomi_previous_owner",))
        self.assertIn(b" FROM PUBLIC,lomi_owner,lomi_previous_owner,lomi_runtime;",
                      changed_owner_absent)
        self.assertNotIn(b"GRANT EXECUTE ON FUNCTION " + signature.encode()
                         + b" TO lomi_owner", changed_owner_absent)

        same_owner_present = {"owner": owner, "acl": [owner_acl_rows[0]]}
        same_owner_sql = controller.restore_function_owner_acl_sql(signature, same_owner_present)
        self.assertIn(b"ALTER FUNCTION " + signature.encode() + b" OWNER TO lomi_owner;", same_owner_sql)
        self.assertIn(b"GRANT EXECUTE ON FUNCTION " + signature.encode()
                      + b" TO lomi_owner WITH GRANT OPTION;", same_owner_sql)

    def test_helper_reference_creates_body_owner_when_role_is_absent(self):
        package = (BUNDLED_FROZEN.parents[1] if BUNDLED_FROZEN.is_dir() else
                   Path("/Users/woro/Documents/Lomi/lomi-remote/staging/consumer-derivatives-v3-product-successor"))
        frozen = package / "inputs/frozen-v3-successor"
        helper_contract = json.loads((frozen / "helper-seal.pending.json").read_text())
        old_rows = []
        new_rows = []
        for item in helper_contract["helpers"]:
            signature = item["signature"]
            definition = f"CREATE FUNCTION source_{len(old_rows)}() RETURNS void LANGUAGE sql AS $$SELECT$$;\n"
            old_rows.append(function_row(signature, definition, owner=item["old_owner"], acl=[]))
            new_rows.append(function_row(signature, definition, owner=item["new_owner"], acl=[]))
        new_capture = capture(*new_rows)

        class FixtureStub:
            def __init__(self):
                self.query_results = [
                    b"0",
                    (b'{"login":false,"inherit":false,"super":false,"createdb":false,'
                     b'"createrole":false,"replication":false,"bypassRls":false,"config":null}'),
                ]
                self.scripts = []

            def capture_query(self, database, sql, label):
                return self.query_results.pop(0)

            def apply_script(self, database, sql, label):
                self.scripts.append((database, sql, label))
                return {"label": label}

            def capture_catalog(self, database, label):
                return new_capture

        fixture = FixtureStub()
        with patch.object(controller, "PACKAGE", package):
            result, measured = controller.add_body_helper_reference_state(fixture, capture(*old_rows))
        create_role = controller.role_create_sql_from_operator(
            (frozen / "operator-seal-auth-helpers.candidate.sql").read_bytes())
        self.assertEqual(fixture.scripts[0], (
            "postgres", create_role + b"\n", "create-body-owner-once-for-reference-new"))
        self.assertEqual(fixture.scripts[1][0], controller.DATABASES["referenceNew"])
        self.assertEqual(result["independentReference"], controller.DATABASES["referenceNew"])
        self.assertEqual(measured, new_capture)

    def test_operator_catalog_environment_is_scoped_and_does_not_mutate_base(self):
        base = controller.private_environment(Path("/tmp/private-run"))
        original = dict(base)
        operator = controller.catalog_operator_environment(base)
        self.assertEqual(base, original)
        self.assertEqual(operator["PGOPTIONS"],
                         original["PGOPTIONS"] + " -c search_path=pg_catalog")
        self.assertEqual({key: value for key, value in operator.items() if key != "PGOPTIONS"},
                         {key: value for key, value in original.items() if key != "PGOPTIONS"})
        self.assertFalse({"DATABASE_URL", "DIRECT_URL", "AUTH_SECRET"} & set(base))

    def test_old_owner_acl_restore_is_literal_and_rejects_grantor_drift(self):
        signature = "public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)"
        old_row = {
            "owner": "lomi_remote_inventory_owner",
            "acl": [
                {"grantor": "lomi_remote_inventory_owner", "grantee": "PUBLIC",
                 "privilege": "EXECUTE", "grantable": False},
                {"grantor": "lomi_remote_inventory_owner", "grantee": "lomi_runtime",
                 "privilege": "EXECUTE", "grantable": True},
            ],
        }
        sql = controller.restore_function_owner_acl_sql(signature, old_row)
        self.assertIn(b"ALTER FUNCTION " + signature.encode() + b" OWNER TO lomi_remote_inventory_owner;", sql)
        self.assertIn(b"REVOKE ALL ON FUNCTION " + signature.encode()
                      + b" FROM PUBLIC,lomi_remote_inventory_owner,lomi_runtime;", sql)
        self.assertIn(b"GRANT EXECUTE ON FUNCTION " + signature.encode()
                      + b" TO lomi_runtime WITH GRANT OPTION;", sql)
        bad = {**old_row, "acl": [dict(old_row["acl"][0], grantor="other_owner")]}
        with self.assertRaisesRegex(controller.Rejected, "grantor drift"):
            controller.restore_function_owner_acl_sql(signature, bad)

    def test_runtime_dependency_tree_hash_closes_content_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "node_modules"
            (root / ".bin").mkdir(parents=True)
            (root / "pkg").mkdir()
            (root / "pkg/index.js").write_text("export const value = 1;\n")
            (root / ".bin/tool").symlink_to("../pkg/index.js")
            links = {".bin/tool": "../pkg/index.js"}
            before = controller.dependency_tree_digest(root, links)
            (root / "pkg/index.js").write_text("export const value = 2;\n")
            self.assertNotEqual(before, controller.dependency_tree_digest(root, links))
            (root / "pkg/extra.js").write_text("extra\n")
            self.assertNotEqual(before, controller.dependency_tree_digest(root, links))
            (root / "pkg/unapproved").symlink_to("index.js")
            with self.assertRaisesRegex(controller.Rejected, "unapproved runtime dependency symlink"):
                controller.dependency_tree_digest(root, links)

    def test_data_only_bundle_gate_rejects_mutated_local_module_before_loader(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace = root / "workspace"
            project = root / "project"
            bundle_root = project / "artifacts"
            bundle = bundle_root / "consumer-derivatives-v3-product-10000000-0000-4000-8000-000000000001"
            source = workspace / "auth-app/src/source.ts"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"export const source = 1;\n")
            bundle.mkdir(parents=True, mode=0o700)
            (bundle / "inputs/auth-app/src").mkdir(parents=True, mode=0o700)
            (bundle / "inputs/auth-app/src/source.ts").write_bytes(source.read_bytes())
            local = {name: (HERE / name).read_bytes() for name in controller.LOCAL_BUNDLE_FILES}
            for name, raw in local.items():
                (bundle / name).write_bytes(raw)
            lock = {
                "schemaVersion": 1,
                "status": "SOURCE_LOCKED_NOT_ADMITTED",
                "admission": "TWO_DISTINCT_SOURCE_BOUND_INTEGRATOR_AND_REVIEWER_RECEIPTS_REQUIRED",
                "productionQualified": False,
                "postgresVersion": "18.6",
                "bunVersion": "1.4.2",
                "sourceAllowlist": {"auth-app/src/source.ts": digest(source.read_bytes())},
                "closedTrees": {"auth-app/src": ["auth-app/src/source.ts"]},
                "postgresFiles": {"bin/postgres": "a" * 64},
                "bunSha256": "b" * 64,
            }
            lock_raw = (json.dumps(lock, sort_keys=True) + "\n").encode()
            (bundle / "inputs.lock.json").write_bytes(lock_raw)
            plan = valid_plan_fixture()
            plan_raw = (json.dumps(plan, sort_keys=True) + "\n").encode()
            (bundle / "plan.json").write_bytes(plan_raw)
            source_files = {name: digest(raw) for name, raw in local.items()}
            source_files["auth-app/src/source.ts"] = digest(source.read_bytes())
            manifest = {
                "status": "PREPARED_NOT_ADMITTED", "admission": None,
                "productionQualified": False, "qualification": "NOT_RUN",
                "stages": {f"S{i}": "NOT_RUN" for i in range(8)},
                "inputsLockSha256": digest(lock_raw), "planSha256": digest(plan_raw),
                "controllerSha256": digest(local["controller.py"]),
                "sourceFiles": source_files, "postgresFiles": lock["postgresFiles"],
                "bunSha256": lock["bunSha256"],
            }
            (bundle / "bundle-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
            original = (controller.HERE, controller.PROJECT, controller.WORKSPACE,
                        controller.load_local_modules)
            controller.HERE, controller.PROJECT, controller.WORKSPACE = bundle, project, workspace
            controller.load_local_modules = lambda: self.fail("local validators imported before source admission")
            try:
                controller.verify_bundle_data_before_import()
                invalid_plan = dict(plan, schemaVersion=1)
                (bundle / "plan.json").write_text(json.dumps(invalid_plan, sort_keys=True) + "\n")
                with self.assertRaisesRegex(controller.Rejected, "closed v2 unadmitted contract"):
                    controller.verify_bundle_data_before_import()
                (bundle / "plan.json").write_bytes(plan_raw)
                (bundle / "admission.py").write_text("raise RuntimeError('must not execute')\n")
                with self.assertRaisesRegex(controller.Rejected, "manifest local/source hash mismatch"):
                    controller.verify_bundle_data_before_import()
            finally:
                (controller.HERE, controller.PROJECT, controller.WORKSPACE,
                 controller.load_local_modules) = original

    def test_standalone_bundle_validator_loads_and_checks_local_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace = root / "workspace"
            bundle = root / "prepared"
            bundle.mkdir(mode=0o700)
            source_path = workspace / "auth-app/source.txt"
            source_path.parent.mkdir(parents=True)
            source_raw = b"frozen workspace input\n"
            source_path.write_bytes(source_raw)
            (bundle / "inputs/auth-app").mkdir(parents=True)
            (bundle / "inputs/auth-app/source.txt").write_bytes(source_raw)
            contents = {"auth-app/source.txt": source_raw}
            for name in prepare.LOCAL_FILES:
                raw = (HERE / name).read_bytes()
                (bundle / name).write_bytes(raw)
                contents[name] = raw
            empty_loads = {}
            lock = {
                "sourceAllowlist": {"auth-app/source.txt": digest(source_raw)},
                "closedTrees": {},
                "postgresVersion": "18.6", "postgresRoot": "/postgres/18.6",
                "postgresAliasPath": "/opt/postgresql", "postgresAliasTarget": "../cellar/18.6",
                "postgresFiles": {"bin/postgres": "a" * 64}, "postgresSymlinks": {},
                "postgresDependencies": {}, "postgresDependencyAliases": {},
                "postgresDependencyAliasTargets": {}, "postgresFormulaAliases": {},
                "hostPlatform": {}, "systemDependencies": {},
                "postgresLoadCommands": empty_loads,
                "postgresLoadCommandsSha256": digest(b"{}"),
                "bunLoadCommands": empty_loads, "bunLoadCommandsSha256": digest(b"{}"),
                "bunVersion": "1.4.2", "bunPath": "/bun", "bunCanonicalPath": "/bun",
                "bunSha256": "b" * 64, "bunDependencies": {},
                "bunDependencyAliases": {}, "bunDependencyAliasTargets": {},
                "runtimeDependencyPath": "/workspace/auth-app/node_modules",
                "runtimeDependencySymlinks": {}, "dependencyVersions": {},
                "runtimeDependencyTreeSha256": "c" * 64,
                "prismaCliPath": prepare.PRISMA_CLI_PATH,
                "prismaCliSha256": prepare.PRISMA_CLI_SHA256,
                "prismaSchemaEnginePath": prepare.PRISMA_SCHEMA_ENGINE_PATH,
                "prismaSchemaEngineSha256": prepare.PRISMA_SCHEMA_ENGINE_SHA256,
            }
            lock_raw = (json.dumps(lock, sort_keys=True) + "\n").encode()
            (bundle / "inputs.lock.json").write_bytes(lock_raw)
            plan = valid_plan_fixture()
            plan_raw = (json.dumps(plan, sort_keys=True) + "\n").encode()
            (bundle / "plan.json").write_bytes(plan_raw)
            manifest = prepare.make_manifest(lock_raw, contents, plan_raw)
            (bundle / "bundle-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
            previous_workspace = prepare.WORKSPACE
            prepare.WORKSPACE = workspace
            try:
                self.assertEqual(prepare.validate_bundle(bundle, lock_raw, contents=None), manifest)
                (bundle / "controller.py").write_text("raise RuntimeError('tampered')\n")
                with self.assertRaisesRegex(prepare.Rejected, "manifest drift"):
                    prepare.validate_bundle(bundle, lock_raw, contents=None)
            finally:
                prepare.WORKSPACE = previous_workspace


if __name__ == "__main__":
    unittest.main()
