"""Pure tests for the S7 SQL-to-query-spec compiler; no external tools."""
from copy import deepcopy
import hashlib
from pathlib import Path
import re
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import s7_plans
import s7_spec


def source_hashes() -> dict[str, str]:
    return {path: "a" * 64 for path in s7_spec.SOURCE_HASH_PATHS}


def queries_with_bindings(value):
    if isinstance(value, dict):
        if "bindings" in value:
            yield value
        for nested in value.values():
            yield from queries_with_bindings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from queries_with_bindings(nested)


class QuerySpecTests(unittest.TestCase):
    def setUp(self):
        self.spec = s7_spec.build_spec(source_hashes())

    def test_builds_all_seventeen_source_locked_plan_probes(self):
        self.assertEqual(len(self.spec["lookups"]), 7)
        self.assertEqual(len(self.spec["pendingAbsence"]), 3)
        self.assertEqual(len(self.spec["deletes"]), 5)
        self.assertEqual(len(self.spec["sourceTtlDeletes"]), 2)
        self.assertEqual(
            set(s7_plans.sql_digests()),
            {
                *self.spec["lookups"],
                *self.spec["pendingAbsence"],
                *("delete_" + name for name in self.spec["deletes"]),
                *("source_ttl_" + name for name in self.spec["sourceTtlDeletes"]),
            },
        )

        plan_groups = (
            self.spec["lookups"],
            self.spec["pendingAbsence"],
            {"delete_" + name: plan["explainDelete"] for name, plan in self.spec["deletes"].items()},
            {"source_ttl_" + name: plan["explainDelete"] for name, plan in self.spec["sourceTtlDeletes"].items()},
        )
        for group in plan_groups:
            for name, query in group.items():
                self.assertRegex(query["sourceSqlSha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(query["sourceSqlSha256"], s7_plans.sql_digests()[name])
                self.assertTrue(query["sql"].startswith(
                    "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "
                ))
                self.assertEqual(query["sql"].count(";"), 1)
                self.assertNotRegex(query["sql"], r":'[a-z][a-z0-9_]*'")
                self.assertNotRegex(query["sql"], r"\bSET\s+(?:LOCAL\s+)?(?:enable_|plan_cache_mode)")
                positions = [int(item) for item in re.findall(r"\$(\d+)", query["sql"])]
                self.assertEqual(max(positions, default=0), len(query["bindings"]))

    def test_plan_bindings_use_the_expected_runtime_fixture_cases(self):
        lookup_fixture = {
            "intent_parent": "seed.consumed_live.remote_web",
            "intent_account": "seed.consumed_live.remote_web",
            "consent_parent": "seed.consumed_live.remote_web",
            "consent_account": "seed.consumed_live.remote_web",
            "consent_service": "seed.consumed_live.remote_web",
            "consent_web": "seed.consumed_live.remote_web",
            "consent_mobile": "seed.consumed_live.mobile",
        }
        for name, fixture in lookup_fixture.items():
            self.assertTrue(all(binding.startswith(fixture + ".")
                                for binding in self.spec["lookups"][name]["bindings"]))

        expected_pending = {
            "pending_service_absence": [
                "seed.live_pending.remote_web.service_authorization_id",
                "seed.live_pending.remote_web.approval_id",
            ],
            "pending_web_absence": [
                "seed.live_pending.remote_web.web_session_id",
                "seed.live_pending.remote_web.approval_id",
            ],
            "pending_mobile_absence": [
                "seed.live_pending.mobile.mobile_session_id",
                "seed.live_pending.mobile.approval_id",
            ],
        }
        for name, bindings in expected_pending.items():
            query = self.spec["pendingAbsence"][name]
            self.assertEqual(query["bindings"], bindings)
            self.assertIn("SELECT NOT EXISTS (SELECT FROM public.", query["sql"])
            self.assertIn("consumerApprovalId\" = $2::uuid", query["sql"])
            self.assertNotIn("consumer_approval_intent", query["sql"])
            self.assertNotIn('h."', query["sql"])

        expected_deletes = {
            "session": ["expired.remote_web.account_session_id", "expired.remote_web.user_id"],
            "account_identity": ["expired.remote_web.account_id", "expired.remote_web.user_id"],
            "service": ["expired.remote_web.service_authorization_id", "expired.remote_web.user_id"],
            "web": ["expired.remote_web.web_session_id", "expired.remote_web.user_id"],
            "mobile": ["expired.mobile.mobile_session_id", "expired.mobile.user_id"],
        }
        for name, bindings in expected_deletes.items():
            query = self.spec["deletes"][name]["explainDelete"]
            self.assertEqual(query["bindings"], bindings)
            self.assertNotIn("BEGIN", query["sql"])
            self.assertNotIn("ROLLBACK", query["sql"])

        self.assertEqual(
            self.spec["sourceTtlDeletes"]["web"]["explainDelete"]["bindings"],
            ["source_ttl.remote_web.web_attempt_id"],
        )
        self.assertEqual(
            self.spec["sourceTtlDeletes"]["mobile"]["explainDelete"]["bindings"],
            ["source_ttl.mobile.mobile_login_id"],
        )

    def test_parameter_adapter_deduplicates_repeated_bindings_in_first_use_order(self):
        sql, bindings = s7_spec._adapt_sql(
            "SELECT :'id'::text, :'account_id'::uuid, :'id'::text;",
            {"id": "fixture.actual_id", "account_id": "fixture.account_id"},
        )
        self.assertEqual(sql, "SELECT $1::text, $2::uuid, $1::text;")
        self.assertEqual(bindings, ["fixture.actual_id", "fixture.account_id"])

    def test_scalar_count_probes_are_parameterized_direct_row_counts(self):
        for name, plan in self.spec["deletes"].items():
            self.assertEqual(len(plan["beforeCounts"]), 15)
            for group in ("beforeCounts", "insideTransactionCounts", "afterRollbackCounts"):
                for query in plan[group]:
                    self.assertEqual(set(query), {"sql", "bindings", "result"})
                    self.assertEqual(query["result"], "count")
                    self.assertRegex(query["sql"], r"^SELECT count\(\*\)::int AS value FROM public\.")
                    self.assertNotRegex(query["sql"], r"\bJOIN\b")
                    self.assertNotRegex(query["sql"], r"SELECT\s+0\b")
            control = plan["unrelatedControlLiveness"]
            self.assertEqual(len(control), 2)
            self.assertEqual({query["result"] for query in control}, {"boolean"})
            self.assertEqual(control[0]["bindings"], ["control.remote_web.actual_id"])
            self.assertEqual(control[1]["bindings"], ["control.mobile.actual_id"])
            self.assertCanonicalGuard(control[0], "control.remote_web", "remote_web")
            self.assertCanonicalGuard(control[1], "control.mobile", "mobile")

        self.assertIn('public."session"', {
            query["sql"].split(" FROM ", 1)[1].split(" WHERE ", 1)[0]
            for query in self.spec["deletes"]["session"]["beforeCounts"]
        })
        relations = " ".join(
            query["sql"] for query in self.spec["deletes"]["session"]["beforeCounts"]
        )
        for relation in (
            "remote_account_identity", "remote_session_binding", "consumer_approval_intent",
            "consumer_approval_consumed_proof", "consumer_derivative_consent",
            "consumer_authorization", "remote_service_authorization",
            "remote_web_session", "mobile_session",
        ):
            self.assertIn("public." + relation, relations)

    def test_ttl_probes_retain_authority_and_materialize_the_canonical_live_guard(self):
        for kind, origin in (("web", "remote_web"), ("mobile", "mobile")):
            plan = self.spec["sourceTtlDeletes"][kind]
            source_field = "web_attempt_id" if kind == "web" else "mobile_login_id"
            prefix = f"source_ttl.{origin}."
            for group in ("beforeCounts", "insideTransactionCounts", "afterRollbackCounts"):
                self.assertTrue(any(
                    query["result"] == "count" and prefix + source_field in query["bindings"]
                    for query in plan[group]
                ))
            authority = plan["retainedAuthority"]
            self.assertEqual(set(authority), {"proof", "consent", "consumerAuthorization"})
            self.assertIn(prefix + "approval_id", authority["proof"]["bindings"])
            self.assertIn(prefix + "approval_id", authority["consent"]["bindings"])
            self.assertIn(prefix + "actual_id", authority["consumerAuthorization"]["bindings"])
            self.assertTrue(all(query["result"] == "count" for query in authority.values()))

            guard = plan["principalLiveGuard"]
            self.assertEqual(guard["result"], "boolean")
            self.assertEqual(guard["bindings"], [prefix + "actual_id"])
            self.assertIn("WITH guarded AS MATERIALIZED", guard["sql"])
            self.assertIn("SELECT public.lomi_consumer_principal_live_v2(c)", guard["sql"])
            self.assertIn(f'c."originKind" = \'{origin}\'', guard["sql"])
            self.assertIn('c."originId" = $1::text', guard["sql"])
            self.assertIn("SELECT count(*) = 1 AS principal_live FROM guarded", guard["sql"])
            self.assertNotRegex(guard["sql"], r"\bEXISTS\b")
            self.assertEqual({query["result"] for query in plan["unrelatedControlLiveness"]}, {"boolean"})
            self.assertCanonicalGuard(
                plan["unrelatedControlLiveness"][0], "control.remote_web", "remote_web"
            )
            self.assertCanonicalGuard(
                plan["unrelatedControlLiveness"][1], "control.mobile", "mobile"
            )

    def assertCanonicalGuard(self, query, fixture_case, origin):
        self.assertEqual(query["result"], "boolean")
        self.assertEqual(query["bindings"], [fixture_case + ".actual_id"])
        self.assertIn("WITH guarded AS MATERIALIZED", query["sql"])
        self.assertIn("SELECT public.lomi_consumer_principal_live_v2(c)", query["sql"])
        self.assertIn(f'c."originKind" = \'{origin}\'', query["sql"])
        self.assertIn('c."originId" = $1::text', query["sql"])
        self.assertIn("SELECT count(*) = 1 AS principal_live FROM guarded", query["sql"])
        self.assertNotRegex(query["sql"], r"\bEXISTS\b")

    def test_analyze_planner_source_hashes_and_canonical_digest_are_exact(self):
        self.assertEqual(self.spec, s7_spec.build_spec(source_hashes()))
        self.assertEqual(self.spec["analyzeSql"], s7_plans.ANALYZE_SQL)
        self.assertEqual(self.spec["analyzeTables"], list(s7_plans.ANALYZE_TABLES))
        self.assertEqual(self.spec["plannerSettingsSql"], s7_plans.PLANNER_SETTINGS_SQL)
        self.assertEqual(set(self.spec["sourceHashes"]), set(s7_spec.SOURCE_HASH_PATHS))
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", digest)
                            for digest in self.spec["sourceHashes"].values()))
        self.assertEqual(
            self.spec["querySpecificationSha256"],
            hashlib.sha256(s7_spec.canonical_bytes({
                key: value for key, value in self.spec.items()
                if key != "querySpecificationSha256"
            })).hexdigest(),
        )
        self.assertEqual(s7_spec.recompute_spec_sha256(self.spec), self.spec["querySpecificationSha256"])
        self.assertTrue(s7_spec.validate_spec(self.spec))
        valid_binding = re.compile(
            r"^(?:seed\.(?:live_pending|consumed_live)\.(?:remote_web|mobile)|"
            r"control\.(?:remote_web|mobile)|expired\.(?:remote_web|mobile)|"
            r"source_ttl\.(?:remote_web|mobile))\."
            r"(?:user_id|account_id|account_session_id|approval_id|actual_id|"
            r"service_authorization_id|web_session_id|mobile_session_id|"
            r"web_attempt_id|web_code_id|mobile_login_id)$"
        )
        for query in queries_with_bindings(self.spec):
            for binding in query["bindings"]:
                self.assertRegex(binding, valid_binding)

    def test_validation_rejects_mutated_sql_bindings_hashes_and_shape(self):
        modified_sql = deepcopy(self.spec)
        modified_sql["lookups"]["intent_parent"]["sql"] += " -- altered"
        modified_sql["querySpecificationSha256"] = s7_spec.recompute_spec_sha256(modified_sql)
        with self.assertRaisesRegex(s7_spec.Rejected, "reviewed S7 SQL and bindings"):
            s7_spec.validate_spec(modified_sql)

        modified_binding = deepcopy(self.spec)
        modified_binding["deletes"]["web"]["explainDelete"]["bindings"][0] = "control.remote_web.web_session_id"
        modified_binding["querySpecificationSha256"] = s7_spec.recompute_spec_sha256(modified_binding)
        with self.assertRaisesRegex(s7_spec.Rejected, "reviewed S7 SQL and bindings"):
            s7_spec.validate_spec(modified_binding)

        non_fixture_binding = deepcopy(self.spec)
        non_fixture_binding["deletes"]["session"]["beforeCounts"][3]["bindings"][0] = "remote_web"
        non_fixture_binding["querySpecificationSha256"] = s7_spec.recompute_spec_sha256(non_fixture_binding)
        with self.assertRaisesRegex(s7_spec.Rejected, "reviewed S7 SQL and bindings"):
            s7_spec.validate_spec(non_fixture_binding)

        forged_hash = deepcopy(self.spec)
        forged_hash["querySpecificationSha256"] = "0" * 64
        with self.assertRaisesRegex(s7_spec.Rejected, "digest does not match"):
            s7_spec.validate_spec(forged_hash)

        unsupported = deepcopy(self.spec)
        unsupported["unexpected"] = True
        with self.assertRaisesRegex(s7_spec.Rejected, "unsupported shape"):
            s7_spec.validate_spec(unsupported)

    def test_build_rejects_malformed_source_hashes_and_wrapper_drift(self):
        bad_hashes = source_hashes()
        bad_hashes[s7_spec.SOURCE_HASH_PATHS[0]] = "A" * 64
        with self.assertRaisesRegex(s7_spec.Rejected, "malformed"):
            s7_spec.build_spec(bad_hashes)

        with self.assertRaisesRegex(s7_spec.Rejected, "exact S7 source closure"):
            s7_spec.build_spec({**source_hashes(), "extra.py": "a" * 64})

        with self.assertRaisesRegex(s7_spec.Rejected, "malformed transaction wrapper"):
            s7_spec._unwrap_delete("BEGIN; EXPLAIN DELETE; ROLLBACK;")

        with self.assertRaisesRegex(s7_spec.Rejected, "unsupported psql variable"):
            s7_spec._adapt_sql("SELECT :'unknown'::text;", {"id": "fixture.actual_id"})

        original = s7_plans.LOOKUP_SQL["intent_parent"]
        try:
            s7_plans.LOOKUP_SQL["intent_parent"] = original + " -- changed source"
            with self.assertRaisesRegex(s7_spec.Rejected, "source SQL templates differ"):
                s7_spec.build_spec(source_hashes())
        finally:
            s7_plans.LOOKUP_SQL["intent_parent"] = original


if __name__ == "__main__":
    unittest.main()

