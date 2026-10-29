"""Pure-Python S7 plan/cascade contract tests; never starts external tools."""
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import s7_plans


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class SqlContractTests(unittest.TestCase):
    def test_seven_cascade_paths_three_pending_absences_and_five_rollback_deletes(self):
        self.assertEqual(len(s7_plans.LOOKUP_SQL), 7)
        self.assertEqual(len(s7_plans.PENDING_ABSENCE_SQL), 3)
        self.assertEqual(len(s7_plans.DELETE_SQL), 5)
        self.assertEqual(len(s7_plans.ALL_CAPTURE_SQL), 17)
        self.assertEqual(set(s7_plans.SOURCE_TTL_DELETE_SQL), {"web", "mobile"})
        self.assertEqual(len(s7_plans.NEW_CASCADE_INDEXES), 7)
        self.assertEqual(set(s7_plans.LOOKUP_SQL), {
            "intent_parent", "intent_account", "consent_parent", "consent_account",
            "consent_service", "consent_web", "consent_mobile",
        })
        for sql in s7_plans.ALL_PLAN_SQL.values():
            self.assertTrue(sql.startswith("EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "))
            self.assertNotRegex(sql.lower(), r"\bset\s+enable_(seqscan|indexscan|bitmapscan)")
        for sql in s7_plans.DELETE_SQL.values():
            self.assertTrue(sql.startswith("BEGIN;\nEXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "))
            self.assertTrue(sql.endswith("\nROLLBACK;\n"))
            self.assertIn("RETURNING id", sql)

    def test_pending_lookups_use_each_principal_id_and_approval_binding(self):
        expected = {
            "pending_service_absence": ("remote_service_authorization", "service_authorization_id"),
            "pending_web_absence": ("remote_web_session", "web_session_id"),
            "pending_mobile_absence": ("mobile_session", "mobile_session_id"),
        }
        for name, (table, reserved_column) in expected.items():
            sql = s7_plans.PENDING_ABSENCE_SQL[name]
            self.assertIn("public." + table, sql)
            self.assertIn(":'" + reserved_column + "'::text", sql)
            self.assertIn('"consumerApprovalId"', sql)
            self.assertIn(":'approval_id'", sql)
            self.assertNotIn("FROM public.consumer_approval_intent", sql)
            self.assertNotIn('h.', sql)
            self.assertIn("SELECT NOT EXISTS", sql)

    def test_sql_receipts_are_stable_and_cover_every_capture(self):
        first = s7_plans.sql_digests()
        self.assertEqual(first, s7_plans.sql_digests())
        self.assertEqual(set(first), set(s7_plans.ALL_CAPTURE_SQL))
        self.assertTrue(all(len(value) == 64 for value in first.values()))
        self.assertEqual(set(s7_plans.preparation_sql_digests()), {"analyze", "planner_settings"})
        self.assertEqual(s7_plans.ANALYZE_SQL.count("ANALYZE "), len(s7_plans.ANALYZE_TABLES))
        self.assertIn("current_setting('enable_seqscan')", s7_plans.PLANNER_SETTINGS_SQL)


class SourceLockTests(unittest.TestCase):
    def test_source_receipt_requires_exact_module_and_frozen_sql_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pins = {}
            for relative in s7_plans.SOURCE_FILES.values():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = ("fixture source: " + relative).encode()
                path.write_bytes(raw)
                pins[relative] = digest(raw)
            result = s7_plans.source_lock_receipt(root, pins)
            self.assertEqual(result["status"], "SOURCE_LOCKED")
            self.assertEqual(set(result["sourceFiles"]), set(s7_plans.SOURCE_FILES))
            pins[s7_plans.SOURCE_FILES["consent"]] = "0" * 64
            with self.assertRaisesRegex(s7_plans.Rejected, "hash drift"):
                s7_plans.source_lock_receipt(root, pins)

    def test_source_receipt_rejects_symlinked_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pins = {}
            for relative in s7_plans.SOURCE_FILES.values():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = relative.encode()
                path.write_bytes(raw)
                pins[relative] = digest(raw)
            relative = s7_plans.SOURCE_FILES["intent"]
            path = root / relative
            outside = root / "outside.sql"
            outside.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(outside)
            with self.assertRaisesRegex(s7_plans.Rejected, "symlink"):
                s7_plans.source_lock_receipt(root, pins)


class ExplainReceiptTests(unittest.TestCase):
    def test_lookup_plan_capture_retains_raw_json_and_observations(self):
        name = "intent_parent"
        raw = json.dumps([{
            "Plan": {
                "Node Type": "Index Scan",
                "Schema": "public",
                "Relation Name": "consumer_approval_intent",
                "Index Name": "consumer_approval_intent_parent_idx",
                "Index Cond": '("accountSessionId" = \'parent\'::text)',
                "Plan Rows": 1,
                "Actual Rows": 1,
                "Actual Loops": 1,
                "Shared Hit Blocks": 2,
                "Shared Read Blocks": 0,
            },
            "Planning Time": 0.1,
            "Triggers": [],
            "Execution Time": 0.2,
        }]).encode()
        result = s7_plans.validate_plan_capture(
            name, raw, captured_sql_sha256=s7_plans.sql_digests()[name])
        self.assertEqual(result["captureSha256"], digest(raw))
        self.assertEqual(result["nodes"][0]["index"], "consumer_approval_intent_parent_idx")
        self.assertEqual(result["qualification"], "NOT_EVALUATED")
        with self.assertRaisesRegex(s7_plans.Rejected, "fixed S7 source"):
            s7_plans.validate_plan_capture(name, raw, captured_sql_sha256="0" * 64)

    def test_delete_requires_trigger_timings_rollback_and_restored_controls(self):
        name = "session"
        raw = json.dumps([{
            "Plan": {
                "Node Type": "ModifyTable",
                "Operation": "Delete",
                "Actual Rows": 1,
                "Actual Loops": 1,
                "Plan Rows": 1,
                "Shared Hit Blocks": 4,
                "Shared Read Blocks": 0,
                "Plans": [{
                    "Node Type": "Index Scan",
                    "Schema": "public",
                    "Relation Name": "session",
                    "Index Name": "session_pkey",
                    "Plan Rows": 1,
                    "Actual Rows": 1,
                    "Actual Loops": 1,
                }],
            },
            "Planning Time": 0.2,
            "Triggers": [{"Trigger Name": "RI_ConstraintTrigger_a_1", "Time": 0.4, "Calls": 2}],
            "Execution Time": 1.2,
        }]).encode()
        controls = digest(b"controls")
        unrelated = digest(b"unrelated")
        receipt = {
            "transaction": "ROLLED_BACK",
            "beforeControlSha256": controls,
            "afterControlSha256": controls,
            "unrelatedControlSha256Before": unrelated,
            "unrelatedControlSha256After": unrelated,
        }
        result = s7_plans.validate_delete_capture(
            name, raw, captured_sql_sha256=s7_plans.sql_digests()["delete_session"],
            rollback=receipt)
        self.assertEqual(result["triggerTimings"][0]["Calls"], 2)
        receipt["afterControlSha256"] = "f" * 64
        with self.assertRaisesRegex(s7_plans.Rejected, "restored exactly"):
            s7_plans.validate_delete_capture(
                name, raw, captured_sql_sha256=s7_plans.sql_digests()["delete_session"],
                rollback=receipt)


def seed_receipt(state: str, actual_kind: str) -> dict:
    web = actual_kind == "remote_web"
    approval_id = "approval-" + actual_kind
    actual_id = "actual-" + actual_kind
    service_id = "service-" + actual_kind
    approval_snapshot = {
        "accountId": "account-1",
        "userId": "user-1",
        "accountSessionId": "session-1",
        "actualKind": actual_kind,
        "actualId": actual_id,
        "webActualId": actual_id if web else None,
        "mobileActualId": None if web else actual_id,
        "serviceAuthorizationId": service_id,
        "clientId": "client-1",
        "approvalOrigin": "https://auth.example.test",
        "targetOrigin": "https://app.example.test",
        "redirectUri": "https://app.example.test/auth/callback",
        "state": "state-1",
        "scope": "remote:account:read remote:v3:consumer",
        "serviceVersion": 1,
        "consentVersion": 1,
        "authorizationEpoch": 2,
        "approvedAt": "2026-10-23T12:00:00.000Z",
        "approvalXid": 101,
        "requestExpiresAt": "2026-10-23T12:05:00.000Z",
        "codeExpiresAt": "2026-10-23T12:01:00.000Z",
        "codeHashSha256": "a" * 64,
        "codeChallenge": "challenge-1",
        "parentDeadline": "2026-10-24T12:00:00.000Z",
        "serviceDeadline": "2026-10-23T13:00:00.000Z",
        "actualDeadline": "2026-10-23T13:00:00.000Z",
        "actualIdleDeadline": "2026-10-23T13:00:00.000Z" if not web else "2026-10-23T13:00:00.000Z",
        "expiresAt": "2026-10-23T13:00:00.000Z",
    }
    approval = {
        "id": approval_id,
        "actualId": actual_id,
        "serviceAuthorizationId": service_id,
        "consumedAt": None if state == "live_pending" else "2026-10-23T12:00:01.000Z",
        "consumedXid": None if state == "live_pending" else 202,
        "snapshot": approval_snapshot,
    }
    receipt = {
        "state": state,
        "actualKind": actual_kind,
        "issuer": "actual_runtime_flow_primitives",
        "issuancePath": "direct_production_flow_primitives",
        "flowSourceSha256": "b" * 64,
        "authoritySourceSha256": "d" * 64,
        "flowReceiptSha256": "c" * 64,
        "source": {
            "webAttemptId": "attempt-1" if web else None,
            "webCodeId": "code-1" if web else None,
            "mobileLoginId": None if web else "login-1",
        },
        "approval": approval,
        "proof": None,
        "service": None,
        "actual": None,
        "consent": None,
        "consumer": None,
    }
    if state == "consumed_live":
        xid = approval["consumedXid"]
        consent_snapshot = {
            key: (approval_snapshot["approvedAt"] if key == "consentedAt" else approval_snapshot[key])
            for key in s7_plans.CONSENT_SNAPSHOT_FIELDS
        }
        receipt.update({
            "proof": {
                "approvalIntentId": approval_id,
                "consumedAt": approval["consumedAt"],
                "exchangeXid": xid,
                "proofVersion": 1,
            },
            "service": {
                "id": service_id,
                "consumerApprovalId": approval_id,
                "consumerV3BirthXid": xid,
                "expiresAt": approval_snapshot["serviceDeadline"],
            },
            "actual": {
                "id": actual_id,
                "consumerApprovalId": approval_id,
                "consumerV3BirthXid": xid,
                "expiresAt": approval_snapshot["actualDeadline"],
                "idleExpiresAt": approval_snapshot["actualIdleDeadline"],
            },
            "consent": {
                "id": "consent-" + actual_kind,
                "approvalIntentId": approval_id,
                "birthXid": xid,
                "snapshot": consent_snapshot,
            },
            "consumer": {
                "id": "consumer-" + actual_kind,
                "consentId": "consent-" + actual_kind,
                "serviceAuthorizationId": service_id,
                "originKind": actual_kind,
                "originId": actual_id,
            },
        })
    rehash_seed(receipt)
    return receipt


def rehash_seed(receipt):
    unsigned = {key: value for key, value in receipt.items() if key != "flowReceiptSha256"}
    receipt["flowReceiptSha256"] = digest(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


class RuntimeSeedReceiptTests(unittest.TestCase):
    def test_seed_provenance_cannot_claim_http_handler_execution(self):
        receipt = seed_receipt("live_pending", "remote_web")
        receipt["issuer"] = "actual_runtime_handler"
        with self.assertRaisesRegex(s7_plans.Rejected, "production flow primitives"):
            s7_plans.validate_runtime_seed_receipt(receipt)

    def test_seed_matrix_preserves_pending_and_consumed_birth_xids(self):
        self.assertEqual({
            s7_plans.validate_runtime_seed_receipt(seed_receipt(state, kind))
            for state, kind in s7_plans.SEED_CASES
        }, set(s7_plans.SEED_CASES))

    def test_consumed_seed_rejects_proof_birth_xid_or_snapshot_drift(self):
        receipt = seed_receipt("consumed_live", "remote_web")
        receipt["proof"]["exchangeXid"] += 1
        rehash_seed(receipt)
        with self.assertRaisesRegex(s7_plans.Rejected, "proof does not preserve"):
            s7_plans.validate_runtime_seed_receipt(receipt)
        receipt = seed_receipt("consumed_live", "mobile")
        receipt["consent"]["snapshot"]["parentDeadline"] = "changed"
        rehash_seed(receipt)
        with self.assertRaisesRegex(s7_plans.Rejected, "original approval snapshot"):
            s7_plans.validate_runtime_seed_receipt(receipt)

    def test_pending_seed_rejects_any_issued_authority(self):
        receipt = seed_receipt("live_pending", "remote_web")
        receipt["service"] = {"id": "forged"}
        rehash_seed(receipt)
        with self.assertRaisesRegex(s7_plans.Rejected, "consumed or issued authority"):
            s7_plans.validate_runtime_seed_receipt(receipt)

    def test_seed_digest_rejects_changed_source_identity(self):
        receipt = seed_receipt("consumed_live", "remote_web")
        receipt["source"]["webAttemptId"] = "changed"
        with self.assertRaisesRegex(s7_plans.Rejected, "digest does not match"):
            s7_plans.validate_runtime_seed_receipt(receipt)


class StageReceiptTests(unittest.TestCase):
    def test_source_only_report_cannot_qualify_s7(self):
        result = s7_plans.validate_stage_receipt(None)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["fullS7Qualified"], False)
        self.assertEqual(result["receiptValidation"], "INCOMPLETE")
        self.assertEqual(len(result["requiredButMissing"]), len(s7_plans.RECEIPT_REQUIREMENTS))


if __name__ == "__main__":
    unittest.main()
