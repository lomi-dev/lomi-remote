"""Pure mutation tests for the populated S7 evidence postvalidator."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import s7_evidence
import s7_plans
import s7_spec


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_hash(value) -> str:
    return _digest(s7_spec.canonical_bytes(value))


def _counts(values):
    return [{"kind": "count", "value": str(value)} for value in values]


def _controls(values=(True, True)):
    return [{"kind": "boolean", "value": value} for value in values]


def _rollback(before, after, control_before, control_after):
    return {
        "transaction": "ROLLED_BACK",
        "beforeControlSha256": _canonical_hash(before),
        "afterControlSha256": _canonical_hash(after),
        "unrelatedControlSha256Before": _canonical_hash(control_before),
        "unrelatedControlSha256After": _canonical_hash(control_after),
    }


def _fixture_counts(target, historical):
    return {
        key: str(value)
        for key, value in s7_evidence._expected_fixture_counts(target, historical).items()
    }


def _database_counts(target, bump=0):
    return {key: str(20000 + target + bump) for key in s7_evidence._DATABASE_COUNT_KEYS}


def _node(
    node_type,
    *,
    relation=None,
    index=None,
    condition=None,
    children=None,
    rows=1,
    loops=1,
):
    result = {
        "Node Type": node_type,
        "Plan Rows": 1,
        "Actual Rows": rows,
        "Actual Loops": loops,
    }
    if relation is not None:
        result["Schema"] = "public"
        result["Relation Name"] = relation
    if index is not None:
        result["Index Name"] = index
    if condition is not None:
        result["Index Cond"] = condition
    if children is not None:
        result["Plans"] = children
    return result


def _driver_nodes(document):
    result = []

    def visit(node):
        result.append({
            "nodeType": node["Node Type"],
            "relationName": node.get("Relation Name"),
            "actualRows": node["Actual Rows"],
            "actualLoops": node["Actual Loops"],
            "sharedHitBlocks": node.get("Shared Hit Blocks"),
            "sharedReadBlocks": node.get("Shared Read Blocks"),
        })
        for child in node.get("Plans", []):
            visit(child)

    visit(document[0]["Plan"])
    return result


def _plan_observation(name, query, document):
    document[0]["Plan"].setdefault("Shared Hit Blocks", 6)
    document[0]["Plan"].setdefault("Shared Read Blocks", 0)
    raw_json = json.dumps(document, separators=(",", ":"))
    raw = raw_json.encode("utf-8")
    nodes = _driver_nodes(document)
    principal_scan = any(
        row["nodeType"] == "Seq Scan"
        and row["relationName"] in s7_evidence._PRINCIPAL_RELATIONS
        for row in nodes
    )
    return {
        "name": name,
        "sourceSqlSha256": query["sourceSqlSha256"],
        "executedSqlSha256": _digest(query["sql"].encode("utf-8")),
        "captureSha256": _digest(raw),
        "elapsedMilliseconds": 1,
        "plan": document,
        "rawPlanJson": raw_json,
        "nodes": nodes,
        "principalSequentialScanObserved": principal_scan,
    }


def _plan_for(name, query):
    if name in s7_evidence._LOOKUP_INDEXES:
        relation, index = s7_evidence._LOOKUP_INDEXES[name]
        column = s7_evidence._LOOKUP_LEADING_COLUMNS[name]
        root = _node(
            "Index Scan",
            relation=relation,
            index=index,
            condition=f'("{column}" = \'private-probe-id\'::text)',
        )
    elif name in s7_evidence._PENDING_INDEXES:
        child_relation, child_indexes = s7_evidence._PENDING_INDEXES[name]
        # Exercise the reviewed owner-key alternative by default. The direct
        # two-bind absence probe has no outer approval-intent lookup.
        root = _node("Result", children=[
            _node(
                "Index Scan",
                relation=child_relation,
                index=child_indexes[-1],
                condition='("id" = \'private-actual-id\'::text)',
                rows=0,
            ),
        ])
    else:
        if name.startswith("delete_"):
            delete_name = name[len("delete_"):]
            target_relation = {
                "session": "session",
                "account_identity": "remote_account_identity",
                "service": "remote_service_authorization",
                "web": "remote_web_session",
                "mobile": "mobile_session",
            }[delete_name]
            trigger_rows = [{"Trigger Name": "RI_ConstraintTrigger_a_1", "Time": 0.4, "Calls": 1}]
        else:
            delete_name = name.removeprefix("source_ttl_")
            target_relation = "remote_login_attempt" if delete_name == "web" else "mobile_login"
            trigger_rows = []
        root = _node(
            "ModifyTable",
            children=[_node("Index Scan", relation=target_relation, index=target_relation + "_pkey")],
        )
        root["Operation"] = "Delete"
        return _plan_observation(name, query, [{
            "Plan": root,
            "Planning Time": 0.2,
            "Triggers": trigger_rows,
            "Execution Time": 0.8,
        }])
    return _plan_observation(name, query, [{
        "Plan": root,
        "Planning Time": 0.1,
        "Triggers": [],
        "Execution Time": 0.2,
    }])


def _seed_receipt(state, kind, spec):
    web = kind == "remote_web"
    actual_id = "actual-" + kind
    approval_id = "approval-" + kind
    service_id = "service-" + kind
    approved_at = "2026-10-23T12:00:00.000Z"
    deadline = "2026-10-24T12:00:00.000Z"
    consumed_at = None if state == "live_pending" else "2026-10-23T12:00:01.000Z"
    xid = None if consumed_at is None else 202
    snapshot = {
        "accountId": "account-1",
        "userId": "user-1",
        "accountSessionId": "session-1",
        "actualKind": kind,
        "actualId": actual_id,
        "webActualId": actual_id if web else None,
        "mobileActualId": None if web else actual_id,
        "serviceAuthorizationId": service_id,
        "clientId": "client-1",
        "approvalOrigin": "https://auth.example.invalid",
        "targetOrigin": "https://app.example.invalid",
        "redirectUri": "https://app.example.invalid/auth/callback",
        "state": "state-1",
        "scope": "remote:account:read remote:v3:consumer",
        "serviceVersion": 1,
        "consentVersion": 1,
        "authorizationEpoch": 2,
        "approvedAt": approved_at,
        "approvalXid": 101,
        "requestExpiresAt": deadline,
        "codeExpiresAt": "2026-10-23T12:01:00.000Z",
        "codeHashSha256": "a" * 64,
        "codeChallenge": "challenge-1",
        "parentDeadline": deadline,
        "serviceDeadline": deadline,
        "actualDeadline": deadline,
        "actualIdleDeadline": deadline,
        "expiresAt": deadline,
    }
    receipt = {
        "state": state,
        "actualKind": kind,
        "issuer": "actual_runtime_flow_primitives",
        "issuancePath": "direct_production_flow_primitives",
        "flowSourceSha256": spec["sourceHashes"]["auth-app/src/consumer-derivative-flow.ts"],
        "authoritySourceSha256": spec["sourceHashes"]["auth-app/src/consumer-derivative-authority.ts"],
        "source": {
            "webAttemptId": "attempt-1" if web else None,
            "webCodeId": "code-1" if web else None,
            "mobileLoginId": None if web else "login-1",
        },
        "approval": {
            "id": approval_id,
            "actualId": actual_id,
            "serviceAuthorizationId": service_id,
            "consumedAt": consumed_at,
            "consumedXid": xid,
            "snapshot": snapshot,
        },
        "proof": None,
        "service": None,
        "actual": None,
        "consent": None,
        "consumer": None,
    }
    if state == "consumed_live":
        consent_snapshot = {
            field: approved_at if field == "consentedAt" else snapshot[field]
            for field in s7_plans.CONSENT_SNAPSHOT_FIELDS
        }
        consent_id = "consent-" + kind
        receipt.update({
            "proof": {
                "approvalIntentId": approval_id,
                "consumedAt": consumed_at,
                "exchangeXid": xid,
                "proofVersion": 1,
            },
            "service": {
                "id": service_id,
                "consumerApprovalId": approval_id,
                "consumerV3BirthXid": xid,
                "expiresAt": deadline,
            },
            "actual": {
                "id": actual_id,
                "consumerApprovalId": approval_id,
                "consumerV3BirthXid": xid,
                "expiresAt": deadline,
                "idleExpiresAt": deadline,
            },
            "consent": {
                "id": consent_id,
                "approvalIntentId": approval_id,
                "birthXid": xid,
                "snapshot": consent_snapshot,
            },
            "consumer": {
                "consentId": consent_id,
                "serviceAuthorizationId": service_id,
                "originKind": kind,
                "originId": actual_id,
            },
        })
    receipt["flowReceiptSha256"] = _canonical_hash(receipt)
    return receipt


def _deleted(name, relation, branch):
    all_authority = {
        "consumer_approval_intent", "consumer_approval_consumed_proof",
        "consumer_derivative_consent", "consumer_authorization",
        "remote_service_authorization", "remote_web_session", "mobile_session",
    }
    if name == "session":
        return relation in all_authority | {"session", "remote_session_binding"}
    if name == "account_identity":
        return relation in all_authority | {"remote_account_identity", "remote_session_binding"}
    if name == "service":
        return branch == "remote_web" and relation in {
            "remote_service_authorization", "remote_web_session",
            "consumer_derivative_consent", "consumer_authorization",
        }
    if name == "web":
        return branch == "remote_web" and relation in {
            "remote_web_session", "consumer_derivative_consent", "consumer_authorization",
        }
    return branch == "mobile" and relation in {
        "mobile_session", "consumer_derivative_consent", "consumer_authorization",
    }


def _cascade_observation(name, target, spec, fixture_counts, database_counts):
    delete_spec = spec["deletes"][name]
    identities = [s7_evidence._query_identity(query) for query in delete_spec["beforeCounts"]]
    before = _counts([1] * len(identities))
    inside = _counts([0 if _deleted(name, *identity) else 1 for identity in identities])
    after = _counts([1] * len(identities))
    control_before = _controls()
    control_inside = _controls()
    control_after = _controls()
    return {
        "name": name,
        "targetUnrelatedPrincipalsPerKind": target,
        "observedPopulationCounts": dict(fixture_counts),
        "observedDatabaseTableCounts": dict(database_counts),
        "explainDelete": _plan_for("delete_" + name, delete_spec["explainDelete"]),
        "beforeCounts": before,
        "insideTransactionCounts": inside,
        "unrelatedControlLiveness": {
            "before": control_before,
            "insideTransaction": control_inside,
            "afterRollback": control_after,
        },
        "afterRollbackCounts": after,
        "rollbackCompleted": True,
        "rollbackReceipt": _rollback(before, after, control_before, control_after),
    }


def _ttl_observation(name, spec, fixture_counts, database_counts):
    ttl_spec = spec["sourceTtlDeletes"][name]
    before, inside, after = _counts([1]), _counts([0]), _counts([1])
    control_before = _controls()
    control_inside = _controls()
    control_after = _controls()
    return {
        "name": name,
        "targetUnrelatedPrincipalsPerKind": 10000,
        "observedPopulationCounts": dict(fixture_counts),
        "observedDatabaseTableCounts": dict(database_counts),
        "explainDelete": _plan_for("source_ttl_delete_" + name, ttl_spec["explainDelete"]),
        "beforeCounts": before,
        "insideTransactionCounts": inside,
        "retainedAuthority": {
            key: {"kind": "count", "value": "1"}
            for key in ("proof", "consent", "consumerAuthorization")
        },
        "principalLiveGuard": {"kind": "boolean", "value": True},
        "unrelatedControlLiveness": {
            "before": control_before,
            "insideTransaction": control_inside,
            "afterRollback": control_after,
        },
        "afterRollbackCounts": after,
        "rollbackCompleted": True,
        "rollbackReceipt": _rollback(before, after, control_before, control_after),
    }


def _valid_evidence():
    source_hashes = {path: "a" * 64 for path in s7_spec.SOURCE_HASH_PATHS}
    spec = s7_spec.build_spec(source_hashes)
    private = [
        _seed_receipt("live_pending", "remote_web", spec),
        _seed_receipt("live_pending", "mobile", spec),
        _seed_receipt("consumed_live", "remote_web", spec),
        _seed_receipt("consumed_live", "mobile", spec),
    ]
    public_seeds = []
    for state, kind in (
        ("live_pending", "remote_web"), ("live_pending", "mobile"),
        ("consumed_live", "remote_web"), ("consumed_live", "mobile"),
    ):
        live = state == "live_pending"
        receipt = next(
            row for row in private
            if row["state"] == state and row["actualKind"] == kind
        )
        snapshot = receipt["approval"]["snapshot"]
        identity_parts = (
            snapshot["userId"],
            snapshot["accountSessionId"],
            snapshot["accountId"],
            receipt["approval"]["id"],
            receipt["approval"]["serviceAuthorizationId"],
            receipt["approval"]["actualId"],
        )
        public_seeds.append({
            "seed": "seed." + state + "." + kind,
            "kind": kind,
            "state": state,
            "identitySha256": _digest("\n".join(identity_parts).encode("utf-8")),
            "observed": {
                "intentRows": 1,
                "consumed": not live,
                "proofRows": 0 if live else 1,
                "consentRows": 0 if live else 1,
                "serviceRows": 0 if live else 1,
                "webSessionRows": 0 if live else int(kind == "remote_web"),
                "mobileSessionRows": 0 if live else int(kind == "mobile"),
                "consumerAuthorizationRows": 0 if live else 1,
                "pendingSourceLive": True if live else None,
            },
        })

    growth = []
    delete_plans = []
    for index, target in enumerate((1000, 10000)):
        stage_fixture_counts = _fixture_counts(target, 2 * (index + 1))
        stage_database_counts = _database_counts(target)
        lookup_plans = [
            _plan_for(name, spec["lookups"][name]) for name in s7_evidence._LOOKUP_NAMES
        ]
        pending_plans = [
            _plan_for(name, spec["pendingAbsence"][name]) for name in s7_evidence._PENDING_NAMES
        ]
        growth.append({
            "targetUnrelatedPrincipalsPerKind": target,
            "actualFixtureCounts": stage_fixture_counts,
            "privateDatabaseTableCounts": stage_database_counts,
            "analyzeCompleted": True,
            "analyzeSqlSha256": s7_plans.preparation_sql_digests()["analyze"],
            "analyze": {
                "statement": "ANALYZE",
                "sqlSha256": s7_plans.preparation_sql_digests()["analyze"],
                "completed": True,
                "tables": list(s7_plans.ANALYZE_TABLES),
            },
            "plannerSettings": '{"enable_seqscan":"on","enable_indexscan":"on","enable_bitmapscan":"on"}',
            "plannerSettingsSqlSha256": s7_plans.preparation_sql_digests()["planner_settings"],
            "planner": {
                "defaultSettingsVerified": True,
                "controlOverrides": [],
                "sqlSha256": s7_plans.preparation_sql_digests()["planner_settings"],
                "settings": {
                    "enable_seqscan": "on",
                    "enable_indexscan": "on",
                    "enable_bitmapscan": "on",
                },
            },
            "lookupPlans": lookup_plans,
            "pendingAbsencePlans": pending_plans,
            "canonicalPendingLiveIntentRowsAtStart": 2,
            "canonicalPendingLiveIntentRowsAfterLookupPlans": 2,
            "canonicalPendingLiveIntentRowsAtEnd": 2,
            "principalSequentialScanNames": [],
        })
        delete_plans.extend(
            _cascade_observation(name, target, spec, stage_fixture_counts, stage_database_counts)
            for name in s7_evidence._DELETE_NAMES
        )
    final_fixture_counts = _fixture_counts(10000, 4)
    final_database_counts = _database_counts(10000)
    source_ttl = [
        _ttl_observation(name, spec, final_fixture_counts, final_database_counts)
        for name in s7_evidence._SOURCE_TTL_NAMES
    ]
    lifecycle = {
        key: 1 for key in (
            "naturallyExpiredSourceRows", "naturallyExpiredParentRows",
            "naturallyExpiredWebPrincipalRows", "naturallyIdleExpiredWebPrincipalRows",
            "naturallyExpiredMobilePrincipalRows", "naturallyIdleExpiredMobilePrincipalRows",
            "retainedConsumedProofRows", "retainedExpiredWebSourceRows",
            "retainedExpiredMobileSourceRows", "tombstonedConsumerAuthorizationRows",
            "tombstonedConsentRows", "tombstonedWebConsumerAuthorizationRows",
            "tombstonedMobileConsumerAuthorizationRows", "tombstonedWebConsentRows",
            "tombstonedMobileConsentRows", "actualRevokedWebPrincipalRows",
            "actualRevokedMobilePrincipalRows",
        )
    }
    lifecycle.update({"actualRevokedPrincipalRows": 2, "livePendingSeedSourceRows": 2})
    evidence = {
        "driverExecutionCompleted": True,
        "failurePhase": None,
        "failureKind": None,
        "cleanupComplete": True,
        "cleanupObservationCounts": {key: "0" for key in s7_evidence._CLEANUP_COUNT_KEYS},
        "sourceHashes": dict(spec["sourceHashes"]),
        "querySpecificationSha256": spec["querySpecificationSha256"],
        "requestedPrincipalGrowthSizesPerKind": [1000, 10000],
        "actualPrincipalGrowthSizesPerKind": [1000, 10000],
        "seedReceipts": public_seeds,
        "privateSeedReceiptsCaptured": True,
        "growthObservations": growth,
        "deletePlanObservations": delete_plans,
        "sourceTtlDeletePlanObservations": source_ttl,
        "lifecycleObservations": lifecycle,
        "missingCases": [],
        "qualificationClaims": [],
    }
    return evidence, private, spec


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.evidence, self.private, self.spec = _valid_evidence()

    def test_complete_observed_runtime_evidence_passes_only_scoped_s7(self):
        result = s7_evidence.validate_runtime_evidence(self.evidence, self.private, self.spec)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["fullS7Qualified"])
        self.assertFalse(result["productionQualified"])
        self.assertFalse(result["deploymentQualified"])
        self.assertEqual(result["cascadeDeleteCount"], 10)
        self.assertEqual(result["sourceTtlDeleteCount"], 2)
        self.assertNotIn("actual-remote_web", json.dumps(result))
        self.assertNotIn("private-probe-id", json.dumps(result))
        self.assertEqual(len(result["probeWorkComparison"]), 10)
        self.assertTrue(all(row["noUnrelatedWorkGrowth"] for row in result["probeWorkComparison"]))
        final = result["growthStages"][1]
        self.assertEqual(final["targetUnrelatedPrincipalsPerKind"], 10000)
        self.assertEqual(final["fixtureCounts"]["fixtureObjects"], 20008)
        self.assertEqual(final["fixtureCounts"]["unrelatedFixtureObjects"], 20000)
        self.assertEqual(final["fixtureCounts"]["dedicatedFixtureObjects"], 8)
        for key in (
            "distinctUnrelatedWebApprovals",
            "distinctUnrelatedMobileApprovals",
            "distinctUnrelatedWebSessions",
            "distinctUnrelatedMobileSessions",
            "distinctUnrelatedWebServiceAuthorizations",
            "distinctUnrelatedMobileServiceAuthorizations",
            "distinctUnrelatedWebConsents",
            "distinctUnrelatedMobileConsents",
            "distinctUnrelatedWebConsumerAuthorizations",
            "distinctUnrelatedMobileConsumerAuthorizations",
        ):
            self.assertEqual(final["fixtureCounts"][key], 10000)

    def test_rejects_legacy_growth_sizes_and_wrong_final_ttl_target(self):
        evidence = deepcopy(self.evidence)
        evidence["requestedPrincipalGrowthSizesPerKind"] = [2048, 4096]
        evidence["actualPrincipalGrowthSizesPerKind"] = [2048, 4096]
        with self.assertRaisesRegex(s7_evidence.Rejected, "exactly 1000 then 10000"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

        evidence = deepcopy(self.evidence)
        evidence["sourceTtlDeletePlanObservations"][0][
            "targetUnrelatedPrincipalsPerKind"
        ] = 4096
        with self.assertRaisesRegex(s7_evidence.Rejected, "not measured at the final population"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_rejects_v1_half_population_even_when_input_claims_full_s7(self):
        evidence = deepcopy(self.evidence)
        evidence["fullS7Qualified"] = True
        counts = evidence["growthObservations"][1]["actualFixtureCounts"]
        # V1's T=10000 stage had only 2500 live principals of each kind.
        counts["distinctUnrelatedWebSessions"] = "2500"
        counts["distinctUnrelatedMobileSessions"] = "2500"
        with self.assertRaisesRegex(s7_evidence.Rejected, "fixture counts do not match"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_rejects_one_undersized_per_kind_relation_with_full_aggregate_counts(self):
        evidence = deepcopy(self.evidence)
        counts = evidence["growthObservations"][1]["actualFixtureCounts"]
        self.assertEqual(counts["distinctUnrelatedFixtureAccounts"], "20000")
        self.assertEqual(counts["distinctUnrelatedFixtureApprovals"], "20000")
        self.assertEqual(counts["distinctUnrelatedServiceAuthorizations"], "20000")
        counts["distinctUnrelatedMobileSessions"] = "9999"
        with self.assertRaisesRegex(s7_evidence.Rejected, "fixture counts do not match"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_rejects_including_the_eight_dedicated_fixtures_in_unrelated_counts(self):
        evidence = deepcopy(self.evidence)
        counts = evidence["growthObservations"][1]["actualFixtureCounts"]
        counts["unrelatedFixtureObjects"] = "20008"
        for key in (
            "distinctUnrelatedFixtureUsers",
            "distinctUnrelatedFixtureParents",
            "distinctUnrelatedFixtureAccounts",
            "distinctUnrelatedFixtureApprovals",
        ):
            counts[key] = "20008"
        with self.assertRaisesRegex(s7_evidence.Rejected, "fixture counts do not match"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_rejects_source_hash_and_spec_digest_mutations(self):
        evidence = deepcopy(self.evidence)
        evidence["sourceHashes"]["auth-app/src/consumer-derivative-flow.ts"] = "f" * 64
        with self.assertRaises(s7_evidence.Rejected):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)
        spec = deepcopy(self.spec)
        spec["querySpecificationSha256"] = "f" * 64
        with self.assertRaises(s7_evidence.Rejected):
            s7_evidence.validate_runtime_evidence(self.evidence, self.private, spec)

    def test_failure_diagnostic_cannot_coexist_with_success_claim(self):
        self.evidence["failureDiagnostic"] = {
            "operation": "short-web-exchange", "errorClass": "Error", "sqlState": None,
        }
        with self.assertRaisesRegex(s7_evidence.Rejected, "did not complete"):
            s7_evidence.validate_runtime_evidence(self.evidence, self.private, self.spec)

    def test_rejects_resealed_plan_without_intended_cascade_index(self):
        evidence = deepcopy(self.evidence)
        observation = evidence["growthObservations"][0]["lookupPlans"][0]
        document = deepcopy(observation["plan"])
        document[0]["Plan"]["Index Name"] = "consumer_approval_intent_unrelated_idx"
        replacement = _plan_observation(
            "intent_parent", self.spec["lookups"]["intent_parent"], document
        )
        evidence["growthObservations"][0]["lookupPlans"][0] = replacement
        with self.assertRaisesRegex(s7_evidence.Rejected, "unreviewed principal index"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_rejects_resealed_full_index_scan_with_filter_work(self):
        evidence = deepcopy(self.evidence)
        name = "intent_parent"
        observation = evidence["growthObservations"][0]["lookupPlans"][0]
        document = deepcopy(observation["plan"])
        document[0]["Plan"]["Index Cond"] = '("accountSessionId" = \'private-probe-id\'::text)'
        document[0]["Plan"]["Filter"] = '"userId" = \'other-private-user\'::text'
        document[0]["Plan"]["Rows Removed by Filter"] = 4095
        evidence["growthObservations"][0]["lookupPlans"][0] = _plan_observation(
            name, self.spec["lookups"][name], document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "more than one entry"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_rejects_resealed_index_without_leading_key_condition(self):
        evidence = deepcopy(self.evidence)
        name = "intent_parent"
        observation = evidence["growthObservations"][0]["lookupPlans"][0]
        document = deepcopy(observation["plan"])
        del document[0]["Plan"]["Index Cond"]
        evidence["growthObservations"][0]["lookupPlans"][0] = _plan_observation(
            name, self.spec["lookups"][name], document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "does not constrain accountSessionId"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_rejects_second_stage_growth_in_reserved_id_probe_work(self):
        evidence = deepcopy(self.evidence)
        name = "pending_service_absence"
        observation = evidence["growthObservations"][1]["pendingAbsencePlans"][0]
        document = deepcopy(observation["plan"])
        child_index = document[0]["Plan"]["Plans"][0]
        child_index["Rows Removed by Filter"] = 1
        child_index["Filter"] = '"consumerApprovalId" = \'unrelated-private-approval\'::uuid'
        evidence["growthObservations"][1]["pendingAbsencePlans"][0] = _plan_observation(
            name, self.spec["pendingAbsence"][name], document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "work grew at the larger population"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_accepts_reviewed_owner_key_and_compares_work_by_relation_and_key(self):
        evidence = deepcopy(self.evidence)
        name = "pending_service_absence"
        query = self.spec["pendingAbsence"][name]
        relation, indexes = s7_evidence._PENDING_INDEXES[name]

        # Use the primary key at 1000 and the reviewed unique owner key at
        # 10000. They both lead with globally unique id, so physical index-name
        # variation must not look like work growth.
        first = evidence["growthObservations"][0]["pendingAbsencePlans"][0]
        first_plan = deepcopy(first["plan"])
        first_plan[0]["Plan"]["Plans"][0]["Index Name"] = indexes[0]
        evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
            name, query, first_plan
        )

        result = s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)
        comparison = next(row for row in result["probeWorkComparison"] if row["probe"] == name)
        self.assertTrue(comparison["noUnrelatedWorkGrowth"])
        self.assertEqual(comparison["at1000"]["indexes"][0]["keyColumn"], "id")
        self.assertEqual(comparison["at1000"]["indexes"][0]["indexNames"], [indexes[0]])
        self.assertEqual(comparison["at10000"]["indexes"][0]["indexNames"], [indexes[1]])

    def test_rejects_unreviewed_or_nonselective_pending_index_access(self):
        name = "pending_service_absence"
        query = self.spec["pendingAbsence"][name]

        evidence = deepcopy(self.evidence)
        observation = evidence["growthObservations"][0]["pendingAbsencePlans"][0]
        document = deepcopy(observation["plan"])
        target = document[0]["Plan"]["Plans"][0]
        target["Index Name"] = "unreviewed_service_owner_idx"
        evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
            name, query, document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "unreviewed principal index"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

        evidence = deepcopy(self.evidence)
        observation = evidence["growthObservations"][0]["pendingAbsencePlans"][0]
        relation, _ = s7_evidence._PENDING_INDEXES[name]
        bitmap_index = _node(
            "Bitmap Index Scan",
            index="unreviewed_service_bitmap_idx",
            condition='("id" = \'private-actual-id\'::text)',
            rows=0,
        )
        bitmap_heap = _node(
            "Bitmap Heap Scan",
            relation=relation,
            children=[bitmap_index],
            rows=0,
        )
        document = [{
            "Plan": _node("Result", children=[bitmap_heap]),
            "Planning Time": 0.1,
            "Triggers": [],
            "Execution Time": 0.2,
        }]
        evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
            name, query, document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "unreviewed principal index"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

        for field in ("Rows Removed by Filter", "Rows Removed by Index Recheck"):
            evidence = deepcopy(self.evidence)
            observation = evidence["growthObservations"][0]["pendingAbsencePlans"][0]
            document = deepcopy(observation["plan"])
            document[0]["Plan"]["Plans"][0][field] = 2
            evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
                name, query, document
            )
            with self.subTest(field=field):
                with self.assertRaisesRegex(s7_evidence.Rejected, "more than one entry"):
                    s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

        evidence = deepcopy(self.evidence)
        observation = evidence["growthObservations"][0]["pendingAbsencePlans"][0]
        document = deepcopy(observation["plan"])
        target = document[0]["Plan"]["Plans"][0]
        del target["Index Cond"]
        evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
            name, query, document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "does not constrain id"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

        evidence = deepcopy(self.evidence)
        observation = evidence["growthObservations"][0]["pendingAbsencePlans"][0]
        document = deepcopy(observation["plan"])
        document[0]["Plan"]["Plans"][0]["Actual Rows"] = 1
        evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
            name, query, document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "unexpected target row count"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

        evidence = deepcopy(self.evidence)
        observation = evidence["growthObservations"][0]["pendingAbsencePlans"][0]
        document = deepcopy(observation["plan"])
        document[0]["Plan"]["Plans"][0]["Actual Loops"] = 2
        evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
            name, query, document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "exactly once"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_normalizes_bitmap_index_relation_from_reviewed_index(self):
        evidence = deepcopy(self.evidence)
        name = "pending_service_absence"
        query = self.spec["pendingAbsence"][name]
        relation, indexes = s7_evidence._PENDING_INDEXES[name]
        target = _node(
            "Bitmap Index Scan",
            index=indexes[1],
            condition='("id" = \'private-actual-id\'::text)',
            rows=0,
        )
        heap = _node(
            "Bitmap Heap Scan",
            relation=relation,
            children=[target],
            rows=0,
        )
        document = [{
            "Plan": _node("Result", children=[heap]),
            "Planning Time": 0.1,
            "Triggers": [],
            "Execution Time": 0.2,
        }]
        evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
            name, query, document
        )

        result = s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)
        pending = result["growthStages"][0]["pendingAbsencePlans"][0]
        bitmap_index = next(row for row in pending["indexWork"] if row["nodeType"] == "Bitmap Index Scan")
        self.assertEqual(bitmap_index["relation"], relation)
        safe_bitmap = next(row for row in pending["nodes"] if row["nodeType"] == "Bitmap Index Scan")
        self.assertEqual(safe_bitmap["relation"], relation)

    def test_rejects_executed_principal_scan_for_reserved_id_probe(self):
        evidence = deepcopy(self.evidence)
        name = "pending_service_absence"
        query = self.spec["pendingAbsence"][name]
        observation = evidence["growthObservations"][0]["pendingAbsencePlans"][0]
        document = deepcopy(observation["plan"])
        document[0]["Plan"]["Plans"] = [
            _node(
                "Seq Scan",
                relation="remote_service_authorization",
                rows=0,
                loops=1,
            )
        ]
        evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
            name, query, document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "reserved-ID probe executed"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_pending_probe_does_not_require_or_accept_outer_intent_access(self):
        evidence = deepcopy(self.evidence)
        name = "pending_service_absence"
        observation = evidence["growthObservations"][0]["pendingAbsencePlans"][0]
        document = deepcopy(observation["plan"])
        document[0]["Plan"]["Plans"].append(_node(
            "Index Scan",
            relation="consumer_approval_intent",
            index="consumer_approval_intent_pkey",
            condition='("id" = \'private-approval-id\'::uuid)',
        ))
        evidence["growthObservations"][0]["pendingAbsencePlans"][0] = _plan_observation(
            name, self.spec["pendingAbsence"][name], document
        )
        with self.assertRaisesRegex(s7_evidence.Rejected, "unexpected principal relation"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_compiler_rejects_old_correlated_pending_query_shape(self):
        old_sql = s7_plans._explain(
            'SELECT NOT EXISTS (SELECT FROM public.consumer_approval_intent AS h '
            'JOIN public.remote_service_authorization AS s '
            'ON s."consumerApprovalId" = h.id '
            'WHERE s.id = :\'service_authorization_id\'::text '
            'AND h.id = :\'approval_id\'::uuid) AS reserved_id_absent;'
        )
        pending_sql = dict(s7_plans.PENDING_ABSENCE_SQL)
        pending_sql["pending_service_absence"] = old_sql
        with patch.object(s7_plans, "PENDING_ABSENCE_SQL", pending_sql):
            with self.assertRaisesRegex(s7_evidence.Rejected, "source SQL templates differ"):
                s7_spec.build_spec(self.spec["sourceHashes"])

    def test_retain_executed_principal_scan_and_work_on_delete_plan(self):
        evidence = deepcopy(self.evidence)
        observation = evidence["deletePlanObservations"][3]
        query = self.spec["deletes"]["web"]["explainDelete"]
        document = deepcopy(observation["explainDelete"]["plan"])
        delete_root = document[0]["Plan"]
        delete_root["Plans"] = [
            _node(
                "Seq Scan",
                relation="remote_web_session",
                rows=1,
                loops=1,
            )
        ]
        delete_root["Plans"][0]["Filter"] = '"id" = \'private-web-id\'::text'
        filtered_rows = int(evidence["growthObservations"][0]["actualFixtureCounts"]["webSessions"]) - 1
        delete_root["Plans"][0]["Rows Removed by Filter"] = filtered_rows
        observation["explainDelete"] = _plan_observation("delete_web", query, document)

        result = s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)
        scanned_delete = next(
            row for row in result["cascadeDeletes"]
            if row["name"] == "web" and row["targetUnrelatedPrincipalsPerKind"] == 1000
        )["explainDelete"]
        self.assertTrue(scanned_delete["principalSequentialScanObserved"])
        self.assertEqual(scanned_delete["principalSequentialScanNodes"], [
            {"relation": "remote_web_session", "actualRows": 1, "actualLoops": 1}
        ])
        self.assertIn("rowsRemovedByFilter", scanned_delete["nodes"][-1])
        self.assertEqual(scanned_delete["nodes"][-1]["rowsRemovedByFilter"], filtered_rows)
        self.assertGreater(scanned_delete["planningTimeMs"], 0)
        self.assertGreater(scanned_delete["executionTimeMs"], 0)
        self.assertGreater(scanned_delete["elapsedMilliseconds"], 0)

    def test_rejects_wrong_inside_cascade_counts_and_rollback_digest(self):
        evidence = deepcopy(self.evidence)
        # Session deletion must leave the account identity row intact.
        evidence["deletePlanObservations"][0]["insideTransactionCounts"][1]["value"] = "0"
        with self.assertRaisesRegex(s7_evidence.Rejected, "FK effects"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)
        evidence = deepcopy(self.evidence)
        evidence["deletePlanObservations"][0]["rollbackReceipt"]["afterControlSha256"] = "f" * 64
        with self.assertRaisesRegex(s7_evidence.Rejected, "rollback digest"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_rejects_false_canonical_guard_and_nonincreasing_population(self):
        evidence = deepcopy(self.evidence)
        evidence["sourceTtlDeletePlanObservations"][0]["principalLiveGuard"]["value"] = False
        with self.assertRaisesRegex(s7_evidence.Rejected, "canonical live principal"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)
        evidence = deepcopy(self.evidence)
        evidence["growthObservations"][1]["actualFixtureCounts"]["proofs"] = "257"
        with self.assertRaisesRegex(s7_evidence.Rejected, "fixture matrix"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)

    def test_rejects_missing_seed_and_tampered_flow_receipt(self):
        with self.assertRaisesRegex(s7_evidence.Rejected, "exactly four private"):
            s7_evidence.validate_runtime_evidence(self.evidence, self.private[:-1], self.spec)
        private = deepcopy(self.private)
        private[0]["flowReceiptSha256"] = "f" * 64
        with self.assertRaisesRegex(s7_evidence.Rejected, "canonical contents"):
            s7_evidence.validate_runtime_evidence(self.evidence, private, self.spec)

    def test_rejects_old_unprefixed_seed_summary_name(self):
        evidence = deepcopy(self.evidence)
        evidence["seedReceipts"][0]["seed"] = "live_pending.remote_web"
        with self.assertRaisesRegex(s7_evidence.Rejected, "mismatched case name"):
            s7_evidence.validate_runtime_evidence(evidence, self.private, self.spec)


if __name__ == "__main__":
    unittest.main()
