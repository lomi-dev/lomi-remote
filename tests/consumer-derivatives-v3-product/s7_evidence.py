"""Fail-closed postvalidator for actual populated Consumer v3 S7 evidence.

This module is deliberately pure Python.  It validates a driver's retained
observations against the source-locked query specification and never connects
to PostgreSQL, starts a process, or changes qualification state elsewhere.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

import s7_plans
import s7_spec


Rejected = s7_plans.Rejected

_HEX_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)", re.ASCII)
_EXPECTED_GROWTH = [1000, 10000]
_LOOKUP_NAMES = (
    "intent_parent",
    "intent_account",
    "consent_parent",
    "consent_account",
    "consent_service",
    "consent_web",
    "consent_mobile",
)
_PENDING_NAMES = (
    "pending_service_absence",
    "pending_web_absence",
    "pending_mobile_absence",
)
_DELETE_NAMES = ("session", "account_identity", "service", "web", "mobile")
_SOURCE_TTL_NAMES = ("web", "mobile")
_PRINCIPAL_RELATIONS = {
    "consumer_approval_intent",
    "consumer_approval_consumed_proof",
    "consumer_derivative_consent",
    "remote_service_authorization",
    "remote_web_session",
    "mobile_session",
}
_INDEX_NODE_TYPES = {"Index Scan", "Index Only Scan", "Bitmap Index Scan"}
_HEAP_NODE_TYPES = {"Index Scan", "Index Only Scan", "Bitmap Heap Scan", "Seq Scan"}
_LOOKUP_INDEXES = {
    "intent_parent": ("consumer_approval_intent", "consumer_approval_intent_parent_idx"),
    "intent_account": ("consumer_approval_intent", "consumer_approval_intent_account_idx"),
    "consent_parent": ("consumer_derivative_consent", "consumer_derivative_consent_parent_idx"),
    "consent_account": ("consumer_derivative_consent", "consumer_derivative_consent_account_idx"),
    "consent_service": ("consumer_derivative_consent", "consumer_derivative_consent_service_idx"),
    "consent_web": ("consumer_derivative_consent", "consumer_derivative_consent_web_idx"),
    "consent_mobile": ("consumer_derivative_consent", "consumer_derivative_consent_mobile_idx"),
}
_LOOKUP_LEADING_COLUMNS = {
    "intent_parent": "accountSessionId",
    "intent_account": "accountId",
    "consent_parent": "accountSessionId",
    "consent_account": "accountId",
    "consent_service": "serviceAuthorizationId",
    "consent_web": "webSessionId",
    "consent_mobile": "mobileSessionId",
}
_PENDING_INDEXES = {
    "pending_service_absence": (
        "remote_service_authorization",
        ("remote_service_authorization_pkey", "derivative_service_owner_key"),
    ),
    "pending_web_absence": (
        "remote_web_session",
        ("remote_web_session_pkey", "derivative_web_owner_key"),
    ),
    "pending_mobile_absence": (
        "mobile_session",
        ("mobile_session_pkey", "derivative_mobile_owner_key"),
    ),
}
_INDEX_LOGICAL_KEYS = {
    index: (relation, _LOOKUP_LEADING_COLUMNS[name])
    for name, (relation, index) in _LOOKUP_INDEXES.items()
}
for _pending_name, (_pending_relation, _pending_indexes) in _PENDING_INDEXES.items():
    for _pending_index in _pending_indexes:
        # The source-locked migration declares these as B-tree unique indexes
        # whose leading key is id. The global primary key makes the id probe
        # selective for both the primary and owner-key alternatives.
        _INDEX_LOGICAL_KEYS[_pending_index] = (_pending_relation, "id")
_INDEX_LOGICAL_KEYS["consumer_approval_intent_pkey"] = (
    "consumer_approval_intent", "id"
)
_FIXTURE_COUNT_KEYS = (
    "users",
    "distinctFixtureUsers",
    "parents",
    "distinctFixtureParents",
    "accounts",
    "bindings",
    "intents",
    "distinctFixtureAccounts",
    "distinctFixtureApprovals",
    "proofs",
    "consents",
    "consumerAuthorizations",
    "services",
    "webSessions",
    "mobileSessions",
    "distinctConsumedPrincipals",
    "distinctConsumedPrincipalAccounts",
    "distinctDedicatedFixtureUsers",
    "distinctDedicatedFixtureParents",
    "distinctDedicatedFixtureApprovals",
    "distinctDedicatedFixtureAccounts",
    "distinctDedicatedWebApprovals",
    "distinctDedicatedMobileApprovals",
    "distinctDedicatedPendingApprovals",
    "distinctDedicatedWebPendingApprovals",
    "distinctDedicatedMobilePendingApprovals",
    "distinctDedicatedConsumedPrincipals",
    "distinctDedicatedWebPrincipals",
    "distinctDedicatedMobilePrincipals",
    "distinctDedicatedWebSessions",
    "distinctDedicatedMobileSessions",
    "distinctDedicatedWebAccounts",
    "distinctDedicatedMobileAccounts",
    "distinctDedicatedWebBindings",
    "distinctDedicatedMobileBindings",
    "distinctDedicatedServiceAuthorizations",
    "distinctDedicatedConsents",
    "distinctDedicatedConsumerAuthorizations",
    "distinctUnrelatedFixtureUsers",
    "distinctUnrelatedFixtureParents",
    "distinctUnrelatedFixtureAccounts",
    "distinctUnrelatedFixtureApprovals",
    "distinctUnrelatedWebUsers",
    "distinctUnrelatedMobileUsers",
    "distinctUnrelatedWebParents",
    "distinctUnrelatedMobileParents",
    "distinctUnrelatedWebAccounts",
    "distinctUnrelatedMobileAccounts",
    "distinctUnrelatedWebBindings",
    "distinctUnrelatedMobileBindings",
    "distinctUnrelatedWebApprovals",
    "distinctUnrelatedMobileApprovals",
    "distinctUnrelatedWebProofs",
    "distinctUnrelatedMobileProofs",
    "distinctUnrelatedWebPrincipals",
    "distinctUnrelatedMobilePrincipals",
    "distinctUnrelatedLiveWebPrincipals",
    "distinctUnrelatedLiveMobilePrincipals",
    "unrelatedCanonicalLivePrincipalRows",
    "distinctUnrelatedWebSessions",
    "distinctUnrelatedMobileSessions",
    "distinctUnrelatedWebServiceAuthorizations",
    "distinctUnrelatedMobileServiceAuthorizations",
    "distinctUnrelatedWebConsents",
    "distinctUnrelatedMobileConsents",
    "distinctUnrelatedWebConsumerAuthorizations",
    "distinctUnrelatedMobileConsumerAuthorizations",
    "distinctUnrelatedServiceAuthorizations",
    "distinctUnrelatedConsents",
    "distinctUnrelatedConsumerAuthorizations",
    "fixtureObjects",
    "dedicatedFixtureObjects",
    "unrelatedFixtureObjects",
    "historicalSeedFlowObjects",
    "canonicalSeedAndControlFactsObserved",
)
_DATABASE_COUNT_KEYS = (
    "users",
    "sessions",
    "sessionMetadata",
    "accounts",
    "bindings",
    "attempts",
    "identityCodes",
    "mobileLogins",
    "intents",
    "proofs",
    "consents",
    "consumerAuthorizations",
    "services",
    "webSessions",
    "mobileSessions",
)
_CLEANUP_COUNT_KEYS = (
    "users",
    "parents",
    "sessionMetadata",
    "accounts",
    "bindings",
    "webAttempts",
    "identityCodes",
    "mobileLogins",
    "intents",
    "proofs",
    "consents",
    "consumerAuthorizations",
    "services",
    "webSessions",
    "mobileSessions",
)
_PRIVATE_SEED_KEYS = {
    "state",
    "actualKind",
    "issuer",
    "issuancePath",
    "flowSourceSha256",
    "authoritySourceSha256",
    "flowReceiptSha256",
    "source",
    "approval",
    "proof",
    "service",
    "actual",
    "consent",
    "consumer",
}


def _fail(message: str) -> None:
    raise Rejected(message)


def _object(value: object, label: str) -> dict:
    if type(value) is not dict:
        _fail(label + " must be an object")
    return value


def _array(value: object, label: str) -> list:
    if type(value) is not list:
        _fail(label + " must be an array")
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_digest(value: object) -> bool:
    return type(value) is str and _HEX_SHA256.fullmatch(value) is not None


def _count(value: object, label: str) -> int:
    if type(value) is not str or _DECIMAL.fullmatch(value) is None:
        _fail(label + " is not a canonical observed count")
    return int(value)


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(label + " is not a valid observed integer")
    return value


def _finite_number(value: object, label: str, *, minimum: float = 0.0) -> float:
    if (type(value) not in (int, float) or not math.isfinite(value)
            or value < minimum):
        _fail(label + " is not a valid observed number")
    return float(value)


def _canonical_hash(value: object) -> str:
    return _sha256(s7_spec.canonical_bytes(value))


def _flow_receipt_hash(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError) as error:
        raise Rejected("private seed receipt is not canonical JSON") from error
    return _sha256(encoded)


def _source_closure(payload: dict, spec: dict) -> None:
    if payload.get("sourceHashes") != spec["sourceHashes"]:
        _fail("runtime source hashes differ from the validated query specification")
    if payload.get("querySpecificationSha256") != spec["querySpecificationSha256"]:
        _fail("runtime query specification digest differs from the validated specification")


def _validate_private_seeds(
    receipts: object,
    spec: dict,
) -> dict[tuple[str, str], dict]:
    rows = _array(receipts, "private seed receipts")
    if len(rows) != 4:
        _fail("exactly four private production-flow seed receipts are required")
    expected = {
        ("live_pending", "remote_web"),
        ("live_pending", "mobile"),
        ("consumed_live", "remote_web"),
        ("consumed_live", "mobile"),
    }
    cases: dict[tuple[str, str], dict] = {}
    flow_pin = spec["sourceHashes"]["auth-app/src/consumer-derivative-flow.ts"]
    authority_pin = spec["sourceHashes"]["auth-app/src/consumer-derivative-authority.ts"]
    for receipt_value in rows:
        receipt = _object(receipt_value, "private seed receipt")
        if set(receipt) != _PRIVATE_SEED_KEYS:
            _fail("private seed receipt has an unsupported shape")
        case = (receipt.get("state"), receipt.get("actualKind"))
        if case not in expected or case in cases:
            _fail("private seed receipts do not cover four unique required cases")
        if (receipt.get("issuer") != "actual_runtime_flow_primitives"
                or receipt.get("issuancePath") != "direct_production_flow_primitives"):
            _fail("private seed receipt does not identify the production flow primitives")
        if (receipt.get("flowSourceSha256") != flow_pin
                or receipt.get("authoritySourceSha256") != authority_pin):
            _fail("private seed receipt source pins differ from the validated source closure")
        digest = receipt.get("flowReceiptSha256")
        if not _is_digest(digest):
            _fail("private seed receipt digest is missing or malformed")
        unsigned = {key: value for key, value in receipt.items() if key != "flowReceiptSha256"}
        if _flow_receipt_hash(unsigned) != digest:
            _fail("private seed receipt digest does not match its canonical contents")
        try:
            validated_case = s7_plans.validate_runtime_seed_receipt(receipt)
        except Rejected:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise Rejected("private seed receipt is malformed") from error
        if validated_case != case:
            _fail("private seed receipt identity changed during validation")
        cases[case] = receipt
    if set(cases) != expected:
        _fail("private seed receipts omit a required production-flow case")
    return cases


def _validate_public_seed_summaries(payload: dict, private_receipts: dict[tuple[str, str], dict]) -> None:
    rows = _array(payload.get("seedReceipts"), "driver seed receipts")
    if len(rows) != 4:
        _fail("driver seed observations do not contain exactly four cases")
    cases = set()
    for row_value in rows:
        row = _object(row_value, "driver seed observation")
        state = row.get("state")
        kind = row.get("kind")
        name = row.get("seed")
        if (state, kind) not in private_receipts or (state, kind) in cases:
            _fail("driver seed observations do not match private seed cases")
        expected_name = "seed." + state + "." + kind
        if name != expected_name:
            _fail("driver seed observation has a mismatched case name")
        identity_digest = row.get("identitySha256")
        if not _is_digest(identity_digest):
            _fail("driver seed observation has no identity digest")
        receipt = private_receipts[(state, kind)]
        snapshot = receipt["approval"]["snapshot"]
        identity_parts = (
            snapshot["userId"],
            snapshot["accountSessionId"],
            snapshot["accountId"],
            receipt["approval"]["id"],
            receipt["approval"]["serviceAuthorizationId"],
            receipt["approval"]["actualId"],
        )
        expected_identity_digest = _sha256("\n".join(identity_parts).encode("utf-8"))
        if identity_digest != expected_identity_digest:
            _fail("driver seed identity digest does not match its private receipt")
        observed = _object(row.get("observed"), "driver seed observed row counts")
        expected_keys = {
            "intentRows", "consumed", "proofRows", "consentRows", "serviceRows",
            "webSessionRows", "mobileSessionRows", "consumerAuthorizationRows",
            "pendingSourceLive",
        }
        if set(observed) != expected_keys:
            _fail("driver seed observation has an unsupported row-count shape")
        if _integer(observed["intentRows"], "seed intent rows") != 1:
            _fail("driver seed observation did not retain exactly one approval")
        for key in (
            "proofRows", "consentRows", "serviceRows", "webSessionRows",
            "mobileSessionRows", "consumerAuthorizationRows",
        ):
            _integer(observed[key], "seed " + key)
        if state == "live_pending":
            if observed["consumed"] is not False or observed["pendingSourceLive"] is not True:
                _fail("live-pending seed is not observed live and unconsumed")
            if any(observed[key] != 0 for key in expected_keys if key.endswith("Rows") and key != "intentRows"):
                _fail("live-pending seed contains proof or issued authority rows")
        else:
            if observed["consumed"] is not True or observed["pendingSourceLive"] is not None:
                _fail("consumed-live seed is not observed terminally consumed")
            if any(observed[key] != 1 for key in ("proofRows", "consentRows", "serviceRows", "consumerAuthorizationRows")):
                _fail("consumed-live seed is missing proof, consent, service, or C")
            actual_key = "webSessionRows" if kind == "remote_web" else "mobileSessionRows"
            opposite_key = "mobileSessionRows" if kind == "remote_web" else "webSessionRows"
            if observed[actual_key] != 1 or observed[opposite_key] != 0:
                _fail("consumed-live seed does not preserve its actual-kind branch")
        cases.add((state, kind))
    if cases != set(private_receipts):
        _fail("driver seed summaries and private production-flow receipts disagree")


def _validate_counts_map(value: object, keys: tuple[str, ...], label: str) -> dict[str, int]:
    record = _object(value, label)
    if set(record) != set(keys):
        _fail(label + " does not contain the complete observed count set")
    return {key: _count(record[key], label + "." + key) for key in keys}


def _expected_fixture_counts(target: int, historical: int) -> dict[str, int]:
    if target not in _EXPECTED_GROWTH:
        _fail("growth target is not a pinned per-kind S7 principal population")
    unrelated_total = 2 * target
    fixture_total = unrelated_total + 8
    consumed_total = unrelated_total + 6
    consumed_each_kind = target + 3
    return {
        "users": fixture_total,
        "distinctFixtureUsers": fixture_total,
        "parents": fixture_total,
        "distinctFixtureParents": fixture_total,
        "accounts": fixture_total,
        "bindings": fixture_total,
        "intents": fixture_total + historical,
        "distinctFixtureAccounts": fixture_total,
        "distinctFixtureApprovals": fixture_total,
        "distinctConsumedPrincipals": consumed_total,
        "distinctConsumedPrincipalAccounts": consumed_total,
        "distinctDedicatedFixtureUsers": 8,
        "distinctDedicatedFixtureParents": 8,
        "distinctDedicatedFixtureApprovals": 8,
        "distinctDedicatedFixtureAccounts": 8,
        "distinctDedicatedWebApprovals": 4,
        "distinctDedicatedMobileApprovals": 4,
        "distinctDedicatedPendingApprovals": 2,
        "distinctDedicatedWebPendingApprovals": 1,
        "distinctDedicatedMobilePendingApprovals": 1,
        "distinctDedicatedConsumedPrincipals": 6,
        "distinctDedicatedWebPrincipals": 3,
        "distinctDedicatedMobilePrincipals": 3,
        "distinctDedicatedWebSessions": 3,
        "distinctDedicatedMobileSessions": 3,
        "distinctDedicatedWebAccounts": 4,
        "distinctDedicatedMobileAccounts": 4,
        "distinctDedicatedWebBindings": 4,
        "distinctDedicatedMobileBindings": 4,
        "distinctDedicatedServiceAuthorizations": 6,
        "distinctDedicatedConsents": 6,
        "distinctDedicatedConsumerAuthorizations": 6,
        "distinctUnrelatedFixtureUsers": unrelated_total,
        "distinctUnrelatedFixtureParents": unrelated_total,
        "distinctUnrelatedFixtureAccounts": unrelated_total,
        "distinctUnrelatedFixtureApprovals": unrelated_total,
        "distinctUnrelatedWebUsers": target,
        "distinctUnrelatedMobileUsers": target,
        "distinctUnrelatedWebParents": target,
        "distinctUnrelatedMobileParents": target,
        "distinctUnrelatedWebAccounts": target,
        "distinctUnrelatedMobileAccounts": target,
        "distinctUnrelatedWebBindings": target,
        "distinctUnrelatedMobileBindings": target,
        "distinctUnrelatedWebApprovals": target,
        "distinctUnrelatedMobileApprovals": target,
        "distinctUnrelatedWebProofs": target,
        "distinctUnrelatedMobileProofs": target,
        "distinctUnrelatedWebPrincipals": target,
        "distinctUnrelatedMobilePrincipals": target,
        "distinctUnrelatedLiveWebPrincipals": target,
        "distinctUnrelatedLiveMobilePrincipals": target,
        "unrelatedCanonicalLivePrincipalRows": unrelated_total,
        "distinctUnrelatedWebSessions": target,
        "distinctUnrelatedMobileSessions": target,
        "distinctUnrelatedWebServiceAuthorizations": target,
        "distinctUnrelatedMobileServiceAuthorizations": target,
        "distinctUnrelatedWebConsents": target,
        "distinctUnrelatedMobileConsents": target,
        "distinctUnrelatedWebConsumerAuthorizations": target,
        "distinctUnrelatedMobileConsumerAuthorizations": target,
        "distinctUnrelatedServiceAuthorizations": unrelated_total,
        "distinctUnrelatedConsents": unrelated_total,
        "distinctUnrelatedConsumerAuthorizations": unrelated_total,
        "proofs": consumed_total,
        "consents": consumed_total,
        "consumerAuthorizations": consumed_total,
        "services": consumed_total,
        "webSessions": consumed_each_kind,
        "mobileSessions": consumed_each_kind,
        "fixtureObjects": fixture_total,
        "dedicatedFixtureObjects": 8,
        "unrelatedFixtureObjects": unrelated_total,
        "historicalSeedFlowObjects": historical,
        "canonicalSeedAndControlFactsObserved": 6,
    }


def _validate_growth(payload: dict, spec: dict) -> tuple[list[dict], list[dict[str, int]]]:
    if payload.get("requestedPrincipalGrowthSizesPerKind") != _EXPECTED_GROWTH:
        _fail("runtime principal growth request is not exactly 1000 then 10000 per kind")
    if payload.get("actualPrincipalGrowthSizesPerKind") != _EXPECTED_GROWTH:
        _fail("observed principal growth sizes are not exactly 1000 then 10000 per kind")
    growth = _array(payload.get("growthObservations"), "growth observations")
    if len(growth) != 2:
        _fail("exactly two populated growth observations are required")
    validated = []
    fixture_counts: list[dict[str, int]] = []
    global_counts: list[dict[str, int]] = []
    work_by_stage: list[dict[str, dict]] = []
    analyze_hash = s7_plans.preparation_sql_digests()["analyze"]
    planner_hash = s7_plans.preparation_sql_digests()["planner_settings"]
    for index, (observation_value, target) in enumerate(zip(growth, _EXPECTED_GROWTH)):
        observation = _object(observation_value, "growth observation")
        if _integer(observation.get("targetUnrelatedPrincipalsPerKind"), "growth target") != target:
            _fail("growth observation per-kind principal target differs from its request")
        counts = _validate_counts_map(
            observation.get("actualFixtureCounts"), _FIXTURE_COUNT_KEYS,
            "growth actual fixture counts",
        )
        if counts != _expected_fixture_counts(target, 2 * (index + 1)):
            _fail("growth observation fixture counts do not match the actual fixture matrix")
        database_counts = _validate_counts_map(
            observation.get("privateDatabaseTableCounts"), _DATABASE_COUNT_KEYS,
            "growth private database table counts",
        )
        if observation.get("analyzeCompleted") is not True:
            _fail("populated relation ANALYZE did not complete")
        analyze = _object(observation.get("analyze"), "ANALYZE observation")
        if (analyze.get("statement") != "ANALYZE"
                or analyze.get("completed") is not True
                or analyze.get("sqlSha256") != analyze_hash
                or observation.get("analyzeSqlSha256") != analyze_hash
                or analyze.get("tables") != list(s7_plans.ANALYZE_TABLES)):
            _fail("ANALYZE observation differs from the source-locked population contract")
        if (observation.get("plannerSettingsSqlSha256") != planner_hash):
            _fail("planner settings query digest differs from the source-locked contract")
        planner = _object(observation.get("planner"), "planner observation")
        if (planner.get("defaultSettingsVerified") is not True
                or planner.get("controlOverrides") != []
                or planner.get("sqlSha256") != planner_hash):
            _fail("planner settings were not observed with default controls")
        expected_settings = {
            "enable_seqscan": "on",
            "enable_indexscan": "on",
            "enable_bitmapscan": "on",
        }
        if planner.get("settings") != expected_settings:
            _fail("planner settings do not report PostgreSQL defaults")
        raw_settings = observation.get("plannerSettings")
        if type(raw_settings) is str:
            try:
                raw_settings = json.loads(raw_settings)
            except (ValueError, TypeError) as error:
                raise Rejected("raw planner settings receipt is invalid JSON") from error
        if raw_settings != expected_settings:
            _fail("raw planner settings receipt differs from the planner observation")
        pending_at_start = observation.get("canonicalPendingLiveIntentRowsAtStart")
        pending_after = observation.get("canonicalPendingLiveIntentRowsAfterLookupPlans")
        pending_at_end = observation.get("canonicalPendingLiveIntentRowsAtEnd")
        if any(type(value) is not int or value != 2 for value in (pending_at_start, pending_after, pending_at_end)):
            _fail("canonical live-pending source rows did not remain present during measurement")
        lookup_rows = _array(observation.get("lookupPlans"), "growth lookup plans")
        pending_rows = _array(observation.get("pendingAbsencePlans"), "growth pending absence plans")
        if len(lookup_rows) != len(_LOOKUP_NAMES) or len(pending_rows) != len(_PENDING_NAMES):
            _fail("growth stage does not have exactly seven cascade and three pending plans")
        lookups = []
        stage_work = {}
        for name, plan_observation in zip(_LOOKUP_NAMES, lookup_rows):
            query = spec["lookups"][name]
            plan = _validate_plan_observation(
                name, plan_observation, query, reject_principal_sequential_scan=True
            )
            _require_probe_returned_one(plan, name)
            relation, index_name = _LOOKUP_INDEXES[name]
            work = _measure_probe_work(
                plan,
                [(relation, (index_name,), _LOOKUP_LEADING_COLUMNS[name], 1)],
                name,
            )
            plan["indexWork"] = work["indexes"]
            plan["heapWork"] = work["heaps"]
            plan["totalIndexEntriesVisited"] = work["totalIndexEntriesVisited"]
            plan["totalHeapRowsVisited"] = work["totalHeapRowsVisited"]
            plan["_work"] = work
            stage_work[name] = work
            lookups.append(plan)
        pending_plans = []
        for name, plan_observation in zip(_PENDING_NAMES, pending_rows):
            query = spec["pendingAbsence"][name]
            plan = _validate_plan_observation(
                name, plan_observation, query, reject_principal_sequential_scan=True
            )
            _require_probe_returned_one(plan, name)
            relation, index_names = _PENDING_INDEXES[name]
            work = _measure_probe_work(
                plan,
                [(relation, index_names, "id", 0)],
                name,
            )
            plan["indexWork"] = work["indexes"]
            plan["heapWork"] = work["heaps"]
            plan["totalIndexEntriesVisited"] = work["totalIndexEntriesVisited"]
            plan["totalHeapRowsVisited"] = work["totalHeapRowsVisited"]
            plan["_work"] = work
            stage_work[name] = work
            pending_plans.append(plan)
        validated.append({
            "targetUnrelatedPrincipalsPerKind": target,
            "fixtureCounts": counts,
            "privateDatabaseTableCounts": database_counts,
            "lookupPlans": lookups,
            "pendingAbsencePlans": pending_plans,
        })
        fixture_counts.append(counts)
        global_counts.append(database_counts)
        work_by_stage.append(stage_work)
    if any(second[key] <= first[key] for key in _FIXTURE_COUNT_KEYS
           if not key.startswith("distinctDedicated")
           and key not in {
               "dedicatedFixtureObjects",
               "historicalSeedFlowObjects",
               "canonicalSeedAndControlFactsObserved",
           }
           for first, second in [(fixture_counts[0], fixture_counts[1])]):
        _fail("related fixture table populations did not increase with growth")
    population_tables = (
        "users", "sessions", "sessionMetadata", "accounts", "bindings", "attempts",
        "identityCodes", "mobileLogins", "intents", "proofs", "consents",
        "consumerAuthorizations", "services", "webSessions", "mobileSessions",
    )
    if any(global_counts[1][key] <= global_counts[0][key] for key in population_tables):
        _fail("private database relation populations did not increase with growth")
    comparisons = [
        _work_comparison(name, work_by_stage[0][name], work_by_stage[1][name])
        for name in (*_LOOKUP_NAMES, *_PENDING_NAMES)
    ]
    return validated, fixture_counts, comparisons


def _parse_raw_plan(observation: dict) -> tuple[bytes, object]:
    raw_plan_json = observation.get("rawPlanJson")
    if type(raw_plan_json) is not str:
        _fail("plan observation is missing retained raw EXPLAIN JSON")
    try:
        raw = raw_plan_json.encode("utf-8", "strict")
        parsed = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, ValueError, TypeError) as error:
        raise Rejected("retained raw EXPLAIN JSON is invalid") from error
    if observation.get("plan") != parsed:
        _fail("plan observation does not match its retained raw EXPLAIN JSON")
    return raw, parsed


def _raw_node_summaries(document: dict) -> list[dict]:
    root = document.get("Plan")
    nodes = []

    def visit(node: dict) -> None:
        nodes.append({
            "nodeType": node.get("Node Type"),
            "relationName": node.get("Relation Name") if type(node.get("Relation Name")) is str else None,
            "actualRows": node.get("Actual Rows") if type(node.get("Actual Rows")) in (int, float) else None,
            "actualLoops": node.get("Actual Loops") if type(node.get("Actual Loops")) in (int, float) else None,
            "sharedHitBlocks": node.get("Shared Hit Blocks") if type(node.get("Shared Hit Blocks")) in (int, float) else None,
            "sharedReadBlocks": node.get("Shared Read Blocks") if type(node.get("Shared Read Blocks")) in (int, float) else None,
        })
        children = node.get("Plans", [])
        for child in children:
            visit(child)

    if type(root) is not dict:
        _fail("validated EXPLAIN document has no root plan")
    visit(root)
    return nodes


def _safe_nodes(nodes: list[dict], raw_relations: list[str | None] | None = None) -> list[dict]:
    if raw_relations is not None and len(raw_relations) != len(nodes):
        _fail("raw and validated plan nodes disagree during safe summarization")
    return [
        {
            "nodeType": node.get("nodeType"),
            "relation": _normalized_index_relation(
                node,
                raw_relations[index] if raw_relations is not None else None,
            ),
            "schema": node.get("schema"),
            "index": node.get("index"),
            "actualRows": node.get("actualRows"),
            "actualLoops": node.get("actualLoops"),
            "sharedHitBlocks": node.get("sharedHitBlocks"),
            "sharedReadBlocks": node.get("sharedReadBlocks"),
            "rowsRemovedByFilter": node.get("rowsRemovedByFilter", 0),
            "rowsRemovedByIndexRecheck": node.get("rowsRemovedByIndexRecheck", 0),
            "indexConditionPresent": type(node.get("indexCondition")) is str,
            "indexConditionColumns": sorted(_condition_columns(node.get("indexCondition"))),
        }
        for index, node in enumerate(nodes)
    ]


_CONDITION_IDENTIFIER = re.compile(
    r'(?:(?:[A-Za-z_][A-Za-z0-9_]*|"[A-Za-z_][A-Za-z0-9_]*")\s*\.\s*)?'
    r'(?:"(?P<quoted>[A-Za-z_][A-Za-z0-9_]*)"|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))\s*=',
    re.ASCII,
)


def _condition_columns(condition: object) -> set[str]:
    if type(condition) is not str:
        return set()
    columns = set()
    for match in _CONDITION_IDENTIFIER.finditer(condition):
        column = match.group("quoted") or match.group("plain")
        if column in {
            "id", "accountSessionId", "accountId", "serviceAuthorizationId",
            "webSessionId", "mobileSessionId", "userId",
        }:
            columns.add(column)
    return columns


def _normalized_index_relation(
    node: dict,
    raw_relation: str | None = None,
) -> str | None:
    relation = node.get("relation") or raw_relation
    index_name = node.get("index")
    known = _INDEX_LOGICAL_KEYS.get(index_name)
    if relation is None and known is not None:
        return known[0]
    return relation


def _number_field(node: dict, key: str, label: str, *, default: float | None = None) -> float:
    value = node.get(key, default)
    if value is None:
        _fail(label + " is missing")
    return _finite_number(value, label)


def _walk_raw_nodes(document: dict) -> list[dict]:
    result = []

    def visit(node: dict) -> None:
        result.append(node)
        for child in node.get("Plans", []):
            visit(child)

    root = document.get("Plan")
    if type(root) is not dict:
        _fail("validated EXPLAIN document has no root plan")
    visit(root)
    return result


def _walk_raw_relations(document: dict) -> list[str | None]:
    """Retain Bitmap Index Scan's owning relation for safe work accounting."""
    relations: list[str | None] = []

    def visit(node: dict, bitmap_relation: str | None = None) -> None:
        node_type = node.get("Node Type")
        relation = node.get("Relation Name")
        if type(relation) is not str:
            relation = None
        if node_type == "Bitmap Index Scan" and relation is None:
            relation = bitmap_relation
        relations.append(relation)
        if node_type == "Bitmap Heap Scan":
            child_bitmap_relation = relation
        elif node_type in {"BitmapAnd", "BitmapOr"}:
            child_bitmap_relation = bitmap_relation
        else:
            child_bitmap_relation = None
        for child in node.get("Plans", []):
            visit(child, child_bitmap_relation)

    root = document.get("Plan")
    if type(root) is not dict:
        _fail("validated EXPLAIN document has no root plan")
    visit(root)
    return relations


def _node_work(node: dict, label: str) -> tuple[float, float, float]:
    rows = _number_field(node, "actualRows", label + " actual rows")
    loops = _number_field(node, "actualLoops", label + " actual loops")
    filtered = _number_field(
        node, "rowsRemovedByFilter", label + " rows removed by filter", default=0
    )
    rechecked = _number_field(
        node,
        "rowsRemovedByIndexRecheck",
        label + " rows removed by index recheck",
        default=0,
    )
    return rows, loops, (rows + filtered + rechecked) * loops


def _measure_probe_work(
    plan: dict,
    expected_accesses: list[tuple[str, tuple[str, ...], str, int]],
    label: str,
) -> dict:
    """Validate exact key conditions and bound observed index/heap visits."""
    nodes = plan["_validatedNodes"]
    raw_nodes = _walk_raw_nodes(plan["_document"])
    raw_relations = _walk_raw_relations(plan["_document"])
    if len(nodes) != len(raw_nodes) or len(nodes) != len(raw_relations):
        _fail(label + " raw and validated plan trees disagree")

    expected_indexes_by_relation: dict[str, set[str]] = {}
    for relation, indexes, _, _ in expected_accesses:
        expected_indexes_by_relation.setdefault(relation, set()).update(indexes)
    expected_relations = set(expected_indexes_by_relation)
    normalized_indexes = []
    for node, raw_relation in zip(nodes, raw_relations):
        if node.get("nodeType") not in _INDEX_NODE_TYPES:
            continue
        index_name = node.get("index")
        if type(index_name) is not str:
            _fail(label + " has an executed index node without an index name")
        known = _INDEX_LOGICAL_KEYS.get(index_name)
        relation = node.get("relation") or raw_relation
        if relation is None and known is not None:
            relation = known[0]
        if known is not None and relation is not None and relation != known[0]:
            _fail(label + " index name is bound to the wrong relation")
        if relation in _PRINCIPAL_RELATIONS:
            if known is None:
                _fail(label + " uses an unreviewed principal index")
            if relation not in expected_relations:
                _fail(label + " accesses an unexpected principal relation")
            if index_name not in expected_indexes_by_relation[relation]:
                _fail(label + " uses an unreviewed principal index")
            normalized_indexes.append((node, relation, known[1], index_name))

    for relation, accepted_indexes, leading_column, expected_rows in expected_accesses:
        matching = [
            item for item in normalized_indexes
            if item[1] == relation and item[3] in accepted_indexes
        ]
        executed = [
            item for item in matching
            if _number_field(item[0], "actualLoops", label + " intended index loops") > 0
        ]
        if len(executed) != 1:
            _fail(label + " is missing its single reviewed index access")
        if not any(
            raw.get("Relation Name") == relation
            and raw.get("Node Type") in _INDEX_NODE_TYPES | {"Bitmap Heap Scan"}
            for raw in raw_nodes
        ):
            _fail(label + " is missing heap access to its intended relation")
        actual_rows_total = 0.0
        for node, _, logical_key, _ in executed:
            if logical_key != leading_column:
                _fail(label + " reviewed index does not lead with " + leading_column)
            condition = node.get("indexCondition")
            if leading_column not in _condition_columns(condition):
                _fail(label + " index condition does not constrain " + leading_column)
            rows, loops, _ = _node_work(node, label + " intended index")
            if loops != 1:
                _fail(label + " intended index did not execute exactly once")
            actual_rows_total += rows * loops
        if actual_rows_total != expected_rows:
            _fail(label + " intended index returned an unexpected target row count")

    index_work = []
    index_totals: dict[tuple[str, str], float] = {}
    index_names_by_key: dict[tuple[str, str], set[str]] = {}
    for node, relation, logical_key, index_name in normalized_indexes:
        rows, loops, entries = _node_work(node, label + " index scan")
        if loops > 1 or entries > 1:
            _fail(label + " inspected more than one entry in a principal index")
        key = (relation, logical_key)
        index_names_by_key.setdefault(key, set()).add(index_name)
        if loops > 0:
            index_totals[key] = index_totals.get(key, 0.0) + entries
        index_work.append({
            "relation": relation,
            "index": index_name,
            "logicalKeyColumn": logical_key,
            "nodeType": node.get("nodeType"),
            "actualRows": rows,
            "actualLoops": loops,
            "rowsRemovedByFilter": node.get("rowsRemovedByFilter", 0),
            "rowsRemovedByIndexRecheck": node.get("rowsRemovedByIndexRecheck", 0),
            "indexConditionPresent": type(node.get("indexCondition")) is str,
            "indexConditionColumns": sorted(_condition_columns(node.get("indexCondition"))),
            "entriesVisited": entries,
        })
    if any(visited > 1 for visited in index_totals.values()):
        _fail(label + " visited more than one entry through a principal index")

    heap_work = []
    heap_totals: dict[str, float] = {}
    for raw, node, raw_relation in zip(raw_nodes, nodes, raw_relations):
        if node.get("nodeType") not in _HEAP_NODE_TYPES:
            continue
        relation = _normalized_index_relation(node, raw_relation)
        rows, loops, visits = _node_work(node, label + " heap scan")
        if node.get("nodeType") == "Index Only Scan":
            fetches = raw.get("Heap Fetches")
            fetches = _finite_number(fetches, label + " index-only heap fetches")
            visits = fetches
        if loops > 1 or visits > 1:
            _fail(label + " visited more than one row in a principal heap")
        if loops > 0:
            heap_totals[relation] = heap_totals.get(relation, 0.0) + visits
        heap_work.append({
            "relation": relation,
            "nodeType": node.get("nodeType"),
            "actualRows": rows,
            "actualLoops": loops,
            "rowsRemovedByFilter": node.get("rowsRemovedByFilter", 0),
            "rowsRemovedByIndexRecheck": node.get("rowsRemovedByIndexRecheck", 0),
            "heapRowsVisited": visits,
        })
    if any(visited > 1 for visited in heap_totals.values()):
        _fail(label + " visited more than one row in a principal heap")

    return {
        "indexes": index_work,
        "heaps": heap_work,
        "totalIndexEntriesVisited": sum(index_totals.values()),
        "totalHeapRowsVisited": sum(heap_totals.values()),
        "indexEntryTotals": index_totals,
        "indexNamesByKey": index_names_by_key,
        "heapRowTotals": heap_totals,
    }


def _work_comparison(name: str, first: dict, second: dict) -> dict:
    first_indexes = first["indexEntryTotals"]
    second_indexes = second["indexEntryTotals"]
    first_heaps = first["heapRowTotals"]
    second_heaps = second["heapRowTotals"]
    for key in set(first_indexes) | set(second_indexes):
        if second_indexes.get(key, 0.0) > first_indexes.get(key, 0.0):
            _fail("principal index work grew at the larger population: " + name)
    for key in set(first_heaps) | set(second_heaps):
        if second_heaps.get(key, 0.0) > first_heaps.get(key, 0.0):
            _fail("principal heap work grew at the larger population: " + name)
    if (second["totalIndexEntriesVisited"] > first["totalIndexEntriesVisited"]
            or second["totalHeapRowsVisited"] > first["totalHeapRowsVisited"]):
        _fail("probe work grew at the larger population: " + name)

    def public_counts(counts: dict, names_by_key: dict) -> list[dict]:
        return [
            {
                "relation": relation,
                "keyColumn": key_column,
                "indexNames": sorted(names_by_key.get((relation, key_column), set())),
                "entriesVisited": entries,
            }
            for (relation, key_column), entries in sorted(
                counts.items(), key=lambda item: (item[0][0], item[0][1])
            )
        ]

    def public_heaps(counts: dict) -> list[dict]:
        return [
            {"relation": relation, "heapRowsVisited": visits}
            for relation, visits in sorted(counts.items(), key=lambda item: item[0] or "")
        ]

    return {
        "probe": name,
        f"at{_EXPECTED_GROWTH[0]}": {
            "indexes": public_counts(first_indexes, first["indexNamesByKey"]),
            "heaps": public_heaps(first_heaps),
            "totalIndexEntriesVisited": first["totalIndexEntriesVisited"],
            "totalHeapRowsVisited": first["totalHeapRowsVisited"],
        },
        f"at{_EXPECTED_GROWTH[1]}": {
            "indexes": public_counts(second_indexes, second["indexNamesByKey"]),
            "heaps": public_heaps(second_heaps),
            "totalIndexEntriesVisited": second["totalIndexEntriesVisited"],
            "totalHeapRowsVisited": second["totalHeapRowsVisited"],
        },
        "noUnrelatedWorkGrowth": True,
    }


def _public_work(work: dict) -> dict:
    return {
        "indexes": work["indexes"],
        "heaps": work["heaps"],
        "totalIndexEntriesVisited": work["totalIndexEntriesVisited"],
        "totalHeapRowsVisited": work["totalHeapRowsVisited"],
    }


def _require_probe_returned_one(plan: dict, label: str) -> None:
    root = plan["_document"]["Plan"]
    if root.get("Actual Rows") != 1 or root.get("Actual Loops") != 1:
        _fail("reserved-ID probe did not actually return one row: " + label)


def _validate_plan_observation(
    name: str,
    observation_value: object,
    query: dict,
    *,
    capture_name: str | None = None,
    reject_principal_sequential_scan: bool = False,
) -> dict:
    observation = _object(observation_value, "plan observation")
    if observation.get("name") != name:
        _fail("plan observation is out of source-locked order: " + name)
    raw, parsed = _parse_raw_plan(observation)
    source_hash = query.get("sourceSqlSha256")
    adapted_hash = _sha256(query["sql"].encode("utf-8"))
    if observation.get("sourceSqlSha256") != source_hash:
        _fail("plan observation source SQL hash differs from the query specification")
    if observation.get("executedSqlSha256") != adapted_hash:
        _fail("plan observation adapted SQL hash differs from the query specification")
    if observation.get("captureSha256") != _sha256(raw):
        _fail("plan observation raw-plan digest is incorrect")
    try:
        validated = s7_plans.validate_plan_capture(
            capture_name or name, raw, captured_sql_sha256=source_hash
        )
    except Rejected:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise Rejected("plan observation is malformed") from error
    if validated["captureSha256"] != observation.get("captureSha256"):
        _fail("validated raw-plan digest differs from the driver receipt")
    document = validated["explain"]
    # The driver keeps the EXPLAIN JSON value returned by node-postgres.  Check
    # its public flattened node observations against the retained tree too.
    expected_flat = _raw_node_summaries(document)
    supplied_flat = _array(observation.get("nodes"), "flattened plan nodes")
    if supplied_flat != expected_flat:
        _fail("flattened plan nodes differ from the retained EXPLAIN tree")
    principal_scans = [
        node for node in validated["nodes"]
        if node.get("nodeType") == "Seq Scan"
        and node.get("relation") in _PRINCIPAL_RELATIONS
    ]
    observed_flag = observation.get("principalSequentialScanObserved")
    if type(observed_flag) is not bool or observed_flag != bool(principal_scans):
        _fail("principal sequential-scan summary differs from the retained plan")
    if (reject_principal_sequential_scan
            and any(node.get("actualLoops", 0) > 0 for node in principal_scans)):
        _fail("reserved-ID probe executed a principal sequential scan")
    elapsed = _finite_number(observation.get("elapsedMilliseconds"), "driver plan elapsed time")
    triggers = validated.get("triggerTimings")
    if type(triggers) is not list:
        _fail("raw plan trigger timing evidence is malformed")
    safe_triggers = []
    for trigger in triggers:
        if type(trigger) is not dict:
            _fail("raw plan contains a malformed trigger timing")
        trigger_name = trigger.get("Trigger Name")
        if type(trigger_name) is not str:
            _fail("raw plan trigger timing has no trigger name")
        trigger_time = _finite_number(trigger.get("Time"), "trigger time")
        calls = trigger.get("Calls")
        if type(calls) is not int or calls < 0:
            _fail("raw plan trigger timing has an invalid call count")
        safe_triggers.append({"name": trigger_name, "timeMs": trigger_time, "calls": calls})
    planning_time = validated["planningTimeMs"]
    execution_time = validated["executionTimeMs"]
    return {
        "name": name,
        "sourceSqlSha256": source_hash,
        "executedSqlSha256": adapted_hash,
        "rawPlanJsonSha256": validated["captureSha256"],
        "elapsedMilliseconds": elapsed,
        "planningTimeMs": planning_time,
        "executionTimeMs": execution_time,
        "nodes": _safe_nodes(
            validated["nodes"], _walk_raw_relations(document)
        ),
        "principalSequentialScanObserved": bool(principal_scans),
        "principalSequentialScanNodes": [
            {
                "relation": node.get("relation"),
                "actualRows": node.get("actualRows"),
                "actualLoops": node.get("actualLoops"),
            }
            for node in principal_scans
        ],
        "triggerTimings": safe_triggers,
        "_validatedNodes": validated["nodes"],
        "_document": document,
    }


def _require_delete_root(plan: dict, label: str) -> dict:
    root = plan["_document"]["Plan"]
    if root.get("Node Type") != "ModifyTable" or root.get("Operation") != "Delete":
        _fail(label + " raw plan is not an analyzed DELETE")
    if (root.get("Actual Rows") != 1 or root.get("Actual Loops") != 1
            or type(root.get("Actual Rows")) not in (int, float)
            or type(root.get("Actual Loops")) not in (int, float)):
        _fail(label + " did not actually delete exactly one row")
    return root


def _observations(value: object, expected_queries: list[dict], label: str) -> list[dict]:
    rows = _array(value, label)
    if len(rows) != len(expected_queries):
        _fail(label + " count differs from its ordered query family")
    checked = []
    for row_value, query in zip(rows, expected_queries):
        row = _object(row_value, label + " scalar")
        if set(row) != {"kind", "value"} or row.get("kind") != query.get("result"):
            _fail(label + " scalar kind differs from its source query")
        kind = query.get("result")
        value = row.get("value")
        if kind == "count":
            _count(value, label + " count")
        elif kind == "boolean":
            if type(value) is not bool:
                _fail(label + " boolean is missing or malformed")
        else:
            _fail(label + " source query has an unsupported result kind")
        checked.append({"kind": kind, "value": value})
    return checked


def _control_liveness(value: object, expected_queries: list[dict], label: str) -> list[dict]:
    rows = _observations(value, expected_queries, label)
    if len(rows) != 2 or any(row["kind"] != "boolean" or row["value"] is not True for row in rows):
        _fail(label + " did not retain true web and mobile canonical guards")
    return rows


def _query_identity(query: dict) -> tuple[str, str | None]:
    match = re.search(r"\bFROM\s+public\.(\"[^\"]+\"|[a-z_][a-z0-9_]*)", query["sql"], re.I)
    if match is None:
        _fail("source count query has no fixed public relation")
    relation = match.group(1).strip('"')
    bindings = query.get("bindings")
    if type(bindings) is not list:
        _fail("source count query has no fixture bindings")
    branches = {
        "remote_web" if binding.startswith("expired.remote_web.") else "mobile"
        for binding in bindings
        if binding.startswith(("expired.remote_web.", "expired.mobile."))
    }
    if len(branches) > 1:
        _fail("source count query mixes expired authority branches")
    return relation, next(iter(branches)) if branches else None


_DELETE_COUNT_IDENTITIES = (
    ("session", "remote_web"),
    ("remote_account_identity", "remote_web"),
    ("remote_session_binding", "remote_web"),
    ("consumer_approval_intent", "remote_web"),
    ("consumer_approval_consumed_proof", "remote_web"),
    ("consumer_derivative_consent", "remote_web"),
    ("consumer_authorization", "remote_web"),
    ("remote_service_authorization", "remote_web"),
    ("consumer_approval_intent", "mobile"),
    ("consumer_approval_consumed_proof", "mobile"),
    ("consumer_derivative_consent", "mobile"),
    ("consumer_authorization", "mobile"),
    ("remote_service_authorization", "mobile"),
    ("remote_web_session", "remote_web"),
    ("mobile_session", "mobile"),
)


def _expected_deleted_identity(name: str, identity: tuple[str, str | None]) -> bool:
    relation, branch = identity
    all_authority = {
        "consumer_approval_intent",
        "consumer_approval_consumed_proof",
        "consumer_derivative_consent",
        "consumer_authorization",
        "remote_service_authorization",
        "remote_web_session",
        "mobile_session",
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
    if name == "mobile":
        return branch == "mobile" and relation in {
            "mobile_session", "consumer_derivative_consent", "consumer_authorization",
        }
    _fail("unknown S7 cascade-delete family")


def _validate_rollback_receipt(
    receipt_value: object,
    before: list[dict],
    after: list[dict],
    controls_before: list[dict],
    controls_after: list[dict],
    label: str,
) -> dict:
    receipt = _object(receipt_value, label + " rollback receipt")
    expected_keys = {
        "transaction", "beforeControlSha256", "afterControlSha256",
        "unrelatedControlSha256Before", "unrelatedControlSha256After",
    }
    if set(receipt) != expected_keys or receipt.get("transaction") != "ROLLED_BACK":
        _fail(label + " rollback transaction is not explicitly complete")
    expected = {
        "beforeControlSha256": _canonical_hash(before),
        "afterControlSha256": _canonical_hash(after),
        "unrelatedControlSha256Before": _canonical_hash(controls_before),
        "unrelatedControlSha256After": _canonical_hash(controls_after),
    }
    for key, digest in expected.items():
        if not _is_digest(receipt.get(key)) or receipt[key] != digest:
            _fail(label + " rollback digest does not match observed control counts")
    if before != after or controls_before != controls_after:
        _fail(label + " rollback did not restore exact target and unrelated counts")
    return {"transaction": "ROLLED_BACK", **expected}


def _validate_delete_observation(
    observation_value: object,
    name: str,
    target: int,
    spec: dict,
    expected_fixture_counts: dict[str, int],
) -> dict:
    observation = _object(observation_value, "cascade delete observation")
    if (observation.get("name") != name
            or _integer(observation.get("targetUnrelatedPrincipalsPerKind"), "delete growth target") != target):
        _fail("cascade delete observation has the wrong stage or target")
    population = _validate_counts_map(
        observation.get("observedPopulationCounts"), _FIXTURE_COUNT_KEYS,
        "cascade delete observed population counts",
    )
    if population != expected_fixture_counts:
        _fail("cascade delete population differs from its growth observation")
    _validate_counts_map(
        observation.get("observedDatabaseTableCounts"), _DATABASE_COUNT_KEYS,
        "cascade delete observed database counts",
    )
    delete_spec = spec["deletes"][name]
    plan = _validate_plan_observation(
        "delete_" + name, observation.get("explainDelete"), delete_spec["explainDelete"]
    )
    delete_root = _require_delete_root(plan, "cascade " + name)
    triggers = plan["triggerTimings"]
    if not triggers or any(trigger["calls"] <= 0 for trigger in triggers):
        _fail("cascade DELETE has no positive-call trigger timing evidence")
    before = _observations(observation.get("beforeCounts"), delete_spec["beforeCounts"], "cascade before counts")
    inside = _observations(
        observation.get("insideTransactionCounts"),
        delete_spec["insideTransactionCounts"],
        "cascade inside-transaction counts",
    )
    after = _observations(
        observation.get("afterRollbackCounts"), delete_spec["afterRollbackCounts"],
        "cascade after-rollback counts",
    )
    count_identities = [_query_identity(query) for query in delete_spec["beforeCounts"]]
    if tuple(count_identities) != _DELETE_COUNT_IDENTITIES:
        _fail("ordered cascade count queries differ from the reviewed authority family")
    expected_before = [1] * len(count_identities)
    expected_inside = [
        0 if _expected_deleted_identity(name, identity) else 1
        for identity in count_identities
    ]
    if [int(row["value"]) for row in before] != expected_before:
        _fail("cascade fixture did not contain exactly one observed target row per query")
    if [int(row["value"]) for row in inside] != expected_inside:
        _fail("inside-transaction cascade counts differ from the reviewed FK effects")
    if [int(row["value"]) for row in after] != expected_before:
        _fail("rollback did not restore every target authority count")
    controls = observation.get("unrelatedControlLiveness")
    controls = _object(controls, "cascade unrelated controls")
    controls_before = _control_liveness(
        controls.get("before"), delete_spec["unrelatedControlLiveness"], "cascade controls before"
    )
    controls_inside = _control_liveness(
        controls.get("insideTransaction"), delete_spec["unrelatedControlLiveness"], "cascade controls inside"
    )
    controls_after = _control_liveness(
        controls.get("afterRollback"), delete_spec["unrelatedControlLiveness"], "cascade controls after"
    )
    if observation.get("rollbackCompleted") is not True:
        _fail("cascade DELETE did not complete its rollback")
    rollback = _validate_rollback_receipt(
        observation.get("rollbackReceipt"), before, after, controls_before,
        controls_after, "cascade " + name,
    )
    if controls_inside != controls_before or controls_after != controls_before:
        _fail("unrelated web/mobile authorities changed during a cascade DELETE")
    expected_target = {
        "session": ("session", "remote_web"),
        "account_identity": ("remote_account_identity", "remote_web"),
        "service": ("remote_service_authorization", "remote_web"),
        "web": ("remote_web_session", "remote_web"),
        "mobile": ("mobile_session", "mobile"),
    }[name]
    try:
        target_index = count_identities.index(expected_target)
    except ValueError as error:
        raise Rejected("cascade target is missing from its ordered count family") from error
    if int(inside[target_index]["value"]) != 0:
        _fail("cascade DELETE did not remove its intended target authority")
    return {
        "name": name,
        "targetUnrelatedPrincipalsPerKind": target,
        "explainDelete": _public_plan(plan),
        "beforeCounts": [row["value"] for row in before],
        "insideTransactionCounts": [row["value"] for row in inside],
        "afterRollbackCounts": [row["value"] for row in after],
        "unrelatedWebMobileGuards": [True, True],
        "rollback": rollback,
        "deletedRows": delete_root["Actual Rows"],
        "triggerTimingCount": len(triggers),
    }


def _public_plan(plan: dict) -> dict:
    return {
        key: value for key, value in plan.items()
        if key not in {"_validatedNodes", "_document", "_work"}
    }


def _validate_source_ttl_observation(
    observation_value: object,
    name: str,
    spec: dict,
    expected_fixture_counts: dict[str, int],
) -> dict:
    observation = _object(observation_value, "source TTL delete observation")
    if observation.get("name") != name:
        _fail("source TTL delete observation has the wrong target")
    if _integer(observation.get("targetUnrelatedPrincipalsPerKind"), "source TTL growth target") != _EXPECTED_GROWTH[-1]:
        _fail("source TTL delete was not measured at the final population")
    population = _validate_counts_map(
        observation.get("observedPopulationCounts"), _FIXTURE_COUNT_KEYS,
        "source TTL observed population counts",
    )
    if population != expected_fixture_counts:
        _fail("source TTL delete population differs from the final growth stage")
    _validate_counts_map(
        observation.get("observedDatabaseTableCounts"), _DATABASE_COUNT_KEYS,
        "source TTL observed database counts",
    )
    ttl_spec = spec["sourceTtlDeletes"][name]
    plan = _validate_plan_observation(
        "source_ttl_delete_" + name,
        observation.get("explainDelete"),
        ttl_spec["explainDelete"],
        capture_name="source_ttl_" + name,
    )
    root = _require_delete_root(plan, "source TTL " + name)
    before = _observations(observation.get("beforeCounts"), ttl_spec["beforeCounts"], "source TTL before counts")
    inside = _observations(
        observation.get("insideTransactionCounts"), ttl_spec["insideTransactionCounts"],
        "source TTL inside-transaction counts",
    )
    after = _observations(
        observation.get("afterRollbackCounts"), ttl_spec["afterRollbackCounts"],
        "source TTL after-rollback counts",
    )
    if ([row["value"] for row in before] != ["1"]
            or [row["value"] for row in inside] != ["0"]
            or [row["value"] for row in after] != ["1"]):
        _fail("source TTL rollback observations do not prove delete 1, inside 0, rollback 1")
    retained = _object(observation.get("retainedAuthority"), "source TTL retained authority")
    if set(retained) != {"proof", "consent", "consumerAuthorization"}:
        _fail("source TTL retention receipt is incomplete")
    for key, query in ttl_spec["retainedAuthority"].items():
        row = _observations([retained[key]], [query], "source TTL retained " + key)[0]
        if row["value"] != "1":
            _fail("source TTL delete did not retain exactly one " + key)
    guard = _observations(
        [observation.get("principalLiveGuard")], [ttl_spec["principalLiveGuard"]],
        "source TTL canonical principal guard",
    )
    if guard[0]["value"] is not True:
        _fail("source TTL delete did not preserve the canonical live principal")
    controls = _object(observation.get("unrelatedControlLiveness"), "source TTL unrelated controls")
    controls_before = _control_liveness(
        controls.get("before"), ttl_spec["unrelatedControlLiveness"], "source TTL controls before"
    )
    controls_inside = _control_liveness(
        controls.get("insideTransaction"), ttl_spec["unrelatedControlLiveness"], "source TTL controls inside"
    )
    controls_after = _control_liveness(
        controls.get("afterRollback"), ttl_spec["unrelatedControlLiveness"], "source TTL controls after"
    )
    if observation.get("rollbackCompleted") is not True:
        _fail("source TTL DELETE did not complete its rollback")
    rollback = _validate_rollback_receipt(
        observation.get("rollbackReceipt"), before, after,
        controls_before, controls_after, "source TTL " + name,
    )
    if controls_inside != controls_before or controls_after != controls_before:
        _fail("unrelated web/mobile authorities changed during a source TTL DELETE")
    return {
        "name": name,
        "targetUnrelatedPrincipalsPerKind": _EXPECTED_GROWTH[-1],
        "explainDelete": _public_plan(plan),
        "sourceRowsBeforeInsideAfter": ["1", "0", "1"],
        "retainedProofConsentConsumerAuthorization": {key: "1" for key in retained},
        "canonicalPrincipalLiveGuard": True,
        "unrelatedWebMobileGuards": [True, True],
        "rollback": rollback,
        "deletedRows": root["Actual Rows"],
    }


def _validate_lifecycle(value: object) -> dict[str, int]:
    lifecycle = _object(value, "lifecycle observations")
    required_positive = (
        "naturallyExpiredSourceRows",
        "naturallyExpiredParentRows",
        "naturallyExpiredWebPrincipalRows",
        "naturallyIdleExpiredWebPrincipalRows",
        "naturallyExpiredMobilePrincipalRows",
        "naturallyIdleExpiredMobilePrincipalRows",
        "retainedConsumedProofRows",
        "retainedExpiredWebSourceRows",
        "retainedExpiredMobileSourceRows",
        "tombstonedConsumerAuthorizationRows",
        "tombstonedConsentRows",
        "tombstonedWebConsumerAuthorizationRows",
        "tombstonedMobileConsumerAuthorizationRows",
        "tombstonedWebConsentRows",
        "tombstonedMobileConsentRows",
        "actualRevokedWebPrincipalRows",
        "actualRevokedMobilePrincipalRows",
    )
    expected_keys = set(required_positive) | {
        "actualRevokedPrincipalRows", "livePendingSeedSourceRows"
    }
    if set(lifecycle) != expected_keys:
        _fail("lifecycle observations have an unsupported count shape")
    counts = {
        key: _integer(lifecycle[key], "lifecycle " + key)
        for key in expected_keys
    }
    if any(counts[key] <= 0 for key in required_positive):
        _fail("lifecycle evidence omits an expired, retained, revoked, or tombstoned category")
    if counts["actualRevokedPrincipalRows"] < 2:
        _fail("lifecycle evidence does not include both actually revoked principals")
    if counts["livePendingSeedSourceRows"] != 2:
        _fail("lifecycle evidence does not retain both live pending seed sources")
    return counts


def validate_runtime_evidence(payload: dict, private_seed_receipts: list, spec: dict) -> dict:
    """Validate all observed populated S7 evidence and return a safe summary.

    Invalid evidence raises :class:`s7_plans.Rejected`.  A PASS is scoped to
    this private Consumer S7 measurement; production qualification and
    deployment are always false.
    """
    evidence = _object(payload, "runtime evidence")
    try:
        s7_spec.validate_spec(spec)
    except Rejected:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise Rejected("query specification is malformed") from error
    _source_closure(evidence, spec)
    if (evidence.get("driverExecutionCompleted") is not True
            or evidence.get("failurePhase") is not None
            or evidence.get("failureKind") is not None
            or evidence.get("failureDiagnostic") is not None):
        _fail("runtime driver did not complete without a failure")
    if evidence.get("cleanupComplete") is not True:
        _fail("runtime fixture cleanup is incomplete")
    cleanup = _validate_counts_map(
        evidence.get("cleanupObservationCounts"), _CLEANUP_COUNT_KEYS,
        "cleanup observation counts",
    )
    if not cleanup or any(cleanup.values()):
        _fail("runtime cleanup did not observe zero residual fixture rows")
    if evidence.get("qualificationClaims") != []:
        _fail("runtime driver supplied unsupported qualification claims")
    if evidence.get("missingCases") != []:
        _fail("runtime driver reports missing S7 cases")

    private_receipts = _validate_private_seeds(private_seed_receipts, spec)
    if evidence.get("privateSeedReceiptsCaptured") is not True:
        _fail("driver did not capture private production-flow seed receipts")
    _validate_public_seed_summaries(evidence, private_receipts)

    growth, stage_counts, probe_work_comparison = _validate_growth(evidence, spec)
    delete_rows = _array(evidence.get("deletePlanObservations"), "cascade delete observations")
    if len(delete_rows) != 10:
        _fail("exactly five cascade deletes at each of two growth stages are required")
    delete_summaries = []
    offset = 0
    for stage_index, target in enumerate(_EXPECTED_GROWTH):
        stage_rows = delete_rows[offset:offset + len(_DELETE_NAMES)]
        if len(stage_rows) != len(_DELETE_NAMES):
            _fail("cascade delete stage is incomplete")
        for name, row in zip(_DELETE_NAMES, stage_rows):
            delete_summaries.append(
                _validate_delete_observation(
                    row, name, target, spec, stage_counts[stage_index]
                )
            )
        offset += len(_DELETE_NAMES)
    ttl_rows = _array(evidence.get("sourceTtlDeletePlanObservations"), "source TTL delete observations")
    if len(ttl_rows) != 2:
        _fail("exactly two final source TTL rollback plans are required")
    ttl_summaries = [
        _validate_source_ttl_observation(row, name, spec, stage_counts[-1])
        for row, name in zip(ttl_rows, _SOURCE_TTL_NAMES)
    ]
    lifecycle = _validate_lifecycle(evidence.get("lifecycleObservations"))

    growth_summaries = []
    for stage in growth:
        all_plans = stage["lookupPlans"] + stage["pendingAbsencePlans"]
        sequential_nodes = [
            {"plan": plan["name"], **node}
            for plan in all_plans
            for node in plan["principalSequentialScanNodes"]
        ]
        growth_summaries.append({
            "targetUnrelatedPrincipalsPerKind": stage["targetUnrelatedPrincipalsPerKind"],
            "fixtureCounts": stage["fixtureCounts"],
            "privateDatabaseTableCounts": stage["privateDatabaseTableCounts"],
            "principalSequentialScanNodes": sequential_nodes,
            "lookupPlans": [_public_plan(plan) for plan in stage["lookupPlans"]],
            "pendingAbsencePlans": [_public_plan(plan) for plan in stage["pendingAbsencePlans"]],
        })

    return {
        "scope": "PRIVATE_CONSUMER_S7",
        "status": "PASS",
        "fullS7Qualified": True,
        "productionQualified": False,
        "deploymentQualified": False,
        "sourceHashes": dict(spec["sourceHashes"]),
        "querySpecificationSha256": spec["querySpecificationSha256"],
        "cleanupObservationCounts": cleanup,
        "privateSeedReceiptCount": 4,
        "growthStages": growth_summaries,
        "probeWorkComparison": probe_work_comparison,
        "cascadeDeleteCount": len(delete_summaries),
        "cascadeDeletes": delete_summaries,
        "sourceTtlDeleteCount": len(ttl_summaries),
        "sourceTtlDeletes": ttl_summaries,
        "lifecycleCounts": lifecycle,
    }

