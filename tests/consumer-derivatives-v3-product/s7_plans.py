"""Source-only S7 SQL and receipt validators for Consumer v3.

This module deliberately has no database, process, Bun, or SQL execution
interface.  Its SQL is a fixed, parameterized contract for later integration
with the private ``controller.Fixture``.  Planning observations are evidence;
this module does not set acceptance thresholds or qualify S7.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import stat


class Rejected(ValueError):
    """A source pin or captured S7 receipt is malformed or inconsistent."""


SOURCE_FILES = {
    "module": "lomi-remote/tests/consumer-derivatives-v3-product/s7_plans.py",
    "intent": (
        "lomi-remote/staging/consumer-derivatives-v3-product-successor/"
        "inputs/frozen-v3-successor/approval-intent.candidate.sql"
    ),
    "consent": (
        "lomi-remote/staging/consumer-derivatives-v3-product-successor/"
        "inputs/frozen-v3-successor/012-derivative-authority.candidate.sql"
    ),
    "flow": "auth-app/src/consumer-derivative-flow.ts",
    "authority": "auth-app/src/consumer-derivative-authority.ts",
}

NEW_CASCADE_INDEXES = (
    ("public.consumer_approval_intent", ("accountSessionId",)),
    ("public.consumer_approval_intent", ("accountId",)),
    ("public.consumer_derivative_consent", ("accountSessionId",)),
    ("public.consumer_derivative_consent", ("accountId",)),
    ("public.consumer_derivative_consent", ("serviceAuthorizationId",)),
    ("public.consumer_derivative_consent", ("webSessionId",)),
    ("public.consumer_derivative_consent", ("mobileSessionId",)),
)


def _explain(sql: str) -> str:
    return "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) " + sql


# These are the seven exact leading-key child lookups required by the
# successor's composite FKs.  All key parts are constrained; the new indexes
# supply the first column and no planner setting is changed.
LOOKUP_SQL = {
    "intent_parent": _explain(
        'SELECT id FROM public.consumer_approval_intent '
        'WHERE "accountSessionId" = :\'account_session_id\'::text '
        'AND "userId" = :\'user_id\'::text;'
    ),
    "intent_account": _explain(
        'SELECT id FROM public.consumer_approval_intent '
        'WHERE "accountId" = :\'account_id\'::uuid '
        'AND "userId" = :\'user_id\'::text;'
    ),
    "consent_parent": _explain(
        'SELECT id FROM public.consumer_derivative_consent '
        'WHERE "accountSessionId" = :\'account_session_id\'::text '
        'AND "userId" = :\'user_id\'::text;'
    ),
    "consent_account": _explain(
        'SELECT id FROM public.consumer_derivative_consent '
        'WHERE "accountId" = :\'account_id\'::uuid '
        'AND "userId" = :\'user_id\'::text;'
    ),
    "consent_service": _explain(
        'SELECT id FROM public.consumer_derivative_consent '
        'WHERE "serviceAuthorizationId" = :\'service_authorization_id\'::text '
        'AND "userId" = :\'user_id\'::text '
        'AND "accountSessionId" = :\'account_session_id\'::text;'
    ),
    "consent_web": _explain(
        'SELECT id FROM public.consumer_derivative_consent '
        'WHERE "webSessionId" = :\'web_session_id\'::text '
        'AND "userId" = :\'user_id\'::text '
        'AND "accountSessionId" = :\'account_session_id\'::text '
        'AND "serviceAuthorizationId" = :\'service_authorization_id\'::text;'
    ),
    "consent_mobile": _explain(
        'SELECT id FROM public.consumer_derivative_consent '
        'WHERE "mobileSessionId" = :\'mobile_session_id\'::text '
        'AND "userId" = :\'user_id\'::text '
        'AND "accountSessionId" = :\'account_session_id\'::text '
        'AND "serviceAuthorizationId" = :\'service_authorization_id\'::text;'
    ),
}


# The PL/pgSQL pending-source guard first loads h, then runs three separate
# EXISTS queries with record values as parameters. Preserve those point
# lookups: an outer SQL join to h would introduce a different correlated plan
# which PostgreSQL may turn into a full-table hashed subplan.
PENDING_ABSENCE_SQL = {
    "pending_service_absence": _explain(
        'SELECT NOT EXISTS (SELECT FROM public.remote_service_authorization AS s '
        'WHERE s.id = :\'service_authorization_id\'::text '
        'AND s."consumerApprovalId" = :\'approval_id\'::uuid) AS reserved_id_absent;'
    ),
    "pending_web_absence": _explain(
        'SELECT NOT EXISTS (SELECT FROM public.remote_web_session AS w '
        'WHERE w.id = :\'web_session_id\'::text '
        'AND w."consumerApprovalId" = :\'approval_id\'::uuid) AS reserved_id_absent;'
    ),
    "pending_mobile_absence": _explain(
        'SELECT NOT EXISTS (SELECT FROM public.mobile_session AS m '
        'WHERE m.id = :\'mobile_session_id\'::text '
        'AND m."consumerApprovalId" = :\'approval_id\'::uuid) AS reserved_id_absent;'
    ),
}


# Actual EXPLAIN ANALYZE DELETE statements run inside an explicit transaction
# and roll back immediately.  Fixture identifiers are supplied using psql's
# quoted variable syntax by the eventual controller integration.
DELETE_SQL = {
    "session": (
        "BEGIN;\n"
        + _explain(
            'DELETE FROM public."session" '
            'WHERE id = :\'account_session_id\'::text '
            'AND "userId" = :\'user_id\'::text RETURNING id;'
        )
        + "\nROLLBACK;\n"
    ),
    "account_identity": (
        "BEGIN;\n"
        + _explain(
            'DELETE FROM public.remote_account_identity '
            'WHERE id = :\'account_id\'::uuid '
            'AND "userId" = :\'user_id\'::text RETURNING id;'
        )
        + "\nROLLBACK;\n"
    ),
    "service": (
        "BEGIN;\n"
        + _explain(
            'DELETE FROM public.remote_service_authorization '
            'WHERE id = :\'service_authorization_id\'::text '
            'AND "userId" = :\'user_id\'::text RETURNING id;'
        )
        + "\nROLLBACK;\n"
    ),
    "web": (
        "BEGIN;\n"
        + _explain(
            'DELETE FROM public.remote_web_session '
            'WHERE id = :\'web_session_id\'::text '
            'AND "userId" = :\'user_id\'::text RETURNING id;'
        )
        + "\nROLLBACK;\n"
    ),
    "mobile": (
        "BEGIN;\n"
        + _explain(
            'DELETE FROM public.mobile_session '
            'WHERE id = :\'mobile_session_id\'::text '
            'AND "userId" = :\'user_id\'::text RETURNING id;'
        )
        + "\nROLLBACK;\n"
    ),
}

SOURCE_TTL_DELETE_SQL = {
    "web": (
        "BEGIN;\n"
        + _explain('DELETE FROM public.remote_login_attempt WHERE id = :\'web_attempt_id\'::text RETURNING id;')
        + "\nROLLBACK;\n"
    ),
    "mobile": (
        "BEGIN;\n"
        + _explain('DELETE FROM public.mobile_login WHERE id = :\'mobile_login_id\'::text RETURNING id;')
        + "\nROLLBACK;\n"
    ),
}

ALL_PLAN_SQL = {**LOOKUP_SQL, **PENDING_ABSENCE_SQL}
ALL_CAPTURE_SQL = {**ALL_PLAN_SQL, **{"delete_" + key: value for key, value in DELETE_SQL.items()},
                   **{"source_ttl_" + key: value for key, value in SOURCE_TTL_DELETE_SQL.items()}}

SEED_CASES = (
    ("live_pending", "remote_web"),
    ("live_pending", "mobile"),
    ("consumed_live", "remote_web"),
    ("consumed_live", "mobile"),
)

ANALYZE_TABLES = (
    "public.consumer_approval_intent",
    "public.consumer_approval_consumed_proof",
    "public.consumer_derivative_consent",
    "public.consumer_authorization",
    "public.remote_account_identity",
    "public.remote_service_authorization",
    "public.remote_web_session",
    "public.mobile_session",
    'public."session"',
    "public.remote_session_binding",
)

ANALYZE_SQL = "\n".join(
    "ANALYZE " + table + ";" for table in ANALYZE_TABLES
) + "\n"
PLANNER_SETTINGS_SQL = (
    "SELECT jsonb_build_object("
    "'enable_seqscan', current_setting('enable_seqscan'), "
    "'enable_indexscan', current_setting('enable_indexscan'), "
    "'enable_bitmapscan', current_setting('enable_bitmapscan'))::text;\n"
)

APPROVAL_SNAPSHOT_FIELDS = (
    "accountId", "userId", "accountSessionId", "actualKind", "actualId",
    "webActualId", "mobileActualId", "serviceAuthorizationId", "clientId",
    "approvalOrigin", "targetOrigin", "redirectUri", "state", "scope",
    "serviceVersion", "consentVersion", "authorizationEpoch", "approvedAt",
    "approvalXid", "requestExpiresAt", "codeExpiresAt", "codeHashSha256",
    "codeChallenge", "parentDeadline", "serviceDeadline", "actualDeadline",
    "actualIdleDeadline", "expiresAt",
)

CONSENT_SNAPSHOT_FIELDS = (
    "accountId", "userId", "accountSessionId", "actualKind", "actualId",
    "serviceAuthorizationId", "authorizationEpoch", "consentedAt",
    "parentDeadline", "serviceDeadline", "actualDeadline", "actualIdleDeadline",
    "expiresAt", "scope", "consentVersion",
)

RECEIPT_REQUIREMENTS = (
    "source pins cover this module and both exact frozen SQL files",
    "production-flow-generated live pending and consumed-live web/mobile seed receipts",
    "normal ANALYZE receipt for the populated target relations",
    "normal planner settings receipt with no per-query forcing controls",
    "EXPLAIN (ANALYZE, BUFFERS, VERBOSE) capture for all ten lookup probes",
    "rollback EXPLAIN ANALYZE DELETE captures for session/account/service/web/mobile",
    "before/after restoration controls for every rollback delete",
    "unrelated-row growth comparison with raw plans retained",
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sql_digests() -> dict[str, str]:
    """Return exact UTF-8 SQL digests for the source-defined capture set."""
    return {name: sha256(sql.encode("utf-8")) for name, sql in sorted(ALL_CAPTURE_SQL.items())}


def preparation_sql_digests() -> dict[str, str]:
    """Return exact hashes for the population ANALYZE and planner snapshot SQL."""
    return {
        "analyze": sha256(ANALYZE_SQL.encode("utf-8")),
        "planner_settings": sha256(PLANNER_SETTINGS_SQL.encode("utf-8")),
    }


def _safe_relative(relative: str) -> tuple[str, ...]:
    if (type(relative) is not str or not relative or "\\" in relative
            or relative.startswith("/") or re.match(r"^[A-Za-z]:", relative)):
        raise Rejected("source pin has an unsafe relative path")
    parts = tuple(relative.split("/"))
    if any(part in ("", ".", "..") for part in parts):
        raise Rejected("source pin has an unsafe relative path")
    return parts


def source_lock_receipt(source_root: Path, source_allowlist: dict) -> dict:
    """Verify the exact S7 module/frozen SQL source pins without running tools."""
    if type(source_allowlist) is not dict:
        raise Rejected("source allowlist must be an object")
    root = Path(source_root)
    try:
        root_info = root.lstat()
    except OSError as error:
        raise Rejected("source root is unavailable") from error
    if not stat.S_ISDIR(root_info.st_mode) or root.is_symlink():
        raise Rejected("source root must be a regular directory")

    records = {}
    for label, relative in SOURCE_FILES.items():
        expected = source_allowlist.get(relative)
        if type(expected) is not str or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise Rejected("source lock pin missing or malformed: " + label)
        path = root
        for part in _safe_relative(relative):
            path = path / part
            if path.is_symlink():
                raise Rejected("source closure traverses a symlink: " + relative)
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise Rejected("source pin is not a regular file: " + label)
            raw = path.read_bytes()
        except OSError as error:
            raise Rejected("source pin cannot be read: " + label) from error
        actual = sha256(raw)
        if actual != expected:
            raise Rejected("source pin hash drift: " + label)
        records[label] = {"path": relative, "sha256": actual, "bytes": len(raw)}
    return {
        "status": "SOURCE_LOCKED",
        "sourceFiles": records,
        "captureSqlSha256": sql_digests(),
        "preparationSqlSha256": preparation_sql_digests(),
    }


def _strict_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise Rejected("invalid EXPLAIN JSON capture") from error


def _number(value, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise Rejected("invalid numeric EXPLAIN field: " + label)
    return float(value)


def _plan_document(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > 64 * 1024 * 1024:
        raise Rejected("EXPLAIN capture is missing or over the evidence bound")
    document = _strict_json(raw)
    if type(document) is list:
        if len(document) != 1:
            raise Rejected("EXPLAIN JSON must contain exactly one statement")
        document = document[0]
    if type(document) is not dict or type(document.get("Plan")) is not dict:
        raise Rejected("EXPLAIN JSON has no plan object")
    _number(document.get("Planning Time"), "Planning Time")
    _number(document.get("Execution Time"), "Execution Time")
    return document


def _walk_nodes(root: dict):
    nodes = []
    pending = [root]
    while pending:
        node = pending.pop()
        if type(node) is not dict or type(node.get("Node Type")) is not str:
            raise Rejected("malformed EXPLAIN plan node")
        for field in ("Plan Rows", "Actual Rows", "Actual Loops"):
            if field not in node:
                raise Rejected("EXPLAIN ANALYZE node is missing " + field)
            _number(node[field], field)
        summary = {"nodeType": node["Node Type"]}
        for source, target in (
            ("Relation Name", "relation"), ("Schema", "schema"),
            ("Index Name", "index"), ("Index Cond", "indexCondition"),
            ("Filter", "filter"), ("Rows Removed by Filter", "rowsRemovedByFilter"),
            ("Rows Removed by Index Recheck", "rowsRemovedByIndexRecheck"),
            ("Plan Rows", "planRows"), ("Actual Rows", "actualRows"),
            ("Actual Loops", "actualLoops"), ("Shared Hit Blocks", "sharedHitBlocks"),
            ("Shared Read Blocks", "sharedReadBlocks"),
        ):
            if source in node:
                value = node[source]
                if source in ("Plan Rows", "Actual Rows", "Actual Loops", "Rows Removed by Filter",
                              "Rows Removed by Index Recheck",
                              "Shared Hit Blocks", "Shared Read Blocks"):
                    _number(value, source)
                elif type(value) is not str:
                    raise Rejected("malformed EXPLAIN text field: " + source)
                summary[target] = value
        nodes.append(summary)
        children = node.get("Plans", [])
        if type(children) is not list:
            raise Rejected("malformed EXPLAIN child-node list")
        pending.extend(reversed(children))
    return nodes


def validate_plan_capture(name: str, raw: bytes, *, captured_sql_sha256: str) -> dict:
    """Validate and retain one raw natural-planner JSON plan, without scoring it."""
    expected = sql_digests().get(name)
    if expected is None or captured_sql_sha256 != expected:
        raise Rejected("captured plan SQL does not match the fixed S7 source")
    document = _plan_document(raw)
    for field in ("Shared Hit Blocks", "Shared Read Blocks"):
        if field not in document["Plan"]:
            raise Rejected("EXPLAIN BUFFERS root is missing " + field)
        _number(document["Plan"][field], field)
    return {
        "captureName": name,
        "captureSqlSha256": expected,
        "captureSha256": sha256(raw),
        "explain": document,
        "nodes": _walk_nodes(document["Plan"]),
        "triggerTimings": document.get("Triggers", []),
        "planningTimeMs": _number(document["Planning Time"], "Planning Time"),
        "executionTimeMs": _number(document["Execution Time"], "Execution Time"),
        "qualification": "NOT_EVALUATED",
    }


def validate_delete_capture(name: str, raw: bytes, *, captured_sql_sha256: str,
                            rollback: dict) -> dict:
    """Validate a DELETE plan and its explicit rollback/restoration receipt."""
    full_name = "delete_" + name
    if name not in DELETE_SQL:
        raise Rejected("unknown S7 delete target")
    result = validate_plan_capture(full_name, raw, captured_sql_sha256=captured_sql_sha256)
    plan = result["explain"]["Plan"]
    if plan.get("Node Type") != "ModifyTable" or plan.get("Operation") != "Delete":
        raise Rejected("captured EXPLAIN is not an analyzed DELETE")
    _number(plan.get("Actual Rows"), "DELETE Actual Rows")
    if "Triggers" not in result["explain"]:
        raise Rejected("DELETE EXPLAIN did not retain trigger timing evidence")
    triggers = result["triggerTimings"]
    if type(triggers) is not list:
        raise Rejected("DELETE EXPLAIN is missing trigger timing evidence")
    for trigger in triggers:
        if type(trigger) is not dict:
            raise Rejected("malformed DELETE trigger timing")
        if type(trigger.get("Trigger Name")) is not str:
            raise Rejected("DELETE trigger timing has no name")
        _number(trigger.get("Time"), "trigger Time")
        calls = trigger.get("Calls")
        if type(calls) is not int or calls < 0:
            raise Rejected("DELETE trigger timing has an invalid call count")
    if type(rollback) is not dict or rollback.get("transaction") != "ROLLED_BACK":
        raise Rejected("DELETE capture lacks an explicit rollback receipt")
    before = rollback.get("beforeControlSha256")
    after = rollback.get("afterControlSha256")
    if (type(before) is not str or re.fullmatch(r"[0-9a-f]{64}", before) is None
            or after != before):
        raise Rejected("DELETE target/control state was not restored exactly")
    unrelated_before = rollback.get("unrelatedControlSha256Before")
    unrelated_after = rollback.get("unrelatedControlSha256After")
    if (type(unrelated_before) is not str
            or re.fullmatch(r"[0-9a-f]{64}", unrelated_before) is None
            or unrelated_after != unrelated_before):
        raise Rejected("unrelated control rows were not restored exactly")
    result["rollback"] = {
        "transaction": "ROLLED_BACK",
        "beforeControlSha256": before,
        "afterControlSha256": after,
        "unrelatedControlSha256Before": unrelated_before,
        "unrelatedControlSha256After": unrelated_after,
    }
    return result


def _nonempty_text(value, label: str) -> None:
    if type(value) is not str or not value:
        raise Rejected("seed receipt is missing " + label)


def _positive_xid(value, label: str) -> None:
    if type(value) is not int or value <= 0:
        raise Rejected("seed receipt has an invalid " + label)


def _sha256_value(value, label: str) -> None:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise Rejected("seed receipt has an invalid " + label)


def validate_runtime_seed_receipt(receipt: dict) -> tuple[str, str]:
    """Check links in production-flow-issued S7 seed identities.

    This validates a receipt only.  It does not create authority rows or accept
    caller-constructed rows as proof that production primitives ran. The
    admitted controller separately binds the receipt to the executed source.
    """
    if type(receipt) is not dict:
        raise Rejected("runtime seed receipt must be an object")
    state = receipt.get("state")
    actual_kind = receipt.get("actualKind")
    if (state, actual_kind) not in SEED_CASES:
        raise Rejected("runtime seed receipt case is outside the required matrix")
    if (receipt.get("issuer") != "actual_runtime_flow_primitives"
            or receipt.get("issuancePath") != "direct_production_flow_primitives"):
        raise Rejected("seed must name the actual production flow primitives")
    _sha256_value(receipt.get("flowSourceSha256"), "flow source digest")
    _sha256_value(receipt.get("authoritySourceSha256"), "authority source digest")
    _sha256_value(receipt.get("flowReceiptSha256"), "flow receipt digest")
    unsigned = {key: value for key, value in receipt.items() if key != "flowReceiptSha256"}
    try:
        encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError) as error:
        raise Rejected("seed receipt is not canonical JSON") from error
    if sha256(encoded) != receipt["flowReceiptSha256"]:
        raise Rejected("seed flow receipt digest does not match its contents")

    approval = receipt.get("approval")
    source = receipt.get("source")
    if type(approval) is not dict or type(source) is not dict:
        raise Rejected("seed receipt has no approval/source identity")
    for field in ("id", "actualId", "serviceAuthorizationId"):
        _nonempty_text(approval.get(field), "approval " + field)
    snapshot = approval.get("snapshot")
    if type(snapshot) is not dict or not set(APPROVAL_SNAPSHOT_FIELDS) <= set(snapshot):
        raise Rejected("seed receipt omits original approval/code snapshots")
    if (snapshot["actualKind"] != actual_kind or snapshot["actualId"] != approval["actualId"]
            or snapshot["serviceAuthorizationId"] != approval["serviceAuthorizationId"]):
        raise Rejected("approval identity differs from its original snapshots")
    _sha256_value(snapshot["codeHashSha256"], "approval code hash")
    for field in ("accountId", "userId", "accountSessionId", "clientId", "state",
                  "codeChallenge", "codeExpiresAt", "approvedAt", "parentDeadline",
                  "serviceDeadline", "actualDeadline", "actualIdleDeadline", "expiresAt"):
        _nonempty_text(snapshot[field], "approval snapshot " + field)
    if type(snapshot["approvalXid"]) is not int or snapshot["approvalXid"] <= 0:
        raise Rejected("approval snapshot has an invalid approval XID")
    if (type(snapshot["serviceVersion"]) is not int or snapshot["serviceVersion"] != 1
            or type(snapshot["consentVersion"]) is not int or snapshot["consentVersion"] != 1
            or type(snapshot["authorizationEpoch"]) is not int
            or snapshot["authorizationEpoch"] <= 0):
        raise Rejected("approval snapshot version or epoch is invalid")

    if actual_kind == "remote_web":
        _nonempty_text(source.get("webAttemptId"), "web attempt identity")
        _nonempty_text(source.get("webCodeId"), "web code identity")
        if (source.get("mobileLoginId") is not None
                or snapshot["webActualId"] != approval["actualId"]
                or snapshot["mobileActualId"] is not None):
            raise Rejected("web approval does not preserve the nullable mobile branch")
    else:
        _nonempty_text(source.get("mobileLoginId"), "mobile login identity")
        if (source.get("webAttemptId") is not None or source.get("webCodeId") is not None
                or snapshot["mobileActualId"] != approval["actualId"]
                or snapshot["webActualId"] is not None):
            raise Rejected("mobile approval does not preserve the nullable web branch")

    consumed_at = approval.get("consumedAt")
    consumed_xid = approval.get("consumedXid")
    artifact_names = ("proof", "service", "actual", "consent", "consumer")
    artifacts = {name: receipt.get(name) for name in artifact_names}
    if state == "live_pending":
        if consumed_at is not None or consumed_xid is not None or any(
                value is not None for value in artifacts.values()):
            raise Rejected("live pending seed has consumed or issued authority artifacts")
        return state, actual_kind

    if consumed_at is None:
        raise Rejected("consumed-live seed has no terminal consumption time")
    _positive_xid(consumed_xid, "consumed XID")
    proof, service, actual, consent, consumer = (artifacts[name] for name in artifact_names)
    if any(type(value) is not dict for value in (proof, service, actual, consent, consumer)):
        raise Rejected("consumed-live seed is missing proof or authority rows")
    if (proof.get("approvalIntentId") != approval["id"]
            or proof.get("consumedAt") != consumed_at
            or proof.get("exchangeXid") != consumed_xid
            or proof.get("proofVersion") != 1):
        raise Rejected("consumed proof does not preserve approval/XID identity")
    if (service.get("id") != approval["serviceAuthorizationId"]
            or actual.get("id") != approval["actualId"]
            or service.get("consumerApprovalId") != approval["id"]
            or actual.get("consumerApprovalId") != approval["id"]
            or service.get("consumerV3BirthXid") != consumed_xid
            or actual.get("consumerV3BirthXid") != consumed_xid):
        raise Rejected("issued principals do not preserve approval/birth XID identity")
    if (service.get("expiresAt") != snapshot["serviceDeadline"]
            or actual.get("expiresAt") != snapshot["actualDeadline"]
            or actual.get("idleExpiresAt") != snapshot["actualIdleDeadline"]):
        raise Rejected("issued principal does not preserve the original deadline snapshots")
    if (consent.get("approvalIntentId") != approval["id"]
            or consent.get("birthXid") != consumed_xid):
        raise Rejected("consent does not preserve approval/birth XID identity")
    consent_snapshot = consent.get("snapshot")
    if type(consent_snapshot) is not dict or not set(CONSENT_SNAPSHOT_FIELDS) <= set(consent_snapshot):
        raise Rejected("consent receipt omits original snapshot ceilings")
    expected_consent = {key: snapshot["approvedAt"] if key == "consentedAt" else snapshot[key]
                        for key in CONSENT_SNAPSHOT_FIELDS if key != "consentedAt" or "approvedAt" in snapshot}
    if any(consent_snapshot[key] != value for key, value in expected_consent.items()):
        raise Rejected("consent does not retain the original approval snapshot")
    if (consumer.get("consentId") != consent.get("id")
            or consumer.get("serviceAuthorizationId") != approval["serviceAuthorizationId"]
            or consumer.get("originKind") != actual_kind
            or consumer.get("originId") != approval["actualId"]):
        raise Rejected("consumer authority row does not link to the issued consent/principal")
    return state, actual_kind


def validate_stage_receipt(receipt: dict | None, *, source_receipt: dict | None = None) -> dict:
    """Report missing S7 obligations; never turn source/plans into stage PASS."""
    missing = list(RECEIPT_REQUIREMENTS)
    validated_captures = {}
    if type(receipt) is dict:
        if receipt.get("sourceReceipt") == source_receipt and source_receipt is not None:
            missing.remove(RECEIPT_REQUIREMENTS[0])
        seeds = receipt.get("seedReceipts")
        if type(seeds) is list:
            try:
                cases = {validate_runtime_seed_receipt(row) for row in seeds}
            except Rejected:
                cases = set()
            if cases == set(SEED_CASES) and len(seeds) == len(SEED_CASES):
                missing.remove(RECEIPT_REQUIREMENTS[1])
        analyze = receipt.get("analyze")
        if (type(analyze) is dict and analyze.get("statement") == "ANALYZE"
                and analyze.get("sqlSha256") == preparation_sql_digests()["analyze"]
                and analyze.get("completed") is True
                and type(analyze.get("tables")) in (list, tuple)
                and set(analyze["tables"]) == set(ANALYZE_TABLES)
                and len(analyze["tables"]) == len(ANALYZE_TABLES)):
            missing.remove(RECEIPT_REQUIREMENTS[2])
        planner = receipt.get("planner")
        settings = planner.get("settings") if type(planner) is dict else None
        if (type(planner) is dict and planner.get("defaultSettingsVerified") is True
                and planner.get("controlOverrides") == []
                and planner.get("sqlSha256") == preparation_sql_digests()["planner_settings"]
                and type(settings) is dict
                and settings.get("enable_seqscan") == "on"
                and settings.get("enable_indexscan") == "on"
                and settings.get("enable_bitmapscan") == "on"):
            missing.remove(RECEIPT_REQUIREMENTS[3])
        plans = receipt.get("lookupPlanCaptures")
        expected_plans = set(ALL_PLAN_SQL)
        if type(plans) is dict and set(plans) == expected_plans:
            for name, capture in plans.items():
                try:
                    validated_captures[name] = validate_plan_capture(
                        name, capture["raw"], captured_sql_sha256=capture["captureSqlSha256"])
                except (KeyError, Rejected, TypeError):
                    validated_captures = {}
                    break
            if len(validated_captures) == len(expected_plans):
                missing.remove(RECEIPT_REQUIREMENTS[4])
        deletes = receipt.get("rollbackDeleteCaptures")
        if type(deletes) is dict and set(deletes) == set(DELETE_SQL):
            for name, capture in deletes.items():
                try:
                    validated_captures["delete_" + name] = validate_delete_capture(
                        name, capture["raw"], captured_sql_sha256=capture["captureSqlSha256"],
                        rollback=capture["rollback"])
                except (KeyError, Rejected, TypeError):
                    validated_captures = {}
                    break
            if all("delete_" + name in validated_captures for name in DELETE_SQL):
                missing.remove(RECEIPT_REQUIREMENTS[5])
                missing.remove(RECEIPT_REQUIREMENTS[6])
        growth = receipt.get("growthComparison")
        if type(growth) is dict:
            baseline = growth.get("baseline")
            grown = growth.get("grown")
        else:
            baseline = grown = None
        if (type(baseline) is dict and type(grown) is dict
                and type(baseline.get("unrelatedRowCount")) is int
                and type(grown.get("unrelatedRowCount")) is int
                and baseline["unrelatedRowCount"] >= 0
                and grown["unrelatedRowCount"] > baseline["unrelatedRowCount"]
                and type(baseline.get("planCaptures")) is dict
                and type(grown.get("planCaptures")) is dict
                and set(baseline["planCaptures"]) == set(PENDING_ABSENCE_SQL)
                and set(grown["planCaptures"]) == set(PENDING_ABSENCE_SQL)):
            growth_valid = True
            for scale, group in (("baseline", baseline), ("grown", grown)):
                for name, capture in group["planCaptures"].items():
                    try:
                        observation = validate_plan_capture(
                            name, capture["raw"], captured_sql_sha256=capture["captureSqlSha256"])
                        if capture.get("captureSha256") != observation["captureSha256"]:
                            raise Rejected("growth plan digest mismatch")
                        validated_captures["growth_" + scale + "_" + name] = observation
                    except (KeyError, Rejected, TypeError):
                        growth_valid = False
                        break
                if not growth_valid:
                    break
            if growth_valid:
            # No size/latency/index threshold is assigned here.  Actual counts,
            # raw plans, and changes remain available for the integrator to review.
                missing.remove(RECEIPT_REQUIREMENTS[7])
    return {
        "status": "NOT_RUN",
        "receiptValidation": "INCOMPLETE" if missing else "STRUCTURALLY_VALID",
        "fullS7Qualified": False,
        "qualification": "NOT_EVALUATED",
        "requiredButMissing": missing,
        "validatedCaptureNames": sorted(validated_captures),
        "captureSqlSha256": sql_digests(),
    }

