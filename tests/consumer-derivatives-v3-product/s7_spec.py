"""Pure source-locked query specification compiler for Consumer v3 S7.

This module compiles fixed SQL from :mod:`s7_plans` into node-postgres query
objects.  It does not connect to PostgreSQL, invoke a process, or interpolate
fixture values.  The source SQL digests below make an unreviewed template edit
fail closed until this compiler is deliberately updated with it.
"""
from __future__ import annotations

import hashlib
import json
import re

import s7_plans


Rejected = s7_plans.Rejected


SOURCE_HASH_PATHS = (
    "lomi-remote/tests/consumer-derivatives-v3-product/s7_plans.py",
    "lomi-remote/staging/consumer-derivatives-v3-product-successor/inputs/frozen-v3-successor/approval-intent.candidate.sql",
    "lomi-remote/staging/consumer-derivatives-v3-product-successor/inputs/frozen-v3-successor/012-derivative-authority.candidate.sql",
    "auth-app/src/consumer-derivative-flow.ts",
    "auth-app/src/consumer-derivative-authority.ts",
    "auth-app/test/consumer-derivative-populated-runtime.ts",
    "lomi-remote/tests/consumer-derivatives-v3-product/s7_spec.py",
)


# Exact source SQL bytes from s7_plans.sql_digests().  A source change requires
# an explicit review of both its bind mapping and the receipt contract here.
EXPECTED_CAPTURE_SQL_SHA256 = {
    "consent_account": "171c86aa4c685280b7be2b44e264b364d7c00392cdfef244412d667ffb7af48a",
    "consent_mobile": "14021a67da321e95aac122c9120fbae2cf7dd363923ca34d029fc1806e008833",
    "consent_parent": "3297f65b21618536956f946d6973b7dff80bbb50c684ebfa1b8c94fdd3ade5e6",
    "consent_service": "ae511b380df97c503d728fbba3714f7b7da0db3b55cf7a1ad51920ce9eff821d",
    "consent_web": "b75d138ca4b69c0d2d7b402c2eb427da485c4b73da02855f8d6fe583731a624c",
    "delete_account_identity": "a362270abef123db63af17face47884bf63940397c3fb00b35731f908dbf9208",
    "delete_mobile": "5e54d7d52f21f18070d434a8121a429d1bcce7704ccbe7bc736d756ab502351c",
    "delete_service": "dbaa59cbd4635b6329380ae825e5c98cad506f368eb6a7659d56cec539dc3551",
    "delete_session": "62cd69da3d6c6d7f6e829f138fd6fdcef1d2c3a480ae2998c9f79e9c6f7b1f59",
    "delete_web": "dd6a664bb0a8779d70c1e2ffc982d69d3bf371cc48c151b06ef422409cbe8e56",
    "intent_account": "e1df2f4fe34dad80482fea861f4e174463c691566589c1a7ac802924b8298cef",
    "intent_parent": "3f3f603043740feafe4b191cac542ce9362504c472c8a0be6331c4ee042299f0",
    "pending_mobile_absence": "1e0754f9c9dfa1bec83305200718efb45f782618e21d864df55bfb0c69dee133",
    "pending_service_absence": "41b0a38b5c7b6d39a37a62425ed96e4f7a599eede94eaad4e1ed9113f5fa5330",
    "pending_web_absence": "bf5eb014aeb3a6b74be6c7d8ce1d63ff89a71f8ca17621cbb14d94c457bbaf66",
    "source_ttl_mobile": "045469346cca98ec612a7215acc64f5bce74432ce385e4164d4d3dc4b780436d",
    "source_ttl_web": "d956c03b61c7ba85b4e9184a514eec4007e575f673fa2367ff08ab2273bf49d7",
}


EXPECTED_ANALYZE_TABLES = (
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
EXPECTED_ANALYZE_SQL = "\n".join(
    "ANALYZE " + table + ";" for table in EXPECTED_ANALYZE_TABLES
) + "\n"
EXPECTED_PLANNER_SETTINGS_SQL = (
    "SELECT jsonb_build_object("
    "'enable_seqscan', current_setting('enable_seqscan'), "
    "'enable_indexscan', current_setting('enable_indexscan'), "
    "'enable_bitmapscan', current_setting('enable_bitmapscan'))::text;\n"
)


LOOKUP_BINDINGS = {
    "intent_parent": "account_session_id user_id",
    "intent_account": "account_id user_id",
    "consent_parent": "account_session_id user_id",
    "consent_account": "account_id user_id",
    "consent_service": "service_authorization_id user_id account_session_id",
    "consent_web": "web_session_id user_id account_session_id service_authorization_id",
    "consent_mobile": "mobile_session_id user_id account_session_id service_authorization_id",
}
PENDING_BINDINGS = {
    "pending_service_absence": "service_authorization_id approval_id",
    "pending_web_absence": "web_session_id approval_id",
    "pending_mobile_absence": "mobile_session_id approval_id",
}
DELETE_BINDINGS = {
    "session": "account_session_id user_id",
    "account_identity": "account_id user_id",
    "service": "service_authorization_id user_id",
    "web": "web_session_id user_id",
    "mobile": "mobile_session_id user_id",
}
SOURCE_TTL_BINDINGS = {
    "web": "web_attempt_id",
    "mobile": "mobile_login_id",
}

_PSQL_VARIABLE = re.compile(r":'([a-z][a-z0-9_]*)'", re.ASCII)
_POSITIONAL_PARAMETER = re.compile(r"\$(\d+)")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_DELETE_PREFIX = "BEGIN;\n"
_DELETE_SUFFIX = "\nROLLBACK;\n"
_EXPLAIN_PREFIX = "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "
_ORIGIN_KIND_LITERALS = {
    "remote_web": "'remote_web'",
    "mobile": "'mobile'",
}


def _fail(message: str) -> None:
    raise Rejected(message)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_bytes(value: object) -> bytes:
    """Return deterministic compact ASCII JSON bytes for hashing a spec."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise Rejected("query specification is not canonical JSON") from error


def recompute_spec_sha256(spec: dict) -> str:
    """Recompute the canonical specification digest, excluding its own field."""
    if type(spec) is not dict:
        _fail("query specification must be an object")
    unsigned = {
        key: value for key, value in spec.items()
        if key != "querySpecificationSha256"
    }
    return _sha256(canonical_bytes(unsigned))


def _check_source_hashes(source_hashes: dict) -> dict[str, str]:
    if type(source_hashes) is not dict or set(source_hashes) != set(SOURCE_HASH_PATHS):
        _fail("source hash paths do not match the exact S7 source closure")
    checked = {}
    for path in SOURCE_HASH_PATHS:
        digest = source_hashes[path]
        if type(digest) is not str or _HEX_SHA256.fullmatch(digest) is None:
            _fail("source hash is missing or malformed: " + path)
        checked[path] = digest
    return checked


def _assert_source_templates() -> dict[str, str]:
    capture_sql = {
        **s7_plans.LOOKUP_SQL,
        **s7_plans.PENDING_ABSENCE_SQL,
        **{"delete_" + key: value for key, value in s7_plans.DELETE_SQL.items()},
        **{"source_ttl_" + key: value for key, value in s7_plans.SOURCE_TTL_DELETE_SQL.items()},
    }
    digests = {
        name: _sha256(sql.encode("utf-8"))
        for name, sql in sorted(capture_sql.items())
    }
    if digests != EXPECTED_CAPTURE_SQL_SHA256:
        _fail("S7 source SQL templates differ from the reviewed compiler contract")
    if (tuple(s7_plans.ANALYZE_TABLES) != EXPECTED_ANALYZE_TABLES
            or s7_plans.ANALYZE_SQL != EXPECTED_ANALYZE_SQL
            or s7_plans.PLANNER_SETTINGS_SQL != EXPECTED_PLANNER_SETTINGS_SQL):
        _fail("S7 preparation SQL differs from the reviewed compiler contract")
    return digests


def _unwrap_delete(sql: str) -> str:
    """Remove only the exact transaction wrapper used by source DELETE plans."""
    if (type(sql) is not str or not sql.startswith(_DELETE_PREFIX)
            or not sql.endswith(_DELETE_SUFFIX)):
        _fail("S7 DELETE source has a malformed transaction wrapper")
    statement = sql[len(_DELETE_PREFIX):-len(_DELETE_SUFFIX)]
    if ("\n" in statement or "\r" in statement
            or not statement.startswith(_EXPLAIN_PREFIX)
            or statement.count(";") != 1 or not statement.endswith(";")):
        _fail("S7 DELETE wrapper does not contain exactly one EXPLAIN statement")
    return statement


def _adapt_sql(sql: str, variable_bindings: dict[str, str]) -> tuple[str, list[str]]:
    """Adapt psql quoted variables to numbered binds with stable deduplication."""
    if type(sql) is not str or type(variable_bindings) is not dict:
        _fail("invalid S7 SQL adaptation input")
    binding_order: list[str] = []
    binding_positions: dict[str, int] = {}
    seen_variables: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        seen_variables.add(name)
        if name not in variable_bindings:
            _fail("unsupported psql variable in S7 SQL: " + name)
        binding = variable_bindings[name]
        if type(binding) is not str or not binding:
            _fail("malformed S7 fixture binding for psql variable: " + name)
        position = binding_positions.get(binding)
        if position is None:
            position = len(binding_order) + 1
            binding_positions[binding] = position
            binding_order.append(binding)
        return "$" + str(position)

    adapted = _PSQL_VARIABLE.sub(replace, sql)
    if seen_variables != set(variable_bindings):
        _fail("S7 source variables do not match the reviewed bind mapping")
    if re.search(r":'[A-Za-z0-9_]*'", adapted):
        _fail("unsupported quoted psql variable syntax in S7 SQL")
    _check_parameter_positions(adapted, binding_order)
    return adapted, binding_order


def _check_parameter_positions(sql: str, bindings: list[str]) -> None:
    positions = [int(match.group(1)) for match in _POSITIONAL_PARAMETER.finditer(sql)]
    if any(position < 1 or position > len(bindings) for position in positions):
        _fail("S7 SQL has a positional parameter outside its binding list")
    if positions and set(positions) != set(range(1, len(bindings) + 1)):
        _fail("S7 SQL positional parameters do not match its binding list")
    if not positions and bindings:
        _fail("S7 SQL has bindings but no positional parameters")


def _plan_query(
    sql: str,
    source_digest: str,
    variable_bindings: dict[str, str],
    *,
    delete_wrapper: bool = False,
) -> dict:
    source_sql = _unwrap_delete(sql) if delete_wrapper else sql
    adapted, bindings = _adapt_sql(source_sql, variable_bindings)
    if (not adapted.startswith(_EXPLAIN_PREFIX)
            or not adapted.endswith(";")
            or adapted.count(";") != 1
            or re.search(r"\bSET\s+(?:LOCAL\s+)?(?:enable_|plan_cache_mode)", adapted, re.I)):
        _fail("S7 capture is not one natural EXPLAIN statement")
    return {
        "sql": adapted,
        "sourceSqlSha256": source_digest,
        "bindings": bindings,
    }


class _ScalarSql:
    """Build one static scalar SQL statement and its fixture binding list."""

    def __init__(self) -> None:
        self.bindings: list[str] = []
        self.positions: dict[str, int] = {}

    def bind(self, reference: str, cast: str) -> str:
        if type(reference) is not str or not reference or type(cast) is not str:
            _fail("malformed S7 scalar binding")
        position = self.positions.get(reference)
        if position is None:
            position = len(self.bindings) + 1
            self.positions[reference] = position
            self.bindings.append(reference)
        return f"${position}::{cast}"

    def count(self, relation: str, predicates: list[tuple[str, str, str]]) -> dict:
        where = " AND ".join(
            f'{column} = {self.bind(reference, cast)}'
            for column, reference, cast in predicates
        )
        sql = f"SELECT count(*)::int AS value FROM {relation} WHERE {where};"
        _check_parameter_positions(sql, self.bindings)
        return {"sql": sql, "bindings": list(self.bindings), "result": "count"}

    def count_with_origin_kind(
        self,
        predicates: list[tuple[str, str, str]],
        origin_kind: str,
    ) -> dict:
        literal = _ORIGIN_KIND_LITERALS.get(origin_kind)
        if literal is None:
            _fail("unsupported static consumer origin kind")
        where = '"originKind" = ' + literal + " AND " + " AND ".join(
            f'{column} = {self.bind(reference, cast)}'
            for column, reference, cast in predicates
        )
        sql = (
            "SELECT count(*)::int AS value FROM public.consumer_authorization "
            f"WHERE {where};"
        )
        _check_parameter_positions(sql, self.bindings)
        return {"sql": sql, "bindings": list(self.bindings), "result": "count"}

def _entity_count(
    relation: str,
    predicates: list[tuple[str, str, str]],
) -> dict:
    return _ScalarSql().count(relation, predicates)


def _consumer_authorization_count(origin_kind: str, prefix: str) -> dict:
    return _ScalarSql().count_with_origin_kind([
        ('"originId"', prefix + "actual_id", "text"),
        ('"userId"', prefix + "user_id", "text"),
        ('"accountId"', prefix + "account_id", "uuid"),
        ('"accountSessionId"', prefix + "account_session_id", "text"),
    ], origin_kind)


def _delete_count_queries() -> list[dict]:
    expired_web = "expired.remote_web."
    expired_mobile = "expired.mobile."
    counts = [
        _entity_count('public."session"', [
            ('id', expired_web + "account_session_id", "text"),
            ('"userId"', expired_web + "user_id", "text"),
        ]),
        _entity_count("public.remote_account_identity", [
            ('id', expired_web + "account_id", "uuid"),
            ('"userId"', expired_web + "user_id", "text"),
        ]),
        _entity_count("public.remote_session_binding", [
            ('"sessionId"', expired_web + "account_session_id", "text"),
            ('"userId"', expired_web + "user_id", "text"),
            ('"accountId"', expired_web + "account_id", "uuid"),
        ]),
    ]
    for prefix in (expired_web, expired_mobile):
        counts.extend([
            _entity_count("public.consumer_approval_intent", [
                ("id", prefix + "approval_id", "uuid"),
                ('"accountId"', prefix + "account_id", "uuid"),
                ('"userId"', prefix + "user_id", "text"),
                ('"accountSessionId"', prefix + "account_session_id", "text"),
                ('"actualId"', prefix + "actual_id", "text"),
            ]),
            _entity_count("public.consumer_approval_consumed_proof", [
                ('"approvalIntentId"', prefix + "approval_id", "uuid"),
            ]),
            _entity_count("public.consumer_derivative_consent", [
                ('"approvalIntentId"', prefix + "approval_id", "uuid"),
                ('"accountId"', prefix + "account_id", "uuid"),
                ('"userId"', prefix + "user_id", "text"),
                ('"accountSessionId"', prefix + "account_session_id", "text"),
                ('"actualId"', prefix + "actual_id", "text"),
                ('"serviceAuthorizationId"', prefix + "service_authorization_id", "text"),
            ]),
            _consumer_authorization_count(
                "remote_web" if prefix == expired_web else "mobile",
                prefix,
            ),
            _entity_count("public.remote_service_authorization", [
                ("id", prefix + "service_authorization_id", "text"),
                ('"userId"', prefix + "user_id", "text"),
                ('"sourceSessionId"', prefix + "account_session_id", "text"),
            ]),
        ])
    counts.extend([
        _entity_count("public.remote_web_session", [
            ("id", expired_web + "web_session_id", "text"),
            ('"userId"', expired_web + "user_id", "text"),
            ('"sourceSessionId"', expired_web + "account_session_id", "text"),
            ('"authorizationId"', expired_web + "service_authorization_id", "text"),
        ]),
        _entity_count("public.mobile_session", [
            ("id", expired_mobile + "mobile_session_id", "text"),
            ('"userId"', expired_mobile + "user_id", "text"),
            ('"sourceSessionId"', expired_mobile + "account_session_id", "text"),
            ('"authorizationId"', expired_mobile + "service_authorization_id", "text"),
        ]),
    ])
    return counts


def _control_liveness_queries() -> list[dict]:
    return [
        _principal_live_guard("control.remote_web"),
        _principal_live_guard("control.mobile"),
    ]


def _source_ttl_count_queries(kind: str) -> list[dict]:
    if kind == "web":
        return [_entity_count("public.remote_login_attempt", [
            ("id", "source_ttl.remote_web.web_attempt_id", "text"),
        ])]
    if kind == "mobile":
        return [_entity_count("public.mobile_login", [
            ("id", "source_ttl.mobile.mobile_login_id", "text"),
        ])]
    _fail("unknown source-TTL delete target")


def _retained_authority_queries(kind: str) -> dict:
    prefix = "source_ttl.remote_web." if kind == "web" else "source_ttl.mobile."
    origin_kind = "remote_web" if kind == "web" else "mobile"
    proof = _entity_count("public.consumer_approval_consumed_proof", [
        ('"approvalIntentId"', prefix + "approval_id", "uuid"),
    ])
    consent = _entity_count("public.consumer_derivative_consent", [
        ('"approvalIntentId"', prefix + "approval_id", "uuid"),
        ('"actualId"', prefix + "actual_id", "text"),
        ('"serviceAuthorizationId"', prefix + "service_authorization_id", "text"),
    ])
    consumer_authorization = _consumer_authorization_count(origin_kind, prefix)
    return {
        "proof": proof,
        "consent": consent,
        "consumerAuthorization": consumer_authorization,
    }


def _principal_live_guard(fixture_case: str) -> dict:
    supported_cases = {
        "source_ttl.remote_web": "remote_web",
        "source_ttl.mobile": "mobile",
        "control.remote_web": "remote_web",
        "control.mobile": "mobile",
    }
    origin_kind = supported_cases.get(fixture_case)
    if origin_kind is None:
        _fail("unsupported principal-live fixture case")
    prefix = fixture_case + "."
    kind_literal = _ORIGIN_KIND_LITERALS[origin_kind]
    query = _ScalarSql()
    origin_id = query.bind(prefix + "actual_id", "text")
    sql = (
        "WITH guarded AS MATERIALIZED (\n"
        "  SELECT public.lomi_consumer_principal_live_v2(c) AS guard_result\n"
        "  FROM public.consumer_authorization AS c\n"
        f"  WHERE c.\"originKind\" = {kind_literal} AND c.\"originId\" = {origin_id}\n"
        ")\n"
        "SELECT count(*) = 1 AS principal_live FROM guarded;"
    )
    _check_parameter_positions(sql, query.bindings)
    return {"sql": sql, "bindings": query.bindings, "result": "boolean"}


def _compile_unsigned(source_hashes: dict) -> dict:
    hashes = _check_source_hashes(source_hashes)
    source_digests = _assert_source_templates()

    lookups = {}
    for name, source_sql in s7_plans.LOOKUP_SQL.items():
        state = "mobile" if name == "consent_mobile" else "remote_web"
        lookup_bindings = {
            variable: f"seed.consumed_live.{state}.{variable}"
            for variable in LOOKUP_BINDINGS[name].split()
        }
        lookups[name] = _plan_query(
            source_sql,
            source_digests[name],
            lookup_bindings,
        )

    pending_absence = {}
    for name, source_sql in s7_plans.PENDING_ABSENCE_SQL.items():
        state = "mobile" if name == "pending_mobile_absence" else "remote_web"
        variables = PENDING_BINDINGS[name].split()
        pending_absence[name] = _plan_query(
            source_sql,
            source_digests[name],
            {variable: f"seed.live_pending.{state}.{variable}" for variable in variables},
        )

    deletes = {}
    for name, source_sql in s7_plans.DELETE_SQL.items():
        bindings = {
            variable: f"expired.{('mobile' if name == 'mobile' else 'remote_web')}.{variable}"
            for variable in DELETE_BINDINGS[name].split()
        }
        explain_delete = _plan_query(
            source_sql,
            source_digests["delete_" + name],
            bindings,
            delete_wrapper=True,
        )
        deletes[name] = {
            "explainDelete": explain_delete,
            "beforeCounts": _delete_count_queries(),
            "insideTransactionCounts": _delete_count_queries(),
            "unrelatedControlLiveness": _control_liveness_queries(),
            "afterRollbackCounts": _delete_count_queries(),
        }

    source_ttl_deletes = {}
    for name, source_sql in s7_plans.SOURCE_TTL_DELETE_SQL.items():
        prefix = "source_ttl.remote_web." if name == "web" else "source_ttl.mobile."
        variable = SOURCE_TTL_BINDINGS[name]
        source_ttl_deletes[name] = {
            "explainDelete": _plan_query(
                source_sql,
                source_digests["source_ttl_" + name],
                {variable: prefix + variable},
                delete_wrapper=True,
            ),
            "beforeCounts": _source_ttl_count_queries(name),
            "insideTransactionCounts": _source_ttl_count_queries(name),
            "retainedAuthority": _retained_authority_queries(name),
            "principalLiveGuard": _principal_live_guard(
                "source_ttl.remote_web" if name == "web" else "source_ttl.mobile"
            ),
            "unrelatedControlLiveness": _control_liveness_queries(),
            "afterRollbackCounts": _source_ttl_count_queries(name),
        }

    return {
        "sourceHashes": hashes,
        "analyzeSql": s7_plans.ANALYZE_SQL,
        "analyzeTables": list(s7_plans.ANALYZE_TABLES),
        "plannerSettingsSql": s7_plans.PLANNER_SETTINGS_SQL,
        "lookups": lookups,
        "pendingAbsence": pending_absence,
        "deletes": deletes,
        "sourceTtlDeletes": source_ttl_deletes,
    }


def build_spec(source_hashes: dict) -> dict:
    """Compile the exact S7 plan shape and attach its canonical self-digest."""
    spec = _compile_unsigned(source_hashes)
    spec["querySpecificationSha256"] = recompute_spec_sha256(spec)
    validate_spec(spec)
    return spec


def validate_spec(spec: dict) -> bool:
    """Reject any shape, source, binding, SQL, or self-hash drift."""
    if type(spec) is not dict:
        _fail("query specification must be an object")
    expected_top_level = {
        "sourceHashes", "querySpecificationSha256", "analyzeSql", "analyzeTables",
        "plannerSettingsSql", "lookups", "pendingAbsence", "deletes", "sourceTtlDeletes",
    }
    if set(spec) != expected_top_level:
        _fail("query specification has an unsupported shape")
    hashes = _check_source_hashes(spec["sourceHashes"])
    digest = spec["querySpecificationSha256"]
    if type(digest) is not str or _HEX_SHA256.fullmatch(digest) is None:
        _fail("query specification digest is malformed")
    if recompute_spec_sha256(spec) != digest:
        _fail("query specification digest does not match its contents")
    expected = _compile_unsigned(hashes)
    if {key: value for key, value in spec.items() if key != "querySpecificationSha256"} != expected:
        _fail("query specification differs from reviewed S7 SQL and bindings")
    return True

