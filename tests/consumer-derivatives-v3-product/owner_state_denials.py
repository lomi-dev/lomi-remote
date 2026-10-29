"""Source-only plan and evidence checks for Consumer owner-state denials.

This module never connects to PostgreSQL or executes SQL.  It extracts only
the reviewed DO block from each measured operator, then builds a transaction
which applies one private role mutation, catches that operator's exact known
rejection, rolls the whole transaction back, and emits bound evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid


class Rejected(ValueError):
    """The plan or evidence did not satisfy the fixed owner-state contract."""


BODY_OWNER = "lomi_consumer_auth_body_owner"
OPERATOR_ROLE = "e2_owner"
EXPECTED_SQLSTATE = "P0001"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024

OPERATORS = ("helperSeal", "threeRoots")
CASES = (
    "missing_owner_name",
    "login",
    "inherit",
    "superuser",
    "createdb",
    "createrole",
    "replication",
    "bypassrls",
    "role_config",
    "public_schema_create",
    "owner_granted_to_operator",
    "operator_granted_to_owner",
    "owner_granted_to_operator_admin",
    "operator_granted_to_owner_admin",
)

_HELPER_SIGNATURES = (
    "public.lomi_consumer_principal_live_v2(public.consumer_authorization)",
    "public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)",
)
_ROOT_SIGNATURES = (
    "public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)",
    "public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea)",
    "public.lomi_consumer_recipient_recheck(uuid,uuid)",
)
_FIRST_HELPER_SIGNATURE = _HELPER_SIGNATURES[0]
_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_RESULT = re.compile(
    rb"OWNER_STATE_DENIAL_RESULT\|run=([0-9a-f-]{36})"
    rb"\|attempt=([0-9a-f-]{36}:[0-9]{3})"
    rb"\|operator=(helperSeal|threeRoots)"
    rb"\|source_sha256=([0-9a-f]{64})"
    rb"\|case=([a-z0-9_]+)\|session_user=([a-z0-9_]+)"
    rb"\|current_user=([a-z0-9_]+)\|is_superuser=(true|false)"
    rb"\|sqlstate=([0-9A-Z]{5})\|reason=([a-z0-9_]+)"
)
_ROLLBACK_ACK = re.compile(
    rb"OWNER_STATE_DENIAL_ROLLBACK_ACK\|run=([0-9a-f-]{36})"
    rb"\|attempt=([0-9a-f-]{36}:[0-9]{3})"
    rb"\|operator=(helperSeal|threeRoots)"
    rb"\|source_sha256=([0-9a-f]{64})\|case=([a-z0-9_]+)"
)

# Exact preambles keep the accepted source IDs tied to the two reviewed
# candidate shapes.  The transaction wrappers from those files are never
# copied into the attempt: only the DO statement is extracted.
_SOURCE_SHAPES = {
    "helperSeal": {
        "preamble": (
            b"-- REVIEW CANDIDATE ONLY. NULL pins make this operator transition unexecutable.\n"
            b"-- Install core once, seal these two bodies, then validate/switch the three roots.\n"
            b"BEGIN;\n"
        ),
        "tag": "seal_helpers",
        "trailer": b"\nCOMMIT;\n",
        "required": (
            b"unmeasured helper catalog/ACL pins",
            b"unexpected helper definition/owner/ACL: %",
            b"missing sealed body owner",
            b"body owner must be unreachable and retain no broad capability",
        ),
    },
    "threeRoots": {
        "preamble": (
            b"-- REVIEW CANDIDATE ONLY. NULL catalog/ACL pins intentionally prevent execution.\n"
            b"-- Run as the operator after additive 012 + core deployment/sealing, never migrator.\n"
            b"BEGIN;\n"
        ),
        "tag": "operator",
        "trailer": b"\nCOMMIT;\n",
        "required": (
            b"unmeasured catalog/ACL pins: candidate cannot execute",
            b"missing execution owner",
            b"execution owner retains excessive authority: %",
        ),
    },
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _valid_uuid(value) -> bool:
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _strict_json(raw: bytes, label: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise Rejected("invalid " + label) from error


def _embedded_json(raw: bytes, marker: str):
    tag = marker.encode("ascii")
    if raw.count(tag) != 2:
        raise Rejected("operator pin delimiter count drift")
    start = raw.index(tag) + len(tag)
    end = raw.index(tag, start)
    return _strict_json(raw[start:end], "operator pin JSON")


def _is_digest(value) -> bool:
    return type(value) is str and _HEX_256.fullmatch(value) is not None


def _validate_measured_pins(operator_id: str, raw: bytes) -> None:
    if operator_id == "helperSeal":
        rows = _embedded_json(raw, "$helper_pins$")
        if type(rows) is not list or len(rows) != 2:
            raise Rejected("helper operator pin closure drift")
        if tuple(row.get("signature") for row in rows if type(row) is dict) != _HELPER_SIGNATURES:
            raise Rejected("helper operator signatures drift")
        for row in rows:
            if (type(row) is not dict or row.get("old_owner") != "lomi_migrator"
                    or row.get("new_owner") != BODY_OWNER
                    or not _is_digest(row.get("old_catalog_sha256"))
                    or not _is_digest(row.get("new_catalog_sha256"))
                    or type(row.get("old_acl")) is not list
                    or type(row.get("new_acl")) is not list
                    or not _is_digest(row.get("source_sha256"))):
                raise Rejected("helper operator pins are not measured")
        return

    roots = _embedded_json(raw, "$pins$")
    deps = _embedded_json(raw, "$deps$")
    if type(roots) is not list or len(roots) != 3:
        raise Rejected("three-root operator pin closure drift")
    if tuple(row.get("signature") for row in roots if type(row) is dict) != _ROOT_SIGNATURES:
        raise Rejected("three-root operator signatures drift")
    for row in roots:
        if (type(row) is not dict or row.get("owner") != "lomi_remote_inventory_owner"
                or not _is_digest(row.get("old_catalog_sha256"))
                or not _is_digest(row.get("new_catalog_sha256"))
                or type(row.get("old_acl")) is not list
                or type(row.get("new_acl")) is not list
                or not _is_digest(row.get("old_source_sha256"))
                or not _is_digest(row.get("new_source_sha256"))):
            raise Rejected("three-root operator pins are not measured")
    if type(deps) is not list or len(deps) < 1:
        raise Rejected("three-root dependency pin closure drift")
    allowed_owners = {
        "lomi_consumer_auth_body_owner", "lomi_remote_inventory_owner",
        "lomi_remote_pairing_write_owner", "lomi_migrator",
    }
    for row in deps:
        if (type(row) is not dict or row.get("owner") not in allowed_owners
                or not _is_digest(row.get("catalog_sha256"))
                or type(row.get("acl")) is not list):
            raise Rejected("three-root dependency pins are not measured")


def _extract_do_statement(operator_id: str, raw: bytes) -> bytes:
    shape = _SOURCE_SHAPES[operator_id]
    if (type(raw) is not bytes or not raw or len(raw) > MAX_SOURCE_BYTES
            or not raw.startswith(shape["preamble"]) or not raw.endswith(shape["trailer"])):
        raise Rejected("operator source wrapper shape drift")
    try:
        raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Rejected("operator source is not UTF-8") from error
    tag = shape["tag"].encode("ascii")
    delimiter = b"$" + tag + b"$"
    opener = b"DO " + delimiter + b"\n"
    closer = b"END " + delimiter + b";"
    if raw.count(delimiter) != 2 or raw.count(opener) != 1 or raw.count(closer) != 1:
        raise Rejected("operator DO delimiter closure drift")
    start = raw.index(opener)
    end = raw.index(closer, start) + len(closer)
    if raw[end:] != shape["trailer"]:
        raise Rejected("operator source has statements outside its DO block")
    statement = raw[start:end]
    for marker in shape["required"]:
        if raw.count(marker) != 1:
            raise Rejected("operator rejection guard closure drift")
    return statement


def _selected_operator_ids(operator_ids) -> tuple[str, ...]:
    if (type(operator_ids) is not tuple or not operator_ids
            or any(type(item) is not str or item not in OPERATORS for item in operator_ids)
            or len(set(operator_ids)) != len(operator_ids)
            or tuple(item for item in OPERATORS if item in operator_ids) != operator_ids):
        raise Rejected("operator_ids must be a canonical nonempty operator tuple")
    return operator_ids


def _validate_positive_controls(source_digests, controls, selected_operators) -> None:
    if type(controls) is not dict or set(controls) != set(selected_operators):
        raise Rejected("source-bound positive controls must match selected operators")
    required = {"operatorSha256", "allOldTransition", "allNewIdempotent"}
    for operator_id in selected_operators:
        row = controls[operator_id]
        if (type(row) is not dict or set(row) != required
                or row.get("operatorSha256") != source_digests[operator_id]
                or type(row.get("allOldTransition")) is not int
                or row["allOldTransition"] != 0
                or type(row.get("allNewIdempotent")) is not int
                or row["allNewIdempotent"] != 0):
            raise Rejected("positive operator control is missing or source-mismatched")


def _mutation(case: str, attempt_index: int, run_uuid: str) -> str:
    role = BODY_OWNER
    statements = {
        "login": f"ALTER ROLE {role} LOGIN;",
        "inherit": f"ALTER ROLE {role} INHERIT;",
        "superuser": f"ALTER ROLE {role} SUPERUSER;",
        "createdb": f"ALTER ROLE {role} CREATEDB;",
        "createrole": f"ALTER ROLE {role} CREATEROLE;",
        "replication": f"ALTER ROLE {role} REPLICATION;",
        "bypassrls": f"ALTER ROLE {role} BYPASSRLS;",
        "role_config": f"ALTER ROLE {role} SET statement_timeout TO '1s';",
        "public_schema_create": f"GRANT CREATE ON SCHEMA public TO {role};",
        "owner_granted_to_operator": f"GRANT {role} TO {OPERATOR_ROLE};",
        "operator_granted_to_owner": f"GRANT {OPERATOR_ROLE} TO {role};",
        "owner_granted_to_operator_admin": f"GRANT {role} TO {OPERATOR_ROLE} WITH ADMIN OPTION;",
        "operator_granted_to_owner_admin": f"GRANT {OPERATOR_ROLE} TO {role} WITH ADMIN OPTION;",
    }
    if case == "missing_owner_name":
        renamed = f"lomi_owner_state_missing_{attempt_index:03d}_{run_uuid.replace('-', '')}"
        if len(renamed.encode("ascii")) > 63:
            raise Rejected("owner-state rename identifier exceeds PostgreSQL bounds")
        return f"ALTER ROLE {BODY_OWNER} RENAME TO {renamed};"
    try:
        return statements[case]
    except KeyError as error:
        raise Rejected("unsupported owner-state case") from error


def _expected_reason(operator_id: str, case: str) -> tuple[str, str]:
    if case == "missing_owner_name":
        if operator_id == "helperSeal":
            # The seal operator compares each function's owner before its
            # later "missing sealed body owner" check. Since the renamed role
            # still owns both functions, the first exact rejection is the
            # principal helper owner mismatch.
            return (
                "helper_owner_name_mismatch",
                "unexpected helper definition/owner/ACL: " + _FIRST_HELPER_SIGNATURE,
            )
        # The three-root operator checks the exact owner-role count before its
        # dependency catalog pins, so this rename reaches its missing-owner
        # source guard directly.
        return (
            "three_roots_missing_execution_owner",
            "missing execution owner",
        )
    if operator_id == "helperSeal":
        return (
            "helper_owner_policy",
            "body owner must be unreachable and retain no broad capability",
        )
    return (
        "three_roots_owner_policy",
        "execution owner retains excessive authority: " + BODY_OWNER,
    )


def _wrapped_sql(run_uuid: str, attempt_id: str, operator_id: str,
                 source_sha256: str, case: str, mutation: str,
                 expected_reason_code: str, expected_reason: str,
                 operator_statement: bytes) -> str:
    try:
        operator_sql = operator_statement.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Rejected("operator DO block is not UTF-8") from error
    result = (
        "OWNER_STATE_DENIAL_RESULT"
        f"|run={run_uuid}|attempt={attempt_id}|operator={operator_id}"
        f"|source_sha256={source_sha256}|case={case}"
        f"|session_user={OPERATOR_ROLE}|current_user={OPERATOR_ROLE}"
        "|is_superuser=true|sqlstate=%|reason=%"
    )
    ack = (
        "OWNER_STATE_DENIAL_ROLLBACK_ACK"
        f"|run={run_uuid}|attempt={attempt_id}|operator={operator_id}"
        f"|source_sha256={source_sha256}|case={case}"
    )
    return (
        "BEGIN;\n"
        "DO $consumer_owner_state_attempt$\n"
        "DECLARE observed_sqlstate text := '00000'; observed_message text; "
        "reason_code text := 'operator_returned';\n"
        "BEGIN\n"
        f"  IF session_user IS DISTINCT FROM {_sql_literal(OPERATOR_ROLE)}\n"
        f"     OR current_user IS DISTINCT FROM {_sql_literal(OPERATOR_ROLE)}\n"
        "     OR NOT current_setting('is_superuser')::boolean\n"
        "     OR current_setting('server_version_num')::integer <> 180006 THEN\n"
        "    RAISE EXCEPTION 'owner-state operator connection identity mismatch';\n"
        "  END IF;\n"
        f"  EXECUTE {_sql_literal(mutation)};\n"
        "  BEGIN\n"
        f"    EXECUTE {_sql_literal(operator_sql)};\n"
        "  EXCEPTION WHEN OTHERS THEN\n"
        "    GET STACKED DIAGNOSTICS observed_sqlstate = RETURNED_SQLSTATE, "
        "observed_message = MESSAGE_TEXT;\n"
        "    IF observed_sqlstate = 'P0001' AND observed_message IS NOT DISTINCT FROM "
        f"{_sql_literal(expected_reason)} THEN\n"
        f"      reason_code := {_sql_literal(expected_reason_code)};\n"
        "    ELSE\n"
        "      reason_code := 'unexpected_rejection';\n"
        "    END IF;\n"
        "  END;\n"
        f"  RAISE NOTICE {_sql_literal(result)}, observed_sqlstate, reason_code;\n"
        "END\n"
        "$consumer_owner_state_attempt$;\n"
        "ROLLBACK;\n"
        f"SELECT {_sql_literal(ack)};\n"
    )


def build_attempts(run_uuid: str, *, operator_sources: dict,
                   expected_operator_sha256: dict,
                   positive_controls: dict,
                   operator_ids: tuple[str, ...] = OPERATORS) -> list[dict]:
    """Build selected operator denials from both measured source byte sets.

    ``positive_controls`` must be the already-observed S4 all-old and all-new
    success return codes, bound to each selected operator's exact filled
    digest. Source bytes and digest pins are required for both operators even
    when only one operator's phase is selected.
    """
    if not _valid_uuid(run_uuid):
        raise Rejected("canonical run UUID required")
    selected_operators = _selected_operator_ids(operator_ids)
    if (type(operator_sources) is not dict or set(operator_sources) != set(OPERATORS)
            or type(expected_operator_sha256) is not dict
            or set(expected_operator_sha256) != set(OPERATORS)):
        raise Rejected("exact supported operator source IDs required")
    source_digests = {}
    statements = {}
    for operator_id in OPERATORS:
        raw = operator_sources[operator_id]
        if type(raw) is not bytes or not raw or len(raw) > MAX_SOURCE_BYTES:
            raise Rejected("filled operator source missing or over evidence bound")
        measured = _sha256(raw)
        if (not _is_digest(expected_operator_sha256[operator_id])
                or expected_operator_sha256[operator_id] != measured):
            raise Rejected("filled operator source digest mismatch")
        _validate_measured_pins(operator_id, raw)
        statements[operator_id] = _extract_do_statement(operator_id, raw)
        source_digests[operator_id] = measured
    _validate_positive_controls(source_digests, positive_controls, selected_operators)

    attempts = []
    for operator_id in selected_operators:
        operator_offset = OPERATORS.index(operator_id) * len(CASES)
        for case_index, case in enumerate(CASES):
            index = operator_offset + case_index
            attempt_id = f"{run_uuid}:{index:03d}"
            mutation = _mutation(case, index, run_uuid)
            reason_code, reason = _expected_reason(operator_id, case)
            source_sha256 = source_digests[operator_id]
            attempts.append({
                "attemptId": attempt_id,
                "runUuid": run_uuid,
                "operator": operator_id,
                "operatorSha256": source_sha256,
                "case": case,
                "mutation": mutation,
                "expectedSqlstate": EXPECTED_SQLSTATE,
                "expectedReasonCode": reason_code,
                "expectedRejectionReason": reason,
                "sql": _wrapped_sql(
                    run_uuid, attempt_id, operator_id, source_sha256, case,
                    mutation, reason_code, reason, statements[operator_id],
                ),
            })
    return attempts


def _trusted_attempt(attempt, *, operator_sources, expected_operator_sha256,
                     positive_controls, operator_ids):
    if type(attempt) is not dict or not _valid_uuid(attempt.get("runUuid")):
        raise Rejected("attempt plan record is malformed")
    expected = {
        row["attemptId"]: row for row in build_attempts(
            attempt["runUuid"], operator_sources=operator_sources,
            expected_operator_sha256=expected_operator_sha256,
            positive_controls=positive_controls, operator_ids=operator_ids,
        )
    }
    planned = expected.get(attempt.get("attemptId"))
    if planned is None or attempt != planned:
        raise Rejected("attempt does not match fixed owner-state plan")
    return planned


def _output_bytes(output) -> bytes:
    if type(output) is str:
        try:
            output = output.encode("utf-8", "strict")
        except UnicodeError as error:
            raise Rejected("attempt output is not valid UTF-8") from error
    if type(output) is not bytes or len(output) > MAX_OUTPUT_BYTES:
        raise Rejected("attempt output missing or over evidence bound")
    if re.search(rb"(?im)^\s*(?:ERROR|DETAIL|CONTEXT|HINT):", output):
        raise Rejected("attempt output contains an unredacted database diagnostic")
    return output


def _snapshot(capture: bytes, label: str) -> bytes:
    if type(capture) is not bytes or not capture or len(capture) > MAX_CAPTURE_BYTES:
        raise Rejected(label + " catalog/role capture missing or over evidence bound")
    return capture


def _transcript(attempt: dict, *, process_return_code: int, output) -> str:
    if type(process_return_code) is not int or process_return_code != 0:
        raise Rejected("owner-state denial process did not succeed")
    raw = _output_bytes(output)
    result_matches = list(_RESULT.finditer(raw))
    ack_matches = list(_ROLLBACK_ACK.finditer(raw))
    if len(result_matches) != 1 or len(ack_matches) != 1:
        raise Rejected("attempt output must contain one result and rollback acknowledgement")
    if ack_matches[0].start() <= result_matches[0].end():
        raise Rejected("rollback acknowledgement did not follow the attempt result")
    result = tuple(item.decode("ascii") for item in result_matches[0].groups())
    ack = tuple(item.decode("ascii") for item in ack_matches[0].groups())
    (run_uuid, attempt_id, operator_id, source_sha256, case, session_user,
     current_user, is_superuser, sqlstate, reason_code) = result
    if (run_uuid != attempt["runUuid"] or attempt_id != attempt["attemptId"]
            or operator_id != attempt["operator"]
            or source_sha256 != attempt["operatorSha256"] or case != attempt["case"]):
        raise Rejected("attempt transcript belongs to another run, attempt, operator, or source")
    if (session_user != OPERATOR_ROLE or current_user != OPERATOR_ROLE
            or is_superuser != "true"):
        raise Rejected("attempt transcript has unexpected operator identity")
    if sqlstate != attempt["expectedSqlstate"] or reason_code != attempt["expectedReasonCode"]:
        raise Rejected("operator did not produce its exact expected source rejection")
    if ack != (run_uuid, attempt_id, operator_id, source_sha256, case):
        raise Rejected("rollback acknowledgement belongs to another attempt")
    return sqlstate


def validate_attempt_result(
    attempt, *, process_return_code, output, before_capture, after_capture,
    operator_sources, expected_operator_sha256, positive_controls,
    operator_ids: tuple[str, ...] = OPERATORS,
):
    """Require an exact source rejection, post-rollback ack, and byte-equal captures."""
    planned = _trusted_attempt(
        attempt, operator_sources=operator_sources,
        expected_operator_sha256=expected_operator_sha256,
        positive_controls=positive_controls, operator_ids=operator_ids,
    )
    sqlstate = _transcript(
        planned, process_return_code=process_return_code, output=output,
    )
    before = _snapshot(before_capture, "before")
    after = _snapshot(after_capture, "after")
    if before != after:
        raise Rejected("full catalog and role capture changed across owner-state rollback")
    return {
        "attemptId": planned["attemptId"],
        "operator": planned["operator"],
        "operatorSha256": planned["operatorSha256"],
        "case": planned["case"],
        "sqlstate": sqlstate,
        "reasonCode": planned["expectedReasonCode"],
        "expectedRejectionReason": planned["expectedRejectionReason"],
        "catalogAndRolesUnchanged": True,
        "beforeCaptureSha256": _sha256(before),
        "afterCaptureSha256": _sha256(after),
        "rollbackAcknowledged": True,
    }


def validate_complete_matrix(
    run_uuid, outcomes, *, operator_sources, expected_operator_sha256,
    positive_controls, operator_ids: tuple[str, ...] = OPERATORS,
):
    """Validate exactly the selected operator/case outcomes and return evidence."""
    selected_operators = _selected_operator_ids(operator_ids)
    attempts = build_attempts(
        run_uuid, operator_sources=operator_sources,
        expected_operator_sha256=expected_operator_sha256,
        positive_controls=positive_controls, operator_ids=selected_operators,
    )
    if type(outcomes) not in (list, tuple) or len(outcomes) != len(attempts):
        raise Rejected("complete owner-state denial matrix required")
    by_id = {attempt["attemptId"]: attempt for attempt in attempts}
    seen = set()
    validated = {}
    required = {"attemptId", "processReturnCode", "output", "beforeCapture", "afterCapture"}
    for outcome in outcomes:
        if type(outcome) is not dict or set(outcome) != required:
            raise Rejected("owner-state denial outcome record is malformed")
        attempt_id = outcome["attemptId"]
        if attempt_id not in by_id or attempt_id in seen:
            raise Rejected("owner-state denial matrix has unknown or duplicate attempt")
        seen.add(attempt_id)
        validated[attempt_id] = validate_attempt_result(
            by_id[attempt_id], process_return_code=outcome["processReturnCode"],
            output=outcome["output"], before_capture=outcome["beforeCapture"],
            after_capture=outcome["afterCapture"], operator_sources=operator_sources,
            expected_operator_sha256=expected_operator_sha256,
            positive_controls=positive_controls, operator_ids=selected_operators,
        )
    if seen != set(by_id):
        raise Rejected("owner-state denial matrix is incomplete")
    results = [validated[attempt["attemptId"]] for attempt in attempts]
    full_matrix = selected_operators == OPERATORS
    return {
        "attemptCount": len(results),
        "deniedCount": len(results),
        "operators": [
            {"operator": operator_id, "operatorSha256": expected_operator_sha256[operator_id],
             "positiveControlPassed": True}
            for operator_id in selected_operators
        ],
        "cases": list(CASES),
        "casesByOperator": {operator_id: list(CASES) for operator_id in selected_operators},
        "operatorIds": list(selected_operators),
        "matrixScope": "FULL_28" if full_matrix else "OPERATOR_SUBSET",
        "fullOwnerStateDenialMatrixValidated": full_matrix,
        "fullS5Qualified": False,
        "results": results,
        "entireCatalogAndRoleCaptureEqualAfterEveryRollback": True,
    }
