"""Build and validate isolated PostgreSQL denial probes for sealed helpers.

This module never connects to PostgreSQL or runs SQL. It builds a fixed plan
for the private fixture controller and validates attempt-bound transcripts.
"""
import json
import re
import uuid


class Rejected(ValueError):
    pass


BODY_OWNER = "lomi_consumer_auth_body_owner"
MIGRATOR = "lomi_migrator"
APP_ROLES = ("lomi_runtime", "lomi_remote_api", "lomi_remote_exchange")
ROLES = (MIGRATOR, *APP_ROLES)
CONNECTION_ROLE_BY_ACTOR = {
    MIGRATOR: MIGRATOR,
    "lomi_runtime": "lomi_runtime",
    "lomi_remote_api": "lomi_remote_api",
    "lomi_remote_exchange": "lomi_remote_exchange",
}

# Keep these signatures and argument names in step with authority-core.candidate.sql.
HELPERS = (
    {
        "signature": "public.lomi_consumer_principal_live_v2(public.consumer_authorization)",
        "name": "lomi_consumer_principal_live_v2",
        "arguments": "c public.consumer_authorization",
    },
    {
        "signature": "public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)",
        "name": "lomi_consumer_scalar_recheck_v2",
        "arguments": (
            "p_account uuid,p_consumer uuid,p_session text,p_class text,"
            "p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea"
        ),
    },
)

OPERATIONS = (
    "replace_noop",
    "alter_security_mode",
    "alter_search_path",
    "alter_owner",
    "rename",
    "drop",
    "drop_cascade",
    "set_role_owner",
    "grant_owner_membership",
    "grant_owner_admin",
)
EXPECTED_SQLSTATE = "42501"
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
_HEX_UUID = re.compile(r"[0-9a-f]{32}")
_RESULT = re.compile(
    rb"CONSUMER_DENIAL_RESULT\|run=([0-9a-f-]{36})"
    rb"\|attempt=([0-9a-f-]{36}:[0-9]{3})"
    rb"\|role=([a-z0-9_]+)\|session_user=([a-z0-9_]+)"
    rb"\|current_user=([a-z0-9_]+)\|rolsuper=(true|false)"
    rb"\|rolcreaterole=(true|false)\|is_superuser=(true|false)"
    rb"\|sqlstate=([0-9A-Z]{5})"
)
_ROLLBACK_ACK = re.compile(
    rb"CONSUMER_DENIAL_ROLLBACK_ACK\|run=([0-9a-f-]{36})"
    rb"\|attempt=([0-9a-f-]{36}:[0-9]{3})\|role=([a-z0-9_]+)"
)


def valid_uuid(value):
    """Accept only canonical lowercase UUID text before using it in identifiers."""
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _sql_literal(value):
    """Quote an internally generated value as a PostgreSQL string literal."""
    return "'" + value.replace("'", "''") + "'"


def _statement(helper, operation, run_uuid, attempt_index, actor):
    name = helper["name"]
    signature = helper["signature"]
    if operation == "replace_noop":
        return (
            f"CREATE OR REPLACE FUNCTION public.{name}({helper['arguments']}) "
            "RETURNS void LANGUAGE plpgsql AS "
            "$consumer_denial_noop$ BEGIN RETURN; END $consumer_denial_noop$"
        )
    if operation == "alter_security_mode":
        return f"ALTER FUNCTION {signature} SECURITY DEFINER"
    if operation == "alter_search_path":
        return f"ALTER FUNCTION {signature} SET search_path TO pg_catalog"
    if operation == "alter_owner":
        return f"ALTER FUNCTION {signature} OWNER TO {MIGRATOR}"
    if operation == "rename":
        name = f"lomi_helper_denial_{attempt_index}_{run_uuid.replace('-', '')}"
        if len(name.encode("ascii")) > 63 or _HEX_UUID.fullmatch(run_uuid.replace("-", "")) is None:
            raise Rejected("rename probe identifier exceeds PostgreSQL bounds")
        return f"ALTER FUNCTION {signature} RENAME TO {name}"
    if operation == "drop":
        return f"DROP FUNCTION {signature}"
    if operation == "drop_cascade":
        return f"DROP FUNCTION {signature} CASCADE"
    if operation == "set_role_owner":
        return f"SET ROLE {BODY_OWNER}"
    if operation == "grant_owner_membership":
        return f"GRANT {BODY_OWNER} TO {actor}"
    if operation == "grant_owner_admin":
        return f"GRANT {BODY_OWNER} TO {actor} WITH ADMIN OPTION"
    raise Rejected("unknown denial operation")


def _wrapped_sql(run_uuid, attempt_id, actor, connection_role, statement):
    # Every actor uses its actual LOGIN connection. Reassert its own session
    # authorization before each attempt, without any operator authority.
    connection_super = "true" if connection_role == "e2_owner" else "false"
    return (
        "BEGIN;\n"
        "DO $consumer_denial_connection$\n"
        "BEGIN\n"
        f"  IF session_user IS DISTINCT FROM {_sql_literal(connection_role)}\n"
        f"     OR current_user IS DISTINCT FROM {_sql_literal(connection_role)}\n"
        f"     OR current_setting('is_superuser')::boolean IS DISTINCT FROM {connection_super}::boolean THEN\n"
        "    RAISE EXCEPTION 'denial probe connection identity mismatch';\n"
        "  END IF;\n"
        "END\n"
        "$consumer_denial_connection$;\n"
        f"SET LOCAL SESSION AUTHORIZATION {_sql_literal(actor)};\n"
        "DO $consumer_denial_attempt$\n"
        "DECLARE observed_sqlstate text := '00000'; role_super boolean; role_create boolean;\n"
        "BEGIN\n"
        f"  IF session_user IS DISTINCT FROM {_sql_literal(actor)}\n"
        f"     OR current_user IS DISTINCT FROM {_sql_literal(actor)}\n"
        "     OR current_setting('is_superuser')::boolean THEN\n"
        "    RAISE EXCEPTION 'denial probe tested identity mismatch';\n"
        "  END IF;\n"
        "  SELECT r.rolsuper, r.rolcreaterole INTO STRICT role_super, role_create\n"
        "    FROM pg_roles r WHERE r.rolname = current_user;\n"
        "  IF role_super OR role_create THEN\n"
        "    RAISE EXCEPTION 'denial probe tested role has elevated attributes';\n"
        "  END IF;\n"
        "  BEGIN\n"
        f"    EXECUTE {_sql_literal(statement)};\n"
        "  EXCEPTION WHEN OTHERS THEN\n"
        "    GET STACKED DIAGNOSTICS observed_sqlstate = RETURNED_SQLSTATE;\n"
        "  END;\n"
        "  RAISE NOTICE 'CONSUMER_DENIAL_RESULT|run=%|attempt=%|role=%|session_user=%|current_user=%|rolsuper=%|rolcreaterole=%|is_superuser=%|sqlstate=%',\n"
        f"    {_sql_literal(run_uuid)}, {_sql_literal(attempt_id)}, {_sql_literal(actor)},\n"
        "    session_user, current_user,\n"
        "    CASE WHEN role_super THEN 'true' ELSE 'false' END,\n"
        "    CASE WHEN role_create THEN 'true' ELSE 'false' END,\n"
        "    CASE WHEN current_setting('is_superuser')::boolean THEN 'true' ELSE 'false' END,\n"
        "    observed_sqlstate;\n"
        "END\n"
        "$consumer_denial_attempt$;\n"
        "ROLLBACK;\n"
        f"SELECT {_sql_literal('CONSUMER_DENIAL_ROLLBACK_ACK|run=' + run_uuid + '|attempt=' + attempt_id + '|role=' + actor)};\n"
    )


def build_attempts(run_uuid):
    """Return the fixed 2-helper × 4-role × 10-operation SQL attempt matrix."""
    if not valid_uuid(run_uuid):
        raise Rejected("canonical run UUID required")
    attempts = []
    for helper in HELPERS:
        for actor in ROLES:
            for operation in OPERATIONS:
                attempt_index = len(attempts)
                attempt_id = f"{run_uuid}:{attempt_index:03d}"
                connection_role = CONNECTION_ROLE_BY_ACTOR[actor]
                statement = _statement(helper, operation, run_uuid, attempt_index, actor)
                attempts.append({
                    "attemptId": attempt_id,
                    "runUuid": run_uuid,
                    "role": actor,
                    "connectionRole": connection_role,
                    "signature": helper["signature"],
                    "operation": operation,
                    "statement": statement,
                    "sql": _wrapped_sql(run_uuid, attempt_id, actor, connection_role, statement),
                })
    return attempts


def _output_bytes(output):
    if type(output) is str:
        try:
            output = output.encode("utf-8", "strict")
        except UnicodeError as error:
            raise Rejected("attempt output is not valid UTF-8") from error
    if type(output) is not bytes:
        raise Rejected("attempt output must be bytes or text")
    return output


def _attempt_transcript(attempt, *, process_return_code, output):
    if type(process_return_code) is not int or process_return_code != 0:
        raise Rejected("denial probe process did not succeed")
    output = _output_bytes(output)
    result_matches = list(_RESULT.finditer(output))
    ack_matches = list(_ROLLBACK_ACK.finditer(output))
    results = [match.groups() for match in result_matches]
    acknowledgements = [match.groups() for match in ack_matches]
    if len(results) != 1 or len(acknowledgements) != 1:
        raise Rejected("attempt output must contain one result and rollback acknowledgement")
    if ack_matches[0].start() <= result_matches[0].end():
        raise Rejected("rollback acknowledgement did not follow the attempt result")
    run_uuid, attempt_id, role, session_user, current_user, superuser, create_role, is_superuser = (
        value.decode("ascii") for value in results[0][:-1]
    )
    sqlstate = results[0][-1].decode("ascii")
    ack_run, ack_attempt, ack_role = (value.decode("ascii") for value in acknowledgements[0])
    if (run_uuid != attempt["runUuid"] or attempt_id != attempt["attemptId"]
            or role != attempt["role"] or ack_run != run_uuid
            or ack_attempt != attempt_id or ack_role != role):
        raise Rejected("attempt transcript belongs to another run, role, or attempt")
    if (session_user != attempt["role"] or current_user != attempt["role"]
            or superuser != "false" or create_role != "false" or is_superuser != "false"):
        raise Rejected("attempt transcript has unexpected identity or role attributes")
    return sqlstate


def _strict_json(raw, label):
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


def _snapshot(capture, signature):
    if type(capture) is not bytes or len(capture) > MAX_CAPTURE_BYTES:
        raise Rejected("function capture missing or over evidence bound")
    matches = []
    for line in capture.splitlines():
        if not line:
            continue
        row = _strict_json(line, "function capture row")
        if type(row) is dict and row.get("kind") == "function" and row.get("signature") == signature:
            matches.append(row)
    if len(matches) != 1:
        raise Rejected("function capture must contain exactly one target signature")
    row = matches[0]
    definition = row.get("definition")
    encoded = row.get("definitionUtf8Hex")
    owner = row.get("owner")
    acl = row.get("acl")
    config = row.get("config")
    security_definer = row.get("securityDefiner")
    if ("config" not in row or type(definition) is not str or type(encoded) is not str
            or re.fullmatch(r"(?:[0-9a-f]{2})*", encoded) is None
            or type(owner) is not str or not owner
            or type(acl) is not list
            or (config is not None and (type(config) is not list or any(type(item) is not str for item in config)))
            or type(security_definer) is not bool):
        raise Rejected("function capture fields are malformed")
    try:
        definition_bytes = definition.encode("utf-8", "strict")
    except UnicodeError as error:
        raise Rejected("function definition is not valid UTF-8") from error
    if definition_bytes.hex() != encoded:
        raise Rejected("function definition UTF-8 bytes do not match capture")
    for entry in acl:
        if (type(entry) is not dict
                or set(entry) != {"grantor", "grantee", "privilege", "grantable"}
                or any(type(entry.get(field)) is not str for field in ("grantor", "grantee", "privilege"))
                or type(entry.get("grantable")) is not bool):
            raise Rejected("expanded function ACL is malformed")
    return {
        "definitionUtf8": definition_bytes,
        "owner": owner,
        "acl": acl,
        "config": config,
        "securityDefiner": security_definer,
    }


def _trusted_attempt(attempt):
    if type(attempt) is not dict or not valid_uuid(attempt.get("runUuid")):
        raise Rejected("attempt plan record is malformed")
    expected = {item["attemptId"]: item for item in build_attempts(attempt["runUuid"])}
    planned = expected.get(attempt.get("attemptId"))
    if planned is None or attempt != planned:
        raise Rejected("attempt does not match fixed denial plan")
    return planned


def validate_attempt_result(
    attempt, *, process_return_code, output, before_capture, after_capture
):
    """Require a bound 42501 transcript, rollback ack, and unchanged helper snapshot."""
    planned = _trusted_attempt(attempt)
    sqlstate = _attempt_transcript(
        planned, process_return_code=process_return_code, output=output
    )
    if sqlstate != EXPECTED_SQLSTATE:
        raise Rejected("attempt did not receive expected permission-denied SQLSTATE")
    before = _snapshot(before_capture, planned["signature"])
    after = _snapshot(after_capture, planned["signature"])
    if before["owner"] != BODY_OWNER or after["owner"] != BODY_OWNER:
        raise Rejected("helper owner differs from sealed body owner")
    if before["securityDefiner"] is not False or after["securityDefiner"] is not False:
        raise Rejected("sealed helper must remain SECURITY INVOKER")
    if before != after:
        raise Rejected("helper definition, owner, config, or expanded ACL drifted")
    return {
        "attemptId": planned["attemptId"],
        "role": planned["role"],
        "connectionRole": planned["connectionRole"],
        "signature": planned["signature"],
        "operation": planned["operation"],
        "sqlstate": sqlstate,
        "catalogUnchanged": True,
        "rollbackAcknowledged": True,
    }


def validate_complete_matrix(run_uuid, outcomes):
    """Validate every planned denial result exactly once and return a compact receipt."""
    attempts = build_attempts(run_uuid)
    if type(outcomes) not in (list, tuple) or len(outcomes) != len(attempts):
        raise Rejected("complete denial attempt matrix required")
    by_id = {attempt["attemptId"]: attempt for attempt in attempts}
    seen = set()
    validated = []
    required = {"attemptId", "processReturnCode", "output", "beforeCapture", "afterCapture"}
    for outcome in outcomes:
        if type(outcome) is not dict or set(outcome) != required:
            raise Rejected("denial outcome record is malformed")
        attempt_id = outcome["attemptId"]
        if attempt_id not in by_id or attempt_id in seen:
            raise Rejected("denial outcome matrix has unknown or duplicate attempt")
        seen.add(attempt_id)
        validated.append(validate_attempt_result(
            by_id[attempt_id], process_return_code=outcome["processReturnCode"],
            output=outcome["output"], before_capture=outcome["beforeCapture"],
            after_capture=outcome["afterCapture"],
        ))
    if seen != set(by_id):
        raise Rejected("denial outcome matrix is incomplete")
    return {
        "attemptCount": len(validated),
        "deniedCount": len(validated),
        "helpers": [helper["signature"] for helper in HELPERS],
        "roles": list(ROLES),
        "operations": list(OPERATIONS),
        "results": validated,
    }
