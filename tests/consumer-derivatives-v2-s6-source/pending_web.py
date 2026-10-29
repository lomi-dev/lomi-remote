"""Source-only SQL text builder for the synthetic S6 pending web approval case.

This module deliberately has no database or process execution code. The SQL is
an artifact for review and must only be used in an independently authorized
fixture environment.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Mapping


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "staging/consumer-derivatives-v3-successor/approval-intent.candidate.sql"
CANDIDATE_SHA256 = "877e84817034495cfdcca27fc79517cc7932643b9fec36ed0698daea065e13fc"

FIELDS = (
    "user_id", "session_id", "attempt_id", "code_id",
    "cookie_hash", "state", "verifier", "client_id", "target_origin",
    "code_hash",
)
_SAFE = re.compile(r"^[!-~]{1,128}$")
_CODE_HASH = re.compile(r"^[A-Za-z0-9_-]{43}$")


def _literal(value: str) -> str:
    if not isinstance(value, str) or not _SAFE.fullmatch(value):
        raise ValueError("fixture values must be 1-128 printable ASCII characters")
    return "'" + value.replace("'", "''") + "'"


def validate_seed(seed: Mapping[str, str]) -> dict[str, str]:
    if set(seed) != set(FIELDS):
        raise ValueError("seed must contain exactly the documented synthetic fields")
    result = {key: seed[key] for key in FIELDS}
    if result != DEFAULT_SEED:
        raise ValueError("only the fixed S6 synthetic fixture values are accepted")
    for value in result.values():
        _literal(value)
    if result["user_id"] != "s6-user" or not result["session_id"].startswith("s6-session-"):
        raise ValueError("only reserved S6 synthetic identities are accepted")
    if result["attempt_id"] != "s6-attempt" or result["code_id"] != "s6-code":
        raise ValueError("only reserved S6 source identifiers are accepted")
    if result["target_origin"] != "https://s6.invalid":
        raise ValueError("target origin must be the reserved synthetic origin")
    if not _CODE_HASH.fullmatch(result["code_hash"]):
        raise ValueError("synthetic code hash must match the candidate's 43-character format")
    for field in ("cookie_hash", "state"):
        if not _CODE_HASH.fullmatch(result[field]):
            raise ValueError(f"synthetic {field} must be a 43-character base64url value")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", result["verifier"]):
        raise ValueError("synthetic PKCE verifier must be 43-128 base64url characters")
    if result["verifier"] == result["session_id"]:
        raise ValueError("synthetic verifier must be distinct from session id")
    return result


def candidate_source_hash() -> str:
    return hashlib.sha256(CANDIDATE.read_bytes()).hexdigest()


def build_pending_web_sql(
    seed: Mapping[str, str], *, mismatch: bool = False,
    consume_sources_without_proof: bool = False,
    legacy_upgrade: bool = False,
    immutable_snapshots: bool = False,
) -> str:
    """Return one synthetic pending or negative source-lifecycle fixture."""
    if (type(mismatch) is not bool or type(consume_sources_without_proof) is not bool
            or type(legacy_upgrade) is not bool or type(immutable_snapshots) is not bool):
        raise ValueError("fixture mode selectors must be booleans")
    if sum((mismatch, consume_sources_without_proof, legacy_upgrade, immutable_snapshots)) > 1:
        raise ValueError("only one negative fixture mode may be selected")
    s = validate_seed(seed)
    if candidate_source_hash() != CANDIDATE_SHA256:
        raise ValueError("approval-intent candidate source hash changed")
    q = {key: _literal(value) for key, value in s.items()}
    mismatch_client = _literal("s6-mismatched-client") if mismatch else 'a."clientId"'
    request_marker = "false" if legacy_upgrade else "true"
    marker_predicate = "false" if legacy_upgrade else "true"
    legacy_declarations = """  upgrade_rejected boolean := false;
  remint_rejected boolean := false;
  diagnostic text;
""" if legacy_upgrade else ""
    if mismatch:
        intent_insert = f"""  rejected boolean := false;
BEGIN
  BEGIN
    {intent_insert_sql(mismatch_client, q)}
  EXCEPTION WHEN SQLSTATE '23514' THEN
    rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'S6 mismatched binding was accepted'; END IF;
  PERFORM set_config('lomi_s6.mismatch_rejected','true',true);
END $s6_intent$;
SET LOCAL ROLE e2_owner;
DO $s6_assert$
BEGIN
  IF current_setting('lomi_s6.mismatch_rejected') IS DISTINCT FROM 'true'
     OR EXISTS (SELECT FROM public.consumer_approval_intent WHERE id=current_setting('lomi_s6.intent_id')::uuid)
     OR EXISTS (SELECT FROM public.consumer_approval_consumed_proof WHERE "approvalIntentId"=current_setting('lomi_s6.intent_id')::uuid)
     OR EXISTS (SELECT FROM public.remote_service_authorization WHERE id='s6-service')
     OR EXISTS (SELECT FROM public.remote_web_session WHERE id='s6-web-actual')
     OR EXISTS (SELECT FROM public.consumer_derivative_consent WHERE "approvalIntentId"=current_setting('lomi_s6.intent_id')::uuid)
  THEN RAISE EXCEPTION 'S6 mismatch rollback assertion failed'; END IF;
END $s6_assert$;
ROLLBACK;
"""
    elif legacy_upgrade:
        intent_insert = f"""BEGIN
  BEGIN
    UPDATE public.remote_login_attempt SET "consumerV3Requested"=true
      WHERE id={q['attempt_id']};
  EXCEPTION WHEN SQLSTATE '23514' THEN
    GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;
    IF diagnostic IS DISTINCT FROM 'fresh request intent cannot be upgraded in place' THEN RAISE; END IF;
    upgrade_rejected := true;
  END;
  IF NOT upgrade_rejected THEN RAISE EXCEPTION 'S6 legacy request upgrade was accepted'; END IF;
  BEGIN
    {intent_insert_sql(mismatch_client, q, marker_predicate)}
  EXCEPTION WHEN SQLSTATE '23514' THEN
    GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;
    IF diagnostic IS DISTINCT FROM 'exact real Remote web source and PKCE required' THEN RAISE; END IF;
    remint_rejected := true;
  END;
  IF NOT remint_rejected THEN RAISE EXCEPTION 'S6 legacy request remint was accepted'; END IF;
  IF NOT EXISTS (SELECT FROM public.remote_login_attempt WHERE id={q['attempt_id']} AND "consumerV3Requested" IS FALSE)
     OR EXISTS (SELECT FROM public.consumer_approval_intent WHERE id=current_setting('lomi_s6.intent_id')::uuid)
     OR EXISTS (SELECT FROM public.consumer_approval_consumed_proof WHERE "approvalIntentId"=current_setting('lomi_s6.intent_id')::uuid)
     OR EXISTS (SELECT FROM public.remote_service_authorization WHERE id='s6-service')
     OR EXISTS (SELECT FROM public.remote_web_session WHERE id='s6-web-actual')
     OR EXISTS (SELECT FROM public.consumer_derivative_consent WHERE "approvalIntentId"=current_setting('lomi_s6.intent_id')::uuid)
  THEN RAISE EXCEPTION 'S6 legacy upgrade/remint assertion failed'; END IF;
END $s6_intent$;
ROLLBACK;
"""
    elif immutable_snapshots:
        immutable_updates = (
            'id=gen_random_uuid()',
            '"accountId"=\'00000000-0000-4000-8000-000000000001\'::uuid',
            '"userId"=\'s6-other-user\'',
            '"accountSessionId"=\'s6-other-session\'',
            "scope='remote:account:read'",
            '"serviceVersion"="serviceVersion"+1',
            '"consentVersion"="consentVersion"+1',
            '"authorizationEpoch"="authorizationEpoch"+1',
            '"actualKind"=\'mobile\'',
            '"actualId"=\'s6-other-actual\'',
            '"webActualId"=\'s6-other-web\'',
            '"mobileActualId"=\'s6-other-mobile\'',
            '"serviceAuthorizationId"=\'s6-other-service\'',
            '"clientId"=\'s6-other-client\'',
            '"approvalOrigin"=\'https://other.s6.invalid\'',
            '"targetOrigin"=\'https://other.s6.invalid\'',
            '"redirectUri"=\'https://other.s6.invalid/auth/callback\'',
            'state=\'T\'',
            '"webAttemptId"=\'s6-other-attempt\'',
            '"webCodeId"=\'s6-other-code\'',
            '"mobileLoginId"=\'s6-other-mobile-login\'',
            '"cookieHash"=repeat(\'D\',43)',
            '"codeHash"=repeat(\'E\',43)',
            '"codeChallenge"=repeat(\'F\',43)',
            '"requestExpiresAt"="requestExpiresAt"+interval \'1 second\'',
            '"codeExpiresAt"="codeExpiresAt"+interval \'1 second\'',
            '"approvedAt"="approvedAt"+interval \'1 second\'',
            '"approvalXid"="approvalXid"+1',
            '"parentDeadline"="parentDeadline"+interval \'1 second\'',
            '"serviceDeadline"="serviceDeadline"+interval \'1 second\'',
            '"actualDeadline"="actualDeadline"+interval \'1 second\'',
            '"actualIdleDeadline"="actualIdleDeadline"+interval \'1 second\'',
            '"expiresAt"="expiresAt"+interval \'1 second\'',
        )
        mutation_blocks = "\n".join(
            f"""  BEGIN
    UPDATE public.consumer_approval_intent SET {assignment}
      WHERE id=current_setting('lomi_s6.intent_id')::uuid;
    RAISE EXCEPTION 'S6 immutable approval snapshot mutation was accepted';
  EXCEPTION WHEN SQLSTATE '23514' THEN
    GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;
    IF diagnostic IS DISTINCT FROM 'immutable approval or terminal consumption' THEN RAISE; END IF;
  END;"""
            for assignment in immutable_updates
        )
        intent_insert = f"""BEGIN
  {intent_insert_sql(mismatch_client, q)}
END $s6_intent$;
SET LOCAL ROLE e2_owner;
SET CONSTRAINTS approval_intent_complete_v2 IMMEDIATE;
DO $s6_immutable$
DECLARE
  original public.consumer_approval_intent;
  current_row public.consumer_approval_intent;
  diagnostic text;
BEGIN
  SELECT * INTO original FROM public.consumer_approval_intent
    WHERE id=current_setting('lomi_s6.intent_id')::uuid;
  IF original.id IS NULL THEN RAISE EXCEPTION 'S6 pending intent absent'; END IF;
{mutation_blocks}
  SELECT * INTO current_row FROM public.consumer_approval_intent WHERE id=original.id;
  IF (to_jsonb(current_row)-ARRAY['consumedAt','consumedXid']) IS DISTINCT FROM
     (to_jsonb(original)-ARRAY['consumedAt','consumedXid'])
     OR current_row."consumedAt" IS NOT NULL
     OR EXISTS (SELECT FROM public.consumer_approval_consumed_proof WHERE "approvalIntentId"=original.id)
     OR EXISTS (SELECT FROM public.remote_service_authorization WHERE id='s6-service')
     OR EXISTS (SELECT FROM public.remote_web_session WHERE id='s6-web-actual')
     OR EXISTS (SELECT FROM public.consumer_derivative_consent WHERE "approvalIntentId"=original.id)
  THEN RAISE EXCEPTION 'S6 immutable snapshot rollback assertion failed'; END IF;
END $s6_immutable$;
ROLLBACK;
"""
    elif consume_sources_without_proof:
        intent_insert = f"""BEGIN
  {intent_insert_sql(mismatch_client, q)}
END $s6_intent$;
DO $s6_partial$
DECLARE
  consumed_at timestamp(3) := date_trunc('milliseconds',clock_timestamp()) AT TIME ZONE 'UTC';
  rejected boolean := false; diagnostic text;
BEGIN
  UPDATE public.remote_login_attempt SET "consumedAt"=consumed_at WHERE id={q['attempt_id']};
  IF NOT FOUND THEN RAISE EXCEPTION 'S6 synthetic attempt missing'; END IF;
  UPDATE public.remote_identity_code SET "consumedAt"=consumed_at WHERE id={q['code_id']};
  IF NOT FOUND THEN RAISE EXCEPTION 'S6 synthetic code missing'; END IF;
  BEGIN
    SET CONSTRAINTS approval_web_attempt_complete_v2 IMMEDIATE;
  EXCEPTION WHEN SQLSTATE '23514' THEN
    GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;
    IF diagnostic IS DISTINCT FROM 'web approval/code consumption mismatch' THEN RAISE; END IF;
    rejected := true;
  END;
  IF NOT rejected THEN RAISE EXCEPTION 'S6 partial source consumption was accepted'; END IF;
  IF NOT EXISTS (SELECT FROM public.remote_login_attempt WHERE id={q['attempt_id']} AND "consumedAt" IS NOT NULL)
     OR NOT EXISTS (SELECT FROM public.remote_identity_code WHERE id={q['code_id']} AND "consumedAt" IS NOT NULL)
     OR NOT EXISTS (SELECT FROM public.consumer_approval_intent WHERE id=current_setting('lomi_s6.intent_id')::uuid AND "consumedAt" IS NULL)
     OR EXISTS (SELECT FROM public.consumer_approval_consumed_proof WHERE "approvalIntentId"=current_setting('lomi_s6.intent_id')::uuid)
     OR EXISTS (SELECT FROM public.remote_service_authorization WHERE id='s6-service')
     OR EXISTS (SELECT FROM public.remote_web_session WHERE id='s6-web-actual')
     OR EXISTS (SELECT FROM public.consumer_derivative_consent WHERE "approvalIntentId"=current_setting('lomi_s6.intent_id')::uuid)
  THEN RAISE EXCEPTION 'S6 partial-consumption rollback assertion failed'; END IF;
END $s6_partial$;
ROLLBACK;
"""
    else:
        intent_insert = f"""BEGIN
  {intent_insert_sql(mismatch_client, q)}
END $s6_intent$;
SET LOCAL ROLE e2_owner;
SET CONSTRAINTS approval_intent_complete_v2 IMMEDIATE;
DO $s6_assert$
DECLARE iid uuid := current_setting('lomi_s6.intent_id')::uuid;
BEGIN
  IF EXISTS (SELECT FROM public.consumer_approval_consumed_proof WHERE "approvalIntentId"=iid)
     OR EXISTS (SELECT FROM public.remote_service_authorization WHERE id='s6-service')
     OR EXISTS (SELECT FROM public.remote_web_session WHERE id='s6-web-actual')
     OR EXISTS (SELECT FROM public.consumer_derivative_consent WHERE "approvalIntentId"=iid)
  THEN RAISE EXCEPTION 'S6 pending intent issued authority'; END IF;
  IF NOT EXISTS (SELECT FROM public.consumer_approval_intent WHERE id=iid AND "consumedAt" IS NULL)
  THEN RAISE EXCEPTION 'S6 pending intent absent'; END IF;
END $s6_assert$;
COMMIT;
"""
    return f"""-- SOURCE ONLY; synthetic disposable fixture; candidate SHA-256 {CANDIDATE_SHA256}
BEGIN;
SET LOCAL TIME ZONE 'UTC';
SET LOCAL search_path = pg_catalog, public, pg_temp;
SET LOCAL ROLE e2_owner;
DO $s6_seed$
DECLARE
  uid text := {q['user_id']}; sid text := {q['session_id']}; aid uuid := gen_random_uuid();
  expiry timestamptz := date_trunc('milliseconds',clock_timestamp()) + interval '1 hour';
  request_exp timestamp(3); code_exp timestamp(3); stamp timestamp(3);
  intent_id uuid := gen_random_uuid();
  hash_text text := {q['code_hash']}; code_challenge text;
BEGIN
  stamp := (expiry - interval '1 hour') AT TIME ZONE 'UTC';
  request_exp := (stamp + interval '5 minutes')::timestamp(3);
  code_exp := (stamp + interval '30 seconds')::timestamp(3);
  code_challenge := rtrim(translate(encode(sha256(convert_to({q['verifier']},'UTF8')),'base64'),'+/','-_'),'=');
  INSERT INTO public."user" (id,name,email,status,"createdAt","updatedAt")
    VALUES (uid,'S6 synthetic user',uid || '@fixture.invalid','active',stamp,stamp);
  INSERT INTO public."session" (id,"userId",token,"expiresAt","createdAt","updatedAt")
    VALUES (sid,uid,'s6-synthetic-token',expiry AT TIME ZONE 'UTC',stamp,stamp);
  INSERT INTO public.session_metadata ("sessionId",kind) VALUES (sid,'browser');
  INSERT INTO public.remote_account_identity ("userId") VALUES (uid)
    RETURNING id INTO aid;
  INSERT INTO public.remote_session_binding ("sessionId","userId","accountId","clientClass")
    VALUES (sid,uid,aid,'web');
  INSERT INTO public.remote_login_attempt
    (id,"cookieHash",state,verifier,"clientId","redirectUri","expiresAt","consumedAt","consumerV3Requested")
    VALUES ({q['attempt_id']},{q['cookie_hash']},{q['state']},{q['verifier']},{q['client_id']},
      {q['target_origin']} || '/auth/callback',request_exp,NULL,{request_marker});
  INSERT INTO public.remote_identity_code
    (id,"codeHash","attemptId","userId","sourceSessionId","codeChallenge","expiresAt","consumedAt")
    VALUES ({q['code_id']},hash_text,{q['attempt_id']},uid,sid,code_challenge,code_exp,NULL);
  PERFORM set_config('lomi_s6.account_id',aid::text,true);
  PERFORM set_config('lomi_s6.intent_id',intent_id::text,true);
END $s6_seed$;
SET LOCAL ROLE lomi_runtime;
DO $s6_intent$
DECLARE
  intent_id uuid := current_setting('lomi_s6.intent_id')::uuid;
  aid uuid := current_setting('lomi_s6.account_id')::uuid;
{legacy_declarations}
{intent_insert}
"""


def intent_insert_sql(
    mismatch_client: str, q: Mapping[str, str], marker_predicate: str = "true",
) -> str:
    if marker_predicate not in ("true", "false"):
        raise ValueError("request marker predicate must be fixed")
    return f"""INSERT INTO public.consumer_approval_intent
      (id,"accountId","userId","accountSessionId","actualKind","actualId","webActualId",
       "serviceAuthorizationId","clientId","approvalOrigin","targetOrigin","redirectUri",state,
       scope,"serviceVersion","consentVersion","authorizationEpoch","webAttemptId","webCodeId",
       "cookieHash","codeHash","codeChallenge","requestExpiresAt","codeExpiresAt")
    SELECT intent_id,aid,c."userId",c."sourceSessionId",'remote_web','s6-web-actual','s6-web-actual',
       's6-service',{mismatch_client},'https://identity.s6.invalid', {q['target_origin']}, a."redirectUri",a.state,
       'remote:account:read remote:v3:consumer',1,1,1,a.id,c.id,a."cookieHash",c."codeHash",
       c."codeChallenge",a."expiresAt",c."expiresAt"
      FROM public.remote_login_attempt a JOIN public.remote_identity_code c ON c."attemptId"=a.id
     WHERE a.id={q['attempt_id']} AND c.id={q['code_id']}
       AND a."consumerV3Requested" IS {marker_predicate.upper()} AND c."userId"={q['user_id']}
       AND c."sourceSessionId"={q['session_id']};
    IF NOT FOUND THEN RAISE EXCEPTION 'S6 synthetic source seed mismatch'; END IF;"""


DEFAULT_SEED = {
    "user_id": "s6-user", "session_id": "s6-session-fixture",
    "attempt_id": "s6-attempt", "code_id": "s6-code", "cookie_hash": "C" * 43,
    "state": "S" * 43, "verifier": "V" * 43, "client_id": "s6-client",
    "target_origin": "https://s6.invalid", "code_hash": "s6" + "A" * 41,
}
