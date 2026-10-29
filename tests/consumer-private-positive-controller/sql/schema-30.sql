-- REVIEW CANDIDATE ONLY. Install before 012 in the gated, reviewed rollout.
-- No endpoint invokes this schema yet. All new objects remain default-deny.
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));

-- Fresh start intent is immutable; old pending requests cannot be upgraded.
ALTER TABLE public.remote_login_attempt ADD COLUMN "consumerV3Requested" boolean NOT NULL DEFAULT false;
ALTER TABLE public.mobile_login ADD COLUMN "consumerV3Requested" boolean NOT NULL DEFAULT false;
CREATE TABLE public.consumer_approval_intent (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 "accountId" uuid NOT NULL, "userId" text NOT NULL, "accountSessionId" text NOT NULL,
 "actualKind" text NOT NULL CHECK ("actualKind" IN ('remote_web','mobile')),
 "actualId" text NOT NULL CHECK (length("actualId") BETWEEN 1 AND 128 AND "actualId" ~ '^[!-~]+$'),
 "webActualId" text, "mobileActualId" text,
 "serviceAuthorizationId" text NOT NULL UNIQUE,
 "clientId" text NOT NULL, "approvalOrigin" text NOT NULL, "targetOrigin" text NOT NULL,
 "redirectUri" text NOT NULL, state text NOT NULL,
 scope text NOT NULL CHECK(scope='remote:account:read remote:v3:consumer'),
 "serviceVersion" integer NOT NULL CHECK("serviceVersion"=1),
 "consentVersion" integer NOT NULL CHECK("consentVersion"=1),
 "authorizationEpoch" bigint NOT NULL CHECK("authorizationEpoch">=1),
 "webAttemptId" text UNIQUE, "webCodeId" text UNIQUE, "mobileLoginId" text UNIQUE,
 "cookieHash" text, "codeHash" text NOT NULL CHECK("codeHash" ~ '^[A-Za-z0-9_-]{43}$'),
 "codeChallenge" text NOT NULL CHECK("codeChallenge" ~ '^[A-Za-z0-9_-]{43}$'),
 -- Legacy source timestamps are UTC without TZ; compare explicitly as UTC.
 "requestExpiresAt" timestamp(3) NOT NULL, "codeExpiresAt" timestamp(3) NOT NULL,
 "approvedAt" timestamptz(3) NOT NULL DEFAULT clock_timestamp(),
 "approvalXid" bigint NOT NULL DEFAULT txid_current(),
 "parentDeadline" timestamptz(3) NOT NULL,
 "serviceDeadline" timestamptz(3) NOT NULL,
 "actualDeadline" timestamptz(3) NOT NULL,
 "actualIdleDeadline" timestamptz(3) NOT NULL,
 "expiresAt" timestamptz(3) NOT NULL,
 "consumedAt" timestamptz(3), "consumedXid" bigint,
 CHECK(("consumedAt" IS NULL)=("consumedXid" IS NULL)),
 CHECK(("actualKind"='remote_web' AND "webActualId" IS NOT NULL AND "webActualId"="actualId" AND "mobileActualId" IS NULL
   AND "webAttemptId" IS NOT NULL AND "webCodeId" IS NOT NULL AND "mobileLoginId" IS NULL AND "cookieHash" IS NOT NULL)
  OR ("actualKind"='mobile' AND "mobileActualId" IS NOT NULL AND "mobileActualId"="actualId" AND "webActualId" IS NULL
   AND "mobileLoginId" IS NOT NULL AND "webAttemptId" IS NULL AND "webCodeId" IS NULL AND "cookieHash" IS NULL)),
 CHECK("expiresAt">"approvedAt" AND "expiresAt"=least("approvedAt"+interval '604800 seconds',"parentDeadline","serviceDeadline","actualDeadline")),
 CHECK("serviceDeadline"="expiresAt" AND "actualDeadline"="expiresAt"),
 CHECK("actualIdleDeadline"=CASE "actualKind" WHEN 'remote_web' THEN least("approvedAt"+interval '43200 seconds',"expiresAt") ELSE "expiresAt" END),
 CHECK(("codeExpiresAt" AT TIME ZONE 'UTC')>"approvedAt" AND ("codeExpiresAt" AT TIME ZONE 'UTC')<=least("approvedAt"+interval '60 seconds',"requestExpiresAt" AT TIME ZONE 'UTC',"parentDeadline")),
 FOREIGN KEY("accountId","userId") REFERENCES public.remote_account_identity(id,"userId") ON DELETE CASCADE ON UPDATE NO ACTION,
 FOREIGN KEY("accountSessionId","userId") REFERENCES public."session"(id,"userId") ON DELETE CASCADE ON UPDATE NO ACTION,
 -- Source IDs/hashes remain immutable evidence, not retention FKs. Live source
 -- ownership/PKCE is checked at approval, consumption, proof INSERT and exchange
 -- commit. An immutable consumed proof permits subsequent ordinary TTL cleanup.
 UNIQUE(id,"consumedAt","consumedXid"),
 UNIQUE("actualKind","actualId"),
 UNIQUE(id,"serviceAuthorizationId","userId","accountSessionId","clientId",scope,"serviceVersion"),
 UNIQUE(id,"webActualId","userId","accountSessionId","serviceAuthorizationId"),
 UNIQUE(id,"mobileActualId","userId","accountSessionId","serviceAuthorizationId"),
 UNIQUE(id,"accountId","userId","accountSessionId","actualKind","actualId","serviceAuthorizationId","authorizationEpoch","approvedAt","parentDeadline","serviceDeadline","actualDeadline","actualIdleDeadline","expiresAt",scope,"consentVersion")
);
CREATE INDEX consumer_approval_intent_parent_idx ON public.consumer_approval_intent("accountSessionId");
CREATE INDEX consumer_approval_intent_account_idx ON public.consumer_approval_intent("accountId");
REVOKE ALL ON public.consumer_approval_intent FROM PUBLIC;
ALTER TABLE public.remote_service_authorization ADD COLUMN "consumerApprovalId" uuid,
 ADD CONSTRAINT derivative_service_approval_exact FOREIGN KEY("consumerApprovalId",id,"userId","sourceSessionId","clientId",scope,version)
 REFERENCES public.consumer_approval_intent(id,"serviceAuthorizationId","userId","accountSessionId","clientId",scope,"serviceVersion") ON DELETE NO ACTION ON UPDATE NO ACTION;
ALTER TABLE public.remote_web_session ADD COLUMN "consumerApprovalId" uuid,
 ADD CONSTRAINT derivative_web_approval_exact FOREIGN KEY("consumerApprovalId",id,"userId","sourceSessionId","authorizationId")
 REFERENCES public.consumer_approval_intent(id,"webActualId","userId","accountSessionId","serviceAuthorizationId") ON DELETE NO ACTION ON UPDATE NO ACTION;
ALTER TABLE public.mobile_session ADD COLUMN "consumerApprovalId" uuid,
 ADD CONSTRAINT derivative_mobile_approval_exact FOREIGN KEY("consumerApprovalId",id,"userId","sourceSessionId","authorizationId")
 REFERENCES public.consumer_approval_intent(id,"mobileActualId","userId","accountSessionId","serviceAuthorizationId") ON DELETE NO ACTION ON UPDATE NO ACTION;

CREATE FUNCTION public.lomi_approval_source_require_v2(h public.consumer_approval_intent,p_consumed boolean) RETURNS void
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE flow record; code_row record;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF h."actualKind"='remote_web' THEN
  SELECT * INTO flow FROM public.remote_login_attempt WHERE id=h."webAttemptId";
  SELECT * INTO code_row FROM public.remote_identity_code WHERE id=h."webCodeId";
  IF flow.id IS NULL OR flow."consumerV3Requested" IS DISTINCT FROM true OR code_row.id IS NULL
   OR (flow."clientId",flow."redirectUri",flow.state,flow."cookieHash",flow."expiresAt") IS DISTINCT FROM
      (h."clientId",h."redirectUri",h.state,h."cookieHash",h."requestExpiresAt")
   OR (code_row."attemptId",code_row."userId",code_row."sourceSessionId",code_row."codeHash",code_row."codeChallenge",code_row."expiresAt") IS DISTINCT FROM
      (h."webAttemptId",h."userId",h."accountSessionId",h."codeHash",h."codeChallenge",h."codeExpiresAt")
   OR h."redirectUri" IS DISTINCT FROM h."targetOrigin"||'/auth/callback'
   OR rtrim(translate(encode(sha256(convert_to(flow.verifier,'UTF8')),'base64'),'+/','-_'),'=') IS DISTINCT FROM h."codeChallenge" THEN
   RAISE EXCEPTION 'exact real Remote web source and PKCE required' USING ERRCODE='23514'; END IF;
  IF (p_consumed AND (h."consumedAt" IS NULL OR (flow."consumedAt" AT TIME ZONE 'UTC') IS DISTINCT FROM h."consumedAt" OR (code_row."consumedAt" AT TIME ZONE 'UTC') IS DISTINCT FROM h."consumedAt"))
   OR (NOT p_consumed AND (flow."consumedAt" IS NOT NULL OR code_row."consumedAt" IS NOT NULL)) THEN
   RAISE EXCEPTION 'web approval/code consumption mismatch' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT * INTO flow FROM public.mobile_login WHERE id=h."mobileLoginId";
  IF flow.id IS NULL OR flow."consumerV3Requested" IS DISTINCT FROM true OR flow."deniedAt" IS NOT NULL
   OR (flow."clientId",flow."redirectUri",flow.state,flow."expiresAt",flow."userId",flow."sourceSessionId",flow."codeHash",flow."codeChallenge",flow."codeExpiresAt") IS DISTINCT FROM
      (h."clientId",h."redirectUri",h.state,h."requestExpiresAt",h."userId",h."accountSessionId",h."codeHash",h."codeChallenge",h."codeExpiresAt")
   OR h."targetOrigin" IS DISTINCT FROM h."redirectUri" THEN
   RAISE EXCEPTION 'exact real mobile source and PKCE required' USING ERRCODE='23514'; END IF;
  IF (p_consumed AND (h."consumedAt" IS NULL OR (flow."consumedAt" AT TIME ZONE 'UTC') IS DISTINCT FROM h."consumedAt"))
   OR (NOT p_consumed AND flow."consumedAt" IS NOT NULL) THEN
   RAISE EXCEPTION 'mobile approval/code consumption mismatch' USING ERRCODE='23514'; END IF;
 END IF;
END $$;
REVOKE ALL ON FUNCTION public.lomi_approval_source_require_v2(public.consumer_approval_intent,boolean) FROM PUBLIC;

CREATE FUNCTION public.lomi_approval_intent_guard_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE stamp timestamptz; p record;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 stamp:=date_trunc('milliseconds',clock_timestamp());
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['consumedAt','consumedXid']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['consumedAt','consumedXid'])
   OR OLD."consumedAt" IS NOT NULL OR NEW."consumedAt" IS NULL THEN
   RAISE EXCEPTION 'immutable approval or terminal consumption' USING ERRCODE='23514'; END IF;
  IF NEW."consumedAt"<NEW."approvedAt" OR NEW."consumedAt">stamp OR NEW."consumedAt"<stamp-interval '5 seconds'
   OR NEW."expiresAt"<=stamp OR (NEW."codeExpiresAt" AT TIME ZONE 'UTC')<=stamp OR (NEW."requestExpiresAt" AT TIME ZONE 'UTC')<=stamp THEN
   RAISE EXCEPTION 'live approval and bounded code required' USING ERRCODE='23514'; END IF;
  NEW."consumedXid":=txid_current();
 ELSE
  IF NEW."consumedAt" IS NOT NULL OR NEW."consumedXid" IS NOT NULL THEN RAISE EXCEPTION 'approval must start unconsumed' USING ERRCODE='23514'; END IF;
  NEW."approvedAt":=stamp; NEW."approvalXid":=txid_current();
 END IF;
 SELECT s."expiresAt" AT TIME ZONE 'UTC' AS expiry,m.kind,b."clientClass",u.status,a."authorizationEpoch" AS epoch INTO p
 FROM public."session" s JOIN public."user" u ON u.id=s."userId"
 JOIN public.remote_account_identity a ON a.id=NEW."accountId" AND a."userId"=s."userId"
 JOIN public.session_metadata m ON m."sessionId"=s.id
 JOIN public.remote_session_binding b ON b."sessionId"=s.id AND b."userId"=s."userId" AND b."accountId"=a.id
 WHERE s.id=NEW."accountSessionId" AND s."userId"=NEW."userId";
 IF p.status IS DISTINCT FROM 'active' OR p.kind IS DISTINCT FROM 'browser' OR p."clientClass" IS DISTINCT FROM 'web' OR p.expiry IS NULL OR p.expiry<=stamp THEN
  RAISE EXCEPTION 'real live approving browser required' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  NEW."authorizationEpoch":=p.epoch; NEW."parentDeadline":=p.expiry;
  NEW."expiresAt":=least(stamp+interval '604800 seconds',p.expiry);
  NEW."serviceDeadline":=NEW."expiresAt"; NEW."actualDeadline":=NEW."expiresAt";
  -- Original web 12h idle policy is liveness, not an irrevocable C hard cap.
  NEW."actualIdleDeadline":=CASE NEW."actualKind" WHEN 'remote_web' THEN least(stamp+interval '43200 seconds',NEW."expiresAt") ELSE NEW."expiresAt" END;
 ELSE
  IF p.epoch IS DISTINCT FROM NEW."authorizationEpoch" OR p.expiry<NEW."expiresAt" THEN
   RAISE EXCEPTION 'current authority cannot satisfy original approval ceilings' USING ERRCODE='23514'; END IF;
 END IF;
 PERFORM public.lomi_approval_source_require_v2(NEW,TG_OP='UPDATE');
 RETURN NEW;
END $$;
CREATE TRIGGER approval_intent_guard_v2 BEFORE INSERT OR UPDATE ON public.consumer_approval_intent FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_intent_guard_v2();
REVOKE ALL ON FUNCTION public.lomi_approval_intent_guard_v2() FROM PUBLIC;

CREATE TABLE public.consumer_approval_consumed_proof (
 "approvalIntentId" uuid PRIMARY KEY,
 "consumedAt" timestamptz(3) NOT NULL,
 "exchangeXid" bigint NOT NULL,
 "proofVersion" integer NOT NULL DEFAULT 1 CHECK("proofVersion"=1),
 FOREIGN KEY("approvalIntentId","consumedAt","exchangeXid") REFERENCES public.consumer_approval_intent(id,"consumedAt","consumedXid") ON DELETE CASCADE ON UPDATE NO ACTION,
 UNIQUE("approvalIntentId","exchangeXid")
);
REVOKE ALL ON public.consumer_approval_consumed_proof FROM PUBLIC;
CREATE FUNCTION public.lomi_approval_consumed_proof_guard_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE h public.consumer_approval_intent; stamp timestamptz;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'consumed handoff proof is immutable' USING ERRCODE='23514'; END IF;
 stamp:=clock_timestamp();
 SELECT * INTO h FROM public.consumer_approval_intent WHERE id=NEW."approvalIntentId";
 IF NOT FOUND OR h."consumedAt" IS NULL OR h."consumedXid" IS DISTINCT FROM txid_current()
  OR h."consumedAt">stamp OR h."consumedAt"<stamp-interval '5 seconds'
  OR (h."codeExpiresAt" AT TIME ZONE 'UTC')<=stamp OR (h."requestExpiresAt" AT TIME ZONE 'UTC')<=stamp OR h."expiresAt"<=stamp THEN
  RAISE EXCEPTION 'proof requires live real-source consumption in this exchange' USING ERRCODE='23514'; END IF;
 PERFORM public.lomi_approval_source_require_v2(h,true);
 NEW."consumedAt":=h."consumedAt"; NEW."exchangeXid":=txid_current(); NEW."proofVersion":=1;
 RETURN NEW;
END $$;
CREATE TRIGGER approval_consumed_proof_guard_v2 BEFORE INSERT OR UPDATE ON public.consumer_approval_consumed_proof FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_consumed_proof_guard_v2();
REVOKE ALL ON FUNCTION public.lomi_approval_consumed_proof_guard_v2() FROM PUBLIC;

CREATE FUNCTION public.lomi_approval_flow_guard_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE pinned boolean;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF TG_TABLE_NAME IN ('remote_login_attempt','mobile_login') THEN
  IF NEW."consumerV3Requested" IS DISTINCT FROM OLD."consumerV3Requested" THEN RAISE EXCEPTION 'fresh request intent cannot be upgraded in place' USING ERRCODE='23514'; END IF;
 END IF;
 SELECT EXISTS(SELECT FROM public.consumer_approval_intent h WHERE
  (TG_TABLE_NAME='remote_login_attempt' AND h."webAttemptId"=OLD.id)
  OR (TG_TABLE_NAME='remote_identity_code' AND h."webCodeId"=OLD.id)
  OR (TG_TABLE_NAME='mobile_login' AND h."mobileLoginId"=OLD.id)) INTO pinned;
 IF NOT pinned THEN RETURN NEW; END IF;
 IF (to_jsonb(NEW)-'consumedAt') IS DISTINCT FROM (to_jsonb(OLD)-'consumedAt')
  OR OLD."consumedAt" IS NOT NULL OR NEW."consumedAt" IS NULL THEN
  RAISE EXCEPTION 'approved flow is immutable except one-time consume' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER approval_remote_attempt_guard_v2 BEFORE UPDATE ON public.remote_login_attempt FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_flow_guard_v2();
CREATE TRIGGER approval_remote_code_guard_v2 BEFORE UPDATE ON public.remote_identity_code FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_flow_guard_v2();
CREATE TRIGGER approval_mobile_flow_guard_v2 BEFORE UPDATE ON public.mobile_login FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_flow_guard_v2();
REVOKE ALL ON FUNCTION public.lomi_approval_flow_guard_v2() FROM PUBLIC;

-- Re-read final rows, rather than the intermediate NEW tuple in a deferred event.
-- The consent relation is created by 012 before any gate can admit approval.
CREATE FUNCTION public.lomi_approval_exchange_complete_v2(p_id uuid) RETURNS void
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE h public.consumer_approval_intent; proof public.consumer_approval_consumed_proof; s record; d record; k record;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO h FROM public.consumer_approval_intent WHERE id=p_id;
 IF NOT FOUND THEN RETURN; END IF; -- parent/account deletion removes authority
 SELECT * INTO proof FROM public.consumer_approval_consumed_proof WHERE "approvalIntentId"=h.id;
 IF h."consumedAt" IS NULL THEN
  IF proof."approvalIntentId" IS NOT NULL OR EXISTS(SELECT FROM public.remote_service_authorization WHERE id=h."serviceAuthorizationId" AND "consumerApprovalId"=h.id)
   OR EXISTS(SELECT FROM public.remote_web_session WHERE id=h."webActualId" AND "consumerApprovalId"=h.id)
   OR EXISTS(SELECT FROM public.mobile_session WHERE id=h."mobileActualId" AND "consumerApprovalId"=h.id)
   OR EXISTS(SELECT FROM public.consumer_derivative_consent WHERE "approvalIntentId"=h.id) THEN RAISE EXCEPTION 'unconsumed approval issued authority' USING ERRCODE='23514'; END IF;
  -- Expired pending intents can never issue; original source TTL cleanup is safe.
  IF (h."codeExpiresAt" AT TIME ZONE 'UTC')<=clock_timestamp() THEN RETURN; END IF;
  PERFORM public.lomi_approval_source_require_v2(h,false);
  RETURN;
 END IF;
 IF proof."approvalIntentId" IS NULL OR proof."proofVersion"<>1 OR proof."consumedAt" IS DISTINCT FROM h."consumedAt" OR proof."exchangeXid" IS DISTINCT FROM h."consumedXid" THEN
  RAISE EXCEPTION 'immutable consumed handoff proof required' USING ERRCODE='23514'; END IF;
 -- Only an earlier committed proof releases source retention. The initial
 -- exchange must still see exact real source rows through deferred commit.
 IF h."consumedXid"<>txid_current() THEN RETURN; END IF;
 PERFORM public.lomi_approval_source_require_v2(h,true);
 SELECT * INTO s FROM public.remote_service_authorization WHERE id=h."serviceAuthorizationId" AND "consumerApprovalId"=h.id;
 IF h."actualKind"='remote_web' THEN
  SELECT * INTO d FROM public.remote_web_session WHERE id=h."actualId" AND "consumerApprovalId"=h.id;
 ELSE
  SELECT * INTO d FROM public.mobile_session WHERE id=h."actualId" AND "consumerApprovalId"=h.id;
 END IF;
 SELECT * INTO k FROM public.consumer_derivative_consent WHERE "approvalIntentId"=h.id;
 IF s.id IS NULL OR d.id IS NULL OR k.id IS NULL OR s."consumerV3BirthXid" IS DISTINCT FROM h."consumedXid"
  OR d."consumerV3BirthXid" IS DISTINCT FROM h."consumedXid" OR k."birthXid" IS DISTINCT FROM h."consumedXid" THEN
  RAISE EXCEPTION 'one exchange must commit exact service/actual/consent together' USING ERRCODE='23514'; END IF;
 -- Initial expiry equality is enforced by birth/consent guards, never resampled.
END $$;
REVOKE ALL ON FUNCTION public.lomi_approval_exchange_complete_v2(uuid) FROM PUBLIC;

-- Ordinary maintenance deletes do not already hold Auth's global lock. Take
-- it before row locks so source TTL cleanup follows the exchange lock order.
CREATE FUNCTION public.lomi_approval_source_delete_lock_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 RETURN NULL;
END $$;
CREATE TRIGGER approval_web_attempt_delete_lock_v2 BEFORE DELETE ON public.remote_login_attempt FOR EACH STATEMENT EXECUTE FUNCTION public.lomi_approval_source_delete_lock_v2();
CREATE TRIGGER approval_web_code_delete_lock_v2 BEFORE DELETE ON public.remote_identity_code FOR EACH STATEMENT EXECUTE FUNCTION public.lomi_approval_source_delete_lock_v2();
CREATE TRIGGER approval_mobile_delete_lock_v2 BEFORE DELETE ON public.mobile_login FOR EACH STATEMENT EXECUTE FUNCTION public.lomi_approval_source_delete_lock_v2();
REVOKE ALL ON FUNCTION public.lomi_approval_source_delete_lock_v2() FROM PUBLIC;

CREATE FUNCTION public.lomi_approval_deferred_guard_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE approval_id uuid; source_id text;
BEGIN
 IF TG_TABLE_NAME='consumer_approval_intent' THEN approval_id:=NEW.id;
 ELSIF TG_TABLE_NAME='consumer_approval_consumed_proof' THEN approval_id:=NEW."approvalIntentId";
 ELSE
  IF TG_OP='DELETE' THEN source_id:=OLD.id; ELSE source_id:=NEW.id; END IF;
  SELECT h.id INTO approval_id FROM public.consumer_approval_intent h WHERE
   (TG_TABLE_NAME='remote_login_attempt' AND h."webAttemptId"=source_id)
   OR (TG_TABLE_NAME='remote_identity_code' AND h."webCodeId"=source_id)
   OR (TG_TABLE_NAME='mobile_login' AND h."mobileLoginId"=source_id);
 END IF;
 IF approval_id IS NOT NULL THEN PERFORM public.lomi_approval_exchange_complete_v2(approval_id); END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER approval_intent_complete_v2 AFTER INSERT OR UPDATE ON public.consumer_approval_intent DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_deferred_guard_v2();
CREATE CONSTRAINT TRIGGER approval_proof_complete_v2 AFTER INSERT ON public.consumer_approval_consumed_proof DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_deferred_guard_v2();
CREATE CONSTRAINT TRIGGER approval_web_attempt_complete_v2 AFTER UPDATE OR DELETE ON public.remote_login_attempt DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_deferred_guard_v2();
CREATE CONSTRAINT TRIGGER approval_web_code_complete_v2 AFTER UPDATE OR DELETE ON public.remote_identity_code DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_deferred_guard_v2();
CREATE CONSTRAINT TRIGGER approval_mobile_complete_v2 AFTER UPDATE OR DELETE ON public.mobile_login DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_approval_deferred_guard_v2();
REVOKE ALL ON FUNCTION public.lomi_approval_deferred_guard_v2() FROM PUBLIC;
-- GENERATED default-deny closure below.
DO $default_deny$
DECLARE role_name text; signature text;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_approval_source_delete_lock_v2() FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_approval_source_require_v2(public.consumer_approval_intent,boolean) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_approval_consumed_proof_guard_v2() FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_approval_intent_guard_v2() FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_approval_flow_guard_v2() FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_approval_exchange_complete_v2(uuid) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_approval_deferred_guard_v2() FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON TABLE public.consumer_approval_intent,public.consumer_approval_consumed_proof FROM %I',role_name);
  END IF;
 END LOOP;
END $default_deny$;
COMMIT;
