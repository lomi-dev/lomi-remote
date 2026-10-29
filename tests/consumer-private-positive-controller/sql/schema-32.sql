-- REVIEW CANDIDATE ONLY. Apply/seal with 012 and operator roots as one reviewed rollout.
BEGIN;
CREATE FUNCTION public.lomi_consumer_principal_live_v2(c public.consumer_authorization) RETURNS void
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE stamp timestamptz; p record; a record; d record; k public.consumer_derivative_consent; h record;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 stamp:=clock_timestamp();
 SELECT s."expiresAt" AT TIME ZONE 'UTC' AS expiry,u.status,i."authorizationEpoch" AS epoch,m.kind,b."clientClass" AS class INTO p
 FROM public."session" s JOIN public."user" u ON u.id=s."userId"
 JOIN public.remote_account_identity i ON i."userId"=s."userId" AND i.id=c."accountId"
 JOIN public.session_metadata m ON m."sessionId"=s.id
 JOIN public.remote_session_binding b ON b."sessionId"=s.id AND b."userId"=s."userId" AND b."accountId"=i.id
 WHERE s.id=c."accountSessionId" AND s."userId"=c."userId";
 IF p.status IS DISTINCT FROM 'active' OR p.epoch IS DISTINCT FROM c."authorizationEpoch" OR c.revoked IS DISTINCT FROM false
  OR c."authorizationEpoch" IS NULL OR c."authorizationEpoch"<1 OR c."expiresAt" IS NULL OR c."expiresAt"<=stamp
  OR p.expiry IS NULL OR p.expiry<=stamp OR c."expiresAt">p.expiry OR c."accountSessionId" IS NULL
  OR length(c."accountSessionId") NOT BETWEEN 1 AND 128 OR c."accountSessionId" !~ '^[!-~]+$' THEN
  RAISE EXCEPTION 'consumer principal unavailable' USING ERRCODE='28000'; END IF;
 IF c."originKind"='better_auth' THEN
  IF c."originId" IS DISTINCT FROM c."accountSessionId" OR c."canManageAccount" IS DISTINCT FROM true OR c."consentId" IS NOT NULL
   OR c."serviceAuthorizationId" IS NOT NULL OR c."clientClass" IS NULL OR c."clientClass" NOT IN ('web','desktop')
   OR p.class IS DISTINCT FROM c."clientClass" OR (CASE p.kind WHEN 'browser' THEN 'web' WHEN 'desktop' THEN 'desktop' END) IS DISTINCT FROM c."clientClass" THEN
   RAISE EXCEPTION 'direct consumer principal unavailable' USING ERRCODE='28000'; END IF;
  RETURN;
 END IF;
 IF c."originKind" IS NULL OR c."originKind" NOT IN ('remote_web','mobile') OR c."canManageAccount" IS DISTINCT FROM false
  OR c."clientClass" IS DISTINCT FROM (CASE c."originKind" WHEN 'remote_web' THEN 'web' ELSE 'mobile' END)
  OR p.kind IS DISTINCT FROM 'browser' OR p.class IS DISTINCT FROM 'web' THEN
  RAISE EXCEPTION 'derivative principal unavailable' USING ERRCODE='28000'; END IF;
 SELECT * INTO k FROM public.consumer_derivative_consent WHERE id=c."consentId";
 IF NOT FOUND OR k.revoked OR k."consentVersion"<>1 OR k.scope<>'remote:account:read remote:v3:consumer'
  OR (k."accountId",k."userId",k."accountSessionId",k."actualKind",k."actualId",k."serviceAuthorizationId",k."authorizationEpoch",k."expiresAt") IS DISTINCT FROM
     (c."accountId",c."userId",c."accountSessionId",c."originKind",c."originId",c."serviceAuthorizationId",c."authorizationEpoch",c."expiresAt") THEN
  RAISE EXCEPTION 'exact derivative consent required' USING ERRCODE='28000'; END IF;
 SELECT i.id,i."consumedAt",i."consumedXid",i."approvedAt",i."expiresAt" INTO h FROM public.consumer_approval_intent i
 JOIN public.consumer_approval_consumed_proof p ON p."approvalIntentId"=i.id AND p."consumedAt"=i."consumedAt" AND p."exchangeXid"=i."consumedXid" AND p."proofVersion"=1
 WHERE i.id=k."approvalIntentId";
 IF NOT FOUND OR h."consumedAt" IS NULL OR h."consumedXid" IS DISTINCT FROM k."birthXid"
  OR h."approvedAt" IS DISTINCT FROM k."consentedAt" OR h."expiresAt" IS DISTINCT FROM c."expiresAt" THEN
  RAISE EXCEPTION 'original consumed browser approval required' USING ERRCODE='28000'; END IF;
 SELECT id,"userId","sourceSessionId",version,scope,"expiresAt","revokedAt","consumerV3BirthXid","consumerApprovalId" INTO a FROM public.remote_service_authorization WHERE id=c."serviceAuthorizationId";
 IF c."originKind"='remote_web' THEN
  SELECT "userId","sourceSessionId","authorizationId","expiresAt","idleExpiresAt","revokedAt","consumerV3BirthXid","consumerApprovalId" INTO d FROM public.remote_web_session WHERE id=c."originId";
 ELSE
  SELECT "userId","sourceSessionId","authorizationId","expiresAt","idleExpiresAt","revokedAt","consumerV3BirthXid","consumerApprovalId" INTO d FROM public.mobile_session WHERE id=c."originId";
 END IF;
 IF a.id IS NULL OR a."userId" IS DISTINCT FROM c."userId" OR a."sourceSessionId" IS DISTINCT FROM c."accountSessionId"
  OR a."consumerApprovalId" IS DISTINCT FROM h.id OR d."consumerApprovalId" IS DISTINCT FROM h.id
  OR a."consumerV3BirthXid" IS DISTINCT FROM k."birthXid" OR d."consumerV3BirthXid" IS DISTINCT FROM k."birthXid"
  OR a.version IS DISTINCT FROM 1 OR a.scope IS DISTINCT FROM k.scope OR a."revokedAt" IS NOT NULL
  OR (a."expiresAt" AT TIME ZONE 'UTC')<=stamp OR c."expiresAt"> (a."expiresAt" AT TIME ZONE 'UTC')
  OR d."userId" IS DISTINCT FROM c."userId" OR d."sourceSessionId" IS DISTINCT FROM c."accountSessionId" OR d."authorizationId" IS DISTINCT FROM a.id
  OR d."revokedAt" IS NOT NULL OR (d."expiresAt" AT TIME ZONE 'UTC')<=stamp OR (d."idleExpiresAt" AT TIME ZONE 'UTC')<=stamp
  OR c."expiresAt"> (d."expiresAt" AT TIME ZONE 'UTC') THEN
  RAISE EXCEPTION 'actual derivative authority unavailable' USING ERRCODE='28000'; END IF;
 -- No mobile accessExpiresAt check here. A short access credential expiry does
 -- not end an already established grant while the principal remains live.
END $$;
REVOKE ALL ON FUNCTION public.lomi_consumer_principal_live_v2(public.consumer_authorization) FROM PUBLIC;

CREATE FUNCTION public.lomi_consumer_scalar_recheck_v2(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea)
 RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.consumer_authorization; actual_hash text; access_expiry timestamptz;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF p_account IS NULL OR p_consumer IS NULL OR p_session IS NULL OR p_class IS NULL OR p_epoch IS NULL OR p_expiry_ms IS NULL OR p_manage IS NULL
  OR p_hash IS NULL OR octet_length(p_hash)<>32 THEN RAISE EXCEPTION 'consumer assertion required' USING ERRCODE='28000'; END IF;
 SELECT * INTO c FROM public.consumer_authorization WHERE id=p_consumer;
 IF NOT FOUND OR (c."accountId",c."accountSessionId",c."clientClass",c."authorizationEpoch",(extract(epoch FROM c."expiresAt")*1000)::bigint,c."canManageAccount") IS DISTINCT FROM
   (p_account,p_session,p_class,p_epoch,p_expiry_ms,p_manage) THEN RAISE EXCEPTION 'exact consumer assertion required' USING ERRCODE='28000'; END IF;
 PERFORM public.lomi_consumer_principal_live_v2(c);
 IF c."originKind"='better_auth' THEN
  IF NOT EXISTS(SELECT FROM public."session" WHERE id=c."accountSessionId" AND "userId"=c."userId" AND sha256(convert_to(token,'UTF8'))=p_hash) THEN
   RAISE EXCEPTION 'actual credential required' USING ERRCODE='28000'; END IF;
 ELSE
  IF c."originKind"='remote_web' THEN
   SELECT "tokenHash" INTO actual_hash FROM public.remote_web_session WHERE id=c."originId";
  ELSE
   SELECT "accessHash","accessExpiresAt" AT TIME ZONE 'UTC' INTO actual_hash,access_expiry FROM public.mobile_session WHERE id=c."originId";
   IF access_expiry IS NULL OR access_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'mobile access expired' USING ERRCODE='28000'; END IF;
  END IF;
  -- Existing loginHash uses SHA256 ASCII token bytes, unpadded base64url.
  IF actual_hash IS DISTINCT FROM rtrim(translate(encode(p_hash,'base64'),'+/','-_'),'=') THEN
   RAISE EXCEPTION 'actual derivative credential required' USING ERRCODE='28000'; END IF;
 END IF;
END $$;
REVOKE ALL ON FUNCTION public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea) FROM PUBLIC;

CREATE FUNCTION public.lomi_consumer_assertion_v2_recheck(p public.lomi_consumer_assertion_v2) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.consumer_authorization;
BEGIN
 IF current_user<>'lomi_remote_inventory_owner' THEN RAISE EXCEPTION 'typed assertion unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF p.version IS DISTINCT FROM 2 THEN RAISE EXCEPTION 'assertion version required' USING ERRCODE='28000'; END IF;
 SELECT * INTO c FROM public.consumer_authorization WHERE id=p."consumerAuthorizationId";
 IF NOT FOUND OR (c."originKind",c."originId",c."serviceAuthorizationId",c."consentId") IS DISTINCT FROM
   (p."actualKind",p."actualId",p."serviceAuthorizationId",p."consentId")
  OR (c."originKind"='better_auth' AND p."consentVersion" IS NOT NULL)
  OR (c."originKind"<>'better_auth' AND p."consentVersion" IS DISTINCT FROM 1) THEN
  RAISE EXCEPTION 'exact actual-origin provenance required' USING ERRCODE='28000'; END IF;
 PERFORM public.lomi_consumer_scalar_recheck_v2(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash");
END $$;
REVOKE ALL ON FUNCTION public.lomi_consumer_assertion_v2_recheck(public.lomi_consumer_assertion_v2) FROM PUBLIC;
-- GENERATED 004 guarded extensions below.
CREATE OR REPLACE FUNCTION public.lomi_consumer_require_live(a public.consumer_authorization) RETURNS void
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE account_status text; epoch bigint; session_expiry timestamptz; metadata_kind text; binding_class text;
BEGIN
 IF a."originKind" IN ('remote_web','mobile') THEN
  PERFORM public.lomi_consumer_principal_live_v2(a);
  RETURN;
 END IF;
 SELECT status INTO account_status FROM public."user" WHERE id=a."userId" FOR SHARE;
 SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=a."accountId" AND "userId"=a."userId" FOR SHARE;
 -- Better Auth timestamps are UTC without time zone, independent of caller TZ.
 SELECT "expiresAt" AT TIME ZONE 'UTC' INTO session_expiry FROM public."session" WHERE id=a."accountSessionId" AND "userId"=a."userId" FOR SHARE;
 SELECT kind INTO metadata_kind FROM public.session_metadata WHERE "sessionId"=a."accountSessionId" FOR SHARE;
 -- Binding rows are immutable. The composite FK and locked authorization
 -- serialize their parent cascades without granting UPDATE on server bindings.
 SELECT "clientClass" INTO binding_class FROM public.remote_session_binding WHERE "sessionId"=a."accountSessionId" AND "userId"=a."userId" AND "accountId"=a."accountId";
 IF a.revoked OR a."originKind" IS DISTINCT FROM 'better_auth' OR a."originId" IS DISTINCT FROM a."accountSessionId" OR NOT a."canManageAccount"
  OR account_status IS DISTINCT FROM 'active' OR epoch IS DISTINCT FROM a."authorizationEpoch"
  OR binding_class IS DISTINCT FROM a."clientClass"
  OR (CASE metadata_kind WHEN 'browser' THEN 'web' WHEN 'desktop' THEN 'desktop' ELSE NULL END) IS DISTINCT FROM a."clientClass"
  OR a."clientClass" NOT IN ('web','desktop') OR session_expiry IS NULL
  OR session_expiry<=clock_timestamp() OR a."expiresAt"<=clock_timestamp() OR a."expiresAt">session_expiry THEN
  RAISE EXCEPTION 'consumer requires live direct session and current account authority' USING ERRCODE='23514';
 END IF;
END $$;
CREATE OR REPLACE FUNCTION public.lomi_consumer_authorization_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF TG_OP='INSERT' AND NEW.revoked THEN RAISE EXCEPTION 'consumer must start live' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' AND (NEW."consentId",NEW."serviceAuthorizationId") IS DISTINCT FROM (OLD."consentId",OLD."serviceAuthorizationId") THEN
  RAISE EXCEPTION 'immutable derivative provenance' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (NEW.id,NEW."accountId",NEW."userId",NEW."accountSessionId",NEW."originKind",NEW."originId",NEW."clientClass",NEW."canManageAccount",NEW."authorizationEpoch",NEW."expiresAt") IS DISTINCT FROM
   (OLD.id,OLD."accountId",OLD."userId",OLD."accountSessionId",OLD."originKind",OLD."originId",OLD."clientClass",OLD."canManageAccount",OLD."authorizationEpoch",OLD."expiresAt") OR (OLD.revoked AND NOT NEW.revoked) THEN
   RAISE EXCEPTION 'immutable consumer origin or revocation rollback' USING ERRCODE='23514';
  END IF;
  -- Revocation remains possible after all parent authority has expired.
 ELSE
  PERFORM public.lomi_consumer_require_live(NEW);
 END IF;
 RETURN NEW;
END $$;
-- GENERATED default-deny closure below.
DO $default_deny$
DECLARE role_name text; signature text;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_consumer_principal_live_v2(public.consumer_authorization) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_consumer_assertion_v2_recheck(public.lomi_consumer_assertion_v2) FROM %I',role_name);
  END IF;
 END LOOP;
END $default_deny$;
COMMIT;
