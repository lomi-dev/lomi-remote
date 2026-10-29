-- Host-only authority foundation. No HTTP route or feature gate is enabled.
-- Creation and PUBLIC revocation are atomic; the operator seals ownership later.
BEGIN;
CREATE TABLE public.host_runtime (
 "hostId" uuid PRIMARY KEY REFERENCES public.host_identity("hostId") ON DELETE CASCADE,
 "authorizationId" uuid NOT NULL REFERENCES public.host_authorization(id) ON DELETE CASCADE,
 "runtimeId" uuid NOT NULL CHECK ("runtimeId" <> '00000000-0000-0000-0000-000000000000'),
 generation bigint NOT NULL CHECK (generation > 0),
 "hostAccessEpoch" bigint NOT NULL CHECK ("hostAccessEpoch" > 0),
 "predecessorGeneration" bigint NOT NULL CHECK ("predecessorGeneration"=generation-1),
 "predecessorEpoch" bigint NOT NULL CHECK ("predecessorEpoch"="hostAccessEpoch"-1),
 "leaseExpiresAt" timestamptz(3) NOT NULL,
 "freshUntil" timestamptz(3) NOT NULL,
 "publicationSeq" bigint NOT NULL DEFAULT 0 CHECK ("publicationSeq">=0),
 workspaces jsonb NOT NULL DEFAULT '[]'::jsonb
);
-- Ephemeral evidence is private even from Auth. Only the sealed execution owner
-- can write it; guards remain SECURITY INVOKER and require that identity first.
CREATE TABLE public.host_runtime_transition (
 "hostId" uuid PRIMARY KEY,
 "accountId" uuid NOT NULL,
 "authorizationId" uuid NOT NULL,
 "oldEpoch" bigint NOT NULL CHECK ("oldEpoch">0),
 "newEpoch" bigint NOT NULL CHECK ("newEpoch"="oldEpoch"+1),
 "oldGeneration" bigint NOT NULL CHECK ("oldGeneration">=0),
 "newGeneration" bigint NOT NULL CHECK ("newGeneration"="oldGeneration"+1),
 "transactionId" bigint NOT NULL
);
CREATE OR REPLACE FUNCTION public.lomi_host_identity_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE e public.host_enrollment; b public.host_bootstrap; epoch bigint; account_status text; session_expiry timestamptz;
BEGIN
 IF TG_OP='UPDATE' AND current_user='lomi_remote_runtime_owner' AND NEW."accessEpoch" IS DISTINCT FROM OLD."accessEpoch" THEN
  IF (to_jsonb(NEW)-'accessEpoch') IS DISTINCT FROM (to_jsonb(OLD)-'accessEpoch') OR NOT EXISTS (
   SELECT FROM public.host_runtime_transition t
   WHERE t."hostId"=OLD."hostId" AND t."accountId"=OLD."accountId"
    AND t."oldEpoch"=OLD."accessEpoch" AND t."newEpoch"=NEW."accessEpoch"
    AND t."transactionId"=txid_current()
    AND t."oldGeneration"=COALESCE((SELECT r.generation FROM public.host_runtime r WHERE r."hostId"=t."hostId"),0)
    AND EXISTS (SELECT FROM public.host_authorization a WHERE a.id=t."authorizationId" AND a."hostId"=t."hostId" AND a."accountId"=t."accountId" AND a.confirmed AND NOT a.revoked AND a."hostAccessEpoch"=t."oldEpoch")
  ) THEN RAISE EXCEPTION 'invalid runtime epoch transition' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' THEN
   IF (NEW."hostId",NEW."accountId",NEW."firstEnrollmentId",NEW."signedHostKey",NEW."initialCommitment",NEW."hostKeyFingerprint") IS DISTINCT FROM
      (OLD."hostId",OLD."accountId",OLD."firstEnrollmentId",OLD."signedHostKey",OLD."initialCommitment",OLD."hostKeyFingerprint") OR
      (NEW."accessEpoch"<>OLD."accessEpoch" AND NEW."accessEpoch"<>OLD."accessEpoch"+1) THEN
     RAISE EXCEPTION 'immutable host identity or invalid epoch advance' USING ERRCODE='23514';
   END IF;
   IF NEW."accessEpoch"<>OLD."accessEpoch" AND EXISTS (SELECT FROM public.host_authorization WHERE "hostId"=OLD."hostId" AND NOT revoked) THEN
     RAISE EXCEPTION 'revoke active family before advancing host epoch' USING ERRCODE='23514';
   END IF;
 ELSE
   SELECT * INTO e FROM public.host_enrollment WHERE id=NEW."firstEnrollmentId" FOR UPDATE;
   IF NOT FOUND OR NOT e.approved OR e.revoked OR e.consumed OR e."expiresAt"<=clock_timestamp() OR NEW."accessEpoch"<>1 OR
      (NEW."hostId",NEW."accountId",NEW."signedHostKey",NEW."initialCommitment",NEW."hostKeyFingerprint") IS DISTINCT FROM
      (e."hostId",e."accountId",e."signedHostKey",e."initialCommitment",e."hostKeyFingerprint") THEN
     RAISE EXCEPTION 'host identity requires exact approved enrollment' USING ERRCODE='23514';
   END IF;
   SELECT u.status INTO account_status FROM public."user" u JOIN public.remote_account_identity a ON a."userId"=u.id WHERE a.id=NEW."accountId" FOR SHARE OF u;
   SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=NEW."accountId" FOR SHARE;
   SELECT * INTO b FROM public.host_bootstrap WHERE id=e."bootstrapId" AND "enrollmentId"=e.id AND "accountId"=e."accountId" FOR UPDATE;
   IF NOT FOUND OR b.consumed OR b.revoked OR account_status IS DISTINCT FROM 'active' OR epoch IS DISTINCT FROM e."approvedEpoch" THEN
     RAISE EXCEPTION 'identity requires current live bootstrap and account' USING ERRCODE='23514';
   END IF;
   SELECT "expiresAt" AT TIME ZONE 'UTC' INTO session_expiry FROM public."session" WHERE id=b."sessionId" FOR SHARE;
   IF NOT FOUND OR session_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'identity bootstrap session expired' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION public.lomi_host_authorization_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE e public.host_enrollment; h public.host_identity; b public.host_bootstrap; epoch bigint; account_status text; session_expiry timestamptz; prior_epoch bigint;
BEGIN
 IF TG_OP='UPDATE' AND current_user='lomi_remote_runtime_owner' AND NEW."hostAccessEpoch" IS DISTINCT FROM OLD."hostAccessEpoch" THEN
  IF (to_jsonb(NEW)-'hostAccessEpoch') IS DISTINCT FROM (to_jsonb(OLD)-'hostAccessEpoch') OR NOT EXISTS (
   SELECT FROM public.host_runtime_transition t
   WHERE t."hostId"=OLD."hostId" AND t."accountId"=OLD."accountId"
    AND t."oldEpoch"=OLD."hostAccessEpoch" AND t."newEpoch"=NEW."hostAccessEpoch"
    AND t."transactionId"=txid_current()
    AND t."oldGeneration"=COALESCE((SELECT r.generation FROM public.host_runtime r WHERE r."hostId"=t."hostId"),0)
    AND t."authorizationId"=OLD.id AND OLD.confirmed AND NOT OLD.revoked
  ) THEN RAISE EXCEPTION 'invalid runtime epoch transition' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' THEN
   IF (NEW.id,NEW."enrollmentId",NEW."hostId",NEW."accountId",NEW."approvedAccountEpoch",NEW."hostAccessEpoch",NEW."clientClass",NEW."createdAt") IS DISTINCT FROM
      (OLD.id,OLD."enrollmentId",OLD."hostId",OLD."accountId",OLD."approvedAccountEpoch",OLD."hostAccessEpoch",OLD."clientClass",OLD."createdAt") OR
      (OLD.revoked AND NEW IS DISTINCT FROM OLD) OR (OLD.confirmed AND NOT NEW.confirmed) OR
      (NEW.rotation<>OLD.rotation AND NEW.rotation<>OLD.rotation+1) OR
      (NEW.rotation=OLD.rotation AND (NEW."accessHash",NEW."accessExpiresAt",NEW."idleExpiresAt") IS DISTINCT FROM (OLD."accessHash",OLD."accessExpiresAt",OLD."idleExpiresAt")) THEN
     RAISE EXCEPTION 'immutable family or invalid transition' USING ERRCODE='23514';
   END IF;
   -- Revoke must remain available even after suspension, expiry or epoch fencing.
   IF NEW.rotation=OLD.rotation THEN RETURN NEW; END IF;
   IF NEW.revoked OR NOT EXISTS (SELECT FROM public.host_refresh_credential WHERE "authorizationId"=OLD.id AND rotation=OLD.rotation AND "consumedOperationId" IS NOT NULL) THEN
     RAISE EXCEPTION 'rotation requires consumed current credential' USING ERRCODE='23514';
   END IF;
 ELSE
   IF NEW.rotation<>0 OR NEW.confirmed OR NEW.revoked THEN RAISE EXCEPTION 'family must start unconfirmed at rotation zero' USING ERRCODE='23514'; END IF;
 END IF;
 SELECT u.status INTO account_status FROM public."user" u JOIN public.remote_account_identity a ON a."userId"=u.id WHERE a.id=NEW."accountId" FOR SHARE OF u;
 SELECT "authorizationEpoch" INTO epoch FROM public.remote_account_identity WHERE id=NEW."accountId" FOR SHARE;
 SELECT * INTO h FROM public.host_identity WHERE "hostId"=NEW."hostId" FOR UPDATE;
 IF NOT FOUND OR account_status IS DISTINCT FROM 'active' OR epoch IS DISTINCT FROM NEW."approvedAccountEpoch" OR
    (NEW."accountId",NEW."hostAccessEpoch") IS DISTINCT FROM (h."accountId",h."accessEpoch") OR NEW."accessExpiresAt"<=clock_timestamp() OR NEW."idleExpiresAt"<=clock_timestamp() OR
    (TG_OP='UPDATE' AND OLD."idleExpiresAt"<=clock_timestamp()) THEN
   RAISE EXCEPTION 'family requires live account and host epochs' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
   SELECT * INTO e FROM public.host_enrollment WHERE id=NEW."enrollmentId" FOR UPDATE;
   IF NOT FOUND OR NOT e.approved OR e.revoked OR e.consumed OR e."expiresAt"<=clock_timestamp() OR
      (NEW."hostId",NEW."accountId",NEW."approvedAccountEpoch",h."signedHostKey",h."initialCommitment",h."hostKeyFingerprint") IS DISTINCT FROM
      (e."hostId",e."accountId",e."approvedEpoch",e."signedHostKey",e."initialCommitment",e."hostKeyFingerprint") THEN
     RAISE EXCEPTION 'family requires exact live approved enrollment' USING ERRCODE='23514';
   END IF;
   SELECT * INTO b FROM public.host_bootstrap WHERE id=e."bootstrapId" AND "enrollmentId"=e.id AND "accountId"=e."accountId" FOR UPDATE;
   IF NOT FOUND OR b.consumed OR b.revoked THEN RAISE EXCEPTION 'family requires exact live bootstrap' USING ERRCODE='23514'; END IF;
   SELECT "expiresAt" AT TIME ZONE 'UTC' INTO session_expiry FROM public."session" WHERE id=b."sessionId" FOR SHARE;
   IF NOT FOUND OR session_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'bootstrap session expired' USING ERRCODE='23514'; END IF;
   SELECT max("hostAccessEpoch") INTO prior_epoch FROM public.host_authorization WHERE "hostId"=NEW."hostId";
   IF (prior_epoch IS NULL AND (NEW."hostAccessEpoch"<>1 OR NEW."enrollmentId"<>h."firstEnrollmentId")) OR
      (prior_epoch IS NOT NULL AND NEW."hostAccessEpoch"<=prior_epoch) THEN
     RAISE EXCEPTION 'new family requires next host epoch' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END $$;

-- No secrets are returned. This helper is private; each public entry point takes
-- the same global lock and authenticates again inside its transaction.
CREATE FUNCTION public.lomi_host_runtime_authority(p_host uuid,p_hash bytea)
 RETURNS TABLE("hostId" uuid,"accountId" uuid,"authorizationId" uuid,"hostAccessEpoch" bigint,"accessExpiresAt" timestamptz,"idleExpiresAt" timestamptz)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_runtime_owner' THEN RAISE EXCEPTION 'runtime authority unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF p_host IS NULL OR p_host='00000000-0000-0000-0000-000000000000' OR p_hash IS NULL OR octet_length(p_hash)<>32 THEN
  RAISE EXCEPTION 'host authority required' USING ERRCODE='28000';
 END IF;
 RETURN QUERY SELECT h."hostId",h."accountId",a.id,h."accessEpoch",a."accessExpiresAt",a."idleExpiresAt"
 FROM public.host_identity h JOIN public.host_authorization a ON a."hostId"=h."hostId" AND a."accountId"=h."accountId"
 JOIN public.remote_account_identity r ON r.id=h."accountId" JOIN public."user" u ON u.id=r."userId"
 WHERE h."hostId"=p_host AND a."accessHash"=p_hash AND NOT a.revoked AND a.confirmed
  AND h."finalizedIdentity" IS NOT NULL AND a."clientClass"='host' AND u.status='active'
  AND a."approvedAccountEpoch"=r."authorizationEpoch" AND a."hostAccessEpoch"=h."accessEpoch"
  AND a."accessExpiresAt">clock_timestamp() AND a."idleExpiresAt">clock_timestamp()
;
 IF NOT FOUND THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
END $$;
CREATE FUNCTION public.lomi_host_access_lookup(p_host uuid,p_hash bytea)
 RETURNS TABLE("hostId" uuid,"accountId" uuid,"authorizationId" uuid,"hostAccessEpoch" bigint,"accessExpiresAt" timestamptz,"idleExpiresAt" timestamptz)
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT * FROM public.lomi_host_runtime_authority(p_host,p_hash)
$$;
CREATE FUNCTION public.lomi_host_runtime_get(p_host uuid,p_hash bytea)
 RETURNS TABLE("hostId" uuid,"hostAccessEpoch" bigint,"runtimeGeneration" bigint,"runtimeId" uuid,"publicationSeq" bigint,"leaseRemainingMs" bigint,"freshnessRemainingMs" bigint)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE a record; r public.host_runtime; live boolean; stamp timestamptz;
BEGIN
 SELECT * INTO STRICT a FROM public.lomi_host_runtime_authority(p_host,p_hash);
 SELECT * INTO r FROM public.host_runtime t WHERE t."hostId"=p_host;
 stamp:=clock_timestamp();
 live:=r."hostId" IS NOT NULL AND r."authorizationId"=a."authorizationId" AND r."hostAccessEpoch"=a."hostAccessEpoch" AND r."leaseExpiresAt">stamp;
 RETURN QUERY SELECT p_host,a."hostAccessEpoch",COALESCE(r.generation,0),CASE WHEN live THEN r."runtimeId" END,
  CASE WHEN live THEN r."publicationSeq" ELSE 0::bigint END,
  CASE WHEN live THEN greatest(0,floor(extract(epoch FROM (r."leaseExpiresAt"-stamp))*1000)::bigint) ELSE 0::bigint END,
  CASE WHEN live THEN greatest(0,floor(extract(epoch FROM (least(r."freshUntil",r."leaseExpiresAt")-stamp))*1000)::bigint) ELSE 0::bigint END;
END $$;
CREATE FUNCTION public.lomi_host_runtime_claim(p_host uuid,p_hash bytea,p_runtime uuid,p_generation bigint,p_epoch bigint)
 RETURNS TABLE("hostId" uuid,"hostAccessEpoch" bigint,"runtimeGeneration" bigint,"runtimeId" uuid,"publicationSeq" bigint,"leaseRemainingMs" bigint,"freshnessRemainingMs" bigint)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE a record; r public.host_runtime; gen bigint; stamp timestamptz;
BEGIN
 SELECT * INTO STRICT a FROM public.lomi_host_runtime_authority(p_host,p_hash);
 IF p_runtime IS NULL OR p_runtime='00000000-0000-0000-0000-000000000000' OR p_generation IS NULL OR p_generation<0 OR p_epoch IS NULL OR p_epoch<1 THEN
  RAISE EXCEPTION 'invalid runtime binding' USING ERRCODE='22023'; END IF;
 SELECT * INTO r FROM public.host_runtime t WHERE t."hostId"=p_host FOR UPDATE;
 stamp:=clock_timestamp(); gen:=COALESCE(r.generation,0);
 IF r."hostId" IS NOT NULL AND r."leaseExpiresAt">stamp AND r."authorizationId"=a."authorizationId" AND r."hostAccessEpoch"=a."hostAccessEpoch" THEN
  IF r."runtimeId"=p_runtime AND r."predecessorGeneration"=p_generation AND p_epoch IN (r."predecessorEpoch",a."hostAccessEpoch") THEN
   RETURN QUERY SELECT * FROM public.lomi_host_runtime_get(p_host,p_hash); RETURN;
  END IF;
  RAISE EXCEPTION 'HOST_BUSY' USING ERRCODE='LR001';
 END IF;
 IF p_generation<>gen OR p_epoch<>a."hostAccessEpoch" OR gen=9223372036854775807 OR p_epoch=9223372036854775807 THEN
  RAISE EXCEPTION 'runtime compare and swap failed' USING ERRCODE='40001'; END IF;
 INSERT INTO public.host_runtime_transition VALUES(p_host,a."accountId",a."authorizationId",p_epoch,p_epoch+1,gen,gen+1,txid_current());
 UPDATE public.host_identity h SET "accessEpoch"=p_epoch+1 WHERE h."hostId"=p_host AND h."accessEpoch"=p_epoch;
 IF NOT FOUND THEN RAISE EXCEPTION 'runtime epoch transition failed'; END IF;
 UPDATE public.host_authorization f SET "hostAccessEpoch"=p_epoch+1 WHERE f.id=a."authorizationId" AND f."hostAccessEpoch"=p_epoch;
 IF NOT FOUND THEN RAISE EXCEPTION 'runtime epoch transition failed'; END IF;
 INSERT INTO public.host_runtime AS t VALUES(p_host,a."authorizationId",p_runtime,gen+1,p_epoch+1,gen,p_epoch,stamp+interval '30 seconds',stamp+interval '5 seconds',0,'[]')
 ON CONFLICT ON CONSTRAINT host_runtime_pkey DO UPDATE SET "authorizationId"=EXCLUDED."authorizationId","runtimeId"=EXCLUDED."runtimeId",generation=EXCLUDED.generation,
 "hostAccessEpoch"=EXCLUDED."hostAccessEpoch","predecessorGeneration"=EXCLUDED."predecessorGeneration","predecessorEpoch"=EXCLUDED."predecessorEpoch",
 "leaseExpiresAt"=EXCLUDED."leaseExpiresAt","freshUntil"=EXCLUDED."freshUntil","publicationSeq"=0,workspaces='[]';
 IF NOT EXISTS (SELECT FROM public.host_identity h JOIN public.host_authorization f ON f."hostId"=h."hostId" JOIN public.host_runtime t ON t."hostId"=h."hostId"
  WHERE h."hostId"=p_host AND h."accessEpoch"=p_epoch+1 AND f.id=a."authorizationId" AND f."accountId"=a."accountId" AND f."hostAccessEpoch"=h."accessEpoch"
   AND t."authorizationId"=f.id AND t.generation=gen+1 AND t."hostAccessEpoch"=h."accessEpoch") THEN RAISE EXCEPTION 'runtime epoch postcondition failed'; END IF;
 DELETE FROM public.host_runtime_transition t WHERE t."hostId"=p_host AND t."transactionId"=txid_current();
 RETURN QUERY SELECT * FROM public.lomi_host_runtime_get(p_host,p_hash);
END $$;
CREATE FUNCTION public.lomi_host_runtime_heartbeat(p_host uuid,p_hash bytea,p_runtime uuid,p_generation bigint,p_epoch bigint)
 RETURNS TABLE("hostId" uuid,"hostAccessEpoch" bigint,"runtimeGeneration" bigint,"runtimeId" uuid,"publicationSeq" bigint,"leaseRemainingMs" bigint,"freshnessRemainingMs" bigint)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE a record; stamp timestamptz;
BEGIN
 SELECT * INTO STRICT a FROM public.lomi_host_runtime_authority(p_host,p_hash); stamp:=clock_timestamp();
 UPDATE public.host_runtime t SET "leaseExpiresAt"=stamp+interval '30 seconds',"freshUntil"=stamp+interval '5 seconds'
 WHERE t."hostId"=p_host AND t."authorizationId"=a."authorizationId" AND t."runtimeId"=p_runtime AND t.generation=p_generation
  AND t."hostAccessEpoch"=p_epoch AND p_epoch=a."hostAccessEpoch" AND t."leaseExpiresAt">stamp;
 IF NOT FOUND THEN RAISE EXCEPTION 'runtime binding required' USING ERRCODE='40001'; END IF;
 RETURN QUERY SELECT * FROM public.lomi_host_runtime_get(p_host,p_hash);
END $$;
-- Routing IDs only, in the canonical PublishedWorkspace/PublishedTerminal form.
CREATE FUNCTION public.lomi_host_runtime_publication_valid(p_workspaces jsonb) RETURNS boolean
 LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE w jsonb; t jsonb; v text; work_ids uuid[]:='{}'; pane_ids uuid[]:='{}'; session_ids uuid[]:='{}'; id uuid;
BEGIN
 IF p_workspaces IS NULL OR jsonb_typeof(p_workspaces)<>'array' OR jsonb_array_length(p_workspaces)>256 THEN RETURN false; END IF;
 FOR w IN SELECT value FROM jsonb_array_elements(p_workspaces) LOOP
  IF jsonb_typeof(w)<>'object' OR NOT w ?& ARRAY['workspaceId','workspaceEpoch','terminals'] OR w-ARRAY['workspaceId','workspaceEpoch','terminals']<>'{}' OR jsonb_typeof(w->'terminals')<>'array' THEN RETURN false; END IF;
  FOREACH v IN ARRAY ARRAY['workspaceId','workspaceEpoch'] LOOP
   IF jsonb_typeof(w->v)<>'string' OR (w->>v)!~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR (w->>v)::uuid='00000000-0000-0000-0000-000000000000' THEN RETURN false; END IF;
  END LOOP;
  id:=(w->>'workspaceId')::uuid; IF id=ANY(work_ids) THEN RETURN false; END IF; work_ids:=array_append(work_ids,id);
  IF cardinality(pane_ids)+jsonb_array_length(w->'terminals')>4096 THEN RETURN false; END IF;
  FOR t IN SELECT value FROM jsonb_array_elements(w->'terminals') LOOP
   IF jsonb_typeof(t)<>'object' OR NOT t ?& ARRAY['paneId','sessionId','sessionEpoch'] OR t-ARRAY['paneId','sessionId','sessionEpoch']<>'{}' THEN RETURN false; END IF;
   FOREACH v IN ARRAY ARRAY['paneId','sessionId','sessionEpoch'] LOOP
    IF jsonb_typeof(t->v)<>'string' OR (t->>v)!~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR (t->>v)::uuid='00000000-0000-0000-0000-000000000000' THEN RETURN false; END IF;
   END LOOP;
   id:=(t->>'paneId')::uuid; IF id=ANY(pane_ids) THEN RETURN false; END IF; pane_ids:=array_append(pane_ids,id);
   id:=(t->>'sessionId')::uuid; IF id=ANY(session_ids) THEN RETURN false; END IF; session_ids:=array_append(session_ids,id);
  END LOOP;
 END LOOP;
 RETURN true;
EXCEPTION WHEN invalid_text_representation THEN RETURN false;
END $$;
ALTER TABLE public.host_runtime ADD CONSTRAINT host_runtime_publication_wire CHECK (public.lomi_host_runtime_publication_valid(workspaces));
CREATE FUNCTION public.lomi_host_runtime_publish(p_host uuid,p_hash bytea,p_runtime uuid,p_generation bigint,p_epoch bigint,p_expected bigint,p_next bigint,p_workspaces jsonb)
 RETURNS TABLE("hostId" uuid,"hostAccessEpoch" bigint,"runtimeGeneration" bigint,"runtimeId" uuid,"publicationSeq" bigint,"leaseRemainingMs" bigint,"freshnessRemainingMs" bigint)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE a record;
BEGIN
 SELECT * INTO STRICT a FROM public.lomi_host_runtime_authority(p_host,p_hash);
 IF p_expected IS NULL OR p_next IS NULL OR p_expected<0 OR p_expected=9223372036854775807 OR p_next<>p_expected+1 OR NOT public.lomi_host_runtime_publication_valid(p_workspaces) THEN
  RAISE EXCEPTION 'invalid runtime publication' USING ERRCODE='22023'; END IF;
 UPDATE public.host_runtime t SET "publicationSeq"=p_next,workspaces=p_workspaces
 WHERE t."hostId"=p_host AND t."authorizationId"=a."authorizationId" AND t."runtimeId"=p_runtime AND t.generation=p_generation
  AND t."hostAccessEpoch"=p_epoch AND p_epoch=a."hostAccessEpoch" AND t."leaseExpiresAt">clock_timestamp() AND t."publicationSeq"=p_expected;
 IF NOT FOUND THEN RAISE EXCEPTION 'runtime publication compare and swap failed' USING ERRCODE='40001'; END IF;
 RETURN QUERY SELECT * FROM public.lomi_host_runtime_get(p_host,p_hash);
END $$;
REVOKE ALL ON TABLE public.host_runtime,public.host_runtime_transition FROM PUBLIC;
REVOKE ALL ON FUNCTION public.lomi_host_runtime_authority(uuid,bytea),public.lomi_host_access_lookup(uuid,bytea),public.lomi_host_runtime_get(uuid,bytea),
 public.lomi_host_runtime_claim(uuid,bytea,uuid,bigint,bigint),public.lomi_host_runtime_heartbeat(uuid,bytea,uuid,bigint,bigint),
 public.lomi_host_runtime_publication_valid(jsonb),public.lomi_host_runtime_publish(uuid,bytea,uuid,bigint,bigint,bigint,bigint,jsonb) FROM PUBLIC;
-- Existing deployment default privileges may grant Auth every new table.
DO $seal$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON public.host_runtime,public.host_runtime_transition FROM %I',role_name);
  END IF;
 END LOOP;
END $seal$;
COMMIT;
