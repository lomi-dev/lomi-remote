-- Bounded pairing proposals only: no approval, grants, channels or relay.
-- Helpers and public entry points are sealed atomically before operator setup.
BEGIN;
CREATE FUNCTION public.lomi_consumer_assertion_recheck(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea)
 RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE stamp timestamptz;
BEGIN
 IF current_user<>'lomi_remote_inventory_owner' THEN RAISE EXCEPTION 'consumer assertion unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 stamp:=clock_timestamp();
 IF p_account IS NULL OR p_consumer IS NULL OR p_session IS NULL OR length(p_session) NOT BETWEEN 1 AND 128 OR p_session !~ '^[!-~]+$'
  OR p_class IS NULL OR p_class NOT IN ('web','desktop') OR p_epoch IS NULL OR p_epoch<1 OR p_expiry_ms IS NULL OR p_expiry_ms<1
  OR p_manage IS NULL OR p_hash IS NULL OR octet_length(p_hash)<>32 THEN
  RAISE EXCEPTION 'consumer authority required' USING ERRCODE='28000';
 END IF;
 -- Normal SELECT is deliberate: this execution owner has no UPDATE privilege.
 -- All authority operations serialize on the exact shared global Auth lock.
 PERFORM 1 FROM public.consumer_authorization c
  JOIN public.remote_account_identity a ON a.id=c."accountId" AND a."userId"=c."userId"
  JOIN public."user" u ON u.id=c."userId"
  JOIN public."session" s ON s.id=c."accountSessionId" AND s."userId"=c."userId"
  JOIN public.remote_session_binding b ON b."sessionId"=s.id AND b."userId"=c."userId" AND b."accountId"=c."accountId" AND b."clientClass"=c."clientClass"
  JOIN public.session_metadata m ON m."sessionId"=s.id
  WHERE c.id=p_consumer AND c."accountId"=p_account AND c."accountSessionId"=p_session AND c."clientClass"=p_class
   AND c."authorizationEpoch"=p_epoch AND c."canManageAccount"=p_manage AND c."canManageAccount"
   AND extract(epoch FROM c."expiresAt")*1000=p_expiry_ms::numeric
   AND c."originKind"='better_auth' AND c."originId"=s.id AND NOT c.revoked
   AND a."authorizationEpoch"=c."authorizationEpoch" AND u.status='active'
   AND (CASE m.kind WHEN 'browser' THEN 'web' WHEN 'desktop' THEN 'desktop' END)=c."clientClass"
   AND sha256(convert_to(s.token,'UTF8'))=p_hash
   AND c."expiresAt">stamp AND (s."expiresAt" AT TIME ZONE 'UTC')>stamp
   AND c."expiresAt"<=(s."expiresAt" AT TIME ZONE 'UTC')
;
 IF NOT FOUND THEN RAISE EXCEPTION 'consumer authority required' USING ERRCODE='28000'; END IF;
END $$;
CREATE TABLE public.pairing_proposal (
 id uuid PRIMARY KEY,
 "accountId" uuid NOT NULL REFERENCES public.remote_account_identity(id) ON DELETE CASCADE,
 "consumerAuthorizationId" uuid NOT NULL REFERENCES public.consumer_authorization(id) ON DELETE CASCADE,
 "operationId" uuid NOT NULL,
 "hostId" uuid NOT NULL,
 request jsonb NOT NULL,
 "trustedGrant" jsonb NOT NULL,
 identities jsonb NOT NULL,
 authority jsonb NOT NULL,
 "createdAt" timestamptz(3) NOT NULL,
 "pendingExpiresAt" timestamptz(3) NOT NULL,
 "maximumGrant" text CHECK (length("maximumGrant") BETWEEN 2 AND 16384 AND "maximumGrant" ~ '^(?:[0-9a-f]{2})+$'),
 "creatorTransaction" bigint NOT NULL,
 "creatorBackend" integer NOT NULL,
 expired boolean NOT NULL DEFAULT false,
 UNIQUE ("consumerAuthorizationId","operationId"),
 CHECK ("pendingExpiresAt">"createdAt")
);
CREATE INDEX "pairing_proposal_hostId_pendingExpiresAt_idx" ON public.pairing_proposal("hostId","pendingExpiresAt");
CREATE FUNCTION public.lomi_pairing_uuid_bytes(p_id uuid) RETURNS jsonb
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT jsonb_agg(get_byte(uuid_send(p_id),i) ORDER BY i) FROM generate_series(0,15) i
$$;
CREATE FUNCTION public.lomi_pairing_request_normalize(p_request jsonb) RETURNS jsonb
 LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE key text; v text; caps jsonb; names text[]; n bigint;
BEGIN
 IF p_request IS NULL OR jsonb_typeof(p_request)<>'object' OR NOT p_request ?& ARRAY['operationId','hostId','workspaceId','workspaceEpoch','runtime','windowIdentityId','requestedCapabilities']
  OR p_request-ARRAY['operationId','hostId','workspaceId','workspaceEpoch','runtime','windowIdentityId','requestedCapabilities']<>'{}' THEN
  RAISE EXCEPTION 'invalid pairing request' USING ERRCODE='22023'; END IF;
 FOREACH key IN ARRAY ARRAY['operationId','hostId','workspaceId','workspaceEpoch','windowIdentityId'] LOOP
  v:=p_request->>key;
  IF jsonb_typeof(p_request->key)<>'string' OR v !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR v::uuid='00000000-0000-0000-0000-000000000000' THEN
   RAISE EXCEPTION 'invalid pairing identifier' USING ERRCODE='22023'; END IF;
 END LOOP;
 IF jsonb_typeof(p_request->'runtime')<>'object' OR NOT (p_request->'runtime') ?& ARRAY['runtimeId','runtimeGeneration','hostAccessEpoch']
  OR (p_request->'runtime')-ARRAY['runtimeId','runtimeGeneration','hostAccessEpoch']<>'{}' THEN RAISE EXCEPTION 'invalid pairing runtime' USING ERRCODE='22023'; END IF;
 v:=p_request#>>'{runtime,runtimeId}';
 IF jsonb_typeof(p_request#>'{runtime,runtimeId}')<>'string' OR v !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR v::uuid='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'invalid pairing runtime id' USING ERRCODE='22023'; END IF;
 FOREACH key IN ARRAY ARRAY['runtimeGeneration','hostAccessEpoch'] LOOP
  v:=p_request->'runtime'->>key;
  IF jsonb_typeof(p_request->'runtime'->key)<>'string' OR v !~ '^[1-9][0-9]{0,18}$' THEN RAISE EXCEPTION 'invalid pairing runtime counter' USING ERRCODE='22023'; END IF;
  n:=v::bigint;
 END LOOP;
 caps:=p_request->'requestedCapabilities';
 IF jsonb_typeof(caps)<>'array' OR jsonb_array_length(caps) NOT BETWEEN 1 AND 10 OR EXISTS(SELECT FROM jsonb_array_elements(caps) c WHERE jsonb_typeof(c)<>'string') THEN RAISE EXCEPTION 'invalid pairing capabilities' USING ERRCODE='22023'; END IF;
 SELECT array_agg(value ORDER BY value) INTO names FROM jsonb_array_elements_text(caps);
 IF cardinality(names)<>(SELECT count(DISTINCT value) FROM unnest(names) value) OR NOT names @> ARRAY['workspace.read']
  OR NOT names <@ ARRAY['workspace.read','terminal.observe','terminal.control','terminal.manage','files.read','files.write','git.read','git.write','git.network','git.execute']
  OR (names && ARRAY['terminal.control','terminal.manage'] AND NOT names @> ARRAY['terminal.observe'])
  OR ('files.write'=ANY(names) AND NOT names @> ARRAY['files.read'])
  OR (names && ARRAY['git.write','git.network','git.execute'] AND NOT names @> ARRAY['git.read']) THEN
  RAISE EXCEPTION 'invalid pairing capability closure' USING ERRCODE='22023'; END IF;
 RETURN jsonb_set(p_request,'{requestedCapabilities}',to_jsonb(names));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
 RAISE EXCEPTION 'invalid pairing request' USING ERRCODE='22023';
END $$;
-- This private helper reads public authority only; it cannot read parent tokens.
CREATE FUNCTION public.lomi_pairing_target(p_account uuid,p_consumer uuid,p_epoch bigint,p_expiry_ms bigint,p_request jsonb)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE w record; h record; r record; stamp timestamptz:=clock_timestamp(); expires bigint;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing authority unavailable' USING ERRCODE='42501'; END IF;
 SELECT "signedIdentity","identityFingerprint" INTO w FROM public.consumer_window_identity
  WHERE "windowIdentityId"=(p_request->>'windowIdentityId')::uuid AND "consumerAuthorizationId"=p_consumer AND NOT revoked;
 IF NOT FOUND THEN RAISE EXCEPTION 'pairing target unavailable' USING ERRCODE='LR004'; END IF;
 SELECT i."hostId",i."accessEpoch",i."finalizedIdentity",i."hostKeyFingerprint",f.id AS family,f."accessExpiresAt",f."idleExpiresAt"
  INTO h FROM public.host_identity i JOIN public.host_authorization f ON f."hostId"=i."hostId" AND f."accountId"=i."accountId" AND f."hostAccessEpoch"=i."accessEpoch"
  WHERE i."hostId"=(p_request->>'hostId')::uuid AND i."accountId"=p_account AND i."finalizedIdentity" IS NOT NULL
   AND f.confirmed AND NOT f.revoked AND f."clientClass"='host' AND f."approvedAccountEpoch"=p_epoch
   AND f."accessExpiresAt">stamp AND f."idleExpiresAt">stamp;
 IF NOT FOUND THEN RAISE EXCEPTION 'pairing target unavailable' USING ERRCODE='LR004'; END IF;
 SELECT "runtimeId",generation,"hostAccessEpoch",workspaces INTO r FROM public.host_runtime
  WHERE "hostId"=h."hostId" AND "authorizationId"=h.family AND "hostAccessEpoch"=h."accessEpoch"
   AND "runtimeId"=(p_request#>>'{runtime,runtimeId}')::uuid AND generation=(p_request#>>'{runtime,runtimeGeneration}')::bigint
   AND "hostAccessEpoch"=(p_request#>>'{runtime,hostAccessEpoch}')::bigint
   AND "leaseExpiresAt">stamp AND "freshUntil">stamp AND "publicationSeq">0;
 IF NOT FOUND THEN RAISE EXCEPTION 'pairing runtime stale' USING ERRCODE='40001'; END IF;
 IF NOT public.lomi_host_runtime_publication_valid(r.workspaces) OR NOT EXISTS(
  SELECT FROM jsonb_array_elements(r.workspaces) item WHERE item->>'workspaceId'=p_request->>'workspaceId' AND item->>'workspaceEpoch'=p_request->>'workspaceEpoch'
 ) THEN RAISE EXCEPTION 'pairing workspace unavailable' USING ERRCODE='LR004'; END IF;
 expires:=floor(least(extract(epoch FROM stamp)+600,p_expiry_ms::numeric/1000,extract(epoch FROM h."accessExpiresAt"),extract(epoch FROM h."idleExpiresAt")))::bigint;
 IF expires<=floor(extract(epoch FROM stamp)) THEN RAISE EXCEPTION 'pairing deadline unavailable' USING ERRCODE='LR004'; END IF;
 RETURN jsonb_build_object(
  'identities',jsonb_build_object('host',h."finalizedIdentity",'consumer',w."signedIdentity",'hostFingerprint',encode(h."hostKeyFingerprint",'hex'),'consumerFingerprint',encode(w."identityFingerprint",'hex')),
  'authority',jsonb_build_object('hostAuthorizationId',h.family,'consumerAuthorizationId',p_consumer,'accountSessionId',NULL,'accessEpoch',h."accessEpoch"::text,'grantRevision','1','workspaceEpoch',p_request->>'workspaceEpoch','runtimeId',r."runtimeId",'runtimeGeneration',r.generation::text,'terminalMembership',NULL),
  'maximumExpiresAt',expires::text);
END $$;
CREATE FUNCTION public.lomi_pairing_proposal_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing write unavailable' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND ((classid::bigint<<32)|objid::bigint)=hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0)) THEN
  RAISE EXCEPTION 'pairing write requires authorization lock' USING ERRCODE='42501'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.expired OR NEW."maximumGrant" IS NOT NULL OR NEW."creatorTransaction"<>txid_current() OR NEW."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'invalid pairing draft' USING ERRCODE='23514'; END IF;
 ELSE
  IF NOT OLD.expired AND NEW.expired AND OLD."maximumGrant" IS NOT NULL AND (to_jsonb(NEW)-'expired') IS NOT DISTINCT FROM (to_jsonb(OLD)-'expired') THEN
   RETURN NEW;
  END IF;
  IF OLD.expired OR (to_jsonb(NEW)-'maximumGrant') IS DISTINCT FROM (to_jsonb(OLD)-'maximumGrant') OR OLD."maximumGrant" IS NOT NULL OR NEW."maximumGrant" IS NULL
   OR OLD."creatorTransaction"<>txid_current() OR OLD."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'immutable pairing proposal' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER pairing_proposal_guard BEFORE INSERT OR UPDATE ON public.pairing_proposal FOR EACH ROW EXECUTE FUNCTION public.lomi_pairing_proposal_guard();
CREATE FUNCTION public.lomi_pairing_draft_commit_guard() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing commit unavailable' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT FROM public.pairing_proposal p WHERE p.id=NEW.id AND p."maximumGrant" IS NULL) THEN RAISE EXCEPTION 'unfinished pairing draft' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER pairing_proposal_draft_finalized AFTER INSERT OR UPDATE ON public.pairing_proposal
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_pairing_draft_commit_guard();
CREATE FUNCTION public.lomi_pairing_prepare(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_request jsonb)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE req jsonb; target jsonb; prior public.pairing_proposal; pairing uuid; grant_id uuid; nonce bytea; trusted jsonb; authority jsonb; stamp timestamptz; expires bigint;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 req:=public.lomi_pairing_request_normalize(p_request);stamp:=date_trunc('milliseconds',clock_timestamp());
 SELECT * INTO prior FROM public.pairing_proposal WHERE "consumerAuthorizationId"=p_consumer AND "operationId"=(req->>'operationId')::uuid;
 IF FOUND THEN
  IF prior.request<>req THEN RAISE EXCEPTION 'pairing idempotency conflict' USING ERRCODE='LR003'; END IF;
  IF prior.expired OR prior."pendingExpiresAt"<=stamp THEN
   IF NOT prior.expired AND prior."maximumGrant" IS NOT NULL THEN UPDATE public.pairing_proposal SET expired=true WHERE id=prior.id; END IF;
   RETURN jsonb_build_object('result',jsonb_build_object('status','expired','pairingId',prior.id)); END IF;
  BEGIN
   target:=public.lomi_pairing_target(p_account,p_consumer,p_epoch,p_expiry_ms,req);
  EXCEPTION WHEN SQLSTATE 'LR004' OR serialization_failure THEN
   IF prior."maximumGrant" IS NOT NULL THEN UPDATE public.pairing_proposal SET expired=true WHERE id=prior.id; END IF;
   RETURN jsonb_build_object('result',jsonb_build_object('status','expired','pairingId',prior.id));
  END;
  authority:=jsonb_set(target->'authority','{accountSessionId}',to_jsonb(p_session));
  IF prior.authority<>authority OR prior.identities<>target->'identities' OR (prior."trustedGrant"->>'expiresAt')::bigint<=floor(extract(epoch FROM stamp))
   OR (prior."trustedGrant"->>'expiresAt')::bigint>(target->>'maximumExpiresAt')::bigint THEN
   IF prior."maximumGrant" IS NOT NULL THEN UPDATE public.pairing_proposal SET expired=true WHERE id=prior.id; END IF;
   RETURN jsonb_build_object('result',jsonb_build_object('status','expired','pairingId',prior.id)); END IF;
  IF prior."maximumGrant" IS NOT NULL THEN RETURN jsonb_build_object('trustedGrant',prior."trustedGrant",'result',jsonb_build_object('status','pending','pairingId',prior.id,
   'proposal',jsonb_build_object('maximumGrant',prior."maximumGrant",'identities',prior.identities,'authority',prior.authority))); END IF;
  IF prior."creatorTransaction"<>txid_current() OR prior."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'unfinished pairing operation' USING ERRCODE='23514'; END IF;
  RETURN jsonb_build_object('pairingId',prior.id,'trustedGrant',prior."trustedGrant",'identities',prior.identities,'authority',prior.authority);
 END IF;
 IF (SELECT count(*) FROM public.pairing_proposal WHERE "consumerAuthorizationId"=p_consumer)>=1024 THEN RAISE EXCEPTION 'pairing receipt budget' USING ERRCODE='LR002'; END IF;
 target:=public.lomi_pairing_target(p_account,p_consumer,p_epoch,p_expiry_ms,req);
 IF (SELECT count(*) FROM public.pairing_proposal WHERE "hostId"=(req->>'hostId')::uuid AND NOT expired AND "pendingExpiresAt">stamp)>=64 THEN RAISE EXCEPTION 'pairing pending budget' USING ERRCODE='LR002'; END IF;
 pairing:=gen_random_uuid();grant_id:=gen_random_uuid();
 -- Core UUID v4 uses PostgreSQL's CSPRNG. Hash three independent random UUIDs
 -- into a fixed 32-byte proposal nonce without requiring a new extension.
 nonce:=sha256(uuid_send(gen_random_uuid())||uuid_send(gen_random_uuid())||uuid_send(gen_random_uuid()));
 authority:=jsonb_set(target->'authority','{accountSessionId}',to_jsonb(p_session));expires:=(target->>'maximumExpiresAt')::bigint;
 trusted:=jsonb_build_object('version',3,'apiMajor',2,'applicationMajor',2,
  'accountId',public.lomi_pairing_uuid_bytes(p_account),'hostId',public.lomi_pairing_uuid_bytes((req->>'hostId')::uuid),
  'hostFingerprint',(SELECT jsonb_agg(get_byte(decode(target#>>'{identities,hostFingerprint}','hex'),i) ORDER BY i) FROM generate_series(0,31) i),
  'hostAuthorizationId',public.lomi_pairing_uuid_bytes((authority->>'hostAuthorizationId')::uuid),'accessEpoch',authority->>'accessEpoch',
  'consumerAuthorizationId',public.lomi_pairing_uuid_bytes(p_consumer),'accountSessionId',p_session,'consumerId',public.lomi_pairing_uuid_bytes((req->>'windowIdentityId')::uuid),
  'consumerFingerprint',(SELECT jsonb_agg(get_byte(decode(target#>>'{identities,consumerFingerprint}','hex'),i) ORDER BY i) FROM generate_series(0,31) i),
  'grantId',public.lomi_pairing_uuid_bytes(grant_id),'grantRevision','1',
  'workspaceId',public.lomi_pairing_uuid_bytes((req->>'workspaceId')::uuid),'workspaceEpoch',public.lomi_pairing_uuid_bytes((req->>'workspaceEpoch')::uuid),
  'runtimeId',public.lomi_pairing_uuid_bytes((authority->>'runtimeId')::uuid),'runtimeGeneration',authority->>'runtimeGeneration',
  'capabilities',req->'requestedCapabilities','nonce',(SELECT jsonb_agg(get_byte(nonce,i) ORDER BY i) FROM generate_series(0,31) i),'expiresAt',expires::text,'purpose','workspace');
 INSERT INTO public.pairing_proposal VALUES(pairing,p_account,p_consumer,(req->>'operationId')::uuid,(req->>'hostId')::uuid,req,trusted,target->'identities',authority,stamp,least(stamp+interval '120 seconds',to_timestamp(expires)),NULL,txid_current(),pg_backend_pid(),false);
 RETURN jsonb_build_object('pairingId',pairing,'trustedGrant',trusted,'identities',target->'identities','authority',authority);
END $$;
CREATE FUNCTION public.lomi_pairing_finalize(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_pairing uuid,p_maximum text)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE prior public.pairing_proposal; target jsonb; authority jsonb; stamp timestamptz;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 IF p_maximum IS NULL OR length(p_maximum) NOT BETWEEN 2 AND 16384 OR p_maximum !~ '^(?:[0-9a-f]{2})+$' THEN RAISE EXCEPTION 'invalid pairing maximum' USING ERRCODE='22023'; END IF;
 SELECT * INTO prior FROM public.pairing_proposal WHERE id=p_pairing AND "consumerAuthorizationId"=p_consumer AND "accountId"=p_account;
 IF NOT FOUND THEN RAISE EXCEPTION 'pairing unavailable' USING ERRCODE='LR004'; END IF;
 IF prior."creatorTransaction"<>txid_current() OR prior."creatorBackend"<>pg_backend_pid() OR prior.expired OR prior."maximumGrant" IS NOT NULL THEN RAISE EXCEPTION 'pairing draft transaction required' USING ERRCODE='23514'; END IF;
 target:=public.lomi_pairing_target(p_account,p_consumer,p_epoch,p_expiry_ms,prior.request);stamp:=clock_timestamp();
 authority:=jsonb_set(target->'authority','{accountSessionId}',to_jsonb(p_session));
 IF prior.authority<>authority OR prior.identities<>target->'identities' OR prior."pendingExpiresAt"<=stamp OR (prior."trustedGrant"->>'expiresAt')::bigint<=floor(extract(epoch FROM stamp))
  OR (prior."trustedGrant"->>'expiresAt')::bigint>(target->>'maximumExpiresAt')::bigint THEN RAISE EXCEPTION 'pairing draft stale' USING ERRCODE='40001'; END IF;
 UPDATE public.pairing_proposal SET "maximumGrant"=p_maximum WHERE id=prior.id;
 RETURN jsonb_build_object('status','pending','pairingId',prior.id,'proposal',jsonb_build_object('maximumGrant',p_maximum,'identities',prior.identities,'authority',prior.authority));
END $$;
REVOKE ALL ON TABLE public.pairing_proposal FROM PUBLIC;
REVOKE ALL ON FUNCTION public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea),
 public.lomi_pairing_uuid_bytes(uuid),public.lomi_pairing_request_normalize(jsonb),public.lomi_pairing_target(uuid,uuid,bigint,bigint,jsonb),
 public.lomi_pairing_proposal_guard(),public.lomi_pairing_draft_commit_guard(),
 public.lomi_pairing_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb),
 public.lomi_pairing_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text) FROM PUBLIC;
DO $seal$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON TABLE public.pairing_proposal FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea), public.lomi_pairing_uuid_bytes(uuid), public.lomi_pairing_request_normalize(jsonb), public.lomi_pairing_target(uuid,uuid,bigint,bigint,jsonb), public.lomi_pairing_proposal_guard(), public.lomi_pairing_draft_commit_guard(), public.lomi_pairing_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb), public.lomi_pairing_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text) FROM %I',role_name);
  END IF;
 END LOOP;
END $seal$;
COMMIT;
