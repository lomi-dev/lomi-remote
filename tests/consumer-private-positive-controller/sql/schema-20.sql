-- Host-authorized pending/decision persistence only. Stored hex is never a
-- cryptographic ceiling or usable grant without fresh canonical Rust validation.
BEGIN;
CREATE FUNCTION public.lomi_consumer_recipient_recheck(p_account uuid,p_consumer uuid)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE stamp timestamptz; recipient jsonb;
BEGIN
 IF current_user<>'lomi_remote_inventory_owner' THEN RAISE EXCEPTION 'recipient unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 stamp:=clock_timestamp();
 SELECT jsonb_build_object('accountId',c."accountId",'consumerAuthorizationId',c.id,'accountSessionId',c."accountSessionId",'class',c."clientClass",
  'authorizationEpoch',c."authorizationEpoch"::text,'expiresAtMs',(extract(epoch FROM c."expiresAt")*1000)::bigint::text,'canManageAccount',c."canManageAccount") INTO recipient FROM public.consumer_authorization c
  JOIN public.remote_account_identity a ON a.id=c."accountId" AND a."userId"=c."userId"
  JOIN public."user" u ON u.id=c."userId"
  JOIN public."session" s ON s.id=c."accountSessionId" AND s."userId"=c."userId"
  JOIN public.remote_session_binding b ON b."sessionId"=s.id AND b."userId"=c."userId" AND b."accountId"=c."accountId" AND b."clientClass"=c."clientClass"
  JOIN public.session_metadata m ON m."sessionId"=s.id
  WHERE c.id=p_consumer AND c."accountId"=p_account AND length(c."accountSessionId") BETWEEN 1 AND 128 AND c."accountSessionId" ~ '^[!-~]+$' AND c."clientClass" IN ('web','desktop') AND c."canManageAccount"
   AND c."originKind"='better_auth' AND c."originId"=s.id AND NOT c.revoked
   AND a."authorizationEpoch"=c."authorizationEpoch" AND u.status='active'
   AND (CASE m.kind WHEN 'browser' THEN 'web' WHEN 'desktop' THEN 'desktop' END)=c."clientClass"
   AND c."expiresAt">stamp AND (s."expiresAt" AT TIME ZONE 'UTC')>stamp
   AND c."expiresAt"<=(s."expiresAt" AT TIME ZONE 'UTC');
 IF NOT FOUND THEN RAISE EXCEPTION 'recipient unavailable' USING ERRCODE='28000'; END IF;
 RETURN recipient;
END $$;
CREATE TABLE public.pairing_decision (
 "pairingId" uuid PRIMARY KEY REFERENCES public.pairing_proposal(id) ON DELETE CASCADE,
 decision text NOT NULL CHECK (decision IN ('approve','deny')),
 wire jsonb,
 "createdAt" timestamptz(3) NOT NULL,
 CHECK ((decision='approve')=(wire IS NOT NULL))
);
CREATE TABLE public.pairing_grant (
 "pairingId" uuid PRIMARY KEY REFERENCES public.pairing_proposal(id) ON DELETE CASCADE,
 "grantId" uuid NOT NULL UNIQUE,
 "accountId" uuid NOT NULL,
 "hostId" uuid NOT NULL,
 "hostAuthorizationId" uuid NOT NULL,
 "consumerAuthorizationId" uuid NOT NULL,
 "accountSessionId" text NOT NULL,
 "windowIdentityId" uuid NOT NULL,
 "runtimeId" uuid NOT NULL,
 "runtimeGeneration" bigint NOT NULL CHECK ("runtimeGeneration">0),
 "workspaceId" uuid NOT NULL,
 "workspaceEpoch" uuid NOT NULL,
 "hostAccessEpoch" bigint NOT NULL CHECK ("hostAccessEpoch">0),
 "grantRevision" bigint NOT NULL CHECK ("grantRevision"=1),
 "verifiedGrant" jsonb NOT NULL,
 "signedGrant" jsonb NOT NULL,
 "expiresAt" bigint NOT NULL CHECK ("expiresAt">0)
);
CREATE FUNCTION public.lomi_pairing_host_current(p_host uuid,p_hash bytea,p_runtime jsonb,p_live boolean)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE h record; r record; binding jsonb; stamp timestamptz;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'host pairing unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO STRICT h FROM public.lomi_host_access_lookup(p_host,p_hash);stamp:=clock_timestamp();
 SELECT "runtimeId",generation,"hostAccessEpoch" INTO r FROM public.host_runtime
  WHERE "hostId"=h."hostId" AND "authorizationId"=h."authorizationId" AND "hostAccessEpoch"=h."hostAccessEpoch"
   AND (NOT p_live OR ("leaseExpiresAt">stamp AND "freshUntil">stamp AND "publicationSeq">0 AND public.lomi_host_runtime_publication_valid(workspaces)));
 IF NOT FOUND THEN RAISE EXCEPTION 'host pairing runtime stale' USING ERRCODE='40001'; END IF;
 binding:=jsonb_build_object('runtimeId',r."runtimeId",'runtimeGeneration',r.generation::text,'hostAccessEpoch',r."hostAccessEpoch"::text);
 IF p_runtime IS NOT NULL AND p_runtime<>binding THEN RAISE EXCEPTION 'host pairing runtime stale' USING ERRCODE='40001'; END IF;
 RETURN jsonb_build_object('hostId',h."hostId",'accountId',h."accountId",'hostAuthorizationId',h."authorizationId",'runtime',binding);
END $$;
-- Only lifecycle state is returned. This helper never authenticates a consumer
-- using submitted IDs: its caller already authenticated the host or all8 C fields.
CREATE FUNCTION public.lomi_pairing_retained(p_pairing uuid)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE p public.pairing_proposal; d public.pairing_decision; g public.pairing_grant; recipient jsonb; target jsonb; authority jsonb; deadline bigint; stale boolean:=false; stamp timestamptz;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'retained pairing unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO p FROM public.pairing_proposal WHERE id=p_pairing;
 IF NOT FOUND THEN RAISE EXCEPTION 'pairing unavailable' USING ERRCODE='LR004'; END IF;
 SELECT * INTO d FROM public.pairing_decision WHERE "pairingId"=p.id;
 IF d.decision='deny' THEN RETURN jsonb_build_object('result',jsonb_build_object('status','denied','pairingId',p.id)); END IF;
 IF p.expired THEN RETURN jsonb_build_object('result',jsonb_build_object('status','expired','pairingId',p.id)); END IF;
 IF p."maximumGrant" IS NULL THEN RAISE EXCEPTION 'unfinished pairing unavailable' USING ERRCODE='23514'; END IF;
 IF d.decision='approve' THEN
  SELECT * INTO g FROM public.pairing_grant WHERE "pairingId"=p.id;
  IF NOT FOUND OR g."signedGrant" IS DISTINCT FROM d.wire THEN RAISE EXCEPTION 'incomplete pairing approval' USING ERRCODE='23514'; END IF;
  deadline:=g."expiresAt";
 ELSE deadline:=(p."trustedGrant"->>'expiresAt')::bigint;
 END IF;
 BEGIN
  recipient:=public.lomi_consumer_recipient_recheck(p."accountId",p."consumerAuthorizationId");
  target:=public.lomi_pairing_target(p."accountId",p."consumerAuthorizationId",(recipient->>'authorizationEpoch')::bigint,(recipient->>'expiresAtMs')::bigint,p.request);
 EXCEPTION WHEN invalid_authorization_specification OR SQLSTATE 'LR004' OR serialization_failure THEN stale:=true;
 END;
 stamp:=clock_timestamp();
 IF NOT stale THEN
  authority:=jsonb_set(target->'authority','{accountSessionId}',recipient->'accountSessionId');
  stale:=p.authority IS DISTINCT FROM authority OR p.identities IS DISTINCT FROM target->'identities'
   OR deadline<=floor(extract(epoch FROM stamp)) OR deadline>(target->>'maximumExpiresAt')::bigint
   OR (d.decision IS NULL AND p."pendingExpiresAt"<=stamp);
 END IF;
 IF stale THEN
  UPDATE public.pairing_proposal SET expired=true WHERE id=p.id;
  RETURN jsonb_build_object('result',jsonb_build_object('status','expired','pairingId',p.id));
 END IF;
 RETURN jsonb_build_object('pairingId',p.id,'trustedGrant',p."trustedGrant",'identities',target->'identities','authority',authority,'recipient',recipient,
  'request',p.request,'maximumGrant',p."maximumGrant",'now',floor(extract(epoch FROM clock_timestamp()))::bigint::text,'recordedGrant',g."signedGrant");
END $$;
CREATE FUNCTION public.lomi_pairing_pending(p_host uuid,p_hash bytea)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE h jsonb; p record; retained jsonb; pairings jsonb:='[]'; n integer:=0; scanned integer:=0; stamp timestamptz;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing pending unavailable' USING ERRCODE='42501'; END IF;
 h:=public.lomi_pairing_host_current(p_host,p_hash,NULL,true);stamp:=clock_timestamp();
 FOR p IN SELECT q.id FROM public.pairing_proposal q WHERE q."hostId"=p_host AND NOT q.expired AND q."pendingExpiresAt">stamp
  AND NOT EXISTS(SELECT FROM public.pairing_decision d WHERE d."pairingId"=q.id) ORDER BY q.id LIMIT 65 LOOP
  scanned:=scanned+1;IF scanned>64 THEN RAISE EXCEPTION 'pairing pending scan budget' USING ERRCODE='LR002'; END IF;
  retained:=public.lomi_pairing_retained(p.id);
  IF retained ? 'result' THEN CONTINUE; END IF;
  n:=n+1;IF n>64 THEN RAISE EXCEPTION 'pairing pending budget' USING ERRCODE='LR002'; END IF;
  pairings:=pairings||jsonb_build_array(retained-'recordedGrant');
  IF octet_length(jsonb_build_object('pairings',pairings)::text)>1048576 THEN RAISE EXCEPTION 'pairing pending budget' USING ERRCODE='LR002'; END IF;
 END LOOP;
 RETURN jsonb_build_object('pairings',pairings);
END $$;
CREATE FUNCTION public.lomi_pairing_host_prepare(p_pairing uuid,p_hash bytea,p_runtime jsonb,p_decision text,p_wire jsonb)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE p public.pairing_proposal; d public.pairing_decision; h jsonb; retained jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing decision unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO p FROM public.pairing_proposal WHERE id=p_pairing;
 IF NOT FOUND THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 h:=public.lomi_pairing_host_current(p."hostId",p_hash,p_runtime,false);
 IF p_runtime IS NULL THEN RAISE EXCEPTION 'pairing runtime required' USING ERRCODE='40001'; END IF;
 retained:=public.lomi_pairing_retained(p.id);
 IF retained#>>'{result,status}'='expired' THEN RETURN retained; END IF;
 IF p_decision IS NULL OR p_decision NOT IN ('approve','deny') OR (p_decision='deny' AND p_wire IS NOT NULL) THEN RAISE EXCEPTION 'invalid pairing decision' USING ERRCODE='22023'; END IF;
 IF p_decision='approve' AND (p_wire IS NULL OR jsonb_typeof(p_wire)<>'object' OR NOT p_wire ?& ARRAY['canonicalCbor','signature'] OR p_wire-ARRAY['canonicalCbor','signature']<>'{}'
  OR jsonb_typeof(p_wire->'canonicalCbor')<>'string' OR length(p_wire->>'canonicalCbor') NOT BETWEEN 2 AND 16384 OR (p_wire->>'canonicalCbor')!~'^(?:[0-9a-f]{2})+$'
  OR jsonb_typeof(p_wire->'signature')<>'string' OR (p_wire->>'signature')!~'^[0-9a-f]{128}$') THEN RAISE EXCEPTION 'invalid signed pairing decision' USING ERRCODE='22023'; END IF;
 SELECT * INTO d FROM public.pairing_decision WHERE "pairingId"=p.id;
 IF FOUND AND (d.decision<>p_decision OR d.wire IS DISTINCT FROM p_wire) THEN RAISE EXCEPTION 'pairing decision conflict' USING ERRCODE='LR003'; END IF;
 RETURN retained;
END $$;
CREATE FUNCTION public.lomi_pairing_grant_id(p_bytes jsonb) RETURNS uuid
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT string_agg(lpad(to_hex(value::integer),2,'0') ,'' ORDER BY ord)::uuid FROM jsonb_array_elements_text(p_bytes) WITH ORDINALITY v(value,ord)
$$;
-- Verify independent relational binding and narrowing. Cryptographic verification
-- is mandatory in the canonical Rust adapter before calling finalize or exposing
-- any saved approval; SQL hex/JSON checks alone never establish grant authority.
CREATE FUNCTION public.lomi_pairing_grant_valid(p public.pairing_proposal,p_verified jsonb) RETURNS boolean
 LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE normalized jsonb; expiry bigint;
BEGIN
 IF p_verified IS NULL OR jsonb_typeof(p_verified)<>'object' OR (p_verified-ARRAY['capabilities','expiresAt']) IS DISTINCT FROM (p."trustedGrant"-ARRAY['capabilities','expiresAt'])
  OR jsonb_typeof(p_verified->'expiresAt') IS DISTINCT FROM 'string' OR (p_verified->>'expiresAt')!~'^[1-9][0-9]{0,18}$' THEN RETURN false; END IF;
 expiry:=(p_verified->>'expiresAt')::bigint;
 IF expiry>(p."trustedGrant"->>'expiresAt')::bigint THEN RETURN false; END IF;
 normalized:=public.lomi_pairing_request_normalize(jsonb_set(p.request,'{requestedCapabilities}',p_verified->'capabilities'));
 RETURN (normalized->'requestedCapabilities')<@(p."trustedGrant"->'capabilities');
EXCEPTION WHEN invalid_parameter_value OR invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;
CREATE FUNCTION public.lomi_pairing_decision_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE p public.pairing_proposal; g public.pairing_grant;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing decision write unavailable' USING ERRCODE='42501'; END IF;
 IF TG_OP<>'INSERT' OR NOT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND ((classid::bigint<<32)|objid::bigint)=hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0)) THEN RAISE EXCEPTION 'immutable pairing decision' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT p FROM public.pairing_proposal WHERE id=NEW."pairingId";
 SELECT * INTO g FROM public.pairing_grant WHERE "pairingId"=p.id;
 IF p.expired OR p."maximumGrant" IS NULL OR p."pendingExpiresAt"<=clock_timestamp() OR (NEW.decision='approve' AND g."signedGrant" IS DISTINCT FROM NEW.wire) OR (NEW.decision='deny' AND g."pairingId" IS NOT NULL) THEN
  RAISE EXCEPTION 'invalid pairing decision binding' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION public.lomi_pairing_grant_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE p public.pairing_proposal;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing grant write unavailable' USING ERRCODE='42501'; END IF;
 IF TG_OP<>'INSERT' OR NOT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND ((classid::bigint<<32)|objid::bigint)=hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0)) THEN RAISE EXCEPTION 'immutable pairing grant' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT p FROM public.pairing_proposal WHERE id=NEW."pairingId";
 IF p.expired OR p."maximumGrant" IS NULL OR p."pendingExpiresAt"<=clock_timestamp() OR EXISTS(SELECT FROM public.pairing_decision WHERE "pairingId"=p.id)
  OR NOT public.lomi_pairing_grant_valid(p,NEW."verifiedGrant") OR NEW."expiresAt"<>(NEW."verifiedGrant"->>'expiresAt')::bigint OR NEW."expiresAt"<=floor(extract(epoch FROM clock_timestamp()))
  OR (NEW."grantId",NEW."accountId",NEW."hostId",NEW."hostAuthorizationId",NEW."consumerAuthorizationId",NEW."accountSessionId",NEW."windowIdentityId",NEW."runtimeId",NEW."runtimeGeneration",NEW."workspaceId",NEW."workspaceEpoch",NEW."hostAccessEpoch",NEW."grantRevision") IS DISTINCT FROM
   (public.lomi_pairing_grant_id(p."trustedGrant"->'grantId'),p."accountId",p."hostId",(p.authority->>'hostAuthorizationId')::uuid,p."consumerAuthorizationId",p.authority->>'accountSessionId',(p.request->>'windowIdentityId')::uuid,(p.authority->>'runtimeId')::uuid,(p.authority->>'runtimeGeneration')::bigint,(p.request->>'workspaceId')::uuid,(p.request->>'workspaceEpoch')::uuid,(p.authority->>'accessEpoch')::bigint,1::bigint) THEN
  RAISE EXCEPTION 'invalid pairing grant binding' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER pairing_decision_guard BEFORE INSERT OR UPDATE ON public.pairing_decision FOR EACH ROW EXECUTE FUNCTION public.lomi_pairing_decision_guard();
CREATE TRIGGER pairing_grant_guard BEFORE INSERT OR UPDATE ON public.pairing_grant FOR EACH ROW EXECUTE FUNCTION public.lomi_pairing_grant_guard();
CREATE FUNCTION public.lomi_pairing_host_finalize(p_pairing uuid,p_hash bytea,p_runtime jsonb,p_decision text,p_wire jsonb,p_verified_grant jsonb)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE retained jsonb; p public.pairing_proposal; g public.pairing_grant; result jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing decision unavailable' USING ERRCODE='42501'; END IF;
 retained:=public.lomi_pairing_host_prepare(p_pairing,p_hash,p_runtime,p_decision,p_wire);
 IF retained ? 'result' THEN RETURN retained->'result'; END IF;
 SELECT * INTO STRICT p FROM public.pairing_proposal WHERE id=p_pairing;
 IF p_decision='deny' THEN
  IF p_verified_grant IS NOT NULL THEN RAISE EXCEPTION 'invalid denial grant' USING ERRCODE='22023'; END IF;
  INSERT INTO public.pairing_decision VALUES(p.id,'deny',NULL,date_trunc('milliseconds',clock_timestamp()));
  RETURN jsonb_build_object('status','denied','pairingId',p.id);
 END IF;
 IF NOT public.lomi_pairing_grant_valid(p,p_verified_grant) THEN RAISE EXCEPTION 'invalid verified pairing grant' USING ERRCODE='22023'; END IF;
 IF (p_verified_grant->>'expiresAt')::bigint<=floor(extract(epoch FROM clock_timestamp())) THEN RAISE EXCEPTION 'verified pairing grant expired' USING ERRCODE='40001'; END IF;
 IF retained->'recordedGrant'<>'null'::jsonb THEN
  SELECT * INTO STRICT g FROM public.pairing_grant WHERE "pairingId"=p.id;
  IF g."verifiedGrant" IS DISTINCT FROM p_verified_grant THEN RAISE EXCEPTION 'pairing verified grant conflict' USING ERRCODE='LR003'; END IF;
 ELSE
  INSERT INTO public.pairing_grant VALUES(p.id,public.lomi_pairing_grant_id(p."trustedGrant"->'grantId'),p."accountId",p."hostId",(p.authority->>'hostAuthorizationId')::uuid,p."consumerAuthorizationId",p.authority->>'accountSessionId',
   (p.request->>'windowIdentityId')::uuid,(p.authority->>'runtimeId')::uuid,(p.authority->>'runtimeGeneration')::bigint,(p.request->>'workspaceId')::uuid,(p.request->>'workspaceEpoch')::uuid,(p.authority->>'accessEpoch')::bigint,1,p_verified_grant,p_wire,(p_verified_grant->>'expiresAt')::bigint);
  INSERT INTO public.pairing_decision VALUES(p.id,'approve',p_wire,date_trunc('milliseconds',clock_timestamp()));
 END IF;
 RETURN jsonb_build_object('status','approved','pairingId',p.id,'grant',p_wire,'identities',retained->'identities','authority',retained->'authority');
END $$;
-- Additive successor: the ordinary migrator cannot replace a function already
-- owned by a sealed NOLOGIN role. Operator permissions retire the 007 entrypoint.
CREATE FUNCTION public.lomi_pairing_create_prepare(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_request jsonb)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE req jsonb; target jsonb; prior public.pairing_proposal; pairing uuid; grant_id uuid; nonce bytea; trusted jsonb; authority jsonb; stamp timestamptz; expires bigint; retained jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 req:=public.lomi_pairing_request_normalize(p_request);stamp:=date_trunc('milliseconds',clock_timestamp());
 SELECT * INTO prior FROM public.pairing_proposal WHERE "consumerAuthorizationId"=p_consumer AND "operationId"=(req->>'operationId')::uuid;
 IF FOUND THEN
  IF prior.request<>req THEN RAISE EXCEPTION 'pairing idempotency conflict' USING ERRCODE='LR003'; END IF;
  IF prior."maximumGrant" IS NOT NULL THEN
   retained:=public.lomi_pairing_retained(prior.id);
   IF retained ? 'result' THEN RETURN retained; END IF;
   IF retained->'recordedGrant'<>'null'::jsonb THEN
    RETURN jsonb_build_object('result',jsonb_build_object('status','approved','pairingId',prior.id,'grant',retained->'recordedGrant','identities',retained->'identities','authority',retained->'authority'),
     'trustedGrant',prior."trustedGrant",'maximumGrant',prior."maximumGrant",'now',retained->'now');
   END IF;
  END IF;
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
 IF (SELECT count(*) FROM public.pairing_proposal WHERE "hostId"=(req->>'hostId')::uuid AND NOT expired AND "pendingExpiresAt">stamp AND NOT EXISTS(SELECT FROM public.pairing_decision d WHERE d."pairingId"=pairing_proposal.id))>=64 THEN RAISE EXCEPTION 'pairing pending budget' USING ERRCODE='LR002'; END IF;
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
REVOKE ALL ON public.pairing_decision,public.pairing_grant FROM PUBLIC;
REVOKE ALL ON FUNCTION public.lomi_consumer_recipient_recheck(uuid,uuid),public.lomi_pairing_host_current(uuid,bytea,jsonb,boolean),public.lomi_pairing_retained(uuid),
 public.lomi_pairing_pending(uuid,bytea),public.lomi_pairing_host_prepare(uuid,bytea,jsonb,text,jsonb),public.lomi_pairing_host_finalize(uuid,bytea,jsonb,text,jsonb,jsonb),
 public.lomi_pairing_grant_id(jsonb),public.lomi_pairing_grant_valid(public.pairing_proposal,jsonb),public.lomi_pairing_decision_guard(),public.lomi_pairing_grant_guard(),
 public.lomi_pairing_create_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb) FROM PUBLIC;
DO $seal$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON public.pairing_decision,public.pairing_grant FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_consumer_recipient_recheck(uuid,uuid), public.lomi_pairing_host_current(uuid,bytea,jsonb,boolean), public.lomi_pairing_retained(uuid), public.lomi_pairing_pending(uuid,bytea), public.lomi_pairing_host_prepare(uuid,bytea,jsonb,text,jsonb), public.lomi_pairing_host_finalize(uuid,bytea,jsonb,text,jsonb,jsonb), public.lomi_pairing_grant_id(jsonb), public.lomi_pairing_grant_valid(public.pairing_proposal,jsonb), public.lomi_pairing_decision_guard(), public.lomi_pairing_grant_guard(), public.lomi_pairing_create_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb) FROM %I',role_name);
  END IF;
 END LOOP;
END $seal$;
COMMIT;
