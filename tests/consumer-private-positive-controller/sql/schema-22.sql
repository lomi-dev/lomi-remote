-- Experimental retained contexts/admissions only. No tickets or relay authority.
-- Canonical Rust revalidates every saved grant/context/admission before use.
BEGIN;
CREATE TABLE public.channel_proposal (
 id uuid PRIMARY KEY,
 "grantId" uuid NOT NULL,
 "accountId" uuid NOT NULL REFERENCES public.remote_account_identity(id) ON DELETE CASCADE,
 "hostId" uuid NOT NULL,
 "hostAuthorizationId" uuid NOT NULL,
 "consumerAuthorizationId" uuid NOT NULL,
 "creatorKind" text NOT NULL CHECK ("creatorKind" IN ('H','C')),
 "creatorAuthorizationId" uuid NOT NULL,
 "creatorHostAuthorizationId" uuid REFERENCES public.host_authorization(id) ON DELETE CASCADE,
 "creatorConsumerAuthorizationId" uuid REFERENCES public.consumer_authorization(id) ON DELETE CASCADE,
 "operationId" uuid NOT NULL,
 request jsonb NOT NULL,
 context jsonb NOT NULL,
 authority jsonb NOT NULL,
 "expectedContext" text CHECK (length("expectedContext") BETWEEN 2 AND 16384 AND "expectedContext" ~ '^(?:[0-9a-f]{2})+$'),
 "issuedAt" bigint NOT NULL CHECK ("issuedAt">0),
 "expiresAt" bigint NOT NULL,
 "creatorTransaction" bigint NOT NULL,
 "creatorBackend" integer NOT NULL,
 expired boolean NOT NULL DEFAULT false,
 UNIQUE ("creatorKind","creatorAuthorizationId","operationId"),
 CHECK ("expiresAt">"issuedAt" AND "expiresAt"<="issuedAt"+30),
 CHECK (("creatorKind"='H' AND "creatorHostAuthorizationId"="creatorAuthorizationId" AND "creatorHostAuthorizationId" IS NOT NULL AND "creatorConsumerAuthorizationId" IS NULL)
  OR ("creatorKind"='C' AND "creatorConsumerAuthorizationId"="creatorAuthorizationId" AND "creatorConsumerAuthorizationId" IS NOT NULL AND "creatorHostAuthorizationId" IS NULL))
);
CREATE INDEX "channel_proposal_hostId_expiresAt_idx" ON public.channel_proposal("hostId","expiresAt");
CREATE INDEX "channel_proposal_grantId_id_idx" ON public.channel_proposal("grantId",id);
CREATE INDEX "channel_proposal_creatorHostAuthorizationId_idx" ON public.channel_proposal("creatorHostAuthorizationId");
CREATE INDEX "channel_proposal_creatorConsumerAuthorizationId_idx" ON public.channel_proposal("creatorConsumerAuthorizationId");
CREATE TABLE public.channel_admission (
 "channelId" uuid PRIMARY KEY REFERENCES public.channel_proposal(id) ON DELETE CASCADE,
 wire jsonb NOT NULL,
 "createdAt" timestamptz(3) NOT NULL
);
CREATE FUNCTION public.lomi_channel_request_normalize(p_request jsonb) RETURNS jsonb
 LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE t jsonb; v text; key text; ignored jsonb; rev numeric;
BEGIN
 IF p_request IS NULL OR jsonb_typeof(p_request)<>'object' OR NOT p_request ?& ARRAY['operationId','grantId','grantRevision','runtime','target']
  OR p_request-ARRAY['operationId','grantId','grantRevision','runtime','target']<>'{}' THEN RAISE EXCEPTION 'invalid channel request' USING ERRCODE='22023'; END IF;
 t:=p_request->'target';
 IF jsonb_typeof(t) IS DISTINCT FROM 'object' OR t->>'purpose' IS NULL OR t->>'purpose' NOT IN ('workspace','terminal')
  OR NOT t ?& ARRAY['purpose','workspaceId','workspaceEpoch'] THEN RAISE EXCEPTION 'invalid channel target' USING ERRCODE='22023'; END IF;
 IF (t->>'purpose'='workspace' AND t-ARRAY['purpose','workspaceId','workspaceEpoch']<>'{}')
  OR (t->>'purpose'='terminal' AND (NOT t ?& ARRAY['paneId','sessionId','sessionEpoch'] OR t-ARRAY['purpose','workspaceId','workspaceEpoch','paneId','sessionId','sessionEpoch']<>'{}')) THEN RAISE EXCEPTION 'invalid channel target' USING ERRCODE='22023'; END IF;
 ignored:=public.lomi_pairing_request_normalize(jsonb_build_object('operationId',p_request->'operationId','hostId',p_request->'grantId','workspaceId',t->'workspaceId','workspaceEpoch',t->'workspaceEpoch',
  'runtime',p_request->'runtime','windowIdentityId','00000000-0000-0000-0000-000000000001','requestedCapabilities',jsonb_build_array('workspace.read')));
 IF t->>'purpose'='terminal' THEN
  FOREACH key IN ARRAY ARRAY['paneId','sessionId','sessionEpoch'] LOOP
   v:=t->>key;
   IF jsonb_typeof(t->key) IS DISTINCT FROM 'string' OR v !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR v::uuid='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'invalid channel terminal' USING ERRCODE='22023'; END IF;
  END LOOP;
 END IF;
 IF jsonb_typeof(p_request->'grantRevision') IS DISTINCT FROM 'string' OR (p_request->>'grantRevision')!~'^(0|[1-9][0-9]{0,19})$' THEN RAISE EXCEPTION 'invalid channel revision' USING ERRCODE='22023'; END IF;
 rev:=(p_request->>'grantRevision')::numeric;
 IF rev>18446744073709551615::numeric THEN RAISE EXCEPTION 'invalid channel revision' USING ERRCODE='22023'; END IF;
 RETURN p_request;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RAISE EXCEPTION 'invalid channel request' USING ERRCODE='22023';
END $$;
CREATE FUNCTION public.lomi_channel_context(p_id uuid,p_grant jsonb,p_terminal jsonb,p_issued bigint,p_expires bigint) RETURNS jsonb
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT jsonb_build_object('version',3,'grant',p_grant,'channelId',public.lomi_pairing_uuid_bytes(p_id),'initiatorRole','device','responderRole','host','purpose',CASE WHEN p_terminal IS NULL OR p_terminal='null'::jsonb THEN 'workspace' ELSE 'terminal' END,
  'terminal',CASE WHEN p_terminal IS NULL OR p_terminal='null'::jsonb THEN 'null'::jsonb ELSE jsonb_build_object('paneId',public.lomi_pairing_uuid_bytes((p_terminal->>'paneId')::uuid),'sessionId',public.lomi_pairing_uuid_bytes((p_terminal->>'sessionId')::uuid),'sessionEpoch',public.lomi_pairing_uuid_bytes((p_terminal->>'sessionEpoch')::uuid),'terminalProfile','lomi-rust-grid-v1-experimental') END,
  'issuedAt',p_issued::text,'expiresAt',p_expires::text)
$$;
CREATE FUNCTION public.lomi_channel_wire_valid(p_wire jsonb) RETURNS boolean
 LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT COALESCE(jsonb_typeof(p_wire)='object' AND p_wire ?& ARRAY['canonicalCbor','signature'] AND p_wire-ARRAY['canonicalCbor','signature']='{}'
  AND jsonb_typeof(p_wire->'canonicalCbor')='string' AND length(p_wire->>'canonicalCbor') BETWEEN 2 AND 16384 AND (p_wire->>'canonicalCbor')~'^(?:[0-9a-f]{2})+$'
  AND jsonb_typeof(p_wire->'signature')='string' AND (p_wire->>'signature')~'^[0-9a-f]{128}$',false)
$$;
CREATE FUNCTION public.lomi_channel_host_auth(p_grant uuid,p_hash bytea) RETURNS uuid
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE g public.pairing_grant; h record;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel authority unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO g FROM public.pairing_grant WHERE "grantId"=p_grant;
 IF NOT FOUND THEN
  -- Historical rows identify scope only. A removed source grant can never
  -- produce fresh authority, but its live creator keeps the operation receipt.
  SELECT c."hostId",c."accountId",c."hostAuthorizationId" INTO g."hostId",g."accountId",g."hostAuthorizationId" FROM public.channel_proposal c WHERE c."grantId"=p_grant ORDER BY c.id LIMIT 1;
  IF NOT FOUND THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 END IF;
 SELECT * INTO STRICT h FROM public.lomi_host_access_lookup(g."hostId",p_hash);
 IF (h."hostId",h."accountId",h."authorizationId") IS DISTINCT FROM (g."hostId",g."accountId",g."hostAuthorizationId") THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 RETURN h."authorizationId";
END $$;
CREATE FUNCTION public.lomi_channel_consumer_scope(p_grant uuid,p_account uuid,p_consumer uuid,p_session text) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel authority unavailable' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT FROM public.pairing_grant WHERE "grantId"=p_grant AND "accountId"=p_account AND "consumerAuthorizationId"=p_consumer AND "accountSessionId"=p_session) THEN RETURN; END IF;
 IF NOT EXISTS(SELECT FROM public.pairing_grant WHERE "grantId"=p_grant) AND EXISTS(SELECT FROM public.channel_proposal WHERE "grantId"=p_grant AND "accountId"=p_account AND "consumerAuthorizationId"=p_consumer AND context#>>'{grant,accountSessionId}'=p_session) THEN RETURN; END IF;
 RAISE EXCEPTION 'channel grant unavailable' USING ERRCODE='LR004';
END $$;
-- Current rows, not a submitted context, supply the experimental terminal profile.
CREATE FUNCTION public.lomi_channel_grant_state(p_grant uuid,p_request jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE g public.pairing_grant; pairing jsonb; a jsonb; terminal jsonb:='null'; published_workspaces jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel authority unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO g FROM public.pairing_grant WHERE "grantId"=p_grant;
 IF NOT FOUND THEN RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 IF EXISTS(SELECT FROM public.grant_revocation WHERE "grantId"=g."grantId") THEN
  UPDATE public.pairing_proposal SET expired=true WHERE id=g."pairingId" AND NOT expired;
  RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 pairing:=public.lomi_pairing_retained(g."pairingId");
 IF pairing ? 'result' OR EXISTS(SELECT FROM public.grant_revocation WHERE "grantId"=g."grantId") THEN RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 IF pairing->'recordedGrant' IS NULL OR pairing->'recordedGrant'='null'::jsonb THEN RAISE EXCEPTION 'approved channel grant required' USING ERRCODE='23514'; END IF;
 a:=pairing->'authority';
 IF p_request->'runtime' IS DISTINCT FROM jsonb_build_object('runtimeId',a->'runtimeId','runtimeGeneration',a->'runtimeGeneration','hostAccessEpoch',a->'accessEpoch') THEN RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 IF (p_request#>>'{target,workspaceId}',p_request#>>'{target,workspaceEpoch}') IS DISTINCT FROM (g."workspaceId"::text,g."workspaceEpoch"::text) THEN RETURN jsonb_build_object('failure','WORKSPACE_UNSHARED'); END IF;
 IF p_request#>>'{target,purpose}'='terminal' THEN
  IF NOT (g."verifiedGrant"->'capabilities') ? 'terminal.observe' THEN RETURN jsonb_build_object('failure','WORKSPACE_UNSHARED'); END IF;
  SELECT workspaces INTO STRICT published_workspaces FROM public.host_runtime WHERE "hostId"=g."hostId";
  SELECT t.value INTO terminal FROM jsonb_array_elements(published_workspaces) w CROSS JOIN LATERAL jsonb_array_elements(w.value->'terminals') t
   WHERE w.value->>'workspaceId'=g."workspaceId"::text AND w.value->>'workspaceEpoch'=g."workspaceEpoch"::text
    AND t.value->>'paneId'=p_request#>>'{target,paneId}' AND t.value->>'sessionId'=p_request#>>'{target,sessionId}' AND t.value->>'sessionEpoch'=p_request#>>'{target,sessionEpoch}';
  IF NOT FOUND THEN RETURN jsonb_build_object('failure','WORKSPACE_UNSHARED'); END IF;
  terminal:=terminal||jsonb_build_object('terminalProfile','lomi-rust-grid-v1-experimental');
 END IF;
 RETURN jsonb_build_object('pairing',pairing,'authority',jsonb_set(a,'{terminalMembership}',terminal),'terminal',terminal);
END $$;
CREATE FUNCTION public.lomi_channel_retained(p_channel uuid) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.channel_proposal; g public.pairing_grant; state jsonb; expected jsonb; admission jsonb; now_s bigint;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO c FROM public.channel_proposal WHERE id=p_channel;
 IF NOT FOUND THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='LR004'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF c.expired OR c."expiresAt"<=now_s OR c."issuedAt">now_s THEN
  IF NOT c.expired THEN UPDATE public.channel_proposal SET expired=true WHERE id=c.id; END IF;
  RETURN jsonb_build_object('result',jsonb_build_object('status','expired','channelId',c.id)); END IF;
 state:=public.lomi_channel_grant_state(c."grantId",c.request);
 -- Grant/recipient validation may cross the signed context deadline. One fresh
 -- sample governs both the terminal branch and the returned metadata clock.
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF state ? 'failure' OR c."expiresAt"<=now_s OR c."issuedAt">now_s THEN
  UPDATE public.channel_proposal SET expired=true WHERE id=c.id;
  RETURN jsonb_build_object('result',jsonb_build_object('status','expired','channelId',c.id)); END IF;
 SELECT * INTO STRICT g FROM public.pairing_grant WHERE "grantId"=c."grantId";
 expected:=public.lomi_channel_context(c.id,g."verifiedGrant",state->'terminal',c."issuedAt",c."expiresAt");
 IF c.context IS DISTINCT FROM expected OR c.authority IS DISTINCT FROM state->'authority' OR c."expiresAt">g."expiresAt" THEN RAISE EXCEPTION 'invalid retained channel context' USING ERRCODE='23514'; END IF;
 SELECT wire INTO admission FROM public.channel_admission WHERE "channelId"=c.id;
 RETURN jsonb_build_object('channelId',c.id,'request',c.request,'context',expected,'pairing',state->'pairing','authority',state->'authority','expectedContext',c."expectedContext",'now',now_s::text,'recordedAdmission',admission);
END $$;
CREATE FUNCTION public.lomi_channel_proposal_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE g public.pairing_grant; state jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel write unavailable' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND ((classid::bigint<<32)|objid::bigint)=hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0)) THEN RAISE EXCEPTION 'channel write requires authorization lock' USING ERRCODE='42501'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.expired OR NEW."expectedContext" IS NOT NULL OR NEW."creatorTransaction"<>txid_current() OR NEW."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'invalid channel draft' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT g FROM public.pairing_grant WHERE "grantId"=NEW."grantId";
  IF (NEW."accountId",NEW."hostId",NEW."hostAuthorizationId",NEW."consumerAuthorizationId") IS DISTINCT FROM (g."accountId",g."hostId",g."hostAuthorizationId",g."consumerAuthorizationId")
   OR NEW."creatorAuthorizationId" IS DISTINCT FROM (CASE WHEN NEW."creatorKind"='H' THEN g."hostAuthorizationId" ELSE g."consumerAuthorizationId" END)
   OR NEW.context IS DISTINCT FROM public.lomi_channel_context(NEW.id,g."verifiedGrant",NEW.authority->'terminalMembership',NEW."issuedAt",NEW."expiresAt") OR NEW."expiresAt">g."expiresAt" THEN RAISE EXCEPTION 'invalid channel draft binding' USING ERRCODE='23514'; END IF;
  state:=public.lomi_channel_grant_state(NEW."grantId",NEW.request);
  IF state ? 'failure' THEN NEW.expired:=true;RETURN NEW; END IF;
  IF NEW.authority IS DISTINCT FROM state->'authority' THEN RAISE EXCEPTION 'invalid channel current authority' USING ERRCODE='23514'; END IF;
 ELSE
  IF NOT OLD.expired AND NEW.expired AND (to_jsonb(NEW)-'expired') IS NOT DISTINCT FROM (to_jsonb(OLD)-'expired') THEN RETURN NEW; END IF;
  IF OLD.expired OR (to_jsonb(NEW)-'expectedContext') IS DISTINCT FROM (to_jsonb(OLD)-'expectedContext') OR OLD."expectedContext" IS NOT NULL OR NEW."expectedContext" IS NULL
   OR OLD."creatorTransaction"<>txid_current() OR OLD."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'immutable channel context' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER channel_proposal_guard BEFORE INSERT OR UPDATE ON public.channel_proposal FOR EACH ROW EXECUTE FUNCTION public.lomi_channel_proposal_guard();
CREATE FUNCTION public.lomi_channel_draft_commit_guard() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel commit unavailable' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT FROM public.channel_proposal WHERE id=NEW.id AND NOT expired AND "expectedContext" IS NULL) THEN RAISE EXCEPTION 'unfinished channel draft' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER channel_proposal_draft_finalized AFTER INSERT OR UPDATE ON public.channel_proposal DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_channel_draft_commit_guard();
CREATE FUNCTION public.lomi_channel_create_apply(p_kind text,p_creator uuid,p_request jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.channel_proposal; g public.pairing_grant; state jsonb; actual bigint; expected numeric; new_id uuid; issued bigint; expiry bigint; h record; ctx jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO c FROM public.channel_proposal WHERE "creatorKind"=p_kind AND "creatorAuthorizationId"=p_creator AND "operationId"=(p_request->>'operationId')::uuid;
 IF FOUND THEN
  IF c.request<>p_request THEN RAISE EXCEPTION 'channel idempotency conflict' USING ERRCODE='LR003'; END IF;
  RETURN public.lomi_channel_retained(c.id);
 END IF;
 SELECT * INTO g FROM public.pairing_grant WHERE "grantId"=(p_request->>'grantId')::uuid;
 IF NOT FOUND THEN RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 SELECT "grantRevision" INTO actual FROM public.grant_revocation WHERE "grantId"=g."grantId";actual:=COALESCE(actual,g."grantRevision");expected:=(p_request->>'grantRevision')::numeric;
 IF expected<>actual THEN RETURN jsonb_build_object('conflict',jsonb_build_object('expectedRevision',trunc(expected)::text,'actualRevision',actual::text)); END IF;
 state:=public.lomi_channel_grant_state(g."grantId",p_request);
 IF state ? 'failure' THEN RETURN state; END IF;
 issued:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 SELECT ha."accessExpiresAt",ha."idleExpiresAt" INTO STRICT h FROM public.host_authorization ha WHERE ha.id=g."hostAuthorizationId";
 expiry:=least(issued+30,g."expiresAt",floor((state#>>'{pairing,recipient,expiresAtMs}')::numeric/1000)::bigint,floor(extract(epoch FROM h."accessExpiresAt"))::bigint,floor(extract(epoch FROM h."idleExpiresAt"))::bigint);
 IF expiry<=issued THEN RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 IF (SELECT count(*) FROM public.channel_proposal WHERE "creatorKind"=p_kind AND "creatorAuthorizationId"=p_creator)>=1024 OR
  (SELECT count(*) FROM public.channel_proposal WHERE "hostId"=g."hostId" AND NOT expired AND "expiresAt">issued)>=64 THEN RAISE EXCEPTION 'channel resource limit' USING ERRCODE='LR002'; END IF;
 new_id:=gen_random_uuid();ctx:=public.lomi_channel_context(new_id,g."verifiedGrant",state->'terminal',issued,expiry);
 INSERT INTO public.channel_proposal VALUES(new_id,g."grantId",g."accountId",g."hostId",g."hostAuthorizationId",g."consumerAuthorizationId",p_kind,p_creator,
  CASE WHEN p_kind='H' THEN p_creator END,CASE WHEN p_kind='C' THEN p_creator END,(p_request->>'operationId')::uuid,p_request,ctx,state->'authority',NULL,issued,expiry,txid_current(),pg_backend_pid(),false);
 RETURN public.lomi_channel_retained(new_id);
END $$;
CREATE FUNCTION public.lomi_channel_finalize_apply(p_channel uuid,p_kind text,p_creator uuid,p_expected text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.channel_proposal; retained jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='42501'; END IF;
 retained:=public.lomi_channel_retained(p_channel);
 IF retained ? 'result' THEN RETURN retained; END IF;
 IF p_expected IS NULL OR length(p_expected) NOT BETWEEN 2 AND 16384 OR p_expected!~'^(?:[0-9a-f]{2})+$' THEN RAISE EXCEPTION 'invalid channel expected bytes' USING ERRCODE='22023'; END IF;
 SELECT * INTO STRICT c FROM public.channel_proposal WHERE id=p_channel;
 IF c."expectedContext" IS NOT NULL THEN
  IF c."expectedContext"<>p_expected THEN RAISE EXCEPTION 'changed channel expected bytes' USING ERRCODE='22023'; END IF;
  RETURN retained;
 END IF;
 IF c."creatorKind"<>p_kind OR c."creatorAuthorizationId"<>p_creator OR c."creatorTransaction"<>txid_current() OR c."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'channel draft transaction required' USING ERRCODE='23514'; END IF;
 UPDATE public.channel_proposal SET "expectedContext"=p_expected WHERE id=c.id;
 RETURN public.lomi_channel_retained(c.id);
END $$;
CREATE FUNCTION public.lomi_channel_host_prepare(p_hash bytea,p_request jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE req jsonb; creator uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 req:=public.lomi_channel_request_normalize(p_request);
 creator:=public.lomi_channel_host_auth((req->>'grantId')::uuid,p_hash);
 RETURN public.lomi_channel_create_apply('H',creator,req);
END $$;
CREATE FUNCTION public.lomi_channel_consumer_prepare(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_request jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE req jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 req:=public.lomi_channel_request_normalize(p_request);
 -- A live exact creator authenticates its operation namespace even when a
 -- changed retry names a missing source grant. Compare the immutable request
 -- before source liveness; never let deletion erase an idempotency conflict.
 IF EXISTS(SELECT FROM public.channel_proposal WHERE "creatorKind"='C' AND "creatorAuthorizationId"=p_consumer AND "operationId"=(req->>'operationId')::uuid) THEN
  RETURN public.lomi_channel_create_apply('C',p_consumer,req);
 END IF;
 PERFORM public.lomi_channel_consumer_scope((req->>'grantId')::uuid,p_account,p_consumer,p_session);
 RETURN public.lomi_channel_create_apply('C',p_consumer,req);
END $$;
CREATE FUNCTION public.lomi_channel_peer_host_read(p_channel uuid,p_hash bytea) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE grant_id uuid; creator uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT "grantId" INTO grant_id FROM public.channel_proposal WHERE id=p_channel;
 IF NOT FOUND THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 creator:=public.lomi_channel_host_auth(grant_id,p_hash);
 RETURN public.lomi_channel_retained(p_channel);
END $$;
CREATE FUNCTION public.lomi_channel_host_finalize(p_channel uuid,p_hash bytea,p_expected text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE grant_id uuid; creator uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT "grantId" INTO grant_id FROM public.channel_proposal WHERE id=p_channel;
 IF NOT FOUND THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 creator:=public.lomi_channel_host_auth(grant_id,p_hash);
 RETURN public.lomi_channel_finalize_apply(p_channel,'H',creator,p_expected);
END $$;
CREATE FUNCTION public.lomi_channel_peer_consumer_read(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_channel uuid) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE grant_id uuid; creator uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 SELECT "grantId" INTO grant_id FROM public.channel_proposal WHERE id=p_channel;
 IF NOT FOUND THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='LR004'; END IF;
 PERFORM public.lomi_channel_consumer_scope(grant_id,p_account,p_consumer,p_session);
 RETURN public.lomi_channel_retained(p_channel);
END $$;
CREATE FUNCTION public.lomi_channel_consumer_finalize(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_channel uuid,p_expected text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE grant_id uuid; creator uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 SELECT "grantId" INTO grant_id FROM public.channel_proposal WHERE id=p_channel;
 IF NOT FOUND THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='LR004'; END IF;
 PERFORM public.lomi_channel_consumer_scope(grant_id,p_account,p_consumer,p_session);
 RETURN public.lomi_channel_finalize_apply(p_channel,'C',p_consumer,p_expected);
END $$;
CREATE FUNCTION public.lomi_channel_pending(p_host uuid,p_hash bytea) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE h jsonb; c record; retained jsonb; channels jsonb:='[]'; scanned integer:=0; stamp bigint;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel pending unavailable' USING ERRCODE='42501'; END IF;
 h:=public.lomi_pairing_host_current(p_host,p_hash,NULL,true);stamp:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 FOR c IN SELECT p.id FROM public.channel_proposal p WHERE p."hostId"=p_host AND p."hostAuthorizationId"=(h->>'hostAuthorizationId')::uuid AND NOT p.expired AND p."expiresAt">stamp
  AND NOT EXISTS(SELECT FROM public.channel_admission a WHERE a."channelId"=p.id) ORDER BY p.id LIMIT 65 LOOP
  scanned:=scanned+1;IF scanned>64 THEN RAISE EXCEPTION 'channel pending scan budget' USING ERRCODE='LR002'; END IF;
  retained:=public.lomi_channel_retained(c.id);
  IF retained ? 'result' THEN CONTINUE; END IF;
  channels:=channels||jsonb_build_array(retained);
  IF octet_length(jsonb_build_object('channels',channels)::text)>1048576 THEN RAISE EXCEPTION 'channel pending byte budget' USING ERRCODE='LR002'; END IF;
 END LOOP;
 RETURN jsonb_build_object('channels',channels);
END $$;
CREATE FUNCTION public.lomi_channel_admission_prepare(p_channel uuid,p_hash bytea,p_runtime jsonb,p_wire jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.channel_proposal; retained jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel admission unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO c FROM public.channel_proposal WHERE id=p_channel;
 IF NOT FOUND THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 PERFORM public.lomi_channel_host_auth(c."grantId",p_hash);
 PERFORM public.lomi_pairing_host_current(c."hostId",p_hash,p_runtime,false);
 IF p_runtime IS NULL THEN RAISE EXCEPTION 'channel runtime required' USING ERRCODE='40001'; END IF;
 retained:=public.lomi_channel_retained(c.id);
 IF retained ? 'result' THEN RETURN retained; END IF;
 IF NOT public.lomi_channel_wire_valid(p_wire) THEN RAISE EXCEPTION 'invalid channel admission wire' USING ERRCODE='22023'; END IF;
 IF retained->'recordedAdmission'<>'null'::jsonb AND retained->'recordedAdmission' IS DISTINCT FROM p_wire THEN RAISE EXCEPTION 'channel admission conflict' USING ERRCODE='LR003'; END IF;
 RETURN retained;
END $$;
CREATE FUNCTION public.lomi_channel_admission_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.channel_proposal;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel admission write unavailable' USING ERRCODE='42501'; END IF;
 IF TG_OP<>'INSERT' OR NOT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND ((classid::bigint<<32)|objid::bigint)=hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0)) THEN RAISE EXCEPTION 'immutable channel admission' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT c FROM public.channel_proposal WHERE id=NEW."channelId";
 IF c.expired THEN RETURN NULL; END IF;
 IF c."expiresAt"<=floor(extract(epoch FROM clock_timestamp())) THEN UPDATE public.channel_proposal SET expired=true WHERE id=c.id;RETURN NULL; END IF;
 IF c."expectedContext" IS NULL OR NOT public.lomi_channel_wire_valid(NEW.wire) THEN RAISE EXCEPTION 'invalid channel admission binding' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER channel_admission_guard BEFORE INSERT OR UPDATE ON public.channel_admission FOR EACH ROW EXECUTE FUNCTION public.lomi_channel_admission_guard();
CREATE FUNCTION public.lomi_channel_admission_finalize(p_channel uuid,p_hash bytea,p_runtime jsonb,p_wire jsonb,p_verified_context jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE retained jsonb; c public.channel_proposal;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel admission unavailable' USING ERRCODE='42501'; END IF;
 retained:=public.lomi_channel_admission_prepare(p_channel,p_hash,p_runtime,p_wire);
 IF retained ? 'result' THEN RETURN retained; END IF;
 SELECT * INTO STRICT c FROM public.channel_proposal WHERE id=p_channel;
 IF c."expectedContext" IS NULL OR p_verified_context IS DISTINCT FROM c.context THEN RAISE EXCEPTION 'invalid verified channel context' USING ERRCODE='22023'; END IF;
 IF retained->'recordedAdmission'='null'::jsonb THEN INSERT INTO public.channel_admission VALUES(c.id,p_wire,date_trunc('milliseconds',clock_timestamp())); END IF;
 RETURN public.lomi_channel_retained(c.id);
END $$;
REVOKE ALL ON public.channel_proposal,public.channel_admission FROM PUBLIC;
REVOKE ALL ON FUNCTION public.lomi_channel_request_normalize(jsonb),
 public.lomi_channel_context(uuid,jsonb,jsonb,bigint,bigint),
 public.lomi_channel_wire_valid(jsonb),
 public.lomi_channel_host_auth(uuid,bytea),
 public.lomi_channel_consumer_scope(uuid,uuid,uuid,text),
 public.lomi_channel_grant_state(uuid,jsonb),
 public.lomi_channel_retained(uuid),
 public.lomi_channel_proposal_guard(),
 public.lomi_channel_draft_commit_guard(),
 public.lomi_channel_create_apply(text,uuid,jsonb),
 public.lomi_channel_finalize_apply(uuid,text,uuid,text),
 public.lomi_channel_host_prepare(bytea,jsonb),
 public.lomi_channel_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb),
 public.lomi_channel_peer_host_read(uuid,bytea),
 public.lomi_channel_host_finalize(uuid,bytea,text),
 public.lomi_channel_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid),
 public.lomi_channel_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text),
 public.lomi_channel_pending(uuid,bytea),
 public.lomi_channel_admission_prepare(uuid,bytea,jsonb,jsonb),
 public.lomi_channel_admission_guard(),
 public.lomi_channel_admission_finalize(uuid,bytea,jsonb,jsonb,jsonb) FROM PUBLIC;
DO $seal$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON public.channel_proposal,public.channel_admission FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_channel_request_normalize(jsonb),public.lomi_channel_context(uuid,jsonb,jsonb,bigint,bigint),public.lomi_channel_wire_valid(jsonb),public.lomi_channel_host_auth(uuid,bytea),public.lomi_channel_consumer_scope(uuid,uuid,uuid,text),public.lomi_channel_grant_state(uuid,jsonb),public.lomi_channel_retained(uuid),public.lomi_channel_proposal_guard(),public.lomi_channel_draft_commit_guard(),public.lomi_channel_create_apply(text,uuid,jsonb),public.lomi_channel_finalize_apply(uuid,text,uuid,text),public.lomi_channel_host_prepare(bytea,jsonb),public.lomi_channel_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb),public.lomi_channel_peer_host_read(uuid,bytea),public.lomi_channel_host_finalize(uuid,bytea,text),public.lomi_channel_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid),public.lomi_channel_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text),public.lomi_channel_pending(uuid,bytea),public.lomi_channel_admission_prepare(uuid,bytea,jsonb,jsonb),public.lomi_channel_admission_guard(),public.lomi_channel_admission_finalize(uuid,bytea,jsonb,jsonb,jsonb) FROM %I',role_name);
  END IF;
 END LOOP;
END $seal$;
COMMIT;
