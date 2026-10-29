-- One-use attachment tickets and continuously rechecked active authority only.
-- Canonical Rust verifies every evidence object; SQL bytes alone confer no authority.
BEGIN;
CREATE TABLE public.channel_authority_invalidation (
 "channelId" uuid PRIMARY KEY REFERENCES public.channel_proposal(id) ON DELETE CASCADE,
 "observedAt" bigint NOT NULL CHECK ("observedAt">0)
);
CREATE TABLE public.channel_ticket (
 id uuid PRIMARY KEY,
 "channelId" uuid NOT NULL REFERENCES public.channel_proposal(id) ON DELETE CASCADE,
 role text NOT NULL CHECK(role IN ('host','device')),
 "tokenHash" bytea UNIQUE CHECK(octet_length("tokenHash")=32),
 "issuanceNumber" integer CHECK("issuanceNumber" BETWEEN 1 AND 8),
 "expiresAt" bigint,
 "consumedAt" bigint,
 superseded boolean NOT NULL DEFAULT false,
 "creatorTransaction" bigint NOT NULL,
 "creatorBackend" integer NOT NULL,
 CHECK (("tokenHash" IS NULL AND "issuanceNumber" IS NULL AND "expiresAt" IS NULL AND "consumedAt" IS NULL AND NOT superseded)
  OR ("tokenHash" IS NOT NULL AND "issuanceNumber" IS NOT NULL AND "expiresAt" IS NOT NULL AND "expiresAt">0)),
 UNIQUE("channelId",role,"issuanceNumber")
);
CREATE INDEX "channel_ticket_channelId_role_idx" ON public.channel_ticket("channelId",role);
CREATE UNIQUE INDEX "channel_ticket_draft_idx" ON public.channel_ticket("creatorTransaction","creatorBackend","channelId",role) WHERE "tokenHash" IS NULL;
CREATE TABLE public.channel_transport (
 "channelId" uuid PRIMARY KEY REFERENCES public.channel_proposal(id) ON DELETE CASCADE,
 "accountId" uuid NOT NULL,
 "hostId" uuid NOT NULL,
 "ownerId" text NOT NULL CHECK("ownerId" ~ '^[A-Za-z0-9_-]{1,128}$'),
 "ownerEpoch" bigint NOT NULL CHECK("ownerEpoch">0),
 "firstAttachedAt" bigint NOT NULL CHECK("firstAttachedAt">0),
 "grantExpiresAt" bigint NOT NULL,
 "hostAttachedAt" bigint,
 "deviceAttachedAt" bigint,
 closed boolean NOT NULL DEFAULT false,
 CHECK("grantExpiresAt">"firstAttachedAt"),
 CHECK("hostAttachedAt" IS NOT NULL OR "deviceAttachedAt" IS NOT NULL),
 CHECK(("hostAttachedAt" IS NULL OR "hostAttachedAt">="firstAttachedAt") AND ("deviceAttachedAt" IS NULL OR "deviceAttachedAt">="firstAttachedAt"))
);
CREATE INDEX "channel_transport_hostId_grantExpiresAt_idx" ON public.channel_transport("hostId","grantExpiresAt") WHERE NOT closed AND "hostAttachedAt" IS NOT NULL AND "deviceAttachedAt" IS NOT NULL;
CREATE TABLE public.channel_transport_attempt (
 id uuid PRIMARY KEY,
 "channelId" uuid NOT NULL REFERENCES public.channel_proposal(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('consume','validate')),
 role text CHECK(role IN ('host','device')),
 "ticketId" uuid REFERENCES public.channel_ticket(id) ON DELETE CASCADE,
 "ownerId" text NOT NULL,
 "ownerEpoch" bigint NOT NULL,
 evidence jsonb NOT NULL,
 "creatorTransaction" bigint NOT NULL,
 "creatorBackend" integer NOT NULL,
 UNIQUE("creatorTransaction","creatorBackend"),
 CHECK((kind='consume' AND role IS NOT NULL AND "ticketId" IS NOT NULL) OR (kind='validate' AND role IS NULL AND "ticketId" IS NULL))
);
CREATE INDEX "channel_transport_attempt_channelId_idx" ON public.channel_transport_attempt("channelId");
CREATE INDEX "channel_transport_attempt_ticketId_idx" ON public.channel_transport_attempt("ticketId");
CREATE FUNCTION public.lomi_transport_fence(p_channel uuid,p_authority boolean) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF p_authority THEN INSERT INTO public.channel_authority_invalidation VALUES(p_channel,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) ON CONFLICT DO NOTHING; END IF;
 UPDATE public.channel_transport SET closed=true WHERE "channelId"=p_channel AND NOT closed;
END $$;
-- This synchronous trigger classifies the actual current authority while the
-- original writer still holds the same global lock. Mere HTTP window expiry
-- does not invalidate a healthy, already attached transport.
CREATE FUNCTION public.lomi_channel_expiry_classify() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE state jsonb; stamp bigint;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'channel classification unavailable' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND ((classid::bigint<<32)|objid::bigint)=hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0)) THEN RAISE EXCEPTION 'channel classification requires authorization lock' USING ERRCODE='42501'; END IF;
 state:=public.lomi_channel_grant_state(NEW."grantId",NEW.request);stamp:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF state ? 'failure' OR NEW."issuedAt">stamp OR NEW."expiresAt">stamp THEN PERFORM public.lomi_transport_fence(NEW.id,true); END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER channel_proposal_authority_classify AFTER UPDATE OF expired ON public.channel_proposal FOR EACH ROW WHEN (NOT OLD.expired AND NEW.expired) EXECUTE FUNCTION public.lomi_channel_expiry_classify();
CREATE FUNCTION public.lomi_transport_evidence(p_channel uuid,p_active boolean) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.channel_proposal; g public.pairing_grant; t public.channel_transport; state jsonb; wire jsonb; expected jsonb; stamp bigint; stamp_ms bigint; admitted_at bigint;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport evidence unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO c FROM public.channel_proposal WHERE id=p_channel;
 IF NOT FOUND THEN RETURN jsonb_build_object('valid',false); END IF;
 SELECT * INTO t FROM public.channel_transport WHERE "channelId"=p_channel;
 IF EXISTS(SELECT FROM public.channel_authority_invalidation WHERE "channelId"=p_channel) OR COALESCE(t.closed,false) THEN
  PERFORM public.lomi_transport_fence(p_channel,false);RETURN jsonb_build_object('valid',false); END IF;
 state:=public.lomi_channel_grant_state(c."grantId",c.request);
 stamp_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;stamp:=stamp_ms/1000;
 IF state ? 'failure' OR c."issuedAt">stamp OR (t."firstAttachedAt" IS NOT NULL AND stamp_ms<t."firstAttachedAt") THEN
  PERFORM public.lomi_transport_fence(p_channel,true);RETURN jsonb_build_object('valid',false); END IF;
 IF NOT p_active OR t."firstAttachedAt" IS NULL THEN
  IF c.expired OR c."expiresAt"<=stamp THEN
   IF NOT c.expired THEN UPDATE public.channel_proposal SET expired=true WHERE id=c.id; END IF;
   RETURN jsonb_build_object('valid',false); END IF;
 ELSE
  IF t."firstAttachedAt"<c."issuedAt"*1000 OR t."firstAttachedAt">=c."expiresAt"*1000 THEN
   PERFORM public.lomi_transport_fence(p_channel,true);RETURN jsonb_build_object('valid',false); END IF;
 END IF;
 SELECT * INTO STRICT g FROM public.pairing_grant WHERE "grantId"=c."grantId";
 SELECT a.wire INTO wire FROM public.channel_admission a WHERE a."channelId"=p_channel;
 IF c."expectedContext" IS NULL OR wire IS NULL THEN RETURN jsonb_build_object('valid',false); END IF;
 expected:=public.lomi_channel_context(c.id,g."verifiedGrant",state->'terminal',c."issuedAt",c."expiresAt");
 IF c.context IS DISTINCT FROM expected OR c.authority IS DISTINCT FROM state->'authority' OR c."expiresAt">g."expiresAt" THEN RAISE EXCEPTION 'invalid transport context binding' USING ERRCODE='23514'; END IF;
 admitted_at:=CASE WHEN p_active AND t."firstAttachedAt" IS NOT NULL THEN t."firstAttachedAt"/1000 ELSE stamp END;
 RETURN jsonb_build_object('channelId',c.id,'request',c.request,'context',expected,'pairing',state->'pairing','authority',state->'authority','expectedContext',c."expectedContext",'now',stamp::text,'recordedAdmission',wire,'admissionVerifiedAt',admitted_at::text);
END $$;
CREATE FUNCTION public.lomi_transport_runtime(p_channel uuid,p_runtime jsonb) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE binding jsonb;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport runtime unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT jsonb_build_object('runtimeId',r."runtimeId",'runtimeGeneration',r.generation::text,'hostAccessEpoch',r."hostAccessEpoch"::text) INTO binding
  FROM public.host_runtime r JOIN public.channel_proposal c ON c."hostId"=r."hostId" WHERE c.id=p_channel;
 IF binding IS NULL OR p_runtime IS DISTINCT FROM binding THEN RAISE EXCEPTION 'current transport runtime required' USING ERRCODE='40001'; END IF;
END $$;
CREATE FUNCTION public.lomi_transport_owner_live(p_owner text,p_epoch bigint) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport owner unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 RETURN COALESCE(p_owner ~ '^[A-Za-z0-9_-]{1,128}$' AND p_epoch>0 AND EXISTS(SELECT FROM public.remote_relay_owner g JOIN public.remote_relay_owner h ON h.id='owner:'||p_owner
  WHERE g.id='global' AND g.epoch::bigint=p_epoch AND h.epoch=g.epoch AND (g."expiresAt" AT TIME ZONE 'UTC')>clock_timestamp()),false);
END $$;
CREATE FUNCTION public.lomi_ticket_prepare_apply(p_channel uuid,p_role text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE evidence jsonb; new_ticket uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'ticket unavailable' USING ERRCODE='42501'; END IF;
 evidence:=public.lomi_transport_evidence(p_channel,false);
 IF evidence ? 'valid' THEN RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 IF EXISTS(SELECT FROM public.channel_ticket WHERE "channelId"=p_channel AND role=p_role AND "consumedAt" IS NOT NULL) THEN RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 IF (SELECT count(*) FROM public.channel_ticket WHERE "channelId"=p_channel AND role=p_role AND "tokenHash" IS NOT NULL)>=8 THEN RAISE EXCEPTION 'ticket issuance budget' USING ERRCODE='LR002'; END IF;
 new_ticket:=gen_random_uuid();
 INSERT INTO public.channel_ticket(id,"channelId",role,"creatorTransaction","creatorBackend") VALUES(new_ticket,p_channel,p_role,txid_current(),pg_backend_pid());
 RETURN jsonb_build_object('ticketId',new_ticket,'role',p_role,'evidence',evidence);
END $$;
CREATE FUNCTION public.lomi_ticket_finalize_apply(p_ticket uuid,p_role text,p_hash bytea) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE ticket public.channel_ticket; evidence jsonb; stamp_ms bigint; expiry_ms bigint; serial integer; h record;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'ticket unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT ticket FROM public.channel_ticket WHERE id=p_ticket;
 IF ticket.role<>p_role OR ticket."creatorTransaction"<>txid_current() OR ticket."creatorBackend"<>pg_backend_pid() OR ticket."tokenHash" IS NOT NULL THEN RAISE EXCEPTION 'ticket draft transaction required' USING ERRCODE='23514'; END IF;
 IF p_hash IS NULL OR octet_length(p_hash)<>32 THEN RAISE EXCEPTION 'ticket hash required' USING ERRCODE='22023'; END IF;
 evidence:=public.lomi_transport_evidence(ticket."channelId",false);
 IF evidence ? 'valid' OR EXISTS(SELECT FROM public.channel_ticket WHERE "channelId"=ticket."channelId" AND role=p_role AND "consumedAt" IS NOT NULL) THEN
  DELETE FROM public.channel_ticket WHERE id=ticket.id;RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 SELECT ha."accessExpiresAt",ha."idleExpiresAt" INTO STRICT h FROM public.host_authorization ha WHERE ha.id=(evidence#>>'{authority,hostAuthorizationId}')::uuid;
 stamp_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 expiry_ms:=least(stamp_ms+5000,floor(extract(epoch FROM h."accessExpiresAt")*1000)::bigint,floor(extract(epoch FROM h."idleExpiresAt")*1000)::bigint,(evidence#>>'{context,expiresAt}')::bigint*1000,(evidence#>>'{context,grant,expiresAt}')::bigint*1000,(evidence#>>'{pairing,recipient,expiresAtMs}')::bigint);
 IF expiry_ms<=stamp_ms THEN
  IF floor(extract(epoch FROM h."accessExpiresAt")*1000)::bigint<=stamp_ms OR floor(extract(epoch FROM h."idleExpiresAt")*1000)::bigint<=stamp_ms THEN PERFORM public.lomi_transport_fence(ticket."channelId",true); END IF;
  DELETE FROM public.channel_ticket WHERE id=ticket.id;RETURN jsonb_build_object('failure','STALE_EPOCH'); END IF;
 SELECT COALESCE(max("issuanceNumber"),0)+1 INTO serial FROM public.channel_ticket WHERE "channelId"=ticket."channelId" AND role=p_role;
 IF serial>8 THEN RAISE EXCEPTION 'ticket issuance budget' USING ERRCODE='LR002'; END IF;
 UPDATE public.channel_ticket SET superseded=true WHERE "channelId"=ticket."channelId" AND role=p_role AND "tokenHash" IS NOT NULL AND "consumedAt" IS NULL AND NOT superseded;
 UPDATE public.channel_ticket SET "tokenHash"=p_hash,"issuanceNumber"=serial,"expiresAt"=expiry_ms WHERE id=ticket.id;
 RETURN jsonb_build_object('channelId',ticket."channelId",'expiresInMs',expiry_ms-stamp_ms);
END $$;
CREATE FUNCTION public.lomi_transport_current(p_channel uuid,p_owner text,p_epoch bigint,p_attachment boolean) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.channel_proposal; t public.channel_transport; evidence jsonb; stamp_ms bigint; expiry_ms bigint;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO c FROM public.channel_proposal WHERE id=p_channel;
 IF NOT FOUND THEN RETURN jsonb_build_object('valid',false); END IF;
 SELECT * INTO t FROM public.channel_transport WHERE "channelId"=p_channel;
 IF NOT public.lomi_transport_owner_live(p_owner,p_epoch) OR (t."channelId" IS NOT NULL AND (t.closed OR (t."ownerId",t."ownerEpoch") IS DISTINCT FROM (p_owner,p_epoch))) THEN
  PERFORM public.lomi_transport_fence(p_channel,false);RETURN jsonb_build_object('valid',false); END IF;
 evidence:=public.lomi_transport_evidence(p_channel,NOT p_attachment);
 IF evidence ? 'valid' THEN PERFORM public.lomi_transport_fence(p_channel,false);RETURN evidence; END IF;
 stamp_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF p_attachment THEN
  IF c.expired OR c."expiresAt"*1000<=stamp_ms THEN PERFORM public.lomi_transport_fence(p_channel,false);RETURN jsonb_build_object('valid',false); END IF;
 ELSE
  IF t."channelId" IS NULL THEN RETURN jsonb_build_object('valid',false); END IF;
  expiry_ms:=CASE WHEN t."hostAttachedAt" IS NOT NULL AND t."deviceAttachedAt" IS NOT NULL THEN t."grantExpiresAt" ELSE c."expiresAt"*1000 END;
  IF expiry_ms<=stamp_ms THEN PERFORM public.lomi_transport_fence(p_channel,false);RETURN jsonb_build_object('valid',false); END IF;
 END IF;
 RETURN evidence;
END $$;
CREATE FUNCTION public.lomi_transport_consume_prepare(p_channel uuid,p_hash bytea,p_owner text,p_owner_epoch bigint) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE ticket public.channel_ticket; evidence jsonb; attempt_id uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF p_hash IS NULL OR octet_length(p_hash)<>32 THEN RETURN jsonb_build_object('valid',false); END IF;
 SELECT * INTO ticket FROM public.channel_ticket WHERE "tokenHash"=p_hash AND "channelId"=p_channel;
 IF NOT FOUND OR ticket.superseded OR ticket."consumedAt" IS NOT NULL OR ticket."expiresAt"<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint THEN RETURN jsonb_build_object('valid',false); END IF;
 evidence:=public.lomi_transport_current(p_channel,p_owner,p_owner_epoch,true);
 IF evidence ? 'valid' THEN RETURN evidence; END IF;
 attempt_id:=gen_random_uuid();
 INSERT INTO public.channel_transport_attempt VALUES(attempt_id,p_channel,'consume',ticket.role,ticket.id,p_owner,p_owner_epoch,evidence,txid_current(),pg_backend_pid());
 RETURN jsonb_build_object('attemptId',attempt_id,'role',ticket.role,'evidence',evidence);
END $$;
CREATE FUNCTION public.lomi_transport_consume_finalize(p_attempt uuid,p_owner text,p_owner_epoch bigint) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE attempt public.channel_transport_attempt; ticket public.channel_ticket; t public.channel_transport; c public.channel_proposal; evidence jsonb; stamp_ms bigint; expiry_ms bigint;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO attempt FROM public.channel_transport_attempt WHERE id=p_attempt;
 IF NOT FOUND THEN RETURN jsonb_build_object('valid',false); END IF;
 IF attempt.kind<>'consume' OR attempt."creatorTransaction"<>txid_current() OR attempt."creatorBackend"<>pg_backend_pid() OR (attempt."ownerId",attempt."ownerEpoch") IS DISTINCT FROM (p_owner,p_owner_epoch) THEN RAISE EXCEPTION 'transport attempt transaction required' USING ERRCODE='23514'; END IF;
 evidence:=public.lomi_transport_current(attempt."channelId",p_owner,p_owner_epoch,true);
 SELECT * INTO ticket FROM public.channel_ticket WHERE id=attempt."ticketId";
 stamp_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 DELETE FROM public.channel_transport_attempt WHERE id=attempt.id;
 IF NOT public.lomi_transport_owner_live(p_owner,p_owner_epoch) THEN PERFORM public.lomi_transport_fence(attempt."channelId",false);RETURN jsonb_build_object('valid',false); END IF;
 IF evidence ? 'valid' OR ticket.id IS NULL OR ticket.superseded OR ticket."consumedAt" IS NOT NULL OR ticket."expiresAt"<=stamp_ms THEN RETURN jsonb_build_object('valid',false); END IF;
 SELECT * INTO STRICT c FROM public.channel_proposal WHERE id=attempt."channelId";
 IF c."expiresAt"*1000<=stamp_ms THEN PERFORM public.lomi_transport_fence(c.id,false);RETURN jsonb_build_object('valid',false); END IF;
 SELECT * INTO t FROM public.channel_transport WHERE "channelId"=c.id;
 IF (attempt.role='host' AND t."hostAttachedAt" IS NOT NULL) OR (attempt.role='device' AND t."deviceAttachedAt" IS NOT NULL) THEN RETURN jsonb_build_object('valid',false); END IF;
 IF t."channelId" IS NOT NULL AND (SELECT count(*) FROM public.channel_transport WHERE "hostId"=c."hostId" AND NOT closed AND "hostAttachedAt" IS NOT NULL AND "deviceAttachedAt" IS NOT NULL AND "grantExpiresAt">stamp_ms)>=256 THEN RAISE EXCEPTION 'active transport budget' USING ERRCODE='LR002'; END IF;
 IF t."channelId" IS NULL THEN
  INSERT INTO public.channel_transport VALUES(c.id,c."accountId",c."hostId",p_owner,p_owner_epoch,stamp_ms,(evidence#>>'{context,grant,expiresAt}')::bigint*1000,CASE WHEN attempt.role='host' THEN stamp_ms END,CASE WHEN attempt.role='device' THEN stamp_ms END,false);
 ELSE
  UPDATE public.channel_transport SET "hostAttachedAt"=CASE WHEN attempt.role='host' THEN stamp_ms ELSE "hostAttachedAt" END,"deviceAttachedAt"=CASE WHEN attempt.role='device' THEN stamp_ms ELSE "deviceAttachedAt" END WHERE "channelId"=c.id;
 END IF;
 UPDATE public.channel_ticket SET "consumedAt"=stamp_ms WHERE id=ticket.id;
 SELECT * INTO STRICT t FROM public.channel_transport WHERE "channelId"=c.id;
 expiry_ms:=CASE WHEN t."hostAttachedAt" IS NOT NULL AND t."deviceAttachedAt" IS NOT NULL THEN t."grantExpiresAt" ELSE c."expiresAt"*1000 END;
 RETURN jsonb_build_object('accountId',c."accountId",'channelId',c.id,'role',attempt.role,'ownerEpoch',p_owner_epoch,'expiresAt',expiry_ms,'admissionExpiresAt',c."expiresAt"*1000,'transportExpiresAt',t."grantExpiresAt",'active',t."hostAttachedAt" IS NOT NULL AND t."deviceAttachedAt" IS NOT NULL);
END $$;
CREATE FUNCTION public.lomi_transport_validate_prepare(p_channel uuid,p_owner text,p_owner_epoch bigint) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE evidence jsonb; attempt_id uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport unavailable' USING ERRCODE='42501'; END IF;
 evidence:=public.lomi_transport_current(p_channel,p_owner,p_owner_epoch,false);
 IF evidence ? 'valid' THEN RETURN evidence; END IF;
 attempt_id:=gen_random_uuid();
 INSERT INTO public.channel_transport_attempt VALUES(attempt_id,p_channel,'validate',NULL,NULL,p_owner,p_owner_epoch,evidence,txid_current(),pg_backend_pid());
 RETURN jsonb_build_object('attemptId',attempt_id,'evidence',evidence);
END $$;
CREATE FUNCTION public.lomi_transport_validate_finalize(p_attempt uuid,p_owner text,p_owner_epoch bigint) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE attempt public.channel_transport_attempt; evidence jsonb; t public.channel_transport; c public.channel_proposal; expiry_ms bigint;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO attempt FROM public.channel_transport_attempt WHERE id=p_attempt;
 IF NOT FOUND THEN RETURN jsonb_build_object('valid',false); END IF;
 IF attempt.kind<>'validate' OR attempt."creatorTransaction"<>txid_current() OR attempt."creatorBackend"<>pg_backend_pid() OR (attempt."ownerId",attempt."ownerEpoch") IS DISTINCT FROM (p_owner,p_owner_epoch) THEN RAISE EXCEPTION 'transport attempt transaction required' USING ERRCODE='23514'; END IF;
 evidence:=public.lomi_transport_current(attempt."channelId",p_owner,p_owner_epoch,false);
 DELETE FROM public.channel_transport_attempt WHERE id=attempt.id;
 IF evidence ? 'valid' THEN RETURN evidence; END IF;
 SELECT * INTO STRICT t FROM public.channel_transport WHERE "channelId"=attempt."channelId";
 SELECT * INTO STRICT c FROM public.channel_proposal WHERE id=attempt."channelId";
 expiry_ms:=CASE WHEN t."hostAttachedAt" IS NOT NULL AND t."deviceAttachedAt" IS NOT NULL THEN t."grantExpiresAt" ELSE c."expiresAt"*1000 END;
 IF NOT public.lomi_transport_owner_live(p_owner,p_owner_epoch) OR expiry_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint THEN PERFORM public.lomi_transport_fence(c.id,false);RETURN jsonb_build_object('valid',false); END IF;
 RETURN jsonb_build_object('valid',true,'expiresAt',expiry_ms,'admissionExpiresAt',c."expiresAt"*1000,'transportExpiresAt',t."grantExpiresAt",'active',t."hostAttachedAt" IS NOT NULL AND t."deviceAttachedAt" IS NOT NULL);
END $$;
CREATE FUNCTION public.lomi_ticket_host_prepare(p_channel uuid,p_hash bytea,p_runtime jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE channel_id uuid; grant_id uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'ticket unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 channel_id:=p_channel;
 SELECT "grantId" INTO grant_id FROM public.channel_proposal WHERE id=channel_id;
 IF grant_id IS NULL THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 PERFORM public.lomi_channel_host_auth(grant_id,p_hash);
 PERFORM public.lomi_transport_runtime(channel_id,p_runtime);
 RETURN public.lomi_ticket_prepare_apply(channel_id,'host');
END $$;
CREATE FUNCTION public.lomi_ticket_host_finalize(p_ticket uuid,p_hash bytea,p_runtime jsonb,p_token_hash bytea) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE channel_id uuid; grant_id uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'ticket unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT "channelId" INTO channel_id FROM public.channel_ticket WHERE id=p_ticket;
 SELECT "grantId" INTO grant_id FROM public.channel_proposal WHERE id=channel_id;
 IF grant_id IS NULL THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 PERFORM public.lomi_channel_host_auth(grant_id,p_hash);
 PERFORM public.lomi_transport_runtime(channel_id,p_runtime);
 RETURN public.lomi_ticket_finalize_apply(p_ticket,'host',p_token_hash);
END $$;
CREATE FUNCTION public.lomi_ticket_consumer_prepare(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_channel uuid,p_runtime jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE channel_id uuid; grant_id uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'ticket unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 channel_id:=p_channel;
 SELECT "grantId" INTO grant_id FROM public.channel_proposal WHERE id=channel_id;
 IF grant_id IS NULL THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='LR004'; END IF;
 PERFORM public.lomi_channel_consumer_scope(grant_id,p_account,p_consumer,p_session);
 PERFORM public.lomi_transport_runtime(channel_id,p_runtime);
 RETURN public.lomi_ticket_prepare_apply(channel_id,'device');
END $$;
CREATE FUNCTION public.lomi_ticket_consumer_finalize(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_ticket uuid,p_runtime jsonb,p_token_hash bytea) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE channel_id uuid; grant_id uuid;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'ticket unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 SELECT "channelId" INTO channel_id FROM public.channel_ticket WHERE id=p_ticket;
 SELECT "grantId" INTO grant_id FROM public.channel_proposal WHERE id=channel_id;
 IF grant_id IS NULL THEN RAISE EXCEPTION 'channel unavailable' USING ERRCODE='LR004'; END IF;
 PERFORM public.lomi_channel_consumer_scope(grant_id,p_account,p_consumer,p_session);
 PERFORM public.lomi_transport_runtime(channel_id,p_runtime);
 RETURN public.lomi_ticket_finalize_apply(p_ticket,'device',p_token_hash);
END $$;
CREATE FUNCTION public.lomi_transport_write_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.channel_proposal; g public.pairing_grant;
BEGIN
 -- Parent lifecycle deletion may cascade through immutable receipt rows.
 IF TG_OP='DELETE' AND pg_trigger_depth()>1 THEN RETURN OLD; END IF;
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport write unavailable' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND ((classid::bigint<<32)|objid::bigint)=hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0)) THEN RAISE EXCEPTION 'transport write requires authorization lock' USING ERRCODE='42501'; END IF;
 IF TG_TABLE_NAME='channel_authority_invalidation' THEN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'immutable authority invalidation' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='channel_ticket' THEN
  IF TG_OP='INSERT' THEN
   IF NEW."tokenHash" IS NOT NULL OR NEW."creatorTransaction"<>txid_current() OR NEW."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'invalid ticket draft' USING ERRCODE='23514'; END IF;
  ELSIF TG_OP='DELETE' THEN
   IF OLD."tokenHash" IS NOT NULL OR OLD."creatorTransaction"<>txid_current() OR OLD."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'immutable ticket receipt' USING ERRCODE='23514'; END IF;RETURN OLD;
  ELSE
   IF OLD."tokenHash" IS NULL AND NEW."tokenHash" IS NOT NULL AND OLD."creatorTransaction"=txid_current() AND OLD."creatorBackend"=pg_backend_pid()
    AND (to_jsonb(NEW)-ARRAY['tokenHash','issuanceNumber','expiresAt']) IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['tokenHash','issuanceNumber','expiresAt']) THEN RETURN NEW; END IF;
   IF NOT OLD.superseded AND NEW.superseded AND OLD."tokenHash" IS NOT NULL AND OLD."consumedAt" IS NULL AND (to_jsonb(NEW)-'superseded') IS NOT DISTINCT FROM (to_jsonb(OLD)-'superseded') THEN RETURN NEW; END IF;
   IF OLD."consumedAt" IS NULL AND NEW."consumedAt" IS NOT NULL AND NOT OLD.superseded AND OLD."tokenHash" IS NOT NULL AND NEW."consumedAt"<OLD."expiresAt"
    AND (to_jsonb(NEW)-'consumedAt') IS NOT DISTINCT FROM (to_jsonb(OLD)-'consumedAt') THEN RETURN NEW; END IF;
   RAISE EXCEPTION 'immutable ticket receipt' USING ERRCODE='23514';
  END IF;
 ELSIF TG_TABLE_NAME='channel_transport_attempt' THEN
  IF TG_OP='DELETE' THEN
   IF OLD."creatorTransaction"<>txid_current() OR OLD."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'transport attempt transaction required' USING ERRCODE='23514'; END IF;RETURN OLD;
  END IF;
  IF TG_OP<>'INSERT' OR NEW."creatorTransaction"<>txid_current() OR NEW."creatorBackend"<>pg_backend_pid() THEN RAISE EXCEPTION 'immutable transport attempt' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT * INTO STRICT c FROM public.channel_proposal WHERE id=NEW."channelId";
  IF TG_OP='INSERT' THEN
   SELECT * INTO STRICT g FROM public.pairing_grant WHERE "grantId"=c."grantId";
   IF NEW.closed OR (NEW."accountId",NEW."hostId",NEW."grantExpiresAt") IS DISTINCT FROM (c."accountId",c."hostId",g."expiresAt"*1000)
    OR NEW."firstAttachedAt"<c."issuedAt"*1000 OR NEW."firstAttachedAt">=c."expiresAt"*1000
    OR (NEW."hostAttachedAt" IS NOT NULL AND NEW."hostAttachedAt"<>NEW."firstAttachedAt") OR (NEW."deviceAttachedAt" IS NOT NULL AND NEW."deviceAttachedAt"<>NEW."firstAttachedAt")
    OR (NEW."hostAttachedAt" IS NOT NULL AND NEW."deviceAttachedAt" IS NOT NULL) THEN RAISE EXCEPTION 'invalid transport binding' USING ERRCODE='23514'; END IF;
  ELSE
   IF NOT OLD.closed AND NEW.closed AND (to_jsonb(NEW)-'closed') IS NOT DISTINCT FROM (to_jsonb(OLD)-'closed') THEN RETURN NEW; END IF;
   IF OLD.closed OR NEW.closed OR (to_jsonb(NEW)-ARRAY['hostAttachedAt','deviceAttachedAt']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['hostAttachedAt','deviceAttachedAt'])
    OR (OLD."hostAttachedAt" IS NOT NULL AND NEW."hostAttachedAt" IS DISTINCT FROM OLD."hostAttachedAt") OR (OLD."deviceAttachedAt" IS NOT NULL AND NEW."deviceAttachedAt" IS DISTINCT FROM OLD."deviceAttachedAt")
    OR (NEW."hostAttachedAt" IS NOT DISTINCT FROM OLD."hostAttachedAt" AND NEW."deviceAttachedAt" IS NOT DISTINCT FROM OLD."deviceAttachedAt")
    OR (NEW."hostAttachedAt" IS NOT NULL AND NEW."hostAttachedAt">=c."expiresAt"*1000) OR (NEW."deviceAttachedAt" IS NOT NULL AND NEW."deviceAttachedAt">=c."expiresAt"*1000) THEN RAISE EXCEPTION 'immutable transport binding' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER channel_ticket_guard BEFORE INSERT OR UPDATE OR DELETE ON public.channel_ticket FOR EACH ROW EXECUTE FUNCTION public.lomi_transport_write_guard();
CREATE TRIGGER channel_transport_guard BEFORE INSERT OR UPDATE ON public.channel_transport FOR EACH ROW EXECUTE FUNCTION public.lomi_transport_write_guard();
CREATE TRIGGER channel_transport_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON public.channel_transport_attempt FOR EACH ROW EXECUTE FUNCTION public.lomi_transport_write_guard();
CREATE TRIGGER channel_authority_invalidation_guard BEFORE INSERT OR UPDATE ON public.channel_authority_invalidation FOR EACH ROW EXECUTE FUNCTION public.lomi_transport_write_guard();
CREATE FUNCTION public.lomi_transport_draft_commit_guard() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'transport commit unavailable' USING ERRCODE='42501'; END IF;
 IF TG_TABLE_NAME='channel_ticket' THEN
  IF EXISTS(SELECT FROM public.channel_ticket WHERE id=NEW.id AND "tokenHash" IS NULL) THEN RAISE EXCEPTION 'unfinished ticket draft' USING ERRCODE='23514'; END IF;
 ELSE
  IF EXISTS(SELECT FROM public.channel_transport_attempt WHERE id=NEW.id) THEN RAISE EXCEPTION 'unfinished transport attempt' USING ERRCODE='23514'; END IF;
 END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER channel_ticket_draft_finalized AFTER INSERT OR UPDATE ON public.channel_ticket DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_transport_draft_commit_guard();
CREATE CONSTRAINT TRIGGER channel_transport_attempt_finalized AFTER INSERT ON public.channel_transport_attempt DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_transport_draft_commit_guard();
REVOKE ALL ON public.channel_ticket,public.channel_transport,public.channel_transport_attempt,public.channel_authority_invalidation FROM PUBLIC;
REVOKE ALL ON FUNCTION public.lomi_transport_fence(uuid,boolean),
 public.lomi_channel_expiry_classify(),
 public.lomi_transport_evidence(uuid,boolean),
 public.lomi_transport_runtime(uuid,jsonb),
 public.lomi_transport_owner_live(text,bigint),
 public.lomi_ticket_prepare_apply(uuid,text),
 public.lomi_ticket_finalize_apply(uuid,text,bytea),
 public.lomi_transport_current(uuid,text,bigint,boolean),
 public.lomi_transport_consume_prepare(uuid,bytea,text,bigint),
 public.lomi_transport_consume_finalize(uuid,text,bigint),
 public.lomi_transport_validate_prepare(uuid,text,bigint),
 public.lomi_transport_validate_finalize(uuid,text,bigint),
 public.lomi_ticket_host_prepare(uuid,bytea,jsonb),
 public.lomi_ticket_host_finalize(uuid,bytea,jsonb,bytea),
 public.lomi_ticket_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb),
 public.lomi_ticket_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb,bytea),
 public.lomi_transport_write_guard(),
 public.lomi_transport_draft_commit_guard() FROM PUBLIC;
DO $seal$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON public.channel_ticket,public.channel_transport,public.channel_transport_attempt,public.channel_authority_invalidation FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_transport_fence(uuid,boolean),public.lomi_channel_expiry_classify(),public.lomi_transport_evidence(uuid,boolean),public.lomi_transport_runtime(uuid,jsonb),public.lomi_transport_owner_live(text,bigint),public.lomi_ticket_prepare_apply(uuid,text),public.lomi_ticket_finalize_apply(uuid,text,bytea),public.lomi_transport_current(uuid,text,bigint,boolean),public.lomi_transport_consume_prepare(uuid,bytea,text,bigint),public.lomi_transport_consume_finalize(uuid,text,bigint),public.lomi_transport_validate_prepare(uuid,text,bigint),public.lomi_transport_validate_finalize(uuid,text,bigint),public.lomi_ticket_host_prepare(uuid,bytea,jsonb),public.lomi_ticket_host_finalize(uuid,bytea,jsonb,bytea),public.lomi_ticket_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb),public.lomi_ticket_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb,bytea),public.lomi_transport_write_guard(),public.lomi_transport_draft_commit_guard() FROM %I',role_name);
  END IF;
 END LOOP;
END $seal$;
COMMIT;
