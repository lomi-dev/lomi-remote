-- Either-own-peer reads and authority-reducing revocation only. Original signed
-- grants remain immutable; a revision-two overlay and pairing tombstone commit
-- atomically. No channels, tickets, or relay authority is introduced.
BEGIN;
CREATE TABLE public.grant_revocation (
 "grantId" uuid PRIMARY KEY REFERENCES public.pairing_grant("grantId") ON DELETE CASCADE,
 "pairingId" uuid NOT NULL UNIQUE REFERENCES public.pairing_proposal(id) ON DELETE CASCADE,
 "expectedGrantRevision" bigint NOT NULL CHECK ("expectedGrantRevision"=1),
 "grantRevision" bigint NOT NULL CHECK ("grantRevision"=2),
 "createdAt" timestamptz(3) NOT NULL
);
CREATE FUNCTION public.lomi_grant_revocation_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'grant revocation write unavailable' USING ERRCODE='42501'; END IF;
 IF TG_OP<>'INSERT' OR NOT EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1
  AND ((classid::bigint<<32)|objid::bigint)=hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0)) THEN
  RAISE EXCEPTION 'immutable grant revocation' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT FROM public.pairing_grant g JOIN public.pairing_decision d ON d."pairingId"=g."pairingId"
  WHERE g."grantId"=NEW."grantId" AND g."pairingId"=NEW."pairingId" AND g."grantRevision"=1 AND d.decision='approve') THEN
  RAISE EXCEPTION 'invalid grant revocation binding' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER grant_revocation_guard BEFORE INSERT OR UPDATE ON public.grant_revocation FOR EACH ROW EXECUTE FUNCTION public.lomi_grant_revocation_guard();
CREATE FUNCTION public.lomi_grant_revocation_commit_guard() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'grant revocation commit unavailable' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT FROM public.grant_revocation r JOIN public.pairing_proposal p ON p.id=r."pairingId" WHERE r."grantId"=NEW."grantId" AND NOT p.expired) THEN
  RAISE EXCEPTION 'grant revocation requires pairing tombstone' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER grant_revocation_tombstone AFTER INSERT ON public.grant_revocation
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.lomi_grant_revocation_commit_guard();
CREATE FUNCTION public.lomi_pairing_peer_host_read(p_pairing uuid,p_hash bytea)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE p public.pairing_proposal; h record;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing peer read unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO p FROM public.pairing_proposal WHERE id=p_pairing;
 IF NOT FOUND THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 SELECT * INTO STRICT h FROM public.lomi_host_access_lookup(p."hostId",p_hash);
 IF (h."hostId",h."accountId",h."authorizationId") IS DISTINCT FROM (p."hostId",p."accountId",(p.authority->>'hostAuthorizationId')::uuid) THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 RETURN public.lomi_pairing_retained(p.id);
END $$;
CREATE FUNCTION public.lomi_pairing_peer_consumer_read(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_pairing uuid)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE p public.pairing_proposal;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'pairing peer read unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 SELECT * INTO p FROM public.pairing_proposal WHERE id=p_pairing AND "accountId"=p_account AND "consumerAuthorizationId"=p_consumer;
 IF NOT FOUND THEN RAISE EXCEPTION 'pairing unavailable' USING ERRCODE='LR004'; END IF;
 RETURN public.lomi_pairing_retained(p.id);
END $$;
-- Private apply stage: ownership is established by a public entry point first.
-- Submitted expectations are numeric to preserve the full canonical u64 domain.
CREATE FUNCTION public.lomi_grant_revoke_apply(p_grant uuid,p_expected numeric)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE g public.pairing_grant; actual bigint; expected text;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'grant revocation unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF p_expected IS NULL OR p_expected<0 OR p_expected>18446744073709551615::numeric OR p_expected<>trunc(p_expected) THEN RAISE EXCEPTION 'invalid grant revision' USING ERRCODE='22023'; END IF;
 expected:=trunc(p_expected)::text;
 SELECT * INTO STRICT g FROM public.pairing_grant WHERE "grantId"=p_grant;
 SELECT "grantRevision" INTO actual FROM public.grant_revocation WHERE "grantId"=g."grantId";
 actual:=COALESCE(actual,g."grantRevision");
 IF (actual=1 AND p_expected<>1) OR (actual=2 AND p_expected NOT IN (1,2)) THEN
  RETURN jsonb_build_object('conflict',jsonb_build_object('expectedRevision',expected,'actualRevision',actual::text)); END IF;
 IF actual=1 THEN
  INSERT INTO public.grant_revocation VALUES(g."grantId",g."pairingId",1,2,date_trunc('milliseconds',clock_timestamp()));
 END IF;
 UPDATE public.pairing_proposal SET expired=true WHERE id=g."pairingId" AND NOT expired;
 RETURN jsonb_build_object('grantId',g."grantId",'grantRevision','2');
END $$;
CREATE FUNCTION public.lomi_grant_host_revoke(p_grant uuid,p_hash bytea,p_expected numeric)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE g public.pairing_grant; h record;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'grant revocation unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO g FROM public.pairing_grant WHERE "grantId"=p_grant;
 IF NOT FOUND THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 SELECT * INTO STRICT h FROM public.lomi_host_access_lookup(g."hostId",p_hash);
 IF (h."hostId",h."accountId",h."authorizationId") IS DISTINCT FROM (g."hostId",g."accountId",g."hostAuthorizationId") THEN RAISE EXCEPTION 'host authority required' USING ERRCODE='28000'; END IF;
 RETURN public.lomi_grant_revoke_apply(g."grantId",p_expected);
END $$;
CREATE FUNCTION public.lomi_grant_consumer_revoke(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea,p_grant uuid,p_expected numeric)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE g public.pairing_grant;
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'grant revocation unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 PERFORM public.lomi_consumer_assertion_recheck(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 SELECT * INTO g FROM public.pairing_grant WHERE "grantId"=p_grant AND "accountId"=p_account AND "consumerAuthorizationId"=p_consumer AND "accountSessionId"=p_session;
 IF NOT FOUND THEN RAISE EXCEPTION 'grant unavailable' USING ERRCODE='LR004'; END IF;
 RETURN public.lomi_grant_revoke_apply(g."grantId",p_expected);
END $$;
REVOKE ALL ON public.grant_revocation FROM PUBLIC;
REVOKE ALL ON FUNCTION public.lomi_grant_revocation_guard(),public.lomi_grant_revocation_commit_guard(),
 public.lomi_pairing_peer_host_read(uuid,bytea),public.lomi_pairing_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid),
 public.lomi_grant_revoke_apply(uuid,numeric),public.lomi_grant_host_revoke(uuid,bytea,numeric),public.lomi_grant_consumer_revoke(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,numeric) FROM PUBLIC;
DO $seal$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON public.grant_revocation FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_grant_revocation_guard(),public.lomi_grant_revocation_commit_guard(),public.lomi_pairing_peer_host_read(uuid,bytea),public.lomi_pairing_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid),public.lomi_grant_revoke_apply(uuid,numeric),public.lomi_grant_host_revoke(uuid,bytea,numeric),public.lomi_grant_consumer_revoke(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,numeric) FROM %I',role_name);
  END IF;
 END LOOP;
END $seal$;
COMMIT;
