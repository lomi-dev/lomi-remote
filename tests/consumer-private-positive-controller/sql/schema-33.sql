-- REVIEW CANDIDATE ONLY. New entrypoints remain default-deny until operator sealing.
BEGIN;
CREATE FUNCTION public.lomi_consumer_inventory_v2(p public.lomi_consumer_assertion_v2) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_consumer_inventory(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash");
END $$;
REVOKE ALL ON FUNCTION public.lomi_consumer_inventory_v2(public.lomi_consumer_assertion_v2) FROM PUBLIC;
CREATE FUNCTION public.lomi_pairing_create_prepare_v2(p public.lomi_consumer_assertion_v2,p_request jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_pairing_create_prepare(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash",p_request);
END $$;
REVOKE ALL ON FUNCTION public.lomi_pairing_create_prepare_v2(public.lomi_consumer_assertion_v2,jsonb) FROM PUBLIC;
CREATE FUNCTION public.lomi_pairing_finalize_v2(p public.lomi_consumer_assertion_v2,p_pairing uuid,p_maximum text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_pairing_finalize(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash",p_pairing,p_maximum);
END $$;
REVOKE ALL ON FUNCTION public.lomi_pairing_finalize_v2(public.lomi_consumer_assertion_v2,uuid,text) FROM PUBLIC;
CREATE FUNCTION public.lomi_pairing_peer_consumer_read_v2(p public.lomi_consumer_assertion_v2,p_pairing uuid) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_pairing_peer_consumer_read(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash",p_pairing);
END $$;
REVOKE ALL ON FUNCTION public.lomi_pairing_peer_consumer_read_v2(public.lomi_consumer_assertion_v2,uuid) FROM PUBLIC;
CREATE FUNCTION public.lomi_grant_consumer_revoke_v2(p public.lomi_consumer_assertion_v2,p_grant uuid,p_expected numeric) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_grant_consumer_revoke(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash",p_grant,p_expected);
END $$;
REVOKE ALL ON FUNCTION public.lomi_grant_consumer_revoke_v2(public.lomi_consumer_assertion_v2,uuid,numeric) FROM PUBLIC;
CREATE FUNCTION public.lomi_channel_consumer_prepare_v2(p public.lomi_consumer_assertion_v2,p_request jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_channel_consumer_prepare(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash",p_request);
END $$;
REVOKE ALL ON FUNCTION public.lomi_channel_consumer_prepare_v2(public.lomi_consumer_assertion_v2,jsonb) FROM PUBLIC;
CREATE FUNCTION public.lomi_channel_peer_consumer_read_v2(p public.lomi_consumer_assertion_v2,p_channel uuid) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_channel_peer_consumer_read(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash",p_channel);
END $$;
REVOKE ALL ON FUNCTION public.lomi_channel_peer_consumer_read_v2(public.lomi_consumer_assertion_v2,uuid) FROM PUBLIC;
CREATE FUNCTION public.lomi_channel_consumer_finalize_v2(p public.lomi_consumer_assertion_v2,p_channel uuid,p_expected text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_channel_consumer_finalize(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash",p_channel,p_expected);
END $$;
REVOKE ALL ON FUNCTION public.lomi_channel_consumer_finalize_v2(public.lomi_consumer_assertion_v2,uuid,text) FROM PUBLIC;
CREATE FUNCTION public.lomi_ticket_consumer_prepare_v2(p public.lomi_consumer_assertion_v2,p_channel uuid,p_runtime jsonb) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_ticket_consumer_prepare(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash",p_channel,p_runtime);
END $$;
REVOKE ALL ON FUNCTION public.lomi_ticket_consumer_prepare_v2(public.lomi_consumer_assertion_v2,uuid,jsonb) FROM PUBLIC;
CREATE FUNCTION public.lomi_ticket_consumer_finalize_v2(p public.lomi_consumer_assertion_v2,p_ticket uuid,p_runtime jsonb,p_token_hash bytea) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_pairing_write_owner' THEN RAISE EXCEPTION 'typed consumer entrypoint unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_assertion_v2_recheck(p);
 RETURN public.lomi_ticket_consumer_finalize(p."accountId",p."consumerAuthorizationId",p."accountSessionId",p."clientClass",p."authorizationEpoch",p."expiresAtMs",p."canManageAccount",p."credentialHash",p_ticket,p_runtime,p_token_hash);
END $$;
REVOKE ALL ON FUNCTION public.lomi_ticket_consumer_finalize_v2(public.lomi_consumer_assertion_v2,uuid,jsonb,bytea) FROM PUBLIC;
-- GENERATED default-deny closure below.
DO $default_deny$
DECLARE role_name text; signature text;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_consumer_inventory_v2(public.lomi_consumer_assertion_v2) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_pairing_create_prepare_v2(public.lomi_consumer_assertion_v2,jsonb) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_pairing_finalize_v2(public.lomi_consumer_assertion_v2,uuid,text) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_pairing_peer_consumer_read_v2(public.lomi_consumer_assertion_v2,uuid) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_grant_consumer_revoke_v2(public.lomi_consumer_assertion_v2,uuid,numeric) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_channel_consumer_prepare_v2(public.lomi_consumer_assertion_v2,jsonb) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_channel_peer_consumer_read_v2(public.lomi_consumer_assertion_v2,uuid) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_channel_consumer_finalize_v2(public.lomi_consumer_assertion_v2,uuid,text) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_ticket_consumer_prepare_v2(public.lomi_consumer_assertion_v2,uuid,jsonb) FROM %I',role_name);
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_ticket_consumer_finalize_v2(public.lomi_consumer_assertion_v2,uuid,jsonb,bytea) FROM %I',role_name);
  END IF;
 END LOOP;
END $default_deny$;
COMMIT;
