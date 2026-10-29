BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
CREATE ROLE lomi_consumer_auth_body_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER FUNCTION public.lomi_consumer_principal_live_v2(public.consumer_authorization) OWNER TO lomi_consumer_auth_body_owner;
ALTER FUNCTION public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea) OWNER TO lomi_consumer_auth_body_owner;
REVOKE ALL ON FUNCTION public.lomi_consumer_principal_live_v2(public.consumer_authorization),public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)
  FROM PUBLIC,lomi_migrator,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_pairing_write_owner,lomi_remote_inventory_owner;
GRANT EXECUTE ON FUNCTION public.lomi_consumer_principal_live_v2(public.consumer_authorization) TO lomi_runtime,lomi_remote_inventory_owner;
GRANT EXECUTE ON FUNCTION public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea) TO lomi_remote_inventory_owner;
CREATE OR REPLACE FUNCTION public.lomi_consumer_inventory(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE stamp timestamptz; h record; hosts jsonb:='[]'; result jsonb; public_context jsonb; live boolean; host_count integer:=0;
BEGIN
 IF current_user<>'lomi_remote_inventory_owner' THEN RAISE EXCEPTION 'inventory unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 stamp:=clock_timestamp();
 PERFORM public.lomi_consumer_scalar_recheck_v2(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
 SELECT jsonb_build_object('accountId',c."accountId",'consumerAuthorizationId',c.id,'accountSessionId',c."accountSessionId",
  'class',c."clientClass",'expiresAt',floor(extract(epoch FROM c."expiresAt"))::bigint::text,'canManageAccount',c."canManageAccount")
 INTO STRICT public_context FROM public.consumer_authorization c WHERE c.id=p_consumer;
 FOR h IN
  SELECT i."hostId",i."finalizedIdentity",i."hostKeyFingerprint",r."runtimeId",r.generation,r."hostAccessEpoch",
   r."leaseExpiresAt",r."freshUntil",r.workspaces,f."accessExpiresAt",f."idleExpiresAt"
  FROM public.host_identity i
  JOIN public.host_authorization f ON f."hostId"=i."hostId" AND f."accountId"=i."accountId" AND f."hostAccessEpoch"=i."accessEpoch"
  JOIN public.host_runtime r ON r."hostId"=i."hostId" AND r."authorizationId"=f.id AND r."hostAccessEpoch"=i."accessEpoch"
  WHERE i."accountId"=p_account AND i."finalizedIdentity" IS NOT NULL AND f.confirmed AND NOT f.revoked AND f."clientClass"='host'
   AND f."approvedAccountEpoch"=p_epoch AND r.generation>0 AND r."publicationSeq">0
   AND jsonb_typeof(r.workspaces)='array' AND jsonb_array_length(r.workspaces)>0
  ORDER BY i."hostId" LIMIT 257
 LOOP
  host_count:=host_count+1;
  IF host_count>256 OR NOT public.lomi_host_runtime_publication_valid(h.workspaces) THEN
   RAISE EXCEPTION 'inventory resource limit' USING ERRCODE='LR002'; END IF;
  live:=h."accessExpiresAt">stamp AND h."idleExpiresAt">stamp AND h."leaseExpiresAt">stamp AND h."freshUntil">stamp;
  hosts:=hosts||jsonb_build_array(jsonb_build_object(
   'hostId',h."hostId",'identity',h."finalizedIdentity",'identityFingerprint',encode(h."hostKeyFingerprint",'hex'),
   'runtime',jsonb_build_object('runtimeId',h."runtimeId",'runtimeGeneration',h.generation::text,'hostAccessEpoch',h."hostAccessEpoch"::text),
   'status',CASE WHEN live THEN 'online' ELSE 'offline' END,'workspaces',CASE WHEN live THEN h.workspaces ELSE '[]'::jsonb END));
  -- jsonb text includes whitespace, giving a conservative canonical JSON bound.
  IF octet_length(jsonb_build_object('authorization',public_context,'hosts',hosts)::text)>1048576 THEN
   RAISE EXCEPTION 'inventory resource limit' USING ERRCODE='LR002'; END IF;
 END LOOP;
 result:=jsonb_build_object('authorization',public_context,'hosts',hosts);
 RETURN result;
END $$;
CREATE OR REPLACE FUNCTION public.lomi_consumer_assertion_recheck(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea)
 RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_user<>'lomi_remote_inventory_owner' THEN RAISE EXCEPTION 'consumer assertion unavailable' USING ERRCODE='42501'; END IF;
 PERFORM public.lomi_consumer_scalar_recheck_v2(p_account,p_consumer,p_session,p_class,p_epoch,p_expiry_ms,p_manage,p_hash);
END $$;
CREATE OR REPLACE FUNCTION public.lomi_consumer_recipient_recheck(p_account uuid,p_consumer uuid)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE c public.consumer_authorization;
BEGIN
 IF current_user<>'lomi_remote_inventory_owner' THEN RAISE EXCEPTION 'recipient unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 SELECT * INTO c FROM public.consumer_authorization WHERE id=p_consumer AND "accountId"=p_account;
 IF NOT FOUND THEN RAISE EXCEPTION 'recipient unavailable' USING ERRCODE='28000'; END IF;
 PERFORM public.lomi_consumer_principal_live_v2(c);
 RETURN jsonb_build_object('accountId',c."accountId",'consumerAuthorizationId',c.id,'accountSessionId',c."accountSessionId",'class',c."clientClass",
  'authorizationEpoch',c."authorizationEpoch"::text,'expiresAtMs',(extract(epoch FROM c."expiresAt")*1000)::bigint::text,'canManageAccount',c."canManageAccount");
END $$;
REVOKE ALL ON FUNCTION public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea) FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner;
GRANT EXECUTE ON FUNCTION public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea) TO lomi_remote_pairing_write_owner;
COMMIT;