-- Read-only direct-consumer inventory. Creation and PUBLIC revocation are atomic;
-- the operator seals the separate execution owner after ordinary migrations.
BEGIN;
CREATE FUNCTION public.lomi_consumer_inventory(p_account uuid,p_consumer uuid,p_session text,p_class text,p_epoch bigint,p_expiry_ms bigint,p_manage boolean,p_hash bytea)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE stamp timestamptz; h record; hosts jsonb:='[]'; result jsonb; public_context jsonb; live boolean; host_count integer:=0;
BEGIN
 IF current_user<>'lomi_remote_inventory_owner' THEN RAISE EXCEPTION 'inventory unavailable' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 stamp:=clock_timestamp();
 IF p_account IS NULL OR p_consumer IS NULL OR p_session IS NULL OR length(p_session) NOT BETWEEN 1 AND 128 OR p_session !~ '^[!-~]+$'
  OR p_class IS NULL OR p_class NOT IN ('web','desktop') OR p_epoch IS NULL OR p_epoch<1 OR p_expiry_ms IS NULL OR p_expiry_ms<1
  OR p_manage IS NULL OR p_hash IS NULL OR octet_length(p_hash)<>32 THEN
  RAISE EXCEPTION 'consumer authority required' USING ERRCODE='28000';
 END IF;
 -- Normal SELECT is deliberate: this execution owner has no UPDATE privilege.
 -- All authority operations serialize on the exact shared global Auth lock.
 SELECT jsonb_build_object(
   'accountId',c."accountId",'consumerAuthorizationId',c.id,'accountSessionId',c."accountSessionId",
   'class',c."clientClass",'expiresAt',floor(extract(epoch FROM c."expiresAt"))::bigint::text,'canManageAccount',c."canManageAccount"
  ) INTO public_context FROM public.consumer_authorization c
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
REVOKE ALL ON FUNCTION public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea) FROM PUBLIC;
DO $seal$ DECLARE role_name text; BEGIN
 FOREACH role_name IN ARRAY ARRAY['lomi_runtime','lomi_remote_api','lomi_remote_exchange'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=role_name) THEN
   EXECUTE format('REVOKE ALL ON FUNCTION public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea) FROM %I',role_name);
  END IF;
 END LOOP;
END $seal$;
COMMIT;
