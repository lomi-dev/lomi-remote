-- SOURCE ONLY. Requires a separately approved credential-safe recorder.
-- Never submit through the existing raw-output f.sql/controller.
BEGIN;
SET LOCAL TIME ZONE 'UTC';
SET LOCAL search_path = pg_catalog, public, pg_temp;
DO $initial_identity$
BEGIN
 IF current_user <> 'e2_owner' OR session_user <> 'e2_owner' THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='positive-auth:initial-identity:P0001';
 END IF;
END $initial_identity$;
SET SESSION AUTHORIZATION lomi_runtime;
DO $setup$
DECLARE
 stage constant text := 'setup-runtime'; code text;
 u text := gen_random_uuid()::text;
 s text := 's5-positive-' || replace(gen_random_uuid()::text,'-','');
 secret text := replace(gen_random_uuid()::text,'-','') || replace(gen_random_uuid()::text,'-','');
 a uuid; epoch bigint; c uuid := gen_random_uuid();
 expiry timestamptz := date_trunc('milliseconds',clock_timestamp()) + interval '5 minutes';
 stamp timestamp; credential bytea;
BEGIN
 IF current_user <> 'lomi_runtime' OR session_user <> 'lomi_runtime'
  OR current_setting('TimeZone') <> 'UTC' THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 stamp := (expiry - interval '5 minutes') AT TIME ZONE 'UTC';
 credential := sha256(convert_to(secret,'UTF8'));
 IF octet_length(credential) <> 32 OR s !~ '^[!-~]+$' OR length(s) NOT BETWEEN 1 AND 128
  OR secret !~ '^[!-~]+$' OR secret = s THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 INSERT INTO public."user" (id,name,email,status,"createdAt","updatedAt")
 VALUES (u,'Synthetic positive principal',u || '@fixture.invalid','active',stamp,stamp);
 INSERT INTO public."session" (id,"userId",token,"expiresAt","createdAt","updatedAt")
 VALUES (s,u,secret,expiry AT TIME ZONE 'UTC',stamp,stamp);
 secret := NULL;
 INSERT INTO public.session_metadata ("sessionId",kind) VALUES (s,'browser');
 -- The reviewed runtime grant permits only this INSERT column. Use real defaults.
 INSERT INTO public.remote_account_identity ("userId") VALUES (u)
 RETURNING id,"authorizationEpoch" INTO a,epoch;
 IF a IS NULL OR epoch IS DISTINCT FROM 1::bigint THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 INSERT INTO public.remote_session_binding ("sessionId","userId","accountId","clientClass")
 VALUES (s,u,a,'web');
 INSERT INTO public.consumer_authorization
 (id,"accountId","userId","accountSessionId","originKind","originId","clientClass",
  "canManageAccount","authorizationEpoch","expiresAt",revoked,"consentId","serviceAuthorizationId")
 VALUES (c,a,u,s,'better_auth',s,'web',true,1,expiry,false,NULL,NULL);
 SET CONSTRAINTS ALL IMMEDIATE;
 -- Local identifiers/hash only; the token never enters a GUC or a result row.
 PERFORM set_config('lomi_positive.user_id',u,true);
 PERFORM set_config('lomi_positive.account_id',a::text,true);
 PERFORM set_config('lomi_positive.consumer_id',c::text,true);
 PERFORM set_config('lomi_positive.session_id',s,true);
 PERFORM set_config('lomi_positive.expiry',expiry::text,true);
 PERFORM set_config('lomi_positive.expiry_ms',((extract(epoch FROM expiry)*1000)::bigint)::text,true);
 PERFORM set_config('lomi_positive.credential_hash',encode(credential,'hex'),true);
 RAISE NOTICE 'positive-auth:setup-runtime:PASS';
EXCEPTION WHEN OTHERS THEN
 GET STACKED DIAGNOSTICS code = RETURNED_SQLSTATE;
 RAISE EXCEPTION USING ERRCODE=code,MESSAGE='positive-auth:setup-runtime:' || code,DETAIL='',HINT='';
END $setup$;

DO $principal$
DECLARE c public.consumer_authorization; code text;
BEGIN
 IF current_user <> 'lomi_runtime' OR session_user <> 'lomi_runtime' THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 SELECT * INTO STRICT c FROM public.consumer_authorization
 WHERE id=current_setting('lomi_positive.consumer_id')::uuid;
 IF (c."accountId",c."userId",c."accountSessionId",c."originKind",c."originId",c."clientClass",
     c."canManageAccount",c."authorizationEpoch",c."expiresAt",c.revoked,c."consentId",c."serviceAuthorizationId")
 IS DISTINCT FROM (current_setting('lomi_positive.account_id')::uuid,current_setting('lomi_positive.user_id'),
 current_setting('lomi_positive.session_id'),'better_auth',current_setting('lomi_positive.session_id'),'web',
 true,1::bigint,current_setting('lomi_positive.expiry')::timestamptz,false,NULL::uuid,NULL::text)
 THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 PERFORM public.lomi_consumer_principal_live_v2(c);
 RAISE NOTICE 'positive-auth:principal-runtime:PASS';
EXCEPTION WHEN OTHERS THEN
 GET STACKED DIAGNOSTICS code = RETURNED_SQLSTATE;
 RAISE EXCEPTION USING ERRCODE=code,MESSAGE='positive-auth:principal-runtime:' || code,DETAIL='',HINT='';
END $principal$;

SET SESSION AUTHORIZATION lomi_remote_inventory_owner;
DO $scalar$
DECLARE
 a uuid := current_setting('lomi_positive.account_id')::uuid;
 c uuid := current_setting('lomi_positive.consumer_id')::uuid;
 s text := current_setting('lomi_positive.session_id');
 ms bigint := current_setting('lomi_positive.expiry_ms')::bigint;
 good bytea := decode(current_setting('lomi_positive.credential_hash'),'hex');
 bad bytea; denied boolean := false; diagnostic text; code text;
BEGIN
 IF current_user <> 'lomi_remote_inventory_owner' OR session_user <> 'lomi_remote_inventory_owner'
 THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 bad := set_byte(good,0,get_byte(good,0) # 1);
 IF octet_length(good) <> 32 OR bad IS NOT DISTINCT FROM good THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 PERFORM public.lomi_consumer_scalar_recheck_v2(a,c,s,'web',1,ms,true,good);
 RAISE NOTICE 'positive-auth:scalar-invoker:PASS';
 BEGIN
  PERFORM public.lomi_consumer_scalar_recheck_v2(a,c,s,'web',1,ms,true,bad);
 EXCEPTION WHEN SQLSTATE '28000' THEN
  GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;
  IF diagnostic IS DISTINCT FROM 'actual credential required' THEN RAISE EXCEPTION 'fixture assertion'; END IF;
  denied := true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 RAISE NOTICE 'positive-auth:scalar-wronghash:PASS';
 PERFORM public.lomi_consumer_scalar_recheck_v2(a,c,s,'web',1,ms,true,good);
 RAISE NOTICE 'positive-auth:scalar-repeat:PASS';
EXCEPTION WHEN OTHERS THEN
 GET STACKED DIAGNOSTICS code = RETURNED_SQLSTATE;
 RAISE EXCEPTION USING ERRCODE=code,MESSAGE='positive-auth:scalar-group:' || code,DETAIL='',HINT='';
END $scalar$;

SET SESSION AUTHORIZATION lomi_remote_pairing_write_owner;
DO $roots$
DECLARE
 a uuid := current_setting('lomi_positive.account_id')::uuid;
 c uuid := current_setting('lomi_positive.consumer_id')::uuid;
 s text := current_setting('lomi_positive.session_id');
 ms bigint := current_setting('lomi_positive.expiry_ms')::bigint;
 good bytea := decode(current_setting('lomi_positive.credential_hash'),'hex');
 bad bytea; denied boolean := false; diagnostic text; code text; expected jsonb; actual jsonb;
BEGIN
 IF current_user <> 'lomi_remote_pairing_write_owner' OR session_user <> 'lomi_remote_pairing_write_owner'
 THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 bad := set_byte(good,0,get_byte(good,0) # 1);
 IF octet_length(good) <> 32 OR bad IS NOT DISTINCT FROM good THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 PERFORM public.lomi_consumer_assertion_recheck(a,c,s,'web',1,ms,true,good);
 RAISE NOTICE 'positive-auth:assertion-root:PASS';
 BEGIN
  PERFORM public.lomi_consumer_assertion_recheck(a,c,s,'web',1,ms,true,bad);
 EXCEPTION WHEN SQLSTATE '28000' THEN
  GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;
  IF diagnostic IS DISTINCT FROM 'actual credential required' THEN RAISE EXCEPTION 'fixture assertion'; END IF;
  denied := true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 RAISE NOTICE 'positive-auth:assertion-wronghash:PASS';
 PERFORM public.lomi_consumer_assertion_recheck(a,c,s,'web',1,ms,true,good);
 RAISE NOTICE 'positive-auth:assertion-repeat:PASS';
 expected := jsonb_build_object('accountId',a,'consumerAuthorizationId',c,'accountSessionId',s,
  'class','web','authorizationEpoch','1','expiresAtMs',ms::text,'canManageAccount',true);
 actual := public.lomi_consumer_recipient_recheck(a,c);
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 RAISE NOTICE 'positive-auth:recipient-root:PASS';
EXCEPTION WHEN OTHERS THEN
 GET STACKED DIAGNOSTICS code = RETURNED_SQLSTATE;
 RAISE EXCEPTION USING ERRCODE=code,MESSAGE='positive-auth:roots-group:' || code,DETAIL='',HINT='';
END $roots$;

SET SESSION AUTHORIZATION lomi_remote_api;
DO $typed$
DECLARE
 a uuid := current_setting('lomi_positive.account_id')::uuid;
 c uuid := current_setting('lomi_positive.consumer_id')::uuid;
 s text := current_setting('lomi_positive.session_id');
 ms bigint := current_setting('lomi_positive.expiry_ms')::bigint;
 good bytea := decode(current_setting('lomi_positive.credential_hash'),'hex');
 bad bytea; p public.lomi_consumer_assertion_v2;
 denied boolean := false; diagnostic text; code text; expected jsonb; actual jsonb;
BEGIN
 IF current_user <> 'lomi_remote_api' OR session_user <> 'lomi_remote_api' THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 bad := set_byte(good,0,get_byte(good,0) # 1);
 IF octet_length(good) <> 32 OR bad IS NOT DISTINCT FROM good THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 p := ROW(2,a,c,s,'web',1::bigint,ms,true,'better_auth',s,NULL::text,NULL::uuid,NULL::integer,good)::public.lomi_consumer_assertion_v2;
 expected := jsonb_build_object('authorization',jsonb_build_object('accountId',a,
  'consumerAuthorizationId',c,'accountSessionId',s,'class','web','expiresAt',(ms/1000)::text,
  'canManageAccount',true),'hosts','[]'::jsonb);
 actual := public.lomi_consumer_inventory_v2(p);
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 RAISE NOTICE 'positive-auth:typed-inventory:PASS';
 p."credentialHash" := bad;
 BEGIN
  actual := public.lomi_consumer_inventory_v2(p);
 EXCEPTION WHEN SQLSTATE '28000' THEN
  GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;
  IF diagnostic IS DISTINCT FROM 'actual credential required' THEN RAISE EXCEPTION 'fixture assertion'; END IF;
  denied := true;
 END;
 IF NOT denied THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 RAISE NOTICE 'positive-auth:typed-wronghash:PASS';
 p."credentialHash" := good;
 actual := public.lomi_consumer_inventory_v2(p);
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'fixture assertion'; END IF;
 RAISE NOTICE 'positive-auth:typed-repeat:PASS';
EXCEPTION WHEN OTHERS THEN
 GET STACKED DIAGNOSTICS code = RETURNED_SQLSTATE;
 RAISE EXCEPTION USING ERRCODE=code,MESSAGE='positive-auth:typed-group:' || code,DETAIL='',HINT='';
END $typed$;
RESET SESSION AUTHORIZATION;
ROLLBACK;
-- Fixed protocol marker only. Future parent must independently verify row counts,
-- exact catalog/metadata and session closure before accepting this group.
DO $rolled_back$
BEGIN
 IF current_user <> 'e2_owner' OR session_user <> 'e2_owner'
  OR nullif(current_setting('lomi_positive.credential_hash',true),'') IS NOT NULL
 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='positive-auth:rollback:P0001'; END IF;
 RAISE NOTICE 'positive-auth:rollback:PASS';
END $rolled_back$;
