-- REVIEW CANDIDATE ONLY. NULL pins make this operator transition unexecutable.
-- Install core once, seal these two bodies, then validate/switch the three roots.
BEGIN;
DO $seal_helpers$
DECLARE pins jsonb := $helper_pins$[{"signature": "public.lomi_consumer_principal_live_v2(public.consumer_authorization)", "old_owner": "lomi_migrator", "new_owner": "lomi_consumer_auth_body_owner", "old_catalog_sha256": "5e920b1c9f7b37facc3236bf1d7b4f766a34d3b85e7e4ecceb9a83aac1fcff99", "new_catalog_sha256": "5e920b1c9f7b37facc3236bf1d7b4f766a34d3b85e7e4ecceb9a83aac1fcff99", "old_acl": [{"grantee":"lomi_migrator","grantor":"lomi_migrator","grantable":false,"privilege":"EXECUTE"}], "new_acl": [{"grantee":"lomi_runtime","grantor":"lomi_consumer_auth_body_owner","grantable":false,"privilege":"EXECUTE"},{"grantee":"lomi_remote_inventory_owner","grantor":"lomi_consumer_auth_body_owner","grantable":false,"privilege":"EXECUTE"},{"grantee":"lomi_consumer_auth_body_owner","grantor":"lomi_consumer_auth_body_owner","grantable":false,"privilege":"EXECUTE"}], "source_sha256": "305bfbf0bb2aa22df64c56b01b6d7e36ecdab881b03875a3e4c683a95655db42"}, {"signature": "public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)", "old_owner": "lomi_migrator", "new_owner": "lomi_consumer_auth_body_owner", "old_catalog_sha256": "6d8f0df55e8416489c4e9707eff2e78d7fa999288596367926f395b25d8a237d", "new_catalog_sha256": "6d8f0df55e8416489c4e9707eff2e78d7fa999288596367926f395b25d8a237d", "old_acl": [{"grantee":"lomi_migrator","grantor":"lomi_migrator","grantable":false,"privilege":"EXECUTE"}], "new_acl": [{"grantee":"lomi_remote_inventory_owner","grantor":"lomi_consumer_auth_body_owner","grantable":false,"privilege":"EXECUTE"},{"grantee":"lomi_consumer_auth_body_owner","grantor":"lomi_consumer_auth_body_owner","grantable":false,"privilege":"EXECUTE"}], "source_sha256": "51db96ac50196ec8af6f0df3cfc021724a69fe49c32cd991e76148b2d6e773b6"}]$helper_pins$::jsonb;
 r jsonb; p record; body_owner record; actual_acl jsonb; seen_old integer:=0; seen_new integer:=0;
BEGIN
 IF NOT current_setting('is_superuser')::boolean OR current_setting('server_version_num')::integer<>180006 THEN RAISE EXCEPTION 'operator and exact PostgreSQL 18.6 required'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='lomi_migrator' AND NOT rolsuper AND NOT rolcreaterole) THEN RAISE EXCEPTION 'routine migrator must lack owner-bypass authority'; END IF;
 FOR r IN SELECT value FROM jsonb_array_elements(pins) LOOP
  IF r->>'old_catalog_sha256' IS NULL OR r->>'new_catalog_sha256' IS NULL OR r->'old_acl'='null'::jsonb OR r->'new_acl'='null'::jsonb THEN RAISE EXCEPTION 'unmeasured helper catalog/ACL pins'; END IF;
  SELECT * INTO STRICT p FROM pg_proc WHERE oid=(r->>'signature')::regprocedure;
  SELECT coalesce(jsonb_agg(jsonb_build_object('grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
   'privilege',x.privilege_type,'grantable',x.is_grantable) ORDER BY x.grantor,x.grantee,x.privilege_type,x.is_grantable),'[]'::jsonb)
   INTO actual_acl FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) x;
  IF p.prosecdef THEN RAISE EXCEPTION 'authentication body must remain invoker'; END IF;
  IF pg_get_userbyid(p.proowner)=r->>'old_owner' AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')=r->>'old_catalog_sha256' AND actual_acl=r->'old_acl' THEN seen_old:=seen_old+1;
  ELSIF pg_get_userbyid(p.proowner)=r->>'new_owner' AND encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')=r->>'new_catalog_sha256' AND actual_acl=r->'new_acl' THEN seen_new:=seen_new+1;
  ELSE RAISE EXCEPTION 'unexpected helper definition/owner/ACL: %',r->>'signature'; END IF;
 END LOOP;
 IF NOT ((seen_old=2 AND seen_new=0) OR (seen_new=2 AND seen_old=0)) THEN RAISE EXCEPTION 'mixed helper seal state'; END IF;
 IF seen_new=2 AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname='lomi_consumer_auth_body_owner') THEN RAISE EXCEPTION 'missing sealed body owner'; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='lomi_consumer_auth_body_owner') THEN
  CREATE ROLE lomi_consumer_auth_body_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 SELECT * INTO STRICT body_owner FROM pg_roles WHERE rolname='lomi_consumer_auth_body_owner';
 IF body_owner.rolcanlogin OR body_owner.rolinherit OR body_owner.rolsuper OR body_owner.rolcreatedb OR body_owner.rolcreaterole OR body_owner.rolreplication OR body_owner.rolbypassrls OR body_owner.rolconfig IS NOT NULL
  OR has_schema_privilege(body_owner.oid,'public','CREATE') OR EXISTS(SELECT FROM pg_auth_members WHERE member=body_owner.oid OR roleid=body_owner.oid) THEN
  RAISE EXCEPTION 'body owner must be unreachable and retain no broad capability'; END IF;
 IF seen_new=2 THEN RETURN; END IF;
 ALTER FUNCTION public.lomi_consumer_principal_live_v2(public.consumer_authorization) OWNER TO lomi_consumer_auth_body_owner;
 ALTER FUNCTION public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea) OWNER TO lomi_consumer_auth_body_owner;
 REVOKE ALL ON FUNCTION public.lomi_consumer_principal_live_v2(public.consumer_authorization),public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)
  FROM PUBLIC,lomi_migrator,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_pairing_write_owner,lomi_remote_inventory_owner;
 GRANT EXECUTE ON FUNCTION public.lomi_consumer_principal_live_v2(public.consumer_authorization) TO lomi_runtime,lomi_remote_inventory_owner;
 GRANT EXECUTE ON FUNCTION public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea) TO lomi_remote_inventory_owner;
 FOR r IN SELECT value FROM jsonb_array_elements(pins) LOOP
  SELECT * INTO STRICT p FROM pg_proc WHERE oid=(r->>'signature')::regprocedure;
  SELECT coalesce(jsonb_agg(jsonb_build_object('grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
   'privilege',x.privilege_type,'grantable',x.is_grantable) ORDER BY x.grantor,x.grantee,x.privilege_type,x.is_grantable),'[]'::jsonb)
   INTO actual_acl FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) x;
  IF p.prosecdef OR pg_get_userbyid(p.proowner)<>r->>'new_owner' OR encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex')<>r->>'new_catalog_sha256' OR actual_acl IS DISTINCT FROM r->'new_acl' THEN
   RAISE EXCEPTION 'helper seal post-state mismatch: %',r->>'signature'; END IF;
 END LOOP;
END $seal_helpers$;
COMMIT;
