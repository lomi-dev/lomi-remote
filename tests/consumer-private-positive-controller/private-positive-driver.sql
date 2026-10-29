-- Source-only private driver. Never emit raw snapshots or table contents.
-- The unchanged include emits exactly the original thirteen NOTICE markers.
-- TEMP baseline is committed before the included BEGIN and survives ROLLBACK.
SET search_path = pg_catalog, public, pg_temp;
CREATE TEMPORARY VIEW lomi_private_snapshot AS
SELECT 1::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
-- PREPARED ONLY. Exact raw catalog bytes; no text normalization/substitutions.
-- Run separately in reference-old/reference-new and target after source identity
-- admission. A target record alone is never authority to populate a pin.
WITH expected(signature) AS (VALUES
 ('public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)'),
 ('public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea)'),
 ('public.lomi_consumer_recipient_recheck(uuid,uuid)'),
 ('public.lomi_consumer_principal_live_v2(public.consumer_authorization)'),
 ('public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)'),
 ('public.lomi_consumer_assertion_v2_recheck(public.lomi_consumer_assertion_v2)'),
 ('public.lomi_consumer_require_live(public.consumer_authorization)'),
 ('public.lomi_consumer_authorization_guard()'),
 ('public.lomi_derivative_birth_guard_v2()'),
 ('public.lomi_derivative_consent_guard_v2()'),
 ('public.lomi_consumer_inventory_v2(public.lomi_consumer_assertion_v2)'),
 ('public.lomi_pairing_create_prepare_v2(public.lomi_consumer_assertion_v2,jsonb)'),
 ('public.lomi_pairing_finalize_v2(public.lomi_consumer_assertion_v2,uuid,text)'),
 ('public.lomi_pairing_peer_consumer_read_v2(public.lomi_consumer_assertion_v2,uuid)'),
 ('public.lomi_grant_consumer_revoke_v2(public.lomi_consumer_assertion_v2,uuid,numeric)'),
 ('public.lomi_channel_consumer_prepare_v2(public.lomi_consumer_assertion_v2,jsonb)'),
 ('public.lomi_channel_peer_consumer_read_v2(public.lomi_consumer_assertion_v2,uuid)'),
 ('public.lomi_channel_consumer_finalize_v2(public.lomi_consumer_assertion_v2,uuid,text)'),
 ('public.lomi_ticket_consumer_prepare_v2(public.lomi_consumer_assertion_v2,uuid,jsonb)'),
 ('public.lomi_ticket_consumer_finalize_v2(public.lomi_consumer_assertion_v2,uuid,jsonb,bytea)'),
 ('public.lomi_approval_source_delete_lock_v2()'),
 ('public.lomi_approval_source_require_v2(public.consumer_approval_intent,boolean)'),
 ('public.lomi_approval_consumed_proof_guard_v2()'),
 ('public.lomi_approval_intent_guard_v2()'),
 ('public.lomi_approval_flow_guard_v2()'),
 ('public.lomi_approval_exchange_complete_v2(uuid)'),
 ('public.lomi_approval_deferred_guard_v2()')
), functions AS (SELECT signature,p.* FROM expected JOIN pg_proc p ON p.oid=signature::regprocedure)
SELECT jsonb_build_object('kind','function','signature',f.signature,'owner',pg_get_userbyid(f.proowner),'securityDefiner',f.prosecdef,'config',f.proconfig,
 'definitionUtf8Hex',encode(convert_to(pg_get_functiondef(f.oid),'UTF8'),'hex'),
 'catalogSha256',encode(sha256(convert_to(pg_get_functiondef(f.oid),'UTF8')),'hex'),
 'acl',coalesce((SELECT jsonb_agg(jsonb_build_object('grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,'privilege',x.privilege_type,'grantable',x.is_grantable) ORDER BY x.grantor,x.grantee,x.privilege_type,x.is_grantable)
 FROM aclexplode(coalesce(f.proacl,acldefault('f',f.proowner))) x),'[]'::jsonb))
FROM functions f ORDER BY f.signature
) AS fixed_rows(value)
UNION ALL
SELECT 2::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (

-- No row data, credentials, role passwords or operator configuration is queried.
SELECT jsonb_build_object('kind','role','name',rolname,'login',rolcanlogin,'inherit',rolinherit,'super',rolsuper,'createRole',rolcreaterole,'createDb',rolcreatedb,'replication',rolreplication,'bypassRls',rolbypassrls,'config',rolconfig)
FROM pg_roles WHERE rolname IN ('e2_owner','lomi_migrator','lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner','lomi_consumer_auth_body_owner','fixture_unexpected') ORDER BY rolname
) AS fixed_rows(value)
UNION ALL
SELECT 3::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','membership','role',pg_get_userbyid(roleid),'member',pg_get_userbyid(member),'admin',admin_option,'inherit',inherit_option,'set',set_option) FROM pg_auth_members ORDER BY roleid,member
) AS fixed_rows(value)
UNION ALL
SELECT 4::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','defaultAcl','owner',pg_get_userbyid(defaclrole),'namespace',defaclnamespace,'objectType',defaclobjtype,'grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,'privilege',x.privilege_type,'grantable',x.is_grantable)
FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) x ORDER BY defaclrole,defaclnamespace,defaclobjtype,x.grantee,x.privilege_type
) AS fixed_rows(value)
UNION ALL
SELECT 5::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
WITH protected AS (SELECT unnest(ARRAY['public.consumer_approval_intent','public.consumer_approval_consumed_proof','public.consumer_derivative_consent','public.consumer_authorization'])::regclass AS oid)
SELECT jsonb_build_object('kind','protectedAcl','relation',p.oid::text,'column',a.attname,'tableAcl',c.relacl,'columnAcl',a.attacl,'owner',pg_get_userbyid(c.relowner)) FROM protected p JOIN pg_class c ON c.oid=p.oid JOIN pg_attribute a ON a.attrelid=p.oid AND a.attnum>0 AND NOT a.attisdropped ORDER BY p.oid,a.attnum
) AS fixed_rows(value)
UNION ALL
SELECT 6::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','assertionTypeAcl','owner',pg_get_userbyid(typowner),'acl',typacl) FROM pg_type WHERE oid='public.lomi_consumer_assertion_v2'::regtype
) AS fixed_rows(value)
UNION ALL
SELECT 7::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
-- Additional raw schema/ACL evidence, no application rows or role passwords.
SELECT jsonb_build_object('kind','objectAcl','relation',c.oid::regclass::text,
 'owner',pg_get_userbyid(c.relowner),'grantor',pg_get_userbyid(x.grantor),
 'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
 'privilege',x.privilege_type,'grantable',x.is_grantable)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) x
WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
ORDER BY c.relname,x.grantor,x.grantee,x.privilege_type
) AS fixed_rows(value)
UNION ALL
SELECT 8::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','columnAcl','relation',c.oid::regclass::text,'column',a.attname,
 'grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
 'privilege',x.privilege_type,'grantable',x.is_grantable)
FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped
ORDER BY c.relname,a.attnum,x.grantee,x.privilege_type
) AS fixed_rows(value)
UNION ALL
SELECT 9::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','schemaAuthority','role',r.rolname,
 'create',has_schema_privilege(r.oid,n.oid,'CREATE'),'usage',has_schema_privilege(r.oid,n.oid,'USAGE'))
FROM pg_roles r CROSS JOIN pg_namespace n WHERE n.nspname='public' ORDER BY r.rolname
) AS fixed_rows(value)
UNION ALL
SELECT 10::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','constraint','relation',conrelid::regclass::text,'name',conname,
 'definition',pg_get_constraintdef(oid,false),'validated',convalidated,'deferrable',condeferrable,'deferred',condeferred)
FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY conrelid::regclass::text,conname
) AS fixed_rows(value)
UNION ALL
SELECT 11::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','trigger','relation',tgrelid::regclass::text,'name',tgname,
 'definition',pg_get_triggerdef(oid,false),'enabled',tgenabled,'internal',tgisinternal,
 'constraint',(SELECT conname FROM pg_constraint WHERE oid=tgconstraint),
 'function',tgfoid::regprocedure::text,'type',tgtype,'argsHex',encode(tgargs,'hex'),
 'deferrable',tgdeferrable,'deferred',tginitdeferred,
 'referencedRelation',tgconstrrelid::regclass::text,'constraintIndex',tgconstrindid::regclass::text,
 'columns',tgattr::text,
 'whenTriggerDefinition',CASE WHEN tgqual IS NULL THEN NULL ELSE pg_get_triggerdef(oid,false) END)
FROM pg_trigger WHERE tgrelid IN (SELECT c.oid FROM pg_class c WHERE c.relnamespace='public'::regnamespace)
ORDER BY tgrelid::regclass::text,tgname
) AS fixed_rows(value)
UNION ALL
SELECT 12::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','index','relation',indrelid::regclass::text,'name',indexrelid::regclass::text,
 'definition',pg_get_indexdef(indexrelid),'valid',indisvalid,'ready',indisready)
FROM pg_index WHERE indrelid IN (SELECT c.oid FROM pg_class c WHERE c.relnamespace='public'::regnamespace)
ORDER BY indexrelid::regclass::text
) AS fixed_rows(value)
UNION ALL
SELECT 13::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','role','name',rolname,'login',rolcanlogin,'inherit',rolinherit,
 'super',rolsuper,'createRole',rolcreaterole,'createDb',rolcreatedb,'replication',rolreplication,
 'bypassRls',rolbypassrls,'config',rolconfig)
FROM pg_roles WHERE rolname NOT LIKE 'pg\_%' ESCAPE '\' ORDER BY rolname
) AS fixed_rows(value)
UNION ALL
SELECT 14::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','membership','role',pg_get_userbyid(roleid),'member',pg_get_userbyid(member),
 'admin',admin_option,'inherit',inherit_option,'set',set_option) FROM pg_auth_members ORDER BY roleid,member
) AS fixed_rows(value)
UNION ALL
SELECT 15::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (
SELECT jsonb_build_object('kind','defaultAcl','owner',pg_get_userbyid(defaclrole),
 'namespace',CASE WHEN defaclnamespace=0 THEN NULL ELSE defaclnamespace::regnamespace::text END,
 'objectType',defaclobjtype,'grantor',pg_get_userbyid(x.grantor),
 'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
 'privilege',x.privilege_type,'grantable',x.is_grantable)
FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) x
ORDER BY defaclrole,defaclnamespace,defaclobjtype,x.grantee,x.privilege_type
) AS fixed_rows(value)
UNION ALL
SELECT 16::smallint AS section,
 convert_to(coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C")::text,'[]'),'UTF8') AS payload
FROM (

-- Independently captured strict OID-to-name map for the frozen discovery's raw
-- protectedAcl relation OIDs. Raw discovery rows are never rewritten.
SELECT jsonb_build_object('kind','relationIdentity','oid',c.oid::text,'catalogKey',c.oid::regclass::text,'schema',n.nspname,'name',c.relname)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind='r' AND c.relname IN
 ('consumer_approval_intent','consumer_approval_consumed_proof','consumer_derivative_consent','consumer_authorization')
ORDER BY n.nspname,c.relname
) AS fixed_rows(value)
UNION ALL
SELECT 17::smallint AS section,
 convert_to(jsonb_build_array(
 (SELECT count(*) FROM public."user"),
 (SELECT count(*) FROM public."session"),
 (SELECT count(*) FROM public."session_metadata"),
 (SELECT count(*) FROM public."remote_account_identity"),
 (SELECT count(*) FROM public."remote_session_binding"),
 (SELECT count(*) FROM public."consumer_authorization"))::text,'UTF8') AS payload;
CREATE TEMPORARY TABLE lomi_private_baseline (
 section smallint PRIMARY KEY, payload bytea NOT NULL
) ON COMMIT PRESERVE ROWS;
INSERT INTO pg_temp.lomi_private_baseline SELECT * FROM pg_temp.lomi_private_snapshot;
DO $private_before$
BEGIN
 IF current_user <> 'e2_owner' OR session_user <> 'e2_owner'
  OR (SELECT count(*) FROM pg_temp.lomi_private_baseline) <> 17
  OR (SELECT jsonb_array_length(convert_from(payload,'UTF8')::jsonb)
      FROM pg_temp.lomi_private_baseline WHERE section=1) <> 27
  OR (SELECT convert_from(payload,'UTF8')::jsonb FROM pg_temp.lomi_private_baseline WHERE section=17)
      IS DISTINCT FROM to_jsonb(ARRAY[0::bigint,0,0,0,0,0])
 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='private precondition rejected'; END IF;
END $private_before$;
\ir positive-auth.sql
DO $private_after$
BEGIN
 IF current_user <> 'e2_owner' OR session_user <> 'e2_owner'
  OR nullif(current_setting('lomi_positive.credential_hash',true),'') IS NOT NULL
  OR EXISTS((SELECT section,payload FROM pg_temp.lomi_private_baseline)
            EXCEPT (SELECT section,payload FROM pg_temp.lomi_private_snapshot))
  OR EXISTS((SELECT section,payload FROM pg_temp.lomi_private_snapshot)
            EXCEPT (SELECT section,payload FROM pg_temp.lomi_private_baseline))
 THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='private postcondition rejected'; END IF;
END $private_after$;
DROP VIEW pg_temp.lomi_private_snapshot;
DROP TABLE pg_temp.lomi_private_baseline;
