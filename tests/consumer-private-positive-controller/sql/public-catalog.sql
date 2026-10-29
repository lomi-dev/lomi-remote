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
FROM functions f ORDER BY f.signature;

-- No row data, credentials, role passwords or operator configuration is queried.
SELECT jsonb_build_object('kind','role','name',rolname,'login',rolcanlogin,'inherit',rolinherit,'super',rolsuper,'createRole',rolcreaterole,'createDb',rolcreatedb,'replication',rolreplication,'bypassRls',rolbypassrls,'config',rolconfig)
FROM pg_roles WHERE rolname IN ('e2_owner','lomi_migrator','lomi_runtime','lomi_remote_api','lomi_remote_exchange','lomi_remote_runtime_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner','lomi_consumer_auth_body_owner','fixture_unexpected') ORDER BY rolname;
SELECT jsonb_build_object('kind','membership','role',pg_get_userbyid(roleid),'member',pg_get_userbyid(member),'admin',admin_option,'inherit',inherit_option,'set',set_option) FROM pg_auth_members ORDER BY roleid,member;
SELECT jsonb_build_object('kind','defaultAcl','owner',pg_get_userbyid(defaclrole),'namespace',defaclnamespace,'objectType',defaclobjtype,'grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,'privilege',x.privilege_type,'grantable',x.is_grantable)
FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) x ORDER BY defaclrole,defaclnamespace,defaclobjtype,x.grantee,x.privilege_type;
WITH protected AS (SELECT unnest(ARRAY['public.consumer_approval_intent','public.consumer_approval_consumed_proof','public.consumer_derivative_consent','public.consumer_authorization'])::regclass AS oid)
SELECT jsonb_build_object('kind','protectedAcl','relation',p.oid::text,'column',a.attname,'tableAcl',c.relacl,'columnAcl',a.attacl,'owner',pg_get_userbyid(c.relowner)) FROM protected p JOIN pg_class c ON c.oid=p.oid JOIN pg_attribute a ON a.attrelid=p.oid AND a.attnum>0 AND NOT a.attisdropped ORDER BY p.oid,a.attnum;
SELECT jsonb_build_object('kind','assertionTypeAcl','owner',pg_get_userbyid(typowner),'acl',typacl) FROM pg_type WHERE oid='public.lomi_consumer_assertion_v2'::regtype;
