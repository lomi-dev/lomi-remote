-- Additional raw schema/ACL evidence, no application rows or role passwords.
SELECT jsonb_build_object('kind','objectAcl','relation',c.oid::regclass::text,
 'owner',pg_get_userbyid(c.relowner),'grantor',pg_get_userbyid(x.grantor),
 'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
 'privilege',x.privilege_type,'grantable',x.is_grantable)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) x
WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
ORDER BY c.relname,x.grantor,x.grantee,x.privilege_type;
SELECT jsonb_build_object('kind','columnAcl','relation',c.oid::regclass::text,'column',a.attname,
 'grantor',pg_get_userbyid(x.grantor),'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
 'privilege',x.privilege_type,'grantable',x.is_grantable)
FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped
ORDER BY c.relname,a.attnum,x.grantee,x.privilege_type;
SELECT jsonb_build_object('kind','schemaAuthority','role',r.rolname,
 'create',has_schema_privilege(r.oid,n.oid,'CREATE'),'usage',has_schema_privilege(r.oid,n.oid,'USAGE'))
FROM pg_roles r CROSS JOIN pg_namespace n WHERE n.nspname='public' ORDER BY r.rolname;
SELECT jsonb_build_object('kind','constraint','relation',conrelid::regclass::text,'name',conname,
 'definition',pg_get_constraintdef(oid,false),'validated',convalidated,'deferrable',condeferrable,'deferred',condeferred)
FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY conrelid::regclass::text,conname;
SELECT jsonb_build_object('kind','trigger','relation',tgrelid::regclass::text,'name',tgname,
 'definition',pg_get_triggerdef(oid,false),'enabled',tgenabled,'internal',tgisinternal,
 'constraint',(SELECT conname FROM pg_constraint WHERE oid=tgconstraint),
 'function',tgfoid::regprocedure::text,'type',tgtype,'argsHex',encode(tgargs,'hex'),
 'deferrable',tgdeferrable,'deferred',tginitdeferred,
 'referencedRelation',tgconstrrelid::regclass::text,'constraintIndex',tgconstrindid::regclass::text,
 'columns',tgattr::text,
 'whenTriggerDefinition',CASE WHEN tgqual IS NULL THEN NULL ELSE pg_get_triggerdef(oid,false) END)
FROM pg_trigger WHERE tgrelid IN (SELECT c.oid FROM pg_class c WHERE c.relnamespace='public'::regnamespace)
ORDER BY tgrelid::regclass::text,tgname;
SELECT jsonb_build_object('kind','index','relation',indrelid::regclass::text,'name',indexrelid::regclass::text,
 'definition',pg_get_indexdef(indexrelid),'valid',indisvalid,'ready',indisready)
FROM pg_index WHERE indrelid IN (SELECT c.oid FROM pg_class c WHERE c.relnamespace='public'::regnamespace)
ORDER BY indexrelid::regclass::text;
SELECT jsonb_build_object('kind','role','name',rolname,'login',rolcanlogin,'inherit',rolinherit,
 'super',rolsuper,'createRole',rolcreaterole,'createDb',rolcreatedb,'replication',rolreplication,
 'bypassRls',rolbypassrls,'config',rolconfig)
FROM pg_roles WHERE rolname NOT LIKE 'pg\_%' ESCAPE '\' ORDER BY rolname;
SELECT jsonb_build_object('kind','membership','role',pg_get_userbyid(roleid),'member',pg_get_userbyid(member),
 'admin',admin_option,'inherit',inherit_option,'set',set_option) FROM pg_auth_members ORDER BY roleid,member;
SELECT jsonb_build_object('kind','defaultAcl','owner',pg_get_userbyid(defaclrole),
 'namespace',CASE WHEN defaclnamespace=0 THEN NULL ELSE defaclnamespace::regnamespace::text END,
 'objectType',defaclobjtype,'grantor',pg_get_userbyid(x.grantor),
 'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
 'privilege',x.privilege_type,'grantable',x.is_grantable)
FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) x
ORDER BY defaclrole,defaclnamespace,defaclobjtype,x.grantee,x.privilege_type;

-- Independently captured strict OID-to-name map for the frozen discovery's raw
-- protectedAcl relation OIDs. Raw discovery rows are never rewritten.
SELECT jsonb_build_object('kind','relationIdentity','oid',c.oid::text,'catalogKey',c.oid::regclass::text,'schema',n.nspname,'name',c.relname)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind='r' AND c.relname IN
 ('consumer_approval_intent','consumer_approval_consumed_proof','consumer_derivative_consent','consumer_authorization')
ORDER BY n.nspname,c.relname;
