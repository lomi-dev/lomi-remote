-- Raw UTF-8 PostgreSQL catalog evidence. pg_get_functiondef is retained as-is;
-- its digest is over those exact UTF-8 bytes. No definition text is rewritten.
-- A closed search path keeps every regprocedure/regtype/regclass identity
-- schema-qualified without changing pg_get_functiondef() bytes.
SET search_path = pg_catalog;

SELECT json_build_object(
  'kind','function',
  'signature',p.oid::regprocedure::text,
  'owner',pg_get_userbyid(p.proowner),
  'securityDefiner',p.prosecdef,
  'config',p.proconfig,
  'definition',pg_get_functiondef(p.oid),
  'definitionUtf8Hex',encode(convert_to(pg_get_functiondef(p.oid),'UTF8'),'hex'),
  'catalogSha256',encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex'),
  'acl',coalesce((
    SELECT json_agg(json_build_object(
      'grantor',pg_get_userbyid(x.grantor),
      'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
      'privilege',x.privilege_type,
      'grantable',x.is_grantable
    ) ORDER BY x.grantor,x.grantee,x.privilege_type,x.is_grantable)
    FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) x
  ),'[]'::json))
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname='public' AND left(p.proname,5)='lomi_'
ORDER BY p.oid::regprocedure::text;

SELECT json_build_object(
  'kind','role',
  'name',r.rolname,
  'login',r.rolcanlogin,
  'inherit',r.rolinherit,
  'super',r.rolsuper,
  'createRole',r.rolcreaterole,
  'createDb',r.rolcreatedb,
  'replication',r.rolreplication,
  'bypassRls',r.rolbypassrls,
  'config',r.rolconfig
)
FROM pg_roles r WHERE left(r.rolname,3)<>'pg_'
ORDER BY r.rolname;

SELECT json_build_object(
  'kind','membership',
  'role',pg_get_userbyid(m.roleid),
  'member',pg_get_userbyid(m.member),
  'admin',m.admin_option,
  'inherit',m.inherit_option,
  'set',m.set_option
)
FROM pg_auth_members m ORDER BY m.roleid,m.member;

SELECT json_build_object(
  'kind','defaultAcl',
  'owner',pg_get_userbyid(d.defaclrole),
  'namespace',CASE WHEN d.defaclnamespace=0 THEN NULL ELSE d.defaclnamespace::regnamespace::text END,
  'objectType',d.defaclobjtype,
  'acl',coalesce((
    SELECT json_agg(json_build_object(
      'grantor',pg_get_userbyid(x.grantor),
      'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
      'privilege',x.privilege_type,
      'grantable',x.is_grantable
    ) ORDER BY x.grantor,x.grantee,x.privilege_type,x.is_grantable)
    FROM aclexplode(d.defaclacl) x
  ),'[]'::json)
)
FROM pg_default_acl d
ORDER BY d.defaclrole,d.defaclnamespace,d.defaclobjtype;

SELECT json_build_object(
  'kind','relation',
  'relation',c.oid::regclass::text,
  'owner',pg_get_userbyid(c.relowner),
  'persistence',c.relpersistence,
  'kindCode',c.relkind,
  'rowSecurity',c.relrowsecurity,
  'forceRowSecurity',c.relforcerowsecurity,
  'replicaIdentity',c.relreplident,
  'tableAcl',coalesce((
    SELECT json_agg(json_build_object(
      'grantor',pg_get_userbyid(x.grantor),
      'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
      'privilege',x.privilege_type,
      'grantable',x.is_grantable
    ) ORDER BY x.grantor,x.grantee,x.privilege_type,x.is_grantable)
    FROM aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) x
  ),'[]'::json),
  'columns',coalesce((
    SELECT json_agg(json_build_object(
      'number',a.attnum,
      'name',a.attname,
      'type',format_type(a.atttypid,a.atttypmod),
      'notNull',a.attnotnull,
      'hasDefault',a.atthasdef,
      'identity',a.attidentity,
      'generated',a.attgenerated,
      'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::regcollation::text END,
      'acl',coalesce((
        SELECT json_agg(json_build_object(
          'grantor',pg_get_userbyid(x.grantor),
          'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
          'privilege',x.privilege_type,
          'grantable',x.is_grantable
        ) ORDER BY x.grantor,x.grantee,x.privilege_type,x.is_grantable)
        FROM aclexplode(a.attacl) x
      ),'[]'::json)
    ) ORDER BY a.attnum)
    FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
  ),'[]'::json)
)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
ORDER BY c.oid::regclass::text;

SELECT json_build_object(
  'kind','constraint',
  'relation',c.conrelid::regclass::text,
  'name',c.conname,
  'type',c.contype,
  'definition',pg_get_constraintdef(c.oid,false),
  'validated',c.convalidated,
  'deferrable',c.condeferrable,
  'deferred',c.condeferred,
  'local',c.conislocal,
  'inheritCount',c.coninhcount,
  'noInherit',c.connoinherit,
  'parent',CASE WHEN c.conparentid=0 THEN NULL ELSE c.conparentid::regclass::text END,
  'index',CASE WHEN c.conindid=0 THEN NULL ELSE c.conindid::regclass::text END,
  'referencedRelation',CASE WHEN c.confrelid=0 THEN NULL ELSE c.confrelid::regclass::text END,
  'columns',c.conkey,
  'referencedColumns',c.confkey,
  'updateAction',c.confupdtype,
  'deleteAction',c.confdeltype,
  'matchType',c.confmatchtype
)
FROM pg_constraint c WHERE c.connamespace='public'::regnamespace
ORDER BY c.conrelid::regclass::text,c.conname;

SELECT json_build_object(
  'kind','trigger',
  'relation',t.tgrelid::regclass::text,
  'name',t.tgname,
  'definition',pg_get_triggerdef(t.oid,false),
  'enabled',t.tgenabled,
  'internal',t.tgisinternal,
  'constraint',(SELECT c.conname FROM pg_constraint c WHERE c.oid=t.tgconstraint),
  'function',t.tgfoid::regprocedure::text,
  'type',t.tgtype,
  'argsHex',encode(t.tgargs,'hex'),
  'deferrable',t.tgdeferrable,
  'deferred',t.tginitdeferred,
  'referencedRelation',CASE WHEN t.tgconstrrelid=0 THEN NULL ELSE t.tgconstrrelid::regclass::text END,
  'constraintIndex',CASE WHEN t.tgconstrindid=0 THEN NULL ELSE t.tgconstrindid::regclass::text END,
  'columns',t.tgattr::text
)
FROM pg_trigger t WHERE t.tgrelid IN (
  SELECT c.oid FROM pg_class c WHERE c.relnamespace='public'::regnamespace
)
ORDER BY t.tgrelid::regclass::text,t.tgname;

SELECT json_build_object(
  'kind','index',
  'relation',i.indrelid::regclass::text,
  'index',i.indexrelid::regclass::text,
  'definition',pg_get_indexdef(i.indexrelid),
  'valid',i.indisvalid,
  'ready',i.indisready,
  'unique',i.indisunique,
  'primary',i.indisprimary,
  'immediate',i.indimmediate,
  'live',i.indislive,
  'nullsNotDistinct',i.indnullsnotdistinct,
  'keyCount',i.indnkeyatts,
  'attributeCount',i.indnatts,
  'attributes',i.indkey::text,
  'options',i.indoption::text,
  'collations',i.indcollation::text,
  'opclasses',i.indclass::text,
  'predicate',pg_get_expr(i.indpred,i.indrelid),
  'expressions',pg_get_expr(i.indexprs,i.indrelid)
)
FROM pg_index i WHERE i.indrelid IN (
  SELECT c.oid FROM pg_class c WHERE c.relnamespace='public'::regnamespace
)
ORDER BY i.indexrelid::regclass::text;

SELECT json_build_object(
  'kind','type',
  'name',t.oid::regtype::text,
  'owner',pg_get_userbyid(t.typowner),
  'typeKind',t.typtype,
  'category',t.typcategory,
  'length',t.typlen,
  'byValue',t.typbyval,
  'alignment',t.typalign,
  'storage',t.typstorage,
  'notNull',t.typnotnull,
  'baseType',CASE WHEN t.typbasetype=0 THEN NULL ELSE t.typbasetype::regtype::text END,
  'relation',CASE WHEN t.typrelid=0 THEN NULL ELSE t.typrelid::regclass::text END,
  'acl',coalesce((
    SELECT json_agg(json_build_object(
      'grantor',pg_get_userbyid(x.grantor),
      'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
      'privilege',x.privilege_type,
      'grantable',x.is_grantable
    ) ORDER BY x.grantor,x.grantee,x.privilege_type,x.is_grantable)
    FROM aclexplode(coalesce(t.typacl,acldefault('T',t.typowner))) x
  ),'[]'::json)
)
FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
WHERE n.nspname='public' AND t.typtype IN ('c','d','e','r')
ORDER BY t.oid::regtype::text;

SELECT json_build_object(
  'kind','schema',
  'name',n.nspname,
  'owner',pg_get_userbyid(n.nspowner),
  'acl',coalesce((
    SELECT json_agg(json_build_object(
      'grantor',pg_get_userbyid(x.grantor),
      'grantee',CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
      'privilege',x.privilege_type,
      'grantable',x.is_grantable
    ) ORDER BY x.grantor,x.grantee,x.privilege_type,x.is_grantable)
    FROM aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) x
  ),'[]'::json)
)
FROM pg_namespace n WHERE n.nspname='public';
