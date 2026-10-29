-- Raw same-database evidence: no canonicalization or absent object casts.
SELECT jsonb_build_object('section','objects','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT c.oid,c.relname AS name,c.relkind,c.relowner,c.relnamespace,c.reltype,c.reloftype,c.relpersistence,c.relchecks AS checks,c.relhastriggers,c.relrowsecurity,c.relforcerowsecurity,c.relacl,c.reloptions,c.relpartbound FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.oid) q;
SELECT jsonb_build_object('section','columns','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(a) AS catalog,pg_get_expr(d.adbin,d.adrelid,false) AS default_definition FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND a.attnum>0 ORDER BY a.attrelid,a.attnum) q;
SELECT jsonb_build_object('section','constraints','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(c) AS catalog,r.relname AS relation,pg_get_constraintdef(c.oid,false) AS definition FROM pg_constraint c LEFT JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public' ORDER BY c.oid) q;
SELECT jsonb_build_object('section','indexes','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(i) AS catalog,pg_get_indexdef(i.indexrelid) AS definition FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY i.indexrelid) q;
SELECT jsonb_build_object('section','triggers','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(t) AS catalog,pg_get_triggerdef(t.oid,false) AS definition FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY t.oid) q;
SELECT jsonb_build_object('section','functions','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(p) AS catalog,CASE WHEN p.prokind<>'a' THEN pg_get_functiondef(p.oid) END AS definition FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' ORDER BY p.oid) q;
SELECT jsonb_build_object('section','types','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(t) AS catalog FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' ORDER BY t.oid) q;
SELECT jsonb_build_object('section','roles','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(r) AS catalog FROM pg_roles r ORDER BY oid) q;
SELECT jsonb_build_object('section','memberships','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(m) AS catalog FROM pg_auth_members m ORDER BY roleid,member,grantor) q;
SELECT jsonb_build_object('section','schemas','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(n) AS catalog FROM pg_namespace n WHERE n.nspname='public' ORDER BY oid) q;
SELECT jsonb_build_object('section','schemaAuthority','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT r.oid,r.rolname,has_schema_privilege(r.oid,n.oid,'USAGE') AS usage,has_schema_privilege(r.oid,n.oid,'CREATE') AS create FROM pg_roles r CROSS JOIN pg_namespace n WHERE n.nspname='public' ORDER BY r.oid) q;
SELECT jsonb_build_object('section','defaultAcl','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(d) AS catalog FROM pg_default_acl d ORDER BY oid) q;
SELECT jsonb_build_object('section','expandedFunctionAcl','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT p.oid,a.* FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='public' ORDER BY p.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable) q;
SELECT jsonb_build_object('section','expandedRelationAcl','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT c.oid,a.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) a WHERE n.nspname='public' ORDER BY c.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable) q;
SELECT jsonb_build_object('section','expandedColumnAcl','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT c.oid,t.attnum,a.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute t ON t.attrelid=c.oid CROSS JOIN LATERAL aclexplode(t.attacl) a WHERE n.nspname='public' ORDER BY c.oid,t.attnum,a.grantor,a.grantee,a.privilege_type,a.is_grantable) q;
SELECT jsonb_build_object('section','ledger','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT count(*) AS count FROM public._prisma_migrations) q;
SELECT jsonb_build_object('section','consumerRows','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT count(*) AS count FROM public.consumer_authorization) q;
SELECT jsonb_build_object('section','expandedSchemaAcl','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT n.oid,a.* FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='public' ORDER BY n.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable) q;
SELECT jsonb_build_object('section','expandedTypeAcl','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT t.oid,a.* FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace CROSS JOIN LATERAL aclexplode(coalesce(t.typacl,acldefault('T',t.typowner))) a WHERE n.nspname='public' ORDER BY t.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable) q;
SELECT jsonb_build_object('section','expandedDefaultAcl','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT d.oid,a.* FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a ORDER BY d.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable) q;
SELECT jsonb_build_object('section','attributeDefaults','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(d) AS catalog,pg_get_expr(d.adbin,d.adrelid,false) AS definition FROM pg_attrdef d JOIN pg_class c ON c.oid=d.adrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY d.oid) q;
SELECT jsonb_build_object('section','rules','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(r) AS catalog,pg_get_ruledef(r.oid,false) AS definition FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY r.oid) q;
SELECT jsonb_build_object('section','policies','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(p) AS catalog FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY p.oid) q;
SELECT jsonb_build_object('section','enums','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(e) AS catalog FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' ORDER BY e.oid) q;
SELECT jsonb_build_object('section','sequences','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(s) AS catalog FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY s.seqrelid) q;
SELECT jsonb_build_object('section','ranges','rows',coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb)) FROM (SELECT to_jsonb(r) AS catalog FROM pg_range r JOIN pg_type t ON t.oid=r.rngtypid JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' ORDER BY r.rngtypid) q;
SELECT jsonb_build_object('section','selected','rows',q.value) FROM (SELECT coalesce(jsonb_agg(item ORDER BY item->>'name'),'[]'::jsonb)
 FROM (
  SELECT jsonb_build_object(
   'name',c.conname,'type',c.contype,'definition',pg_get_constraintdef(c.oid,false),
   'columns',(SELECT jsonb_agg(a.attname ORDER BY k.n) FROM unnest(c.conkey) WITH ORDINALITY k(num,n)
     JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.num AND NOT a.attisdropped),
   'validated',c.convalidated,'enforced',c.conenforced,'deferrable',c.condeferrable,'deferred',c.condeferred,
   'isLocal',c.conislocal,'inheritCount',c.coninhcount,'noInherit',c.connoinherit,
   'hasParent',c.conparentid<>0,'period',c.conperiod)
   || CASE WHEN c.contype='f' THEN jsonb_build_object(
    'targetSchema',tn.nspname,'targetRelation',t.relname,
    'targetColumns',(SELECT jsonb_agg(a.attname ORDER BY k.n) FROM unnest(c.confkey) WITH ORDINALITY k(num,n)
      JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.num AND NOT a.attisdropped),
    'updateAction',c.confupdtype,'deleteAction',c.confdeltype,'matchType',c.confmatchtype,
    'deleteSetColumns',(SELECT jsonb_agg(a.attname ORDER BY k.n) FROM unnest(c.confdelsetcols) WITH ORDINALITY k(num,n)
      JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.num AND NOT a.attisdropped),
    'indexSchema',ixn.nspname,'indexName',ix.relname,'indexValid',i.indisvalid,'indexReady',i.indisready,
    'indexUnique',i.indisunique,'indexImmediate',i.indimmediate,'indexLive',i.indislive,
    'indexPrimary',i.indisprimary,'indexPredicate',pg_get_expr(i.indpred,i.indrelid,false),
    'indexExpressions',pg_get_expr(i.indexprs,i.indrelid,false)) ELSE '{}'::jsonb END AS item
  FROM pg_constraint c
  LEFT JOIN pg_class t ON t.oid=c.confrelid LEFT JOIN pg_namespace tn ON tn.oid=t.relnamespace
  LEFT JOIN pg_class ix ON ix.oid=c.conindid LEFT JOIN pg_namespace ixn ON ixn.oid=ix.relnamespace
  LEFT JOIN pg_index i ON i.indexrelid=c.conindid
  WHERE c.conrelid='public.consumer_authorization'::regclass AND (
   c.conname IN ('consumer_authorization_originKind_check','consumer_authorization_check',
    'consumer_authorization_clientClass_check','consumer_authorization_canManageAccount_check',
    'consumer_authorization_accountSessionId_accountId_clientCl_fkey')
   OR (c.contype='c' AND c.conkey && ARRAY(SELECT attnum FROM pg_attribute
      WHERE attrelid=c.conrelid AND attname IN ('accountSessionId','canManageAccount','clientClass','originId','originKind')
      AND NOT attisdropped)::smallint[])
   OR (c.contype='f' AND (c.confrelid='public.remote_session_binding'::regclass
      OR EXISTS(SELECT FROM pg_attribute a WHERE a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey)
        AND a.attname IN ('originKind','originId','clientClass','canManageAccount') AND NOT a.attisdropped)
      OR ARRAY(SELECT a.attname::text FROM unnest(c.conkey) k(num) JOIN pg_attribute a
        ON a.attrelid=c.conrelid AND a.attnum=k.num AND NOT a.attisdropped ORDER BY a.attname)
        =ARRAY['accountId','accountSessionId','clientClass']::text[])))
 ) measured) q(value);
