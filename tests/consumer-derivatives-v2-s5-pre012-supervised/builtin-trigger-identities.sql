-- Separate closed pristine builtin identity capture; no writes or absent v2 casts.
SELECT jsonb_build_object('catalog',to_jsonb(p),'namespace',n.nspname,
 'language',l.lanname,'returnNamespace',tn.nspname,'returnType',t.typname)
FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
JOIN pg_catalog.pg_language l ON l.oid=p.prolang
JOIN pg_catalog.pg_type t ON t.oid=p.prorettype
JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace
WHERE n.nspname='pg_catalog' AND p.proname IN
 ('RI_FKey_cascade_del','RI_FKey_noaction_upd','RI_FKey_check_ins',
  'RI_FKey_check_upd','RI_FKey_restrict_del','RI_FKey_cascade_upd')
ORDER BY p.proname,p.oid;
