"""Pure v2 predecessor expectation/model and deterministic literal SQL renderer.

Not an SQL executor. Synthetic model tests do not establish real PG acceptance.
"""
import json

TRANSITION_FK_COLUMNS = frozenset({"originKind", "originId", "clientClass", "canManageAccount"})


def selected(row, contract):
    fk = next(r for r in contract['constraints'] if r['type'] == 'f')
    return (row.get('name') in {r['name'] for r in contract['constraints']}
            or row.get('type') == 'c' and bool(set(row.get('columns') or []) & set(contract['protectedCheckColumns']))
            or row.get('type') == 'f' and (row.get('targetSchema') == fk['targetSchema']
                and row.get('targetRelation') == fk['targetRelation']
                or bool(set(row.get('columns') or []) & TRANSITION_FK_COLUMNS)
                or set(row.get('columns') or []) == set(fk['columns'])))


def admit_predecessors(rows, contract):
    actual = sorted((r for r in rows if selected(r, contract)), key=lambda r: r['name'])
    expected = sorted(contract['constraints'], key=lambda r: r['name'])
    if actual != expected:
        raise ValueError('v2 predecessor contract mismatch; no DDL admitted')
    return True


def guard_sql(contract):
    expected = json.dumps(sorted(contract['constraints'], key=lambda r: r['name']), separators=(',', ':'))
    return '''-- Strict successor guard: exact source-admitted predecessor, no target blessing.
-- Global lock is already held. Retain relation locks until this transaction ends.
LOCK TABLE public.consumer_authorization IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.remote_session_binding IN SHARE MODE;
DO $v2_predecessor_guard$
DECLARE expected jsonb := $v2_expected$''' + expected + '''$v2_expected$::jsonb; actual jsonb;
BEGIN
 SELECT coalesce(jsonb_agg(item ORDER BY item->>'name'),'[]'::jsonb) INTO actual
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
 ) measured;
 IF actual IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'v2 predecessor contract mismatch; no DDL admitted' USING ERRCODE='55000';
 END IF;
END $v2_predecessor_guard$;
'''


def successor_sql(original, contract):
    lock = "SELECT pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));\n"
    if original.count(lock) != 1 or not original.startswith('-- Requires') or '\nBEGIN;\n' not in original:
        raise ValueError('unexpected historical transaction shape')
    old = ' DROP CONSTRAINT "consumer_authorization_originId_check",'
    if original.count(old) != 1:
        raise ValueError('unexpected historical origin CHECK source')
    start = original.index('-- Remove only the 004 class-equality FK')
    end = original.index('ALTER TABLE public.consumer_authorization\n ADD CONSTRAINT consumer_origin_disjoint', start)
    replacement = ('-- Drop only the exact FK already admitted by the locked predecessor guard.\n'
                   'ALTER TABLE public.consumer_authorization\n'
                   ' DROP CONSTRAINT "consumer_authorization_accountSessionId_accountId_clientCl_fkey";\n')
    result = original[:start] + replacement + original[end:]
    result = result.replace(old, ' DROP CONSTRAINT "consumer_authorization_check",')
    return result.replace(lock, lock + '\n' + guard_sql(contract), 1)


AUTHORITY_CASE_BEFORE = 'OR c."clientClass" IS DISTINCT FROM CASE c."originKind" WHEN \'remote_web\' THEN \'web\' ELSE \'mobile\' END'
AUTHORITY_CASE_AFTER = AUTHORITY_CASE_BEFORE.replace('FROM CASE', 'FROM (CASE') + ')'


def group_authority_case(source):
    """Exactly two grouping bytes; does not change any CASE token or branch."""
    if source.count(AUTHORITY_CASE_BEFORE) != 1:
        raise ValueError('unexpected historical authority CASE fragment')
    return source.replace(AUTHORITY_CASE_BEFORE, AUTHORITY_CASE_AFTER, 1)
