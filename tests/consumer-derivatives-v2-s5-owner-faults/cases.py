"""Pure SQL source generation for120 additional owner denials; never executes SQL."""
import hashlib

ROLES=('lomi_migrator','lomi_runtime','lomi_remote_api','lomi_remote_exchange')
SIGNATURES=(
 'public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)',
 'public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea)',
 'public.lomi_consumer_recipient_recheck(uuid,uuid)',
 'public.lomi_consumer_principal_live_v2(public.consumer_authorization)',
 'public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)')
JSON_RETURNS={SIGNATURES[0],SIGNATURES[2]}


def statements(row):
    signature=row['signature']
    if signature not in SIGNATURES:raise ValueError('unknown function')
    raw=bytes.fromhex(row['definitionUtf8Hex'])
    if hashlib.sha256(raw).hexdigest()!=row['catalogSha256']:raise ValueError('definition hash mismatch')
    text=raw.decode('utf8')
    if text.count('$function$')!=2:raise ValueError('unexpected source body delimiters')
    head,body,tail=text.split('$function$')
    if not head.startswith('CREATE OR REPLACE FUNCTION public.') or tail.strip():raise ValueError('unexpected catalog definition shape')
    # Explicit hostile test body, only in a separately labeled denial statement.
    # Keep exact argument/header/language/config and catalog declaration bytes.
    # VOID returns skip all checks; JSONB returns data without auth checks.
    bypass_body="\nBEGIN RETURN '{\"fixtureBypass\":true}'::jsonb; END;\n" if signature in JSON_RETURNS else '\nBEGIN RETURN; END;\n'
    if bypass_body==body:raise ValueError('bypass body unchanged')
    if ((' RETURNS jsonb\n' not in head) if signature in JSON_RETURNS else (' RETURNS void\n' not in head)):
        raise ValueError('unexpected declared return type')
    if row['securityDefiner']:
        if ' SECURITY DEFINER\n' not in head:raise ValueError('security source mismatch')
        security='INVOKER'
    else:
        if ' SECURITY DEFINER\n' in head:raise ValueError('security source mismatch')
        security='DEFINER'
    name=signature.split('(')[0].split('.')[1]
    return {
      'bypass-body':head+'$function$'+bypass_body+'$function$'+tail,
      'security-flip':'ALTER FUNCTION '+signature+' SECURITY '+security+';',
      'search-path':'ALTER FUNCTION '+signature+' SET search_path TO public, pg_catalog, pg_temp;',
      'owner':'ALTER FUNCTION '+signature+' OWNER TO ROLE_PLACEHOLDER;',
      'rename':'ALTER FUNCTION '+signature+' RENAME TO fixture_denied_'+name+';',
      'drop-cascade':'DROP FUNCTION '+signature+' CASCADE;'}


def build(rows,denied_sql):
    functions={}
    for row in rows:
        if row.get('kind')!='function' or row['signature'] not in SIGNATURES:continue
        if row['signature'] in functions:raise ValueError('duplicate function')
        functions[row['signature']]=row
    if set(functions)!=set(SIGNATURES):raise ValueError('missing owner-denial function')
    result=[]
    for role in ROLES:
        for signature in SIGNATURES:
            for action,statement in statements(functions[signature]).items():
                if action=='owner':statement=statement.replace('ROLE_PLACEHOLDER',role)
                result.append({'id':role+':'+action+':'+signature,'role':role,'action':action,
                  'signature':signature,'statement':statement,'statementSha256':hashlib.sha256(statement.encode()).hexdigest(),
                  'admittedDefinitionSha256':functions[signature]['catalogSha256'],
                  'expectedSqlstate':'42501','sql':denied_sql(role,statement)})
    if len(result)!=120 or len({c['id'] for c in result})!=120:raise ValueError('case closure')
    return result
