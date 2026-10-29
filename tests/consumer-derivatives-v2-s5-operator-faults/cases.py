"""Sixteen legal ordinary-DDL operator fault recipes; source generation only."""
import copy
import hashlib
import re

HELPER='public.lomi_consumer_principal_live_v2(public.consumer_authorization)'
ROOT='public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)'
BODY_OWNER='lomi_consumer_auth_body_owner'
REVOKE_ROLES='PUBLIC,lomi_migrator,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_pairing_write_owner,lomi_remote_inventory_owner'


def function_map(catalog):
    rows={}
    for row in catalog:
        if row.get('kind')!='function':continue
        if row['signature'] in rows:raise ValueError('duplicate function')
        if hashlib.sha256(bytes.fromhex(row['definitionUtf8Hex'])).hexdigest()!=row['catalogSha256']:raise ValueError('definition hash')
        rows[row['signature']]=row
    if len(rows)!=27:raise ValueError('function closure')
    return rows


def body_statement(row):
    raw=bytes.fromhex(row['definitionUtf8Hex']).decode()
    if raw.count('$function$')!=2:raise ValueError('body delimiter')
    head,body,tail=raw.split('$function$')
    replacement="\nBEGIN RETURN '{\"fixtureBypass\":true}'::jsonb; END;\n" if row['signature']==ROOT else '\nBEGIN RETURN; END;\n'
    if replacement==body:raise ValueError('no body drift')
    return head+'$function$'+replacement+'$function$'+tail


def build(refs):
    maps={s:function_map(refs[s]['catalog']) for s in ('old','new')};cases=[]
    def add(name,state,database,operator,setup,message,mutation,signature=None):
        cases.append(dict(id=name,baseline=state,database=database,operator=operator,setupSql=setup,
            expectedPsqlExit=3,expectedSqlstate='P0001',expectedGuardMessage=message,
            mutation=mutation,signature=signature))
    add('mixed-one-of-two-helpers','old',0,'helper',
        'ALTER FUNCTION '+HELPER+' OWNER TO '+BODY_OWNER+';\nREVOKE ALL ON FUNCTION '+HELPER+' FROM '+REVOKE_ROLES+';\nGRANT EXECUTE ON FUNCTION '+HELPER+' TO lomi_runtime,lomi_remote_inventory_owner;',
        'mixed helper seal state','mixed-helper',HELPER)
    root_sigs=[r['signature'] for r in refs['new']['catalog'] if r.get('kind')=='function' and r['signature'] in (ROOT,
        'public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea)','public.lomi_consumer_recipient_recheck(uuid,uuid)')]
    if len(root_sigs)!=3:raise ValueError('root closure')
    setup='\n'.join(bytes.fromhex(maps['old'][s]['definitionUtf8Hex']).decode()+';\n' for s in root_sigs if s!=ROOT)
    add('mixed-one-of-three-roots','new',2,'root',setup,'mixed catalog state rejected','mixed-root',ROOT)
    for state,database,operator,signature in [('old',0,'helper',HELPER),('new',2,'root',ROOT)]:
        owner_message='unexpected helper definition/owner/ACL: '+signature if operator=='helper' else 'unexpected root owner/security/search_path: '+signature
        hash_message='unexpected helper definition/owner/ACL: '+signature if operator=='helper' else 'unexpected root definition/ACL: '+signature
        for mutation,sql,message in [
            ('body',body_statement(maps[state][signature])+';',hash_message),
            ('config','ALTER FUNCTION '+signature+" SET work_mem TO '8MB';",hash_message),
            ('owner','ALTER FUNCTION '+signature+' OWNER TO e2_owner;',owner_message),
            ('acl','GRANT EXECUTE ON FUNCTION '+signature+' TO lomi_remote_api;',hash_message)]:
            add(operator+'-'+mutation,state,database,operator,sql,message,mutation,signature)
    for operator in ('helper','root'):
        message='body owner must be unreachable and retain no broad capability' if operator=='helper' else 'execution owner retains excessive authority: '+BODY_OWNER
        for mutation,sql in [
            ('schema-create','GRANT CREATE ON SCHEMA public TO '+BODY_OWNER+';'),
            ('membership-in','GRANT '+BODY_OWNER+' TO lomi_runtime;'),
            ('membership-out','GRANT lomi_runtime TO '+BODY_OWNER+';')]:
            add(operator+'-'+mutation,'new',2,operator,sql,message,mutation)
    if len(cases)!=16 or len({c['id'] for c in cases})!=16:raise ValueError('case closure')
    return cases


def validate_role_oids(rows,roles):
    result={}
    for row in rows:
        if set(row)!= {'role','oid'} or row['role'] not in roles or row['role'] in result or type(row['oid']) is not int or row['oid']<=0:raise ValueError('role OID identity')
        result[row['role']]=row['oid']
    if set(result)!=roles or len(set(result.values()))!=len(result):raise ValueError('incomplete/duplicate role OID map')
    return result


def expected_setup(case,refs,role_oids):
    """Compute exact known drift, preserving raw bytes/ACLs in captured evidence.

    ACL rows are GENERATED in the pinned discovery's OID sort order; captured
    ACLs are never sorted, normalized, repaired, or used to choose expected pins.
    """
    result=copy.deepcopy(refs[case['baseline']]);rows=function_map(result['catalog']);new=function_map(refs['new']['catalog']);old=function_map(refs['old']['catalog'])
    mutation=case['mutation'];signature=case['signature']
    def acl_order(acl):
        return sorted(acl,key=lambda a:(role_oids[a['grantor']],0 if a['grantee']=='PUBLIC' else role_oids[a['grantee']],a['privilege'],a['grantable']))
    if mutation=='mixed-helper':rows[HELPER]=copy.deepcopy(new[HELPER])
    elif mutation=='mixed-root':
        for s in ('public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea)','public.lomi_consumer_recipient_recheck(uuid,uuid)'):rows[s]=copy.deepcopy(old[s])
    elif mutation in ('body','config','owner','acl'):
        row=rows[signature]
        if mutation=='body':
            definition=body_statement(row).encode();row['definitionUtf8Hex']=definition.hex();row['catalogSha256']=hashlib.sha256(definition).hexdigest()
        elif mutation=='config':
            raw=bytes.fromhex(row['definitionUtf8Hex']).decode();needle='AS $function$'
            if raw.count(needle)!=1:raise ValueError('config header')
            definition=raw.replace(needle," SET work_mem TO '8MB'\n"+needle).encode()
            row['config']=[*row['config'],'work_mem=8MB'];row['definitionUtf8Hex']=definition.hex();row['catalogSha256']=hashlib.sha256(definition).hexdigest()
        elif mutation=='owner':
            oldowner=row['owner'];row['owner']='e2_owner'
            row['acl']=acl_order([{k:('e2_owner' if k in ('grantor','grantee') and v==oldowner else v) for k,v in a.items()} for a in row['acl']])
        else:
            if any(a['grantee']=='lomi_remote_api' for a in row['acl']):raise ValueError('ACL drift already present')
            row['acl']=acl_order([*row['acl'],{'grantor':row['owner'],'grantee':'lomi_remote_api','privilege':'EXECUTE','grantable':False}])
    elif mutation=='schema-create':
        matched=[r for r in result['metadata'] if r.get('kind')=='schemaAuthority' and r['role']==BODY_OWNER]
        if len(matched)!=1 or matched[0]['create']:raise ValueError('schema CREATE baseline')
        matched[0]['create']=True
    elif mutation.startswith('membership-'):
        role,member=(BODY_OWNER,'lomi_runtime') if mutation=='membership-in' else ('lomi_runtime',BODY_OWNER)
        membership={'kind':'membership','role':role,'member':member,'admin':False,'inherit':False,'set':True}
        result['catalog'].append(copy.deepcopy(membership))
        result['metadata'].append(copy.deepcopy(membership))
    else:raise ValueError('unknown mutation')
    result['catalog']=[rows[r['signature']] if r.get('kind')=='function' else r for r in result['catalog']]
    return result


def markers(case_id):
    if not re.fullmatch('[a-z0-9-]+',case_id):raise ValueError('case id')
    return [case_id+':'+x for x in ('CAT_BEGIN','CAT_END','META_BEGIN','META_END','OPERATOR_BEGIN','UNEXPECTED_ACCEPTANCE')]


def branch_sql(case,catalog_sql,metadata_sql,operator):
    if not operator.lstrip().startswith('--') or '\nBEGIN;' not in operator or not operator.rstrip().endswith('COMMIT;'):raise ValueError('full operator shape')
    m=markers(case['id']);literal=lambda x:"SELECT '"+x+"';\n"
    prefix='BEGIN;\n'+case['setupSql']+'\n'+literal(m[0])+catalog_sql+'\n'+literal(m[1])+literal(m[2])+metadata_sql+'\n'+literal(m[3])+literal(m[4])
    return prefix+operator+'\n'+literal(m[5])


def parse_result(case,stdout,stderr,parse_catalog):
    m=markers(case['id']);lines=stdout.splitlines()
    if any(lines.count(tag)!=1 for tag in m[:5]) or m[5] in lines:raise ValueError('setup markers incomplete/operator accepted')
    positions=[lines.index(tag) for tag in m[:5]]
    if positions!=sorted(positions) or positions[0]!=0 or positions[2]!=positions[1]+1 or positions[4]!=positions[3]+1:raise ValueError('setup marker order/extra output')
    errors=re.findall(r'ERROR:\s+([A-Z0-9]{5}):\s*([^\n]+)',stderr)
    if errors!=[('P0001',case['expectedGuardMessage'])]:raise ValueError('wrong SQLSTATE/guard message or earlier setup error')
    return {'catalog':parse_catalog('\n'.join(lines[positions[0]+1:positions[1]])),
            'metadata':parse_catalog('\n'.join(lines[positions[2]+1:positions[3]]))}
