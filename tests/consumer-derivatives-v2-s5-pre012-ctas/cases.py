"""Four legal CTAS faults; full public-projection expectation, never target pins.

Only ten fresh OID scalar identities may be bound from a fault capture. Every
other expected field comes from pristine same-DB templates or declared DDL.
This models the27 captured public projections, not TOAST/dependencies globally.
"""
import copy
import re
TABLE='consumer_authorization'
REMOTE='remote_session_binding'
FK='consumer_authorization_accountSessionId_accountId_clientCl_fkey'
UNIQUE='remote_session_binding_sessionId_accountId_clientClass_key'
TARGET='fixture_pre012_ctas_target'
KEY='fixture_pre012_ctas_unique'
EXTRA='fixture_pre012_ctas_fk'
OID_KEYS=('heap','composite','array','index','unique','fk','action_delete','action_update','check_insert','check_update')
SECTIONS=('objects','columns','constraints','indexes','triggers','functions','types','roles','memberships','schemas','schemaAuthority','defaultAcl','expandedFunctionAcl','expandedRelationAcl','expandedColumnAcl','ledger','consumerRows','expandedSchemaAcl','expandedTypeAcl','expandedDefaultAcl','attributeDefaults','rules','policies','enums','sequences','ranges','selected')

def sections(rows):
    if not isinstance(rows,list) or tuple(r.get('section') for r in rows)!=SECTIONS or any(set(r)!= {'section','rows'} or not isinstance(r['rows'],list) for r in rows):raise ValueError('exact27 raw section envelopes')
    return {r['section']:r['rows'] for r in rows}

def one(rows,predicate):
    matches=[r for r in rows if predicate(r)]
    if len(matches)!=1:raise ValueError('nonunique declared template/identity')
    return matches[0]

def quoted(columns):return ', '.join('"'+c+'"' for c in columns)

def build():
    specs=[('extra-clientClass',TABLE,('clientClass',),('clientClass',),False),('extra-originId',TABLE,('originId',),('originId',),False),('extra-permuted-triple',TABLE,('clientClass','accountId','accountSessionId'),('clientClass','accountId','accountSessionId'),False),('replace-class-target',REMOTE,('sessionId','accountId','clientClass'),('accountSessionId','accountId','clientClass'),True)]
    result=[]
    for name,source,targetcols,sourcecols,replace in specs:
        constraint=FK if replace else EXTRA
        definition='FOREIGN KEY ('+quoted(sourcecols)+') REFERENCES '+TARGET+'('+quoted(targetcols)+') ON DELETE CASCADE'
        empty='DO $ctas_empty$ BEGIN IF EXISTS (SELECT 1 FROM public.consumer_authorization)'+(' OR EXISTS (SELECT 1 FROM public.remote_session_binding)' if replace else '')+" THEN RAISE EXCEPTION 'CTAS empty predecessor required'; END IF; END $ctas_empty$;\n"
        sql=empty+'CREATE TABLE public.'+TARGET+' AS SELECT '+quoted(targetcols)+' FROM public.'+source+' WITH NO DATA;\nALTER TABLE public.'+TARGET+' ADD CONSTRAINT '+KEY+' UNIQUE ('+quoted(targetcols)+');\n'
        if replace:sql+='ALTER TABLE public.'+TABLE+' DROP CONSTRAINT "'+FK+'";\n'
        sql+='ALTER TABLE public.'+TABLE+' ADD CONSTRAINT "'+constraint+'" '+definition+';'
        result.append(dict(id=name,source=source,targetColumns=list(targetcols),sourceColumns=list(sourcecols),replace=replace,constraint=constraint,definition=definition,setupSql=sql,expectedPsqlExit=3,expectedSqlstate='55000'))
    return result

def require_case(case):
    if case not in build():raise ValueError('undeclared CTAS case')

def fresh_identities(values,baseline,builtins):
    if type(values)!=dict or set(values)!=set(OID_KEYS):raise ValueError('exact ten identity scalars')
    occupied=set()
    def visit(value):
        if isinstance(value,dict):
            for item in value.values():visit(item)
        elif isinstance(value,list):
            for item in value:visit(item)
        elif type(value)==str and re.fullmatch('[1-9][0-9]*',value):occupied.add(value)
    visit(baseline);visit(list(builtins.values()));seen=set()
    for key in OID_KEYS:
        value=values[key]
        if type(value)!=str or not re.fullmatch('[1-9][0-9]*',value) or int(value)>4294967295 or value in occupied or value in seen:raise ValueError('nonfresh/duplicate/noncanonical OID')
        seen.add(value)
    return dict(values)

def bind_identities(case,baseline,observed,builtins):
    """Selectors expose only the declared ten OID fields; no row learned here."""
    require_case(case);s=sections(observed)
    obj=one(s['objects'],lambda r:r['name']==TARGET)
    index=one(s['objects'],lambda r:r['name']==KEY)
    composite=one(s['types'],lambda r:r['catalog']['typname']==TARGET)
    array=one(s['types'],lambda r:r['catalog']['typname']=='_'+TARGET)
    unique=one(s['constraints'],lambda r:r['relation']==TARGET and r['catalog']['conname']==KEY)
    fk=one(s['constraints'],lambda r:r['relation']==TABLE and r['catalog']['conname']==case['constraint'])
    source=one(sections(baseline)['objects'],lambda r:r['name']==TABLE)['oid']
    values=dict(heap=obj['oid'],index=index['oid'],composite=composite['catalog']['oid'],array=array['catalog']['oid'],unique=unique['catalog']['oid'],fk=fk['catalog']['oid'])
    for key,relation,event in [('action_delete',obj['oid'],9),('action_update',obj['oid'],17),('check_insert',source,5),('check_update',source,17)]:
        values[key]=one(s['triggers'],lambda r:r['catalog']['tgconstraint']==values['fk'] and r['catalog']['tgrelid']==relation and r['catalog']['tgtype']==event)['catalog']['oid']
    return fresh_identities(values,baseline,builtins)

def expected_setup(case,baseline,identities,builtins):
    require_case(case);ids=fresh_identities(identities,baseline,builtins)
    result=copy.deepcopy(baseline);s=sections(result)
    if s['ledger']!=[{'count':0}] or s['consumerRows']!=[{'count':0}]:raise ValueError('empty pristine predecessor required')
    if any(r['name'] in (TARGET,KEY) for r in s['objects']):raise ValueError('CTAS object already present')
    consumer=one(s['objects'],lambda r:r['name']==TABLE)
    remote=one(s['objects'],lambda r:r['name']==REMOTE)
    fk=one(s['constraints'],lambda r:r['relation']==TABLE and r['catalog']['conname']==FK)
    unique=one(s['constraints'],lambda r:r['relation']==REMOTE and r['catalog']['conname']==UNIQUE)
    index=one(s['indexes'],lambda r:r['catalog']['indexrelid']==unique['catalog']['conindid'])
    indexobj=one(s['objects'],lambda r:r['oid']==unique['catalog']['conindid'])
    source=consumer if case['source']==TABLE else remote
    attribute=lambda relation,name:one(s['columns'],lambda r:r['catalog']['attrelid']==relation and r['catalog']['attname']==name)
    sourceatts=[attribute(source['oid'],name) for name in case['targetColumns']]
    conatts=[attribute(consumer['oid'],name) for name in case['sourceColumns']]
    # Derive opclass/collation/options and three equality associations through
    # the pristine typed FK target positions, not from numeric constants.
    typed={}
    for i,attnum in enumerate(unique['catalog']['conkey']):
        att=one(s['columns'],lambda r:r['catalog']['attrelid']==remote['oid'] and r['catalog']['attnum']==attnum)['catalog']
        signature=(att['atttypid'],att['atttypmod'],att['attcollation'])
        entry=dict(indclass=index['catalog']['indclass'][i],indcollation=index['catalog']['indcollation'][i],indoption=index['catalog']['indoption'][i])
        pos=fk['catalog']['confkey'].index(attnum)
        entry.update({key:fk['catalog'][key][pos] for key in ('conpfeqop','conppeqop','conffeqop')})
        if signature in typed and typed[signature]!=entry:raise ValueError('inconsistent pristine typed association')
        typed[signature]=entry
    associations=[]
    for targetatt,conatt in zip(sourceatts,conatts,strict=True):
        a,b=targetatt['catalog'],conatt['catalog'];signature=(a['atttypid'],a['atttypmod'],a['attcollation'])
        if signature!=(b['atttypid'],b['atttypmod'],b['attcollation']) or signature not in typed:raise ValueError('unmodeled CTAS/FK source type')
        associations.append(typed[signature])
    owner=consumer['relowner']
    if source['relowner']!=owner or source['relnamespace']!=consumer['relnamespace'] or any(r['catalog']['defaclrole']==owner for r in s['defaultAcl']):raise ValueError('unmodeled owner/namespace/default ACL')
    heap=copy.deepcopy(consumer);heap.update(oid=ids['heap'],name=TARGET,reltype=ids['composite'],checks=0,relhastriggers=True,relacl=None)
    if any(heap[key]!=value for key,value in dict(relkind='r',reloftype='0',relpersistence='p',relrowsecurity=False,relforcerowsecurity=False,reloptions=None,relpartbound=None).items()):raise ValueError('unmodeled heap template')
    ixobj=copy.deepcopy(indexobj);ixobj.update(oid=ids['index'],name=KEY)
    if ixobj['relowner']!=owner or ixobj['relacl'] is not None:raise ValueError('unmodeled index owner/ACL')
    s['objects'] += [heap,ixobj]
    # Both CTAS and its plain btree key have new ordinals and no copied ACL,
    # NOT NULL, generated/default/identity/statistics/options metadata.
    reset=dict(attnotnull=False,atthasdef=False,atthasmissing=False,attidentity='',attgenerated='',attacl=None,attoptions=None,attfdwoptions=None,attmissingval=None,attstattarget=None,attcompression='',attisdropped=False,attislocal=True,attinhcount=0,attndims=0)
    for number,att in enumerate(sourceatts,1):
        for relation in (ids['heap'],ids['index']):
            new=copy.deepcopy(att);new['default_definition']=None;new['catalog'].update(reset,attrelid=relation,attnum=number);s['columns'].append(new)
    composite=copy.deepcopy(one(s['types'],lambda r:r['catalog']['oid']==consumer['reltype']))
    array=copy.deepcopy(one(s['types'],lambda r:r['catalog']['oid']==composite['catalog']['typarray']))
    composite['catalog'].update(oid=ids['composite'],typname=TARGET,typrelid=ids['heap'],typarray=ids['array'])
    array['catalog'].update(oid=ids['array'],typname='_'+TARGET,typelem=ids['composite'])
    if composite['catalog']['typacl'] is not None or array['catalog']['typacl'] is not None:raise ValueError('unmodeled type ACL')
    s['types'] += [composite,array]
    newunique=copy.deepcopy(unique);newunique['relation']=TARGET;newunique['definition']='UNIQUE ('+quoted(case['targetColumns'])+')'
    ordinals=list(range(1,len(sourceatts)+1))
    newunique['catalog'].update(oid=ids['unique'],conname=KEY,conrelid=ids['heap'],conindid=ids['index'],conkey=ordinals)
    newindex=copy.deepcopy(index);newindex['definition']='CREATE UNIQUE INDEX '+KEY+' ON public.'+TARGET+' USING btree ('+quoted(case['targetColumns'])+')'
    newindex['catalog'].update(indexrelid=ids['index'],indrelid=ids['heap'],indkey=ordinals,indnatts=len(sourceatts),indnkeyatts=len(sourceatts))
    for key in ('indclass','indcollation','indoption'):newindex['catalog'][key]=[a[key] for a in associations]
    s['indexes'].append(newindex);s['constraints'].append(newunique)
    newfk=copy.deepcopy(fk);newfk['definition']=case['definition'];newfk['catalog'].update(oid=ids['fk'],conname=case['constraint'],conindid=ids['index'],confrelid=ids['heap'],conkey=[r['catalog']['attnum'] for r in conatts],confkey=ordinals)
    for key in ('conpfeqop','conppeqop','conffeqop'):newfk['catalog'][key]=[a[key] for a in associations]
    selected=copy.deepcopy(one(s['selected'],lambda r:r['name']==FK))
    selected.update(name=case['constraint'],definition=case['definition'],columns=case['sourceColumns'][:],targetColumns=case['targetColumns'][:],targetRelation=TARGET,indexName=KEY)
    templates=[r for r in s['triggers'] if r['catalog']['tgconstraint']==fk['catalog']['oid']]
    if len(templates)!=4:raise ValueError('exact four original FK trigger templates')
    for key,action,event,kind,function in [('action_delete',True,'DELETE',9,'RI_FKey_cascade_del'),('action_update',True,'UPDATE',17,'RI_FKey_noaction_upd'),('check_insert',False,'INSERT',5,'RI_FKey_check_ins'),('check_update',False,'UPDATE',17,'RI_FKey_check_upd')]:
        oldrel=remote['oid'] if action else consumer['oid']
        trigger=copy.deepcopy(one(templates,lambda r:r['catalog']['tgrelid']==oldrel and r['catalog']['tgtype']==kind));raw=trigger['catalog']
        if raw['tgfoid']!=builtins[function] or raw['tgdeferrable'] is not False or raw['tginitdeferred'] is not False:raise ValueError('pristine admitted builtin/deferral binding')
        name='RI_ConstraintTrigger_'+('a' if action else 'c')+'_'+ids[key]
        raw.update(oid=ids[key],tgname=name,tgconstraint=ids['fk'],tgconstrindid=ids['index'],tgrelid=ids['heap'] if action else consumer['oid'],tgconstrrelid=consumer['oid'] if action else ids['heap'])
        relation=TARGET if action else TABLE;other=TABLE if action else TARGET
        trigger['definition']='CREATE CONSTRAINT TRIGGER "'+name+'" AFTER '+event+' ON public.'+relation+' FROM '+other+' NOT DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION "'+function+'"()'
        s['triggers'].append(trigger)
    if case['replace']:
        s['constraints'].remove(fk);s['selected'].remove(one(s['selected'],lambda r:r['name']==FK))
        for old in templates:s['triggers'].remove(old)
    s['constraints'].append(newfk);s['selected'].append(selected)
    # Exact owner-eight rows from a pristine null-relacl ordinary index; both
    # heap AND index are expanded by the unchanged capture projection.
    relation_acl=[r for r in s['expandedRelationAcl'] if r['oid']==indexobj['oid']]
    if len(relation_acl)!=8 or {r['privilege_type'] for r in relation_acl}!={'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN'} or any(r['grantor']!=owner or r['grantee']!=owner or r['is_grantable'] is not False for r in relation_acl):raise ValueError('pristine owner-eight ACL template')
    for oid in (ids['heap'],ids['index']):s['expandedRelationAcl'] += [dict(r,oid=oid) for r in relation_acl]
    for oldoid,newoid in ((consumer['reltype'],ids['composite']),(one(s['types'],lambda r:r['catalog']['oid']==consumer['reltype'])['catalog']['typarray'],ids['array'])):
        acl=[r for r in s['expandedTypeAcl'] if r['oid']==oldoid]
        if len(acl)!=2 or {r['grantee'] for r in acl}!={'0',owner} or any(r['grantor']!=owner or r['privilege_type']!='USAGE' or r['is_grantable'] is not False for r in acl):raise ValueError('pristine type PUBLIC/owner USAGE')
        s['expandedTypeAcl'] += [dict(r,oid=newoid) for r in acl]
    for name in ('objects','types','constraints','triggers'):s[name].sort(key=lambda r:int(r['catalog']['oid'] if 'catalog' in r else r['oid']))
    s['columns'].sort(key=lambda r:(int(r['catalog']['attrelid']),r['catalog']['attnum']))
    s['indexes'].sort(key=lambda r:int(r['catalog']['indexrelid']))
    for name in ('expandedRelationAcl','expandedTypeAcl'):s[name].sort(key=lambda r:(int(r['oid']),int(r['grantor']),int(r['grantee']),r['privilege_type'],r['is_grantable']))
    s['selected'].sort(key=lambda r:r['name'])
    return result

def raw_equal(left,right):
    """Exact JSON structure/types/array order, without rewriting captured data."""
    if type(left) is not type(right):return False
    if isinstance(left,dict):return left.keys()==right.keys() and all(raw_equal(left[key],right[key]) for key in left)
    if isinstance(left,list):return len(left)==len(right) and all(raw_equal(a,b) for a,b in zip(left,right,strict=True))
    return left==right

def verify_setup(case,baseline,observed,builtins):
    identities=bind_identities(case,baseline,observed,builtins)
    expected=expected_setup(case,baseline,identities,builtins)
    if not raw_equal(observed,expected):raise ValueError('CTAS captured public projection differs from independent full-row model')
    return dict(status='PURE_MODEL_MATCH_ONLY',identities=identities,fullS5Qualified=False)
