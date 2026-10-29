"""Eighteen source-only ordinary-DDL faults; opaque identities are narrowly bound."""
import copy
NAMES=('RI_FKey_cascade_del','RI_FKey_noaction_upd','RI_FKey_check_ins','RI_FKey_check_upd','RI_FKey_restrict_del','RI_FKey_cascade_upd')
TABLE='public.consumer_authorization'
FK='consumer_authorization_accountSessionId_accountId_clientCl_fkey'

def sections(rows):
    result={r['section']:r['rows'] for r in rows}
    if len(result)!=len(rows) or len(result)!=27:raise ValueError('raw section closure')
    return result

def one(rows,predicate):
    matches=[r for r in rows if predicate(r)]
    if len(matches)!=1:raise ValueError('nonunique declared identity')
    return matches[0]

def build(contract):
    checks=[r for r in contract['constraints'] if r['type']=='c'];cases=[]
    if len(checks)!=4:raise ValueError('CHECK closure')
    for index,row in enumerate(checks):
        name=row['name'];original=row['definition'];other='consumer_authorization_check' if name.endswith('canManageAccount_check') else 'consumer_authorization_canManageAccount_check'
        wrong=one(checks,lambda r:r['name']==other)['definition']
        for mutation in ('wrong','notvalid','duplicate'):
            newname='fixture_pre012_duplicate' if mutation=='duplicate' else name
            expression=wrong if mutation=='wrong' else original
            setup=('' if mutation=='duplicate' else 'ALTER TABLE '+TABLE+' DROP CONSTRAINT "'+name+'";\n')+'ALTER TABLE '+TABLE+' ADD CONSTRAINT "'+newname+'" '+expression+(' NOT VALID' if mutation=='notvalid' else '')+';'
            cases.append(dict(id='check-'+str(index+1)+'-'+mutation,kind='check',name=name,newName=newname,mutation=mutation,expressionSource=other if mutation=='wrong' else name,setupSql=setup))
    fk=one(contract['constraints'],lambda r:r['name']==FK)
    prefix=fk['definition'].removesuffix(' ON DELETE CASCADE')
    for mutation,clause in [('notvalid',' ON DELETE CASCADE NOT VALID'),('immediate',' ON DELETE CASCADE DEFERRABLE INITIALLY IMMEDIATE'),('deferred',' ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED'),('delete-restrict',' ON DELETE RESTRICT'),('update-cascade',' ON UPDATE CASCADE ON DELETE CASCADE')]:
        ddl_definition=prefix+clause
        # REL_18_6 ruleutils.c prints DEFERRABLE but suppresses default IMMEDIATE
        # for constraints; trigger definitions still print INITIALLY IMMEDIATE.
        definition=ddl_definition.removesuffix(' INITIALLY IMMEDIATE')
        cases.append(dict(id='fk-'+mutation,kind='fk',name=FK,newName=FK,mutation=mutation,definition=definition,setupSql='ALTER TABLE '+TABLE+' DROP CONSTRAINT "'+FK+'";\nALTER TABLE '+TABLE+' ADD CONSTRAINT "'+FK+'" '+ddl_definition+';'))
    cases.append(dict(id='reapply-last',kind='reapply',mutation='reapply',setupSql='-- No setup DDL: independently committed first012 baseline.'))
    if len(cases)!=18 or len({c['id'] for c in cases})!=18:raise ValueError('case closure')
    return cases

def admit_builtins(rows,baseline):
    if len(rows)!=6:raise ValueError('builtin closure')
    result={};oids=set()
    for row in rows:
        raw=row['catalog'];name=raw['proname'];oid=raw['oid']
        if name not in NAMES or name in result or type(oid)!=str or not oid.isdecimal() or int(oid)<=0 or str(int(oid))!=oid or oid in oids:raise ValueError('builtin identity')
        if (row['namespace'],row['language'],row['returnNamespace'],row['returnType'])!=('pg_catalog','internal','pg_catalog','trigger'):raise ValueError('builtin namespace/language/type')
        if raw['prosrc']!=name or raw['prokind']!='f' or raw['pronargs']!=0 or (type(raw['proargtypes']) is not list or raw['proargtypes']!=[]) or raw['prosecdef'] is not False or raw['proretset'] is not False:raise ValueError('builtin signature/security')
        result[name]=oid;oids.add(oid)
    if set(result)!=set(NAMES):raise ValueError('builtin names')
    reverse={v:k for k,v in result.items()};bound=set()
    for trigger in sections(baseline)['triggers']:
        raw=trigger['catalog']
        for name in NAMES:
            if trigger['definition'].endswith('EXECUTE FUNCTION "'+name+'"()'):
                if raw['tgfoid']!=result[name]:raise ValueError('pristine builtin name/OID binding')
                bound.add(name)
        if raw['tgfoid'] in reverse and not trigger['definition'].endswith('EXECUTE FUNCTION "'+reverse[raw['tgfoid']]+'"()'):raise ValueError('pristine builtin trigger binding')
    if not set(NAMES[:4])<=bound:raise ValueError('missing four pristine builtin bindings')
    return result

def expected_setup(case,baseline,observed,reference,builtins):
    """Only fresh OID scalars are taken from observed; every other field is predicted."""
    if case['kind']=='reapply':
        sections(observed);return copy.deepcopy(baseline)
    result=copy.deepcopy(baseline);s=sections(result);actual=sections(observed);ref=sections(reference)
    old=one(s['constraints'],lambda r:r['relation']=='consumer_authorization' and r['catalog']['conname']==case['name'])
    old_selected=one(s['selected'],lambda r:r['name']==case['name'])
    candidate=one(actual['constraints'],lambda r:r['relation']=='consumer_authorization' and r['catalog']['conname']==case['newName'])
    previous=set(builtins.values());fresh=set()
    def occupied(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key=='oid':previous.add(str(item))
                else:occupied(item)
        elif isinstance(value,list):
            for item in value:occupied(item)
    occupied(baseline)
    def oid(value):
        if type(value)!=str or not value.isdecimal() or int(value)<=0 or str(int(value))!=value or value in previous or value in fresh:raise ValueError('nonfresh/duplicate generated OID')
        fresh.add(value);return value
    new=copy.deepcopy(old);new['catalog']['oid']=oid(candidate['catalog']['oid']);new['catalog']['conname']=case['newName']
    selected=copy.deepcopy(old_selected);selected['name']=case['newName']
    if case['kind']=='check':
        template=one(ref['constraints'],lambda r:r['relation']=='consumer_authorization' and r['catalog']['conname']==case['expressionSource'])
        templated=one(ref['selected'],lambda r:r['name']==case['expressionSource'])
        # conbin/conkey are independent accepted expression fields, never fault rows.
        for key in ('conbin','conkey'):new['catalog'][key]=copy.deepcopy(template['catalog'][key])
        new['definition']=template['definition'];selected['definition']=templated['definition'];selected['columns']=copy.deepcopy(templated['columns'])
        if case['mutation']=='notvalid':
            new['catalog']['convalidated']=False;selected['validated']=False
            new['definition']+=' NOT VALID';selected['definition']+=' NOT VALID'
        if case['mutation']=='duplicate':
            one(s['objects'],lambda r:r['name']=='consumer_authorization')['checks']+=1
        else:s['constraints'].remove(old);s['selected'].remove(old_selected)
    elif case['kind']=='fk':
        mutation=case['mutation'];defer=mutation in ('immediate','deferred');initial=mutation=='deferred'
        new['definition']=case['definition'];selected['definition']=case['definition']
        for rawkey,selectedkey,value in [('convalidated','validated',mutation!='notvalid'),('condeferrable','deferrable',defer),('condeferred','deferred',initial),('confdeltype','deleteAction','r' if mutation=='delete-restrict' else 'c'),('confupdtype','updateAction','c' if mutation=='update-cascade' else 'a')]:
            new['catalog'][rawkey]=value;selected[selectedkey]=value
        old_triggers=[r for r in s['triggers'] if r['catalog']['tgconstraint']==old['catalog']['oid']]
        new_triggers=[r for r in actual['triggers'] if r['catalog']['tgconstraint']==new['catalog']['oid']]
        if len(old_triggers)!=4 or len(new_triggers)!=4:raise ValueError('four FK triggers required')
        keys={(r['catalog']['tgrelid'],r['catalog']['tgtype']) for r in new_triggers}
        if keys!={(r['catalog']['tgrelid'],r['catalog']['tgtype']) for r in old_triggers} or len(keys)!=4:raise ValueError('FK trigger relationships')
        for oldtrigger in old_triggers:
            raw=oldtrigger['catalog'];candidate_trigger=one(new_triggers,lambda r:(r['catalog']['tgrelid'],r['catalog']['tgtype'])==(raw['tgrelid'],raw['tgtype']))
            trigger=copy.deepcopy(oldtrigger);t=trigger['catalog'];t['oid']=oid(candidate_trigger['catalog']['oid']);t['tgconstraint']=new['catalog']['oid']
            action=raw['tgrelid']==old['catalog']['confrelid'];event='DELETE' if raw['tgtype']==9 else ('INSERT' if raw['tgtype']==5 else 'UPDATE')
            function=('RI_FKey_restrict_del' if mutation=='delete-restrict' else 'RI_FKey_cascade_del') if action and event=='DELETE' else (('RI_FKey_cascade_upd' if mutation=='update-cascade' else 'RI_FKey_noaction_upd') if action else ('RI_FKey_check_ins' if event=='INSERT' else 'RI_FKey_check_upd'))
            t['tgfoid']=builtins[function];t['tgname']='RI_ConstraintTrigger_'+('a' if action else 'c')+'_'+t['oid']
            t['tgdeferrable']=defer and function not in ('RI_FKey_cascade_del','RI_FKey_restrict_del','RI_FKey_cascade_upd');t['tginitdeferred']=initial and t['tgdeferrable']
            mode=('DEFERRABLE' if t['tgdeferrable'] else 'NOT DEFERRABLE')+' INITIALLY '+('DEFERRED' if t['tginitdeferred'] else 'IMMEDIATE')
            relation='remote_session_binding' if action else 'consumer_authorization';other='consumer_authorization' if action else 'remote_session_binding'
            trigger['definition']='CREATE CONSTRAINT TRIGGER "'+t['tgname']+'" AFTER '+event+' ON public.'+relation+' FROM '+other+' '+mode+' FOR EACH ROW EXECUTE FUNCTION "'+function+'"()'
            s['triggers'].remove(oldtrigger);s['triggers'].append(trigger)
        s['constraints'].remove(old);s['selected'].remove(old_selected)
    else:raise ValueError('case kind')
    s['constraints'].append(new);s['selected'].append(selected)
    s['constraints'][:]=sorted(s['constraints'],key=lambda r:int(r['catalog']['oid']))
    s['triggers'][:]=sorted(s['triggers'],key=lambda r:int(r['catalog']['oid']))
    s['selected'][:]=sorted(s['selected'],key=lambda r:r['name'])
    return result


def first012_script(operator):
    if '\nBEGIN;\n' not in operator or not operator.rstrip().endswith('COMMIT;'):raise ValueError('whole012 shape')
    return operator+"\nSELECT 'FIRST012_COMMITTED';\n"

def admit_first012_stdout(stdout):
    if stdout!="\nFIRST012_COMMITTED\n":raise ValueError('first012 missing confirmed post-COMMIT output')
    return True
