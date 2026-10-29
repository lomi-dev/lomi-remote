"""Ten ordinary-DDL pristine predecessor faults; pure source model."""
import copy
import re
MESSAGE='v2 predecessor contract mismatch; no DDL admitted'

def build(contract):
    if len(contract['constraints'])!=5:raise ValueError('constraint closure')
    cases=[]
    for index,row in enumerate(contract['constraints']):
        for mutation in ('missing','renamed'):
            name=row['name'];renamed='fixture_pre012_renamed'
            sql='ALTER TABLE public.consumer_authorization '+('DROP CONSTRAINT "'+name+'";' if mutation=='missing' else 'RENAME CONSTRAINT "'+name+'" TO '+renamed+';')
            cases.append(dict(id=str(index+1)+'-'+mutation,name=name,mutation=mutation,renamed=renamed,setupSql=sql,expectedPsqlExit=3,expectedSqlstate='55000',expectedGuardMessage=MESSAGE))
    return cases

def expected_setup(case,baseline,contract):
    """Only declared existing-row removal/rename; no captured target supplies pins."""
    result=copy.deepcopy(baseline)
    sections={r['section']:r['rows'] for r in result}
    selected=sections['selected'];rows=[r for r in selected if r['name']==case['name']]
    if len(rows)!=1:raise ValueError('selected identity')
    constraints=sections['constraints'];matches=[r for r in constraints if r['catalog']['conname']==case['name'] and r['relation']=='consumer_authorization']
    if len(matches)!=1:raise ValueError('raw constraint identity')
    raw=matches[0];oid=raw['catalog']['oid']
    if case['mutation']=='renamed':
        rows[0]['name']=case['renamed'];raw['catalog']['conname']=case['renamed']
        # The strict SQL orders selected rows by name. Generate that prescribed
        # ordering; captured rows themselves are never reordered or normalized.
        sections['selected'][:]=sorted(selected,key=lambda r:r['name'])
    elif case['mutation']=='missing':
        selected.remove(rows[0]);constraints.remove(raw)
        sections['triggers'][:]=[r for r in sections['triggers'] if r['catalog']['tgconstraint']!=oid]
        if rows[0]['type']=='c':
            relation=[r for r in sections['objects'] if r['name']=='consumer_authorization']
            if len(relation)!=1:raise ValueError('relation identity')
            relation[0]['checks']-=1
    else:raise ValueError('undeclared mutation')
    return result

def markers(case):return [case['id']+':'+x for x in ('SETUP_BEGIN','SETUP_END','ATTEMPT','UNEXPECTED_ACCEPTANCE')]

def branch_sql(case,capture_sql,operator):
    if '\nBEGIN;\n' not in operator or not operator.rstrip().endswith('COMMIT;'):raise ValueError('whole012 shape')
    m=markers(case);tag=lambda s:"SELECT '"+s+"';\n"
    return 'BEGIN;\n'+case['setupSql']+'\n'+tag(m[0])+capture_sql+'\n'+tag(m[1])+tag(m[2])+operator+'\n'+tag(m[3])

def parse_result(case,stdout,stderr,parse):
    lines=stdout.splitlines();m=markers(case)
    if any(lines.count(t)!=1 for t in m[:3]) or m[3] in lines:raise ValueError('012 accepted/incomplete markers')
    a,b,c=[lines.index(t) for t in m[:3]]
    # The unchanged012 advisory-lock SELECT emits exactly one empty result
    # line under pinned psql -qAt before the strict guard rejects.
    if a!=0 or not a<b or c!=b+1 or lines[c+1:]!=['']:raise ValueError('marker order/extra output')
    if re.findall(r'ERROR:\s+([A-Z0-9]{5}):\s*([^\n]+)',stderr)!=[('55000',MESSAGE)]:raise ValueError('unexpected setup/guard error')
    return parse('\n'.join(lines[a+1:b]))
