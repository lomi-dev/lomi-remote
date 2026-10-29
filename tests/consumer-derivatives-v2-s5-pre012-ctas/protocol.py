"""Source-only transaction/protocol renderer; no process or Guardian harness.

Future executor must supply owned psql3 and complete actual stdout/stderr, save
raw captures/authority result, and prove post-rollback equality on all3 DBs.
A pure model/protocol return alone never establishes actual execution.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
DATABASES=('lomi_derivative_fixture','lomi_derivative_reference_old','lomi_derivative_reference_new')
MESSAGE='v2 predecessor contract mismatch; no DDL admitted'
DEPENDENCIES=dict(base='tests/consumer-derivatives-v2/pg-s0-s4.py',predecessor='tests/consumer-derivatives-v2/predecessor-model.py',extended='tests/consumer-derivatives-v2-s5-pre012-extended/cases.py')

def admit():
    lock=json.loads((HERE/'inputs.lock.json').read_bytes())
    for name,pin in {**lock['dependenciesSha256'],**{'tests/consumer-derivatives-v2-s5-pre012-ctas/'+name:pin for name,pin in lock['localSha256'].items()}}.items():
        path=ROOT/name
        if any(p.is_symlink() for p in (path,*path.parents)) or hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise ValueError('CTAS source closure substitution')
    return lock

def load_modules():
    admit();result={}
    for name,relative in {**DEPENDENCIES,'model':'tests/consumer-derivatives-v2-s5-pre012-ctas/cases.py'}.items():
        spec=importlib.util.spec_from_file_location('ctas_pinned_'+name,ROOT/relative);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);result[name]=module
    return result

def contract():
    admit();return json.loads((ROOT/'staging/consumer-derivatives-v2/predecessor-contract.json').read_bytes())

def capture_sql(modules):
    admit();guard=modules['predecessor'].guard_sql(contract())
    projection=guard[guard.index(' SELECT coalesce('):guard.index(' IF actual IS DISTINCT')].replace(' INTO actual','',1)
    return (ROOT/'tests/consumer-derivatives-v2-s5-pre012/raw-capture.sql').read_text()+"SELECT jsonb_build_object('section','selected','rows',q.value) FROM ("+projection.strip().removesuffix(';')+") q(value);\n"

def markers(case):return [case['id']+':'+name for name in ('RAW_BEGIN','RAW_END','AUTHORITY_BEGIN','AUTHORITY_END','ATTEMPT','UNEXPECTED_ACCEPTANCE')]

def branch_sql(case,modules):
    admit();modules['model'].require_case(case)
    operator=(ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').read_text()
    if '\nBEGIN;\n' not in operator or not operator.rstrip().endswith('COMMIT;'):raise ValueError('whole frozen012 shape')
    metadata=(ROOT/'tests/consumer-derivatives-v2/pg-s0-s4-metadata.sql').read_text()
    m=markers(case);tag=lambda value:"SELECT '"+value+"';\n"
    # Actual authority rows are inside the SAME fault transaction; no capture()
    # envelope shortcut and no pristine-metadata equality against intentional DDL.
    return 'BEGIN;\n'+case['setupSql']+'\n'+tag(m[0])+capture_sql(modules)+tag(m[1])+tag(m[2])+metadata+'\n'+tag(m[3])+tag(m[4])+operator+'\n'+tag(m[5])

def parse_result(case,stdout,stderr,psql_exit):
    if type(psql_exit)!=int or psql_exit!=3:raise ValueError('actual owned psql3 required')
    lines=stdout.splitlines();m=markers(case)
    if any(lines.count(mark)!=1 for mark in m[:5]) or m[5] in lines:raise ValueError('missing/duplicate/acceptance marker')
    a,b,c,d,e=[lines.index(mark) for mark in m[:5]]
    if a!=0 or not a<b or c!=b+1 or not c<d or e!=d+1 or lines[e+1:]!=['']:raise ValueError('exact ordered captures and single advisory blank required')
    if re.findall(r'ERROR:\s+([A-Z0-9]{5}):\s*([^\n]+)',stderr)!=[('55000',MESSAGE)]:raise ValueError('unexpected setup/operator error')
    raw=[json.loads(line) for line in lines[a+1:b]]
    metadata=[json.loads(line) for line in lines[c+1:d]]
    kinds={'objectAcl','columnAcl','schemaAuthority','constraint','trigger','index','role','membership','defaultAcl','relationIdentity'}
    if not metadata or any(type(row)!=dict or row.get('kind') not in kinds for row in metadata) or {row['kind'] for row in metadata}!=kinds:raise ValueError('actual metadata row-kind closure, no vacuous envelopes')
    return raw,metadata

def verify_attempt(case,baseline,stdout,stderr,psql_exit,builtin_rows,modules):
    admit();raw,metadata=parse_result(case,stdout,stderr,psql_exit)
    modules['model'].sections(baseline)
    modules['predecessor'].admit_predecessors(next(r['rows'] for r in baseline if r['section']=='selected'),contract())
    builtins=modules['extended'].admit_builtins(builtin_rows,baseline)
    # The original source guard must RETURN on actual metadata, not27 wrappers.
    modules['base'].reject_authority_drift(metadata)
    authority=dict(marker=case['id']+':ORIGINAL_AUTHORITY_GUARD_RETURNED',metadataRows=len(metadata),metadataSha256=hashlib.sha256(json.dumps(metadata,separators=(',',':'),sort_keys=True).encode()).hexdigest(),rawEnvelopeShortcutUsed=False)
    modeled=modules['model'].verify_setup(case,baseline,raw,builtins)
    return dict(status='PROTOCOL_MODEL_MATCH_ONLY_ACTUAL_EXECUTION_NOT_ESTABLISHED',setup=raw,metadata=metadata,authorityGuard=authority,model=modeled,fullS5Qualified=False)

def verify_rollback_all(baseline,after,modules):
    admit()
    if set(baseline)!=set(DATABASES) or set(after)!=set(DATABASES):raise ValueError('all3 same-database rollback snapshots required')
    for database in DATABASES:
        s=modules['model'].sections(after[database]);modules['model'].sections(baseline[database])
        if not modules['model'].raw_equal(after[database],baseline[database]) or s['ledger']!=[{'count':0}] or s['consumerRows']!=[{'count':0}] or any(row['name'] in (modules['model'].TARGET,modules['model'].KEY) for row in s['objects']):raise ValueError('raw same-database rollback mismatch/setup remains')
        modules['predecessor'].admit_predecessors(s['selected'],contract())
    return dict(status='PURE_ROLLBACK_COMPARISON_ONLY',databases=list(DATABASES),fullS5Qualified=False)
