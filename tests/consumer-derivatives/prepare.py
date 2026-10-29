"""Static-only fixture preparation. Never starts a child, probes PG, or edits staging."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import tarfile
import uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def require_file(path,expected):
    if path.is_symlink() or not path.is_file() or sha(path)!=expected:
        raise ValueError('unexpected named public input: '+str(path))

def source_function(text,name):
    m=re.search(r'CREATE FUNCTION public\.'+name+r'\(.*?\$\$;',text,re.S)
    if not m: raise ValueError('missing expected literal function '+name)
    return m.group()

def inspect_inputs():
    lock=json.loads((HERE/'inputs.lock.json').read_text())
    for key in ['baselineReceipt','baselineArchive','candidateManifest','toolchainSidecar','ownedProcessSource']:
        item=lock[key];require_file(ROOT/item['path'],item['sha256'])
    receipt=json.loads((ROOT/lock['baselineReceipt']['path']).read_text())
    side=json.loads((ROOT/lock['toolchainSidecar']['path']).read_text())
    if not receipt['shutdownAndCleanupCompleted'] or receipt['liveSourceChangedDuringRun']:
        raise ValueError('baseline is not the closed unchanged FC66 run')
    if receipt['frozenInputsArchiveSha256']!=lock['baselineArchive']['sha256']:
        raise ValueError('archive is not the frozen receipt input')
    if side['coreSha256Before']!=side['coreSha256After'] or side['defaultInitdbScriptSha256Before']!=side['defaultInitdbScriptSha256After']:
        raise ValueError('toolchain sidecar reports drift')
    tool=ROOT/lock['toolchainRoot']
    require_file(tool/'summary.json',lock['toolchainSummarySha256'])
    require_file(tool/'acquisition-receipt.json',lock['acquisitionReceiptSha256'])
    for name,digest in lock['toolchainCoreSha256'].items(): require_file(tool/'Postgres.app'/name,digest)
    for name,digest in lock['toolchainInitdbSha256'].items(): require_file(tool/'Postgres.app'/name,digest)
    public={}
    with tarfile.open(ROOT/lock['baselineArchive']['path'],'r:gz') as archive:
        for name,digest in lock['publicArchiveMembers'].items():
            if Path(name).is_absolute() or '..' in Path(name).parts or '.env' in Path(name).parts:
                raise ValueError('unsafe allowlist member')
            member=archive.getmember(name)
            if not member.isfile() or member.issym() or member.islnk(): raise ValueError('named member is not a regular public file')
            data=archive.extractfile(member).read()
            if hashlib.sha256(data).hexdigest()!=digest or receipt['sourceInputSha256Before'][name]!=digest:
                raise ValueError('public source differs from FC66 receipt: '+name)
            public[name]=data
    staging=ROOT/'staging/consumer-derivatives'
    candidate_manifest=json.loads((ROOT/lock['candidateManifest']['path']).read_text())
    for name,digest in candidate_manifest.items(): require_file(staging/name,digest)
    for name,digest in lock['candidateCatalogFiles'].items(): require_file(staging/name,digest)
    catalog=json.loads((staging/'catalog-contract.pending.json').read_text())
    helper=json.loads((staging/'helper-seal.pending.json').read_text())
    for item in catalog['roots']+helper['helpers']:
        if any(item[k] is not None for k in ['old_catalog_sha256','new_catalog_sha256','old_acl','new_acl']):
            raise ValueError('reviewed pins must stay NULL')
    if any(x['catalog_sha256'] is not None or x['acl'] is not None for x in catalog['prerequisites']):
        raise ValueError('reviewed prerequisite pins must stay NULL')
    migrations={'lomi_consumer_inventory':'202610190006_consumer_inventory','lomi_consumer_assertion_recheck':'202610190007_pairing_proposals','lomi_consumer_recipient_recheck':'202610190008_pairing_decisions'}
    for name,migration in migrations.items():
        original=source_function(public['prisma/migrations/'+migration+'/migration.sql'].decode(),name)
        if (staging/(name+'.old-source.sql')).read_text()!=original+'\n':
            raise ValueError('candidate predecessor is not the frozen intended root')
    return lock,public,candidate_manifest

def prepare():
    lock,public,candidate=inspect_inputs()
    run_id=str(uuid.uuid4())
    plan_root=ROOT/'artifacts/consumer-derivatives-plan'/run_id
    plan_root.mkdir(parents=True,exist_ok=False)
    for name,data in public.items():
        target=plan_root/'frozen-public'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    staging=ROOT/'staging/consumer-derivatives'
    # Explicit parent creation, then only the named immutable copies.
    (plan_root/'reviewed-candidate').mkdir(exist_ok=True)
    for name in list(candidate)+['candidate-source-sha256.json',*lock['candidateCatalogFiles']]:
        (plan_root/'reviewed-candidate'/name).write_bytes((staging/name).read_bytes())
    (plan_root/'public-support').mkdir()
    (plan_root/'public-support/owned_process.py').write_bytes((ROOT/lock['ownedProcessSource']['path']).read_bytes())
    (plan_root/'inputs.lock.json').write_text((HERE/'inputs.lock.json').read_text())
    acceptance=json.loads((HERE/'acceptance.json').read_text())
    plan={'status':'PREPARED_NOT_EXECUTED','runId':run_id,'pgAdmission':None,'postgresInvocations':0,'sqlExecution':False,
      'baseline':'FC66 frozen SQL only; not mutable live Auth or operator state',
      'processOwner':'No process owner allocated. Current root appointment remains untouched.',
      'futurePrivateRoot':'/private/tmp/lomi-consumer-derivatives-'+run_id,
      'futureEnvironment':{'PATH':'/usr/bin:/bin','HOME':'<private-root>/home','TMPDIR':'<private-root>/tmp','LANG':'C','LC_ALL':'C'},
      'prohibitedInheritedEnvironment':['DATABASE_URL','PGHOST','PGPORT','PGUSER','PGPASSWORD','PGSERVICE','PGSERVICEFILE','PGPASSFILE','BUN_ENV_FILE'],
      'futureProcessPolicy':lock['fixture'],
      'migrationOrder':[n for n in sorted(public) if n.startswith('prisma/migrations/')],
      'baselineOpsOrderTwice':['ops/database-permissions.sql','ops/remote-database-permissions.sql','ops/push-database-permissions.sql'],
      'candidateOrder':['approval-intent.candidate.sql','012-derivative-authority.candidate.sql','authority-core.candidate.sql','typed-entrypoints.candidate.sql'],
      'stages':acceptance['stages'],
      'runtimeDriver':'Not included or authorized. Root reviews this concrete recipe before a fresh owned PG fixture is admitted.',
      'privateDerivedPins':'Separate RAM/owned-fixture copies only after independent reference equality and reviewed transition manifest; no pg_get_functiondef rewrite',
      'qualificationExcluded':['HTTP','BetterAuth handler','Prisma migration012','UI','production','remote service','native/Cargo']}
    (plan_root/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    source_names=['prepare.py','validate.py','inputs.lock.json','acceptance.json','fixture-ops.sql','fixture-ownership-bootstrap.sql','catalog-discovery.sql','README.md']
    (plan_root/'qualification-source').mkdir()
    for name in source_names: (plan_root/'qualification-source'/name).write_bytes((HERE/name).read_bytes())
    (plan_root/'preparation-source-sha256.json').write_text(json.dumps({n:sha(HERE/n) for n in source_names},indent=2)+'\n')
    print(json.dumps({'status':plan['status'],'path':str(plan_root),'planSha256':sha(plan_root/'plan.json'),'postgresInvocations':0}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-inputs',action='store_true')
    args=parser.parse_args()
    if args.check_inputs:
        inspect_inputs();print('PASS: named public inputs and frozen candidate verified; no PG invocation')
    else: prepare()
