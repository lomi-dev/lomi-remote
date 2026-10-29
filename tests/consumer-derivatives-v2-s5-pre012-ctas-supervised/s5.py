"""Standalone four-CTAS in-process Guardian fixture; runtime NOT admitted by source."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import math
import os
import resource
import re
import shutil
import sys
import tempfile
import time
import uuid
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
MODEL=ROOT/'tests/consumer-derivatives-v2-s5-pre012-ctas'
PRIOR=ROOT/'tests/consumer-derivatives-v2-s5-admission-supervised'
SUPERVISED=ROOT/'tests/consumer-derivatives-v2-s5-pre012-supervised'
STATUS='PROVISIONAL_CTAS4_SUBSET_PENDING_ROOT_REVIEW'
STAGES={'PRE012_PREFIX':'PASS','PRE012_CTAS_SUBSET':'SUBSET_PASS','S3':'NOT_RUN','S4':'NOT_RUN'}

def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

def dependencies():
    lock=json.loads((HERE/'inputs.lock.json').read_bytes())
    if {p.name for p in HERE.iterdir()}!=set(lock['localSha256'])|{'inputs.lock.json'}:raise ValueError('CTAS supervised closed source allowlist')
    for path,pin in [(HERE/n,p) for n,p in lock['localSha256'].items()]+[(ROOT/n,p) for n,p in lock['dependenciesSha256'].items()]:
        if any(p.is_symlink() for p in (path,*path.parents)) or sha(path.read_bytes())!=pin:raise ValueError('CTAS supervised source substitution')
    # Reviewed historical14312 admission routing + separately pinned live320.
    # No old helper/controller/entrypoint is executed.
    prior=load('ctas_admitted_prior',PRIOR/'s5.py');helper,_unused_five=prior.dependencies()
    protocol=load('ctas_admitted_protocol',MODEL/'protocol.py');protocol.admit()
    return prior,helper,protocol,protocol.load_modules()

def owned_phase(guardian,make_fixture,exercise):
    """Constructor/parser/recorder errors cannot preempt mandatory owner cleanup."""
    fixture=None;error=None
    try:
        guardian.install();fixture=make_fixture();exercise(fixture)
    except BaseException as exc:error=exc
    finally:clean=guardian.finish_owner()
    return fixture,error,clean

def pristine(modules,protocol,rows):
    s=modules['model'].sections(rows)
    if s['ledger']!=[{'count':0}] or s['consumerRows']!=[{'count':0}] or any(r['name'].startswith('fixture_pre012') for r in s['objects']):raise ValueError('pristine empty pre012/setup absence')
    modules['predecessor'].admit_predecessors(s['selected'],protocol.contract())
    return rows

def validate_attempt(case,baseline,stdout,stderr,exit_code,builtins,compiled,modules,protocol):
    # Metadata was captured inside setup before012. Python guard runs HERE,
    # after the owned rejected psql process returns; this is not a live SQL gate.
    setup,metadata=protocol.parse_result(case,stdout,stderr,exit_code)
    modules['base'].reject_authority_drift(metadata)
    identities=modules['model'].bind_identities(case,baseline,setup,builtins)
    expected=compiled.instantiate(identities)
    if not modules['model'].raw_equal(setup,expected):raise ValueError('compiled independent CTAS setup mismatch')
    return setup,expected,metadata,dict(case=case['id'],identities=identities,psqlExit=exit_code,sqlstate='55000',status='PASS',
        authorityGuard=dict(originalGuardReturned=True,metadataCapturedInsideSetupBefore012=True,pythonGuardValidatedAfterOwnedPsqlReturn=True,livePreOperatorPythonGateClaimed=False),
        actualExecutionEstablishedByThisPureFunction=False)

def run_cases(base,f,inputs,protocol,modules,prepared):
    prefix=load('ctas_pristine_prefix',SUPERVISED/'prefix.py')
    prefix.execute(base,f,inputs)
    capture=protocol.capture_sql(modules)
    baseline={db:pristine(modules,protocol,f.capture(db,'ctas-baseline-'+db,capture)) for db in protocol.DATABASES}
    builtin_sql=(SUPERVISED/'builtin-trigger-identities.sql').read_text();builtins={}
    for db in protocol.DATABASES:
        raw=f.capture(db,'ctas-builtin-identities-'+db,builtin_sql)
        builtins[db]=modules['extended'].admit_builtins(raw,baseline[db])
    f.save('ctas-baseline-builtins.json',builtins)
    cases=modules['model'].build();f.save('ctas-source-cases.json',cases)
    compiled=[]
    # Compile every independent full-row expectation BEFORE the first fault.
    for index,case in enumerate(cases):
        db=protocol.DATABASES[index%3];item=prepared.Prepared(modules['model'],case,baseline[db],builtins[db]);compiled.append(item)
        f.save('compiled-'+case['id']+'.json',item.evidence())
    f.save('ctas-all-models-compiled-before-faults.json',dict(caseIds=[c['id'] for c in cases],count=4,allCompiledBeforeFirstFault=True))
    results=[]
    for index,case in enumerate(cases):
        before={db:pristine(modules,protocol,f.capture(db,'before-'+case['id']+'-'+db,capture)) for db in protocol.DATABASES}
        protocol.verify_rollback_all(baseline,before,modules)
        db=protocol.DATABASES[index%3];script=protocol.branch_sql(case,modules);raw=script.encode()
        path=f.work/('ctas-'+case['id']+'.sql');path.write_bytes(raw)
        f.recording_store.save_bytes('ctas-script-'+case['id']+'.sql',raw)
        f.save('script-'+case['id']+'.json',dict(database=db,case=case,sqlSha256=sha(raw),whole012Sha256=sha((ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').read_bytes())))
        stdout=f.command('ctas-attempt-'+case['id'],[f.pg/'psql','-X','--no-password','-qAt','-h',f.work/'socket','-p','55439','-U','e2_owner','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-d',db,'-f',path],expected=(3,))
        event=f.events[-1];setup,expected,metadata,result=validate_attempt(case,baseline[db],stdout,event['stderr'],event['returncode'],builtins[db],compiled[index],modules,protocol)
        f.save('attempt-'+case['id']+'.json',dict(commandSequence=f.sequence,database=db,result=result))
        f.save('setup-'+case['id']+'.json',setup);f.save('expected-setup-'+case['id']+'.json',expected)
        f.save('actual-metadata-'+case['id']+'.json',metadata);f.save('authority-validation-'+case['id']+'.json',result['authorityGuard'])
        after={name:pristine(modules,protocol,f.capture(name,'after-'+case['id']+'-'+name,capture)) for name in protocol.DATABASES}
        protocol.verify_rollback_all(baseline,after,modules)
        result.update(database=db,allThreeDatabasesRawRollback=True,baselineKind='pristine-pre012');results.append(result)
    f.save('ctas-results.json',results)
    return results

def check_reader(reader):
    if reader.validate() is not True:raise ValueError('reader must return literalTrue')

def verify_sql_sources(reader):
    # This fixture uses the recorder root scope; the prior five-cluster checker
    # requires a nonempty scope and intentionally is not called with ''.
    records={name for name in reader.index['files'] if re.fullmatch(r'sql-[0-9]+\.json',name)}
    sources={name for name in reader.index['files'] if re.fullmatch(r'source-sql-[0-9]+\.sql',name)}
    if not records or len(records)!=len(sources):raise ValueError('root SQL source closure')
    for name in records:
        sequence=Path(name).stem.removeprefix('sql-')
        if reader.raw('source-sql-'+sequence+'.sql')!=reader.read(name)['sql'].encode():raise ValueError('root SQL exact byte mismatch')

def verify_prefix(reader,base,protocol):
    built=reader.read('reference-transcripts.json');old=built['referenceOld']['steps']
    if built['pinsFilled'] is not False or built['catalogInputAccepted'] is not False or len(old)!=36 or not old[30]['id'].endswith('approval-intent.candidate.sql'):raise ValueError('pristine constructor prefix')
    for step in old:
        if step['role']!='e2_owner' or base.digest(step['sql'].encode())!=step['emittedSha256']:raise ValueError('source transcript drift')
    ledger=base.checked(base.HERE/'pg-s0-s4-ledger-fixture.sql',base.LEDGER_FIXTURE_HASH).decode()
    steps=[*base.baseline_steps_with_ledger(old,ledger),old[30]]
    if reader.read('pre012-prefix-schedule.json')!=dict(steps=steps,prismaLedgerQualified=False,stoppedBefore012=True) or len(steps)!=32:raise ValueError('prefix must stop before012')
    sqlrows=[reader.read(name) for name in reader.index['files'] if re.fullmatch(r'sql-[0-9]+\.json',name)]
    for db in protocol.DATABASES:
        for step in steps:
            matches=[r for r in sqlrows if r['database']==db and r['label']==db+':'+step['id']]
            if len(matches)!=1 or matches[0]['sql']!=step['sql']:raise ValueError('actual three-database prefix SQL closure')

def verify_stored(reader,prior,helper,protocol,modules,prepared):
    check_reader(reader);verify_sql_sources(reader);verify_prefix(reader,modules['base'],protocol)
    baseline={db:pristine(modules,protocol,reader.read('ctas-baseline-'+db+'.json')) for db in protocol.DATABASES}
    builtins={db:modules['extended'].admit_builtins(reader.read('ctas-builtin-identities-'+db+'.json'),baseline[db]) for db in protocol.DATABASES}
    model=modules['model'];cases=model.build()
    if not model.raw_equal(reader.read('ctas-source-cases.json'),cases):raise ValueError('stored four-case source closure')
    if reader.read('ctas-baseline-builtins.json')!=builtins:raise ValueError('stored builtin mapping')
    if reader.read('ctas-all-models-compiled-before-faults.json')!=dict(caseIds=[c['id'] for c in cases],count=4,allCompiledBeforeFirstFault=True):raise ValueError('stored before-fault compilation closure')
    results=[]
    for index,case in enumerate(cases):
        db=protocol.DATABASES[index%3];compiled=prepared.Prepared(model,case,baseline[db],builtins[db])
        if not model.raw_equal(reader.read('compiled-'+case['id']+'.json'),compiled.evidence()):raise ValueError('stored independent template')
        if reader.raw('ctas-script-'+case['id']+'.sql')!=protocol.branch_sql(case,modules).encode():raise ValueError('stored whole SQL/operator bytes')
        expected_header=dict(database=db,case=case,sqlSha256=sha(protocol.branch_sql(case,modules).encode()),whole012Sha256=sha((ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').read_bytes()))
        if not model.raw_equal(reader.read('script-'+case['id']+'.json'),expected_header):raise ValueError('stored script header/source binding')
        attempt=reader.read('attempt-'+case['id']+'.json');seq=attempt['commandSequence']
        if type(seq)!=int or seq<=0 or attempt['database']!=db:raise ValueError('stored command sequence/database')
        entry=reader.read('commands.json')[seq-1]
        if entry['id']!=seq or entry['label']!='ctas-attempt-'+case['id'] or entry['returncode']!=3:raise ValueError('stored actual owned command')
        streams=reader.read('owned-result-'+str(seq)+'.json')
        if type(streams)!=list or [r['stream'] for r in streams]!=['stdout','stderr'] or any(set(r)!={'stream','stdout','rawSha256'} or type(r['rawSha256'])!=str or len(r['rawSha256'])!=64 or any(c not in '0123456789abcdef' for c in r['rawSha256']) for r in streams):raise ValueError('owned legacy text/rawSHA closure')
        # These are exact normalized legacy text, with raw byte hashes retained;
        # do not claim reconstructible original CRLF bytes from text.
        stdout,stderr=[reader.stdout(r['stdout']) for r in streams]
        setup,expected,metadata,result=validate_attempt(case,baseline[db],stdout,stderr,entry['returncode'],builtins[db],compiled,modules,protocol)
        for name,value in [('setup',setup),('expected-setup',expected),('actual-metadata',metadata),('authority-validation',result['authorityGuard'])]:
            if not model.raw_equal(reader.read(name+'-'+case['id']+'.json'),value):raise ValueError('stored actual/model/authority disagreement')
        for side in ('before','after'):
            rows={name:reader.read(side+'-'+case['id']+'-'+name+'.json') for name in protocol.DATABASES};protocol.verify_rollback_all(baseline,rows,modules)
        if not model.raw_equal(attempt['result'],result):raise ValueError('stored attempt validation result')
        result.update(database=db,allThreeDatabasesRawRollback=True,baselineKind='pristine-pre012');results.append(result)
    if not model.raw_equal(reader.read('ctas-results.json'),results):raise ValueError('stored result closure')
    startup=reader.read('startup-status.json');shutdown=reader.read('shutdown-clients.json')
    if [r['returncode'] for r in startup]!=[0] or [r['argv'][-1] for r in startup]!=['status'] or any(type(r['returncode'])!=int for r in startup):raise ValueError('actual startup status0 receipt')
    if [r['returncode'] for r in shutdown]!=[0,3] or [r['argv'][-1] for r in shutdown]!=['stop','status'] or any(type(r['returncode'])!=int for r in shutdown):raise ValueError('actual stop0/status3 receipts')
    check_reader(reader);return results

def finalize(store,guardian,fixture,clean,prior,helper,protocol,modules,prepared,manifest,postflight,recorder):
    # Called only AFTER mandatory finish_owner; errors cannot prevent PG cleanup.
    if fixture is None or fixture.evidence_errors or guardian.evidence_errors or not prior.cleanup_is_admissible(clean) or not guardian.observe_qualification():raise ValueError('unqualified sole-owner completion')
    post=postflight();prior.ordinary_receipts(fixture,'shutdown-clients.json',lambda c:c.name=='pg_ctl' and c.argv[-1] in ('stop','status'))
    policy=fixture.raw_log_policy.metadata()
    if not helper.resource_metadata_is_admissible(policy) or type(policy.get('currentReservedBytes'))!=int or policy['currentReservedBytes']!=64*1024**2:raise ValueError('resource metadata incomplete')
    hashes=store.seal();index_sha=hashes['storage-index.json'];reader=recorder.EvidenceReader(store.root,expected_index_sha256=index_sha)
    verify_stored(reader,prior,helper,protocol,modules,prepared)
    manifest.update(status=STATUS,runId=store.root.name,driverInProcess=True,authoritative=False,ctasCount=4,ctasCompleted=True,boundedSubsetCompleted=True,first012Committed=False,sameDatabaseRawProjectionPairs=12,rawPublicSections=27,globalToastCatalogProof=False,businessAndLifecycle=False,fullS5Qualified=False,qualification={'S5':False},stages=STAGES,cleanup=clean,rawLogResourcePolicy=policy,originalInputsUnchanged=True,recordingComplete=True,evidenceWriteErrors=[],storageIndexSha256=index_sha,evidenceSha256=hashes,postflight=post)
    manifest_sha=store.save('transition-manifest.json',manifest)
    if not guardian.observe_qualification():raise ValueError('original900 closed before receipt')
    receipt=dict(status='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO',runId=store.root.name,manifestSha256=manifest_sha,storageIndexSha256=index_sha,driverInProcess=True,ctasCount=4,requiresOwnedControllerExitCode=0,originalOuterDeadlineSeconds=900,manifestAloneIsAdmission=False,receiptAloneIsAdmission=False)
    pending=store.root/'completion-receipt.pending.json'
    with os.fdopen(os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as stream:stream.write(helper.receipt_bytes(receipt))
    os.replace(pending,store.root/'completion-receipt.json')
    if not guardian.observe_qualification():raise ValueError('original900 closed after receipt')
    check_reader(reader);return receipt

def completion_is_admissible(raw,receipt,outer,reader):
    prior,helper,protocol,modules=dependencies();prepared=load('ctas_completion_prepared',HERE/'prepared.py')
    receipt_keys={'status','runId','manifestSha256','storageIndexSha256','driverInProcess','ctasCount','requiresOwnedControllerExitCode','originalOuterDeadlineSeconds','manifestAloneIsAdmission','receiptAloneIsAdmission'}
    outer_keys={'runId','manifestSha256','storageIndexSha256','driverInProcess','ownedControllerExitCode','originalOuterDeadlineSeconds','completed','elapsedSeconds'}
    if type(raw)!=bytes or type(receipt)!=dict or type(outer)!=dict or set(receipt)!=receipt_keys or set(outer)!=outer_keys:return False
    if reader.validate() is not True:return False
    try:
        if helper.stored_completion_bytes(reader,'transition-manifest.json')!=raw or helper.stored_completion_bytes(reader,'completion-receipt.json')!=helper.receipt_bytes(receipt):return False
        recorder=load('ctas_completion_recorder',ROOT/'tests/consumer-fixture-evidence/recording.py');m=recorder.strict_json(raw);run_id=receipt['runId']
        if type(run_id)!=str or str(uuid.UUID(run_id))!=run_id:return False
    except (OSError,ValueError,TypeError):return False
    if type(m)!=dict:return False
    elapsed=outer['elapsedSeconds']
    if not (run_id==reader.root.name==m.get('runId')==outer['runId'] and receipt['manifestSha256']==sha(raw)==outer['manifestSha256']
        and receipt['storageIndexSha256']==reader.index_pin==m.get('storageIndexSha256')==outer['storageIndexSha256']
        and receipt['status']=='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO' and receipt['driverInProcess'] is True and type(receipt['ctasCount'])==int and receipt['ctasCount']==4
        and receipt['manifestAloneIsAdmission'] is False and receipt['receiptAloneIsAdmission'] is False and type(receipt['requiresOwnedControllerExitCode'])==int and receipt['requiresOwnedControllerExitCode']==0
        and type(receipt['originalOuterDeadlineSeconds'])==int and receipt['originalOuterDeadlineSeconds']==900 and type(outer['originalOuterDeadlineSeconds'])==int and outer['originalOuterDeadlineSeconds']==900
        and type(outer['ownedControllerExitCode'])==int and outer['ownedControllerExitCode']==0 and outer['completed'] is True and outer['driverInProcess'] is True
        and type(elapsed) in (int,float) and math.isfinite(elapsed) and 0<=elapsed<900
        and m.get('status')==STATUS and m.get('authoritative') is False and m.get('driverInProcess') is True and m.get('fullS5Qualified') is False and type(m.get('qualification')) is dict and set(m['qualification'])=={'S5'} and m['qualification']['S5'] is False
        and m.get('ctasCompleted') is True and m.get('boundedSubsetCompleted') is True and type(m.get('ctasCount'))==int and m['ctasCount']==4 and m.get('first012Committed') is False and m.get('stages')==STAGES
        and type(m.get('sameDatabaseRawProjectionPairs'))==int and m['sameDatabaseRawProjectionPairs']==12 and type(m.get('rawPublicSections'))==int and m['rawPublicSections']==27 and m.get('globalToastCatalogProof') is False and m.get('businessAndLifecycle') is False
        and m.get('originalInputsUnchanged') is True and m.get('recordingComplete') is True and m.get('evidenceWriteErrors')==[] and prior.cleanup_is_admissible(m.get('cleanup'))
        and helper.resource_metadata_is_admissible(m.get('rawLogResourcePolicy'))):return False
    post=m.get('postflight')
    if type(post)!=dict or set(post)!={'sourceLockSha256','toolchainSha256Before','toolchainSha256After','pythonSha256','nodeSha256','elapsedSeconds'}:return False
    if post['sourceLockSha256']!=sha((HERE/'inputs.lock.json').read_bytes()) or post['pythonSha256']!=helper.PYTHON_SHA or post['nodeSha256']!=modules['base'].NODE_HASH:return False
    before,after=post['toolchainSha256Before'],post['toolchainSha256After']
    if type(before)!=dict or type(after)!=dict or len(before)!=49 or before!=after:return False
    if any(type(v)!=str or len(v)!=64 or any(c not in '0123456789abcdef' for c in v) for v in before.values()):return False
    if type(post['elapsedSeconds']) not in (int,float) or not math.isfinite(post['elapsedSeconds']) or not 0<=post['elapsedSeconds']<900:return False
    pglock,_inputs,current,_owned=modules['base'].admit_sources()
    if current!=before:return False
    verify_stored(reader,prior,helper,protocol,modules,prepared)
    return (reader.validate() is True and helper.stored_completion_bytes(reader,'transition-manifest.json')==raw and helper.stored_completion_bytes(reader,'completion-receipt.json')==helper.receipt_bytes(receipt))

def main():
    started=time.monotonic();parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--appointment',required=True);parser.add_argument('--node',required=True,type=Path);args=parser.parse_args()
    prior,helper,protocol,modules=dependencies()
    if Path(sys.executable)!=helper.PYTHON or not(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):raise ValueError('pinned Python-I-S-B required')
    helper.checked(helper.PYTHON,helper.PYTHON_SHA)
    if not args.appointment.strip() or not args.node.is_absolute():raise ValueError('appointment/absoluteNode required')
    node=args.node.resolve(strict=True);base=modules['base'];base.checked(node,base.NODE_HASH)
    frozen=load('ctas_constructor_source',ROOT/'tests/consumer-derivatives-v2-s5-pre012-extended/s5.py');constructor=frozen.load_constructor();constructor.load_admitted()
    pglock,inputs,tools_before,_unused_owned_helper=base.admit_sources();lock_before=(HERE/'inputs.lock.json').read_bytes()
    recorder=load('ctas_live320_recorder',ROOT/'tests/consumer-fixture-evidence/recording.py');guard=load('ctas_guard24',ROOT/'tests/consumer-pg-guardian/guardian.py');policy=load('ctas_policy1d',SUPERVISED/'resource_policy.py').ResourcePolicy();prepared=load('ctas_prepared',HERE/'prepared.py')
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0));base.require(shutil.disk_usage('/private/tmp').free>=2*1024**3,'immediate2GiB floor')
    evidence=ROOT/'artifacts/consumer-derivatives-v2-s5-pre012-ctas-supervised-runtime'/str(uuid.uuid4());evidence.parent.mkdir(parents=True,exist_ok=True);store=recorder.EvidenceStore(evidence)
    pg=ROOT/pglock['toolchainRoot']/'Postgres.app/Contents/Versions/18/bin';pins={**pglock['toolchainCoreSha256'],**pglock['toolchainInitdbSha256']};tools={name:guard.Executable(pg/name,pins['Contents/Versions/18/bin/'+name]) for name in ('postgres','initdb','pg_ctl','psql')};tools['node']=guard.Executable(node,base.NODE_HASH)
    work=Path(tempfile.mkdtemp(prefix='lcd-ctas-',dir='/private/tmp')).resolve();g=guard.Guardian(work,tools,started=started,run_id=evidence.name,log_policy=policy)
    manifest=dict(status='FAILED',fullS5Qualified=False,ctasCompleted=False,boundedSubsetCompleted=False,globalToastCatalogProof=False,prior10Or18Or5Reexecuted=False,privateOwnedDirectoryRetained=True)
    make=lambda:prior.fixture_class(helper,base,recorder)(g,pglock,work,evidence,args.appointment,node,recording_store=store,raw_log_policy=policy)
    exercise=lambda f:run_cases(base,f,inputs,protocol,modules,prepared)
    f,error,clean=owned_phase(g,make,exercise);receipt=None
    def postflight():
        dependencies();constructor.load_admitted();base.checked(node,base.NODE_HASH);helper.checked(helper.PYTHON,helper.PYTHON_SHA)
        if (HERE/'inputs.lock.json').read_bytes()!=lock_before:raise ValueError('source lock drift')
        after=base.toolchain(pglock)
        if after!=tools_before:raise ValueError('49PG toolchain drift')
        return dict(sourceLockSha256=sha(lock_before),toolchainSha256Before=tools_before,toolchainSha256After=after,pythonSha256=helper.PYTHON_SHA,nodeSha256=base.NODE_HASH,elapsedSeconds=time.monotonic()-started)
    try:
        if error is not None:raise error
        receipt=finalize(store,g,f,clean,prior,helper,protocol,modules,prepared,manifest,postflight,recorder)
    except BaseException as exc:
        error=exc;manifest.update(status='FAILED_OR_UNKNOWN',ctasCompleted=False,boundedSubsetCompleted=False,fullS5Qualified=False,cleanup=clean,runId=evidence.name,error=type(exc).__name__,recordingComplete=False)
        try:
            if not store.sealed:store.seal()
            store.save('transition-manifest.json',manifest)
        except BaseException:pass
    print(json.dumps(dict(status=manifest['status'],manifest=str(evidence/'transition-manifest.json'),cleanupCompleted=clean['completed'],completionReceiptPublished=receipt is not None,requiresIndependentOuterExitZero=True)))
    if error is not None:raise SystemExit(1)

if __name__=='__main__':sys.dont_write_bytecode=True;main()
