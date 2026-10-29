"""Prepared10 pristine-pre012 missing/rename S5 subset. Runtime requires independent review + root appointment.

No child on import. Existing S0-S4 source remains byte-identical and is imported
only after the constructor verifies its closed, reviewed source/evidence lock.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import resource
import shutil
import signal
import sys
import tempfile
import time
import uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
CONSTRUCTOR_SHA='7edfc912fbc079812ac2e35ace9cd2d56505d12c4ffd7f399e22be676759a3fd'
SOURCE_NAMES=('cases.py','prefix.py','raw-capture.sql','inputs.lock.json','s5.py','pre012.test.py','README.md','excluded.json')
PRIOR=ROOT/'tests/consumer-derivatives-v2-sealing'
DEPENDENCY_LOCK_SHA='96fa40e9855f3ef714be24782dfbb9f88bc3e2a159a776dd4698c1729f0c75a8'


def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def dependencies():
    path=HERE/'inputs.lock.json'
    if hashlib.sha256(path.read_bytes()).hexdigest()!=DEPENDENCY_LOCK_SHA:raise ValueError('pre012 lock substitution')
    lock=json.loads(path.read_bytes())
    for name,pin in lock['dependenciesSha256'].items():
        p=ROOT/name
        if any(x.is_symlink() for x in (p,*p.parents)) or hashlib.sha256(p.read_bytes()).hexdigest()!=pin:raise ValueError('dependency substitution: '+name)
    prior=load_module('pre012_prior_admission',ROOT/'tests/consumer-derivatives-v2-s5-operator-faults/s5.py')
    prior.dependencies()
    for name,pin in lock['localSha256'].items():
        p=HERE/name
        if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=pin:raise ValueError('local source substitution: '+name)
    return lock


def load_constructor():
    dependencies();path=PRIOR/'construct.py'
    if hashlib.sha256(path.read_bytes()).hexdigest()!=CONSTRUCTOR_SHA:raise ValueError('original constructor identity')
    return load_module('operator_faults_constructor',path)


def closure(constructor):
    dependencies();return {n:constructor.sha((HERE/n).read_bytes()) for n in SOURCE_NAMES}


def run_s5(base,f,inputs,constructor,admitted,derived,manifest):
    dependencies()
    prefix=load_module('pre012_prefix',HERE/'prefix.py')
    model=load_module('pre012_cases',HERE/'cases.py')
    predecessor=load_module('pre012_predecessor',ROOT/'tests/consumer-derivatives-v2/predecessor-model.py')
    contract=json.loads(base.checked(ROOT/'staging/consumer-derivatives-v2/predecessor-contract.json'))
    # Exact source projection from the frozen guard, with only PL/pgSQL INTO
    # removed for standalone SELECT. The raw candidate below is never rewritten.
    guard=predecessor.guard_sql(contract)
    projection=guard[guard.index(' SELECT coalesce('):guard.index(' IF actual IS DISTINCT')].replace(' INTO actual','',1)
    capture=base.checked(HERE/'raw-capture.sql').decode()+"SELECT jsonb_build_object('section','selected','rows',q.value) FROM ("+projection.strip().removesuffix(';')+") q(value);\n"
    manifest.update(prefix.execute(base,f,inputs))
    def snapshot(database,label):
        rows=f.capture(database,label,capture)
        sections={r['section']:r['rows'] for r in rows}
        base.require(len(rows)==len(sections)==capture.count("SELECT jsonb_build_object('section'") and sections['ledger']==[{'count':0}] and sections['consumerRows']==[{'count':0}],'raw closure/empty fixtures')
        base.require(not any(r['name'].startswith('fixture_pre012') for r in sections['objects']),'setup object present')
        return rows
    baseline={db:snapshot(db,'pre012-baseline-'+db) for db in base.DATABASES}
    def pristine(label):
        for db in base.DATABASES:
            rows=snapshot(db,label+'-'+db)
            base.require(rows==baseline[db],'raw same-DB catalog rollback mismatch')
            predecessor.admit_predecessors(next(r['rows'] for r in rows if r['section']=='selected'),contract)
    cases=model.build(contract);f.save('pre012-source-cases.json',cases);results=[]
    operator=base.checked(ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').decode()
    for index,case in enumerate(cases):
        pristine('before-'+case['id'])
        database=base.DATABASES[index%3]
        script=model.branch_sql(case,capture,operator);path=f.work/('pre012-'+case['id']+'.sql');path.write_text(script)
        f.save('script-'+case['id']+'.json',dict(case=case,sql=script,unchanged012Sha256=constructor.sha(operator.encode())))
        stdout=f.command('pre012-attempt-'+case['id'],[f.pg/'psql','-X','--no-password','-qAt','-h',f.work/'socket','-p','55439','-U','e2_owner','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-d',database,'-f',path],expected=(3,))
        setup=model.parse_result(case,stdout,f.events[-1]['stderr'],base.parse_catalog)
        expected=model.expected_setup(case,baseline[database],contract)
        f.save('setup-'+case['id']+'.json',setup);f.save('expected-setup-'+case['id']+'.json',expected)
        base.require(setup==expected,'undeclared setup catalog change')
        pristine('after-'+case['id'])
        results.append(dict(id=case['id'],status='PASS',allThreeDatabasesRawRollback=True,sqlstate='55000'))
        f.save('pre012-results.json',results)
    manifest.update(status='PROVISIONAL_PRE012_SUBSET_PENDING_ROOT_REVIEW',stages={'PRE012_PREFIX':'PASS','PRE012_SUBSET':'SUBSET_PASS','S3':'NOT_RUN','S4':'NOT_RUN'},fullS5Qualified=False,boundedSubsetCompleted=True,pre012Completed=True,pre012Count=10,qualification={'S5':False},priorAccepted202ChecksReexecuted=False,prismaLedgerQualified=False)
    return manifest


def completion_is_admissible(manifest_bytes,receipt,controller):
    manifest=json.loads(manifest_bytes);elapsed=controller.get('elapsedSeconds')
    return (manifest.get('status')=='PROVISIONAL_PRE012_SUBSET_PENDING_ROOT_REVIEW'
        and manifest.get('authoritative') is False and manifest.get('cleanup',{}).get('completed') is True
        and manifest.get('originalInputsUnchanged') is True and not manifest.get('evidenceWriteErrors')
        and manifest.get('stages')=={'PRE012_PREFIX':'PASS','PRE012_SUBSET':'SUBSET_PASS','S3':'NOT_RUN','S4':'NOT_RUN'}
        and manifest.get('fullS5Qualified') is False and manifest.get('boundedSubsetCompleted') is True
        and manifest.get('qualification',{}).get('S5') is False and manifest.get('pre012Completed') is True
        and type(manifest.get('pre012Count')) is int and manifest['pre012Count']==10
        and receipt.get('status')=='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO'
        and receipt.get('manifestSha256')==hashlib.sha256(manifest_bytes).hexdigest()
        and receipt.get('runId')==manifest.get('runId')==controller.get('runId')
        and receipt.get('requiresOwnedControllerExitCode')==0 and receipt.get('originalOuterDeadlineSeconds')==900
        and type(controller.get('ownedControllerExitCode')) is int and controller['ownedControllerExitCode']==0
        and controller.get('completed') is True and controller.get('originalOuterDeadlineSeconds')==900
        and type(elapsed) in (int,float) and 0<=elapsed<900)


def main():
    started=time.monotonic();parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--appointment',required=True);parser.add_argument('--node',required=True,type=Path)
    parser.add_argument('--derived',required=True,type=Path);args=parser.parse_args()
    constructor=load_constructor()
    # Admit evidence and source identities before importing any owned process helper.
    admitted=constructor.load_admitted();lock_data=admitted[0];inputs_data=admitted[1]
    spec=importlib.util.spec_from_file_location('s5_pinned_s4',ROOT/lock_data['driver'])
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    def interrupted(signum,frame):
        if signum==signal.SIGALRM:raise base.AppointmentDeadline('original appointment watchdog expired')
        raise InterruptedError('fixture interrupted by signal '+str(signum))
    signal.signal(signal.SIGALRM,interrupted);signal.setitimer(signal.ITIMER_REAL,base.remaining_budget(started,840))
    base.require(bool(args.appointment.strip()) and args.node.is_absolute(),'appointment/absolute Node required')
    node=args.node.resolve(strict=True);base.checked(node,base.NODE_HASH)
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    derived,delta=constructor.construct()
    base.require(args.derived.is_dir() and not args.derived.is_symlink(),'derived directory missing/symlink')
    base.require(set(p.name for p in args.derived.iterdir())==set(derived)|{'derived-manifest.json'},'derived file allowlist')
    for name,raw in derived.items():base.require(base.checked(args.derived/name)==raw,'derived source substitution')
    base.require(json.loads(base.checked(args.derived/'derived-manifest.json'))==delta,'derived delta substitution')
    lock,inputs,tools_before,support=base.admit_sources();sources_before=closure(constructor)
    spec=importlib.util.spec_from_file_location('s5_owned',support);owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
    owned.initialize_process_ownership()
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
    base.require(shutil.disk_usage('/private/tmp').free>=2*1024**3,'need2GiB free space')
    evidence=ROOT/'artifacts/consumer-derivatives-v2-s5-pre012-runtime'/str(uuid.uuid4());evidence.mkdir(parents=True,exist_ok=False)
    work=Path(tempfile.mkdtemp(prefix='lcd-s5-',dir='/private/tmp'))
    for name in ('home','tmp','socket'):(work/name).mkdir(mode=0o700)
    f=base.Fixture(owned,lock,work,evidence,args.appointment,node);f.started=started
    manifest={'status':'FAILED','authoritative':False,'stages':{'S5':'INCOMPLETE'},'lastStage':None,
        'fullS5Qualified':False,'boundedSubsetCompleted':False,'pre012Completed':False,
        'originalPinsModified':False,'pinsFilled':False,'measuredOperatorsExecuted':False,'prismaLedgerQualified':False,
        'laterStages':{s:'NOT_RUN' for s in ('S5','S6','S7','S8')},
        'qualification':{k:False for k in ('S5','HTTP','BetterAuth','UI','Prisma012','production')}}
    error=None;completion=None;tools_after=None
    try:
        f.save('derived-manifest.json',delta)
        for name,raw in derived.items():(evidence/name).write_bytes(raw)
        manifest=run_s5(base,f,inputs,constructor,admitted,derived,manifest)
    except BaseException as exc:
        error=exc;manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False,pre012Completed=False,qualification={**manifest['qualification'],'S5':False});manifest['error']=type(exc).__name__+': '+str(exc).replace(str(work),'<owned>')
    finally:
        signal.setitimer(signal.ITIMER_REAL,max(.001,900-(time.monotonic()-started)))
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
        try:manifest['cleanup']=f.cleanup()
        except BaseException as exc:
            error=error or exc;manifest['cleanup']={'completed':False,'status':'UNKNOWN','error':type(exc).__name__+': '+str(exc)}
        try:
            base.remaining_budget(started)
            tools_after=base.toolchain(lock);base.require(tools_after==tools_before,'tool drift')
            constructor.load_admitted();base.require(closure(constructor)==sources_before,'sealing source drift')
            for name,raw in derived.items():base.require(base.checked(args.derived/name)==raw,'derived source drift')
            base.require(json.loads(base.checked(args.derived/'derived-manifest.json'))==delta,'delta drift')
            base.checked(node,base.NODE_HASH);base.remaining_budget(started)
            if f.evidence_errors:error=error or OSError('evidence writes failed')
            if error is not None:
                manifest['status']='UNKNOWN_DEADLINE' if isinstance(error,base.AppointmentDeadline) else 'FAILED'
                manifest['lastCommand']=f.events[-1]['label'] if f.events else None
                manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False,pre012Completed=False)
                manifest['stages']={'PRE012_SUBSET':'INCOMPLETE','S3':'NOT_RUN','S4':'NOT_RUN'}
            manifest.update(runId=evidence.name,appointment=args.appointment,sourceSha256=sources_before,
                toolchainSha256Before=tools_before,toolchainSha256After=tools_after,originalInputsUnchanged=True,
                elapsedSeconds=round(time.monotonic()-started,6),evidenceWriteErrors=f.evidence_errors,
                privateOwnedDirectoryRetained=error is not None,derivedManifestSha256=constructor.sha(json.dumps(delta,indent=2).encode()+b'\n'))
            manifest['evidenceSha256']={p.name:constructor.sha(p.read_bytes()) for p in evidence.iterdir() if p.is_file() and p.name!='transition-manifest.json'}
            manifest['authoritative']=False;manifest['completionGate']='matching atomic receipt AND independent owned outer exit0 within original900s; root review still required'
            base.remaining_budget(started);manifest_sha=f.save('transition-manifest.json',manifest);base.remaining_budget(started)
            if error is None and manifest['cleanup']['completed']:shutil.rmtree(work)
            base.remaining_budget(started)
            if error is None:completion=base.publish_completion(f,manifest_sha)
            base.remaining_budget(started)
        except BaseException as exc:
            error=error or exc;manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False,pre012Completed=False);manifest.setdefault('stages',{})['S5']='INCOMPLETE';manifest['status']='UNKNOWN_DEADLINE' if isinstance(exc,base.AppointmentDeadline) else 'FAILED'
            manifest['finalizationError']=type(exc).__name__+': '+str(exc).replace(str(work),'<owned>')
            try:base.remaining_budget(started);f.try_save('transition-manifest.json',manifest)
            except BaseException:pass
        finally:signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps({'status':manifest['status'],'manifest':str(evidence/'transition-manifest.json'),
        'cleanup':manifest.get('cleanup',{}).get('completed',False),'completionReceiptPublished':completion is not None,
        'requiresExternalOwnedControllerExitZero':True}))
    if error:raise SystemExit(1)

if __name__=='__main__':sys.dont_write_bytecode=True;main()
